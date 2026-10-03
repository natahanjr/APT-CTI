"""E5 - end-to-end alert-path latency profiling (RQ4/H4).

Times one production-shaped batch loop on the test split, time-ordered:

    raw batch -> enrich (IoC lookup + freshness) -> design matrix
             -> predict -> TreeSHAP + reason codes (alerts only) -> emit

    python scripts/run_e5_latency.py --dataset unsw_nb15
    python scripts/run_e5_latency.py --dataset cicids2017 --batch-sizes 16,64,256
"""

from __future__ import annotations

import os
import platform
import sys
import time
from dataclasses import replace
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (  # noqa: E402
    TABLES, base_parser, build_enriched, get_config, get_flows, get_live_records,
    make_settings, write_json,
)

from cti_pipeline.data import build_design  # noqa: E402
from cti_pipeline.enrich import CTI_FEATURES, enrich  # noqa: E402
from cti_pipeline.explain import make_explainer, reason_codes, shap_matrix  # noqa: E402
from cti_pipeline.model import fit_and_score, make_splits  # noqa: E402

WARMUP_BATCHES = 3
TARGET_FLOWS = 10_000


def pct(values: list[float]) -> dict:
    a = np.asarray(values, dtype="float64")
    return {
        "p50": float(np.percentile(a, 50)),
        "p95": float(np.percentile(a, 95)),
        "mean": float(a.mean()),
        "max": float(a.max()),
        "n": int(a.size),
    }


def main() -> None:
    parser = base_parser("E5 - alert-path latency (RQ4/H4)")
    parser.add_argument("--no-poll", action="store_true", help="reuse feed snapshots")
    parser.add_argument("--batch-sizes", default="16,64,256")
    args = parser.parse_args()
    cfg = get_config(args)
    batch_sizes = [int(b) for b in args.batch_sizes.split(",") if b.strip()]

    # ---- feed-update path (measured once) --------------------------------
    t0 = time.perf_counter()
    live = get_live_records(cfg, poll=not args.no_poll)
    poll_seconds = round(time.perf_counter() - t0, 2)

    # ---- build the enriched frame and train ------------------------------
    flows = get_flows(cfg, args.dataset)
    frame, (sightings_map, _), summary = build_enriched(
        cfg, flows, live, interval_min=cfg.cti.poll_interval_min)
    X, y = build_design(frame, include_cti=True, cti_cols=CTI_FEATURES)
    columns = list(X.columns)
    splits = make_splits(y, cfg.data.test_size, cfg.data.val_size, cfg.model.seed)
    print(f"[design] rows={len(y):,} features={X.shape[1]}", flush=True)

    print("[train] fitting model + theta ...", flush=True)
    t0 = time.time()
    model, test_metrics = fit_and_score(
        X.iloc[splits.train], y[splits.train],
        X.iloc[splits.val], y[splits.val],
        X.iloc[splits.test], y[splits.test], cfg)
    fit_seconds = round(time.time() - t0, 1)
    theta = test_metrics["theta"]
    explainer = make_explainer(model)
    print(f"[train] done in {fit_seconds}s theta={theta:.4f}", flush=True)

    settings = replace(make_settings(cfg.cti.poll_interval_min, cfg),
                       t0=float(flows["ts"].min()))

    # time-ordered window over the test split; if the first TARGET_FLOWS
    # flows chronologically yield zero alerts (benign-only period), shift the
    # window to start at the first alerting flow so the explain path runs.
    test_idx = splits.test[np.argsort(frame["ts"].to_numpy()[splits.test], kind="mergesort")]
    all_proba = model.predict_proba(X.iloc[test_idx])[:, 1]
    alert_pos = np.flatnonzero(all_proba >= theta)
    start = 0
    if (all_proba[:TARGET_FLOWS] < theta).all() and alert_pos.size:
        start = int(alert_pos[0])
    test_idx = test_idx[start:start + TARGET_FLOWS]
    win_alerts_all = int((all_proba[start:start + TARGET_FLOWS] >= theta).sum())
    win_mal = int(y[test_idx].sum())
    per_batch_size: dict[str, dict] = {}

    for bsz in batch_sizes:
        n_batches = max(4, -(-len(test_idx) // bsz))
        idx_use = test_idx[:n_batches * bsz]
        n_batches = -(-len(idx_use) // bsz)
        rec: dict[str, list[float]] = {k: [] for k in
                                       ("enrich", "design", "predict", "explain", "total",
                                        "total_no_explain")}
        n_alerts = 0
        for b in range(n_batches):
            rows_idx = idx_use[b * bsz:(b + 1) * bsz]
            if len(rows_idx) < bsz // 2:      # ignore ragged tail batches
                continue
            raw = flows.iloc[rows_idx].reset_index(drop=True)
            t_start = time.perf_counter()

            feats = enrich(raw, sightings_map, settings)
            batch = raw.copy()
            for col in CTI_FEATURES:
                batch[col] = feats[col].to_numpy()
            batch["label"] = y[rows_idx]
            t_feat = time.perf_counter()

            xb, _ = build_design(batch, include_cti=True, cti_cols=CTI_FEATURES,
                                 pool_floor=0)
            xb = xb.reindex(columns=columns, fill_value=0.0)
            t_design = time.perf_counter()

            proba = model.predict_proba(xb)[:, 1]
            t_pred = time.perf_counter()

            alerts = proba >= theta
            k_alerts = int(alerts.sum())
            n_alerts += k_alerts
            if k_alerts:
                phi = shap_matrix(explainer, xb.loc[alerts])
                reason_codes(xb.loc[alerts].iloc[0], phi[0], columns, k=cfg.model.top_k_reasons)
            t_end = time.perf_counter()

            if b < WARMUP_BATCHES:
                continue
            enrich_s = t_feat - t_start
            design_s = t_design - t_feat
            predict_s = t_pred - t_design
            explain_s = t_end - t_pred
            rec["enrich"].append(enrich_s)
            rec["design"].append(design_s)
            rec["predict"].append(predict_s)
            rec["explain"].append(explain_s)
            rec["total"].append(t_end - t_start)
            rec["total_no_explain"].append(t_pred - t_start)

        timed = [i for i in range(n_batches) if i >= WARMUP_BATCHES]
        per_batch_size[str(bsz)] = {
            "batch_size": bsz,
            "batches_timed": len(timed),
            "flows_timed": len(timed) * bsz,
            "warmup_batches_skipped": WARMUP_BATCHES,
            "alerts_scored": n_alerts,
            "stages": {k: pct(v) for k, v in rec.items() if v},
        }
        s = per_batch_size[str(bsz)]["stages"]
        print(f"[e5] batch={bsz:>4}  n={len(timed)}  "
              f"total p50={s['total']['p50']*1000:.0f}ms p95={s['total']['p95']*1000:.0f}ms  "
              f"(explain p95={s['explain']['p95']*1000:.0f}ms)", flush=True)

    default = per_batch_size.get("64") or per_batch_size[str(batch_sizes[0])]
    results = {
        "dataset": args.dataset,
        "theta": theta,
        "poll_seconds": poll_seconds,
        "poll_records": len(live),
        "fit_seconds": fit_seconds,
        "n_features": int(X.shape[1]),
        "test_metrics": test_metrics,
        "batch_sizes": per_batch_size,
        "h4_p95_lt_1s": bool(default["stages"]["total"]["p95"] < 1.0),
        "sightings_summary": summary,
        "hardware": {
            "platform": platform.platform(),
            "processor": platform.processor() or "unknown",
            "cores": os.cpu_count(),
        },
        "protocol": {
            "target_flows": TARGET_FLOWS,
            "warmup_batches": WARMUP_BATCHES,
            "window_start_offset": start,
            "window_malicious": win_mal,
            "window_alerts": win_alerts_all,
            "window_rule": "first TARGET_FLOWS chronologically; shifted to first "
                           "alert if that window contains zero alerts",
            "stages": ["enrich", "design", "predict", "explain(+reason codes)", "total"],
            "explain_only_alerts": True,
        },
    }
    out = TABLES / f"e5_latency_{args.dataset}.json"
    write_json(out, results)

    rows = []
    for bsz, r in per_batch_size.items():
        st = r["stages"]
        rows.append({
            "batch_size": int(bsz), "batches": r["batches_timed"],
            "alerts": r["alerts_scored"],
            **{f"{k}_{p}": round(st[k][p], 4) for k in st for p in ("p50", "p95")},
        })
    pd.DataFrame(rows).to_csv(TABLES / f"e5_latency_{args.dataset}.csv", index=False)
    print(pd.DataFrame(rows).to_string(index=False))
    print(f"\n[h4] p95 total < 1 s at default batch: {results['h4_p95_lt_1s']}")


if __name__ == "__main__":
    main()
