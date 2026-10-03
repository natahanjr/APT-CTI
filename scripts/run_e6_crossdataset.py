"""E6 - cross-dataset transportability (semantic feature bridge).

The two benchmarks share only ~7 raw column names, so a direct intersection is
statistically empty.  Instead both datasets are mapped to one canonical feature
set computed with *identical formulas* on each side:

    duration_s, total_pkts, total_bytes, byte_rate, pkt_rate,
    iat_mean, mean_pkt_size, fwd_bwd_ratio   (+ log1p on all eight)
    proto_{tcp,udp,icmp,other} one-hots
    the six CTI enrichment features (same construction on both datasets)

Protocol, for both directions (unsw->cic, cic->unsw):
  * theta tuned on the SOURCE validation split at 96% recall
  * cross evaluation on the TARGET test split and on the full target set
  * in-domain reference: fresh model trained on the target's own split
  * gap = in-domain - cross for recall / FPR / PR-AUC / ROC-AUC

    python scripts/run_e6_crossdataset.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (  # noqa: E402
    TABLES, base_parser, build_enriched, get_config, get_flows, get_live_records,
    write_json,
)

from cti_pipeline.enrich import CTI_FEATURES  # noqa: E402
from cti_pipeline.model import fit_and_score, make_splits, metrics_at  # noqa: E402

RATES = ("byte_rate", "pkt_rate", "iat_mean", "mean_pkt_size", "duration_s",
         "total_pkts", "total_bytes", "fwd_bwd_ratio")


def _num(df: pd.DataFrame, col: str) -> pd.Series:
    if col not in df.columns:
        raise KeyError(f"canonical bridge: column {col!r} missing")
    return pd.to_numeric(df[col], errors="coerce").fillna(0.0)


def _proto(series: pd.Series) -> pd.Series:
    s = series.astype("string").str.lower().str.strip()
    out = pd.Series("other", index=series.index, dtype="string")
    out[s.isin(["tcp", "6"])] = "tcp"
    out[s.isin(["udp", "17"])] = "udp"
    out[s.isin(["icmp", "1", "icmp6"])] = "icmp"
    return out


def canonical(df: pd.DataFrame, dataset: str) -> tuple[pd.DataFrame, np.ndarray]:
    """Map a dataset-native enriched frame to the shared canonical design."""
    if dataset == "unsw_nb15":
        dur = _num(df, "dur")
        fwd_pkts = _num(df, "Spkts")
        bwd_pkts = _num(df, "Dpkts")
        fwd_bytes = _num(df, "sbytes")
        bwd_bytes = _num(df, "dbytes")
        iat = (_num(df, "Sintpkt") + _num(df, "Dintpkt")) / 2.0
    else:
        dur = _num(df, "Flow Duration") * 1e-6          # us -> s
        fwd_pkts = _num(df, "Total Fwd Packets")
        bwd_pkts = _num(df, "Total Backward Packets")
        fwd_bytes = _num(df, "Total Length of Fwd Packets")
        bwd_bytes = _num(df, "Total Length of Bwd Packets")
        iat = _num(df, "Flow IAT Mean") * 1e-6          # us -> s

    total_pkts = fwd_pkts + bwd_pkts
    total_bytes = fwd_bytes + bwd_bytes
    dur_safe = dur.clip(lower=1e-6)
    raw = pd.DataFrame({
        "duration_s": dur,
        "total_pkts": total_pkts,
        "total_bytes": total_bytes,
        "byte_rate": total_bytes / dur_safe,
        "pkt_rate": total_pkts / dur_safe,
        "iat_mean": iat.clip(lower=0.0),
        "mean_pkt_size": total_bytes / total_pkts.clip(lower=1.0),
        "fwd_bwd_ratio": fwd_pkts / bwd_pkts.clip(lower=1.0),
    }, index=df.index)
    out = np.log1p(raw.clip(lower=0.0))
    out.columns = [f"log_{c}" for c in raw.columns]

    proto = pd.get_dummies(_proto(df["proto"]), prefix="proto", dtype=np.float32)
    out = pd.concat([out, proto], axis=1)
    for col in CTI_FEATURES:
        out[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0).astype("float64")

    y = df["label"].to_numpy().astype("int8")
    return out.replace([np.inf, -np.inf], np.nan).fillna(0.0), y


def describe(model, X, y, theta) -> dict:
    proba = model.predict_proba(X)[:, 1]
    return metrics_at(y, proba, theta)


def main() -> None:
    parser = base_parser("E6 - cross-dataset transport with canonical bridge")
    parser.add_argument("--no-poll", action="store_true", default=False,
                        help="reuse offline feed snapshots instead of polling")
    args = parser.parse_args()
    cfg = get_config(args)

    live = get_live_records(cfg, poll=not args.no_poll)

    designs: dict[str, tuple[pd.DataFrame, np.ndarray]] = {}
    for name in ("unsw_nb15", "cicids2017"):
        t0 = time.time()
        flows = get_flows(cfg, name)
        frame, _, _ = build_enriched(cfg, flows, live, interval_min=cfg.cti.poll_interval_min)
        X, y = canonical(frame, name)
        designs[name] = (X.reset_index(drop=True), y)
        print(f"[e6] {name}: canonical design {X.shape} in {time.time()-t0:.0f}s "
              f"(cols={list(X.columns)})", flush=True)

    # align both sides to one shared column set (a dataset may simply not
    # contain e.g. ICMP flows -> zero column rather than a missing feature)
    shared: list[str] = []
    for name in ("unsw_nb15", "cicids2017"):
        for c in designs[name][0].columns:
            if c not in shared:
                shared.append(c)
    for name in list(designs):
        X, y = designs[name]
        designs[name] = (X.reindex(columns=shared, fill_value=0.0), y)
    print(f"[e6] shared feature set ({len(shared)}): {shared}", flush=True)

    directions = [("unsw_nb15", "cicids2017"), ("cicids2017", "unsw_nb15")]
    results: dict[str, dict] = {}
    rows: list[dict] = []

    for src, tgt in directions:
        t0 = time.time()
        Xs, ys = designs[src]
        Xt, yt = designs[tgt]
        split_s = make_splits(ys, cfg.data.test_size, cfg.data.val_size, cfg.model.seed)
        split_t = make_splits(yt, cfg.data.test_size, cfg.data.val_size, cfg.model.seed)

        model_src, cross_test = fit_and_score(
            Xs.iloc[split_s.train], ys[split_s.train],
            Xs.iloc[split_s.val], ys[split_s.val],
            Xt.iloc[split_t.test], yt[split_t.test], cfg)
        theta_src = cross_test["theta"]
        cross_full = describe(model_src, Xt, yt, theta_src)
        src_test = describe(model_src, Xs.iloc[split_s.test], ys[split_s.test], theta_src)

        model_tgt, in_test = fit_and_score(
            Xt.iloc[split_t.train], yt[split_t.train],
            Xt.iloc[split_t.val], yt[split_t.val],
            Xt.iloc[split_t.test], yt[split_t.test], cfg)

        gap = {
            k: float(in_test[k] - cross_test[k])
            for k in ("recall", "fpr", "precision", "pr_auc", "roc_auc", "f1")
        }
        key = f"{src}_to_{tgt}"
        results[key] = {
            "source": src, "target": tgt,
            "n_features": int(Xs.shape[1]),
            "theta_source": theta_src,
            "cross_target_test": cross_test,
            "cross_target_full": cross_full,
            "source_test": src_test,
            "in_domain_target_test": in_test,
            "gap_in_minus_cross": gap,
            "fit_seconds": round(time.time() - t0, 1),
        }
        rows.append({
            "direction": key, "n_features": int(Xs.shape[1]),
            "theta_src": round(theta_src, 4),
            "cross_recall": round(cross_test["recall"], 4),
            "indomain_recall": round(in_test["recall"], 4),
            "gap_recall": round(gap["recall"], 4),
            "cross_fpr": round(cross_test["fpr"], 6),
            "indomain_fpr": round(in_test["fpr"], 6),
            "gap_fpr": round(gap["fpr"], 6),
            "cross_pr_auc": round(cross_test["pr_auc"], 4),
            "indomain_pr_auc": round(in_test["pr_auc"], 4),
            "gap_pr_auc": round(gap["pr_auc"], 4),
        })
        print(f"[e6] {key}: cross recall={cross_test['recall']:.3f} "
              f"vs in-domain {in_test['recall']:.3f} (gap {gap['recall']:+.3f}); "
              f"cross FPR={cross_test['fpr']:.4f} vs {in_test['fpr']:.4f}", flush=True)

    payload = {
        "protocol": {
            "bridge": "canonical features with identical formulas both sides; "
                      "log1p on eight skewed quantities; shared CTI features",
            "theta_tuned_on": "source validation split (target recall 96%)",
            "evaluated_on": ["target test split", "full target set"],
            "in_domain_reference": "fresh model on target's own split",
        },
        "features": shared,
        "directions": results,
    }
    out = TABLES / "e6_crossdataset.json"
    write_json(out, payload)
    df = pd.DataFrame(rows)
    df.to_csv(TABLES / "e6_crossdataset.csv", index=False)
    print(df.to_string(index=False))
    print(f"\n[write] {out}")


if __name__ == "__main__":
    main()
