"""Contribution 3 (E3) - feed-freshness sweep: poll interval -> detection quality.

Answers RQ2/H2.  One model is trained on 5-minute-fresh features; the same
model is then evaluated while the *feed* refresh interval is swept from 1 min
to 24 h, so the curve isolates staleness instead of model capacity.

    python scripts/run_e3_freshness.py --dataset unsw_nb15
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
    get_sightings, write_json,
)

from cti_pipeline.data import build_design  # noqa: E402
from cti_pipeline.enrich import CTI_FEATURES, coverage_stats  # noqa: E402
from cti_pipeline.model import make_model, make_splits, metrics_at, tune_threshold  # noqa: E402

INTERVAL_LABELS = {1: "1 min", 5: "5 min", 60: "1 hr", 360: "6 hr", 1440: "24 hr"}


def main() -> None:
    parser = base_parser("E3 - freshness sweep (RQ2/H2)")
    parser.add_argument("--no-poll", action="store_true")
    parser.add_argument("--retrain", action="store_true",
                        help="also retrain a model per interval (slower, secondary curve)")
    args = parser.parse_args()
    cfg = get_config(args)

    flows = get_flows(cfg, args.dataset)
    live = get_live_records(cfg, poll=not args.no_poll)

    # sightings are interval-independent: build once from the full traffic frame
    sightings, summary = get_sightings(cfg, flows, live)
    sight_pair = (sightings, summary)

    # reference: features produced at the configured 5-minute poll interval
    t0 = time.time()
    frame_ref, _, _ = build_enriched(
        cfg, flows, live, interval_min=cfg.cti.poll_interval_min, sightings=sight_pair)
    ref_enrich_s = time.time() - t0

    X, y = build_design(frame_ref, include_cti=True, cti_cols=CTI_FEATURES)
    splits = make_splits(y, cfg.data.test_size, cfg.data.val_size, cfg.model.seed)
    print(f"[design] rows={len(y):,} features={X.shape[1]} "
          f"| sightings={summary} | enrich(ref)={ref_enrich_s:.1f}s")

    model = make_model(cfg)
    model.fit(X.iloc[splits.train], y[splits.train])
    theta = tune_threshold(y[splits.val],
                           model.predict_proba(X.iloc[splits.val])[:, 1],
                           cfg.model.target_recall)
    ref = metrics_at(y[splits.test], model.predict_proba(X.iloc[splits.test])[:, 1], theta)
    print(f"[model] theta={theta:.4f} on {cfg.cti.poll_interval_min} min features -> "
          f"recall={ref['recall']:.4f} precision={ref['precision']:.4f} fpr={ref['fpr']:.5f}")

    rows = []
    for interval in cfg.replay.intervals_min:
        t0 = time.time()
        frame_i, _, sum_i = build_enriched(cfg, flows, live, interval_min=interval,
                                           sightings=sight_pair)
        enrich_s = time.time() - t0
        X_i, _ = build_design(frame_i, include_cti=True, cti_cols=CTI_FEATURES)
        X_i = X_i.reindex(columns=X.columns, fill_value=0.0)

        proba_val = model.predict_proba(X_i.iloc[splits.val])[:, 1]
        proba = model.predict_proba(X_i.iloc[splits.test])[:, 1]
        m = metrics_at(y[splits.test], proba, theta)
        # secondary view: what does staleness COST at a fixed recall target?
        theta_i = tune_threshold(y[splits.val], proba_val, cfg.model.target_recall)
        m_match = metrics_at(y[splits.test], proba, theta_i)
        cov = coverage_stats(frame_i, y)
        cov_test = coverage_stats(frame_i.iloc[splits.test], y[splits.test],
                                  age=frame_i.attrs["age_seconds"][splits.test])

        row = {
            "interval_min": float(interval),
            "interval_label": INTERVAL_LABELS.get(int(interval), f"{interval} min"),
            "recall": m["recall"], "precision": m["precision"], "f1": m["f1"],
            "fpr": m["fpr"], "pr_auc": m["pr_auc"], "roc_auc": m["roc_auc"],
            "n_alerts": m["n_alerts"],
            "coverage_all": cov_test["coverage_all"],
            "coverage_malicious": cov_test["coverage_malicious"],
            "coverage_benign": cov_test["coverage_benign"],
            "median_age_min": cov_test["median_age_min"],
            "p90_age_min": cov_test["p90_age_min"],
            "enrich_seconds": round(enrich_s, 2),
            "n_indicators": sum_i["n_indicators"],
            "same_model_theta": theta,
            "matched_recall": m_match["recall"],
            "matched_precision": m_match["precision"],
            "matched_f1": m_match["f1"],
            "matched_fpr": m_match["fpr"],
            "matched_theta": theta_i,
        }

        if args.retrain:
            m2 = make_model(cfg)
            m2.fit(X_i.iloc[splits.train], y[splits.train])
            th2 = tune_threshold(y[splits.val],
                                 m2.predict_proba(X_i.iloc[splits.val])[:, 1],
                                 cfg.model.target_recall)
            m_retrain = metrics_at(y[splits.test],
                                   m2.predict_proba(X_i.iloc[splits.test])[:, 1], th2)
            row["retrain_recall"] = m_retrain["recall"]
            row["retrain_precision"] = m_retrain["precision"]
            row["retrain_f1"] = m_retrain["f1"]
            row["retrain_fpr"] = m_retrain["fpr"]
            row["retrain_pr_auc"] = m_retrain["pr_auc"]
            del m2

        rows.append(row)
        print(f"[sweep] {row['interval_label']:>7s}  recall={row['recall']:.4f} "
              f"precision={row['precision']:.4f} coverage(mal)={row['coverage_malicious']:.3f} "
              f"age_med={row['median_age_min']:.1f}min  enrich={enrich_s:.1f}s", flush=True)

    frame = pd.DataFrame(rows)
    short = next((r for r in rows if r["interval_min"] == 5.0), rows[0])
    long = rows[-1]
    results = {
        "dataset": args.dataset,
        "model_interval_min": cfg.cti.poll_interval_min,
        "theta": theta,
        "reference_metrics": ref,
        "sightings_summary": summary,
        "rows": rows,
        "recall_gap_5m_vs_24h": short["recall"] - long["recall"],
        "coverage_gap_5m_vs_24h": short["coverage_malicious"] - long["coverage_malicious"],
        "matched_recall_fpr_gap_5m_vs_24h": long["matched_fpr"] - short["matched_fpr"],
        "matched_recall_fpr_ratio": (long["matched_fpr"] / short["matched_fpr"]
                                     if short["matched_fpr"] else float("nan")),
        "monotone_recall": all(rows[i]["recall"] >= rows[i + 1]["recall"] - 1e-6
                               for i in range(len(rows) - 1)),
        "monotone_coverage": all(rows[i]["coverage_malicious"] >=
                                 rows[i + 1]["coverage_malicious"] - 1e-6
                                 for i in range(len(rows) - 1)),
    }
    write_json(TABLES / f"e3_freshness_{args.dataset}.json", results)
    frame.to_csv(TABLES / f"e3_freshness_{args.dataset}.csv", index=False)
    print(frame[["interval_label", "recall", "precision", "matched_fpr",
                 "coverage_malicious", "median_age_min"]].to_string(index=False))
    print(f"\n[headline] recall gap 5 min vs 24 hr = "
          f"{results['recall_gap_5m_vs_24h'] * 100:.2f} pp "
          f"(H2 requires >= 3 pp), monotone recall={results['monotone_recall']}, "
          f"monotone coverage={results['monotone_coverage']}")
    print(f"[headline] FPR at matched recall {cfg.model.target_recall}: "
          f"{short['matched_fpr'] * 100:.4f}% (5 min) -> {long['matched_fpr'] * 100:.4f}% "
          f"(24 hr), ratio x{results['matched_recall_fpr_ratio']:.2f}")


if __name__ == "__main__":
    main()
