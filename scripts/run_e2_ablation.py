"""Contribution 2 (E2) - CTI ablation: traffic-only vs traffic+CTI.

Answers RQ1/H1: relative FPR reduction of live CTI at matched recall.

    python scripts/run_e2_ablation.py --dataset unsw_nb15
    python scripts/run_e2_ablation.py --dataset cicids2017 --max-rows 400000
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (  # noqa: E402
    TABLES, base_parser, build_enriched, get_config, get_flows, get_live_records, write_json,
)

from cti_pipeline.data import build_design  # noqa: E402
from cti_pipeline.enrich import CTI_FEATURES  # noqa: E402
from cti_pipeline.model import aggregate, cross_validate, fit_and_score, make_splits  # noqa: E402


def run_variant(name: str, X: pd.DataFrame, y: np.ndarray, cfg, splits, do_cv: bool) -> dict:
    t0 = time.time()
    model, test_metrics = fit_and_score(
        X.iloc[splits.train], y[splits.train],
        X.iloc[splits.val], y[splits.val],
        X.iloc[splits.test], y[splits.test],
        cfg,
    )
    result = {"variant": name, "n_features": int(X.shape[1]),
              "split_test": test_metrics, "fit_seconds": round(time.time() - t0, 1)}
    if do_cv:
        print(f"  [cv] {name} ...", flush=True)
        folds, _ = cross_validate(X.iloc[np.concatenate([splits.train, splits.val])],
                                  y[np.concatenate([splits.train, splits.val])], cfg)
        result["cv"] = aggregate(folds)
        result["cv_folds"] = folds
    del model
    return result


def main() -> None:
    parser = base_parser("E2 - CTI ablation (RQ1/H1)")
    parser.add_argument("--no-poll", action="store_true", help="reuse feed snapshots")
    parser.add_argument("--skip-cv", action="store_true")
    args = parser.parse_args()
    cfg = get_config(args)

    flows = get_flows(cfg, args.dataset)
    live = get_live_records(cfg, poll=not args.no_poll)

    # ---- variant A: controlled live-CTI enrichment (proposal's primary path)
    frame, _, summary = build_enriched(cfg, flows, live, interval_min=cfg.cti.poll_interval_min)
    X_all, y = build_design(frame, include_cti=True, cti_cols=CTI_FEATURES)
    cti_cols = [c for c in CTI_FEATURES if c in X_all.columns]
    X_cti_all = X_all[cti_cols]
    X_traffic = X_all.drop(columns=cti_cols)
    # feature-group ablation: how much of the gain is the IoC-match flag itself?
    match_cols = [c for c in ("ioc_src_match", "ioc_dst_match") if c in X_all.columns]
    X_cti_no_match = X_all.drop(columns=match_cols)

    # ---- variant B: live feeds only (no controlled injection) -------------
    frame_live, _, summary_live = build_enriched(cfg, flows, live,
                                                 interval_min=cfg.cti.poll_interval_min,
                                                 injection="none")
    X_live, _ = build_design(frame_live, include_cti=True, cti_cols=CTI_FEATURES)
    X_live_cti = X_live.reindex(columns=X_all.columns, fill_value=0.0)
    X_live_only = X_live_cti.drop(
        columns=[c for c in CTI_FEATURES if c in X_live_cti.columns])

    splits = make_splits(y, cfg.data.test_size, cfg.data.val_size, cfg.model.seed)
    print(f"[design] rows={len(y):,} features traffic={X_traffic.shape[1]} "
          f"+cti={X_all.shape[1]} | positives={int(y.sum()):,} "
          f"| CTI sightings={summary}")

    results = {
        "dataset": args.dataset,
        "seed": cfg.model.seed,
        "target_recall": cfg.model.target_recall,
        "interval_min": cfg.cti.poll_interval_min,
        "sightings_summary": summary,
        "sightings_live_only": summary_live,
        "variants": [],
    }

    for name, X, do_cv in (
        ("traffic_only", X_traffic, not args.skip_cv),
        ("traffic_cti", X_all, not args.skip_cv),
        ("traffic_cti_no_match", X_cti_no_match, not args.skip_cv),
        ("live_feeds_only", X_live_only, False),
    ):
        print(f"[run] {name} ({X.shape[1]} features)", flush=True)
        results["variants"].append(run_variant(name, X, y, cfg, splits, do_cv))

    by_name = {v["variant"]: v for v in results["variants"]}
    fpr_t = by_name["traffic_only"]["split_test"]["fpr"]
    fpr_c = by_name["traffic_cti"]["split_test"]["fpr"]
    results["fpr_reduction_split"] = {
        "traffic_only_fpr": fpr_t,
        "traffic_cti_fpr": fpr_c,
        "relative_reduction": (fpr_t - fpr_c) / fpr_t if fpr_t else float("nan"),
        "recall_traffic": by_name["traffic_only"]["split_test"]["recall"],
        "recall_cti": by_name["traffic_cti"]["split_test"]["recall"],
    }
    if "cv" in by_name["traffic_only"] and "cv" in by_name["traffic_cti"]:
        ft = by_name["traffic_only"]["cv"]["fpr_mean"]
        fc = by_name["traffic_cti"]["cv"]["fpr_mean"]
        results["fpr_reduction_cv"] = {
            "traffic_only_fpr_mean": ft,
            "traffic_cti_fpr_mean": fc,
            "relative_reduction": (ft - fc) / ft if ft else float("nan"),
            "traffic_only_fpr_std": by_name["traffic_only"]["cv"]["fpr_std"],
            "traffic_cti_fpr_std": by_name["traffic_cti"]["cv"]["fpr_std"],
        }
    if "cv" in by_name.get("traffic_cti_no_match", {}):
        fm = by_name["traffic_cti_no_match"]["cv"]
        ft = by_name["traffic_only"]["cv"]["fpr_mean"]
        results["fpr_reduction_no_match_cv"] = {
            "traffic_cti_no_match_fpr_mean": fm["fpr_mean"],
            "relative_reduction": (ft - fm["fpr_mean"]) / ft if ft else float("nan"),
            "traffic_cti_no_match_fpr_std": fm["fpr_std"],
        }

    out = TABLES / f"e2_ablation_{args.dataset}.json"
    write_json(out, results)

    rows = []
    for v in results["variants"]:
        m = v["split_test"]
        cv = v.get("cv", {})
        rows.append({
            "variant": v["variant"], "n_features": v["n_features"],
            **{k: round(m[k], 5) for k in ("accuracy", "precision", "recall", "f1",
                                           "pr_auc", "roc_auc", "fpr")},
            "cv_fpr_mean": round(cv.get("fpr_mean", float("nan")), 6),
            "cv_recall_mean": round(cv.get("recall_mean", float("nan")), 5),
            "cv_pr_auc_mean": round(cv.get("pr_auc_mean", float("nan")), 5),
        })
    pd.DataFrame(rows).to_csv(TABLES / f"e2_ablation_{args.dataset}.csv", index=False)
    print(pd.DataFrame(rows).to_string(index=False))
    headline = results.get("fpr_reduction_cv") or results.get("fpr_reduction_split")
    print("\n[headline FPR reduction]", json.dumps(headline, indent=2))


if __name__ == "__main__":
    main()
