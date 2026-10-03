"""E1 - baseline reproduction: RF vs Gradient Boosting vs linear SVM (traffic-only).

    python scripts/run_e1_baseline.py --dataset unsw_nb15
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import SGDClassifier

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import TABLES, base_parser, build_enriched, get_config, get_flows, get_live_records, write_json  # noqa: E402

from cti_pipeline.data import build_design  # noqa: E402
from cti_pipeline.enrich import CTI_FEATURES  # noqa: E402
from cti_pipeline.model import make_model, make_splits, metrics_at, tune_threshold  # noqa: E402


def comparators(cfg):
    return {
        "random_forest": ("Random Forest", make_model(cfg)),
        "gradient_boosting": ("Gradient Boosting", HistGradientBoostingClassifier(
            max_iter=250, learning_rate=0.1, random_state=cfg.model.seed)),
        "linear_svm": ("Linear SVM", SGDClassifier(
            loss="hinge", alpha=1e-4, max_iter=1500, random_state=cfg.model.seed,
            early_stopping=True, validation_fraction=0.1)),
    }


def main() -> None:
    parser = base_parser("E1 - baseline reproduction")
    parser.add_argument("--no-poll", action="store_true")
    parser.add_argument("--with-cti", action="store_true",
                        help="also score the CTI-augmented feature set")
    args = parser.parse_args()
    cfg = get_config(args)

    flows = get_flows(cfg, args.dataset)
    live = get_live_records(cfg, poll=not args.no_poll)
    frame, _, summary = build_enriched(cfg, flows, live,
                                       interval_min=cfg.cti.poll_interval_min)
    X_cti, y = build_design(frame, include_cti=True, cti_cols=CTI_FEATURES)
    cti_cols = [c for c in CTI_FEATURES if c in X_cti.columns]
    variants = {"traffic_only": X_cti.drop(columns=cti_cols)}
    if args.with_cti:
        variants["traffic_cti"] = X_cti

    splits = make_splits(y, cfg.data.test_size, cfg.data.val_size, cfg.model.seed)
    rows = []
    for variant, X in variants.items():
        for key, (label, model) in comparators(cfg).items():
            t0 = time.time()
            model.fit(X.iloc[splits.train], y[splits.train])
            scores_val = (model.predict_proba(X.iloc[splits.val])[:, 1]
                          if hasattr(model, "predict_proba")
                          else model.decision_function(X.iloc[splits.val]))
            scores_test = (model.predict_proba(X.iloc[splits.test])[:, 1]
                           if hasattr(model, "predict_proba")
                           else model.decision_function(X.iloc[splits.test]))
            theta = tune_threshold(y[splits.val], scores_val, cfg.model.target_recall)
            m = metrics_at(y[splits.test], scores_test, theta)
            rows.append({"variant": variant, "model": label, **m,
                         "seconds": round(time.time() - t0, 1)})
            print(f"[{variant}] {label:18s} acc={m['accuracy']:.4f} f1={m['f1']:.4f} "
                  f"recall={m['recall']:.3f} fpr={m['fpr']:.5f} pr_auc={m['pr_auc']:.4f} "
                  f"({time.time() - t0:.0f}s)", flush=True)

    frame_df = pd.DataFrame(rows)
    frame_df.to_csv(TABLES / f"e1_baseline_{args.dataset}.csv", index=False)
    write_json(TABLES / f"e1_baseline_{args.dataset}.json",
               {"dataset": args.dataset, "target_recall": cfg.model.target_recall,
                "sightings_summary": summary, "rows": rows})
    print(frame_df[["variant", "model", "accuracy", "precision", "recall", "f1",
                    "pr_auc", "fpr"]].to_string(index=False))


if __name__ == "__main__":
    main()
