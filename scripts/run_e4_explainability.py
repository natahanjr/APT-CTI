"""Contribution 4 (E4) - TreeSHAP reason codes + ATT&CK stability audit.

Answers RQ3/H3: rank stability of top-10 features across folds (Jaccard >= 0.7)
and alignment of emitted reason codes with MITRE ATT&CK tactic categories.

    python scripts/run_e4_explainability.py --dataset unsw_nb15
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold, train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (  # noqa: E402
    ROOT, TABLES, base_parser, build_enriched, get_config, get_flows, get_live_records, write_json,
)

from cti_pipeline.data import build_design  # noqa: E402
from cti_pipeline.enrich import CTI_FEATURES  # noqa: E402
from cti_pipeline.explain import (  # noqa: E402
    explain_alerts, global_ranking, make_explainer, ranking_strength, shap_matrix,
    tactic_distribution, tactic_stability, top_k_jaccard,
)
from cti_pipeline.model import make_model, make_splits, metrics_at, tune_threshold  # noqa: E402


def main() -> None:
    parser = base_parser("E4 - SHAP reason codes + ATT&CK audit (RQ3/H3)")
    parser.add_argument("--no-poll", action="store_true")
    parser.add_argument("--alerts", type=int, default=300, help="alerts to explain")
    args = parser.parse_args()
    cfg = get_config(args)

    flows = get_flows(cfg, args.dataset)
    live = get_live_records(cfg, poll=not args.no_poll)
    frame, _, summary = build_enriched(cfg, flows, live,
                                       interval_min=cfg.cti.poll_interval_min)
    X, y = build_design(frame, include_cti=True, cti_cols=CTI_FEATURES)
    columns = list(X.columns)
    splits = make_splits(y, cfg.data.test_size, cfg.data.val_size, cfg.model.seed)
    trainval = np.concatenate([splits.train, splits.val])
    print(f"[design] rows={len(y):,} features={len(columns)}")

    # ---- fold-wise SHAP rankings (H3) -----------------------------------
    skf = StratifiedKFold(n_splits=cfg.model.cv_folds, shuffle=True, random_state=cfg.model.seed)
    rankings: list[list[str]] = []
    strength_frames: list[pd.Series] = []
    fold_metrics: list[dict] = []
    shap_rows = []
    sample_per_fold = max(500, cfg.model.shap_sample // cfg.model.cv_folds)

    for fold, (tr, te) in enumerate(skf.split(X.iloc[trainval], y[trainval]), start=1):
        abs_idx = trainval[tr], trainval[te]
        tr_rel, va = train_test_split(abs_idx[0], test_size=0.2,
                                      random_state=cfg.model.seed, stratify=y[abs_idx[0]])
        t0 = time.time()
        model = make_model(cfg)
        model.fit(X.iloc[tr_rel], y[tr_rel])
        theta = tune_threshold(y[va], model.predict_proba(X.iloc[va])[:, 1],
                               cfg.model.target_recall)
        m = metrics_at(y[abs_idx[1]], model.predict_proba(X.iloc[abs_idx[1]])[:, 1], theta)
        m["fold"] = fold
        fold_metrics.append(m)

        rng = np.random.default_rng(cfg.model.seed + fold)
        idx = abs_idx[1] if len(abs_idx[1]) <= sample_per_fold else \
            np.sort(rng.choice(abs_idx[1], sample_per_fold, replace=False))
        explainer = make_explainer(model)
        phi = shap_matrix(explainer, X.iloc[idx])
        strength = ranking_strength(phi, columns)
        strength_frames.append(strength)
        rankings.append(list(strength.sort_values(ascending=False).index))
        shap_rows.append(phi)
        print(f"  fold {fold}: recall={m['recall']:.3f} fpr={m['fpr']:.5f} "
              f"shap={phi.shape} ({time.time() - t0:.0f}s)", flush=True)
        del model, explainer

    stability = top_k_jaccard(rankings, k=10)
    mean_strength = pd.concat(strength_frames, axis=1).mean(axis=1).sort_values(ascending=False)
    top10 = list(mean_strength.index[:10])
    dists = [tactic_distribution(s) for s in strength_frames]
    tac = tactic_stability(dists)

    # ---- final model: emit reason-coded alerts --------------------------
    final = make_model(cfg)
    final.fit(X.iloc[splits.train], y[splits.train])
    theta = tune_threshold(y[splits.val], final.predict_proba(X.iloc[splits.val])[:, 1],
                           cfg.model.target_recall)
    test_metrics = metrics_at(y[splits.test],
                              final.predict_proba(X.iloc[splits.test])[:, 1], theta)
    alerts = explain_alerts(
        final, X.iloc[splits.test], y[splits.test], columns, theta,
        top_k=cfg.model.top_k_reasons, limit=args.alerts,
        attack_cat=frame["attack_cat"].to_numpy()[splits.test],
        timestamps=frame["ts"].to_numpy()[splits.test],
    )

    alerts_path = ROOT / "results" / "alerts" / f"alerts_{args.dataset}.jsonl"
    alerts_path.parent.mkdir(parents=True, exist_ok=True)
    with open(alerts_path, "w", encoding="utf-8") as fh:
        for row in alerts:
            fh.write(json.dumps(row, default=float) + "\n")

    all_codes = [c for a in alerts for c in a["reason_codes"]]
    cti_codes = [c for c in all_codes if c["feature"] in CTI_FEATURES]
    tactic_counts = pd.Series([c["tactic"] for c in all_codes]).value_counts()
    alerts_with_cti = sum(
        1 for a in alerts if any(c["feature"] in CTI_FEATURES for c in a["reason_codes"]))

    results = {
        "dataset": args.dataset,
        "n_features": len(columns),
        "cv_folds": cfg.model.cv_folds,
        "sightings_summary": summary,
        "fold_metrics": fold_metrics,
        "top10_features": top10,
        "top10_strength": {f: float(mean_strength[f]) for f in top10},
        "stability_top10_jaccard": stability,
        "h3_jaccard_mean": stability["mean"],
        "h3_pass": stability["mean"] >= 0.7,
        "tactic_stability": tac,
        "test_metrics": test_metrics,
        "theta": theta,
        "n_alerts_explained": len(alerts),
        "alerts_with_cti_reason": alerts_with_cti,
        "alert_cti_reason_share": (alerts_with_cti / len(alerts)) if alerts else 0.0,
        "reason_tactic_distribution": {k: int(v) for k, v in tactic_counts.items()},
        "alerts_path": str(alerts_path),
        "example_alerts": alerts[:5],
    }
    write_json(TABLES / f"e4_explain_{args.dataset}.json", results)

    pd.DataFrame([{f: float(mean_strength[f]) for f in top10},
                  ]).to_csv(TABLES / f"e4_top_features_{args.dataset}.csv", index=False)
    print("\n[top-10 features]", ", ".join(top10))
    print(f"[H3] mean top-10 Jaccard across folds = {stability['mean']:.3f} "
          f"(min {stability['min']:.3f}) -> {'PASS' if results['h3_pass'] else 'FAIL'}")
    print(f"[ATT&CK] tactic stability: mean top-4 Jaccard = {tac['mean_top4_jaccard']:.3f}, "
          f"mean TV distance = {tac['mean_tv_distance']:.3f}")
    print(f"[alerts] explained {len(alerts)}, CTI present in "
          f"{results['alert_cti_reason_share'] * 100:.1f}% of alerts -> {alerts_path}")


if __name__ == "__main__":
    main()
