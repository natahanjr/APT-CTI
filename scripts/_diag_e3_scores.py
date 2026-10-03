"""Diagnose E3 score collapse on CICIDS2017: same model, features at 5 min vs 1 h."""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import numpy as np

from _common import (  # noqa: E402
    base_parser, build_enriched, get_config, get_flows, get_live_records, get_sightings,
)
from cti_pipeline.data import build_design  # noqa: E402
from cti_pipeline.enrich import CTI_FEATURES, coverage_stats  # noqa: E402
from cti_pipeline.model import make_model, make_splits, metrics_at, tune_threshold  # noqa: E402

parser = base_parser("E3 collapse diagnostic")
parser.add_argument("--no-poll", action="store_true")
parser.add_argument("--intervals", type=float, nargs="+", default=[5, 60])
args = parser.parse_args()
cfg = get_config(args)

flows = get_flows(cfg, args.dataset)
live = get_live_records(cfg, poll=not args.no_poll)
sightings, summary = get_sightings(cfg, flows, live)

frame_ref, _, _ = build_enriched(cfg, flows, live, interval_min=cfg.cti.poll_interval_min,
                                 sightings=(sightings, summary))
X, y = build_design(frame_ref, include_cti=True, cti_cols=CTI_FEATURES)
splits = make_splits(y, cfg.data.test_size, cfg.data.val_size, cfg.model.seed)

model = make_model(cfg)
model.fit(X.iloc[splits.train], y[splits.train])
theta = tune_threshold(y[splits.val], model.predict_proba(X.iloc[splits.val])[:, 1],
                       cfg.model.target_recall)
print(f"reference theta={theta:.6f}")

for interval in args.intervals:
    frame_i, _, _ = build_enriched(cfg, flows, live, interval_min=interval,
                                   sightings=(sightings, summary))
    X_i, _ = build_design(frame_i, include_cti=True, cti_cols=CTI_FEATURES)
    X_i = X_i.reindex(columns=X.columns, fill_value=0.0)
    proba = model.predict_proba(X_i.iloc[splits.test])[:, 1]
    pos, neg = proba[y[splits.test] == 1], proba[y[splits.test] == 0]
    m = metrics_at(y[splits.test], proba, theta)
    cov = coverage_stats(frame_i.iloc[splits.test], y[splits.test],
                         age=frame_i.attrs["age_seconds"][splits.test])
    q = [0.5, 0.9, 0.96, 0.99]
    print(f"\ninterval={interval:g} min  recall@theta={m['recall']:.4f} "
          f"fpr={m['fpr']:.5f} coverage(mal)={cov['coverage_malicious']:.4f}")
    print("  pos proba quantiles:", {f"p{int(k * 100)}": round(float(np.quantile(pos, k)), 5) for k in q})
    print("  neg proba quantiles:", {f"p{int(k * 100)}": round(float(np.quantile(neg, k)), 5) for k in q})
    print("  frac pos >= theta:", round(float((pos >= theta).mean()), 4))
    top = (pd_series := None)
