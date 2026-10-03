"""Compare RF tree size / TreeSHAP cost for different min_samples_leaf."""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import shap

from _common import base_parser, build_enriched, get_config, get_flows, get_live_records
from cti_pipeline.data import build_design
from cti_pipeline.enrich import CTI_FEATURES
from cti_pipeline.model import make_model

parser = base_parser("leaf cost test")
parser.add_argument("--no-poll", action="store_true")
args = parser.parse_args()
cfg = get_config(args)

flows = get_flows(cfg, args.dataset)
live = get_live_records(cfg, poll=not args.no_poll)
frame, _, _ = build_enriched(cfg, flows, live, interval_min=cfg.cti.poll_interval_min)
X, y = build_design(frame, include_cti=True, cti_cols=CTI_FEATURES)
print(f"rows={len(X):,} feats={X.shape[1]}")

for leaf in (2, 20, 50):
    cfg.model.min_samples_leaf = leaf
    t0 = time.time()
    model = make_model(cfg)
    model.fit(X, y)
    fit = time.time() - t0
    nodes = [e.tree_.node_count for e in model.estimators_[:5]]
    explainer = shap.TreeExplainer(model)
    t0 = time.time()
    explainer.shap_values(X.iloc[:200])
    dt = time.time() - t0
    print(f"leaf={leaf:3d} fit={fit:5.1f}s nodes(sample5)={nodes} "
          f"shap200={dt:5.1f}s -> per 500-row fold ~{dt * 2.5 / 60:.1f} min")
