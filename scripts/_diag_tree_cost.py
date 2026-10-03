"""Measure RF tree size and TreeSHAP cost at full scale (why E4 is slow)."""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import numpy as np
import shap

from _common import base_parser, build_enriched, get_config, get_flows, get_live_records
from cti_pipeline.data import build_design
from cti_pipeline.enrich import CTI_FEATURES
from cti_pipeline.model import make_model

parser = base_parser("tree cost diagnostic")
parser.add_argument("--no-poll", action="store_true")
args = parser.parse_args()
cfg = get_config(args)

flows = get_flows(cfg, args.dataset)
live = get_live_records(cfg, poll=not args.no_poll)
frame, _, summary = build_enriched(cfg, flows, live, interval_min=cfg.cti.poll_interval_min)
X, y = build_design(frame, include_cti=True, cti_cols=CTI_FEATURES)
print(f"rows={len(X):,} feats={X.shape[1]}")

t0 = time.time()
model = make_model(cfg)
model.fit(X, y)
print(f"fit {cfg.model.n_estimators} trees: {time.time() - t0:.1f}s")
print("nodes/tree:", [e.tree_.node_count for e in model.estimators_[:5]])
print("depth/tree:", [e.tree_.max_depth for e in model.estimators_[:5]])

explainer = shap.TreeExplainer(model)
for n in (50, 200):
    t0 = time.time()
    phi = explainer.shap_values(X.iloc[:n])
    dt = time.time() - t0
    print(f"shap({n} rows): {dt:.1f}s shape={np.shape(phi)} "
          f"-> {dt / n * 500 / 60:.1f} min per 500-row fold")
