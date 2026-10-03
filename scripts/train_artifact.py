"""Train and persist deployable model bundles (profiles).

Profiles
--------
unsw_full    : thesis E1 design - all UNSW-NB15 native features + 6 CTI features.
               Requires full UNSW-schema flow records (lab / pcap-replay input).
live_netflow : reduced set computable from generic flow records (NetFlow,
               Zeek conn.log, Suricata eve) + 6 CTI features. Trained and
               evaluated on the same UNSW-NB15 protocol so the accuracy delta
               against unsw_full is measurable and reported honestly.

Both bundles freeze: model, exact feature list, theta (>=96% recall on
validation), categorical keep-sets (for train/serve category alignment) and
metrics. Saved to model/deploy_<profile>.joblib; metrics to
results/tables/deploy_profiles.json.

    python scripts/train_artifact.py --no-poll
    python scripts/train_artifact.py --profiles live_netflow --max-rows 100000
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from _common import TABLES, build_enriched, get_config, get_flows, get_live_records  # noqa: E402
from cti_pipeline.data import DROP_FROM_FEATURES, build_design  # noqa: E402
from cti_pipeline.enrich import CTI_FEATURES  # noqa: E402
from cti_pipeline.model import make_splits, make_model, tune_threshold, metrics_at  # noqa: E402

MODEL_DIR = ROOT / "model"

LIVE_NATIVE = [
    "dur", "sbytes", "dbytes", "Spkts", "Dpkts",
    "Sload", "Dload", "smeansz", "dmeansz",
]
LIVE_CATS = ["proto", "service", "state"]
LIVE_DERIVED = ["byte_rate", "pkt_rate", "mean_pkt_size", "fwd_bwd_ratio"]

PROFILES = ("unsw_full", "live_netflow")


def add_derived(df: pd.DataFrame) -> pd.DataFrame:
    dur = pd.to_numeric(df["dur"], errors="coerce").fillna(0.0).clip(lower=0.0)
    sb = pd.to_numeric(df["sbytes"], errors="coerce").fillna(0.0).clip(lower=0.0)
    db = pd.to_numeric(df["dbytes"], errors="coerce").fillna(0.0).clip(lower=0.0)
    sp = pd.to_numeric(df["Spkts"], errors="coerce").fillna(0.0).clip(lower=0.0)
    dp = pd.to_numeric(df["Dpkts"], errors="coerce").fillna(0.0).clip(lower=0.0)
    out = df.copy()
    dur_safe = dur.clip(lower=1e-6)
    out["byte_rate"] = (sb + db) / dur_safe
    out["pkt_rate"] = (sp + dp) / dur_safe
    out["mean_pkt_size"] = (sb + db) / (sp + dp).clip(lower=1.0)
    out["fwd_bwd_ratio"] = sp / dp.clip(lower=1.0)
    return out


def profile_columns(name: str) -> list[str]:
    if name == "unsw_full":
        # exact thesis E1 design: all UNSW-NB15 native features + CTI
        return list(df_native_columns())
    if name == "live_netflow":
        return list(LIVE_NATIVE) + list(LIVE_CATS) + list(LIVE_DERIVED)
    raise KeyError(name)


_NATIVE: list[str] = []


def df_native_columns() -> list[str]:
    return list(_NATIVE)


def keep_sets(df: pd.DataFrame, cat_cols: list[str], min_freq: float = 0.001,
              floor: int = 50) -> dict[str, list]:
    """Mirror data._pool_categories keep-set computation for serve-time alignment."""
    out: dict[str, list] = {}
    for col in cat_cols:
        counts = df[col].value_counts(dropna=False)
        keep = counts[counts >= max(min_freq * len(df), floor)].index
        vals = [str(v) for v in keep if pd.notna(v)]
        out[col] = sorted(vals)
    return out


def main() -> None:
    from _common import base_parser
    ap = base_parser("train deployable model bundles")
    ap.add_argument("--profiles", default="both",
                    help="both | unsw_full | live_netflow")
    ap.add_argument("--no-poll", action="store_true", default=False)
    args = ap.parse_args()

    profiles = PROFILES if args.profiles == "both" else (args.profiles,)
    cfg = get_config(args)

    t0 = time.time()
    flows = get_flows(cfg, "unsw_nb15")
    live = get_live_records(cfg, poll=not args.no_poll)
    frame, _, summary = build_enriched(
        cfg, flows, live, interval_min=cfg.cti.poll_interval_min)
    print(f"[train] enriched {len(frame):,} flows in {time.time()-t0:.0f}s; "
          f"sightings: {summary}", flush=True)

    global _NATIVE
    _NATIVE = [c for c in frame.columns
               if c not in DROP_FROM_FEATURES and c != "dataset"
               and c not in CTI_FEATURES]
    frame = add_derived(frame)

    splits = make_splits(frame["label"].to_numpy(), cfg.data.test_size,
                         cfg.data.val_size, cfg.model.seed)
    results: dict[str, dict] = {}

    for name in profiles:
        print(f"\n[train] profile={name}", flush=True)
        cols = profile_columns(name)
        sub = frame[cols + list(CTI_FEATURES) + ["label"]].copy()
        cat_cols = [c for c in cols
                    if not pd.api.types.is_numeric_dtype(sub[c])
                    and not pd.api.types.is_bool_dtype(sub[c])]
        vocab = keep_sets(sub, cat_cols)

        X, y = build_design(sub, include_cti=True, cti_cols=CTI_FEATURES)
        print(f"  design: {X.shape[0]:,} rows x {X.shape[1]} features "
              f"(cats one-hot: {cat_cols})", flush=True)

        model = make_model(cfg)
        t1 = time.time()
        model.fit(X.iloc[splits.train], y[splits.train])
        fit_s = time.time() - t1
        theta = tune_threshold(y[splits.val],
                               model.predict_proba(X.iloc[splits.val])[:, 1],
                               cfg.model.target_recall)
        test_m = metrics_at(y[splits.test],
                            model.predict_proba(X.iloc[splits.test])[:, 1], theta)
        print(f"  fit {fit_s:.1f}s  test: acc={test_m['accuracy']:.4f} "
              f"recall={test_m['recall']:.4f} fpr={test_m['fpr']:.5f} "
              f"pr_auc={test_m['pr_auc']:.4f} theta={theta:.4f}", flush=True)

        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        bundle = {
            "profile": name,
            "model": model,
            "features": list(X.columns),
            "theta": float(theta),
            "cat_cols": cat_cols,
            "cat_keep": vocab,
            "numeric_cols": [c for c in cols if c not in cat_cols],
            "cti_features": list(CTI_FEATURES),
            "meta": {
                "dataset": "unsw_nb15",
                "rows": int(len(frame)),
                "n_features": int(X.shape[1]),
                "n_estimators": int(cfg.model.n_estimators),
                "min_samples_leaf": int(cfg.model.min_samples_leaf),
                "target_recall": cfg.model.target_recall,
                "seed": int(cfg.model.seed),
                "interval_min": cfg.cti.poll_interval_min,
                "injection": cfg.replay.injection,
                "fit_seconds": round(fit_s, 1),
                "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "test_metrics": test_m,
            },
        }
        path = MODEL_DIR / f"deploy_{name}.joblib"
        joblib.dump(bundle, path)
        print(f"  saved {path}", flush=True)
        results[name] = {
            "bundle": str(path),
            "n_features": int(X.shape[1]),
            "theta": round(float(theta), 4),
            "test": {k: test_m[k] for k in
                     ("accuracy", "precision", "recall", "f1", "pr_auc",
                      "roc_auc", "fpr", "n")},
            "fit_seconds": round(fit_s, 1),
        }

    # honest delta: live profile vs full profile on identical protocol
    if len(results) == 2:
        a, b = results["unsw_full"]["test"], results["live_netflow"]["test"]
        results["delta_live_vs_full"] = {
            "accuracy_pp": round((b["accuracy"] - a["accuracy"]) * 100, 3),
            "recall_pp": round((b["recall"] - a["recall"]) * 100, 3),
            "fpr_abs": b["fpr"] - a["fpr"],
            "pr_auc_pp": round((b["pr_auc"] - a["pr_auc"]) * 100, 3),
        }
        print(f"\n[train] delta (live - full): {results['delta_live_vs_full']}")

    TABLES.mkdir(parents=True, exist_ok=True)
    out = TABLES / "deploy_profiles.json"
    out.write_text(json.dumps(results, indent=2, default=float), encoding="utf-8")
    print(f"[write] {out}")
    print(f"[done] total {time.time()-t0:.0f}s")


if __name__ == "__main__":
    main()
