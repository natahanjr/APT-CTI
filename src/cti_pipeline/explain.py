"""TreeSHAP alert explanations: reason codes + stability audit (Contribution 4)."""

from __future__ import annotations

from collections import Counter
from itertools import combinations

import numpy as np
import pandas as pd
import shap

from .attack_map import map_feature
from .enrich import CTI_FEATURES


# --------------------------------------------------------------------------
# SHAP computation
# --------------------------------------------------------------------------
def make_explainer(model) -> shap.TreeExplainer:
    return shap.TreeExplainer(model)


def shap_matrix(explainer: shap.TreeExplainer, X: pd.DataFrame) -> np.ndarray:
    """Return an (n, m) SHAP matrix for the malicious class."""
    values = explainer.shap_values(X)
    if isinstance(values, list):          # older shap: [class0, class1]
        values = values[-1]
    values = np.asarray(values, dtype="float64")
    if values.ndim == 3:                 # shap >= 0.50: (n, m, n_classes)
        values = values[..., -1]
    if values.ndim != 2:
        raise ValueError(f"unexpected SHAP shape {values.shape}")
    return values


def global_ranking(shap_vals: np.ndarray, columns: list[str], k: int = 10) -> list[str]:
    """Top-k features by mean |SHAP|."""
    strength = np.abs(shap_vals).mean(axis=0)
    order = np.argsort(strength)[::-1]
    return [columns[i] for i in order[:k]]


def ranking_strength(shap_vals: np.ndarray, columns: list[str]) -> pd.Series:
    return pd.Series(np.abs(shap_vals).mean(axis=0), index=columns).sort_values(ascending=False)


# --------------------------------------------------------------------------
# Reason codes
# --------------------------------------------------------------------------
_TEMPLATES = {
    "ioc_src_match": "source IP appears on a live CTI feed",
    "ioc_dst_match": "destination IP appears on a live CTI feed",
    "feed_age_score": "intel freshness score {val:.2f} (higher = fresher sighting)",
    "feed_confidence": "feed confidence {val:.2f}",
    "source_count": "{val:.0f} independent feed(s) report this indicator",
    "reputation_bucket": "indicator reputation tier {val:.0f}/3",
}

_PRETTY = {
    "sttl": "source TTL", "dttl": "destination TTL",
    "ct_state_ttl": "connection-state TTL class",
    "Sload": "uplink bit-rate", "Dload": "downlink bit-rate",
    "sbytes": "uplink bytes", "dbytes": "downlink bytes",
    "Spkts": "uplink packets", "Dpkts": "downlink packets",
    "smeansz": "mean uplink segment size", "dmeansz": "mean downlink segment size",
    "dur": "flow duration", "rate": "packet rate",
    "Sintpkt": "uplink inter-arrival time", "Dintpkt": "downlink inter-arrival time",
    "Sjit": "uplink jitter", "Djit": "downlink jitter",
    "synack": "SYN-ACK delay", "ackdat": "ACK delay", "tcprtt": "TCP RTT",
    "swin": "source TCP window", "dwin": "dest TCP window",
    "ct_srv_src": "distinct services from source", "ct_srv_dst": "distinct services to dest",
    "ct_dst_ltm": "flows to same dest (recent)", "ct_src_ltm": "flows from same src (recent)",
    "ct_dst_src_ltm": "src-dst flow count (recent)",
    "ct_src_dport_ltm": "flows to same dport (recent)",
    "ct_dst_sport_ltm": "flows from same sport (recent)",
    "ct_flw_http_mthd": "HTTP methods seen", "is_ftp_login": "FTP login flag",
    "trans_depth": "HTTP transaction depth", "res_bdy_len": "HTTP response body length",
}


def _describe(name: str, val: float) -> str:
    if name.startswith("state_"):
        return f"connection state = {name.split('_', 1)[1]}"
    if name.startswith("service_"):
        return f"service = {name.split('_', 1)[1]}"
    if name.startswith("proto_"):
        return f"protocol = {name.split('_', 1)[1]}"
    if name.startswith("flag_") or name.endswith("_flag"):
        return f"{name.replace('_', ' ')} = {val:g}"
    label = _PRETTY.get(name, name.replace("_", " "))
    return f"{label} = {val:g}"


def reason_codes(row_values: pd.Series, phi: np.ndarray, columns: list[str],
                 k: int = 3, attack_lookup: bool = True) -> list[dict]:
    """Rank this flow's features by positive SHAP contribution and verbalise top-k."""
    contributions = [(i, float(phi[i])) for i in range(len(columns)) if phi[i] > 0]
    contributions.sort(key=lambda t: t[1], reverse=True)
    out: list[dict] = []
    for idx, value in contributions[:k]:
        name = columns[idx]
        val = float(row_values.get(name, 0.0))
        template = _TEMPLATES.get(name)
        text = template.format(val=val) if template else _describe(name, val)
        ref = map_feature(name) if attack_lookup else None
        out.append({
            "feature": name,
            "value": round(val, 4),
            "shap": round(value, 5),
            "reason": text,
            "tactic": ref.tactic if ref else "",
            "technique": ref.technique if ref else "",
        })

    # an active IoC match is always worth surfacing, even when a traffic feature
    # contributes more raw risk (it is the one actionable, feed-backed fact)
    ioc_src = float(row_values.get("ioc_src_match", 0.0))
    ioc_dst = float(row_values.get("ioc_dst_match", 0.0))
    if (ioc_src or ioc_dst) and not any(c["feature"] in CTI_FEATURES for c in out):
        side = "destination" if ioc_dst else "source"
        name = "ioc_dst_match" if ioc_dst else "ioc_src_match"
        ref = map_feature(name) if attack_lookup else None
        out.append({
            "feature": name,
            "value": 1.0,
            "shap": None,
            "reason": (f"{side} IP is on the live CTI feed "
                       f"(freshness {float(row_values.get('feed_age_score', 0)):.2f}, "
                       f"confidence {float(row_values.get('feed_confidence', 0)):.2f}, "
                       f"{int(row_values.get('source_count', 0))} source(s))"),
            "tactic": ref.tactic if ref else "",
            "technique": ref.technique if ref else "",
        })

    if not out:  # never emit an unexplained alert
        out.append({
            "feature": "-", "value": 0.0, "shap": 0.0,
            "reason": "model score driven by negative (risk-reducing) contributions only",
            "tactic": "Uncategorised", "technique": "-",
        })
    return out


def explain_alerts(model, X: pd.DataFrame, y: np.ndarray, columns: list[str],
                   theta: float, top_k: int = 3, limit: int = 500,
                   attack_cat: np.ndarray | None = None,
                   timestamps: np.ndarray | None = None) -> list[dict]:
    """Explain up to ``limit`` alerting flows (probability >= theta)."""
    proba = model.predict_proba(X)[:, 1]
    alert_idx = np.flatnonzero(proba >= theta)
    if alert_idx.size > limit:  # deterministic sample, keeps runs reproducible
        alert_idx = np.sort(np.random.default_rng(42).choice(alert_idx, limit, replace=False))
    if alert_idx.size == 0:
        return []
    explainer = make_explainer(model)
    phi = shap_matrix(explainer, X.iloc[alert_idx])
    rows = []
    for pos, i in enumerate(alert_idx):
        codes = reason_codes(X.iloc[i], phi[pos], columns, k=top_k)
        rows.append({
            "row": int(i),
            "score": round(float(proba[i]), 4),
            "theta": round(float(theta), 4),
            "label": int(y[i]),
            "attack_cat": str(attack_cat[i]) if attack_cat is not None else "",
            "timestamp": float(timestamps[i]) if timestamps is not None else 0.0,
            "reason_codes": codes,
        })
    return rows


# --------------------------------------------------------------------------
# Stability audit
# --------------------------------------------------------------------------
def jaccard(a: list[str] | set, b: list[str] | set) -> float:
    a, b = set(a), set(b)
    if not a and not b:
        return 1.0
    return len(a & b) / len(a | b)


def top_k_jaccard(rankings: list[list[str]], k: int = 10) -> dict:
    """Pairwise Jaccard similarity of top-k feature lists across folds."""
    tops = [list(r[:k]) for r in rankings]
    pairs = [(jaccard(a, b), a, b) for a, b in combinations(tops, 2)]
    if not pairs:
        return {"mean": 1.0, "min": 1.0, "pairs": []}
    vals = [p[0] for p in pairs]
    return {"mean": float(np.mean(vals)), "min": float(np.min(vals)),
            "pairs": [float(v) for v in vals]}


def tactic_distribution(ranking: pd.Series) -> dict[str, float]:
    """Share of total |SHAP| mass per ATT&CK tactic."""
    weights = ranking.abs()
    tactics = Counter()
    for name, w in weights.items():
        tactics[map_feature(name).tactic] += float(w)
    total = sum(tactics.values()) or 1.0
    return {k: v / total for k, v in tactics.most_common()}


def tactic_stability(dists: list[dict[str, float]]) -> dict:
    """Stability of ATT&CK-level explanation structure across folds."""
    keys = sorted({k for d in dists for k in d})
    vecs = np.array([[d.get(k, 0.0) for k in keys] for d in dists])
    top_sets = [
        [k for k, _ in sorted(d.items(), key=lambda kv: -kv[1])[:4]] for d in dists
    ]
    jac = top_k_jaccard(top_sets, k=4)
    # total variation distance between every pair of fold distributions
    tv = []
    for i, j in combinations(range(len(dists)), 2):
        tv.append(0.5 * float(np.abs(vecs[i] - vecs[j]).sum()))
    return {
        "mean_top4_jaccard": jac["mean"],
        "mean_tv_distance": float(np.mean(tv)) if tv else 0.0,
        "mean_distribution": {k: float(v) for k, v in
                              zip(keys, vecs.mean(axis=0))},
        "top_tactics_per_fold": top_sets,
    }
