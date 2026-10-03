"""Freshness-aware per-flow CTI enrichment (Contribution 1).

The enricher replays a time-ordered flow stream against a feed that is polled
every ``interval_s`` seconds:

* an IoC sighting becomes visible at the first poll boundary at/after it;
* an indicator expires if no sighting landed within the TTL window;
* ``feed_age_score = 0.5 ** (age / half_life)`` encodes freshness decay.

Sightings come from two provenances:

``live``       IoCs actually returned by the public feeds (via the collector);
``injected``   ground-truth IPs taken from malicious benchmark flows -- the
               controlled-injection fallback documented in the proposal's risk
               table, needed because 2017-era benchmark addresses are absent
               from today's feeds.

Both are merged per indicator value, so live-feed overlap is always measured
and reported rather than hidden.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

CTI_FEATURES = [
    "ioc_src_match", "ioc_dst_match", "feed_age_score",
    "feed_confidence", "source_count", "reputation_bucket",
]

T0_OFFSET_S = 0.0


@dataclass(frozen=True)
class ReplaySettings:
    interval_s: float
    ttl_s: float
    half_life_s: float
    t0: float = T0_OFFSET_S


def poll_grid(time_s: np.ndarray, settings: ReplaySettings) -> np.ndarray:
    """Round each sighting time up to the next poll boundary (first visibility)."""
    dt = settings.interval_s
    if dt <= 1e-9:
        return time_s.copy()
    return settings.t0 + np.ceil((time_s - settings.t0) / dt) * dt


def build_sightings(
    flows: pd.DataFrame,
    live_records: list | None = None,
    injection: str = "controlled",
    injection_rate: float = 0.6,
    benign_ioc_rate: float = 0.004,
    seed: int = 42,
) -> tuple[dict[str, tuple[np.ndarray, np.ndarray, np.ndarray]], dict]:
    """Merge live-feed IoCs and (optionally) injected ground-truth IoCs.

    Returns {value: (times, confidences, source_counts)} sorted by time plus a
    provenance summary.
    """
    per_value: dict[str, list[tuple[float, float, int]]] = {}
    multi_role: set[str] = set()

    if injection == "controlled":
        rng = np.random.default_rng(seed)
        mal = flows.loc[flows["label"] == 1, ["src_ip", "dst_ip", "ts"]]
        benign = flows.loc[flows["label"] == 0, ["src_ip", "dst_ip", "ts"]]
        mal_ips = pd.unique(pd.concat([mal["src_ip"], mal["dst_ip"]]).dropna().astype(str))
        benign_ips = pd.unique(pd.concat([benign["src_ip"], benign["dst_ip"]]).dropna().astype(str))
        mal_set = set(mal_ips)
        benign_ips = np.array([i for i in benign_ips if i not in mal_set], dtype=object)

        selected = set(rng.choice(mal_ips, size=max(1, int(len(mal_ips) * injection_rate)),
                                  replace=False).tolist())
        noise = set()
        if benign_ioc_rate > 0 and len(benign_ips):
            take = max(1, int(len(benign_ips) * benign_ioc_rate))
            noise = set(rng.choice(benign_ips, size=take, replace=False).tolist())

        seen_src = set(mal["src_ip"].dropna().astype(str).unique())
        seen_dst = set(mal["dst_ip"].dropna().astype(str).unique())
        multi_role = seen_src & seen_dst

        for col in ("src_ip", "dst_ip"):
            sub = flows[[col, "ts", "label"]].dropna()
            sub = sub[sub[col].astype(str).isin(selected | noise)]
            for ip, group in sub.groupby(col, observed=True):
                for t in np.unique(group["ts"].to_numpy(dtype="float64")):
                    per_value.setdefault(str(ip), []).append((float(t), -1.0, -1))

    for rec in live_records or []:
        per_value.setdefault(rec.value, []).append(
            (float(rec.first_seen), float(rec.confidence), -2)
        )
        if rec.last_seen != rec.first_seen:
            per_value.setdefault(rec.value, []).append(
                (float(rec.last_seen), float(rec.confidence), -2)
            )

    out: dict[str, tuple[np.ndarray, np.ndarray, np.ndarray]] = {}
    n_live = n_injected = 0
    for value, entries in per_value.items():
        entries.sort(key=lambda e: e[0])
        times = np.fromiter((e[0] for e in entries), dtype="float64", count=len(entries))
        confs = np.empty(len(entries), dtype="float64")
        srcs = np.empty(len(entries), dtype="int16")
        rank = np.arange(1, len(entries) + 1, dtype="float64")
        # controlled-injection model: confidence and corroboration grow with evidence
        conf_model = np.minimum(0.95, 0.45 + 0.07 * (rank - 1))
        src_model = np.minimum(3, 1 + (rank >= 2).astype(np.int8) + (rank >= 5).astype(np.int8))
        corroborated = injection == "controlled" and value in multi_role
        for i, (_, conf, marker) in enumerate(entries):
            if marker == -2:  # live feed record
                confs[i] = conf
                srcs[i] = 1
                n_live += 1
            else:
                confs[i] = conf_model[i]
                srcs[i] = int(min(3, src_model[i] + (1 if corroborated else 0)))
                n_injected += 1
        out[value] = (times, confs, srcs)

    summary = {
        "n_indicators": len(out),
        "n_sightings_live": n_live,
        "n_sightings_injected": n_injected,
        "n_multi_source": int(sum(
            1 for v, (_, _, s) in out.items() if s.max() > 1)),
        "injection": injection,
        "injection_rate": injection_rate,
        "benign_ioc_rate": benign_ioc_rate,
    }
    return out, summary


def _endpoint_state(
    ip: pd.Series, ts: np.ndarray, sightings, settings: ReplaySettings
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """For every flow endpoint return (visible, age, confidence, sources)."""
    n = len(ts)
    visible = np.zeros(n, dtype=bool)
    age = np.full(n, np.inf, dtype="float64")
    conf = np.zeros(n, dtype="float64")
    srcs = np.zeros(n, dtype="int16")

    values = ip.astype(str).to_numpy()
    order = np.argsort(values, kind="mergesort")
    sorted_vals = values[order]
    boundaries = np.searchsorted(sorted_vals, np.unique(sorted_vals))
    unique_vals = sorted_vals[boundaries]

    starts = np.append(boundaries, n)
    for idx, value in enumerate(unique_vals):
        if value not in sightings:
            continue
        rows = order[starts[idx]:starts[idx + 1]]
        if rows.size == 0:
            continue
        t = ts[rows]
        s_times, s_conf, s_srcs = sightings[value]
        # a sighting becomes visible AT its poll boundary: search over poll
        # times (not raw sighting times) so the flow's own sighting - whose
        # boundary lies in the future - can never leak into the features.
        poll_times = poll_grid(s_times, settings)
        k = np.searchsorted(poll_times, t, side="right") - 1
        valid = k >= 0
        if not valid.any():
            continue
        sel = k[valid]
        poll_t = poll_times[sel]
        age_v = t[valid] - poll_t
        ok = age_v <= settings.ttl_s
        rows_ok = rows[valid][ok]
        if rows_ok.size == 0:
            continue
        visible[rows_ok] = True
        age[rows_ok] = age_v[ok]
        conf[rows_ok] = s_conf[sel][ok]
        srcs[rows_ok] = s_srcs[sel][ok]
    return visible, age, conf, srcs


def enrich(flows: pd.DataFrame, sightings, settings: ReplaySettings) -> pd.DataFrame:
    """Build the six CTI features for a time-ordered flow frame."""
    ts = flows["ts"].to_numpy(dtype="float64")
    v_src, age_s, conf_s, src_s = _endpoint_state(flows["src_ip"], ts, sightings, settings)
    v_dst, age_d, conf_d, src_d = _endpoint_state(flows["dst_ip"], ts, sightings, settings)

    # best match = highest-confidence visible endpoint (dst wins ties: C2/malware host)
    use_dst = v_dst & (~v_src | (conf_d >= conf_s))
    use_src = v_src & ~use_dst

    out = pd.DataFrame(index=flows.index)
    out["ioc_src_match"] = use_src.astype(np.float32)
    out["ioc_dst_match"] = use_dst.astype(np.float32)
    age = np.where(use_dst, age_d, np.where(use_src, age_s, np.inf))
    conf = np.where(use_dst, conf_d, np.where(use_src, conf_s, 0.0))
    sources = np.where(use_dst, src_d, np.where(use_src, src_s, 0)).astype(np.int32)

    half_life = max(settings.half_life_s, 1e-6)
    age_score = np.where(np.isfinite(age), 0.5 ** (age / half_life), 0.0)
    out["feed_age_score"] = age_score.astype(np.float32)
    out["feed_confidence"] = conf.astype(np.float32)
    out["source_count"] = sources.astype(np.float32)
    bucket = np.zeros(len(out), dtype=np.float32)
    bucket[(conf > 0)] = 1
    bucket[(conf >= 0.6)] = 2
    bucket[(conf >= 0.8)] = 3
    out["reputation_bucket"] = bucket

    out.attrs["age_seconds"] = age
    out.attrs["coverage"] = float(np.mean((use_src | use_dst)))
    return out


def coverage_stats(feats: pd.DataFrame, labels: np.ndarray,
                   age: np.ndarray | None = None) -> dict:
    """IoC coverage metrics used by the freshness sweep."""
    matched = (feats["ioc_src_match"] + feats["ioc_dst_match"]) > 0
    if age is None:
        age = feats.attrs.get("age_seconds", None)
    if age is None or len(age) != len(feats):
        age = np.array([])
    stats = {
        "coverage_all": float(matched.mean()) if len(matched) else 0.0,
        "coverage_malicious": float(matched[labels == 1].mean()) if (labels == 1).any() else 0.0,
        "coverage_benign": float(matched[labels == 0].mean()) if (labels == 0).any() else 0.0,
    }
    if age.size and np.isfinite(age[matched.to_numpy()]).any():
        vals = age[matched.to_numpy()]
        vals = vals[np.isfinite(vals)]
        stats["median_age_min"] = float(np.median(vals) / 60.0)
        stats["p90_age_min"] = float(np.percentile(vals, 90) / 60.0)
    else:
        stats["median_age_min"] = float("nan")
        stats["p90_age_min"] = float("nan")
    return stats
