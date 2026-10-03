"""Render thesis figures from the experiment JSON tables.

    python scripts/make_figures.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
TABLES = ROOT / "results" / "tables"
FIGURES = ROOT / "results" / "figures"
FIGURES.mkdir(parents=True, exist_ok=True)

INK, MUTE, HAIR = "#1d1d1f", "#6e6e73", "#d2d2d7"
ACCENT, GREEN, ORANGE, RED = "#0071e3", "#30d158", "#ff9f0a", "#ff453a"
TACTIC_COLORS = ["#0071e3", "#30d158", "#ff9f0a", "#ff453a", "#5e5ce6",
                 "#bf5af2", "#64d2ff", "#ffd60a", "#8e8e93"]

plt.rcParams.update({
    "font.family": "Segoe UI", "font.size": 10.5, "text.color": INK,
    "axes.labelcolor": INK, "xtick.color": MUTE, "ytick.color": MUTE,
    "axes.edgecolor": HAIR, "figure.facecolor": "white", "axes.facecolor": "white",
    "savefig.facecolor": "white", "axes.grid": True, "grid.color": "#ececef",
    "grid.linewidth": 0.8, "axes.axisbelow": True,
})


def strip(ax, left=False):
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color(HAIR)
    ax.spines["bottom"].set_color(HAIR)
    ax.spines["left"].set_visible(left)


def save(fig, name: str) -> None:
    fig.savefig(FIGURES / name, dpi=200, bbox_inches="tight", pad_inches=0.06)
    plt.close(fig)
    print("wrote", name)


def loads(pattern: str) -> list[dict]:
    return [json.loads(p.read_text(encoding="utf-8"))
            for p in sorted(TABLES.glob(pattern))]


# --------------------------------------------------------------------------
def fig_e2_one(payload: dict) -> None:
    order = ["traffic_only", "traffic_cti", "traffic_cti_no_match", "live_feeds_only"]
    labels = ["Traffic stats\nonly", "Traffic + live CTI\n(controlled injection)",
              "Traffic + CTI\n(IoC-match flags removed)",
              "Traffic + live feeds\n(2017 overlap ~ 0)"]
    variants = {v["variant"]: v for v in payload["variants"]}
    rows = [variants[k] for k in order if k in variants]
    if len(rows) < 2:
        print(f"skip e2 ({payload['dataset']}): not enough variants")
        return

    fpr = [r["split_test"]["fpr"] * 100 for r in rows]
    prauc = [r["split_test"]["pr_auc"] * 100 for r in rows]
    recall = [r["split_test"]["recall"] * 100 for r in rows]
    names = [labels[order.index(r["variant"])] for r in rows]

    fig, axes = plt.subplots(1, 2, figsize=(7.6, 3.3))
    x = np.arange(len(rows))
    bars = axes[0].bar(x, fpr, 0.55, color=[MUTE, ACCENT, GREEN, ORANGE][:len(rows)],
                       zorder=3, edgecolor="white")
    for b, v in zip(bars, fpr):
        axes[0].text(b.get_x() + b.get_width() / 2, v, f"{v:.3f}%", ha="center",
                     va="bottom", fontsize=8.5, fontweight="bold")
    axes[0].set_title("False-positive rate (matched recall)", fontsize=10, color=INK)
    axes[0].set_xticks(x); axes[0].set_xticklabels(names, fontsize=8.4)
    axes[0].set_ylabel("FPR (%)", fontsize=9); axes[0].set_ylim(0, max(fpr) * 1.35)
    strip(axes[0])

    w = 0.38
    axes[1].bar(x - w / 2, prauc, w, label="PR-AUC", color=ACCENT, zorder=3)
    axes[1].bar(x + w / 2, recall, w, label="Recall", color="#8dc4f5", zorder=3)
    for xi, v in zip(x - w / 2, prauc):
        axes[1].text(xi, v, f"{v:.1f}", ha="center", va="bottom", fontsize=7.6)
    for xi, v in zip(x + w / 2, recall):
        axes[1].text(xi, v, f"{v:.1f}", ha="center", va="bottom", fontsize=7.6)
    axes[1].set_title("PR-AUC and recall (%)", fontsize=10, color=INK)
    axes[1].set_xticks(x); axes[1].set_xticklabels(names, fontsize=8.4)
    axes[1].set_ylim(0, 112); axes[1].legend(frameon=False, fontsize=8.4, ncol=2,
                                              loc="lower right")
    strip(axes[1])
    save(fig, f"e2_ablation_{payload['dataset']}.png")


def fig_e3_one(payload: dict) -> None:
    rows = payload["rows"]
    x = np.arange(len(rows))
    recall = [r["recall"] * 100 for r in rows]
    cov = [r["coverage_malicious"] * 100 for r in rows]
    age = [r["median_age_min"] for r in rows]
    fpr = [r.get("matched_fpr", float("nan")) * 100 for r in rows]
    labels = [r["interval_label"] for r in rows]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.8, 3.4))

    ax1.plot(x, recall, "-o", color=ACCENT, lw=2.2, ms=6, zorder=4, label="recall (%)")
    ax1.plot(x, cov, "--s", color=GREEN, lw=1.8, ms=5, zorder=4,
             label="IoC coverage, malicious (%)")
    ax1.set_xticks(x); ax1.set_xticklabels(labels, fontsize=9, rotation=30, ha="right")
    ax1.set_ylabel("detection quality (%)", fontsize=9.5)
    finite = [v for v in recall + cov if not np.isnan(v)]
    ax1.set_ylim(max(0, min(finite) - 8), 103)
    ax1.legend(frameon=False, fontsize=8.4, loc="lower left")
    ax1.set_title("recall and intel coverage", fontsize=10)
    strip(ax1, left=True)

    ax3 = ax1.twinx()
    ax3.grid(False)
    ax3.bar(x, age, 0.45, color="#ffd8a8", zorder=1, label="median IoC age (min)")
    ax3.set_ylabel("median IoC age (min)", fontsize=9.5, color="#c47f00")
    ax3.tick_params(axis="y", colors="#c47f00")
    ax3.set_ylim(0, max(age + [1]) * 1.4)

    ax2.plot(x, fpr, "-^", color=RED, lw=2.2, ms=6, zorder=4,
             label="FPR at matched recall (%)")
    ax2.set_xticks(x); ax2.set_xticklabels(labels, fontsize=9, rotation=30, ha="right")
    ax2.set_ylabel("false-positive rate (%)", fontsize=9.5)
    lo, hi = min(fpr), max(fpr)
    pad = max((hi - lo) * 0.6, 0.01)
    ax2.set_ylim(max(0, lo - pad), hi + pad)
    ax2.legend(frameon=False, fontsize=8.4, loc="upper right")
    ax2.set_title("cost of feed staleness at matched recall", fontsize=10)
    strip(ax2, left=True)
    for xi, v in zip(x, fpr):
        ax2.annotate(f"{v:.3f}", (xi, v), textcoords="offset points",
                     xytext=(0, 7), ha="center", fontsize=7.6, color=RED)

    save(fig, f"e3_freshness_{payload['dataset']}.png")


def fig_e4_one(payload: dict) -> None:
    top = payload["top10_features"]
    strength = payload["top10_strength"]
    names = [t.replace("_", " ") for t in top][::-1]
    vals = [strength[t] for t in top][::-1]

    from cti_pipeline.attack_map import map_feature
    tactics = [map_feature(t).tactic for t in top][::-1]
    uniq = list(dict.fromkeys(tactics))
    colors = {t: TACTIC_COLORS[i % len(TACTIC_COLORS)] for i, t in enumerate(uniq)}

    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    bars = ax.barh(range(len(names)), vals, color=[colors[t] for t in tactics],
                   zorder=3, height=0.62)
    for i, v in enumerate(vals):
        ax.text(v, i, f" {v:.4g}", va="center", fontsize=7.6, color=MUTE)
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(names, fontsize=8.6)
    ax.set_xlabel("mean |SHAP| (importance)", fontsize=9)
    ax.set_xlim(0, max(vals) * 1.25)
    strip(ax, left=False)
    handles = [plt.Rectangle((0, 0), 1, 1, color=colors[t]) for t in uniq]
    ax.legend(handles, uniq, frameon=False, fontsize=8, loc="lower right")
    save(fig, f"e4_top_features_{payload['dataset']}.png")

    # ATT&CK tactic distribution of emitted reason codes
    dist = payload.get("reason_tactic_distribution", {})
    if dist:
        keys = list(dist.keys())
        vals = [dist[k] / sum(dist.values()) * 100 for k in keys]
        fig, ax = plt.subplots(figsize=(5.4, 3.2))
        bars = ax.bar(range(len(keys)), vals,
                      color=[colors.get(k, TACTIC_COLORS[i % len(TACTIC_COLORS)])
                             for i, k in enumerate(keys)], zorder=3)
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v, f"{v:.0f}%", ha="center",
                    va="bottom", fontsize=8)
        ax.set_xticks(range(len(keys)))
        ax.set_xticklabels(keys, fontsize=8.4, rotation=18, ha="right")
        ax.set_ylabel("share of reason codes (%)", fontsize=9)
        ax.set_ylim(0, max(vals) * 1.25)
        strip(ax)
        save(fig, f"e4_tactics_{payload['dataset']}.png")


def fig_e1_one(payload: dict) -> None:
    df = pd.DataFrame(payload["rows"])
    pivot = df.pivot(index="model", columns="variant", values="accuracy")
    fig, ax = plt.subplots(figsize=(5.6, 3.0))
    pivot.plot(kind="bar", ax=ax, color=[ACCENT, ORANGE][:pivot.shape[1]],
               zorder=3, edgecolor="white")
    for c in ax.containers:
        ax.bar_label(c, fmt="%.3f", fontsize=7.4, padding=2)
    ax.set_ylim(max(0.5, pivot.values.min() - 0.03), 1.005)
    ax.set_ylabel("accuracy", fontsize=9)
    ax.set_xticklabels(ax.get_xticklabels(), rotation=0, fontsize=9)
    ax.legend(frameon=False, fontsize=8.4, title="")
    strip(ax, left=True)
    save(fig, f"e1_baseline_{payload['dataset']}.png")


def fig_e5_one(payload: dict) -> None:
    batches = sorted(payload["batch_sizes"], key=lambda k: int(k))
    labels = [f"batch {b}" for b in batches]
    stages = ["enrich", "design", "predict", "explain"]
    stage_colors = {"enrich": "#64d2ff", "design": "#5e5ce6",
                    "predict": ACCENT, "explain": ORANGE}
    p95 = {s: [payload["batch_sizes"][b]["stages"][s]["p95"] * 1000 for b in batches]
            for s in stages}
    total95 = [payload["batch_sizes"][b]["stages"]["total"]["p95"] * 1000 for b in batches]
    total50 = [payload["batch_sizes"][b]["stages"]["total"]["p50"] * 1000 for b in batches]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.8, 3.3))
    x = np.arange(len(batches))
    bottom = np.zeros(len(batches))
    for s in stages:
        vals = np.asarray(p95[s])
        ax1.bar(x, vals, 0.55, bottom=bottom, label=s, color=stage_colors[s],
                zorder=3, edgecolor="white")
        bottom += vals
    ax1.axhline(1000, color=RED, lw=1.4, ls="--", zorder=4)
    ax1.text(len(batches) - 0.45, 1040, "H4 budget: 1 s", color=RED,
             fontsize=8, ha="right")
    for xi, v in zip(x, total95):
        ax1.text(xi, v, f"{v:.0f}", ha="center", va="bottom",
                 fontsize=8.2, fontweight="bold")
    ax1.set_xticks(x); ax1.set_xticklabels(labels, fontsize=9)
    ax1.set_ylabel("latency per batch (ms)", fontsize=9)
    ax1.set_title("p95 by pipeline stage", fontsize=10)
    ax1.set_ylim(0, max(max(total95), 1200) * 1.22)
    ax1.legend(frameon=False, fontsize=8, ncol=2, loc="upper left")
    strip(ax1, left=True)

    w = 0.36
    ax2.bar(x - w / 2, total50, w, label="p50", color=ACCENT, zorder=3)
    ax2.bar(x + w / 2, total95, w, label="p95", color="#8dc4f5", zorder=3)
    for xi, v in zip(x - w / 2, total50):
        ax2.text(xi, v, f"{v:.0f}", ha="center", va="bottom", fontsize=7.6)
    for xi, v in zip(x + w / 2, total95):
        ax2.text(xi, v, f"{v:.0f}", ha="center", va="bottom", fontsize=7.6)
    ax2.axhline(1000, color=RED, lw=1.4, ls="--", zorder=4)
    ax2.set_xticks(x); ax2.set_xticklabels(labels, fontsize=9)
    ax2.set_ylabel("end-to-end latency (ms)", fontsize=9)
    ax2.set_title("total path: enrich → predict → explain", fontsize=10)
    ax2.set_ylim(0, max(max(total95), 1200) * 1.22)
    ax2.legend(frameon=False, fontsize=8.4, loc="upper left")
    strip(ax2, left=True)
    save(fig, f"e5_latency_{payload['dataset']}.png")


def fig_e6_one(payload: dict) -> None:
    dirs = payload["directions"]
    order = [k for k in ("unsw_nb15_to_cicids2017", "cicids2017_to_unsw_nb15")
             if k in dirs]
    labels = ["UNSW → CICIDS", "CICIDS → UNSW"]
    cross_r = [dirs[k]["cross_target_test"]["recall"] * 100 for k in order]
    dom_r = [dirs[k]["in_domain_target_test"]["recall"] * 100 for k in order]
    cross_p = [dirs[k]["cross_target_test"]["pr_auc"] * 100 for k in order]
    dom_p = [dirs[k]["in_domain_target_test"]["pr_auc"] * 100 for k in order]
    cross_f = [dirs[k]["cross_target_test"]["fpr"] * 100 for k in order]
    dom_f = [dirs[k]["in_domain_target_test"]["fpr"] * 100 for k in order]

    fig, axes = plt.subplots(1, 2, figsize=(7.8, 3.3))
    x = np.arange(len(order))
    w = 0.36
    for ax, cross, dom, title, fmt in (
        (axes[0], cross_r, dom_r, "recall on target test set (%)", "{:.1f}"),
        (axes[1], cross_p, dom_p, "PR-AUC on target test set (%)", "{:.1f}"),
    ):
        ax.bar(x - w / 2, dom, w, label="in-domain", color=ACCENT, zorder=3)
        ax.bar(x + w / 2, cross, w, label="cross-dataset", color=RED, zorder=3)
        for xi, v in zip(x - w / 2, dom):
            ax.text(xi, v, fmt.format(v), ha="center", va="bottom", fontsize=7.8)
        for xi, v in zip(x + w / 2, cross):
            ax.text(xi, v, fmt.format(v), ha="center", va="bottom", fontsize=7.8,
                    color=RED, fontweight="bold")
        ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=9)
        ax.set_ylabel(title, fontsize=9)
        ax.set_title(title, fontsize=10)
        ax.set_ylim(0, 112)
        ax.legend(frameon=False, fontsize=8.4, loc="lower right")
        strip(ax, left=True)

    note = "FPR %: cross " + ", ".join(f"{a:.2f} vs {b:.2f} in-domain"
                                        for a, b in zip(cross_f, dom_f))
    fig.text(0.5, -0.04, note, ha="center", fontsize=8, color=MUTE)
    save(fig, "e6_crossdataset.png")


if __name__ == "__main__":
    for name, pattern, fn in (
        ("e1", "e1_baseline_*.json", fig_e1_one),
        ("e2", "e2_ablation_*.json", fig_e2_one),
        ("e3", "e3_freshness_*.json", fig_e3_one),
        ("e4", "e4_explain_*.json", fig_e4_one),
        ("e5", "e5_latency_*.json", fig_e5_one),
        ("e6", "e6_crossdataset.json", fig_e6_one),
    ):
        payloads = loads(pattern)
        if not payloads:
            print(f"skip {name} (no results yet)")
            continue
        for payload in payloads:
            fn(payload)
