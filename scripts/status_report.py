"""Print a compact status report of whatever result tables exist."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
TABLES = ROOT / "results" / "tables"


def head(title: str) -> None:
    print(f"\n=== {title} ===")


def report_e1(ds: str) -> None:
    path = TABLES / f"e1_baseline_{ds}.csv"
    if not path.exists():
        print(f"[{ds}] E1 not finished")
        return
    head(f"E1 baseline - {ds}")
    df = pd.read_csv(path)
    cols = ["variant", "model", "accuracy", "precision", "recall", "f1", "pr_auc", "fpr"]
    print(df[cols].to_string(index=False))


def report_e2(ds: str) -> None:
    path = TABLES / f"e2_ablation_{ds}.json"
    if not path.exists():
        print(f"[{ds}] E2 not finished")
        return
    head(f"E2 ablation - {ds}")
    d = json.loads(path.read_text(encoding="utf-8"))
    for v in d["variants"]:
        m, cv = v["split_test"], v.get("cv", {})
        print(f"  {v['variant']:16s} feats={v['n_features']:3d} "
              f"acc={m['accuracy']:.4f} recall={m['recall']:.4f} prec={m['precision']:.4f} "
              f"fpr={m['fpr']:.5f} pr_auc={m['pr_auc']:.4f}")
        if cv:
            print(f"    5-fold CV: fpr={cv['fpr_mean']:.5f}+/-{cv['fpr_std']:.5f} "
                  f"recall={cv['recall_mean']:.4f} pr_auc={cv['pr_auc_mean']:.4f}")
    print("  split:", json.dumps(d["fpr_reduction_split"]))
    if "fpr_reduction_cv" in d:
        print("  cv   :", json.dumps(d["fpr_reduction_cv"]))


def report_e3(ds: str) -> None:
    path = TABLES / f"e3_freshness_{ds}.csv"
    if not path.exists():
        print(f"[{ds}] E3 not finished")
        return
    head(f"E3 freshness sweep - {ds}")
    df = pd.read_csv(path)
    cols = ["interval_label", "recall", "precision", "matched_fpr", "coverage_all",
            "coverage_malicious", "median_age_min"]
    print(df[[c for c in cols if c in df.columns]].to_string(index=False))
    j = json.loads((TABLES / f"e3_freshness_{ds}.json").read_text(encoding="utf-8"))
    print(f"  recall gap 5m vs 24h: {j['recall_gap_5m_vs_24h'] * 100:.2f} pp "
          f"(H2 >= 3 pp) | monotone coverage={j['monotone_coverage']} "
          f"| matched-recall FPR ratio x{j['matched_recall_fpr_ratio']:.2f}")


def report_e4(ds: str) -> None:
    path = TABLES / f"e4_explain_{ds}.json"
    if not path.exists():
        print(f"[{ds}] E4 not finished")
        return
    head(f"E4 explainability - {ds}")
    d = json.loads(path.read_text(encoding="utf-8"))
    print("  top-10:", ", ".join(d["top10_features"]))
    print(f"  H3 mean top-10 Jaccard = {d['h3_jaccard_mean']:.3f} "
          f"(min {d['stability_top10_jaccard']['min']:.3f}) "
          f"-> {'PASS' if d['h3_pass'] else 'FAIL'}")
    ts = d["tactic_stability"]
    print(f"  ATT&CK tactic stability: top4 Jaccard={ts['mean_top4_jaccard']:.3f} "
          f"TV distance={ts['mean_tv_distance']:.3f}")
    print(f"  alerts explained={d['n_alerts_explained']} "
          f"CTI in {d['alert_cti_reason_share'] * 100:.1f}% | tactics={d['reason_tactic_distribution']}")


def report_e5(ds: str) -> None:
    path = TABLES / f"e5_latency_{ds}.json"
    if not path.exists():
        print(f"[{ds}] E5 not finished")
        return
    head(f"E5 latency - {ds}")
    d = json.loads(path.read_text(encoding="utf-8"))
    print(f"  theta={d['theta']:.4f} features={d['n_features']} "
          f"poll={d['poll_seconds']}s window_alerts={d['protocol']['window_alerts']}")
    for b in sorted(d["batch_sizes"], key=lambda k: int(k)):
        st = d["batch_sizes"][b]["stages"]
        print(f"  batch {b:>4}: p50={st['total']['p50']*1000:7.0f} ms  "
              f"p95={st['total']['p95']*1000:7.0f} ms  "
              f"(explain p95={st['explain']['p95']*1000:6.0f} ms, "
              f"no-explain p95={st['total_no_explain']['p95']*1000:5.0f} ms)")
    print(f"  H4 (p95 < 1 s at batch 64): {'PASS' if d['h4_p95_lt_1s'] else 'FAIL'}")


def report_e6() -> None:
    path = TABLES / "e6_crossdataset.json"
    if not path.exists():
        print("[cross] E6 not finished")
        return
    head("E6 cross-dataset transport")
    d = json.loads(path.read_text(encoding="utf-8"))
    for key, r in d["directions"].items():
        c, i_, g = r["cross_target_test"], r["in_domain_target_test"], r["gap_in_minus_cross"]
        print(f"  {key:26s} recall {c['recall']:.3f} vs {i_['recall']:.3f} "
              f"(gap {g['recall']:+.3f}) | FPR {c['fpr']:.4f} vs {i_['fpr']:.4f} "
              f"| PR-AUC {c['pr_auc']:.3f} vs {i_['pr_auc']:.3f}")


if __name__ == "__main__":
    for ds in ("unsw_nb15", "cicids2017"):
        print("\n" + "#" * 70)
        print(f"# {ds}")
        report_e1(ds)
        report_e2(ds)
        report_e3(ds)
        report_e4(ds)
        report_e5(ds)
    print("\n" + "#" * 70)
    report_e6()
