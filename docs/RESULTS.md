# Results

Headline outcomes of experiments **E1–E6** for the thesis  
*Real-Time Cyber Threat Intelligence Fusion with Explainable Machine Learning for Early APT Prediction*.

Machine-readable sources of truth:

- `results/tables/*.json` / `*.csv`
- `results/figures/*.png`
- `results/alerts/*.jsonl`
- Summary table: `python scripts/status_report.py`

Experimental scale (unless noted): **400 000 flows/dataset**, RF **200** trees, `min_samples_leaf=20`, seed **42**, operating recall target **0.96**.

---

## 1. E1 — Baseline reproduction

Models: Random Forest (primary), Gradient Boosting, linear SVM.

| Dataset | Model | Role |
|---------|-------|------|
| CIC-IDS2017 / UNSW-NB15 | RF, GBM, linear SVM | Reference points for E2 ablation |

Detailed metrics: `results/tables/e1_baseline_*.json`.

**Notes**

- Linear SVM remains as the proposal’s baseline comparator; at the 96 % recall operating point its FPR is high on both datasets and should not be read as a competitive system.  
- RF/GBM numbers underpin all subsequent CTI comparisons.

---

## 2. E2 / H1 — Live CTI reduces FPR at matched recall

### 2.1 Primary comparison (CV)

| Dataset | Traffic-only FPR (CV) | +CTI FPR (CV) | Relative reduction |
|---------|----------------------:|--------------:|-------------------:|
| UNSW-NB15 | 0.377 % | 0.365 % | **3.2 %** |
| CIC-IDS2017 | 0.0646 % | 0.0016 % | **97.6 %** |

### 2.2 Split-test reduction

| Dataset | Relative FPR reduction (split test) |
|---------|--------------------------------------:|
| UNSW-NB15 | **11.7 %** |
| CIC-IDS2017 | **97.4 %** |

### 2.3 Ablation and live-only control

| Condition | UNSW-NB15 | CIC-IDS2017 |
|-----------|----------:|------------:|
| `traffic_cti_no_match` (IoC-match flags removed) | 2.2 % reduction | still **97.6 %** |
| `live_feeds_only` (today’s feeds, no injection) | ~0 indicator overlap | ~0 indicator overlap |

**Interpretation**

- H1 (≥ 10 %) is **met on the split test** for UNSW (11.7 %) and **overwhelmingly met** on CIC-IDS2017 under controlled injection.  
- The 5-fold CV estimate for UNSW (3.2 %) does **not** meet the ≥ 10 % bar — report both, do not cherry-pick.  
- On CIC-IDS2017, essentially **every** feed-derived feature acts as a label proxy when injection is on (not only the match flag).  
- `live_feeds_only` shows current public feeds share **almost no IPs** with 2017-era benchmarks → no live gain on this label set.

**H1 verdict:** partially supported; strong under documented injection coverage on CIC-IDS2017, modest on UNSW CV, split-test UNSW passes.

---

## 3. E3 / H2 — Freshness curve

Intervals: 1 min → 5 min → 1 h → 6 h → 24 h (`replay.intervals_min`).

| Dataset | Recall 5 min → 24 h (fixed θ) | Malicious IoC coverage | Median age (5 min → 24 h) | FPR at matched recall |
|---------|-------------------------------:|-----------------------:|--------------------------:|----------------------:|
| UNSW-NB15 | 95.94 % → 95.72 % (**−0.22 pp**) | 81.2 % → 5.8 % (monotone) | 2.6 → 11.2 min\* | **×1.38** |
| CIC-IDS2017 | 95.93 % → 0 % (**−95.9 pp**) | 100 % → 99.99 % | 2.9 → 195 min | **×3.00** |

\* Median age at 24 h is non-monotone because surviving sightings are freshly re-published; `p90_age_min` in JSON is monotone.

**Mechanism (CIC-IDS2017 collapse)**

Models whose top features are CTI-driven (E4) drop positive scores from ~1.0 to ~0.73 at 1 h freshness while negatives stay near 0 — the 5-minute threshold stops firing. Diagnostics: `scripts/_diag_e3_scores.py`.

**H2 verdict:** the ≥ 3 pp recall-gap criterion **fails on UNSW** and **passes on CIC-IDS2017**. The robust, dataset-independent staleness cost is **matched-recall FPR inflation** (×1.38 / ×3.00) plus coverage collapse on UNSW. Report H2 as *partially supported; mechanism: freshness cost scales with CTI reliance*.

---

## 4. E4 / H3 — Explanation stability

| Dataset | Mean top-10 Jaccard (min) | Verdict | ATT&CK tactic TV distance | Top-4 Jaccard | Alerts with CTI in reasons |
|---------|--------------------------:|:-------:|--------------------------:|--------------:|----------------------------:|
| UNSW-NB15 | **0.891** (0.818) | **PASS** | 0.018 | 1.000 | 83.2 % |
| CIC-IDS2017 | **0.702** (0.538) | **PASS** | 0.008 | 1.000 | 100 % |

**H3 verdict:** criterion (≥ 0.7) **passes on both datasets**. Tactic-level explanation mix is essentially invariant across folds.

---

## 5. E5 / H4 — End-to-end latency

Per-batch timing: enrich → design matrix → predict → TreeSHAP → reason codes.  
10 000 time-ordered test flows per batch size; explanations on alerts only.

| Dataset | Batch | p50 total | p95 total | Explain p95 | Score path p95 (no SHAP) |
|---------|------:|----------:|----------:|------------:|-------------------------:|
| UNSW-NB15 | 16 | 102 ms | 278 ms | 181 ms | 110 ms |
| UNSW-NB15 | **64** | 180 ms | **671 ms** | 574 ms | 97 ms |
| UNSW-NB15 | 256 | 589 ms | 1966 ms | 1872 ms | 103 ms |
| CIC-IDS2017 | 16 | 76 ms | 146 ms | 69 ms | 80 ms |
| CIC-IDS2017 | **64** | 77 ms | **319 ms** | 246 ms | 79 ms |
| CIC-IDS2017 | 256 | 88 ms | 878 ms | 792 ms | 88 ms |

**H4 verdict:** **supported at reference batch size 64** on both datasets (p95 < 1 s).  
Explanation cost scales with the number of alerts per batch (UNSW alert density is higher). Score path without SHAP stays ≈ 80–110 ms p95; one-off feed poll ≈ 5 s.

---

## 6. E6 — Cross-dataset transport

Both datasets mapped to an identical **18-feature canonical bridge** (same formulas, log1p, shared CTI block). θ tuned on the source only; evaluated on the target.

| Direction | Recall (cross → in-domain) | FPR (cross → in-domain) | PR-AUC (cross → in-domain) |
|-----------|---------------------------:|------------------------:|---------------------------:|
| UNSW → CIC-IDS2017 | 38.3 % → 95.7 % | 6.97 % → 0.35 % | 35.0 % → 99.5 % |
| CIC-IDS2017 → UNSW | **0.0 %** → 95.9 % | 0.00 % → 0.84 % | 49.8 % → 99.4 % |

**Verdict:** transport **collapses in both directions**. Even with semantically matched features, the source-tuned operating point does not survive distribution shift (CIC-IDS2017 → UNSW never crosses θ), while ranking degrades less than the threshold suggests. **Deployment requires a per-target calibration set** — which every other result in this thesis assumes.

---

## 7. Summary of hypothesis outcomes

| ID | Criterion | Outcome |
|----|-----------|---------|
| **H1** | ≥ 10 % FPR reduction at matched recall | Split-test UNSW **11.7 %** (pass); CIC-IDS2017 **97.4–97.6 %** under injection (pass); UNSW CV 3.2 % (fail) |
| **H2** | ≥ 3 pp recall gap 5 min → 24 h | CIC-IDS2017 pass (collapse diagnosed); UNSW fail on recall; FPR/coverage costs clear on both |
| **H3** | Top-k Jaccard ≥ 0.7 | **Pass** both datasets (0.891 / 0.702) |
| **H4** | p95 < 1 s at batch 64 | **Pass** both datasets |
| **E6** | Transport without recalibration | **Fails** both directions → calibration required |

---

## 8. Threats to validity (must accompany any quotation of numbers)

1. **Controlled injection is label-derived.** On CIC-IDS2017 the attacker address space is small, so feed membership ≈ the label (malicious coverage 100 %, all-flow coverage ~36.6 %). The 97.6 % FPR reduction is an *upper bound under perfect intel coverage*, not an estimate of live-feed performance. `live_feeds_only` measures the latter and shows no gain.  
2. **Linear SVM is a strawman** at this operating point (high FPR at 96 % recall); retained only as the proposal baseline.  
3. **`min_samples_leaf=20`** (instead of 2) was chosen for TreeSHAP tractability at 400 k rows (E4 runtime ~176 min → ~4 min). It regularises every model in the suite equally.  
4. **E6’s bridge is deliberately narrow** (18 features): the benchmarks share almost no raw columns. Transport bounds portability; it does not contradict in-domain E1–E5.  
5. **No APT actor ground truth** in either traffic benchmark — attribution is evidence-based ranking.  
6. **Feed drift** — re-running live polls years later may change `live_feeds_only` behaviour.

---

## 9. Reproducing these tables

```bash
python scripts/status_report.py
# or full suite:
powershell -File run_all.ps1          # Windows
# see docs/REPRODUCIBILITY.md for the manual Linux sequence
```

Always archive `results/tables/*.json` alongside the thesis chapter that quotes them.
