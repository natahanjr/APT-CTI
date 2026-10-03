# Methodology

This document describes the experimental design of the thesis artefact  
*Real-Time Cyber Threat Intelligence Fusion with Explainable Machine Learning for Early APT Prediction*.

---

## 1. Research questions and hypotheses

| ID | Hypothesis | Success criterion (as implemented) |
|----|------------|-------------------------------------|
| **H1** | Live CTI features reduce false-positive rate at matched recall versus traffic-only models | Relative FPR reduction ≥ 10 % on at least one benchmark under the split-test protocol; CV estimates reported separately |
| **H2** | Intelligence staleness degrades detection quality in a measurable way | Recall gap ≥ 3 percentage points from 5 min → 24 h freshness (fixed θ); matched-recall FPR inflation also reported |
| **H3** | Explanation reason codes are stable across data folds | Mean top-10 Jaccard ≥ 0.7; ATT&CK tactic distribution distance reported |
| **H4** | End-to-end alert-path latency stays within an operational budget | p95 total latency < 1 s per batch at reference batch size **64** |

Supporting experiment **E1** reproduces baselines (Random Forest, Gradient Boosting, linear SVM). **E6** tests transportability across datasets.

---

## 2. Datasets

| Dataset | Role | Features used |
|---------|------|---------------|
| **CIC-IDS2017** (GeneratedLabelledFlows) | Primary benchmark | Traffic statistics + source/destination IPs for IoC matching |
| **UNSW-NB15** | Secondary benchmark | Traffic statistics; IP fields where available |

Default experimental scale: **400 000 flows per dataset** (stratified subsample), test 20 %, validation 20 %, remainder train. Seed **42**.

See [`DATA.md`](DATA.md) for download instructions and provenance.

---

## 3. Live CTI enrichment pipeline (Contribution 1)

### 3.1 Feed sources

Keyless feeds polled by default:

| Feed | Typical endpoint |
|------|------------------|
| abuse.ch URLhaus | `/downloads/csv_recent/` |
| abuse.ch ThreatFox | `/export/csv/recent/` |
| abuse.ch Feodo Tracker | `ipblocklist.txt` |
| Binary Defense BAN | `banlist.txt` |
| Emerging Threats | `compromised-ips.txt` |
| CINS Army | `ci-badguys.txt` |
| blocklist.de | `lists/all.txt` |
| IPsum (Stamparm) | `ipsum.txt` |
| OpenPhish | `feed.txt` |
| CERT.PL (NASK) | `domains/domains.txt` |

Optional authenticated feeds: AlienVault OTX, MISP (configured in `config/default.yaml`).

Pollers are **fail-soft**: a failing feed is recorded in `results/tables/feed_poll.json`; remaining feeds continue. A DNS-over-HTTPS fallback (Cloudflare `1.1.1.1`) is installed in `cti_pipeline/net.py` for unreliable local resolvers.

### 3.2 Indicator store

- SQLite database (`data/ioc_store.db`, WAL mode) with TTL-based expiry  
- Raw snapshots under `data/feed_snapshots/` (one CSV per feed per poll)  
- Default TTL: **168 hours** (7 days) without a sighting  

### 3.3 Freshness model

Flows are replayed in timestamp order against a feed polled every Δ seconds:

1. An IoC sighting becomes visible from the **first poll boundary at or after** the sighting time.  
2. It expires when no sighting lands within `replay.ttl_hours`.  
3. Per-flow age score:

   \[
   \text{feed\_age\_score} = 0.5^{\,\text{age} / h_{1/2}}
   \]

   where age is measured from the **poll boundary** (not the raw sighting), and \(h_{1/2}\) = `freshness_half_life_h` (default 6 h).  
4. Poll grid origin \(t_0\) is aligned to the start of the replay.

### 3.4 Per-flow CTI feature group

The E2 ablation removes this group:

| Feature | Meaning |
|---------|---------|
| `ioc_src_match` | Source IP present in current IoC store |
| `ioc_dst_match` | Destination IP present in current IoC store |
| `feed_age_score` | Freshness-weighted indicator score |
| `feed_confidence` | Aggregated feed confidence / reputation |
| `source_count` | Number of independent feeds sighting the IoC |
| `reputation_bucket` | Discretised reputation band |

---

## 4. Controlled IoC injection

### 4.1 Problem

CIC-IDS2017 and UNSW-NB15 were collected years before the live feeds used here. Benchmark attacker IPs are therefore typically **absent** from today’s feeds. Using live feeds only would measure an almost empty CTI channel on these labels.

### 4.2 Two provenances (always both reported)

| Mode | Definition |
|------|------------|
| **live** | Indicators actually returned by the polled feeds |
| **injected** | Ground-truth IPs taken from malicious benchmark flows at rate `replay.injection_rate` (default **0.6**), plus benign-only noise at `replay.benign_ioc_rate` (default **0.004**) |

Configuration: `replay.injection: controlled | none`.

### 4.3 Interpretation rules

- Injected rows quantify **what accurate intelligence can buy** under documented coverage — an upper-bound-style estimate.  
- `live_feeds_only` (traffic-only under current feeds) quantifies **what today’s feeds actually deliver** on the benchmark.  
- Both rows are written to the same result tables so the gap is visible and cannot be suppressed in reporting.

---

## 5. Models and operating point

| Component | Choice |
|-----------|--------|
| Primary model | Random Forest (`n_estimators=200`, `min_samples_leaf=20`, seed 42) |
| Comparators | Gradient Boosting; linear SVM (proposal baseline) |
| Regularisation note | `min_samples_leaf=20` keeps TreeSHAP tractable at 400 k rows |
| Operating threshold θ | Largest validation threshold achieving recall ≥ `model.target_recall` (default **0.96**) |
| Scaling | Fit per training fold only; trees are scale-invariant (no Min–Max on RF/GBM path) |

E2 compares FPR **at matched recall**. E3 reports both fixed-θ curves (robustness) and matched-recall FPR curves (analyst-workload cost).

---

## 6. Experiment matrix

| ID | Script | Design |
|----|--------|--------|
| **E1** | `scripts/run_e1_baseline.py` | RF / GBM / linear SVM baselines on each dataset |
| **E2** | `scripts/run_e2_ablation.py` | Traffic-only vs traffic+CTI; feature-group ablation; live-only control |
| **E3** | `scripts/run_e3_freshness.py` | Refresh interval sweep {1, 5, 60, 360, 1440} minutes |
| **E4** | `scripts/run_e4_explainability.py` | TreeSHAP top-k stability (Jaccard), ATT&CK tactic mix |
| **E5** | `scripts/run_e5_latency.py` | Per-stage latency: enrich → design → predict → SHAP → reasons |
| **E6** | `scripts/run_e6_crossdataset.py` | Train on A, test on B via shared 18-feature canonical bridge |

All experiments accept `--dataset`, `--max-rows`, `--n-estimators`, and `--no-poll`.

---

## 7. Explainable alerting layer (Contribution 4)

1. Predict with the trained ensemble.  
2. Compute **TreeSHAP** values for alerts (sample size `model.shap_sample`).  
3. Emit top-k reason codes (`model.top_k_reasons`, default 3) with feature names.  
4. Map contributing features/tactics to **MITRE ATT&CK** techniques via `attack_map.py`.  
5. Measure **stability** across CV folds (E4): Jaccard of top-k feature sets; total-variation distance of tactic distributions.

---

## 8. APT attribution layer (optional)

Not a supervised actor classifier (benchmarks lack actor labels). Instead:

| Stage | Description |
|-------|-------------|
| Corpus | `data/threat_actors.json` — groups/aliases merged from MITRE ATT&CK STIX and MISP galaxies |
| Retrieval | TF-IDF similarity model (`scripts/train_attribution.py` → `model/attribution_tfidf.joblib`) |
| Scoring | Technique-overlap (IDF-weighted) + retrieval similarity over alert tactics/techniques |
| Verdicts | `apt-attributed` (notify), `apt-candidate` (display only), `not-apt` (behavioural fallback) |

Gates: `attribution.min_notify` (default 0.25), specificity (limited close competitors), corroboration (live IoC match or ≥2 independent technique hits).

---

## 9. Metrics

| Metric | Used in |
|--------|---------|
| Recall, FPR, precision, PR-AUC, accuracy | E1, E2, E6 |
| Relative FPR reduction (matched recall) | E1, H1 |
| IoC coverage (malicious / all flows) | E2, E3 |
| Feature-set Jaccard (top-k) | E4, H3 |
| ATT&CK tactic TV distance | E4 |
| Per-stage latency (p50/p95) | E5, H4 |

---

## 10. Threats to validity (design-level)

1. **Label-derived injection** can overstate live-feed performance; mitigated by mandatory `live_feeds_only` rows.  
2. **Benchmark age** — 2017-era labels do not represent current threat landscapes.  
3. **Feed drift** — public lists change; historical re-runs may differ.  
4. **Linear SVM** may be a weak comparator at this operating point; retained as proposal baseline.  
5. **Actor attribution** is evidence-based ranking, not ground-truth evaluation.  
6. **E6 bridge is narrow** (18 features) by construction — bounds portability, does not negate in-domain E1–E5.

Further discussion: [`RESULTS.md`](RESULTS.md).

---

## 11. Configuration reference

Primary file: [`config/default.yaml`](../config/default.yaml)

| Section | Key fields |
|---------|------------|
| `data` | `unsw_dir`, `cic_dir`, `datasets`, `max_rows`, `test_size`, `val_size` |
| `cti` | `feeds`, `poll_interval_min`, `ttl_hours`, `freshness_half_life_h`, `db_path`, optional API keys |
| `replay` | `intervals_min`, `injection`, `injection_rate`, `benign_ioc_rate`, `seed` |
| `model` | `n_estimators`, `min_samples_leaf`, `target_recall`, `cv_folds`, `shap_sample`, `top_k_reasons`, `seed` |
