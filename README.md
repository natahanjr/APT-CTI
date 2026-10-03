# Real-Time Cyber Threat Intelligence Fusion with Explainable Machine Learning for Early APT Prediction

**Repository:** `APT-CTI`  
**Type:** Research artefact / thesis implementation  
**Language:** Python 3.11+  
**Licence:** [MIT](LICENSE) — free to use, study, and build upon (see [LICENSE](LICENSE))  

This repository implements the experimental pipeline, evaluation suite, and real-time scoring prototype described in the thesis *Real-Time Cyber Threat Intelligence Fusion with Explainable Machine Learning for Early APT Prediction*.

---

## Abstract

Advanced Persistent Threat (APT) detection remains difficult when models rely solely on traffic statistics: indicators of compromise (IoCs) observed by operational feeds are often stale, noisy, or absent from historical benchmarks. This work presents a **live cyber threat intelligence (CTI) enrichment pipeline** that continuously polls public CTI feeds, derives freshness-aware per-flow features, and fuses them with network statistics for early APT-oriented detection.

The system is evaluated on two public intrusion detection benchmarks (**CIC-IDS2017** and **UNSW-NB15**) through a controlled experimental suite (E1–E6) covering baseline reproduction, feature ablation, intelligence freshness, explanation stability, end-to-end latency, and cross-dataset transport. An **explainable alerting layer** produces TreeSHAP reason codes mapped to MITRE ATT&CK, and an optional **evidence-based APT attribution** module ranks threat-actor candidates against a curated corpus.

Results indicate that (i) live CTI features can substantially reduce false positives at matched recall on benchmarks where indicator coverage is available, (ii) the operational cost of intelligence staleness scales with how heavily a model depends on CTI features, (iii) reason-code rankings remain stable across folds, and (iv) models do **not** transport across datasets without target-specific calibration. Controlled indicator injection is used explicitly and is reported alongside live-feed-only baselines to avoid overstating real-world performance.

---

## Research contributions

| # | Contribution | Code location |
|---|--------------|---------------|
| 1 | **Live-CTI enrichment pipeline** — continuous polling of public feeds → freshness-aware per-flow features | `src/cti_pipeline/feeds/`, `collector.py`, `store.py`, `enrich.py` |
| 2 | **Ablation of predictive value of live intelligence** (E2): traffic-only vs traffic+CTI | `scripts/run_e2_ablation.py` |
| 3 | **Freshness–performance analysis** (E3): feed refresh interval vs detection quality | `scripts/run_e3_freshness.py` |
| 4 | **Explainable alerting layer** (E4): SHAP reason codes + ATT&CK stability audit | `src/cti_pipeline/explain.py`, `attack_map.py`, `scripts/run_e4_explainability.py` |

Supporting experiments:

| ID | Purpose | Script |
|----|---------|--------|
| E1 | Baseline reproduction (RF / GBM / linear SVM) | `scripts/run_e1_baseline.py` |
| E5 | End-to-end alert-path latency (H4) | `scripts/run_e5_latency.py` |
| E6 | Cross-dataset transport on a shared feature bridge | `scripts/run_e6_crossdataset.py` |

---

## Hypotheses (summary)

| ID | Statement | Primary experiment |
|----|-----------|--------------------|
| **H1** | Live CTI features reduce false-positive rate at matched recall relative to traffic-only models | E2 |
| **H2** | Intelligence freshness degrades detection quality in a measurable, interpretable way | E3 |
| **H3** | Explanation reason codes are stable across data folds (Jaccard ≥ 0.7 on top-k features) | E4 |
| **H4** | End-to-end alert-path latency remains within an operational budget at a reference batch size | E5 |

Detailed definitions, metrics, and verdicts are in [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) and [`docs/RESULTS.md`](docs/RESULTS.md).

---

## Repository structure

```
apt-cti-thesis/
├── README.md
├── docs/
│   ├── METHODOLOGY.md      # hypotheses, experimental design, metrics
│   ├── REPRODUCIBILITY.md  # environment, seeds, commands, data layout
│   ├── DATA.md             # datasets, provenance, download
│   └── RESULTS.md          # experiment outcomes and threats to validity
├── config/default.yaml     # paths, feed set, replay, model hyper-parameters
├── data/                   # large datasets are NOT in git (see docs/DATA.md)
│   ├── cicids2017/raw/     # GeneratedLabelledFlows CSVs
│   ├── unsw_nb15/          # training / testing CSVs (downloaded on demand)
│   ├── feed_snapshots/     # raw CSV snapshot per feed per poll
│   ├── processed/          # cached canonical frames + sighting frames
│   ├── threat_actors.json  # APT reference corpus (STIX + MISP merge)
│   ├── attack_group_techniques.json
│   └── ioc_store.db        # WAL-mode SQLite IoC store
├── src/cti_pipeline/       # core library (feeds, enrichment, model, explain)
├── scripts/                # experiments E1–E6, training, dashboard, downloads
├── deploy/                 # real-time scoring service (see deploy/README.md)
├── model/                  # trained joblib bundles
├── dashboard/index.html    # self-contained results UI
├── results/{tables,figures,alerts}/
├── Dockerfile
├── start.ps1               # Windows one-command launcher
├── run_all.ps1             # sequential experiment driver
└── serve.py                # live poll + local dashboard server
```

---

## Installation

### Requirements

- Python **3.11+**
- ~2–4 GB free disk (datasets + caches)
- Optional: Docker (containerised scorer), NVIDIA NIM API key (AI explanations)

### Linux / macOS

```bash
git clone https://github.com/natahanjr/APT-CTI.git
cd APT-CTI
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# download datasets (not stored in git)
python scripts/download_datasets.py --dataset cicids2017
python scripts/download_datasets.py --dataset unsw_nb15
```

### Windows (PowerShell)

```powershell
git clone https://github.com/natahanjr/APT-CTI.git
cd APT-CTI
powershell -ExecutionPolicy Bypass -File start.ps1
# or step-by-step:
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
python scripts\download_datasets.py
```

`start.ps1` bootstraps the environment, fetches missing data, runs the pipeline if results are absent, and opens the dashboard.

---

## Quickstart experiments

```bash
# Contribution 1 — poll CTI feeds
python scripts/run_collect_feeds.py

# Full suite (Windows)
powershell -File run_all.ps1

# Individual experiments
python scripts/run_e1_baseline.py --dataset cicids2017
python scripts/run_e2_ablation.py --dataset unsw_nb15
python scripts/run_e3_freshness.py
python scripts/run_e4_explainability.py
python scripts/run_e5_latency.py
python scripts/run_e6_crossdataset.py

# Headline summary table
python scripts/status_report.py
```

Common flags on every experiment:

| Flag | Meaning |
|------|---------|
| `--dataset {cicids2017,unsw_nb15}` | benchmark to evaluate |
| `--max-rows N` | stratified subsample cap (default from config: 400 000) |
| `--n-estimators N` | tree ensemble size |
| `--no-poll` | reuse existing feed snapshots instead of polling again |

---

## Live mode and dashboard

```bash
python serve.py                 # http://127.0.0.1:8747, polls every 5 min
python serve.py --no-poll       # serve only
python serve.py --full          # also rerun the full pipeline hourly
python serve.py --interval 60   # poll every minute
```

`dashboard/index.html` is a single-file UI (light/dark, dataset switch) generated from `results/tables` by `scripts/build_dashboard.py`, so the interface cannot drift from the stored numbers.

---

## Real-time scoring service

`deploy/service.py` converts the research pipeline into an operable scorer:

1. Tail a sensor log (Zeek `conn.log`, Suricata `eve.json`, JSONL, or CSV)
2. Poll live CTI feeds (10 keyless sources; optional OTX/MISP)
3. Score batches with the trained Random Forest
4. Emit TreeSHAP reason-coded alerts (MITRE technique mapped) to JSONL, webhook, or syslog
5. Expose health at `GET :8099/__status` and a read-only web dashboard at `http://127.0.0.1:8099/`

See **[`deploy/README.md`](deploy/README.md)** for configuration, hardening, Docker, and production caveats.

---

## Datasets

| Dataset | Role | Location (after download) |
|---------|------|---------------------------|
| **CIC-IDS2017** | Primary traffic benchmark (GeneratedLabelledFlows) | `data/cicids2017/raw/*.csv` |
| **UNSW-NB15** | Secondary traffic benchmark | `data/unsw_nb15/*.csv` |
| Public CTI feeds | Live enrichment (URLhaus, ThreatFox, Feodo, BAN, ET, CINS, blocklist.de, IPsum, OpenPhish, CERT.PL; optional OTX/MISP) | polled → `data/feed_snapshots/`, `data/ioc_store.db` |
| APT actor corpus | Attribution reference (MITRE STIX + MISP galaxies) | `data/threat_actors.json` |

Large raw files are **intentionally excluded from git**. Download with:

```bash
python scripts/download_datasets.py --list
python scripts/download_datasets.py --dataset all
```

See [`docs/DATA.md`](docs/DATA.md) for provenance, sizes, and manual alternatives.

---

## Experimental design (overview)

### Controlled IoC injection

Historical benchmark addresses (2017-era) typically do not appear in today’s public feeds. The pipeline therefore supports two indicator provenances, both stored and reported:

| Provenance | Definition |
|------------|------------|
| **live** | IoCs actually returned by the polled feeds |
| **injected** | Ground-truth IPs from malicious benchmark flows at a configured rate (`replay.injection_rate`), plus benign-only noise |

E2 always reports both a CTI-enhanced row and a `live_feeds_only` baseline so the gap between emulation and live-feed reality cannot be hidden. Details: [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md).

### Operating point

Classification thresholds are **not** fixed at 0.5. For each model, θ is selected on the validation split as the largest threshold that still meets `model.target_recall` (default **0.96**). E2 compares FPR **at matched recall**.

### Freshness model

IoC sightings become visible at the next poll boundary after the indicator is observed and expire after `replay.ttl_hours`. Per-flow CTI features include match flags, feed age score, confidence, source count, and reputation bucket. Full definition: [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md).

---

## Results (headline)

Full tables, figures, and verdicts: [`docs/RESULTS.md`](docs/RESULTS.md).  
Machine-readable outputs: `results/tables/`, `results/figures/`, `results/alerts/`.

### H1 — CTI reduces FPR at matched recall (E2)

| Dataset | Traffic-only FPR (CV) | +CTI FPR (CV) | Relative reduction | Split-test reduction |
|---------|----------------------:|--------------:|-------------------:|---------------------:|
| UNSW-NB15 | 0.377 % | 0.365 % | **3.2 %** | **11.7 %** |
| CIC-IDS2017 | 0.0646 % | 0.0016 % | **97.6 %** | **97.4 %** |

`live_feeds_only` (traffic-only under today’s feeds) shows ~0 indicator overlap with 2017-era benchmarks and no gain — the controlled-injection numbers are an **upper-bound-style** estimate under documented coverage, not a claim of live-feed performance on historical labels.

### H2 — Freshness (E3)

| Dataset | Recall 5 min → 24 h (fixed θ) | Malicious IoC coverage | FPR at matched recall |
|---------|-------------------------------:|-----------------------:|----------------------:|
| UNSW-NB15 | 95.94 % → 95.72 % (−0.22 pp) | 81.2 % → 5.8 % | ×1.38 |
| CIC-IDS2017 | 95.93 % → 0 % (−95.9 pp) | 100 % → 99.99 % | ×3.00 |

**Verdict:** partially supported; the robust staleness cost is matched-recall FPR and coverage collapse, scaling with CTI reliance.

### H3 — Explanation stability (E4)

| Dataset | Mean top-10 Jaccard | Verdict |
|---------|--------------------:|:-------:|
| UNSW-NB15 | **0.891** (min 0.818) | PASS |
| CIC-IDS2017 | **0.702** (min 0.538) | PASS |

### H4 — Latency (E5, reference batch = 64)

| Dataset | p50 total | p95 total | Score path p95 (no SHAP) |
|---------|----------:|----------:|-------------------------:|
| UNSW-NB15 | 180 ms | **671 ms** | 97 ms |
| CIC-IDS2017 | 77 ms | **319 ms** | 79 ms |

**Verdict:** supported at batch size 64 on both datasets; explanation cost scales with alerts per batch.

### E6 — Cross-dataset transport

Transport collapses in both directions without target-specific calibration, even on a shared 18-feature canonical bridge. Deployment therefore requires a **per-target calibration set**.

---

## Reproducibility

- Global seed **42** for splits, models, subsampling, and injection  
- Scaling parameters fit on training folds only  
- Canonical frames cached under `data/processed/*.parquet` (delete to force reload)  
- APT corpus and attribution model rebuildable from source  

Full checklist: [`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md).

```bash
python scripts/build_actor_kb.py      # rebuild threat_actors.json
python scripts/train_attribution.py   # rebuild attribution_tfidf.joblib
python scripts/train_artifact.py      # rebuild deploy scoring bundles
```

---

## Citation

If you use this artefact in academic work, please cite the thesis title:

```bibtex
@mastersthesis{apt-cti-thesis,
  title  = {Real-Time Cyber Threat Intelligence Fusion with Explainable Machine Learning for Early APT Prediction},
  author = {Haaraphel},
  year   = {2026},
  note   = {Source code: https://github.com/natahanjr/APT-CTI}
}
```

---

## Ethical and validity notes

1. **Controlled injection is label-derived** and can overstate live-feed gains; always read `live_feeds_only` alongside injected rows.  
2. Neither public benchmark provides ground-truth **APT actor** labels; attribution is evidence-based candidate ranking, not a supervised actor classifier.  
3. Public CTI feeds change over time; historical reproduction may differ from live runs.  
4. This artefact is for **research and defensive evaluation**. Do not use it to attack systems you do not own or are not authorised to test.

---

## Documentation map

| Document | Contents |
|----------|----------|
| [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) | Hypotheses, metrics, experimental design, injection model |
| [`docs/DATA.md`](docs/DATA.md) | Datasets, download, directory layout |
| [`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md) | Environment, seeds, full command sequence |
| [`docs/RESULTS.md`](docs/RESULTS.md) | E1–E6 outcomes, threats to validity |
| [`deploy/README.md`](deploy/README.md) | Production scorer: config, security, Docker |

---

## Maintainer

- **GitHub:** [natahanjr/APT-CTI](https://github.com/natahanjr/APT-CTI)  
- **Contact:** via GitHub issues on the repository  

---

*This repository is the executable companion to the thesis. For publication-grade tables and discussion, follow the document links above rather than relying solely on dashboard screenshots.*
