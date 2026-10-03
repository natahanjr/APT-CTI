# Reproducibility

This guide allows a third party to rebuild the environment, download data, and re-run the thesis experiments with the same seeds and configuration.

---

## 1. Environment

| Component | Requirement |
|-----------|-------------|
| OS | Windows 10/11 (primary scripts), Linux/macOS (supported) |
| Python | **3.11+** |
| Memory | ≥ 8 GB RAM recommended (400 k-row experiments) |
| Disk | ≥ 4 GB free (datasets + caches) |
| Optional | Docker, PowerShell 5+ / 7+, NVIDIA NIM API key |

### Create virtual environment

**Linux / macOS**

```bash
cd APT-CTI
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```

**Windows (PowerShell)**

```powershell
cd APT-CTI
python -m venv .venv
.venv\Scripts\pip install -U pip
.venv\Scripts\pip install -r requirements.txt
```

---

## 2. Obtain data

```bash
python scripts/download_datasets.py --dataset cicids2017
python scripts/download_datasets.py --dataset unsw_nb15
```

Details, manual mirrors, and expected paths: [`DATA.md`](DATA.md).

Check environment (optional):

```bash
python scripts/env_check.py
# Windows:
powershell -ExecutionPolicy Bypass -File start.ps1 -Check
```

---

## 3. Configuration

Primary config: [`config/default.yaml`](../config/default.yaml)

| Field | Default | Role |
|-------|---------|------|
| `data.max_rows` | `400000` | Stratified subsample cap |
| `data.test_size` / `data.val_size` | `0.2` / `0.2` | Split fractions |
| `cti.poll_interval_min` | `5` | Reference refresh for training features |
| `cti.ttl_hours` | `168` | Indicator expiry |
| `cti.freshness_half_life_h` | `6` | Age-score half-life |
| `replay.intervals_min` | `[1, 5, 60, 360, 1440]` | E3 sweep |
| `replay.injection_rate` | `0.6` | Controlled malicious IoC injection |
| `replay.benign_ioc_rate` | `0.004` | Benign feed noise |
| `model.n_estimators` | `200` | RF size |
| `model.min_samples_leaf` | `20` | Regularisation / SHAP tractability |
| `model.target_recall` | `0.96` | Operating-point recall |
| `model.seed` / `replay.seed` | `42` | Global seed |

Edit paths if your UNSW files live outside `data/unsw_nb15/`.

---

## 4. Full experiment sequence

### Windows (automated)

```powershell
powershell -ExecutionPolicy Bypass -File start.ps1          # bootstrap + run if needed
powershell -ExecutionPolicy Bypass -File run_all.ps1        # feeds → E1..E5 × datasets → E6 → figures → UI
```

### Linux / macOS / manual (equivalent)

```bash
# 1) Contribution 1 — poll feeds (or --no-poll to reuse snapshots)
python scripts/run_collect_feeds.py

# 2) Baselines
python scripts/run_e1_baseline.py --dataset cicids2017
python scripts/run_e1_baseline.py --dataset unsw_nb15

# 3) Ablation (H1)
python scripts/run_e2_ablation.py --dataset cicids2017
python scripts/run_e2_ablation.py --dataset unsw_nb15

# 4) Freshness (H2)
python scripts/run_e3_freshness.py --dataset cicids2017
python scripts/run_e3_freshness.py --dataset unsw_nb15

# 5) Explainability (H3)
python scripts/run_e4_explainability.py --dataset cicids2017
python scripts/run_e4_explainability.py --dataset unsw_nb15

# 6) Latency (H4)
python scripts/run_e5_latency.py --dataset cicids2017
python scripts/run_e5_latency.py --dataset unsw_nb15

# 7) Cross-dataset transport
python scripts/run_e6_crossdataset.py

# 8) Figures + dashboard + summary
python scripts/make_figures.py
python scripts/build_dashboard.py
python scripts/status_report.py
```

Outputs:

| Path | Contents |
|------|----------|
| `results/tables/` | JSON + CSV metrics |
| `results/figures/` | Publication charts (PNG) |
| `results/alerts/` | Reason-coded alert streams |
| `dashboard/index.html` | Regenerated UI |

---

## 5. Seeds and determinism

| Setting | Value |
|---------|-------|
| Global seed | **42** (`model.seed`, `replay.seed`) |
| Applies to | train/test/val splits, RF/GBM fit, subsampling, IoC injection |
| Scaling | fit on training data only |

Strict bitwise identity across machines/libraries is **not** guaranteed (BLAS, tree implementations). Metric tables should be close for the same seeds and row caps; large deviations usually indicate config drift (`max_rows`, leaf size, dataset version).

---

## 6. Force cache rebuild

```bash
rm -rf data/processed/*.parquet   # Linux/macOS
Remove-Item data\processed\*.parquet -Force   # Windows
```

Then re-run experiments.

---

## 7. Rebuild derived artefacts

```bash
# APT actor corpus (STIX + MISP merge)
python scripts/build_actor_kb.py

# Attribution TF-IDF model
python scripts/train_attribution.py

# Deploy scoring bundles
python scripts/train_artifact.py
```

Ships in git: `data/threat_actors.json`, `model/*.joblib`.  
Rebuild if you change corpus sources or training code.

---

## 8. Live mode

```bash
python serve.py                 # http://127.0.0.1:8747
python serve.py --no-poll
python serve.py --full
python serve.py --interval 60
```

---

## 9. Scoring service smoke test

```bash
python deploy/test_service.py
# Docker:
docker build -t apt-cti-scorer .
```

Production notes: [`deploy/README.md`](../deploy/README.md).

---

## 10. Expected runtime (order of magnitude)

| Step | Rough time |
|------|------------|
| Dataset download | minutes–tens of minutes (network) |
| Feed poll | ~5 s + network |
| E1 per dataset (400 k rows) | minutes |
| E2 / E3 | tens of minutes (interval sweep) |
| E4 (SHAP) | minutes after `min_samples_leaf=20` |
| E5 | minutes |
| E6 | minutes |

Wall-clock varies with CPU and disk.

---

## 11. Common issues

| Symptom | Fix |
|---------|-----|
| UNSW not found | Download CSVs; set `data.unsw_dir` correctly |
| Empty CTI features on live mode | Run `run_collect_feeds.py`; check `feed_poll.json` |
| DNS failures on managed networks | DoH fallback is automatic via `cti_pipeline/net.py` |
| Stale metrics after config change | Delete `data/processed/*.parquet` |
| SHAP too slow | Keep `min_samples_leaf=20`; reduce `shap_sample` for drafts |
| Windows execution policy | `Set-ExecutionPolicy -Scope Process Bypass` or use `start.ps1` |

---

## 12. Integrity checklist before publishing numbers

- [ ] `config/default.yaml` matches the reported `max_rows`, seeds, and injection rates  
- [ ] Datasets present under documented paths  
- [ ] `results/tables/*.json` regenerated in the same session  
- [ ] `live_feeds_only` rows present alongside injected CTI rows  
- [ ] `scripts/status_report.py` output archived  
- [ ] Thesis text quotes the same verdicts as [`RESULTS.md`](RESULTS.md)  
