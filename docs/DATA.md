# Data

This repository **does not** store large raw datasets in git. This document describes what is required, where it lives after download, and how to obtain it.

---

## 1. What is tracked in git vs local-only

| Path | In git? | Notes |
|------|:-------:|-------|
| `data/threat_actors.json` | Yes | APT actor corpus (~1 MB) |
| `data/attack_group_techniques.json` | Yes | MITRE G-ID → T-ID map |
| `data/cicids2017/raw/*.csv` | **No** | ~1.4 GB total |
| `data/cicids2017/*.zip` | **No** | Cached archive (~285 MB) |
| `data/unsw_nb15/*.csv` | **No** | Training/testing sets |
| `data/processed/*.parquet` | **No** | Derived caches |
| `data/feed_snapshots/` | **No** | Poll history |
| `data/ioc_store.db` | **No** | SQLite IoC store |
| `data/inbox/` | **No** | Sensor input samples |
| `model/*.joblib` | Yes | Trained scoring/attribution models |

---

## 2. CIC-IDS2017

| Property | Value |
|----------|-------|
| **Name** | CICIDS2017 / GeneratedLabelledFlows |
| **Role** | Primary traffic benchmark |
| **Why this extract** | Contains `Source IP` / `Destination IP` required for IoC matching |
| **Approx. size** | ~285 MB zip; ~1.4 GB extracted CSVs |
| **Default path** | `data/cicids2017/raw/` |
| **Cache path** | `data/cicids2017/GeneratedLabelledFlows.zip` |

### Download (automated)

```bash
python scripts/download_datasets.py --dataset cicids2017
# or the legacy helper:
python scripts/download_cicids2017.py
```

Default source (Hugging Face mirror of the CIC release):

```
https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/main/csvs/GeneratedLabelledFlows.zip
```

The downloader is **resumable** (HTTP Range) and skips work if valid CSVs are already present.

### Manual alternative

1. Obtain GeneratedLabelledFlows from the official CIC website or a trusted mirror.  
2. Extract CSVs into `data/cicids2017/raw/`.  
3. Ensure day-wise files such as `Monday-WorkingHours.pcap_ISCX.csv` are present.

### Expected raw files (typical)

```
Monday-WorkingHours.pcap_ISCX.csv
Tuesday-WorkingHours.pcap_ISCX.csv
Wednesday-workingHours.pcap_ISCX.csv
Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
Friday-WorkingHours-Morning.pcap_ISCX.csv
Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
```

---

## 3. UNSW-NB15

| Property | Value |
|----------|-------|
| **Name** | UNSW-NB15 |
| **Role** | Secondary traffic benchmark |
| **Default path** | `data/unsw_nb15/` |
| **Config key** | `data.unsw_dir` in `config/default.yaml` |

### Download (automated)

```bash
python scripts/download_datasets.py --dataset unsw_nb15
```

Tries, in order:

1. `UNSW_NB15_training-set.csv`  
2. `UNSW_NB15_testing-set.csv`  
3. Full archive zip fallback  

If mirrors fail, download manually from the official page:

```
https://research.unsw.edu.au/projects/unsw-nb15-dataset
```

Place:

```
data/unsw_nb15/UNSW_NB15_training-set.csv
data/unsw_nb15/UNSW_NB15_testing-set.csv
```

> **Note:** On Windows development machines, `data.unsw_dir` may point to an external project folder. Update `config/default.yaml` to match your layout, or keep files under `data/unsw_nb15/` as above.

---

## 4. Live CTI feed snapshots

| Path | Contents |
|------|----------|
| `data/feed_snapshots/` | One CSV per feed per successful poll |
| `data/ioc_store.db` | Consolidated IoC store with TTL metadata |

Populate via:

```bash
python scripts/run_collect_feeds.py
```

Feeds that require credentials (OTX, MISP) leave empty snapshots when keys are unset; keyless feeds still run.

---

## 5. Processed caches

| Path | Contents |
|------|----------|
| `data/processed/*.parquet` | Canonical feature frames + sighting frames |

Caches are keyed by dataset, row cap, and seed. **Delete** `data/processed/*.parquet` after changing `data.max_rows` or related config to force a reload.

---

## 6. Full download command

```bash
python scripts/download_datasets.py --list          # show sources
python scripts/download_datasets.py --dataset all   # CIC-IDS2017 + UNSW-NB15
```

---

## 7. Provenance and citation

When publishing results that depend on these datasets, cite the original dataset papers/pages, not only this repository:

- **CIC-IDS2017** — Canadian Institute for Cybersecurity, University of New Brunswick  
- **UNSW-NB15** — UNSW Canberra, Cyber Security Centre  
- **MITRE ATT&CK** — for technique mappings and STIX corpora  
- Individual CTI feeds — see each provider’s terms of use  

---

## 8. Disk budget (approximate)

| Item | Size |
|------|------|
| CIC-IDS2017 zip + CSVs | ~1.7 GB |
| UNSW-NB15 CSVs | ~100–200 MB |
| Processed parquet caches | ~100 MB |
| Feed snapshots + IoC DB | ~50–100 MB |
| Models (already in git) | ~20 MB |
| **Working total** | **~2–2.5 GB** |
