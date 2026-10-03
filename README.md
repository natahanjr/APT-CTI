# Live-CTI Enrichment + Explainable APT Prediction

Implementation of the four thesis contributions from *Real-Time Cyber Threat
Intelligence Fusion with Explainable Machine Learning for Early APT Prediction*:

| # | Contribution | Where it lives |
|---|--------------|----------------|
| 1 | Live-CTI enrichment pipeline: continuously-polled public feeds → freshness-aware per-flow features | `src/cti_pipeline/feeds/`, `store.py`, `collector.py`, `enrich.py` |
| 2 | Ablation quantifying predictive value of live intelligence over traffic statistics (E2) | `scripts/run_e2_ablation.py` |
| 3 | Freshness–performance curve: feed refresh interval → detection quality (E3) | `scripts/run_e3_freshness.py` |
| 4 | Explainable alerting layer: SHAP reason codes + ATT&CK stability audit (E4) | `src/cti_pipeline/explain.py`, `attack_map.py`, `scripts/run_e4_explainability.py` |

Plus `E1` (baseline reproduction, `scripts/run_e1_baseline.py`) as the reference
point, `E5` (end-to-end alert-path latency, `scripts/run_e5_latency.py`) for H4,
and `E6` (cross-dataset transport on a shared canonical feature bridge,
`scripts/run_e6_crossdataset.py`) for generalisation.

## Layout

```
apt-cti-thesis/
├── config/default.yaml        # intervals, injection rates, thresholds, paths
├── data/
│   ├── cicids2017/raw/        # GeneratedLabelledFlows (has Source/Dest IP)
│   ├── feed_snapshots/        # raw CSV snapshot per feed per poll
│   ├── processed/             # cached canonical frames + sighting frames
│   ├── threat_actors.json     # 1,040-group APT reference corpus (STIX+MISP)
│   ├── attack_group_techniques.json # MITRE G-ID -> T-ID knowledge base
│   └── ioc_store.db           # WAL-mode SQLite IoC store
├── scripts/
│   ├── run_collect_feeds.py   # Contribution 1 - poll all feeds
│   ├── build_actor_kb.py      # STIX+MISP merge -> threat_actors.json
│   ├── train_attribution.py   # APT corpus -> TF-IDF retrieval model
│   ├── run_e1_baseline.py     # E1 - RF / GBM / linear SVM
│   ├── run_e2_ablation.py     # E2 - traffic-only vs traffic+CTI
│   ├── run_e3_freshness.py    # E3 - 1 min -> 24 hr sweep
│   ├── run_e4_explainability.py # E4 - SHAP + ATT&CK audit
│   ├── run_e5_latency.py       # E5 - per-stage latency profile (H4)
│   ├── run_e6_crossdataset.py  # E6 - cross-dataset transport bridge
│   ├── make_figures.py        # charts from results/tables/*.json
│   ├── build_dashboard.py     # single-file UI -> dashboard/index.html
│   ├── env_check.py           # JSON self-check used by start.ps1
│   └── status_report.py       # headline table of every result
├── dashboard/index.html       # design-quality UI (open in a browser)
├── deploy/                    # real-time scoring service (see deploy/README.md)
│   ├── service.py             # tail -> live-CTI enrich -> score -> SHAP -> alerts
│   ├── flow_adapters.py       # zeek / eve / jsonl / csv -> canonical records
│   ├── sinks.py               # JSONL + webhook + syslog alert sinks
│   └── config.yaml, test_service.py, requirements.txt
├── model/                     # deploy_*.joblib bundles + attribution_tfidf.joblib
├── Dockerfile                 # containerised scorer (model + feed corpus baked in)
├── results/{tables,figures,alerts}/
├── start.ps1                  # one-command launcher (bootstrap -> pipeline -> UI)
├── serve.py                   # live mode (poll + rebuild + local server)
└── run_all.ps1                # sequential driver (feeds -> E1..E5 x2 -> E6 -> figures -> UI)
```

## Quick start

```powershell
# one command: creates .venv, installs deps, fetches missing data,
# runs the pipeline if results are missing, then opens the dashboard
powershell -ExecutionPolicy Bypass -File start.ps1

start.ps1 -Check      # validate the environment only (exit 1 if not ready)
start.ps1 -Run        # force a full pipeline run, then open the UI
start.ps1 -Serve      # live mode: poll feeds + refresh + serve (see below)
start.ps1 -NoBrowser  # do everything but don't open a browser
```

`start.ps1` needs Python 3.11+ on PATH and downloads CICIDS2017 automatically
(~285 MB, resumable) if it is missing; UNSW-NB15 part files must be placed
under the path in `config/default.yaml` (`data.unsw_dir`) - the run degrades
gracefully to CICIDS2017-only without them.

### Live mode

```powershell
python serve.py                 # http://127.0.0.1:8747, polls every 5 min
python serve.py --no-poll       # serve only; browser still auto-reloads
python serve.py --full          # also rerun the whole pipeline hourly
python serve.py --interval 60   # poll every minute instead
```

`serve.py` polls the public feeds, rebuilds the dashboard from the fresh
tables, and serves it locally with a live badge: the page reloads itself
whenever `dashboard/index.html` changes. One instance per port (a second one
exits immediately), Ctrl+C stops it.

Manual pipeline (what `start.ps1` automates):

```powershell
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python scripts\run_collect_feeds.py     # Contribution 1
powershell -File run_all.ps1                         # E1..E5 x datasets + E6 + figures + UI
start dashboard\index.html                           # or: python scripts\build_dashboard.py
```

### Dashboard

`dashboard/index.html` is a self-contained, single-file UI (light/dark, dataset
switch, live search) that renders the whole thesis implementation: pipeline
stages and scripts, KPI verdicts for H1–H4, E1/E2/E3/E4/E5/E6 charts as inline SVG,
the reason-coded alert stream with ATT&CK mappings, feed-intake status and the
publication figures. It is regenerated from `results/tables` by
`scripts/build_dashboard.py` (also the last step of `run_all.ps1`), so it can
never drift from the numbers.

Every experiment accepts `--dataset {unsw_nb15,cicids2017}`, `--max-rows`,
`--n-estimators` and `--no-poll` (reuse today's feed snapshots instead of
polling again).

## Real-time scoring service

`deploy/service.py` turns the pipeline into an operable scorer: it tails a
sensor log (Zeek `conn.log`, Suricata `eve.json`, JSONL or CSV), polls live
CTI feeds (10 keyless sources incl. URLhaus/ThreatFox/Feodo, every 5 min;
frozen offline corpus as
fallback), rebuilds live-CTI sightings on every feed refresh, scores batches
at E5's production-representative point (64 flows / 5 s flush) and emits
TreeSHAP reason-coded alerts with ATT&CK mappings to a JSONL file, a webhook
(SIEM) or syslog. Health: `GET :8099/__status`; a read-only web **security
dashboard** (activity timeline, score/protocol/tactic charts, feed-health
chips) with a drill-down alert table at `http://127.0.0.1:8099/`, JSON at
`/api/alerts`. Optionally, with `NVIDIA_API_KEY` set, `POST /api/explain`
(or the **Explain with AI** button) returns a plain-English analyst brief per
alert via NVIDIA NIM — disabled gracefully when no key is configured.
`deploy/install_scorer.ps1` registers a per-user autostart
(Startup folder, no admin; `-Uninstall` removes it).

```powershell
.venv\Scripts\python.exe deploy\service.py        # tail data/inbox/flows.jsonl
.venv\Scripts\python.exe deploy\service.py --replay --input path\to\flows.jsonl
.venv\Scripts\python.exe deploy\test_service.py   # end-to-end check (A, B, C, D)
```

```bash
docker build -t apt-cti-scorer .                  # model + feed corpus + APT corpus baked in
docker run -d --restart unless-stopped -p 8099:8099 \
  -v "$PWD/inbox:/app/data/inbox" -e APT_CTI_TOKEN='<strong-token>' \
  apt-cti-scorer --config deploy/config.yaml --health-host 0.0.0.0
```

Scoring bundles: `model/deploy_live_netflow.joblib` (38 sensor-reachable
features, 98.97 % accuracy, FPR 0.63 %, θ 0.8349 — default) and
`model/deploy_unsw_full.joblib` (67 features, 99.25 %, FPR 0.27 % — offline
reference), trained by `scripts/train_artifact.py`. Sensor vocabulary mapping
tables, alert schema, and the honest production caveats (train/serve skew,
offline metrics, single-node scope) live in **`deploy/README.md`**, together
with the hardening guide (token auth, fail-closed binding, rate limit, audit
trail, log rotation, hardened systemd unit).

## Feeds

| Feed | Endpoint | Status without credentials |
|------|----------|----------------------------|
| abuse.ch URLhaus | `/downloads/csv_recent/` | works (default) |
| abuse.ch ThreatFox | `/export/csv/recent/` | works (default) |
| abuse.ch Feodo Tracker | `ipblocklist.txt` | works (default) |
| BinaryDefense BAN | `banlist.txt` | works (default) |
| Emerging Threats | `compromised-ips.txt` | works (default) |
| CINS Army | `ci-badguys.txt` | works (default) |
| blocklist.de | `lists/all.txt` | works (default) |
| IPsum (Stamparm) | `ipsum.txt` (GitHub raw) | works (default) |
| OpenPhish | `feed.txt` | works (default) |
| CERT.PL (NASK) | `domains/domains.txt` | works (default) |
| AlienVault OTX | `/api/v1/pulses/latest` | needs `cti.otx_api_key` |
| MISP | `<instance>/attributes/restSearch` | needs `cti.misp_url` (+ key) |

Pollers never raise: a failing feed is recorded in `results/tables/feed_poll.json`
and the remaining feeds still run. `cti_pipeline/net.py` installs a
DNS-over-HTTPS fallback (Cloudflare `1.1.1.1`), because the local resolver on
some managed networks intermittently fails.

## APT attribution layer

Every emitted alert is additionally attributed to an APT group - or, when no
group is credibly implicated, classified into a non-APT behavioural category -
by `src/cti_pipeline/attribution.py` (enabled by default in
`deploy/config.yaml`):

* **Corpus** - `data/threat_actors.json`: 1,040 groups / 2,429 aliases merged
  from MITRE ATT&CK STIX (`enterprise-attack.json`), MISP threat-actor
  galaxies and the reference document - origin, sponsor, sectors, MITRE
  techniques and a source-stitched summary. `data/attack_group_techniques.json`
  holds the raw G-ID -> T-ID map.
* **Retrieval model** - `scripts/train_attribution.py` fits a TF-IDF
  (word 1-2 grams, sublinear tf) similarity model over the corpus ->
  `model/attribution_tfidf.joblib` (52,835 features). Retrain after corpus
  updates: `.venv\Scripts\python.exe scripts\train_attribution.py`.
* **Evidence scoring** - candidates rank by technique overlap weighted with
  rarity IDF (only 172 groups carry technique sets, so common T1041/T1071
  hits barely count) plus retrieval similarity over the alert's tactics,
  techniques and port/protocol hints. A verdict needs
  `attribution.min_notify` (0.25 combined score), a specificity gate (few
  close competitors within 0.02) and corroboration: a live-feed IoC match or
  two independent technique hits.
* **Verdicts** - `apt-attributed` (notified: dashboard `APT` chip + toast,
  `apt_notify` audit event, `apt_notified` counter in `/__status`),
  `apt-candidate` (shown, not notified) and `not-apt`, which falls back to a
  behavioural category derived from the alert's ATT&CK tactics (brute-force,
  scanning, exploit, exfiltration, lateral movement, C2 beacon, evasion -
  or commodity malware/C2 when only the IoC matched).

```yaml
attribution:            # deploy/config.yaml
  enabled: true
  top_k: 5              # candidates attached to each alert
  min_score: 0.15       # candidates below this are dropped
  min_notify: 0.25      # combined score required to notify
```

Honest caveat: neither dataset carries ground-truth *actor* labels, so this is
evidence-based candidate ranking with explicit confidence - never a claimed
supervised APT classifier. Tied top scores are marked ambiguous and the
confidence is discounted accordingly.

## The freshness model

Flows are replayed in timestamp order against a feed polled every Δ seconds:

* an IoC sighting is visible from the first poll boundary at/after it;
* it expires when no sighting landed within `replay.ttl_hours`;
* `feed_age_score = 0.5 ** (age / freshness_half_life_h)` — age measured from
  the poll boundary, not from the sighting, so staleness is exactly Δ-boundary
  lag;
* poll grid `t0` is aligned to the start of the replay.

Per-flow CTI features (the group removed by the E2 ablation):

```
ioc_src_match  ioc_dst_match  feed_age_score
feed_confidence  source_count  reputation_bucket
```

## Controlled IoC injection (read this before quoting E2/E3 numbers)

2017-era benchmark addresses are absent from today's feeds — the proposal's
risk table documents this. The pipeline therefore supports two provenances,
both stored and reported:

* **live** — IoCs actually returned by the 10 live feeds (always measured;
  overlap with benchmark IPs is reported as `live_feeds_only` in E2);
* **injected** — ground-truth IPs taken from malicious benchmark flows at
  `replay.injection_rate` (0.6), plus `replay.benign_ioc_rate` (0.004) of
  benign-only IPs as feed noise.

Controlled injection is an emulation with documented ground truth: it is
label-derived, so E2's FPR reduction is an **upper-bound style** estimate of
what accurate intelligence can buy, while `live_feeds_only` measures what today's
feeds actually deliver on this benchmark. Both rows are always written to the
same table so the gap cannot be hidden.

## Operating point

Thresholds are never taken at 0.5. For every model, θ is tuned on the
validation split as the largest threshold that still meets
`model.target_recall` (0.96). E2 therefore compares FPR **at matched recall**;
E3 reports both a fixed-θ curve (robustness to staleness) and a matched-recall
FPR curve (the cost of staleness in analyst workload).

## Results (full scale: 400,000 flows/dataset, 200 trees, seed 42)

Every experiment writes JSON + CSV under `results/tables/`, charts under
`results/figures/`, reason-coded alerts under `results/alerts/`.
Re-run everything with `powershell -File run_all.ps1`; `scripts/status_report.py`
prints the headline table.

### H1 — live CTI reduces FPR at matched recall (E2)

| dataset | traffic-only FPR (CV) | +CTI FPR (CV) | relative reduction | split-test reduction |
|---|---|---|---|---|
| UNSW-NB15 | 0.377 % | 0.365 % | **3.2 %** | **11.7 %** |
| CICIDS2017 | 0.0646 % | 0.0016 % | **97.6 %** | **97.4 %** |

Feature-group ablation (`traffic_cti_no_match`, IoC-match flags removed):
UNSW 2.2 %, CICIDS still 97.6 % — on CICIDS *every* feed-derived feature is a
label proxy (see threat below), not just the match flag.
`live_feeds_only` = traffic-only on both datasets: today's feeds share ~0 IPs
with 2017-era benchmarks.

**Verdict:** H1 (≥ 10 %) met on the split test for UNSW (11.7 %) and
overwhelmingly on CICIDS; the 5-fold CV estimate for UNSW (3.2 %) does not meet
it. Recall lands at 95.9 % vs the 96 % operating target.

### H2 — freshness curve (E3)

| | recall 5 min → 24 h (fixed θ) | IoC coverage, malicious | median age | FPR at matched recall |
|---|---|---|---|---|
| UNSW-NB15 | 95.94 % → 95.72 % (**−0.22 pp**) | 81.2 % → 5.8 % (monotone) | 2.6 → 11.2 min* | ×1.38 |
| CICIDS2017 | 95.93 % → 0 % (**−95.9 pp**) | 100 % → 99.99 % | 2.9 → 195 min | ×3.00 |

\* median age is non-monotone at 24 h because the surviving sightings are the
freshly re-published ones; `p90_age_min` in the JSON is monotone.

**Verdict:** the ≥ 3 pp recall-gap criterion fails on UNSW and passes on
CICIDS — and the CICIDS collapse is diagnosed, not cosmetic: a model whose
top features are CTI (E4 below) drops its positive scores from ~1.0 to ~0.73 at
1 h freshness while negatives stay at 0, so the 5-minute threshold stops firing
(`scripts/_diag_e3_scores.py`). The robust, dataset-independent staleness cost
is the **matched-recall FPR** (×1.38 / ×3.00) plus the coverage collapse on
UNSW. Report H2 as *partially supported, mechanism: freshness cost scales with
how much the model leans on intel*.

### H3 — reason-code stability (E4)

| dataset | mean top-10 Jaccard (min) | verdict | ATT&CK tactic TV distance | top-4 Jaccard | alerts with CTI in reasons |
|---|---|---|---|---|---|
| UNSW-NB15 | **0.891** (0.818) | PASS | 0.018 | 1.000 | 83.2 % |
| CICIDS2017 | **0.702** (0.538) | PASS | 0.008 | 1.000 | 100 % |

**Verdict:** H3 (≥ 0.7) passes on both datasets; tactic-level explanation mix
is essentially invariant across folds.

### H4 — end-to-end alert-path latency (E5)

Per-batch timing of enrich → design → predict → TreeSHAP → reason codes,
10k time-ordered test flows per batch size, alerts-only explanation
(`results/tables/e5_latency_*.json`):

| dataset | batch | p50 total | p95 total | explain p95 | score path p95 (no SHAP) |
|---|---|---|---|---|---|
| UNSW-NB15 | 16 | 102 ms | 278 ms | 181 ms | 110 ms |
| UNSW-NB15 | **64** | 180 ms | **671 ms** | 574 ms | 97 ms |
| UNSW-NB15 | 256 | 589 ms | 1966 ms | 1872 ms | 103 ms |
| CICIDS2017 | 16 | 76 ms | 146 ms | 69 ms | 80 ms |
| CICIDS2017 | **64** | 77 ms | **319 ms** | 246 ms | 79 ms |
| CICIDS2017 | 256 | 88 ms | 878 ms | 792 ms | 88 ms |

**Verdict:** H4 (p95 < 1 s per batch) **supported at the reference batch size of
64** on both datasets. Explanation scales linearly with the number of alerts per
batch: at 256-flow batches UNSW (663 alerts/10k flows) crosses the budget while
CICIDS (285 alerts) stays under. The score path without SHAP stays ≈ 80–110 ms
p95 regardless of batch size; the one-off feed poll is ≈ 5 s.

### E6 — cross-dataset transport

Both datasets mapped to an identical 18-feature canonical bridge (same formulas,
log1p, shared CTI block), θ tuned on the source only, evaluated on the target:

| direction | recall (cross → in-domain) | FPR (cross → in-domain) | PR-AUC (cross → in-domain) |
|---|---|---|---|
| UNSW → CICIDS | 38.3 % → 95.7 % | 6.97 % → 0.35 % | 35.0 % → 99.5 % |
| CICIDS → UNSW | **0.0 %** → 95.9 % | 0.00 % → 0.84 % | 49.8 % → 99.4 % |

**Verdict:** transport collapses in both directions. Even with a semantically
matched feature set, the source-tuned operating point does not survive the
distribution shift (CICIDS→UNSW never crosses θ), while ranking degrades far
less than the threshold suggests — deployment therefore requires a per-target
calibration set, which every other result in this thesis assumes.

### Threats to validity (read before quoting numbers)

1. **Controlled injection is label-derived.** On CICIDS2017 the attacker's
   address space is tiny, so feed membership ≈ the label: malicious-flow
   coverage is 100 % while all-flow coverage is 36.6 %. The 97.6 % FPR
   reduction is therefore an *upper bound under perfect intel coverage*, not
   an estimate of real-feed performance — `live_feeds_only` (0 % overlap)
   measures the latter and shows no gain.
2. **Linear SVM is a strawman at this operating point** (FPR ≈ 0.81 at
   96 % recall on both datasets); it is kept only as the proposal's baseline
   comparator.
3. `min_samples_leaf=20` (instead of 2) was chosen so TreeSHAP is tractable at
   400 k rows — E4 runtime dropped from 176 min to 4 min. It regularises every
   model in the suite equally.
4. **E6's bridge is deliberately narrow** (18 features): the two benchmarks
   share almost no raw columns, so transport is measured on the semantic
   intersection only — it bounds portability, it does not contradict the
   in-domain results of E1–E5.


## Reproducibility

* seed fixed at 42 for splits, models, subsampling and injection;
* scaling parameters are fit per training fold only (trees are scale-invariant,
  so Min–Max scaling is not applied to the RF/GBM path);
* `data/processed/*.parquet` caches the canonical frames; delete them to force a
  reload after changing `data.max_rows`.
* the APT attribution corpus and model are rebuildable from the repo:
  `scripts/build_actor_kb.py` (merges MITRE STIX + MISP galaxy into
  `data/threat_actors.json`) then `scripts/train_attribution.py`
  (deterministic TF-IDF fit -> `model/attribution_tfidf.joblib`).
