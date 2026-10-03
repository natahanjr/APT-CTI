# APT-CTI Scoring Service

Real-time, explainable threat scoring built from the thesis artefact
("Real-Time Cyber Threat Intelligence Fusion with Explainable ML for Early APT
Prediction"). It tails a sensor flow log, enriches each batch with **live CTI
feeds**, scores with the trained Random Forest, and pushes **TreeSHAP-explained
alerts** (MITRE technique mapped) to a file, a webhook, or syslog.

```
Zeek / Suricata / forwarder ──► flow file ──► service tail
        10 keyless feeds (+OTX/MISP) ──► every 5 min ──┘
                                                 │
                    score ≥ θ ──► alerts (JSONL · webhook · syslog)
                                                 │
                              GET /__status  (health)
```

## Quickstart

Native (repo root, venv):

```powershell
.venv\Scripts\python.exe deploy\service.py                 # tail data/inbox/flows.jsonl
.venv\Scripts\python.exe deploy\service.py --replay --input path\to\flows.jsonl
.venv\Scripts\python.exe deploy\service.py --online-feeds  # force live feeds (config default: online)
# web dashboard (charts + alert table): http://127.0.0.1:8099/
```

Docker (image bakes model + offline feed corpus as fallback, ~1.5 GB;
live feed polling works in the container too):

```bash
docker build -t apt-cti-scorer .
docker run -d --restart unless-stopped -p 8099:8099 \
  -v "$PWD/inbox:/app/data/inbox" \
  -v "$PWD/config.yaml:/app/deploy/config.yaml" \
  -e APT_CTI_TOKEN='<strong-token>' \
  -e NVIDIA_API_KEY="$NVIDIA_API_KEY" \
  apt-cti-scorer --config deploy/config.yaml --health-host 0.0.0.0
```

`--health-host 0.0.0.0` (any non-loopback bind) **requires** a token
(`APT_CTI_TOKEN` or `auth.token`) — otherwise the service refuses to start.

Note: `deploy/config.yaml` defaults to `start_at_end: true` (follow a live tail).
To score a file that already has content, set `start_at_end: false` (replay does
this automatically). Configuration: `deploy/config.yaml`.

### Autostart (Windows, per user, no admin)

```powershell
powershell -ExecutionPolicy Bypass -File deploy\install_scorer.ps1            # install (Startup folder)
powershell -ExecutionPolicy Bypass -File deploy\install_scorer.ps1 -StartNow  # install + launch hidden
powershell -ExecutionPolicy Bypass -File deploy\install_scorer.ps1 -Uninstall # remove + stop
```

Runs hidden via `pythonw.exe`; output appends to `deploy\scorer.log`.
Linux/macOS: use the hardened systemd unit `deploy/apt-cti-scorer.service`
(install notes are in the file header).

## Input formats

Detection is automatic (`input.format: auto`), or force `jsonl|csv|zeek|eve`.

| Format  | Source                                          | Notes |
|---------|-------------------------------------------------|-------|
| `jsonl` | forwarders, pipelines                           | canonical schema below (aliases accepted, e.g. `id.orig_h`, `bytes_toserver`) |
| `csv`   | exported logs                                   | header required, same column names/aliases |
| `zeek`  | Zeek `conn.log` (with `#fields` header)         | `conn_state`/`service` mapped to training vocab |
| `eve`   | Suricata `eve.json` (`event_type` flow/netflow) | `app_proto`/`state` mapped; other events skipped |

Canonical record (17 fields — everything else is derived: `Sload = sbytes*8/dur`,
`smeansz = sbytes/Spkts`, `byte_rate`, `pkt_rate`, `mean_pkt_size`,
`fwd_bwd_ratio`):

```
src_ip dst_ip src_port dst_port proto ts dur sbytes dbytes Spkts Dpkts
Sload Dload smeansz dmeansz service state        # last four optional
```

Vocabulary the model was trained on (anything else pools to `OTHER`):

- `service`: `-  dhcp  dns  ftp  ftp-data  http  pop3  radius  smtp  snmp  ssh`
- `state`:   `CLO  CON  ECO  FIN  INT  PAR  REQ  RST` (+ `UNK` if sensor omits it)

### Sensor vocab → training vocab

| Zeek `conn_state` | state | | Suricata `flow.state` | state |
|---|---|---|---|---|
| `SF`, `S1`, `S2`, `S3` | `FIN` | | `established` | `CON` |
| `S0` | `REQ` | | `new` | `REQ` |
| `REJ`, `RSTO`, `RSTR`, `RSTOS0`, `RSTRH` | `RST` | | `closed` | `FIN` |
| `OTH`, `RES1`, `RES2` | `INT` | | `broke`, `closed_by_enemy` | `INT` / `RST` |

Zeek `service`: `http/dns/ftp/smtp/ssh/dhcp/radius/pop3/snmp/ftp_data → same`,
`ssl/tls/irc/ntp/dnp3/krb5 → -` (no service). Suricata `app_proto`:
`http/http2/... → http`, `tls/ssl → -`, unknown → `-`.

## Model profiles

Bundles in `model/` (trained by `scripts/train_artifact.py`, metrics from the
held-out 80 k test split — identical to thesis E1):

| Bundle | Features | Accuracy | Recall | FPR | PR-AUC | θ | Use |
|---|---|---|---|---|---|---|---|
| `deploy_live_netflow.joblib` (default) | 38 | 98.97 % | 96.21 % | 0.63 % | 99.61 % | 0.8349 | sensor-side: flow cols + proto/service/state + derived + 6 CTI |
| `deploy_unsw_full.joblib` | 67 | 99.25 % | 95.94 % | 0.27 % | 99.77 % | 0.8802 | offline/reference: needs UNSW-only cols (`sttl`, `ct_*`, …) |

Live-vs-full delta: **−0.28 pp accuracy, +0.27 pp recall, FPR 0.27 % → 0.63 %,
−0.16 pp PR-AUC** (`results/tables/deploy_profiles.json`).

## Alerts

Emitted when `score ≥ θ`:

```json
{
 "alert_id": "b1-4", "emitted_at": "2026-10-02T05:09:13+00:00",
 "model": {"profile": "live_netflow", "theta": 0.8349},
 "flow": {"src_ip": "175.45.176.0", "dst_ip": "34.204.119.63", "dst_port": 53, "...": "..."},
 "score": 0.9734,
 "cti": {"ioc_dst_match": 1.0, "feed_age_score": 0.77, "feed_confidence": 0.8, "source_count": 1},
 "attribution": {
   "verdict": "apt-attributed", "notify": true, "confidence": 0.615,
   "actor": {"name": "Magic Hound", "mitre_id": "G0059", "origin": "Iran", "...": "..."},
   "candidates": [{"name": "Magic Hound", "mitre_id": "G0059", "score": 0.42, "...": "..."}],
   "techniques": ["T1041", "T1071"], "ioc_backed": true,
   "evidence": ["destination IP matched 1 live feed(s) - known malicious C2", "..."]
 },
 "reasons": [
   {"feature": "mean_pkt_size", "value": 57.0, "shap": 0.066, "reason": "mean pkt size = 57",
    "tactic": "Exfiltration", "technique": "T1041 · Exfiltration over C2 channel"},
   {"feature": "ioc_dst_match", "value": 1.0, "shap": null,
    "reason": "destination IP is on the live CTI feed (freshness 0.77, confidence 0.80, 1 source(s))",
    "tactic": "Command and Control", "technique": "T1071 · Application Layer Protocol"}
 ]
}
```

Sinks (`config.yaml → alerts`): `jsonl` (local file), `webhook_url` (POST with
one retry; `https://` URLs work out of the box, optional `webhook_token` sent as
`Authorization: Bearer`), `syslog_host/port` (UDP). Failures are swallowed —
scoring never stops.

### APT attribution

Each alert carries an `attribution` verdict (see the root README section
"APT attribution layer" for the model): `apt-attributed` (group named **and**
notified), `apt-candidate` (plausible, not notified) or `not-apt` (behavioural
category fallback, e.g. exfiltration / scanning / C2 beacon). Notifying
requires all of: combined score ≥ `attribution.min_notify` (0.25), a
specificity gate (≤ 2-3 near-tied competitors) and corroboration — a live-feed
IoC match or ≥ 2 independent technique hits. Notified alerts produce:

- an `apt_notify` entry in the audit log (alert_id, actor, MITRE ID, confidence),
- `apt_notified` and `attribution {enabled, n_actors}` counters in `/__status`,
- an `APT` chip on the alert row, an **APT attribution** KPI card, the header
  `APT n` chip, a toast on fresh notifications, an `APT notifications only`
  filter pill, and the evidence/candidate breakdown in the alert drill-down.

```yaml
attribution:        # deploy/config.yaml
  enabled: true
  top_k: 5          # candidates attached to each alert
  min_score: 0.15   # candidates below this are dropped
  min_notify: 0.25  # combined score required to notify
```

`enabled: false` skips loading the corpus and alerts omit the block. No
ground-truth actor labels exist in the datasets — verdicts are evidence-based
candidates with explicit confidence, not a supervised APT classifier.

## Feeds

- **Online (default in `deploy/config.yaml`)**: `feeds.online: true` polls
  `sources:` the 10 keyless feeds (`urlhaus, threatfox, feodo, binarydefense,
  emerging, cins, blocklist, ipsum, openphish, certpl`) every 5 min through DoH
  (works on broken-DNS networks). OTX/MISP can be added to `sources` once API
  keys are set in `config/default.yaml`. TTL 168 h, freshness half-life 6 h
  (protocol §3.4). Live polls do **not** rewrite the snapshot corpus.
- **Offline** (`feeds.online: false`): snapshots in `data/feed_snapshots/`
  (the thesis corpus, 553 147 records / 16 204 indicators) — deterministic,
  no network needed.
- Sightings map is rebuilt on each refresh; scoring uses whatever was loaded
  last. `/__status` reports `feed_mode`, per-source `feed_sources`
  (ok/records/error/duration) and `feed_error`; the dashboard shows them as
  chips. A refresh that returns zero records is rejected (previous sightings
  kept) so a network outage cannot silently wipe the IoC set.

## Web view & health

- **`GET /`** — security dashboard (auto-refresh 3 s). Above the views sits a
  top-level **Overview** strip: four hero cards (**Alerts**, **Last 5 min**,
  **IoC hits**, **APT attributed** — large tiered value, live caption such as
  “9.2× the 15-min average” or “22 notified · 3 candidate(s)”) over five
  compact system cards (**Profile**, **Threshold θ**, **Flows scored**,
  **Feed IoCs**, **Feeds synced** — batches, features, source counts).
  Every card opens its deep-explain sheet. Two views:
  - **Dashboard** (default): **Threat Activity** with a 15-minute alert
    timeline overlaid by a live **heartbeat** (ECG trace whose spike height
    scales with per-minute alert count, `/min` beat readout, pulse animation
    when the count changes), score distribution vs θ, protocol mix, ATT&CK
    tactic bars, top targets (★ = IoC hit), a **Top APT Groups** chip panel
    (notified actors with counts — red chips notified, amber candidates —
    click for an evidence insight + filter), and feed-health chips (live
    mode, per-source status).
  - **Everything is clickable**: any widget (timeline bar, score band,
    protocol segment/legend, tactic, target, feed chip, APT group row)
    opens a **deep-explain sheet** — what the metric shows, how it is
    computed, a baseline comparison (e.g. “17 alerts · 15× the 15-min
    average”), why it matters in threat terms, and a one-click
    “Show N alerts →” action that filters the table.
  - The **APT attributed KPI card** and the `APT n` chip open the
    **APT Attribution window** — the deep, visual (no prose) walk-through
    of how a name is assigned: ① evidence extraction (SHAP reasons →
    MITRE techniques → live IoC feeds → rarity weighting, with the real
    evidence bundle of a worked alert), ② TF-IDF candidate ranking over
    the 1040-actor / 52,835-feature corpus (live score bars per candidate
    with retrieval, overlap and shared technique IDs), ③ the
    `0.6·overlap + 0.4·retrieval` formula with all **four notify gates
    worked ✓/✗ on a real alert**, and ④ the three verdict tiers with live
    tallies plus the 7 behavioural-category rules for `not-apt`.
  - The header **`LIVE`** chip opens the **Live Feeds window** — the visual
    counterpart of the old status sheet: ① chip-state legend
    (LIVE / FEED ERR / OFFLINE / LOCKED, current state ringed) with the
    “scoring never stops” guarantees, ② the ingestion flow
    (poll every N min → corpus records → dedupe + TTL 168 h → freshness
    half-life 6 h → live indicators → enrichment features → fusion
    verdict), and ③ live health KPIs plus per-source chips that drill into
    the existing provenance sheet.
  - Every remaining KPI card (Alerts, Last 5 min, IoC hits, Model profile,
    Threshold θ, Flows scored, Feed IoCs, Feeds synced) opens the same
    style **deep-dive window** instead of a prose sheet: alert lifecycle
    flow, a 5-minute per-minute bar chart, the correlation path, bundle +
    profile cards, a θ axis with policy trade-offs, the throughput path,
    the indicator-set flow and the sync cadence — live numbers throughout,
    a filter CTA where a filter applies, and cross-links into the ML /
    LIVE windows.
  - The header **`◆ ML 0.8349`** chip — pulsing dot and live θ in the label,
    idle-greys if no model bundle is loaded, same treatment as the `LIVE` /
    `APT n` chips — opens the **ML Pipeline** window instead of a sheet:
    a *visual process view* of train → detect → attribute: stage flow boxes
    (dataset → design matrix → forest → held-out test → θ → artifact),
    train/test split bar, confusion matrix, θ axis, live alert-score
    spectrum, global feature-importance bars, the notify gate worked
    ✓/✗ on a real alert, and live verdict tallies — “Detailed
    explanation” inside it opens the long-form text sheet.
  - **Stale-tab guard**: each page embeds a build stamp; if `/__status`
    reports a newer build than the open tab, a “↻ Dashboard updated”
    banner appears at the top (refresh button) so an outdated browser
    tab can never silently miss new UI such as the ML chip/window.
  - **Alerts**: a detail-rich table — clock + relative age, confidence-tiered
    score pill with its margin over θ, structured flow (src → dst over
    port/protocol chips), top reason + hidden-reason count, ATT&CK tactic
    chip + technique line, an **Attribution** column (`APT`/`APT?` chip with
    actor name · MITRE ID · confidence, or a `non-APT` tag with the
    behavioural category) and an IoC dot with source count (tooltip shows
    freshness/confidence). Notified rows carry a red tint. Click a
    row for all SHAP reasons + feed context, the attribution evidence
    (actor, candidates, why it was named) and the AI brief button.
    Structured filters (minute, protocol, score band, IoC-only,
    APT-notifications-only, last 5 min) appear as dismissible **filter
    pills** above the table. Fresh APT notifications pop a toast.
  Data routes require the auth token when configured — the page shell stays
  public so the unlock screen can render; the token is kept in
  sessionStorage (`?token=<t>` in the URL also works). Binds `127.0.0.1` by
  default.
- **`GET /api/alerts?limit=100`** — same alerts as JSON (tail of the JSONL
  log; rotation archives are merged, newest first).
- **`GET /__status`** — counters + feed state:

```powershell
Invoke-RestMethod http://127.0.0.1:8099/__status
# { alive, flows_scored, batches, alerts, feed_mode, feed_sources,
#   feed_indicators, feed_error, attribution, apt_notified, web, xai, ... }
```

In containers bind with `--health-host 0.0.0.0` and put auth/TLS in front
(reverse proxy) if exposing beyond localhost.

## AI explanation layer (optional)

Each alert already carries TreeSHAP reason codes. With an API key
(`xai.api_key` / API-key environment variable) the service can also produce
a plain-English analyst brief per alert:

```powershell
# preferred: environment variable (restart the service afterwards)
setx NVIDIA_API_KEY "nvapi-..."
# or put it under xai.api_key in deploy\config.yaml (do not commit)
```

- **`POST /api/explain {"alert_id": "..."}`** →
  `200 { alert_id, explanation, model }` · `400` disabled/invalid request ·
  `404` unknown alert · `502` upstream model failure.
- The web UI shows an **Explain with AI** button per alert row when
  `xai.enabled` is true (responses are cached per alert); the header
  **✦ AI** chip opens the visual explainability window (request path,
  payload gates, cache/rate-limit/audit controls, brief anatomy).
- Sends flow metadata + SHAP reason codes + the threshold verdict — no raw
  payload, no IPs beyond the alert's own flow fields. Only on explicit user
  click; nothing is called automatically. `deploy/xai.py` documents this.

## Security & hardening

Designed for deployment behind a bank/university/government security team's
controls:

- **Authentication**: `auth.token` in `deploy/config.yaml` (or the
  `APT_CTI_TOKEN` environment variable — preferred for Docker/systemd).
  All `__status`/`api` routes accept `Authorization: Bearer <t>`,
  `X-Auth-Token: <t>`, or `?token=<t>`; comparisons are constant-time
  (`hmac.compare_digest`). Empty token = **loopback-only access**.
- **Fail closed**: binding `health.host` to any non-loopback address without
  a token makes the service refuse to start. Remote access therefore always
  requires a token; terminate TLS in front (nginx/caddy `proxy_pass` to
  `127.0.0.1:8099`) rather than exposing plain HTTP.
- **Rate limiting**: `POST /api/explain` is limited to
  `auth.explain_per_min` requests/minute (default 12) → `429` beyond.
- **Audit trail**: `alerts.audit_log` (default `deploy/audit.log`) records
  `service_start`, auth failures (`auth_deny`, throttled), every explain
  request (`explain_ok`/`explain_error`/`explain_rate_limited`) and APT
  notifications (`apt_notify` with actor + MITRE ID) with
  timestamp + client IP; the file rotates at 10 MB (5 archives kept).
- **Alert retention**: `alerts.rotate_mb` (default 50) + `alerts.keep_files`
  (default 8) rotate the alert JSONL into timestamped archives; older
  archives are pruned (retention policy).
- **Browser hardening**: every response carries `X-Content-Type-Options:
  nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a CSP
  (`default-src 'self'`), and `Cache-Control: no-store`.
- **Linux service**: `deploy/apt-cti-scorer.service` ships with
  `NoNewPrivileges`, `ProtectSystem=strict` + explicit `ReadWritePaths`,
  `PrivateTmp`, capability bounding set dropped, `UMask=0077`, and secrets
  via `EnvironmentFile=-/etc/default/apt-cti-scorer` (chmod 600).
- **Docker**: non-root `scorer` user, `HEALTHCHECK` against `/__status`
  (token-aware), `--restart unless-stopped`, secrets only via `-e`.
- **Data egress**: the AI brief (flow metadata + SHAP reasons only) is sent
  to the configured AI model only on explicit click, never automatically;
  disable by leaving the API key unset.

## Tests

```powershell
.venv\Scripts\python.exe deploy\test_service.py
```

Phase A replay: 128 held-out UNSW flows (Feodo C2 IPs forced on attack rows) →
asserts alerts ≥ θ with reasons, IoC hits and a valid attribution verdict
(3-tier taxonomy, notify flag, category on `not-apt`). Phase B runtime: live
tail, `/__status` (incl. `attribution.enabled`), web UI `/` and
`/api/alerts`, plus `POST /api/explain`
(200 with a brief if a key is configured, graceful 400 otherwise, 404 for an
unknown alert). Phase D security: fail-closed non-loopback bind, 401/200
token matrix (header + query), explain rate limit → 429, alert-log rotation
with archive-aware `/api/alerts`, audit-trail events. Phase C: zeek/eve/jsonl
vocab-mapping assertions.

## Performance

Batch 64 (E5, end-to-end on the thesis machine): 671 ms UNSW / 319 ms CICIDS;
observed in the service: `predict ≈ 0.1 s`, TreeSHAP ≈ 40 ms **per alert**
(≈ 2.6 s for a 61-alert batch), total ≈ 3–4 s per batch — well inside the 5 s
flush. Throughput is bound by SHAP, not the model.

## Honest limitations

- **Train/serve skew**: category vocabularies are frozen (`OTHER`/`UNK`
  pooling); unseen sensors values degrade gracefully, not for free.
- **CTI features**: trained with controlled injection (0.6 % of benign rows);
  at runtime they come from real feeds only (`injection: none`), and the offline
  corpus drifts — live feeds are fresher but noisier.
- **Metrics are offline** (UNSW-NB15 held-out). Production traffic is
  unlabeled: expect the FPR, not the accuracy, to be the number you feel.
- Single node, file-tail input (no Kafka/multi-tenant); webhook auth is a
  bearer token only — put real auth/TLS policy at your reverse proxy; manual
  retraining (`scripts/train_artifact.py`).
- θ is fixed at target recall 0.96 on the validation split; retune per site.

Thesis protocol/details: chapters 3–5; artefact root `README.md`.
