#!/usr/bin/env python
"""End-to-end check for the scoring service (run from the repo root with the venv):

    .venv\\Scripts\\python.exe deploy\\test_service.py

Phase A -- replay: score real UNSW rows (reshaped to canonical sensor records,
           fresh timestamps, Feodo C2 IPs forced onto some attack rows), assert
           alerts land in the JSONL sink with reasons and IoC matches.
Phase B -- runtime: tail an empty file, append flows, assert /__status reports
           the scored batch and the feed corpus, then terminate cleanly.
Phase D -- security: fail-closed non-loopback bind, token 401/200 matrix,
           /api/explain rate limit (429), alert rotation + archive-aware tail,
           audit trail events.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
VENV_PY = ROOT / ".venv" / "Scripts" / "python.exe"
WORK = ROOT / "deploy" / "_e2e"
PARQUET = ROOT / "data" / "processed" / "unsw_nb15_rows400000_seed42.parquet"
FEED_IPS = ["162.243.103.246", "178.62.3.223", "27.133.154.218",
            "34.204.119.63", "50.16.16.211"]
NATIVE = ["src_ip", "dst_ip", "src_port", "dst_port", "proto", "ts", "dur",
          "sbytes", "dbytes", "Spkts", "Dpkts", "Sload", "Dload",
          "smeansz", "dmeansz", "service", "state"]


def build_records() -> list[dict]:
    """Real UNSW attack/benign rows as canonical sensor records."""
    df = pd.read_parquet(PARQUET, columns=NATIVE + ["label"])
    attacks = df[df["label"] == 1].sample(n=64, random_state=7)
    benign = df[df["label"] == 0].sample(n=64, random_state=7)
    rows = pd.concat([attacks, benign]).sample(frac=1.0, random_state=9)
    now = time.time()
    records = []
    for i, (_, row) in enumerate(rows.iterrows()):
        rec = {c: row[c] for c in NATIVE}
        rec["ts"] = now - i * 0.25
        rec["src_port"], rec["dst_port"] = int(rec["src_port"]), int(rec["dst_port"])
        if row["label"] == 1 and i % 3 == 0:
            rec["dst_ip"] = FEED_IPS[i % len(FEED_IPS)]
        records.append({k: (float(v) if isinstance(v, (float,)) else v)
                        for k, v in rec.items()})
    return records


def write_config(path: Path, input_path: Path, alerts_path: Path, port: int,
                 start_at_end: bool, token: str = "", explain_per_min: int = 12,
                 rotate_mb: float = 50.0, audit_log: str = "") -> None:
    path.write_text(
        f"""bundle: {ROOT / 'model' / 'deploy_live_netflow.joblib'}
input:
  path: {input_path}
  format: jsonl
  start_at_end: {str(start_at_end).lower()}
batch:
  max_flows: 64
  flush_s: 1.0
feeds:
  online: false
  poll_interval_min: 5
  ttl_hours: 168.0
  half_life_h: 6.0
  snapshot_dir: {ROOT / 'data' / 'feed_snapshots'}
alerts:
  jsonl: {alerts_path}
  rotate_mb: {rotate_mb}
  keep_files: 8
  audit_log: {audit_log if audit_log else '""'}
  webhook_url: ""
  syslog_host: ""
  syslog_port: 514
  top_k_reasons: 3
auth:
  token: {token if token else '""'}
  explain_per_min: {explain_per_min}
health:
  host: 127.0.0.1
  port: {port}
xai:
  reasoning_effort: low
  timeout_s: 60
""", encoding="utf-8")


def run_replay(cfg: Path, flows: Path, out: Path) -> list[str]:
    out.unlink(missing_ok=True)
    r = subprocess.run(
        [str(VENV_PY), str(ROOT / "deploy" / "service.py"),
         "--config", str(cfg), "--input", str(flows), "--replay"],
        capture_output=True, text=True, timeout=600, encoding="utf-8",
        errors="replace")
    print("--- replay stdout ---\n" + r.stdout.strip())
    if r.returncode != 0:
        print(r.stderr[-4000:])
        raise SystemExit(f"FAIL: replay exit {r.returncode}")
    if not out.exists():
        raise SystemExit("FAIL: no alert file written")
    lines = [json.loads(l) for l in out.read_text(encoding="utf-8").splitlines() if l.strip()]
    if not lines:
        raise SystemExit("FAIL: alert file empty (no flow crossed theta)")
    for a in lines:
        assert a["score"] >= a["model"]["theta"], "alert below theta"
        assert a["reasons"], "alert missing reason codes"
        assert {"src_ip", "dst_ip", "proto"} <= set(a["flow"]), "alert missing flow"
        att = a.get("attribution") or {}
        assert att.get("verdict") in ("apt-attributed", "apt-candidate", "not-apt"), \
            f"bad attribution verdict: {att.get('verdict')!r}"
        assert isinstance(att.get("notify"), bool), "attribution.notify missing"
        assert att.get("candidates") or att.get("verdict") == "not-apt" \
            or att.get("category"), "attribution carries neither candidates nor category"
        if att["verdict"] == "not-apt":
            assert att.get("category"), "not-apt alert missing behavioural category"
    if not any(a["cti"]["ioc_dst_match"] > 0 for a in lines):
        raise SystemExit("FAIL: no alert carries an IoC match")
    print(f"phase A OK: {len(lines)} alerts, "
          f"{sum(a['cti']['ioc_dst_match'] > 0 for a in lines)} with IoC hits")
    return lines


def run_runtime(cfg: Path, input_path: Path, appended: list[dict],
                port: int) -> dict:
    input_path.unlink(missing_ok=True)
    proc = subprocess.Popen(
        [str(VENV_PY), str(ROOT / "deploy" / "service.py"), "--config", str(cfg)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        encoding="utf-8", errors="replace")
    try:
        url = f"http://127.0.0.1:{port}/__status"
        status = None
        last = None
        for i in range(90):           # import + feed refresh + first response
            try:
                with urllib.request.urlopen(url, timeout=5) as r:
                    status = json.loads(r.read())
                break
            except Exception as exc:
                if proc.poll() is not None:
                    raise SystemExit(
                        f"FAIL: service died rc={proc.returncode} "
                        f"during health poll: {exc}")
                msg = f"{type(exc).__name__}: {exc}"
                if msg != last:
                    print(f"  health poll {i}: {msg}")
                    last = msg
                time.sleep(1)
        if not status:
            raise SystemExit("FAIL: health endpoint never answered")
        with input_path.open("a", encoding="utf-8") as fh:
            for rec in appended:
                fh.write(json.dumps(rec) + "\n")
        for attempt in range(60):
            try:
                with urllib.request.urlopen(url, timeout=5) as r:
                    status = json.loads(r.read())
            except Exception as exc:                          # transient slowness
                print(f"  status poll {attempt}: {type(exc).__name__}")
                time.sleep(1)
                continue
            if status["flows_scored"] >= len(appended):
                break
            time.sleep(1)
        assert status["alive"] is True
        assert status["flows_scored"] >= len(appended), \
            f"scored {status['flows_scored']} < {len(appended)}"
        assert status["feed_indicators"] >= 5, status
        assert status["profile"] == "live_netflow"
        assert (status.get("attribution") or {}).get("enabled") is True, status
        assert status["web"].endswith(f":{port}/"), status["web"]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as r:
            html = r.read().decode()
        assert r.status == 200 and "APT-CTI" in html and "live alerts" in html.lower()
        with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/api/alerts?limit=50", timeout=5) as r:
            alerts = json.loads(r.read())
        assert isinstance(alerts, list) and alerts, "viewer api returned no alerts"
        a = alerts[-1]
        assert "score" in a and a.get("reasons") and "flow" in a and "cti" in a, a
        # XAI endpoint: 200 with a brief if a key is configured, else graceful 400/502
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/explain",
            data=json.dumps({"alert_id": a["alert_id"]}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=90) as r:
                body = json.loads(r.read())
            assert body.get("explanation"), body
            assert body.get("model"), body
            print(f"  xai: explanation via {body['model']} "
                  f"({len(body['explanation'])} chars)")
        except urllib.error.HTTPError as he:
            err = json.loads(he.read())
            assert he.code in (400, 502) and err.get("error"), (he.code, err)
            print(f"  xai: not configured/error as expected -> {err['error'][:70]}")
        req2 = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/explain",
            data=json.dumps({"alert_id": "no-such-alert"}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req2, timeout=30) as r:
                code2, body2 = r.status, json.loads(r.read())
        except urllib.error.HTTPError as he:
            code2, body2 = he.code, json.loads(he.read())
        assert code2 in (400, 404) and body2.get("error"), (code2, body2)
        print(f"phase B OK: scored={status['flows_scored']} "
              f"alerts={status['alerts']} feed_indicators={status['feed_indicators']} "
              f"web={status['web']} api_rows={len(alerts)}")
        return status
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
        out, err = proc.communicate(timeout=5)
        if out.strip():
            print("--- service stdout ---\n" + out.strip())
        if err.strip():
            print("--- service stderr ---\n" + err.strip()[-2000:])


def run_adapters() -> None:
    """Static parser checks: sensor vocab -> training vocab."""
    sys.path.insert(0, str(ROOT / "deploy"))
    import flow_adapters as fa

    zeek = ("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\t"
            "proto\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\t"
            "conn_state\tservice\n"
            "1700000000.5\tCabc\t10.1.1.1\t44321\t162.243.103.246\t443\ttcp\t"
            "2.5\t1200\t3400\t10\t12\tSF\thttp\n")
    recs = fa.parse_chunk(zeek, "zeek")
    assert len(recs) == 1, recs
    r = recs[0]
    assert r["state"] == "FIN" and r["service"] == "http", r
    assert r["dst_ip"] == "162.243.103.246" and r["dur"] == 2.5, r

    eve = json.dumps({
        "event_type": "flow", "timestamp": "2026-10-02T10:00:00.000000+0000",
        "src_ip": "10.2.2.2", "src_port": 51000, "dest_ip": "50.16.16.211",
        "dest_port": 443, "proto": "TCP", "app_proto": "tls",
        "flow": {"start": "2026-10-02T10:00:00.000000+0000",
                 "end": "2026-10-02T10:00:03.000000+0000",
                 "bytes_toserver": 900, "bytes_toclient": 2000,
                 "pkts_toserver": 7, "pkts_toclient": 9,
                 "state": "established"}})
    recs = fa.parse_chunk(eve, "eve")
    assert len(recs) == 1, recs
    r = recs[0]
    assert r["service"] == "-", r["service"]        # tls -> no-training-service
    assert r["state"] == "CON" and r["proto"] == "tcp", r
    assert r["dur"] == 3.0 and r["Spkts"] == 7, r

    generic = json.dumps({"src_ip": "10.3.3.3", "dst_ip": "10.4.4.4",
                          "id.orig_p": 1234, "id.resp_p": 53, "proto": "UDP",
                          "timestamp": 1700000000, "duration": 0.5,
                          "bytes_toserver": 120, "bytes_toclient": 240,
                          "orig_pkts": 2, "resp_pkts": 3, "app_proto": "dns"})
    r = fa.parse_chunk(generic, "jsonl")[0]
    assert r["service"] == "dns" and r["state"] == "UNK", r
    assert r["smeansz"] == 60.0, r                  # derived: sbytes/Spkts
    print("phase C OK: zeek/eve/jsonl adapters map sensor vocab to training vocab")


def run_auth(port: int) -> None:
    """Production security: token auth, rate limit, rotation, audit, fail-closed."""
    token = "e2e-secret"

    # 0) fail-closed: non-loopback bind without a token must refuse to start
    cfg_fc = WORK / "config_failclosed.yaml"
    write_config(cfg_fc, WORK / "fc_flows.jsonl", WORK / "fc_alerts.jsonl",
                 18101, start_at_end=True)
    txt = cfg_fc.read_text(encoding="utf-8").replace("host: 127.0.0.1",
                                                     "host: 0.0.0.0")
    cfg_fc.write_text(txt, encoding="utf-8")
    r = subprocess.run(
        [str(VENV_PY), str(ROOT / "deploy" / "service.py"),
         "--config", str(cfg_fc)],
        capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=120)
    msg = r.stdout + r.stderr
    assert r.returncode != 0 and "refusing to bind" in msg, \
        f"fail-closed bind not enforced: rc={r.returncode} {msg[-800:]}"
    print("  fail-closed: non-loopback bind without token refused")

    # 1) start a token-protected service
    input_d = WORK / "auth_flows.jsonl"
    alerts_d = WORK / "auth_alerts.jsonl"
    audit_d = WORK / "auth_audit.log"
    input_d.unlink(missing_ok=True)
    alerts_d.unlink(missing_ok=True)
    audit_d.unlink(missing_ok=True)
    for old in WORK.glob("auth_alerts-*.jsonl"):
        old.unlink(missing_ok=True)
    cfg_d = WORK / "config_auth.yaml"
    write_config(cfg_d, input_d, alerts_d, port, start_at_end=True,
                 token=token, explain_per_min=2, rotate_mb=0.0001,
                 audit_log=str(audit_d))
    proc = subprocess.Popen(
        [str(VENV_PY), str(ROOT / "deploy" / "service.py"), "--config", str(cfg_d)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        encoding="utf-8", errors="replace")
    try:
        base = f"http://127.0.0.1:{port}"

        def get(path, hdrs=None):
            req = urllib.request.Request(base + path, headers=hdrs or {})
            try:
                with urllib.request.urlopen(req, timeout=90) as resp:
                    return resp.status, json.loads(resp.read()), dict(resp.headers)
            except urllib.error.HTTPError as he:
                body = he.read()
                try:
                    return he.code, json.loads(body), dict(he.headers)
                except ValueError:
                    return he.code, body.decode(), dict(he.headers)

        # wait for health: an unauthenticated probe must end in 401
        saw401, last = False, None
        for i in range(90):
            try:
                urllib.request.urlopen(f"{base}/__status", timeout=5)
            except urllib.error.HTTPError as he:
                assert he.code == 401, f"expected 401, got {he.code}"
                saw401 = True
                break
            except Exception as exc:                       # noqa: BLE001
                if proc.poll() is not None:
                    raise SystemExit(f"FAIL: service died rc={proc.returncode}: {exc}")
                m = f"{type(exc).__name__}: {exc}"
                if m != last:
                    print(f"  auth health poll {i}: {m}")
                    last = m
            time.sleep(1)
        assert saw401, "service never demanded a token"

        # 2) auth matrix
        code, body, _ = get("/__status")
        assert code == 401 and body.get("error") == "auth required", (code, body)
        code, _, _ = get("/__status", {"X-Auth-Token": "wrong-token"})
        assert code == 401, code
        code, st, _ = get("/__status", {"Authorization": f"Bearer {token}"})
        assert code == 200 and st.get("alive") is True, (code, st.get("alive"))
        assert st.get("auth_required") is True, st
        code, alerts, _ = get("/api/alerts?limit=5", {"X-Auth-Token": token})
        assert code == 200 and isinstance(alerts, list), (code, alerts)
        code, _, _ = get(f"/api/alerts?limit=5&token={token}")   # query form
        assert code == 200, code
        # static shell stays public so the unlock screen can render
        req = urllib.request.Request(base + "/")
        with urllib.request.urlopen(req, timeout=10) as resp:
            page = resp.read().decode()
            sec = {k: resp.headers.get(k) for k in
                   ("X-Content-Type-Options", "X-Frame-Options",
                    "Referrer-Policy", "Content-Security-Policy")}
        assert 'id="unlock"' in page, "unlock shell missing from /"
        assert (sec["X-Content-Type-Options"] == "nosniff"
                and sec["X-Frame-Options"] == "DENY"
                and sec["Referrer-Policy"] and sec["Content-Security-Policy"]), sec
        print("  auth matrix: 401 (no/wrong token) -> 200 (Bearer/query) "
              "+ security headers OK")

        # 3) score flows with the token attached
        with input_d.open("a", encoding="utf-8") as fh:
            for rec in build_records()[:80]:
                fh.write(json.dumps(rec) + "\n")
        for _ in range(60):
            code, st, _ = get("/__status", {"X-Auth-Token": token})
            if st.get("flows_scored", 0) >= 80:
                break
            time.sleep(1)
        assert st.get("flows_scored", 0) >= 80, st

        # 4) rate limit: 3rd /api/explain within 60 s -> 429
        codes = []
        for aid in ("r1", "r2", "r3"):
            req = urllib.request.Request(
                f"{base}/api/explain",
                data=json.dumps({"alert_id": aid}).encode(),
                headers={"Content-Type": "application/json",
                         "X-Auth-Token": token}, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=90) as resp:
                    codes.append(resp.status)
            except urllib.error.HTTPError as he:
                codes.append(he.code)
        assert codes[0] != 429 and codes[1] != 429, codes
        assert codes[2] == 429, codes
        print(f"  rate limit: explain codes {codes} (3rd -> 429)")

        # 5) rotation: tiny threshold -> archives exist; API still serves them
        archives = sorted(WORK.glob("auth_alerts-*.jsonl"))
        assert archives, "alert rotation archive missing"
        code, alerts, _ = get("/api/alerts?limit=50", {"X-Auth-Token": token})
        assert code == 200 and isinstance(alerts, list), (code, type(alerts))
        print(f"  rotation: {len(archives)} archive(s), api_rows={len(alerts)}")

        # 6) audit trail
        audit = audit_d.read_text(encoding="utf-8")
        for ev in ("service_start", "auth_deny", "explain_rate_limited"):
            assert f'"event": "{ev}"' in audit, f"audit missing {ev}"
        print("  audit: service_start + auth_deny + explain_rate_limited logged")
        print(f"phase D OK: auth + rate limit + rotation + audit on :{port}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
        out, err = proc.communicate(timeout=5)
        if out.strip():
            print("--- auth service stdout ---\n" + out.strip())
        if err.strip():
            print("--- auth service stderr ---\n" + err.strip()[-2000:])


def main() -> None:
    WORK.mkdir(parents=True, exist_ok=True)
    flows = WORK / "flows.jsonl"
    records = build_records()
    flows.write_text("".join(json.dumps(r) + "\n" for r in records),
                     encoding="utf-8")

    cfg_a = WORK / "config_replay.yaml"
    write_config(cfg_a, flows, WORK / "alerts_a.jsonl", 18099, start_at_end=False)
    run_replay(cfg_a, flows, WORK / "alerts_a.jsonl")

    cfg_b = WORK / "config_runtime.yaml"
    input_b = WORK / "runtime_flows.jsonl"
    write_config(cfg_b, input_b, WORK / "alerts_b.jsonl", 18100, start_at_end=True)
    run_runtime(cfg_b, input_b, records[:80], port=18100)

    run_auth(18101)
    run_adapters()
    print("E2E: ALL OK")


if __name__ == "__main__":
    sys.exit(main())
