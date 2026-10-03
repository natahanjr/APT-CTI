#!/usr/bin/env python
"""APT-CTI real-time scoring service.

    tail flows -> enrich (live CTI + freshness) -> RandomForest >= theta
              -> TreeSHAP reason codes -> alerts (JSONL / webhook / syslog)

    python deploy/service.py                       # tail config's inbox
    python deploy/service.py --input logs/eve.json # point at a sensor log
    python deploy/service.py --replay              # score whole file, exit

Health: GET http://127.0.0.1:<health_port>/__status
"""
from __future__ import annotations

import argparse
import hmac
import ipaddress
import json
import os
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cti_pipeline.attribution import default_engine                    # noqa: E402
from cti_pipeline.collector import load_snapshots, poll_once           # noqa: E402
from cti_pipeline.enrich import (                                      # noqa: E402
    CTI_FEATURES, ReplaySettings, build_sightings, enrich)
from cti_pipeline.explain import make_explainer, reason_codes, shap_matrix  # noqa: E402
from cti_pipeline.net import ensure_doh                                # noqa: E402

import flow_adapters as fa                                             # noqa: E402
import sinks as sk                                                     # noqa: E402
import viewer as vw                                                    # noqa: E402
import xai as xa                                                       # noqa: E402

DEFAULTS = {
    "bundle": "model/deploy_live_netflow.joblib",
    "input": {"path": "data/inbox/flows.jsonl", "format": "auto", "start_at_end": True},
    "batch": {"max_flows": 64, "flush_s": 5.0},
    "feeds": {"online": False, "poll_interval_min": 5, "ttl_hours": 168.0,
              "half_life_h": 6.0, "snapshot_dir": "data/feed_snapshots"},
    "alerts": {"jsonl": "deploy/alerts/alerts.jsonl", "webhook_url": "",
               "syslog_host": "", "syslog_port": 514, "top_k_reasons": 3,
               "rotate_mb": 50.0, "keep_files": 8,
               "audit_log": "deploy/audit.log"},
    "auth": {"token": "", "explain_per_min": 12},
    "health": {"host": "127.0.0.1", "port": 8099},
    "attribution": {"enabled": True, "top_k": 5, "min_score": 0.15,
                    "min_notify": 0.25},
}


def load_deploy_config(path: Path | None) -> dict:
    cfg = json.loads(json.dumps(DEFAULTS))  # deep copy
    if path and path.exists():
        import yaml
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for section, values in raw.items():
            if isinstance(values, dict) and section in cfg:
                cfg[section].update(values)
            else:
                cfg[section] = values
    return cfg


def resolve(p: str) -> Path:
    q = Path(p)
    return q if q.is_absolute() else ROOT / q


def add_derived(df: pd.DataFrame) -> pd.DataFrame:
    dur = pd.to_numeric(df["dur"], errors="coerce").fillna(0.0).clip(lower=0.0)
    sb = pd.to_numeric(df["sbytes"], errors="coerce").fillna(0.0).clip(lower=0.0)
    db = pd.to_numeric(df["dbytes"], errors="coerce").fillna(0.0).clip(lower=0.0)
    sp = pd.to_numeric(df["Spkts"], errors="coerce").fillna(0.0).clip(lower=0.0)
    dp = pd.to_numeric(df["Dpkts"], errors="coerce").fillna(0.0).clip(lower=0.0)
    out = df.copy()
    dur_safe = dur.clip(lower=1e-6)
    out["byte_rate"] = (sb + db) / dur_safe
    out["pkt_rate"] = (sp + dp) / dur_safe
    out["mean_pkt_size"] = (sb + db) / (sp + dp).clip(lower=1.0)
    out["fwd_bwd_ratio"] = sp / dp.clip(lower=1.0)
    return out


def _fnum(v) -> float:
    try:
        f = float(v)
        return f if f == f else 0.0
    except (TypeError, ValueError):
        return 0.0


def _port(v) -> int:
    return int(_fnum(v))


class Bundle:
    def __init__(self, path: Path):
        self.b = joblib.load(path)
        self.path = path
        self.model = self.b["model"]
        self.features: list[str] = self.b["features"]
        self.theta: float = float(self.b["theta"])
        self.cat_cols: list[str] = self.b["cat_cols"]
        self.cat_keep: dict[str, list[str]] = self.b["cat_keep"]
        self.numeric_cols: list[str] = self.b["numeric_cols"]
        self.cti_features: list[str] = self.b["cti_features"]
        self.profile: str = self.b["profile"]
        self.meta: dict = self.b.get("meta", {})
        self.explainer = make_explainer(self.model)

    def design(self, frame: pd.DataFrame) -> pd.DataFrame:
        parts: list[pd.DataFrame] = []
        nums = {c: pd.to_numeric(frame[c], errors="coerce") if c in frame.columns
                else np.nan for c in self.numeric_cols}
        parts.append(pd.DataFrame(nums, index=frame.index).astype("float64"))
        cti = {c: pd.to_numeric(frame[c], errors="coerce") if c in frame.columns
               else 0.0 for c in self.cti_features}
        parts.append(pd.DataFrame(cti, index=frame.index).astype("float64"))
        for col in self.cat_cols:
            if col in frame.columns:
                s = frame[col].astype("string")
            else:
                s = pd.Series("UNK", index=frame.index, dtype="string")
            pooled = s.where(s.isin(self.cat_keep.get(col, [])), "OTHER").fillna("UNK")
            parts.append(pd.get_dummies(pooled, prefix=col, dtype=np.float32))
        X = pd.concat(parts, axis=1).replace([np.inf, -np.inf], np.nan).fillna(0.0)
        return X.reindex(columns=self.features, fill_value=0.0)


class FileTailer:
    def __init__(self, path: Path, fmt: str, start_at_end: bool):
        self.path, self.fmt = path, fmt
        self.pos = 0
        self.zeek_fields = ""
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(65536)
            if fmt == "zeek":
                for line in head.splitlines():
                    if line.startswith("#fields"):
                        self.zeek_fields = line
            if fmt == "csv":
                self.csv_header = head.splitlines()[0] if head else ""
            else:
                self.csv_header = ""
            if start_at_end:
                fh.seek(0, 2)
            else:
                fh.seek(0)
            self.pos = fh.tell()

    def read(self) -> list[dict]:
        with self.path.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(self.pos)
            text = fh.read()
            self.pos = fh.tell()
        if not text:
            return []
        if self.fmt == "zeek" and "#fields" not in text:
            text = (self.zeek_fields + "\n" + text) if self.zeek_fields else text
        if self.fmt == "csv" and self.csv_header and "," not in text.split("\n", 1)[0]:
            text = self.csv_header + "\n" + text
        return fa.parse_chunk(text, self.fmt)


class FeedWorker(threading.Thread):
    """Refreshes IoC sightings on a timer; never lets feed failure stop scoring."""

    def __init__(self, cfg: dict):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.stop_evt = threading.Event()
        self.lock = threading.Lock()
        self.sightings: dict = {}
        self.summary: dict = {}
        self.n_records = 0
        self.updated_at = 0.0
        self.last_error = ""
        self.polls = 0
        self.last_polls: list = []          # per-source results of last live poll

    def refresh(self) -> None:
        try:
            if self.cfg["online"]:
                report, records = poll_once(self._cti_cfg(), save_snapshot=False)
                if not records:
                    raise RuntimeError("all live feeds returned no records")
                with self.lock:
                    self.last_polls = report.polls
            else:
                records = load_snapshots(resolve(self.cfg["snapshot_dir"]))
            pair = build_sightings(pd.DataFrame(), records, injection="none")
            with self.lock:
                self.sightings, self.summary = pair[0], pair[1]
                self.n_records = len(records)
                self.updated_at = time.time()
                self.polls += 1
                self.last_error = ""
        except Exception as exc:                              # noqa: BLE001
            with self.lock:
                self.last_error = f"{type(exc).__name__}: {exc}"

    def _cti_cfg(self):
        from cti_pipeline.config import load_config
        cti = load_config().cti
        sources = self.cfg.get("sources") or []
        if sources:
            cti.feeds = list(sources)
        return cti

    def run(self) -> None:
        self.refresh()
        interval = max(30.0, self.cfg["poll_interval_min"] * 60.0)
        while not self.stop_evt.wait(interval):
            self.refresh()

    def current(self) -> tuple[dict, dict]:
        with self.lock:
            return dict(self.sightings), dict(self.summary)


class Service:
    def __init__(self, cfg: dict, args):
        self.cfg = cfg
        self.args = args
        # token: config file, else environment (Docker/systemd friendly)
        if not self.cfg["auth"].get("token"):
            self.cfg["auth"]["token"] = (
                os.environ.get("APT_CTI_TOKEN", "") or "").strip()
        self.bundle = Bundle(resolve(cfg["bundle"]))
        _imp = sorted(
            zip(self.bundle.features, self.bundle.model.feature_importances_),
            key=lambda kv: -kv[1])[:10]
        self.model_card = {
            "profile": self.bundle.profile,
            "theta": round(self.bundle.theta, 4),
            "meta": self.bundle.meta,
            "top_features": [[f, round(float(w), 4)] for f, w in _imp],
        }
        inpath = resolve(args.input or cfg["input"]["path"])
        fmt = fa.detect_format(inpath, args.format or cfg["input"]["format"])
        start_end = cfg["input"]["start_at_end"] and not args.replay
        self.tailer = FileTailer(inpath, fmt, start_end)
        self.feeds = FeedWorker(cfg["feeds"])
        sink_list: list = []
        if cfg["alerts"].get("jsonl"):
            self.jsonl = sk.JsonlSink(
                resolve(cfg["alerts"]["jsonl"]),
                rotate_mb=float(cfg["alerts"].get("rotate_mb", 0) or 0),
                keep_files=int(cfg["alerts"].get("keep_files", 0) or 0))
            sink_list.append(self.jsonl)
        else:
            self.jsonl = None
        if cfg["alerts"].get("webhook_url"):
            sink_list.append(sk.WebhookSink(
                cfg["alerts"]["webhook_url"],
                token=cfg["alerts"].get("webhook_token", "")))
        if cfg["alerts"].get("syslog_host"):
            sink_list.append(sk.SyslogSink(cfg["alerts"]["syslog_host"],
                                           int(cfg["alerts"].get("syslog_port", 514))))
        self.sink = sk.Fanout(sink_list)
        self.buffer: list[dict] = []
        self.stats = {
            "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "flows_scored": 0, "batches": 0, "alerts": 0,
            "parse_errors": 0, "last_batch_at": None,
            "input": str(inpath), "format": fmt,
            "profile": self.bundle.profile, "theta": self.bundle.theta,
            "n_features": len(self.bundle.features),
        }
        self.stats["web"] = (f"http://{self.cfg['health']['host']}:"
                             f"{self.cfg['health']['port']}/")
        self.batch_id = 0
        self.sid = datetime.now(timezone.utc).strftime("%y%m%d-%H%M%S")
        self.xai = xa.NvidiaExplainer(cfg.get("xai"))
        self.stats["xai"] = {"enabled": self.xai.enabled,
                             "model": self.xai.model if self.xai.enabled else None}
        self.attributor = default_engine(ROOT, cfg.get("attribution"))
        self.stats["attribution"] = {
            "enabled": self.attributor is not None,
            "n_actors": self.attributor.meta.get("n_actors", 0)
            if self.attributor else 0,
            "n_features": self.attributor.meta.get("n_features", 0)
            if self.attributor else 0}
        self.stats["apt_notified"] = 0
        self._explain_hits = deque()          # /api/explain rate limiter
        self._rl_lock = threading.Lock()
        self._deny_log: dict = {}             # auth-fail audit throttle
        self._stop = threading.Event()
        self._health = None

    # ------------------------------------------------------------------ audit
    def _audit(self, event: str, **fields) -> None:
        """Append-only audit trail (auth + AI-explain activity), rotated."""
        path_s = self.cfg["alerts"].get("audit_log") or ""
        if not path_s:
            return
        try:
            p = resolve(path_s)
            p.parent.mkdir(parents=True, exist_ok=True)
            rec = {"ts": datetime.now(timezone.utc).isoformat(
                timespec="seconds"), "event": event, **fields}
            with p.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, default=str) + "\n")
            if p.stat().st_size > 10 * 1_048_576:
                stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
                p.rename(p.with_name(f"{p.stem}-{stamp}{p.suffix}"))
                for old in sorted(p.parent.glob(f"{p.stem}-*{p.suffix}"),
                                  key=lambda x: x.name, reverse=True)[5:]:
                    old.unlink(missing_ok=True)
        except Exception:                                   # noqa: BLE001
            pass

    # ------------------------------------------------------------------ scoring
    def score_batch(self, records: list[dict]) -> None:
        if not records:
            return
        t0 = time.perf_counter()
        frame = pd.DataFrame(records)
        for c in fa.NATIVE:
            if c not in frame.columns:
                frame[c] = np.nan
        frame = frame[fa.NATIVE]
        frame["ts"] = pd.to_numeric(frame["ts"], errors="coerce").fillna(time.time())
        frame = frame.dropna(subset=["src_ip", "dst_ip"])
        if frame.empty:
            return
        frame = frame.sort_values("ts", kind="mergesort").reset_index(drop=True)
        frame = add_derived(frame)

        sightings, feed_summary = self.feeds.current()
        settings = ReplaySettings(
            interval_s=float(self.cfg["feeds"]["poll_interval_min"]) * 60.0,
            ttl_s=float(self.cfg["feeds"]["ttl_hours"]) * 3600.0,
            half_life_s=float(self.cfg["feeds"]["half_life_h"]) * 3600.0,
            t0=float(frame["ts"].min()),
        )
        feats = enrich(frame, sightings, settings)
        work = frame.copy()
        for col in CTI_FEATURES:
            work[col] = feats[col].to_numpy()

        X = self.bundle.design(work)
        t1 = time.perf_counter()
        proba = self.bundle.model.predict_proba(X)[:, 1]
        alert_idx = np.flatnonzero(proba >= self.bundle.theta)
        self.stats["flows_scored"] += len(frame)
        self.stats["batches"] += 1
        self.stats["last_batch_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.stats["feed_indicators"] = feed_summary.get("n_indicators", 0)
        t2 = time.perf_counter()
        if alert_idx.size == 0:
            print(f"[service] batch {self.stats['batches']}: {len(frame)} flows, "
                  f"0 alerts | prep {t1 - t0:.2f}s predict {t2 - t1:.2f}s "
                  f"total {t2 - t0:.2f}s", flush=True)
            return

        phi = shap_matrix(self.bundle.explainer, X.iloc[alert_idx])
        t3 = time.perf_counter()
        top_k = int(self.cfg["alerts"].get("top_k_reasons", 3))
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.batch_id += 1
        for pos, i in enumerate(alert_idx):
            row = work.iloc[i]
            codes = reason_codes(X.iloc[i], phi[pos], self.bundle.features, k=top_k)
            alert = {
                "alert_id": f"{self.sid}-b{self.batch_id}-{int(i)}",
                "emitted_at": now,
                "model": {"profile": self.bundle.profile,
                          "theta": round(self.bundle.theta, 4),
                          "trained_at": self.bundle.meta.get("trained_at", "")},
                "flow": {
                    "ts": _fnum(row["ts"]),
                    "src_ip": str(row["src_ip"]), "dst_ip": str(row["dst_ip"]),
                    "src_port": _port(row["src_port"]), "dst_port": _port(row["dst_port"]),
                    "proto": str(row["proto"]), "dur": _fnum(row["dur"]),
                    "sbytes": _fnum(row["sbytes"]), "dbytes": _fnum(row["dbytes"]),
                },
                "score": round(float(proba[i]), 4),
                "cti": {
                    "ioc_src_match": _fnum(row.get("ioc_src_match", 0.0)),
                    "ioc_dst_match": _fnum(row.get("ioc_dst_match", 0.0)),
                    "feed_age_score": round(_fnum(row.get("feed_age_score", 0.0)), 4),
                    "feed_confidence": round(_fnum(row.get("feed_confidence", 0.0)), 4),
                    "source_count": int(_fnum(row.get("source_count", 0))),
                },
                "reasons": codes,
            }
            if self.attributor is not None:
                att = self.attributor.attribute(alert)
                alert["attribution"] = att
                if att.get("notify"):
                    self.stats["apt_notified"] += 1
                    self._audit("apt_notify", alert_id=alert["alert_id"],
                                actor=(att.get("actor") or {}).get("name", ""),
                                mitre_id=(att.get("actor") or {}).get("mitre_id") or "",
                                confidence=att.get("confidence", 0))
            self.sink.emit(alert)
        self.stats["alerts"] += len(alert_idx)
        self.stats["alerts_jsonl"] = self.jsonl.count if self.jsonl else 0
        t4 = time.perf_counter()
        print(f"[service] batch {self.stats['batches']}: {len(frame)} flows, "
              f"{len(alert_idx)} alerts | prep {t1 - t0:.2f}s "
              f"predict {t2 - t1:.2f}s shap {t3 - t2:.2f}s emit {t4 - t3:.2f}s "
              f"total {t4 - t0:.2f}s", flush=True)

    # ------------------------------------------------------------------ runtime
    def start_health(self) -> None:
        svc = self

        class Handler(BaseHTTPRequestHandler):
            def _send(self, code: int, body: bytes | str, ctype: str) -> None:
                if isinstance(body, str):
                    body = body.encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                    "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                    "connect-src 'self'")
                self.end_headers()
                self.wfile.write(body)

            # ---- auth ---------------------------------------------------
            def _authed(self) -> bool:
                token = svc.cfg["auth"]["token"]
                if token:
                    got = ""
                    auth_h = self.headers.get("Authorization", "")
                    if auth_h.startswith("Bearer "):
                        got = auth_h[7:].strip()
                    if not got:
                        got = (self.headers.get("X-Auth-Token") or "").strip()
                    if not got:
                        q = parse_qs(urlparse(self.path).query)
                        got = (q.get("token") or [""])[0]
                    return bool(got) and hmac.compare_digest(got, token)
                # no token configured: loopback clients only (fail closed)
                try:
                    return ipaddress.ip_address(
                        self.client_address[0]).is_loopback
                except ValueError:
                    return False

            def _deny(self) -> None:
                ip = self.client_address[0]
                now = time.monotonic()
                if now - svc._deny_log.get(ip, 0.0) > 30:   # throttle audit
                    svc._deny_log[ip] = now
                    svc._audit("auth_deny", ip=ip, path=urlparse(self.path).path)
                self._send(401, json.dumps({"error": "auth required"}),
                           "application/json")

            def do_GET(self):                                  # noqa: N802
                path = urlparse(self.path).path
                if path in ("/", "/index.html"):
                    # static shell is public; data routes below need auth
                    self._send(200, vw.INDEX_HTML.encode(),
                               "text/html; charset=utf-8")
                    return
                if not self._authed():
                    self._deny()
                    return
                if path == "/__status":
                    self._send(200, json.dumps(svc.status(), default=str).encode(),
                               "application/json")
                elif path == "/api/alerts":
                    q = parse_qs(urlparse(self.path).query)
                    try:
                        limit = max(1, min(1000, int(q.get("limit", ["100"])[0])))
                    except ValueError:
                        limit = 100
                    alerts = vw.tail_alerts(
                        svc.jsonl.path if svc.jsonl else None, limit)
                    self._send(200, json.dumps(alerts, default=str).encode(),
                               "application/json")
                else:
                    self._send(404, b"not found", "text/plain")

            def do_POST(self):                                # noqa: N802
                if urlparse(self.path).path != "/api/explain":
                    self._send(404, b"not found", "text/plain")
                    return
                if not self._authed():
                    self._deny()
                    return
                # rate limit: sliding 60 s window on explain requests
                per_min = int(svc.cfg["auth"].get("explain_per_min", 0) or 0)
                if per_min > 0:
                    now = time.monotonic()
                    with svc._rl_lock:
                        dq = svc._explain_hits
                        while dq and now - dq[0] > 60.0:
                            dq.popleft()
                        if len(dq) >= per_min:
                            limited = True
                        else:
                            dq.append(now)
                            limited = False
                    if limited:
                        svc._audit("explain_rate_limited",
                                   ip=self.client_address[0])
                        self._send(429, json.dumps({
                            "error": f"rate limit: {per_min}/min"}),
                            "application/json")
                        return
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    length = 0
                if length > 4096:
                    self._send(413, b"payload too large", "text/plain")
                    return
                try:
                    body = json.loads(self.rfile.read(length) or b"{}")
                except (json.JSONDecodeError, ValueError):
                    self._send(400, json.dumps({"error": "invalid json"}),
                               "application/json")
                    return
                alert_id = str(body.get("alert_id") or "")
                if not alert_id:
                    self._send(400, json.dumps({"error": "alert_id required"}),
                               "application/json")
                    return
                if not svc.xai.enabled:
                    self._send(400, json.dumps({
                        "error": "XAI disabled — set xai.api_key in "
                                 "deploy/config.yaml (see deploy/README.md "
                                 "for the API-key environment variable)"}),
                        "application/json")
                    return
                alert = next((a for a in vw.tail_alerts(
                    svc.jsonl.path if svc.jsonl else None, 1000)
                    if a.get("alert_id") == alert_id), None)
                if alert is None:
                    self._send(404, json.dumps({"error": "alert not found"}),
                               "application/json")
                    return
                try:
                    text = svc.xai.explain(alert_id, alert)
                    svc._audit("explain_ok", alert_id=alert_id,
                               ip=self.client_address[0],
                               model=svc.xai.model)
                    self._send(200, json.dumps({
                        "alert_id": alert_id, "explanation": text,
                        "model": svc.xai.model}).encode(), "application/json")
                except Exception as exc:                      # noqa: BLE001
                    svc._audit("explain_error", alert_id=alert_id,
                               ip=self.client_address[0], error=str(exc)[:200])
                    self._send(502, json.dumps({"error": str(exc)}),
                               "application/json")

            def log_message(self, *args):                      # silence access log
                pass

        host = self.args.health_host or self.cfg["health"]["host"]
        port = int(self.args.health_port or self.cfg["health"]["port"])
        token = self.cfg["auth"]["token"]
        try:
            exposed = not ipaddress.ip_address(host).is_loopback
        except ValueError:
            exposed = host not in ("localhost", "127.0.0.1", "::1")
        if exposed and not token:
            raise RuntimeError(
                f"refusing to bind non-loopback address {host!r} without "
                "auth.token - set auth.token in the config (or keep "
                "health.host 127.0.0.1) so remote access requires a token")
        self._health = ThreadingHTTPServer((host, port), Handler)
        threading.Thread(target=self._health.serve_forever, daemon=True).start()
        self.stats["health_url"] = f"http://{host}:{port}/__status"
        self.stats["web"] = f"http://{host}:{port}/"
        self.stats["auth_required"] = bool(token)

    def status(self) -> dict:
        return {
            **self.stats,
            "model": self.model_card,
            "feed_records": self.feeds.n_records,
            "feed_mode": "online" if self.cfg["feeds"]["online"] else "offline",
            "feed_sources": list(self.feeds.last_polls),
            "poll_interval_min": self.cfg["feeds"]["poll_interval_min"],
            "ttl_hours": self.cfg["feeds"]["ttl_hours"],
            "half_life_h": self.cfg["feeds"]["half_life_h"],
            "feed_updated_at": datetime.fromtimestamp(
                self.feeds.updated_at, timezone.utc).isoformat(timespec="seconds")
            if self.feeds.updated_at else None,
            "feed_error": self.feeds.last_error,
            "buffered": len(self.buffer),
            "build": getattr(vw, "BUILD", ""),
            "alive": True,
        }

    def run(self) -> None:
        ensure_doh()
        self.feeds.start()
        self.start_health()             # serve immediately; feed fills in async
        self._audit("service_start", web=self.stats["web"],
                    auth_required=bool(self.cfg["auth"]["token"]),
                    feeds="online" if self.cfg["feeds"]["online"] else "offline")
        deadline = time.time() + 30.0
        while self.feeds.updated_at == 0.0 and time.time() < deadline:
            time.sleep(0.1)
        flush_s = float(self.cfg["batch"]["flush_s"])
        max_flows = int(self.cfg["batch"]["max_flows"])
        last_flush = time.time()
        print(f"[service] profile={self.bundle.profile} theta={self.bundle.theta:.4f} "
              f"features={len(self.bundle.features)}", flush=True)
        print(f"[service] input={self.stats['input']} ({self.stats['format']}) "
              f"web={self.stats['web']} status={self.stats['health_url']}", flush=True)

        if self.args.replay:
            while True:
                recs = self.tailer.read()
                if not recs:
                    break
                for i in range(0, len(recs), max_flows):
                    self.score_batch(recs[i:i + max_flows])
            print(f"[service] replay done: {self.stats['flows_scored']} flows, "
                  f"{self.stats['alerts']} alerts", flush=True)
            return

        while not self._stop.is_set():
            self.buffer.extend(self.tailer.read())
            now = time.time()
            if len(self.buffer) >= max_flows or (
                    self.buffer and now - last_flush >= flush_s):
                n = (len(self.buffer) // max_flows) * max_flows or len(self.buffer)
                chunk, self.buffer = self.buffer[:n], self.buffer[n:]
                self.score_batch(chunk)
                last_flush = now
            time.sleep(0.25)

    def stop(self) -> None:
        self._stop.set()
        self.feeds.stop_evt.set()
        if self._health:
            self._health.shutdown()


def main() -> None:
    ap = argparse.ArgumentParser(description="APT-CTI real-time scoring service")
    ap.add_argument("--config", default=str(ROOT / "deploy" / "config.yaml"))
    ap.add_argument("--input", default=None, help="flow file to tail")
    ap.add_argument("--format", default=None, choices=["auto", "jsonl", "csv", "zeek", "eve"])
    ap.add_argument("--replay", action="store_true", help="score whole file, then exit")
    ap.add_argument("--online-feeds", action="store_true", help="poll live feeds")
    ap.add_argument("--health-port", type=int, default=None)
    ap.add_argument("--health-host", default=None,
                    help="bind address for /__status (use 0.0.0.0 in containers)")
    args = ap.parse_args()

    cfg = load_deploy_config(Path(args.config))
    if args.online_feeds:
        cfg["feeds"]["online"] = True
    svc = Service(cfg, args)
    try:
        svc.run()
    except KeyboardInterrupt:
        svc.stop()
        print(f"\n[service] stopped: {svc.status()}", flush=True)


if __name__ == "__main__":
    main()
