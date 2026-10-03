"""Alert sinks: JSONL file, webhook POST, syslog UDP."""
from __future__ import annotations

import json
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path


class JsonlSink:
    """Append-only JSONL with optional size-based rotation + retention.

    Rotation renames the file to ``<stem>-YYYYMMDD-HHMMSS.jsonl`` and starts
    fresh; the newest ``keep_files`` archives are retained, older ones are
    deleted (retention policy for regulated environments).
    """

    def __init__(self, path: str | Path, rotate_mb: float = 0.0,
                 keep_files: int = 0):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.rotate_bytes = int(float(rotate_mb) * 1_048_576) if rotate_mb else 0
        self.keep_files = max(0, int(keep_files))
        self._lock = threading.Lock()
        self.count = 0
        self.rotations = 0

    def emit(self, alert: dict) -> None:
        line = json.dumps(alert, default=float, ensure_ascii=False)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            self.count += 1
            if (self.rotate_bytes and self.path.exists()
                    and self.path.stat().st_size >= self.rotate_bytes):
                self._rotate_locked()

    def _rotate_locked(self) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        archive = self.path.with_name(
            f"{self.path.stem}-{ts}{self.path.suffix}")
        n = 1
        while archive.exists():                       # same-second collisions
            archive = self.path.with_name(
                f"{self.path.stem}-{ts}-{n}{self.path.suffix}")
            n += 1
        self.path.rename(archive)
        self.rotations += 1
        if self.keep_files:
            archives = sorted(
                self.path.parent.glob(f"{self.path.stem}-*{self.path.suffix}"),
                key=lambda p: p.name, reverse=True)
            for old in archives[self.keep_files:]:
                old.unlink(missing_ok=True)


class WebhookSink:
    """POST each alert to a SIEM/automation endpoint (best effort + one retry).

    Works with https:// URLs (requests verifies certificates); set
    ``token`` to send it as an ``Authorization: Bearer`` header.
    """

    def __init__(self, url: str, timeout_s: float = 5.0, token: str = ""):
        self.url = url
        self.timeout_s = timeout_s
        self.headers = {"Authorization": f"Bearer {token}"} if token else {}
        self.count = 0
        self.errors = 0

    def emit(self, alert: dict) -> None:
        try:
            import requests
            r = requests.post(self.url, json=alert, headers=self.headers,
                              timeout=self.timeout_s)
            if r.status_code >= 500:
                requests.post(self.url, json=alert, headers=self.headers,
                              timeout=self.timeout_s)
            self.count += 1
        except Exception:                                   # noqa: BLE001
            self.errors += 1


class SyslogSink:
    """RFC3164-ish UDP syslog (works with rsyslog/syslog-ng collectors)."""

    PRI = 134  # daemon.notice

    def __init__(self, host: str, port: int = 514):
        self.addr = (host, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.count = 0
        self.errors = 0

    def emit(self, alert: dict) -> None:
        try:
            ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
            body = json.dumps(alert, default=float, ensure_ascii=False)
            msg = f"<{self.PRI}>{ts} apt-cti-score: {body[:8000]}"
            self.sock.sendto(msg.encode("utf-8", errors="replace"), self.addr)
            self.count += 1
        except OSError:
            self.errors += 1


class Fanout:
    """Emit to every configured sink; failures never break scoring."""

    def __init__(self, sinks: list):
        self.sinks = sinks
        self.count = 0

    def emit(self, alert: dict) -> None:
        self.count += 1
        for s in self.sinks:
            try:
                s.emit(alert)
            except Exception:                               # noqa: BLE001
                pass
