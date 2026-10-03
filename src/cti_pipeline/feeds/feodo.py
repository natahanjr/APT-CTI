"""abuse.ch Feodo Tracker poller (C2 IPs + DGA domains)."""

from __future__ import annotations

import re
import time

from ..net import http_get
from ..store import IocRecord
from .base import PollReport, make_record

URLS = [
    ("https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "feodo-ip"),
    ("https://feodotracker.abuse.ch/downloads/dga_domain_blocklist.txt", "feodo-dga"),
]
_LINE = re.compile(r"^\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9a-f:.]+/[0-9]+|([a-z0-9-]+\.)+[a-z]{2,})\s*(?:#\s*(.*))?$",
                   re.IGNORECASE)


def poll(timeout: int = 30) -> PollReport:
    report = PollReport(source="feodo", ok=False, url=" | ".join(u for u, _ in URLS))
    now = time.time()
    for url, tag in URLS:
        try:
            text = http_get(url, timeout=timeout).decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            report.error = f"{report.error} {tag}: {type(exc).__name__}: {exc};"
            continue
        for line in text.splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            m = _LINE.match(line)
            if not m:
                continue
            value = m.group(1)
            if "/" in value:  # CIDR is not matched against single flows
                continue
            note = (m.group(3) or "").strip()
            rec = make_record(value, "feodo", now, now, 0.8, note or tag)
            if rec:
                report.records.append(rec)
        report.ok = True
    report.error = report.error.strip()
    return report
