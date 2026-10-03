"""abuse.ch URLhaus recent-entries poller (malicious URLs / hostnames)."""

from __future__ import annotations

from ..net import epoch, http_get
from ..store import IocRecord
from .base import PollReport, _read_csv_lines, make_record

URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"


def poll(timeout: int = 60) -> PollReport:
    report = PollReport(source="urlhaus", ok=False, url=URL)
    try:
        payload = http_get(URL, timeout=timeout)
        rows = _read_csv_lines(payload)
        # id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, host
        for row in rows:
            if len(row) < 9:
                continue
            _, dateadded, url, status, last_online, threat, tags, _, host = row[:9]
            first = epoch(dateadded) or 0.0
            last = epoch(last_online) or first
            confidence = 0.75 if status.lower() == "online" else 0.5
            tag_str = ",".join(x for x in (threat.strip(), tags.strip()) if x)
            for value, kind in ((host, None), (url, "url")):
                rec = make_record(value, "urlhaus", first, last, confidence, tag_str, ioc_type=kind)
                if rec:
                    report.records.append(rec)
        report.ok = True
    except Exception as exc:  # noqa: BLE001 - pollers must never crash the collector
        report.error = f"{type(exc).__name__}: {exc}"
    return report
