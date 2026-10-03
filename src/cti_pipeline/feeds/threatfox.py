"""abuse.ch ThreatFox recent-IOC poller (IP:port, domains, hashes)."""

from __future__ import annotations

from ..net import epoch, http_get
from ..store import IocRecord
from .base import PollReport, _read_csv_lines, make_record

URL = "https://threatfox.abuse.ch/export/csv/recent/"
_CONFIDENCE = {"low": 0.3, "medium": 0.6, "high": 0.9}


def poll(timeout: int = 60) -> PollReport:
    report = PollReport(source="threatfox", ok=False, url=URL)
    try:
        payload = http_get(URL, timeout=timeout)
        rows = _read_csv_lines(payload)
        # first_seen,last_seen,ioc,value,malware,agent,tags,id,urlhaus_link,confidence_level
        for row in rows:
            if len(row) < 10:
                continue
            first_s, last_s, ioc, _value, malware, _agent, tags, *_rest, conf = row[:10]
            ioc = ioc.strip()
            if ":" in ioc and ioc.count(":") == 1 and not ioc.startswith("["):  # ip:port
                ioc = ioc.split(":")[0]
            first = epoch(first_s) or 0.0
            last = epoch(last_s) or first
            conf_v = _CONFIDENCE.get(conf.strip().lower(), 0.5)
            tag_str = ",".join(x for x in (malware.strip(), tags.strip()) if x)
            rec = make_record(ioc, "threatfox", first, last, conf_v, tag_str)
            if rec:
                report.records.append(rec)
        report.ok = True
    except Exception as exc:  # noqa: BLE001
        report.error = f"{type(exc).__name__}: {exc}"
    return report
