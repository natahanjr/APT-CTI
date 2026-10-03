"""Feed poller base: every poller returns a list of IocRecord and never raises."""

from __future__ import annotations

import io
import logging
import zipfile
from dataclasses import dataclass, field

from ..net import http_get
from ..store import IocRecord, classify

log = logging.getLogger("cti.feeds")


@dataclass
class PollReport:
    source: str
    ok: bool
    records: list[IocRecord] = field(default_factory=list)
    error: str = ""
    url: str = ""

    def summary(self) -> dict:
        return {
            "source": self.source,
            "ok": self.ok,
            "n_records": len(self.records),
            "error": self.error,
            "url": self.url,
        }


def _read_csv_lines(payload: bytes, delim: str = ",") -> list[list[str]]:
    """Parse a CSV payload, tolerating '#' comment lines and zip containers."""
    if payload[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(payload)) as zf:
            payload = zf.read(zf.namelist()[0])
    text = payload.decode("utf-8", errors="replace")
    import csv

    rows = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        rows.append(next(csv.reader(io.StringIO(line), delimiter=delim)))
    return rows


def make_record(value: str, source: str, first_seen: float, last_seen: float,
                confidence: float = 0.5, tags: str = "", ioc_type: str | None = None,
                sightings: int = 1) -> IocRecord | None:
    value = (value or "").strip()
    kind = ioc_type or classify(value)
    if not kind:
        return None
    if first_seen <= 0:
        first_seen = last_seen
    if last_seen <= 0:
        last_seen = first_seen
    return IocRecord(
        value=value, ioc_type=kind, source=source,
        first_seen=float(first_seen), last_seen=float(last_seen),
        confidence=max(0.0, min(1.0, float(confidence))),
        tags=tags[:500], provenance="live", sightings=sightings,
    )
