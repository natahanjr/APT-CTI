"""WAL-mode SQLite IoC store: dedup, first/last-seen tracking, TTL expiry."""

from __future__ import annotations

import re
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS iocs (
    value       TEXT NOT NULL,
    ioc_type    TEXT NOT NULL,
    source      TEXT NOT NULL,
    provenance  TEXT NOT NULL DEFAULT 'live',
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    confidence  REAL NOT NULL DEFAULT 0.5,
    tags        TEXT NOT NULL DEFAULT '',
    sightings   INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (value, ioc_type, source)
);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
"""

_IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def classify(value: str) -> str | None:
    """Best-effort IoC type classification."""
    v = value.strip().lower()
    if not v or len(v) > 256:
        return None
    if _IPV4.match(v):
        return "ipv4"
    if "://" in v:
        if re.match(r"^[0-9a-f]{32,64}$", v.split("/")[-1]):
            return "hash"
        return "url"
    if re.match(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$", v):
        return "hash"
    if re.match(r"^([a-z0-9-]+\.)+[a-z]{2,}$", v):
        return "domain"
    return None


@dataclass
class IocRecord:
    value: str
    ioc_type: str
    source: str
    first_seen: float
    last_seen: float
    confidence: float = 0.5
    tags: str = ""
    provenance: str = "live"
    sightings: int = 1


class IocStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # -- writes ------------------------------------------------------------
    def upsert(self, records: list[IocRecord]) -> int:
        if not records:
            return 0
        rows = [
            (r.value, r.ioc_type, r.source, r.provenance, r.first_seen, r.last_seen,
             float(r.confidence), r.tags, int(r.sightings))
            for r in records
            if classify(r.value) or r.ioc_type
        ]
        self.conn.executemany(
            """
            INSERT INTO iocs (value, ioc_type, source, provenance, first_seen, last_seen,
                              confidence, tags, sightings)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(value, ioc_type, source) DO UPDATE SET
                last_seen  = MAX(last_seen, excluded.last_seen),
                first_seen = MIN(first_seen, excluded.first_seen),
                confidence = MAX(confidence, excluded.confidence),
                tags       = CASE WHEN excluded.tags = '' THEN tags ELSE excluded.tags END,
                sightings  = sightings + 1
            """,
            rows,
        )
        self.conn.commit()
        return len(rows)

    def expire(self, ttl_hours: float, now: float | None = None) -> int:
        now = time.time() if now is None else now
        cutoff = now - ttl_hours * 3600.0
        cur = self.conn.execute("DELETE FROM iocs WHERE last_seen < ?", (cutoff,))
        self.conn.commit()
        return cur.rowcount

    # -- reads -------------------------------------------------------------
    def lookup(self, values: list[str]) -> dict[str, list[sqlite3.Row]]:
        if not values:
            return {}
        self.conn.row_factory = sqlite3.Row
        out: dict[str, list[sqlite3.Row]] = {}
        unique = list(dict.fromkeys(values))
        for start in range(0, len(unique), 500):
            chunk = unique[start:start + 500]
            marks = ",".join("?" * len(chunk))
            for row in self.conn.execute(f"SELECT * FROM iocs WHERE value IN ({marks})", chunk):
                out.setdefault(row["value"], []).append(row)
        return out

    def all_rows(self) -> list[sqlite3.Row]:
        self.conn.row_factory = sqlite3.Row
        return list(self.conn.execute("SELECT * FROM iocs"))

    def stats(self) -> dict[str, int]:
        self.conn.row_factory = sqlite3.Row
        total = self.conn.execute("SELECT COUNT(*) c FROM iocs").fetchone()["c"]
        by_type = {r["t"]: r["n"] for r in self.conn.execute(
            "SELECT ioc_type t, COUNT(*) n FROM iocs GROUP BY ioc_type")}
        by_source = {r["s"]: r["n"] for r in self.conn.execute(
            "SELECT source s, COUNT(*) n FROM iocs GROUP BY source")}
        return {"total": total, **{f"type:{k}": v for k, v in by_type.items()},
                **{f"source:{k}": v for k, v in by_source.items()}}

    def close(self) -> None:
        self.conn.close()
