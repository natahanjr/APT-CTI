"""Feed collector: poll every configured source, persist to the IoC store,
and keep a raw snapshot per source so experiments can run in replay mode."""

from __future__ import annotations

import csv
import time
from dataclasses import dataclass, field
from pathlib import Path

from .config import CtiConfig
from .feeds import POLLERS
from .feeds.base import PollReport
from .net import ensure_doh
from .store import IocRecord, IocStore


@dataclass
class CollectorReport:
    started_at: float
    finished_at: float = 0.0
    polls: list[dict] = field(default_factory=list)
    store_stats: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_s": round(self.finished_at - self.started_at, 2),
            "polls": self.polls,
            "store_stats": self.store_stats,
        }


def poll_once(cfg: CtiConfig, store: IocStore | None = None,
              save_snapshot: bool = True) -> tuple[CollectorReport, list[IocRecord]]:
    """One full poll cycle across every configured feed."""
    ensure_doh()
    report = CollectorReport(started_at=time.time())
    store = store or IocStore(cfg.db_path)
    snapshot_dir = Path(cfg.snapshot_dir)
    if save_snapshot:
        snapshot_dir.mkdir(parents=True, exist_ok=True)

    all_records: list[IocRecord] = []
    for name in cfg.feeds:
        factory = POLLERS.get(name)
        if factory is None:
            report.polls.append({"source": name, "ok": False, "n_records": 0,
                                 "error": "unknown feed", "url": ""})
            continue
        started = time.time()
        result: PollReport = factory(cfg)
        result.records = [r for r in result.records if r.value]
        all_records.extend(result.records)
        store.upsert(result.records)
        entry = result.summary()
        entry["duration_s"] = round(time.time() - started, 2)
        report.polls.append(entry)
        if save_snapshot and result.records:
            _write_snapshot(snapshot_dir, name, result.records)

    report.finished_at = time.time()
    report.store_stats = store.stats()
    return report, all_records


def _write_snapshot(directory: Path, source: str, records: list[IocRecord]) -> Path:
    path = directory / f"{source}_{int(time.time())}.csv"
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["value", "ioc_type", "first_seen", "last_seen",
                         "confidence", "tags", "provenance", "sightings"])
        for r in records:
            writer.writerow([r.value, r.ioc_type, r.first_seen, r.last_seen,
                             r.confidence, r.tags, r.provenance, r.sightings])
    return path


def load_snapshots(directory: str | Path) -> list[IocRecord]:
    """Read back every saved snapshot (offline / replay mode)."""
    directory = Path(directory)
    records: list[IocRecord] = []
    for path in sorted(directory.glob("*.csv")):
        with open(path, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                try:
                    records.append(IocRecord(
                        value=row["value"], ioc_type=row["ioc_type"],
                        source=path.stem.rsplit("_", 1)[0],
                        first_seen=float(row["first_seen"]),
                        last_seen=float(row["last_seen"]),
                        confidence=float(row["confidence"]),
                        tags=row.get("tags", ""),
                        provenance=row.get("provenance", "live"),
                        sightings=int(row.get("sightings", 1) or 1),
                    ))
                except (KeyError, ValueError):
                    continue
    return records
