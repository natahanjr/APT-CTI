"""Contribution 1 - poll every configured CTI feed into the SQLite IoC store.

    python scripts/run_collect_feeds.py            # live poll
    python scripts/run_collect_feeds.py --offline  # reload saved snapshots
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import ROOT, TABLES, base_parser, get_config, get_live_records, write_json  # noqa: E402


def main() -> None:
    parser = base_parser("Poll public CTI feeds into the IoC store")
    parser.add_argument("--offline", action="store_true", help="reuse saved snapshots")
    args = parser.parse_args()
    cfg = get_config(args)

    records = get_live_records(cfg, poll=not args.offline)
    if args.offline:
        from cti_pipeline.store import IocStore

        store = IocStore(cfg.cti.db_path)
        store.upsert(records)
        stats = store.stats()
    else:
        stats = json.loads((Path(cfg.cti.snapshot_dir) / "last_poll.json")
                           .read_text(encoding="utf-8"))["store_stats"]

    payload = {"n_records": len(records), "store_stats": stats,
               "provenance": "live", "polled_at": __import__("time").time()}
    write_json(TABLES / "feed_poll.json", payload)
    print("[store]", json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
