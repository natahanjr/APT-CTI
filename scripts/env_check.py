"""Environment self-check used by start.ps1. Prints one JSON object.

    python scripts/env_check.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from _common import FIGURES, ROOT, TABLES, dataset_dir  # noqa: E402
from cti_pipeline.config import load_config  # noqa: E402


def main() -> None:
    cfg = load_config()

    datasets: dict[str, bool] = {}
    paths: dict[str, str] = {}
    for name in ("unsw_nb15", "cicids2017"):
        d = dataset_dir(cfg, name)
        paths[name] = str(d)
        if name == "unsw_nb15":
            ok = d.exists() and bool(sorted(d.glob("UNSW-NB15_[1-4].csv")))
        else:
            ok = d.exists() and any(d.glob("*.csv"))
        datasets[name] = bool(ok)

    dash = ROOT / "dashboard" / "index.html"
    tables = len(list(TABLES.glob("*.json")))
    figures = len(list(FIGURES.glob("*.png")))

    def has_results(ds: str) -> bool:
        return all(
            (TABLES / f"{prefix}_{ds}.json").exists()
            for prefix in ("e1_baseline", "e2_ablation", "e3_freshness", "e4_explain")
        )

    results = {name: has_results(name) for name in datasets}

    store: dict = {"exists": Path(cfg.cti.db_path).exists(), "stats": None}
    if store["exists"]:
        try:
            from cti_pipeline.store import IocStore

            store["stats"] = IocStore(cfg.cti.db_path).stats()
        except Exception as exc:  # noqa: BLE001
            store["error"] = str(exc)

    payload = {
        "python": "%d.%d.%d" % sys.version_info[:3],
        "root": str(ROOT),
        "datasets": datasets,
        "dataset_paths": paths,
        "tables": tables,
        "figures": figures,
        "results": results,
        "dashboard": {
            "exists": dash.exists(),
            "kb": round(dash.stat().st_size / 1024) if dash.exists() else 0,
        },
        "ioc_store": store,
        "ready": dash.exists() and tables > 0,
    }
    print(json.dumps(payload))


if __name__ == "__main__":
    main()
