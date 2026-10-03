"""Build the single-file thesis dashboard.

    python scripts/build_dashboard.py
    -> dashboard/index.html   (double-click, no server needed)

Reads the experiment tables + a sample of the alert stream and injects them
into scripts/dashboard_template.html.
"""

from __future__ import annotations

import base64
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cti_pipeline.attack_map import map_feature  # noqa: E402
from cti_pipeline.config import load_config  # noqa: E402

TABLES = ROOT / "results" / "tables"
ALERTS = ROOT / "results" / "alerts"
OUT = ROOT / "dashboard" / "index.html"
TEMPLATE = Path(__file__).with_name("dashboard_template.html")

DATASETS = {"unsw_nb15": "UNSW-NB15", "cicids2017": "CICIDS2017"}
ALERT_SAMPLE = 80


def read_json(path: Path):
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def read_alerts(name: str, limit: int) -> tuple[list[dict], int]:
    path = ALERTS / f"alerts_{name}.jsonl"
    if not path.exists():
        return [], 0
    rows, total = [], 0
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            total += 1
            if len(rows) < limit:
                rows.append(json.loads(line))
    return rows, total


def tactic_index(features: list[str]) -> dict[str, str]:
    out = {}
    for f in features:
        try:
            out[f] = map_feature(f).tactic
        except Exception:
            out[f] = "Uncategorised"
    return out


def main() -> None:
    cfg = load_config()
    payload: dict = {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "config": {
            "note": (f"seed {cfg.model.seed} · {cfg.model.n_estimators} trees · "
                     f"min_samples_leaf {cfg.model.min_samples_leaf} · "
                     f"max_rows {cfg.data.max_rows:,} · θ at {cfg.model.target_recall:.0%} recall"),
            "seed": cfg.model.seed,
            "n_estimators": cfg.model.n_estimators,
            "min_samples_leaf": cfg.model.min_samples_leaf,
            "max_rows": cfg.data.max_rows,
            "target_recall": cfg.model.target_recall,
        },
        "feeds": read_json(TABLES / "feed_poll.json") or {},
        "datasets": {},
    }

    missing = []
    for name, label in DATASETS.items():
        e1 = read_json(TABLES / f"e1_baseline_{name}.json")
        e2 = read_json(TABLES / f"e2_ablation_{name}.json")
        e3 = read_json(TABLES / f"e3_freshness_{name}.json")
        e4 = read_json(TABLES / f"e4_explain_{name}.json")
        e5 = read_json(TABLES / f"e5_latency_{name}.json")
        if not all((e1, e2, e3, e4)):
            missing.append(name)
            continue
        alerts, total = read_alerts(name, ALERT_SAMPLE)
        e4["tactic_of_feature"] = tactic_index(list(e4.get("top10_features", [])))
        payload["datasets"][name] = {
            "label": label,
            "e1": e1, "e2": e2, "e3": e3, "e4": e4, "e5": e5,
            "alerts": alerts,
            "alert_total": total,
        }

    payload["e6"] = read_json(TABLES / "e6_crossdataset.json")

    if missing:
        print(f"[warn] incomplete results for: {', '.join(missing)} "
              f"(run scripts/run_e1..e4 first)", file=sys.stderr)
    if not payload["e6"]:
        print("[warn] e6_crossdataset.json missing (run scripts/run_e6_crossdataset.py)",
              file=sys.stderr)

    figure_data = {
        p.name: "data:image/png;base64," + base64.b64encode(p.read_bytes()).decode("ascii")
        for p in sorted((ROOT / "results" / "figures").glob("*.png"))
    }
    payload["figures"] = sorted(figure_data)
    payload["figure_data"] = figure_data

    html = TEMPLATE.read_text(encoding="utf-8")
    blob = json.dumps(payload, separators=(",", ":"), default=float)
    blob = blob.replace("</", "<\\/")          # keep </script> inert
    marker = "/*__DATA__*/{}"
    if marker not in html:
        raise SystemExit("template marker /*__DATA__*/{} not found")
    html = html.replace(marker, blob)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(html, encoding="utf-8")
    size = OUT.stat().st_size / 1024
    print(f"[write] {OUT}  ({size:.0f} KB, datasets: {', '.join(payload['datasets']) or 'none'})")
    print(f"[info] figures embedded: {len(figure_data)} · alerts embedded: "
          f"{', '.join(f'{k}={v['alert_total']}' for k, v in payload['datasets'].items()) or 'none'}")


if __name__ == "__main__":
    main()
