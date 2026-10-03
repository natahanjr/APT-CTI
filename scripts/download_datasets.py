"""Download thesis datasets (CIC-IDS2017 and/or UNSW-NB15).

Large raw datasets are intentionally NOT stored in git. This script fetches
them on demand into ``data/`` (see ``.gitignore``).

Usage
-----
    python scripts/download_datasets.py                  # both datasets
    python scripts/download_datasets.py --dataset cicids2017
    python scripts/download_datasets.py --dataset unsw_nb15
    python scripts/download_datasets.py --list           # show known sources

Outputs (relative to repo root)
-------------------------------
    data/cicids2017/raw/*.csv          CIC-IDS2017 GeneratedLabelledFlows
    data/cicids2017/*.zip              cached archive (resumable)
    data/unsw_nb15/*.csv               UNSW-NB15 training/testing sets
    data/unsw_nb15/*.zip               cached archives when applicable
"""

from __future__ import annotations

import argparse
import sys
import time
import zipfile
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import doh_patch  # noqa: F401  # DNS-over-HTTPS fallback on flaky resolvers

import requests

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"

# Minimum size sanity checks (bytes) — reject truncated/corrupt downloads.
CIC_ZIP_MIN = 250_000_000
UNSW_CSV_MIN = 5_000_000

CICIDS2017_SOURCES = [
    {
        "name": "huggingface-bencorn",
        "url": (
            "https://huggingface.co/datasets/bencorn/CICIDS2017/"
            "resolve/main/csvs/GeneratedLabelledFlows.zip"
        ),
        "zip": DATA / "cicids2017" / "GeneratedLabelledFlows.zip",
        "min_size": CIC_ZIP_MIN,
        "kind": "zip_csv_flat",
        "dest": DATA / "cicids2017" / "raw",
    },
]

# UNSW-NB15: official part files are often mirrored. Try several sources.
UNSW_NB15_SOURCES = [
    {
        "name": "unsw-training-set",
        "url": (
            "https://raw.githubusercontent.com/InitRoot/UNSW-NB15-ML-IDS/"
            "master/CSV%20Dataset/UNSW_NB15_training-set.csv"
        ),
        "dest": DATA / "unsw_nb15" / "UNSW_NB15_training-set.csv",
        "min_size": UNSW_CSV_MIN,
        "kind": "csv",
    },
    {
        "name": "unsw-testing-set",
        "url": (
            "https://raw.githubusercontent.com/InitRoot/UNSW-NB15-ML-IDS/"
            "master/CSV%20Dataset/UNSW_NB15_testing-set.csv"
        ),
        "dest": DATA / "unsw_nb15" / "UNSW_NB15_testing-set.csv",
        "min_size": UNSW_CSV_MIN,
        "kind": "csv",
    },
    # Full archive fallback (if CSV mirrors fail)
    {
        "name": "unsw-full-zip",
        "url": (
            "https://cloudstor.aarnet.edu.au/plus/s/"
            "7Jr7vRNmBp60v6q/download"
        ),
        "zip": DATA / "unsw_nb15" / "UNSW-NB15.zip",
        "min_size": 150_000_000,
        "kind": "zip_csv_any",
        "dest": DATA / "unsw_nb15",
    },
]


def _human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} GB"


def download_file(url: str, dest: Path, *, min_size: int = 0, retries: int = 8) -> Path:
    """Resumable download to ``dest``. Returns the path on success."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size >= min_size:
        print(f"  already present ({_human(dest.stat().st_size)}): {dest.name}")
        return dest

    headers: dict[str, str] = {}
    mode = "wb"
    done = 0
    if dest.exists() and dest.stat().st_size > 0:
        done = dest.stat().st_size
        headers["Range"] = f"bytes={done}-"
        mode = "ab"

    print(f"  downloading {url}")
    print(f"    -> {dest}  (resume from {_human(done)})")

    for attempt in range(1, retries + 1):
        try:
            with requests.get(url, stream=True, timeout=90, headers=headers) as resp:
                # 416: range not satisfiable — file may already be complete
                if resp.status_code == 416:
                    if dest.exists() and dest.stat().st_size >= min_size:
                        print("  server says range complete")
                        return dest
                    dest.unlink(missing_ok=True)
                    headers, mode, done = {}, "wb", 0
                    continue
                resp.raise_for_status()
                remaining = int(resp.headers.get("content-length") or 0)
                expected_total = (done + remaining) if remaining else 0
                last = time.time()
                with open(dest, mode) as fh:
                    for chunk in resp.iter_content(chunk_size=1 << 20):
                        if not chunk:
                            continue
                        fh.write(chunk)
                        done += len(chunk)
                        if time.time() - last >= 10:
                            if expected_total:
                                pct = 100.0 * done / expected_total
                                print(
                                    f"    {_human(done)} / {_human(expected_total)}  ({pct:5.1f}%)",
                                    flush=True,
                                )
                            else:
                                print(f"    {_human(done)}", flush=True)
                            last = time.time()
            size = dest.stat().st_size if dest.exists() else 0
            if min_size and size < min_size:
                raise RuntimeError(
                    f"downloaded size {_human(size)} < expected minimum {_human(min_size)}"
                )
            print(f"  ok: {dest.name} ({_human(size)})")
            return dest
        except Exception as exc:  # noqa: BLE001
            print(f"  attempt {attempt}/{retries} failed: {exc}", flush=True)
            time.sleep(min(30, 3 * attempt))
            if dest.exists():
                done = dest.stat().st_size
                headers = {"Range": f"bytes={done}-"}
                mode = "ab"
            else:
                headers, mode, done = {}, "wb", 0
    raise RuntimeError(f"failed to download {url}")


def extract_zip_csv_flat(zip_path: Path, dest_dir: Path, *, min_csv: int = 1000) -> list[Path]:
    """Extract every ``*.csv`` from a zip into ``dest_dir`` (basename only)."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            name = Path(info.filename).name
            if not info.filename.lower().endswith(".csv") or not name:
                continue
            target = dest_dir / name
            if target.exists() and target.stat().st_size == info.file_size:
                written.append(target)
                continue
            with zf.open(info) as src, open(target, "wb") as dst:
                while True:
                    block = src.read(1 << 20)
                    if not block:
                        break
                    dst.write(block)
            print(f"  extracted {target.name} ({_human(target.stat().st_size)})")
            written.append(target)
    if len(written) < min_csv:
        raise RuntimeError(
            f"expected at least {min_csv} CSVs in {zip_path.name}, found {len(written)}"
        )
    return written


def extract_zip_csv_any(zip_path: Path, dest_dir: Path) -> list[Path]:
    """Extract all CSVs from a zip, keeping relative paths when sensible."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            if not info.filename.lower().endswith(".csv"):
                continue
            # Prefer basename for flat layout expected by the pipeline.
            target = dest_dir / Path(info.filename).name
            if target.exists() and target.stat().st_size == info.file_size:
                written.append(target)
                continue
            with zf.open(info) as src, open(target, "wb") as dst:
                while True:
                    block = src.read(1 << 20)
                    if not block:
                        break
                    dst.write(block)
            print(f"  extracted {target.name} ({_human(target.stat().st_size)})")
            written.append(target)
    return written


def download_cicids2017() -> None:
    print("\n=== CIC-IDS2017 ===")
    dest_dir = DATA / "cicids2017" / "raw"
    dest_dir.mkdir(parents=True, exist_ok=True)

    # Prefer already-extracted CSVs
    existing = sorted(dest_dir.glob("*.csv"))
    if len(existing) >= 8 and all(p.stat().st_size > 1_000_000 for p in existing[:3]):
        print(f"  raw CSVs already present ({len(existing)} files) — skip download")
        for p in existing:
            print(f"    {p.name:70s} {_human(p.stat().st_size)}")
        return

    last_err: Exception | None = None
    for src in CICIDS2017_SOURCES:
        try:
            print(f" source: {src['name']}")
            zip_path = download_file(src["url"], src["zip"], min_size=src["min_size"])
            files = extract_zip_csv_flat(zip_path, src["dest"], min_csv=8)
            print(f" done -> {src['dest']} ({len(files)} CSVs)")
            return
        except Exception as exc:  # noqa: BLE001
            print(f"  source failed: {exc}")
            last_err = exc
    raise SystemExit(f"CIC-IDS2017 download failed: {last_err}")


def download_unsw_nb15() -> None:
    print("\n=== UNSW-NB15 ===")
    dest_dir = DATA / "unsw_nb15"
    dest_dir.mkdir(parents=True, exist_ok=True)

    needed = [
        dest_dir / "UNSW_NB15_training-set.csv",
        dest_dir / "UNSW_NB15_testing-set.csv",
    ]
    if all(p.exists() and p.stat().st_size >= UNSW_CSV_MIN for p in needed):
        print("  training/testing CSVs already present — skip download")
        for p in needed:
            print(f"    {p.name:70s} {_human(p.stat().st_size)}")
        return

    # Try CSV mirrors first (small, fast)
    csv_sources = [s for s in UNSW_NB15_SOURCES if s["kind"] == "csv"]
    for src in csv_sources:
        dest: Path = src["dest"]
        if dest.exists() and dest.stat().st_size >= src["min_size"]:
            print(f"  already have {dest.name}")
            continue
        try:
            print(f" source: {src['name']}")
            download_file(src["url"], dest, min_size=src["min_size"])
        except Exception as exc:  # noqa: BLE001
            print(f"  source failed: {exc}")

    if all(p.exists() and p.stat().st_size >= UNSW_CSV_MIN for p in needed):
        print(f" done -> {dest_dir}")
        for p in needed:
            print(f"    {p.name:70s} {_human(p.stat().st_size)}")
        return

    # Fallback: full zip archive
    for src in UNSW_NB15_SOURCES:
        if src["kind"] != "zip_csv_any":
            continue
        try:
            print(f" source (zip fallback): {src['name']}")
            zip_path = download_file(src["url"], src["zip"], min_size=src["min_size"])
            files = extract_zip_csv_any(zip_path, src["dest"])
            # Re-check canonical names (case variants)
            have = {p.name.lower() for p in dest_dir.glob("*.csv")}
            if any("training" in n for n in have) and any("testing" in n for n in have):
                print(f" done -> {dest_dir} ({len(files)} CSVs)")
                return
            print("  zip extracted but canonical training/testing CSVs not found")
        except Exception as exc:  # noqa: BLE001
            print(f"  zip source failed: {exc}")

    raise SystemExit(
        "UNSW-NB15 download failed.\n"
        "Manual option: download from https://research.unsw.edu.au/projects/unsw-nb15-dataset\n"
        f"and place UNSW_NB15_training-set.csv / UNSW_NB15_testing-set.csv into {dest_dir}"
    )


def list_sources() -> None:
    print("Known dataset sources\n")
    print("CIC-IDS2017:")
    for s in CICIDS2017_SOURCES:
        print(f"  - {s['name']}: {s['url']}")
    print("\nUNSW-NB15:")
    for s in UNSW_NB15_SOURCES:
        print(f"  - {s['name']}: {s['url']}")
    print(f"\nRepo root: {ROOT}")
    print(f"Data dir:  {DATA}")


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Download thesis IDS datasets")
    parser.add_argument(
        "--dataset",
        choices=("cicids2017", "unsw_nb15", "all"),
        default="all",
        help="which dataset to download (default: all)",
    )
    parser.add_argument("--list", action="store_true", help="print known sources and exit")
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.list:
        list_sources()
        return 0

    print(f"Repo: {ROOT}")
    print(f"Dataset filter: {args.dataset}")

    if args.dataset in ("cicids2017", "all"):
        download_cicids2017()
    if args.dataset in ("unsw_nb15", "all"):
        download_unsw_nb15()

    print("\nAll requested downloads finished.")
    print("Next: run experiments, e.g.")
    print("  python scripts/run_e1_baseline.py --dataset cicids2017")
    print("  python scripts/run_e1_baseline.py --dataset unsw_nb15")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
