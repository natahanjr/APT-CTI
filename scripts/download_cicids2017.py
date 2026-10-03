"""Download CICIDS2017 GeneratedLabelledFlows (contains Source/Dest IPs) from a
Hugging Face mirror of the official CIC release.

Run:  python scripts/download_cicids2017.py
"""

from __future__ import annotations

import os
import sys
import time
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import doh_patch  # noqa: F401  (patches system-DNS failures)

import requests

URL = "https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/main/csvs/GeneratedLabelledFlows.zip"
ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "data" / "cicids2017" / "raw"
ZIP_PATH = ROOT / "data" / "cicids2017" / "GeneratedLabelledFlows.zip"


def download() -> None:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    if ZIP_PATH.exists() and ZIP_PATH.stat().st_size > 280_000_000:
        print("zip already present, skipping download")
        return
    headers = {}
    if ZIP_PATH.exists():
        headers["Range"] = f"bytes={ZIP_PATH.stat().st_size}-"
        mode = "ab"
    else:
        mode = "wb"
    for attempt in range(8):
        try:
            with requests.get(URL, stream=True, timeout=60, headers=headers) as r:
                r.raise_for_status()
                total = int(r.headers.get("content-length", 0))
                done = ZIP_PATH.stat().st_size if mode == "ab" else 0
                last = time.time()
                with open(ZIP_PATH, mode) as fh:
                    for chunk in r.iter_content(chunk_size=1 << 20):
                        fh.write(chunk)
                        done += len(chunk)
                        if time.time() - last > 10:
                            pct = 100 * done / (total + done if total == 0 else total + (done - (done - len(chunk))))
                            print(f"  {done / 1e6:8.1f} MB", flush=True)
                            last = time.time()
            print("download complete:", ZIP_PATH)
            return
        except Exception as exc:  # noqa: BLE001
            print(f"attempt {attempt + 1} failed: {exc}", flush=True)
            time.sleep(5 * (attempt + 1))
            headers = {}
            mode = "ab" if ZIP_PATH.exists() else "wb"
    raise SystemExit("download failed after retries")


def extract() -> None:
    print("extracting ...", flush=True)
    with zipfile.ZipFile(ZIP_PATH) as zf:
        for info in zf.infolist():
            target = RAW_DIR / Path(info.filename).name
            if not info.filename.lower().endswith(".csv") or not Path(info.filename).name:
                continue
            if target.exists() and target.stat().st_size == info.file_size:
                continue
            with zf.open(info) as src, open(target, "wb") as dst:
                while True:
                    block = src.read(1 << 20)
                    if not block:
                        break
                    dst.write(block)
            print("  wrote", target.name, flush=True)


if __name__ == "__main__":
    download()
    extract()
    print("done ->", RAW_DIR)
    for f in sorted(RAW_DIR.glob("*.csv")):
        print(f"  {f.name:70s} {f.stat().st_size / 1e6:8.1f} MB")
