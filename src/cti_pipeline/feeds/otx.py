"""AlienVault OTX poller (pulse indicators).  Requires an API key.

Without a key the poller is skipped gracefully (recorded in the PollReport).
"""

from __future__ import annotations

import json

from ..net import epoch, http_get
from .base import PollReport, make_record

BASE = "https://otx.alienvault.com/api/v1"


def poll(api_key: str = "", timeout: int = 45) -> PollReport:
    report = PollReport(source="otx", ok=False, url=f"{BASE}/pulses/latest")
    if not api_key:
        report.error = "no OTX API key configured (set cti.otx_api_key)"
        return report
    try:
        seen = 0
        for page in range(1, 4):
            payload = http_get(
                f"{BASE}/pulses/latest?limit=50&page={page}",
                timeout=timeout, headers={"X-OTX-API-KEY": api_key},
            )
            data = json.loads(payload.decode("utf-8"))
            results = data.get("results", [])
            if not results:
                break
            for pulse in results:
                created = epoch(pulse.get("created", "")) or 0.0
                modified = epoch(pulse.get("modified", "")) or created
                conf = float(pulse.get("confidence", 0.5) or 0.5) / 100.0
                if conf <= 1:
                    conf = conf if conf > 0 else 0.5
                for ind in pulse.get("indicators", []):
                    rec = make_record(
                        ind.get("indicator", ""), "otx", created, modified,
                        conf, ",".join(pulse.get("tags", [])[:6]),
                        ioc_type=None if ind.get("type") == "IPv4" else None,
                    )
                    if rec:
                        report.records.append(rec)
                        seen += 1
            if not data.get("next"):
                break
        report.ok = True
    except Exception as exc:  # noqa: BLE001
        report.error = f"{type(exc).__name__}: {exc}"
    return report
