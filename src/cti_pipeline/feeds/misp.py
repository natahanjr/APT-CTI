"""MISP attribute poller (any MISP instance; requires URL + optional key)."""

from __future__ import annotations

import json

from ..net import epoch
from .base import PollReport, make_record

TYPES = ["ip-src", "ip-dst", "domain", "hostname", "url", "md5", "sha256", "hostname|port"]


def poll(misp_url: str = "", misp_key: str = "", timeout: int = 45) -> PollReport:
    report = PollReport(source="misp", ok=False, url=misp_url or "(not configured)")
    if not misp_url:
        report.error = "no MISP instance configured (set cti.misp_url)"
        return report
    try:
        url = misp_url.rstrip("/") + "/attributes/restSearch"
        body = json.dumps({
            "returnFormat": "json", "limit": 1000, "page": 1,
            "type": TYPES, "to_ids": 1, "deleted": 0,
        }).encode("utf-8")
        import requests

        headers = {"Content-Type": "application/json", "Accept": "application/json",
                   "User-Agent": "apt-cti-thesis/0.1"}
        if misp_key:
            headers["Authorization"] = misp_key
        resp = requests.post(url, data=body, headers=headers, timeout=timeout, verify=True)
        resp.raise_for_status()
        payload = resp.json()
        rows = payload.get("response", {}).get("Attribute", [])
        for row in rows:
            value = row.get("value", "")
            if "|" in value and row.get("type", "").endswith("|port"):
                value = value.split("|")[0]
            first = epoch(str(row.get("timestamp", ""))) or 0.0
            first = float(row.get("timestamp", 0) or 0) or first
            rec = make_record(
                value, "misp", first, first,
                0.8 if row.get("to_ids") else 0.5,
                row.get("comment", "") or row.get("type", ""),
            )
            if rec:
                report.records.append(rec)
        report.ok = True
    except Exception as exc:  # noqa: BLE001
        report.error = f"{type(exc).__name__}: {exc}"
    return report
