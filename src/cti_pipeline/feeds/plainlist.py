"""Keyless plain-list feeds: one indicator (IP / domain / URL) per line.

Covers seven additional public sources so the platform runs with ten live
feeds out of the box — no API keys, plain text over HTTPS, comment lines
(``#``) tolerated.  Every poller returns a PollReport and never raises.
"""

from __future__ import annotations

import time

from ..net import http_get
from .base import PollReport, make_record

# source -> (url, base confidence, provenance tag, record cap)
SOURCES: dict[str, tuple[str, float, str, int]] = {
    "blocklist": (
        "https://lists.blocklist.de/lists/all.txt", 0.70,
        "fail2ban-aggregated attacker IPs", 60_000),
    "ipsum": (
        "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt", 0.55,
        "aggregated multi-list malicious IPs (count = sightings)", 120_000),
    "emerging": (
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", 0.80,
        "Emerging Threats compromised hosts", 60_000),
    "cins": (
        "https://cinsscore.com/list/ci-badguys.txt", 0.75,
        "CINS Army hostile sources", 60_000),
    "binarydefense": (
        "https://www.binarydefense.com/banlist.txt", 0.75,
        "BinaryDefense BAN sensor IPs", 30_000),
    "openphish": (
        "https://openphish.com/feed.txt", 0.75,
        "OpenPhish phishing URLs", 30_000),
    "certpl": (
        "https://hole.cert.pl/domains/domains.txt", 0.80,
        "CERT.PL malicious domains", 60_000),
}


def _first_token(line: str) -> tuple[str, str]:
    """Split ``value[,\\t ]tail`` into (value, tail); feeds vary in delimiter."""
    parts = line.replace(",", " ", 1).split(None, 1)
    return (parts[0], parts[1].strip() if len(parts) > 1 else "")


def poll_one(name: str, timeout: int = 30) -> PollReport:
    url, conf, tag, cap = SOURCES[name]
    report = PollReport(source=name, ok=False, url=url)
    now = time.time()
    try:
        text = http_get(url, timeout=timeout).decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        report.error = f"{type(exc).__name__}: {exc}"
        return report
    for line in text.splitlines():
        if len(report.records) >= cap:
            break
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        value, tail = _first_token(line)
        sightings, confidence = 1, conf
        if name == "ipsum" and tail.split(None, 1)[0].isdigit():
            # ipsum lines are "<ip> <times-listed>"; more lists = higher trust
            sightings = max(1, int(tail.split(None, 1)[0]))
            confidence = min(0.95, conf + 0.05 * min(sightings, 8))
        rec = make_record(value, name, now, now, confidence, tag,
                          sightings=sightings)
        if rec:
            report.records.append(rec)
    report.ok = True
    return report
