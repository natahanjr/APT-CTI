"""Flow input adapters: sensor formats -> canonical UNSW-schema records.

Supported formats
-----------------
jsonl   one flow per line; keys may be native UNSW names (dur, sbytes, ...)
        or canonical snake_case (src_ip, dst_port, ts, ...). Used by any
        exporter you point at the inbox file.
csv     same keys, header row required.
zeek    Zeek ``conn.log`` (tab-separated, ``#fields`` header).
eve     Suricata ``eve.json`` records with ``event_type`` flow/netflow.

Every adapter emits the canonical record::

    src_ip dst_ip src_port dst_port proto ts
    dur sbytes dbytes Spkts Dpkts Sload Dload smeansz dmeansz service state

Missing derived quantities are computed the UNSW way
(``Sload = sbytes*8/dur`` bits/s, ``smeansz = sbytes/Spkts``); missing
service/state degrade to ``-``/``UNK`` and the model's frozen vocabulary
handles unseen categories at design time.
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path

NATIVE = [
    "src_ip", "dst_ip", "src_port", "dst_port", "proto", "ts",
    "dur", "sbytes", "dbytes", "Spkts", "Dpkts",
    "Sload", "Dload", "smeansz", "dmeansz", "service", "state",
]

# sensor vocabulary -> UNSW-NB15 vocabulary (best effort, documented in README)
ZEEK_SERVICE = {
    "http": "http", "dns": "dns", "ftp": "ftp", "ftp_data": "ftp-data",
    "smtp": "smtp", "ssh": "ssh", "dhcp": "dhcp", "radius": "radius",
    "pop3": "pop3", "snmp": "snmp", "ssl": "-", "tls": "-", "irc": "-",
    "ntp": "-", "dnp3": "-", "krb5": "-",
}
ZEEK_STATE = {
    "SF": "FIN", "S1": "CON", "S2": "FIN", "S3": "FIN",
    "S0": "REQ", "REJ": "RST", "RSTO": "RST", "RSTR": "RST",
    "RSTOS0": "RST", "RSTRH": "RST", "OTH": "INT", "RES1": "INT",
    "RES2": "INT",
}
EVE_APP_PROTO = {
    "http": "http", "http2": "http", "dns": "dns", "ftp": "ftp",
    "ftp-data": "ftp-data", "smtp": "smtp", "ssh": "ssh",
    "dhcp": "dhcp", "radius": "radius", "snmp": "snmp",
    "tls": "-", "ssl": "-", "teredo": "-", "ntp": "-",
}
EVE_STATE = {
    "established": "CON", "closed": "FIN", "new": "REQ",
    "broke": "INT", "closed_by_enemy": "RST",
}


def detect_format(path: Path, hint: str = "auto") -> str:
    if hint and hint != "auto":
        return hint
    suf = path.suffix.lower()
    if suf in (".log",) and "conn" in path.name.lower():
        return "zeek"
    if suf in (".jsonl", ".ndjson"):
        return "jsonl"
    if suf == ".json":
        return "eve"   # suricata eve.json is newline-delimited but .json suffixed
    if suf == ".csv":
        return "csv"
    if suf == ".log":
        return "zeek"
    return "jsonl"


def _f(v, default=0.0) -> float:
    try:
        if v is None or v == "" or v == "-":
            return float(default)
        return float(v)
    except (TypeError, ValueError):
        return float(default)


def _i(v, default=0) -> int:
    return int(_f(v, default))


def _iso_ts(v) -> float:
    if v is None or v == "":
        return 0.0
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return 0.0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _derive(rec: dict) -> dict:
    """Fill UNSW-derived quantities when the sensor did not supply them."""
    dur = max(_f(rec.get("dur")), 0.0)
    sb = max(_f(rec.get("sbytes")), 0.0)
    db = max(_f(rec.get("dbytes")), 0.0)
    sp = max(_f(rec.get("Spkts")), 0.0)
    dp = max(_f(rec.get("Dpkts")), 0.0)
    dur_safe = dur if dur > 1e-6 else 1e-6
    if not rec.get("Sload"):
        rec["Sload"] = sb * 8.0 / dur_safe
    if not rec.get("Dload"):
        rec["Dload"] = db * 8.0 / dur_safe
    if not rec.get("smeansz") and sp > 0:
        rec["smeansz"] = sb / sp
    if not rec.get("dmeansz") and dp > 0:
        rec["dmeansz"] = db / dp
    rec.setdefault("service", "-")
    rec.setdefault("state", "UNK")
    rec["proto"] = str(rec.get("proto") or "-").lower()
    return rec


def from_jsonl_line(line: str) -> dict | None:
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    return _from_generic(obj)


def _from_generic(obj: dict) -> dict | None:
    # canonical or UNSW-native keys (either accepted)
    alias = {
        "src_ip": ["src_ip", "srcip", "src", "source_ip", "id.orig_h",
                   "id_orig_h", "sa"],
        "dst_ip": ["dst_ip", "dstip", "dst", "dest_ip", "destination_ip",
                   "id.resp_h", "id_resp_h", "da"],
        "src_port": ["src_port", "sport", "srcport", "id.orig_p", "id_orig_p",
                     "sp"],
        "dst_port": ["dst_port", "dsport", "dstport", "dest_port",
                     "id.resp_p", "id_resp_p", "dp"],
        "proto": ["proto", "protocol"],
        "ts": ["ts", "timestamp", "time", "start"],
        "dur": ["dur", "duration", "flow_duration"],
        "sbytes": ["sbytes", "bytes_toserver", "orig_bytes", "src_bytes"],
        "dbytes": ["dbytes", "bytes_toclient", "resp_bytes", "dst_bytes"],
        "Spkts": ["Spkts", "pkts_toserver", "orig_pkts", "spkts"],
        "Dpkts": ["Dpkts", "pkts_toclient", "resp_pkts", "dpkts"],
        "service": ["service", "app_proto"],
        "state": ["state", "conn_state", "status"],
    }
    rec: dict = {}
    lower = {str(k).lower(): v for k, v in obj.items()}
    for canon, keys in alias.items():
        for k in keys:
            v = obj.get(k, lower.get(k.lower()))
            if v is not None and v != "":
                rec[canon] = v
                break
    if "src_ip" not in rec or "dst_ip" not in rec:
        return None
    rec["ts"] = _iso_ts(rec.get("ts"))
    rec["src_port"] = _i(rec.get("src_port"))
    rec["dst_port"] = _i(rec.get("dst_port"))
    rec["proto"] = str(rec.get("proto") or "-").lower()
    rec["service"] = str(rec.get("service") or "-")
    rec["state"] = str(rec.get("state") or "UNK")
    # zeek-style numeric strings
    for k in ("dur", "sbytes", "dbytes", "Spkts", "Dpkts"):
        rec[k] = _f(rec.get(k))
    return _derive(rec)


def from_csv_rows(text: str) -> list[dict]:
    out = []
    for row in csv.DictReader(io.StringIO(text)):
        rec = _from_generic(row)
        if rec:
            out.append(rec)
    return out


def from_zeek(text: str) -> list[dict]:
    """Parse a Zeek conn.log block (with ``#fields`` header)."""
    fields: list[str] = []
    out: list[dict] = []
    for line in text.splitlines():
        if not line:
            continue
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#"):
            continue
        if not fields:
            continue
        parts = line.split("\t")
        if len(parts) < len(fields):
            parts += ["-"] * (len(fields) - len(parts))
        row = dict(zip(fields, parts[:len(fields)]))
        rec = {
            "src_ip": row.get("id.orig_h", "-"),
            "dst_ip": row.get("id.resp_h", "-"),
            "src_port": _i(row.get("id.orig_p")),
            "dst_port": _i(row.get("id.resp_p")),
            "proto": str(row.get("proto", "-")).lower(),
            "ts": _f(row.get("ts")),
            "dur": _f(row.get("duration")),
            "sbytes": _f(row.get("orig_bytes")),
            "dbytes": _f(row.get("resp_bytes")),
            "Spkts": _f(row.get("orig_pkts")),
            "Dpkts": _f(row.get("resp_pkts")),
            "service": ZEEK_SERVICE.get(str(row.get("service", "")).strip(), "-"),
            "state": ZEEK_STATE.get(str(row.get("conn_state", "")).strip(), "UNK"),
        }
        if rec["src_ip"] in ("-", "(empty)"):
            continue
        out.append(_derive(rec))
    return out


def from_eve_line(line: str) -> dict | None:
    """Parse one Suricata eve.json line (flow / netflow events only)."""
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    etype = obj.get("event_type", "")
    if etype not in ("flow", "netflow"):
        return None
    flow = obj.get("flow") or {}
    rec = {
        "src_ip": obj.get("src_ip"),
        "dst_ip": obj.get("dest_ip") or obj.get("dst_ip"),
        "src_port": obj.get("src_port"),
        "dst_port": obj.get("dest_port") or obj.get("dst_port"),
        "proto": str(obj.get("proto", "-")).upper(),
        "ts": obj.get("timestamp") or flow.get("start"),
        "sbytes": flow.get("bytes_toserver"),
        "dbytes": flow.get("bytes_toclient"),
        "Spkts": flow.get("pkts_toserver"),
        "Dpkts": flow.get("pkts_toclient"),
        "service": obj.get("app_proto") or "-",
        "state": obj.get("state") or obj.get("flow_state") or flow.get("state") or "-",
    }
    # netflow event shape: single "bytes"/"pkts" counters, start/end pair
    if etype == "netflow":
        rec["sbytes"] = flow.get("bytes") or rec["sbytes"]
        rec["Spkts"] = flow.get("pkts") or rec["Spkts"]
        rec["dbytes"] = rec.get("dbytes") or 0
        rec["Dpkts"] = rec.get("Dpkts") or 0
    start = _iso_ts(flow.get("start"))
    end = _iso_ts(flow.get("end")) if flow.get("end") else 0.0
    rec["dur"] = max(0.0, end - start) if end else 0.0
    rec["ts"] = start or _iso_ts(rec["ts"])
    rec["proto"] = str(rec["proto"]).lower()
    rec["service"] = EVE_APP_PROTO.get(str(rec["service"]).strip().lower(), "-")
    rec["state"] = EVE_STATE.get(str(rec["state"]).strip().lower(), "UNK")
    if not rec["src_ip"] or not rec["dst_ip"]:
        return None
    for k in ("sbytes", "dbytes", "Spkts", "Dpkts"):
        rec[k] = _f(rec.get(k))
    return _derive(rec)


def parse_chunk(text: str, fmt: str) -> list[dict]:
    """Parse a text chunk (new data read from the tail) into canonical records."""
    if not text:
        return []
    if fmt == "csv":
        return from_csv_rows(text)
    if fmt == "zeek":
        return from_zeek(text)
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if fmt == "eve":
            rec = from_eve_line(line)
        else:
            rec = from_jsonl_line(line)
        if rec:
            out.append(rec)
    return out
