"""Feature -> MITRE ATT&CK mapping used by the E4 reason-code stability audit."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class AttackRef:
    tactic: str
    technique: str
    rationale: str


UNMAPPED = AttackRef("Uncategorised", "-", "feature has no ATT&CK-aligned interpretation")

# exact feature-name rules first (checked in order)
_RULES: list[tuple[re.Pattern, AttackRef]] = [
    (re.compile(r"^(ioc_|feed_|source_count|reputation_bucket)"),
     AttackRef("Command and Control", "T1071 · Application Layer Protocol",
               "live IoC / feed-freshness evidence of known C2 or payload infrastructure")),
    (re.compile(r"^(dst_port|dsport|dport|sport|src_port)$"),
     AttackRef("Command and Control", "T1571 · Non-Standard Port",
               "port choice is a common beacon / covert-channel selection signal")),
    (re.compile(r"^(dur|Sintpkt|Dintpkt|Sjit|Djit|interarrival|iat)"),
     AttackRef("Command and Control", "T1071 · Application Layer Protocol",
               "timing / inter-arrival structure reveals beacon periodicity")),
    (re.compile(r"^(sbytes|dbytes|Spkts|Dpkts|rate|Sload|Dload|bytes_|packets_)"),
     AttackRef("Exfiltration", "T1041 · Exfiltration over C2 channel",
               "volume and direction of transfer indicate data movement")),
    (re.compile(r"^(sttl|dttl|swin|dwin|stcpb|dtcpb)"),
     AttackRef("Defense Evasion", "T1090 · Proxy",
               "stack/window fingerprint suggests proxying, spoofing or covert relays")),
    (re.compile(r"^(sloss|dloss)"),
     AttackRef("Defense Evasion", "T1090 · Proxy",
               "packet loss pattern follows relayed or filtered paths")),
    (re.compile(r"^(synack|ackdat|tcprtt)"),
     AttackRef("Discovery", "T1046 · Network Service Scanning",
               "handshake timing is characteristic of scan / probe activity")),
    (re.compile(r"^ct_srv_src$|^ct_srv_dst$"),
     AttackRef("Lateral Movement", "T1021 · Remote Services",
               "service fan-out from one host indicates lateral probing")),
    (re.compile(r"^ct_dst_ltm$|^ct_src_ltm$|^ct_dst_src_ltm$|^ct_src_dport_ltm$|^ct_dst_sport_ltm$"),
     AttackRef("Lateral Movement", "T1021 · Remote Services",
               "short-window connection bursts to the same host/port")),
    (re.compile(r"^ct_state_ttl$|^state$|flag"),
     AttackRef("Defense Evasion", "T1027 · Obfuscated Files or Information",
               "connection-state mix departs from benign baseline")),
    (re.compile(r"^ct_flw_http_mthd$|^trans_depth$|^res_bdy_len$"),
     AttackRef("Initial Access", "T1190 · Exploit Public-Facing Application",
               "HTTP transaction depth / body size typifies web exploits")),
    (re.compile(r"^is_ftp_login$|^ct_ftp_cmd$"),
     AttackRef("Credential Access", "T1110 · Brute Force",
               "repeated FTP authentication attempts")),
    (re.compile(r"^service$|ssh|ftp|smtp|dns|http"),
     AttackRef("Discovery", "T1046 · Network Service Scanning",
               "service enumeration / service-mix anomaly")),
    (re.compile(r"^is_sm_ips_ports$"),
     AttackRef("Defense Evasion", "T1562 · Impair Defenses",
               "same source/destination IP:port pair indicates reflection or tunneling")),
    (re.compile(r"^proto$"),
     AttackRef("Command and Control", "T1095 · Non-Application Layer Protocol",
               "unusual protocol mix for covert channels")),
    (re.compile(r"smean|dmean|seg|pkt_len|length"),
     AttackRef("Collection", "T1005 · Data from Local Network Storage",
               "segment/packet size statistics reflect payload staging")),
]

_CT_PREFIX = AttackRef("Lateral Movement", "T1021 · Remote Services",
                       "aggregate connection-tracking counter")


def map_feature(name: str) -> AttackRef:
    """Map a model feature name to an ATT&CK tactic + technique."""
    for pattern, ref in _RULES:
        if pattern.search(name):
            return ref
    if name.startswith("ct_"):
        return _CT_PREFIX
    if re.search(r"port", name):
        return _RULES[1][1]
    if re.search(r"byte|pkt|packet|rate|load", name):
        return _RULES[3][1]
    if re.search(r"dur|time|iat|interval|jit", name, re.IGNORECASE):
        return _RULES[2][1]
    return UNMAPPED


def tactic_of(name: str) -> str:
    return map_feature(name).tactic
