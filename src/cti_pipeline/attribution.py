"""Evidence-based APT attribution for live alerts (Contribution 6).

Combines three sources of evidence per alert:

  1. Retrieval similarity  — TF-IDF model trained on the curated threat-actor
     corpus (model/attribution_tfidf.joblib, 1040 actors: names, aliases,
     summaries, sectors, sponsors).
  2. Technique overlap     — alert SHAP reasons map to MITRE ATT&CK techniques
     (attack_map.py); overlap with the actor's observed technique set
     (MITRE ATT&CK STIX) weighs the match.
  3. IoC strength          — live CTI-feed matches (source count + confidence)
     corroborate that the infrastructure is known-malicious.

Verdict tiers (honest by construction — UNSW live flows carry no ground-truth
actor labels, so this ranks candidates with stated evidence):

  apt-attributed  IoC-corroborated + specific enough -> notify=True
  apt-candidate   plausible but uncorroborated/ambiguous -> listed, no ping
  not-apt         no APT corroboration -> behavioural category fallback
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity

_TID = re.compile(r"T\d{4}")

_PORT_HINT = {
    53: "dns", 80: "http", 81: "http", 443: "https", 445: "smb",
    1433: "mssql", 3306: "mysql", 3389: "rdp", 22: "ssh", 21: "ftp",
    23: "telnet", 25: "smtp", 110: "pop3", 143: "imap", 389: "ldap",
    4444: "reverse shell", 8080: "http proxy", 8443: "https",
    5985: "winrm", 123: "ntp", 161: "snmp", 5060: "sip", 1900: "ssdp",
    5353: "mdns", 5355: "llmnr",
}

# fallback buckets for alerts that are not attributable to any known actor
_CATEGORY_RULES: list[tuple[tuple[str, ...], str]] = [
    (("T1110",), "Credential brute-force / password guessing"),
    (("T1046",), "Network scanning / service reconnaissance"),
    (("T1190",), "Exploit attempt against a public-facing service"),
    (("T1041", "T1005"), "Suspected data exfiltration / staging"),
    (("T1021",), "Lateral movement over remote services"),
    (("T1071", "T1571", "T1095"), "Anomalous command-and-control beaconing"),
    (("T1090", "T1027", "T1562"), "Evasive / proxied / obfuscated traffic"),
]


def _round(x, n=3):
    return round(float(x), n)


class AttributionEngine:
    """Loads the actor corpus + trained retrieval model and scores alerts."""

    def __init__(self, root: str | Path, *, top_k: int = 5,
                 min_score: float = 0.15, min_notify: float = 0.25):
        self.root = Path(root)
        self.top_k = int(top_k)
        self.min_score = float(min_score)
        self.min_notify = float(min_notify)

        data = json.loads((self.root / "data" / "threat_actors.json")
                          .read_text(encoding="utf-8"))
        self.actors = {str(a["id"]): a for a in data["actors"]}
        bundle = joblib.load(self.root / "model" / "attribution_tfidf.joblib")
        self.vectorizer = bundle["vectorizer"]
        self.doc_matrix = bundle["doc_matrix"]
        self.actor_ids = [str(i) for i in bundle["actor_ids"]]
        self.meta = dict(bundle.get("meta") or {})
        # pre-compute technique sets for O(1) overlap
        self._tech: dict[str, frozenset[str]] = {
            aid: frozenset(t for t in (a.get("techniques") or []) if _TID.fullmatch(t))
            for aid, a in self.actors.items()
        }
        # IDF-style rarity weights: a technique shared by almost every group
        # (e.g. T1071) is weak evidence of *which* group, while a rare one
        # (e.g. T1110) discriminates. n_t = # mapped groups using technique t.
        n_groups = max(1, sum(1 for s in self._tech.values() if s))
        counts: dict[str, int] = {}
        for s in self._tech.values():
            for t in s:
                counts[t] = counts.get(t, 0) + 1
        self._w = {t: float(np.log((1 + n_groups) / (1 + c)))
                   for t, c in counts.items()}

    # ------------------------------------------------------------------ inputs
    @staticmethod
    def alert_techniques(alert: dict) -> dict[str, str]:
        """T-ID -> technique label from the alert's SHAP reason codes."""
        out: dict[str, str] = {}
        for r in alert.get("reasons") or []:
            label = str(r.get("technique") or "")
            m = _TID.search(label)
            if m:
                out.setdefault(m.group(0), label)
        return out

    @staticmethod
    def ioc_strength(alert: dict) -> float:
        cti = alert.get("cti") or {}
        hit = float(cti.get("ioc_src_match") or 0) or float(cti.get("ioc_dst_match") or 0)
        if not hit:
            return 0.0
        return float(np.clip(0.4 * min(float(cti.get("source_count") or 0), 3)
                             + 0.6 * float(cti.get("feed_confidence") or 0), 0.0, 1.0))

    @staticmethod
    def _query(alert: dict, tech: dict[str, str]) -> str:
        parts: list[str] = []
        for r in alert.get("reasons") or []:
            if r.get("tactic") and r["tactic"] != "Uncategorised":
                parts.append(str(r["tactic"]).replace(" and ", " "))
            if r.get("technique") and r["technique"] != "-":
                parts.append(str(r["technique"]).replace("·", " "))
        flow = alert.get("flow") or {}
        hint = _PORT_HINT.get(int(flow.get("dst_port") or 0))
        if hint:
            parts.append(f"port {flow.get('dst_port')} {hint}")
        parts.append(str(flow.get("proto") or ""))
        cti = alert.get("cti") or {}
        if float(cti.get("ioc_src_match") or 0) or float(cti.get("ioc_dst_match") or 0):
            parts.append("known malicious indicator c2 command control feed")
        parts.extend(tech.values())
        return re.sub(r"\s+", " ", " ".join(str(p) for p in parts if p)).strip()

    # ----------------------------------------------------------------- scoring
    def _rarity_overlap(self, alert_techs: set[str],
                        actor_techs: frozenset[str]) -> tuple[float, list[str]]:
        """Weighted technique overlap: rare techniques count more."""
        if not alert_techs or not actor_techs:
            return 0.0, []
        hits = sorted(alert_techs & actor_techs)
        denom = sum(self._w.get(t, float(np.log(1 + len(self._tech))) )
                    for t in alert_techs)
        if denom <= 0.0 or not hits:
            return 0.0, hits
        num = sum(self._w.get(t, 0.0) for t in hits)
        return float(np.clip(num / denom, 0.0, 1.0)), hits

    def attribute(self, alert: dict) -> dict:
        tech = self.alert_techniques(alert)
        alert_techs = set(tech)
        ioc = self.ioc_strength(alert)
        query = self._query(alert, tech)
        sims = (cosine_similarity(self.vectorizer.transform([query]), self.doc_matrix)[0]
                if query else np.zeros(len(self.actor_ids)))

        scored = []
        for idx, aid in enumerate(self.actor_ids):
            retr = float(sims[idx])
            overlap, hits = self._rarity_overlap(alert_techs, self._tech[aid])
            combined = 0.6 * overlap + 0.4 * retr
            scored.append((combined, retr, overlap, hits, aid))
        scored.sort(key=lambda t: (-t[0], t[4]))
        top = scored[: self.top_k]

        best = top[0] if top else (0.0, 0.0, 0.0, [], None)
        combined, retrieval, overlap, hits, aid = best
        runner = top[1][0] if len(top) > 1 else 0.0
        margin = combined - runner
        # specificity: how many of the 1040 actors are still plausible?
        # (an "APT detected" notification is only actionable when few are)
        n_close = sum(1 for c in scored if combined - c[0] < 0.02)
        ioc_backed = ioc > 0.0

        evidence: list[str] = []
        if alert_techs:
            evidence.append(
                f"alert ATT&CK techniques: {', '.join(sorted(alert_techs))}")
        if hits:
            evidence.append(
                f"{self.actors[aid]['name']} shares {len(hits)}/"
                f"{len(alert_techs)} of them ({', '.join(hits)}) "
                f"[MITRE ATT&CK technique set, rarity-weighted {overlap:.2f}]")
        if ioc_backed:
            cti = alert.get("cti") or {}
            side = ("destination" if float(cti.get("ioc_dst_match") or 0)
                    else "source")
            evidence.append(
                f"{side} IP on live CTI feeds (confidence "
                f"{float(cti.get('feed_confidence') or 0):.2f}, "
                f"{int(cti.get('source_count') or 0)} source(s))")

        # notify = APT activity corroborated AND specific enough to be actionable
        specific = n_close <= (3 if ioc_backed else 2)
        corroborated = ioc_backed or (len(hits) >= 2 and overlap >= 0.7)
        notify = bool(aid and hits and corroborated and overlap >= 0.5
                      and combined >= self.min_notify and specific)
        ambiguous = bool(notify and n_close > 1)

        candidates = []
        for c_comb, c_retr, c_ov, c_hits, c_aid in top:
            if c_comb < self.min_score:
                break
            a = self.actors[c_aid]
            candidates.append({
                "id": c_aid, "name": a["name"], "mitre_id": a.get("mitre_id"),
                "origin": a.get("origin"), "score": _round(c_comb),
                "retrieval": _round(c_retr), "tech_overlap": _round(c_ov),
                "technique_hits": c_hits,
            })

        if notify:
            verdict, category = "apt-attributed", None
            conf = float(np.clip(0.45 * combined + 0.30 * ioc
                                 + 0.25 * overlap, 0.0, 0.99))
            if ambiguous:                       # honest tie handling
                conf *= 0.8
                tied = [c["name"] for c in candidates[1:]
                        if combined - c["score"] < 0.02][:3]
                evidence.append(
                    f"top candidates statistically tied (Δ {_round(margin)}): "
                    + ", ".join(tied) + " — treat actor as best guess")
            actor = dict(candidates[0])
            actor["confidence"] = _round(conf)
            actor["ambiguous"] = ambiguous
        elif candidates and ioc_backed:
            # IoC-backed but specificity gate failed -> named candidate, no ping
            verdict, category = "apt-candidate", None
            conf = _round(0.6 * combined + 0.4 * retrieval)
            actor = dict(candidates[0])
            actor["confidence"] = conf
            why = []
            if not specific:
                why.append(f"{n_close} groups equally plausible")
            if overlap < 0.5:
                why.append(f"technique overlap {overlap:.2f} < 0.5")
            evidence.append(
                "notification withheld: " + ("; ".join(why) or "below notify threshold")
                + " — listed as candidate only")
        elif candidates and len(hits) >= 2 and overlap >= 0.7 and n_close <= 2:
            # technique-only corroboration (no IoC): plausible, but never notify
            verdict, category = "apt-candidate", None
            conf = _round(0.6 * combined + 0.4 * retrieval)
            actor = dict(candidates[0])
            actor["confidence"] = conf
            evidence.append(
                "notification withheld: no IoC corroboration (technique-only "
                "match) — listed as candidate only")
        else:
            # no corroboration (no IoC, techniques too generic or too many
            # equally-plausible groups) -> not attributable: fall back to behaviour
            verdict, category = "not-apt", self.category(alert_techs, ioc_backed)
            conf = _round(max(combined, retrieval) * 0.5)
            actor = None
            if aid and hits and combined >= self.min_score:
                why = (f"{n_close} groups equally plausible" if n_close > 2
                       else f"technique overlap {overlap:.2f} too weak")
                evidence.append(
                    f"best candidate {self.actors[aid]['name']} "
                    f"(score {_round(combined)}): {why} — "
                    "no APT corroboration (no IoC hit)")
            else:
                evidence.append(
                    "no actor in the corpus matches this alert's techniques")
            evidence.append("classified by observed behaviour instead")

        if not category:
            evidence.append(f"retrieval similarity {_round(retrieval)} "
                            "against 1040-actor corpus (TF-IDF)")

        return {
            "verdict": verdict,
            "notify": notify,
            "confidence": _round(conf),
            "category": category,
            "actor": actor,
            "candidates": candidates,
            "competitors": int(n_close),
            "techniques": sorted(alert_techs),
            "ioc_backed": ioc_backed,
            "evidence": evidence,
            "model": {"trained_at": self.meta.get("trained_at", ""),
                      "n_actors": self.meta.get("n_actors", 0)},
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

    # ------------------------------------------------------------ fallback tier
    @staticmethod
    def category(alert_techs: set[str], ioc_backed: bool) -> str:
        """Behavioural bucket for alerts that are not attributable to an APT."""
        for rules, label in _CATEGORY_RULES:
            if alert_techs & set(rules):
                return f"{label} (non-APT)"
        if ioc_backed:
            return "Known malicious infrastructure — commodity malware/C2 (non-APT)"
        if not alert_techs:
            return "Unclassified anomalous traffic (non-APT)"
        return "Unclassified anomalous traffic (non-APT)"


def default_engine(root: str | Path, cfg: dict | None = None) -> AttributionEngine | None:
    """Build the engine from the `attribution:` config block (None if disabled)."""
    cfg = cfg or {}
    if not cfg.get("enabled", True):
        return None
    try:
        return AttributionEngine(
            root,
            top_k=int(cfg.get("top_k", 5)),
            min_score=float(cfg.get("min_score", 0.15)),
            min_notify=float(cfg.get("min_notify", 0.25)),
        )
    except Exception as exc:                              # noqa: BLE001
        print(f"[attribution] disabled: {exc}", flush=True)
        return None
