"""Enrich data/threat_actors.json from MITRE ATT&CK STIX + MISP galaxy.

Re-runnable top-up (merges into the existing corpus; never deletes rows):
  descriptions, aliases, MITRE techniques, sponsors and targeted sectors.
Also writes data/attack_group_techniques.json (G-ID -> T-IDs knowledge base).
Requires network; run after the base corpus exists:
  .venv\\Scripts\\python.exe scripts\\build_actor_kb.py
"""
import json
import os
import re
import sys
import time
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from cti_pipeline.net import http_get, ensure_doh  # noqa: E402

ensure_doh()
ACTORS_PATH = ROOT / "data" / "threat_actors.json"
GAL_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
TODAY = date.today().isoformat()

norm = lambda s: re.sub(r"[^a-z0-9]+", " ", str(s).lower()).strip()
clean = lambda s: re.sub(r"\s+", " ", str(s or "")).strip()


def fetch(url, tag):
    t0 = time.time()
    raw = http_get(url, timeout=180)
    print(f"[{tag}] {len(raw)/1e6:.1f} MB in {time.time()-t0:.1f}s", flush=True)
    return json.loads(raw.decode("utf-8"))


# ---------------------------------------------------------------- MISP galaxy
gal = fetch(GAL_URL, "misp")
gal_map = {}                          # norm(name/synonym) -> cluster
for cl in gal.get("values", []):
    meta = cl.get("meta") or {}
    names = [cl.get("value", "")] + list(meta.get("aliases", []) or []) \
        + list(meta.get("synonyms", []) or [])
    for n in names:
        if n:
            gal_map.setdefault(norm(n), cl)
print(f"[misp] {len(gal.get('values',[]))} clusters, {len(gal_map)} keys", flush=True)

# ------------------------------------------------------------------- MITRE STIX
stix = fetch(STIX_URL, "stix")
objs = stix.get("objects", [])
print(f"[stix] {len(objs)} objects", flush=True)
g_of_uuid, t_of_uuid, uses = {}, {}, []
for o in objs:
    if o.get("revoked") or o.get("x_mitre_deprecated"):
        continue
    if o["type"] == "intrusion-set":
        gid = next((r["external_id"] for r in o.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), None)
        if gid:
            g_of_uuid[o["id"]] = (gid, o)
    elif o["type"] == "attack-pattern":
        tid = next((r["external_id"] for r in o.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), None)
        if tid:
            t_of_uuid[o["id"]] = tid
    elif o["type"] == "relationship" and o.get("relationship_type") == "uses":
        uses.append((o.get("source_ref"), o.get("target_ref")))
groups = {}                           # gid -> {"obj": intrusion-set, "tech": [T..]}
for src, tgt in uses:
    if src in g_of_uuid and tgt in t_of_uuid:
        gid, gobj = g_of_uuid[src]
        groups.setdefault(gid, {"obj": gobj, "tech": set()})["tech"].add(t_of_uuid[tgt])
for gid in groups:
    groups[gid]["tech"] = sorted(groups[gid]["tech"])
print(f"[stix] {len(groups)} groups w/ techniques", flush=True)

# ----------------------------------------------------------- merge into actors
data = json.loads(ACTORS_PATH.read_text(encoding="utf-8"))
stats = {"stix_desc": 0, "misp_desc": 0, "stix_alias": 0, "misp_alias": 0,
         "tech": 0, "sponsor": 0, "sectors": 0}


def merge_aliases(base, extra):
    seen = {norm(x) for x in base}
    out = list(base)
    for x in extra:
        n = norm(x)
        if n and n not in seen and n not in ("apt", "group", "actor", "apt group"):
            out.append(clean(x)); seen.add(n)
    return out


for a in data["actors"]:
    gid = a.get("mitre_id")
    aliases = list(a.get("aliases") or [])
    summary, summary_src = a.get("summary") or "", a.get("summary_source", "reference-doc")

    if gid and gid in groups:
        gobj = groups[gid]["obj"]
        desc = clean(gobj.get("description"))
        if len(desc) > len(summary):
            summary, summary_src = desc[:1200], "mitre-stix"
            stats["stix_desc"] += 1
        before = len(aliases)
        aliases = merge_aliases(aliases, gobj.get("aliases", []) or [])
        if len(aliases) > before:
            stats["stix_alias"] += 1
        a["techniques"] = groups[gid]["tech"]
        stats["tech"] += 1

    cl = gal_map.get(norm(a["name"]))
    if not cl and aliases:
        for al in aliases:
            cl = gal_map.get(norm(al))
            if cl:
                break
    if cl:
        meta = cl.get("meta") or {}
        before = len(aliases)
        aliases = merge_aliases(aliases, (meta.get("aliases", []) or [])
                                + (meta.get("synonyms", []) or []))
        if len(aliases) > before:
            stats["misp_alias"] += 1
        mdesc = clean(cl.get("description"))
        if len(mdesc) > len(summary):
            summary, summary_src = mdesc[:1200], "misp-galaxy"
            stats["misp_desc"] += 1
        sponsor = clean(meta.get("cfr-suspected-state-sponsor"))
        if sponsor and not a.get("sponsor"):
            a["sponsor"] = sponsor
            stats["sponsor"] += 1
        secs = meta.get("cfr-target-category") or meta.get("targeted-sector") or []
        if isinstance(secs, str):
            secs = [secs]
        if secs and not a.get("sectors"):
            a["sectors"] = [clean(s) for s in secs if clean(s)]
            stats["sectors"] += 1

    a["summary"] = summary
    a["summary_source"] = summary_src
    a["aliases"] = [x for x in aliases
                    if not re.fullmatch(r"G\d{4}", str(x).strip()) and clean(x)]

names = set()
for a in data["actors"]:
    names.add(norm(a["name"]))
    names.update(norm(x) for x in a["aliases"] if norm(x))
data["total_unique_names"] = len(names)
data["refreshed"] = (f"{TODAY} refreshed: MITRE ATT&CK STIX (descriptions, aliases, "
                     "techniques) + MISP threat-actor galaxy (synonyms, descriptions, sponsors)")

kb = {"source": "MITRE ATT&CK STIX enterprise-attack", "generated": TODAY,
      "groups": {gid: g["tech"] for gid, g in sorted(groups.items())}}
(ROOT / "data" / "attack_group_techniques.json").write_text(
    json.dumps(kb, indent=1, ensure_ascii=False), encoding="utf-8")
ACTORS_PATH.write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding="utf-8")

print("merge stats:", stats)
print("actors:", data["total_actors"], "unique names:", data["total_unique_names"])
print("with techniques:", sum(1 for a in data["actors"] if a.get("techniques")),
      "| with sponsor:", sum(1 for a in data["actors"] if a.get("sponsor")),
      "| with sectors:", sum(1 for a in data["actors"] if a.get("sectors")))
print("files MB:", round(os.path.getsize(ACTORS_PATH)/1e6, 2),
      round(os.path.getsize(ROOT / "data" / "attack_group_techniques.json")/1e6, 2))
