"""Train the threat-actor retrieval model (TF-IDF over the actor corpus).

    python scripts/train_attribution.py

Reads  data/threat_actors.json          (1040 actors: names, aliases, summaries,
                                         sectors, sponsors, MITRE techniques)
Writes model/attribution_tfidf.joblib   {vectorizer, doc_matrix, actor_ids, meta}

The retrieval model is the supervised half of the attribution layer: it is fit
on the curated threat-actor corpus and queried at runtime with an alert's
evidence text (ATT&CK tactics/techniques, service hints, CTI context).
Attribution itself combines retrieval similarity with the MITRE technique
overlap (data/attack_group_techniques.json / per-actor techniques) and IoC
strength — see src/cti_pipeline/attribution.py.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer

ROOT = Path(__file__).resolve().parents[1]


def actor_document(a: dict) -> str:
    parts = [a.get("name", "")]
    parts += list(a.get("aliases") or [])
    parts.append(a.get("origin") or "")
    if a.get("sponsor"):
        parts.append(a["sponsor"])
    parts += list(a.get("sectors") or [])
    parts.append(a.get("summary") or "")
    parts += list(a.get("techniques") or [])
    text = " ".join(str(p) for p in parts if p)
    return re.sub(r"\s+", " ", text).strip()


def main() -> int:
    actors_path = ROOT / "data" / "threat_actors.json"
    out_path = ROOT / "model" / "attribution_tfidf.joblib"
    data = json.loads(actors_path.read_text(encoding="utf-8"))
    actors = data["actors"]
    docs = [actor_document(a) for a in actors]
    empty = sum(1 for d in docs if not d)
    if empty:
        print(f"[warn] {empty} actors have empty documents")

    vectorizer = TfidfVectorizer(
        stop_words="english", ngram_range=(1, 2), sublinear_tf=True,
        min_df=1, max_features=80_000,
    )
    X = vectorizer.fit_transform(docs)
    bundle = {
        "vectorizer": vectorizer,
        "doc_matrix": X,
        "actor_ids": [str(a["id"]) for a in actors],
        "meta": {
            "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "n_actors": len(actors),
            "n_features": X.shape[1],
            "corpus": "data/threat_actors.json",
            "refreshed": data.get("refreshed", ""),
        },
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, out_path)
    print(f"[attribution] {len(actors)} actors -> {X.shape[1]} tf-idf features")
    print(f"[attribution] wrote {out_path} ({out_path.stat().st_size/1e3:.0f} KB)")

    # smoke retrieval: known queries should surface well-known actors
    from sklearn.metrics.pairwise import cosine_similarity
    probes = {
        "russian state espionage spearphishing intelligence": "APT28",
        "cozy bear svr diplomatic": "APT29",
        "north korea financial theft swift": None,
        "ransomware double extortion": None,
    }
    for q, expect in probes.items():
        qv = vectorizer.transform([q])
        sims = cosine_similarity(qv, X)[0]
        order = sims.argsort()[::-1][:3]
        top = [(actors[i]["name"], round(float(sims[i]), 3)) for i in order]
        flag = "" if expect is None else ("  OK" if any(n == expect for n, _ in top)
                                          else f"  MISS (wanted {expect})")
        print(f"  probe {q!r} -> {top}{flag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
