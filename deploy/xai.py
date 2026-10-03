"""Optional NVIDIA NIM layer: turns an alert's SHAP reasons into an analyst brief.

OpenAI-compatible chat completions against https://integrate.api.nvidia.com/v1.
Enabled only when a key is configured (env ``NVIDIA_API_KEY``/``NIM_API_KEY``
or ``xai.api_key`` in the service config). Flow metadata + reason codes are
sent to the API — see deploy/README.md privacy note before enabling.
"""
from __future__ import annotations

import json
import os
import threading

SYSTEM_PROMPT = (
    "You are a senior SOC analyst writing a brief for a teammate. You receive "
    "one scored network flow: its fields, an ML score with SHAP reason codes, "
    "and any threat-intel (IoC) context. Write in plain English, no markdown "
    "headings, exactly three short paragraphs:\n"
    "1) What the traffic shows (2-3 sentences, concrete numbers).\n"
    "2) Why the model flagged it, grounded ONLY in the given reason codes, and "
    "what ATT&CK tactic/technique that pattern suggests.\n"
    "3) Triage advice: what to check next, plus one honest caveat that this is "
    "an ML score on a single flow, not proof of compromise.\n"
    "Under 160 words. Do not invent facts that are not in the input."
)


class ExplainerError(RuntimeError):
    pass


class NvidiaExplainer:
    def __init__(self, cfg: dict | None):
        cfg = cfg or {}
        self.base_url = (cfg.get("base_url")
                         or "https://integrate.api.nvidia.com/v1").rstrip("/")
        self.model = cfg.get("model") or "openai/gpt-oss-20b"
        self.api_key = (cfg.get("api_key")
                        or os.environ.get("NVIDIA_API_KEY")
                        or os.environ.get("NIM_API_KEY") or "").strip()
        self.timeout_s = float(cfg.get("timeout_s", 45.0))
        # reasoning models (gpt-oss, etc.) can burn the whole token budget on
        # thinking; "low" keeps latency and cost down for a short brief.
        self.reasoning_effort = str(cfg.get("reasoning_effort") or "").strip()
        self.cache_max = int(cfg.get("cache_max", 500))
        self._cache: dict[str, str] = {}
        self._lock = threading.Lock()
        self.calls = 0
        self.errors = 0

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def _payload(self, alert: dict) -> str:
        compact = {
            "flow": alert.get("flow"),
            "score": alert.get("score"),
            "theta": alert.get("model", {}).get("theta"),
            "cti": alert.get("cti"),
            "reasons": [
                {"feature": r.get("feature"), "value": r.get("value"),
                 "shap": r.get("shap"), "why": r.get("reason"),
                 "tactic": r.get("tactic"), "technique": r.get("technique")}
                for r in alert.get("reasons", [])
            ],
        }
        return ("Alert JSON:\n" + json.dumps(compact, ensure_ascii=False))

    def explain(self, alert_id: str, alert: dict) -> str:
        """Return the brief for this alert (cached per alert_id)."""
        with self._lock:
            if alert_id in self._cache:
                return self._cache[alert_id]
        text = self._call(self._payload(alert))
        with self._lock:
            self._cache[alert_id] = text
            while len(self._cache) > self.cache_max:
                self._cache.pop(next(iter(self._cache)))
        return text

    def _call(self, user_msg: str) -> str:
        try:
            import requests
        except ImportError as exc:                            # pragma: no cover
            raise ExplainerError("requests not installed") from exc
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                         {"role": "user", "content": user_msg}],
            "max_tokens": 1000,          # reasoning models burn budget first
            "temperature": 0.3,
        }
        if self.reasoning_effort:
            body["reasoning_effort"] = self.reasoning_effort
        headers = {"Authorization": f"Bearer {self.api_key}",
                   "Content-Type": "application/json"}
        url = f"{self.base_url}/chat/completions"
        last = ""
        for attempt in range(2):
            try:
                self.calls += 1
                r = requests.post(url, json=body, headers=headers,
                                  timeout=self.timeout_s)
                if r.status_code == 200:
                    data = r.json()
                    choices = data.get("choices") or [{}]
                    msg = choices[0].get("message") or {}
                    text = (msg.get("content") or "").strip()
                    if text:
                        return text
                    # reasoning model spent the whole budget on reasoning
                    last = (f"empty completion "
                            f"(finish_reason={choices[0].get('finish_reason')})")
                elif r.status_code in (429, 500, 502, 503, 504) and attempt == 0:
                    last = f"HTTP {r.status_code}"
                    continue
                else:
                    snippet = (r.text or "")[:160]
                    raise ExplainerError(f"AI API HTTP {r.status_code}: {snippet}")
            except ExplainerError:
                raise
            except Exception as exc:                          # noqa: BLE001
                last = f"{type(exc).__name__}: {exc}"
                if attempt:
                    break
        self.errors += 1
        raise ExplainerError(f"AI API failed: {last}")
