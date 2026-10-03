"""Network helpers: DNS-over-HTTPS fallback + resilient HTTP GET.

Some managed networks lose their local resolver.  ``ensure_doh()`` patches
``socket.getaddrinfo`` with a Cloudflare DoH (queried by IP) fallback so feed
polling keeps working when the system DNS is broken.
"""

from __future__ import annotations

import json
import socket
import ssl
import time
import urllib.request

_DOH_URL = "https://1.1.1.1/dns-query?name={name}&type={type}"
_CTX = ssl.create_default_context()
_doh_installed = False


def _doh_resolve(name: str, family: int) -> list[str]:
    qtype = "AAAA" if family == socket.AF_INET6 else "A"
    req = urllib.request.Request(
        _DOH_URL.format(name=name, type=qtype), headers={"Accept": "application/dns-json"}
    )
    with urllib.request.urlopen(req, timeout=10, context=_CTX) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    return [a["data"] for a in payload.get("Answer", []) if a.get("type") in (1, 28)]


def ensure_doh() -> None:
    """Fall back to DNS-over-HTTPS whenever native resolution raises gaierror."""
    global _doh_installed
    if _doh_installed:
        return
    original = socket.getaddrinfo

    def getaddrinfo(host, port, *args, **kwargs):
        try:
            return original(host, port, *args, **kwargs)
        except socket.gaierror:
            if not isinstance(host, str) or _is_ip(host):
                raise
            family = args[0] if args else kwargs.get("family", socket.AF_UNSPEC)
            want6 = family == socket.AF_INET6
            addresses = _doh_resolve(host, socket.AF_INET6 if want6 else socket.AF_INET)
            if not addresses:
                raise
            resolved_family = socket.AF_INET6 if want6 else socket.AF_INET
            results = []
            for addr in addresses:
                results.extend(original(resolved_family, socket.SOCK_STREAM, 0, addr, port))
                results.extend(original(resolved_family, socket.SOCK_DGRAM, 0, addr, port))
            return results

    socket.getaddrinfo = getaddrinfo
    _doh_installed = True


def _is_ip(value: str) -> bool:
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, value)
            return True
        except OSError:
            continue
    return False


def http_get(url: str, timeout: int = 30, headers: dict | None = None,
             retries: int = 3, accept: str | None = None) -> bytes:
    """GET ``url`` returning raw bytes; retries on transient failures."""
    ensure_doh()
    import requests  # imported lazily so the module works without requests

    hdrs = {"User-Agent": "apt-cti-thesis/0.1 (+research poller)"}
    if accept:
        hdrs["Accept"] = accept
    if headers:
        hdrs.update(headers)
    last: Exception | None = None
    for attempt in range(retries):
        try:
            resp = requests.get(url, timeout=timeout, headers=hdrs)
            if resp.status_code == 200:
                return resp.content
            last = RuntimeError(f"HTTP {resp.status_code} for {url}")
            if resp.status_code in (404, 401, 403):
                raise last
        except requests.RequestException as exc:  # network layer
            last = exc
        time.sleep(1.5 * (attempt + 1))
    raise last if last else RuntimeError(f"GET failed: {url}")


def epoch(text: str, fmts: tuple[str, ...] = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
                                              "%Y-%m-%d %H:%M", "%Y-%m-%d")) -> float | None:
    """Parse a timestamp string into epoch seconds (UTC); None when unparseable."""
    from datetime import datetime, timezone

    text = (text or "").strip()
    if not text:
        return None
    text = text.replace(" UTC", "").replace("Z", "").strip()
    for fmt in fmts:
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None
