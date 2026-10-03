"""DNS-over-HTTPS fallback resolver.

The local resolver on this machine intermittently returns NXDOMAIN/timeouts.
Installing this patch makes socket.getaddrinfo() fall back to Cloudflare DoH
(queried by IP, so no system DNS is required) whenever native resolution fails.

Usage:
    import doh_patch; doh_patch.install()
"""

from __future__ import annotations

import json
import socket
import ssl
import urllib.request

DOH_URL = "https://1.1.1.1/dns-query?name={name}&type={type}"
_CTX = ssl.create_default_context()
_installed = False


def resolve(name: str, family: int = socket.AF_INET) -> list[str]:
    """Resolve a hostname through DoH; returns a list of IP strings."""
    qtype = "AAAA" if family == socket.AF_INET6 else "A"
    req = urllib.request.Request(
        DOH_URL.format(name=name, type=qtype),
        headers={"Accept": "application/dns-json"},
    )
    with urllib.request.urlopen(req, timeout=10, context=_CTX) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    return [a["data"] for a in payload.get("Answer", []) if a.get("type") in (1, 28)]


def install() -> None:
    global _installed
    if _installed:
        return
    original = socket.getaddrinfo

    def getaddrinfo(host, port, *args, **kwargs):
        try:
            return original(host, port, *args, **kwargs)
        except socket.gaierror:
            if not isinstance(host, str) or _looks_like_ip(host):
                raise
            family = args[0] if args else kwargs.get("family", socket.AF_UNSPEC)
            if family in (socket.AF_UNSPEC, socket.AF_INET):
                addresses = resolve(host, socket.AF_INET)
                resolved_family = socket.AF_INET
            else:
                addresses = resolve(host, socket.AF_INET6)
                resolved_family = socket.AF_INET6
            if not addresses:
                raise
            results = []
            for addr in addresses:
                results.extend(original(resolved_family, socket.SOCK_STREAM, 0, addr, port))
                results.extend(original(resolved_family, socket.SOCK_DGRAM, 0, addr, port))
            return results

    socket.getaddrinfo = getaddrinfo
    _installed = True


def _looks_like_ip(value: str) -> bool:
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, value)
            return True
        except OSError:
            continue
    return False


install()
