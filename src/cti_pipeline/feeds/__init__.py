"""Feed registry: name -> poller module."""

from __future__ import annotations

from . import feodo, misp, otx, plainlist, threatfox, urlhaus

POLLERS = {
    "urlhaus": lambda cfg: urlhaus.poll(cfg.request_timeout_s),
    "threatfox": lambda cfg: threatfox.poll(cfg.request_timeout_s),
    "feodo": lambda cfg: feodo.poll(cfg.request_timeout_s),
    "otx": lambda cfg: otx.poll(cfg.otx_api_key, cfg.request_timeout_s),
    "misp": lambda cfg: misp.poll(cfg.misp_url, cfg.misp_key, cfg.request_timeout_s),
}


def _plain(name: str):
    return lambda cfg: plainlist.poll_one(name, cfg.request_timeout_s)


POLLERS.update({name: _plain(name) for name in plainlist.SOURCES})

__all__ = ["POLLERS", "urlhaus", "threatfox", "feodo", "otx", "misp", "plainlist"]
