"""Live mode - keep CTI feeds polling, the dashboard rebuilding, and serve it.

    python serve.py                  # http://127.0.0.1:8747 - poll every 5 min
    python serve.py --no-poll        # serve only (browser still auto-reloads)
    python serve.py --full           # also rerun the whole pipeline hourly
    python serve.py --port 9000 --interval 60

The page shows a live badge and reloads itself whenever dashboard/index.html
changes (feed poll -> rebuild -> reload).  Ctrl+C stops the server.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parent
DASHBOARD = ROOT / "dashboard" / "index.html"
TABLES = ROOT / "results" / "tables"
SNAPSHOT = ROOT / "data" / "feed_snapshots" / "last_poll.json"

STATE: dict = {"busy": False, "last_error": None, "next_poll_in": None}
ARGS: argparse.Namespace

LIVE_SNIPPET = b"""
<script>
(function(){
  if (window.__liveAttached) return; window.__liveAttached = true;
  var el = document.createElement('div');
  el.style.cssText = 'position:fixed;right:16px;bottom:16px;z-index:999;'
    + 'font:600 11.5px/1.4 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;'
    + 'padding:9px 15px;border-radius:999px;letter-spacing:.02em;'
    + 'background:rgba(18,18,22,.85);color:#f2f2f7;'
    + 'backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);'
    + 'border:1px solid rgba(255,255,255,.14);box-shadow:0 8px 28px rgba(0,0,0,.35);'
    + 'opacity:0;transition:opacity .4s ease;pointer-events:none';
  document.body.appendChild(el);
  requestAnimationFrame(function(){ el.style.opacity = '1'; });
  function fmt(s){
    if (s == null) return '-';
    if (s < 60) return Math.max(0, Math.round(s)) + 's';
    return Math.round(s / 60) + 'm';
  }
  function render(s){
    var ind = (s.indicators != null) ? s.indicators.toLocaleString('en-US') + ' IoCs' : 'no store';
    var mode;
    if (!s.poll_enabled)      mode = 'static';
    else if (s.busy)          mode = s.busy_label || 'working\\u2026';
    else if (s.last_error)    mode = 'last cycle failed';
    else                      mode = 'next poll in ' + fmt(s.next_poll_in);
    var dot = s.last_error ? '\\u25CF' : '\\u25CF';
    var color = s.last_error ? '#ff6961' : '#32d74b';
    el.innerHTML = '<span style="color:' + color + ';margin-right:6px">' + dot + '</span>'
      + '<b>live</b> &middot; ' + ind + ' &middot; polled ' + s.polled + ' &middot; ' + mode;
    if (window.__gen !== undefined && window.__gen !== null && window.__gen !== s.gen) {
      location.reload(); return;
    }
    window.__gen = s.gen;
  }
  function tick(){
    fetch('/__status', {cache:'no-store'}).then(function(r){ return r.json(); })
      .then(render).catch(function(){
        el.innerHTML = '<span style="color:#ff6961;margin-right:6px">&#9679;</span><b>offline</b> &middot; server unreachable';
        el.style.opacity = '1';
      });
  }
  tick(); setInterval(tick, 10000);
})();
</script>
"""


def _log(msg: str) -> None:
    print(f"[serve {datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def status_payload() -> dict:
    gen = str(int(DASHBOARD.stat().st_mtime)) if DASHBOARD.exists() else "missing"
    indicators = None
    feed = TABLES / "feed_poll.json"
    if feed.exists():
        try:
            indicators = json.loads(feed.read_text(encoding="utf-8"))["store_stats"]["total"]
        except Exception:  # noqa: BLE001
            pass
    polled = datetime.fromtimestamp(SNAPSHOT.stat().st_mtime).strftime("%H:%M") \
        if SNAPSHOT.exists() else "never"
    return {
        "gen": gen,
        "indicators": indicators,
        "polled": polled,
        "poll_enabled": not ARGS.no_poll,
        "interval_s": ARGS.interval,
        "busy": STATE["busy"],
        "busy_label": STATE.get("busy_label"),
        "last_error": STATE["last_error"],
        "next_poll_in": STATE["next_poll_in"],
        "time": time.time(),
    }


class ExclusiveServer(ThreadingHTTPServer):
    allow_reuse_address = False     # a second instance must fail fast, not double-serve
    daemon_threads = True


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # noqa: A002 - quiet access log
        pass

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self) -> None:  # noqa: N802
        path = unquote(urlsplit(self.path).path)
        if path in ("/", "/index.html"):
            if not DASHBOARD.exists():
                self._send(503, b"dashboard not built yet - run scripts/build_dashboard.py",
                           "text/plain; charset=utf-8")
                return
            html = DASHBOARD.read_bytes()
            if b"</body>" in html:
                html = html.replace(b"</body>", LIVE_SNIPPET + b"</body>", 1)
            else:
                html += LIVE_SNIPPET
            self._send(200, html, "text/html; charset=utf-8")
            return
        if path == "/__status":
            self._send(200, json.dumps(status_payload()).encode("utf-8"),
                       "application/json")
            return

        target = (ROOT / path.lstrip("/")).resolve()
        if not target.is_relative_to(ROOT) or not target.is_file():
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
        ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        self._send(200, target.read_bytes(), ctype)


def run_step(title: str, argv: list[str], timeout: int | None = None) -> bool:
    _log(f"{title} ...")
    STATE["busy"] = True
    STATE["busy_label"] = title
    t0 = time.time()
    try:
        proc = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        STATE["last_error"] = f"{title} timed out"
        _log(f"{title} TIMED OUT after {timeout}s")
        return False
    finally:
        STATE["busy"] = False
        STATE["busy_label"] = None
    ok = proc.returncode == 0
    tail = [ln for ln in (proc.stdout or "").strip().splitlines() if ln.strip()][-3:]
    for ln in tail:
        print(f"    {ln}", flush=True)
    if not ok:
        err = [ln for ln in (proc.stderr or "").strip().splitlines() if ln.strip()]
        STATE["last_error"] = (err[-1] if err else f"{title} exited {proc.returncode}")[:200]
        _log(f"{title} FAILED ({proc.returncode}): {STATE['last_error']}")
    else:
        STATE["last_error"] = None
        _log(f"{title} ok in {time.time() - t0:.0f}s")
    return ok


def available_datasets() -> list[str]:
    try:
        raw = subprocess.check_output([sys.executable, "scripts/env_check.py"],
                                      cwd=ROOT, encoding="utf-8")
        ds = json.loads(raw)["datasets"]
        return [k for k, v in ds.items() if v]
    except Exception:  # noqa: BLE001
        return ["unsw_nb15", "cicids2017"]


def serve_forever(server: ThreadingHTTPServer) -> None:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()


def main() -> None:
    global ARGS
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")   # never crash on cp1252 consoles
        except Exception:  # noqa: BLE001
            pass
    parser = argparse.ArgumentParser(description="live mode for the thesis dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8747)
    parser.add_argument("--interval", type=int, default=300,
                        help="seconds between feed polls (default 300)")
    parser.add_argument("--no-poll", action="store_true",
                        help="serve only; never poll or rebuild")
    parser.add_argument("--full", action="store_true",
                        help="also rerun the whole pipeline periodically")
    parser.add_argument("--full-every", type=int, default=3600,
                        help="seconds between full pipeline runs (default 3600)")
    parser.add_argument("--no-browser", action="store_true")
    ARGS = parser.parse_args()

    try:
        server = ExclusiveServer((ARGS.host, ARGS.port), Handler)
    except OSError as exc:
        print(f"ERROR: cannot bind {ARGS.host}:{ARGS.port} - {exc}", file=sys.stderr)
        sys.exit(2)
    serve_forever(server)
    url = f"http://{ARGS.host}:{ARGS.port}/"
    _log(f"serving {url}")
    if not ARGS.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    next_poll = time.time()          # first cycle runs immediately
    next_full = time.time() + ARGS.full_every if ARGS.full else None

    try:
        while True:
            now = time.time()
            if not ARGS.no_poll:
                STATE["next_poll_in"] = max(0, next_poll - now)

            if not ARGS.no_poll and now >= next_poll and not STATE["busy"]:
                if run_step("poll feeds", [sys.executable, "scripts/run_collect_feeds.py"],
                            timeout=600):
                    run_step("rebuild dashboard", [sys.executable, "scripts/build_dashboard.py"],
                             timeout=300)
                next_poll = time.time() + ARGS.interval

            if next_full is not None and now >= next_full and not STATE["busy"]:
                ds = available_datasets()
                if ds:
                    run_step("full pipeline",
                             ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                              "-File", str(ROOT / "run_all.ps1"), "-Datasets", *ds],
                             timeout=None)
                next_full = time.time() + ARGS.full_every

            time.sleep(0.5)
    except KeyboardInterrupt:
        _log("stopping ...")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
