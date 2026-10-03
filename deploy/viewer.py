"""Read-only web view for the scoring service: index page + alert-tail API."""
from __future__ import annotations

import json
from pathlib import Path

TAIL_BYTES = 1 << 20  # read the last 1 MiB of the alert log


def _read_tail(path: Path) -> list[dict]:
    """Newest-first alerts from the tail of one JSONL file."""
    with path.open("rb") as fh:
        fh.seek(0, 2)
        size = fh.tell()
        fh.seek(max(0, size - TAIL_BYTES))
        raw = fh.read()
    lines = raw.split(b"\n")
    if size > TAIL_BYTES and lines:
        lines = lines[1:]  # first line may be a partial record
    out: list[dict] = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except (json.JSONDecodeError, ValueError):
            continue
    return out


def tail_alerts(path: Path | None, limit: int = 100) -> list[dict]:
    if path is None:
        return []
    out = _read_tail(path) if path.exists() else []
    if len(out) < limit:
        # rotation archives: prepend newer archives until the limit is met
        seen = {str(a.get("alert_id", i)) for i, a in enumerate(out)}
        archives = sorted(
            path.parent.glob(f"{path.stem}-*{path.suffix}"),
            key=lambda p: p.name, reverse=True)
        for arc in archives:
            if len(out) >= limit:
                break
            if not arc.exists() or arc.stat().st_size == 0:
                continue
            for a in _read_tail(arc):          # newest-first
                aid = str(a.get("alert_id", ""))
                if aid and aid in seen:
                    continue
                if aid:
                    seen.add(aid)
                out.append(a)
                if len(out) >= limit:
                    break
    if len(out) > limit:
        out = out[:limit]
    out.reverse()
    if out:
        # alert ids are unique per session; keep only the newest occurrence
        last: dict = {}
        for i, a in enumerate(out):
            last[str(a.get("alert_id", i))] = i
        out = [a for i, a in enumerate(out)
               if last[str(a.get("alert_id", i))] == i]
    return out


INDEX_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<meta name="app-build" content="__BUILD__">
<title>APT-CTI · Live Alerts</title>
<style>
:root{
  --bg:#070709; --panel:rgba(255,255,255,.05); --panel-2:rgba(255,255,255,.075);
  --line:rgba(255,255,255,.09); --line-soft:rgba(255,255,255,.06);
  --fg:#f2f2f7; --dim:#98989f; --dimmer:#63636a;
  --blue:#0a84ff; --red:#ff453a; --orange:#ff9f0a; --green:#30d158;
  --cyan:#64d2ff; --amber:#ffd60a;
  --r-xl:22px; --r-lg:16px; --r-md:12px; --r-sm:9px;
  --sans:-apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI Variable Display",
        "Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --display:-apple-system,BlinkMacSystemFont,"SF Pro Display","Segoe UI Variable Display",
        "Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --ease:cubic-bezier(.25,.1,.25,1);
  --shadow-panel:inset 0 1px 0 rgba(255,255,255,.07), inset 0 0 0 1px rgba(255,255,255,.022),
    0 30px 64px -34px rgba(0,0,0,.95), 0 4px 14px -8px rgba(0,0,0,.6);
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{
  min-height:100vh; color:var(--fg); background:var(--bg);
  font:14px/1.5 var(--sans);
  -webkit-font-smoothing:antialiased; text-rendering:optimizeLegibility;
  background-image:
    radial-gradient(1200px 560px at 50% -10%, rgba(10,132,255,.16), transparent 60%),
    radial-gradient(900px 460px at 94% 6%, rgba(100,210,255,.07), transparent 58%),
    radial-gradient(820px 520px at 4% 96%, rgba(94,60,255,.08), transparent 62%),
    url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='180' height='180'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.85' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='180' height='180' filter='url(%23n)' opacity='.055'/%3E%3C/svg%3E");
  background-attachment:fixed;
}
::selection{background:rgba(10,132,255,.38)}

/* refined scrollbars */
::-webkit-scrollbar{width:11px; height:11px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(255,255,255,.15); border-radius:999px;
  border:3px solid transparent; background-clip:content-box}
::-webkit-scrollbar-thumb:hover{background-color:rgba(255,255,255,.28)}
::-webkit-scrollbar-corner{background:transparent}

/* ─── unlock overlay ───────────────────────────────────── */
#unlock{position:fixed; inset:0; z-index:90; display:grid; place-items:center;
  background:rgba(6,6,8,.84); backdrop-filter:blur(20px) saturate(160%);
  -webkit-backdrop-filter:blur(20px) saturate(160%);}
#unlock[hidden]{display:none}
.unlock-card{width:min(352px,92vw); padding:30px 26px 26px; border-radius:24px;
  background:linear-gradient(180deg,rgba(30,30,33,.97),rgba(16,16,18,.98));
  border:1px solid rgba(255,255,255,.14);
  box-shadow:0 1px 0 rgba(255,255,255,.1) inset, 0 36px 84px -24px rgba(0,0,0,.9);
  backdrop-filter:blur(30px) saturate(185%);
  text-align:center; animation:sheet .32s var(--ease)}
.unlock-card h3{margin:14px 0 5px; font-family:var(--display); font-size:19px;
  font-weight:750; letter-spacing:-.5px}
.unlock-card p{margin:0 0 18px; color:var(--dim); font-size:12.5px}
.unlock-card input{width:100%; padding:11px 13px; border-radius:11px;
  border:1px solid rgba(255,255,255,.12); background:rgba(255,255,255,.07);
  color:var(--fg); box-shadow:inset 0 1.5px 3px rgba(0,0,0,.4);
  font:13.5px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; outline:none;
  transition:border-color .18s var(--ease), box-shadow .18s var(--ease)}
.unlock-card input:focus{border-color:rgba(10,132,255,.7);
  box-shadow:0 0 0 3.5px rgba(10,132,255,.28), inset 0 1.5px 3px rgba(0,0,0,.4)}
.unlock-card button{width:100%; margin-top:12px; padding:11px; border:1px solid rgba(255,255,255,.18);
  border-radius:999px;
  background:linear-gradient(180deg,#2e9bff,#0070e0); color:#fff; font-size:13.5px;
  font-weight:650; cursor:pointer;
  box-shadow:0 10px 26px -10px rgba(10,132,255,.8), inset 0 1px 0 rgba(255,255,255,.32);
  transition:filter .15s var(--ease), transform .12s var(--ease)}
.unlock-card button:hover{filter:brightness(1.12)}
.unlock-card button:active{transform:scale(.98)}
#unlock-err{margin-top:11px; color:#ff6961; font-size:12.5px; min-height:1em}
#unlock-err[hidden]{display:none}
#stale-bar{position:fixed; top:14px; left:50%; transform:translateX(-50%); z-index:95;
  display:flex; align-items:center; gap:10px; padding:8px 16px; border-radius:999px;
  background:rgba(255,159,10,.16); border:1px solid rgba(255,159,10,.55); color:#ffd60a;
  font-size:11.5px; font-weight:800; letter-spacing:.5px;
  box-shadow:0 14px 34px -14px rgba(255,159,10,.7); backdrop-filter:blur(20px)}
#stale-bar[hidden]{display:none}
#stale-bar button{font:inherit; cursor:pointer; padding:3px 12px; border-radius:999px;
  color:#070709; background:#ffd60a; border:1px solid rgba(255,255,255,.4)}

/* ─── top bar ─────────────────────────────────────────── */
.topbar{
  position:sticky; top:0; z-index:40; display:flex; align-items:center; gap:15px;
  padding:13px 28px; border-bottom:1px solid var(--line);
  background:rgba(8,8,10,.74); backdrop-filter:blur(26px) saturate(185%);
  -webkit-backdrop-filter:blur(26px) saturate(185%);
  box-shadow:0 18px 44px -34px rgba(0,0,0,.95);
}
.topbar::after{content:''; position:absolute; left:0; right:0; bottom:-1px; height:1px;
  background:linear-gradient(90deg, transparent 4%, rgba(10,132,255,.38) 38%,
    rgba(100,210,255,.22) 58%, transparent 96%); pointer-events:none}
.brand{display:flex; align-items:center; gap:12px; min-width:0}
.mark{
  width:33px;height:33px;border-radius:10px;display:grid;place-items:center;flex:none;
  background:linear-gradient(145deg,rgba(10,132,255,.42),rgba(100,210,255,.16));
  border:1px solid rgba(100,210,255,.38);
  box-shadow:0 6px 18px -4px rgba(10,132,255,.45), inset 0 1px 0 rgba(255,255,255,.22);
}
.title{display:flex; align-items:baseline; gap:10px; white-space:nowrap; min-width:0}
.title b{font-family:var(--display); font-size:16.5px; font-weight:750;
  letter-spacing:-.45px; color:#fff}
.title span{font-size:15.5px; font-weight:400; color:var(--dim); letter-spacing:-.3px}
.live{
  display:flex;align-items:center;gap:7px;padding:4px 12px;border-radius:999px;
  background:rgba(48,209,88,.11); border:1px solid rgba(48,209,88,.32);
  font-size:10.5px; font-weight:750; letter-spacing:1.2px; color:#3ddc6f; flex:none;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.07), 0 4px 14px -6px rgba(48,209,88,.35);
}
.live.off{background:rgba(255,69,58,.11); border-color:rgba(255,69,58,.34); color:#ff6961;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.07), 0 4px 14px -6px rgba(255,69,58,.4)}
.dot{width:7px;height:7px;border-radius:50%;background:var(--green);
  box-shadow:0 0 0 0 rgba(48,209,88,.5); animation:pulse 2.4s infinite}
.live.off .dot{background:var(--red); animation:none}
@keyframes pulse{
  0%{box-shadow:0 0 0 0 rgba(48,209,88,.45)}
  70%{box-shadow:0 0 0 7px rgba(48,209,88,0)}
  100%{box-shadow:0 0 0 0 rgba(48,209,88,0)}
}
.spacer{flex:1}
.search{
  width:250px; max-width:34vw; padding:8px 15px; border-radius:999px; outline:none;
  background:rgba(255,255,255,.065); border:1px solid rgba(255,255,255,.08);
  color:var(--fg); font:inherit; font-size:13px;
  box-shadow:inset 0 1px 2.5px rgba(0,0,0,.32);
  transition:border-color .18s var(--ease), box-shadow .18s var(--ease),
  background .18s var(--ease);
}
.search::placeholder{color:var(--dimmer)}
.search:hover{background:rgba(255,255,255,.085)}
.search:focus{border-color:rgba(10,132,255,.9); background:rgba(255,255,255,.09);
  box-shadow:0 0 0 3.5px rgba(10,132,255,.3), inset 0 1px 2.5px rgba(0,0,0,.3)}
.seg{display:flex; gap:2px; padding:3px; border-radius:999px; flex:none;
  background:rgba(255,255,255,.07); border:1px solid rgba(255,255,255,.08);
  box-shadow:inset 0 1.5px 3px rgba(0,0,0,.35)}
.seg button{
  border:0; background:transparent; color:var(--dim); cursor:pointer;
  font:650 12.5px/1 var(--sans); padding:6.5px 15px; border-radius:999px;
  transition:background .18s var(--ease), color .18s var(--ease),
             box-shadow .18s var(--ease);
}
.seg button:hover{color:var(--fg)}
.seg button.on{background:rgba(255,255,255,.95); color:#0b0b0e;
  box-shadow:0 1.5px 5px rgba(0,0,0,.45)}

/* ─── layout ──────────────────────────────────────────── */
main{max-width:1280px; margin:0 auto; padding:30px 24px 80px}
.stats{display:grid; gap:14px; grid-template-columns:repeat(auto-fit,minmax(152px,1fr))}
.overview{margin-bottom:26px}
.ov-head{display:flex; align-items:baseline; gap:12px; margin-bottom:14px}
.ov-head h2{margin:0; font-family:var(--display); font-size:16.5px; font-weight:750;
  letter-spacing:-.4px}
.ov-sub{font-size:12px; color:var(--dimmer)}
.stats-hero{grid-template-columns:repeat(auto-fit,minmax(230px,1fr))}
.stats-meta{grid-template-columns:repeat(auto-fit,minmax(152px,1fr)); margin-top:14px}
@media (min-width:1040px){
  .stats-hero{grid-template-columns:repeat(4,1fr)}
  .stats-meta{grid-template-columns:repeat(5,1fr)}
}
.stat{
  position:relative; overflow:hidden;
  background:linear-gradient(180deg,rgba(255,255,255,.062),rgba(255,255,255,.028));
  border:1px solid var(--line);
  border-radius:var(--r-lg); padding:15px 17px 14px; backdrop-filter:blur(12px);
  box-shadow:inset 0 1px 0 rgba(255,255,255,.07),
    0 18px 38px -26px rgba(0,0,0,.9), 0 2px 8px -5px rgba(0,0,0,.5);
  transition:border-color .2s var(--ease), transform .2s var(--ease),
             box-shadow .2s var(--ease);
}
.stat::before{content:''; position:absolute; top:0; left:16px; right:16px; height:1px;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,.16),transparent);
  pointer-events:none}
.stat:hover{border-color:rgba(255,255,255,.17); transform:translateY(-1px)}
.stat .k{font-size:10px; font-weight:700; letter-spacing:1.05px; text-transform:uppercase;
  color:var(--dim); font-family:var(--display)}
.stat .v{margin-top:7px; font-family:var(--display); font-size:26px; font-weight:750;
  letter-spacing:-.7px; color:#fff; line-height:1.1;
  font-variant-numeric:tabular-nums; transition:color .2s var(--ease)}
.stat .c{margin-top:3px; font-size:11.5px; color:var(--dimmer)}
.stat .v.blue{color:var(--cyan)} .stat .v.orange{color:var(--orange)}
.stat .v.green{color:#3ddc6f} .stat .v.red{color:#ff6961}
.stat .v.amber{color:var(--amber)}
.stat.hero{padding:18px 20px 17px}
.stat.hero .k{font-size:11px; letter-spacing:1.2px}
.stat.hero .v{margin-top:9px; font-size:38px; letter-spacing:-1.4px;
  text-shadow:0 0 30px rgba(10,132,255,.30)}
.stat.hero .v.orange{text-shadow:0 0 30px rgba(255,159,10,.40)}
.stat.hero .v.amber{text-shadow:0 0 30px rgba(255,185,54,.40)}
.stat.hero .v.red{text-shadow:0 0 30px rgba(255,105,97,.42)}
.stat.hero .c{margin-top:6px; font-size:12px; color:var(--dim)}
.stats-meta .v{font-size:21px; letter-spacing:-.4px}
.stats-meta .v.sm{font-size:16.5px; padding-top:4px; letter-spacing:-.2px}
.stat.click{cursor:pointer; user-select:none}
.stat.click:hover{border-color:rgba(10,132,255,.5); transform:translateY(-3px);
  box-shadow:inset 0 1px 0 rgba(255,255,255,.08),
    0 22px 44px -24px rgba(10,132,255,.55), 0 2px 8px -5px rgba(0,0,0,.5)}
.stat.click:active{transform:translateY(-1px) scale(.985)}
.stat.click::after{
  content:'›'; position:absolute; top:12px; right:15px; font-size:16px;
  color:var(--dimmer); transition:color .18s var(--ease), transform .18s var(--ease);
}
.stat.click:hover::after{color:var(--blue); transform:translateX(2px)}
.live[data-f]{cursor:pointer; user-select:none;
  transition:transform .15s var(--ease), filter .15s var(--ease),
             border-color .15s var(--ease)}
.live[data-f]:hover{transform:translateY(-1px); filter:brightness(1.18);
  border-color:rgba(255,255,255,.3)}
.live[data-f]:active{transform:scale(.97)}

.panel{position:relative; overflow:hidden;
  background:linear-gradient(180deg,rgba(255,255,255,.056),rgba(255,255,255,.024));
  border:1px solid var(--line);
  border-radius:18px; box-shadow:var(--shadow-panel);
  transition:border-color .22s var(--ease), transform .22s var(--ease)}
.panel::before{content:''; position:absolute; top:0; left:22px; right:22px; height:1px;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,.15),transparent);
  pointer-events:none; z-index:1}
.panel:hover{border-color:rgba(255,255,255,.14)}
.panel-head{display:flex; align-items:center; gap:12px; padding:18px 22px 16px;
  border-bottom:1px solid var(--line-soft); flex-wrap:wrap}
.panel-head h2{margin:0; font-family:var(--display); font-size:16.5px; font-weight:750;
  letter-spacing:-.45px; color:#fff}
.count{font-size:11.5px; font-weight:650; color:var(--dim);
  background:linear-gradient(180deg,rgba(255,255,255,.09),rgba(255,255,255,.05));
  border:1px solid rgba(255,255,255,.1); padding:3.5px 11px; border-radius:999px;
  font-variant-numeric:tabular-nums; box-shadow:inset 0 1px 0 rgba(255,255,255,.08)}

/* ─── table ───────────────────────────────────────────── */
.tbl-wrap{overflow-x:auto}
table{width:100%; border-collapse:collapse}
thead th{
  position:sticky; top:0; z-index:2;
  font-size:10px; font-weight:700; letter-spacing:1.05px; text-transform:uppercase;
  color:var(--dim); text-align:left; padding:12px 18px 10px;
  border-bottom:1px solid var(--line); white-space:nowrap;
  background:rgba(13,13,15,.96); backdrop-filter:blur(10px);
  -webkit-backdrop-filter:blur(10px);
  box-shadow:0 1px 0 rgba(255,255,255,.05);
}
tbody td{padding:13px 18px; border-bottom:1px solid var(--line-soft); vertical-align:middle}
tr.row{cursor:pointer; transition:background .13s var(--ease)}
tr.row:hover td{background:rgba(255,255,255,.05)}
tr.row:hover td:first-child{box-shadow:inset 2.5px 0 0 var(--blue)}
tr.row.apt-notify td{background:rgba(255,69,58,.05)}
tr.row.apt-notify:hover td{background:rgba(255,69,58,.10)}
tr.row.open td,
tr.row.open.apt-notify td{background:rgba(10,132,255,.08)}
tr.row.open td:first-child{box-shadow:inset 2.5px 0 0 var(--blue)}
.mono{font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
  font-size:12.5px; letter-spacing:-.2px}

/* time: clock + relative age */
.t-time{white-space:nowrap}
.thms{display:block; font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
  font-size:12.5px; font-weight:650; color:var(--fg); letter-spacing:-.2px;
  font-variant-numeric:tabular-nums}
.trel{display:block; margin-top:3px; font-size:10.5px; color:var(--dimmer);
  font-variant-numeric:tabular-nums}

/* score: confidence-tiered pill + margin over θ */
.score-cell{white-space:nowrap}
.score{
  display:inline-block; min-width:58px; text-align:center; padding:3.5px 10px;
  border-radius:999px;
  font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
  font-size:12.5px; font-weight:800; font-variant-numeric:tabular-nums;
  color:#fff; background:linear-gradient(180deg,#ff6961,#e0362c);
  border:1px solid rgba(255,255,255,.16);
  box-shadow:0 3px 12px -4px rgba(255,69,58,.6), inset 0 1px 0 rgba(255,255,255,.28);
}
.score.s-warm{background:linear-gradient(180deg,#ff9f0a,#d97706);
  box-shadow:0 3px 12px -4px rgba(255,159,10,.55), inset 0 1px 0 rgba(255,255,255,.28)}
.score.s-mod{background:linear-gradient(180deg,rgba(255,255,255,.17),rgba(255,255,255,.09));
  color:#e9e9ee; border-color:rgba(255,255,255,.2);
  box-shadow:0 3px 12px -6px rgba(0,0,0,.65), inset 0 1px 0 rgba(255,255,255,.2)}
.smg{display:block; margin-top:4px; font-size:10.5px; font-weight:650; color:var(--dimmer);
  font-variant-numeric:tabular-nums; letter-spacing:.1px}

/* flow: src → dst over port + protocol */
.fcell{white-space:nowrap}
.fip{font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
  font-size:12.5px; letter-spacing:-.2px; color:var(--fg)}
.fip.dst{color:#fff; font-weight:700}
.farr{margin:0 7px; color:var(--dimmer)}
.fmeta{display:flex; align-items:center; gap:7px; margin-top:6px}
.fport{font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
  font-size:11px; color:var(--dim); background:rgba(255,255,255,.06);
  border:1px solid rgba(255,255,255,.10); padding:1.5px 7px; border-radius:6px}
.fmeta .proto{margin-left:0; vertical-align:0}
.proto{font-size:10px; font-weight:750; letter-spacing:.6px;
  color:var(--cyan); background:rgba(100,210,255,.10); border:1px solid rgba(100,210,255,.24);
  padding:2px 7.5px; border-radius:6px; text-transform:uppercase}

/* reason: primary line + hidden-reason count */
.reason-cell{max-width:440px}
.rtx{display:block; color:var(--fg); max-width:410px; overflow:hidden;
  text-overflow:ellipsis; white-space:nowrap}
.rsb{margin-top:3px; font-size:10.5px; color:var(--dimmer); letter-spacing:.15px}

/* ATT&CK: tactic chip + technique line */
.tsub{margin-top:5px; font-size:11px; color:var(--dimmer); max-width:235px; overflow:hidden;
  text-overflow:ellipsis; white-space:nowrap}
.tsub .tid{font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
  font-weight:750; color:#6eb4ff; margin-right:5px}

/* attribution: verdict chip + actor / category line */
.attd{white-space:nowrap}
.attd .apt-chip{margin-left:0}
.aline{margin-top:5px; font-size:11.5px; color:var(--dim); max-width:195px; overflow:hidden;
  text-overflow:ellipsis; white-space:nowrap}
.aline b{color:#fff; font-weight:650}
.aline .mid{color:var(--dimmer); font-variant-numeric:tabular-nums}
.ntag{display:inline-block; padding:1.5px 8px; border-radius:999px; vertical-align:1px;
  font:750 9.5px/1.6 var(--display); letter-spacing:.7px;
  color:var(--dim); background:rgba(255,255,255,.07); border:1px solid rgba(255,255,255,.16)}
.anone{color:var(--dimmer)}

.tactic{
  display:inline-block; font-size:11px; font-weight:650; color:#6eb4ff;
  background:rgba(10,132,255,.12); border:1px solid rgba(10,132,255,.26);
  padding:2.5px 10px; border-radius:999px; white-space:nowrap;
}
.ioc{color:var(--amber); font-size:13px; text-shadow:0 0 10px rgba(255,214,10,.45)}
.ioc-src{display:block; margin-top:3px; font-size:10px; color:var(--dimmer);
  letter-spacing:.2px; white-space:nowrap}
.no-ioc{color:var(--dimmer)}
.col-wide{display:none}
.rc-inline{display:inline-block; margin-left:9px; vertical-align:1px}
.apt-mini{display:inline-block; margin-left:8px; vertical-align:1px}
@media (min-width:1050px){
  .col-wide{display:table-cell}
  .rc-inline{display:none}
  .apt-mini{display:none}
}

/* ─── XAI (AI brief) ─────────────────────────────────── */
.live.ai{background:rgba(10,132,255,.11); border-color:rgba(10,132,255,.34); color:#6eb4ff;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.07), 0 4px 14px -6px rgba(10,132,255,.45)}
.live.ai .dot{background:var(--blue); animation:none;
  box-shadow:0 0 8px rgba(10,132,255,.7)}

/* ─── APT attribution ─────────────────────────────────── */
.live.apt{background:rgba(255,69,58,.13); border-color:rgba(255,69,58,.4); color:#ff8a80;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.07), 0 4px 14px -6px rgba(255,69,58,.45)}
.live.apt .dot{background:var(--red); animation:pulseRed 1.8s infinite}
@keyframes pulseRed{
  0%{box-shadow:0 0 0 0 rgba(255,69,58,.5)}
  70%{box-shadow:0 0 0 7px rgba(255,69,58,0)}
  100%{box-shadow:0 0 0 0 rgba(255,69,58,0)}
}
.live.apt.idle{background:rgba(255,255,255,.05); border-color:rgba(255,255,255,.14);
  color:var(--dim); box-shadow:inset 0 1px 0 rgba(255,255,255,.05)}
.live.apt.idle .dot{background:var(--dimmer); animation:none; box-shadow:none}

/* ─── ML decision pipeline ────────────────────────────── */
.live.ml{background:rgba(191,90,242,.12); border-color:rgba(191,90,242,.38); color:#d0a6ff;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.07), 0 4px 14px -6px rgba(191,90,242,.45)}
.live.ml .dot{background:#bf5af2; animation:pulseMl 1.8s infinite;
  box-shadow:0 0 8px rgba(191,90,242,.7)}
@keyframes pulseMl{
  0%{box-shadow:0 0 0 0 rgba(191,90,242,.5)}
  70%{box-shadow:0 0 0 7px rgba(191,90,242,0)}
  100%{box-shadow:0 0 0 0 rgba(191,90,242,0)}
}
.live.ml.idle{background:rgba(255,255,255,.05); border-color:rgba(255,255,255,.14);
  color:var(--dim); box-shadow:inset 0 1px 0 rgba(255,255,255,.05)}
.live.ml.idle .dot{background:var(--dimmer); animation:none; box-shadow:none}

.apt-chip{display:inline-block; margin-left:7px; padding:1px 7px; border-radius:999px;
  font:750 9.5px/1.55 var(--display); letter-spacing:.7px; vertical-align:1px;
  background:rgba(255,69,58,.16); border:1px solid rgba(255,69,58,.42); color:#ff8a80}
.apt-chip.cand{background:rgba(255,159,10,.13); border-color:rgba(255,159,10,.4);
  color:var(--amber)}
.att-head{display:flex; gap:10px; align-items:center; flex-wrap:wrap}
.att-badge{font:750 10.5px/1 var(--display); letter-spacing:1.1px; padding:5px 11px;
  border-radius:999px; border:1px solid transparent}
.att-badge.no{background:rgba(255,69,58,.16); border-color:rgba(255,69,58,.45); color:#ff8a80}
.att-badge.mb{background:rgba(255,159,10,.13); border-color:rgba(255,159,10,.42); color:var(--amber)}
.att-badge.ok{background:rgba(140,140,150,.14); border-color:rgba(160,160,170,.35); color:var(--dim)}
.att-actor{font:700 15px/1.25 var(--display); color:#fff}
.att-actor .dim{font-weight:500; font-size:12.5px; margin-left:6px}
.att-conf{margin-left:auto; font:750 13px/1 var(--display); color:var(--cyan)}
.att-bar{height:5px; border-radius:99px; background:rgba(255,255,255,.09);
  margin-top:10px; overflow:hidden}
.att-bar span{display:block; height:100%; border-radius:99px;
  background:linear-gradient(90deg,var(--cyan),var(--blue))}
.att-cat{margin:10px 0 0; font-size:13.5px; color:var(--fg)}
.att-cat b{color:var(--amber); font-weight:650}
.att-sub{margin-top:12px; font:750 10px/1 var(--display); letter-spacing:1.1px;
  text-transform:uppercase; color:var(--dim)}
.att-list{margin-top:7px; display:grid; gap:4px}
.att-row{display:flex; gap:9px; align-items:baseline; font-size:12.5px; color:var(--fg);
  background:rgba(255,255,255,.04); border:1px solid rgba(255,255,255,.07);
  border-radius:8px; padding:5px 9px}
.att-row b{font-weight:650}
.att-row .mid{color:var(--dim); font-size:11.5px}
.att-row .sc{margin-left:auto; font-family:var(--display); font-weight:700; color:var(--cyan)}
.att-row .hits{color:var(--amber); font-size:11px}
.ev{margin:11px 0 0; padding-left:18px; color:var(--dim); font-size:12.5px}
.ev li{margin:4px 0}
.ev li::marker{color:var(--cyan)}
.att-meta{margin-top:9px; font-size:11.5px}
.apt-toast{position:fixed; top:74px; right:20px; z-index:70; max-width:330px;
  padding:13px 16px; border-radius:14px; cursor:pointer;
  background:linear-gradient(180deg,rgba(60,12,14,.96),rgba(34,8,10,.96));
  border:1px solid rgba(255,69,58,.55); color:#ffd9d6;
  box-shadow:0 22px 50px -18px rgba(255,69,58,.55), inset 0 1px 0 rgba(255,255,255,.12);
  opacity:0; transform:translateY(-14px); pointer-events:none;
  transition:opacity .28s var(--ease), transform .28s var(--ease)}
.apt-toast.show{opacity:1; transform:translateY(0); pointer-events:auto}
.apt-toast b{display:block; font:750 10.5px/1 var(--display); letter-spacing:1.4px;
  color:#ff8a80; margin-bottom:6px}
.apt-toast span{display:block; font:700 15px/1.25 var(--display); color:#fff}
.apt-toast small{display:block; margin-top:4px; font-size:11.5px; color:#e8b0ac}
.ai-btn{
  margin-top:14px; display:inline-flex; align-items:center; gap:8px;
  border:1px solid rgba(100,210,255,.42);
  background:linear-gradient(180deg,rgba(10,132,255,.26),rgba(10,132,255,.14));
  color:#7cc4ff; font:650 12.5px/1 var(--sans); padding:9px 17px; border-radius:999px;
  cursor:pointer; box-shadow:inset 0 1px 0 rgba(255,255,255,.14);
  transition:background .15s var(--ease), transform .1s var(--ease),
             border-color .15s var(--ease);
}
.ai-btn:hover{background:linear-gradient(180deg,rgba(10,132,255,.38),rgba(10,132,255,.22));
  border-color:rgba(100,210,255,.6)}
.ai-btn:active{transform:scale(.97)}
.ai-btn:disabled{opacity:.55; cursor:default}
.ai-btn.busy{opacity:.6; cursor:default}
.ai-out{
  margin-top:12px; padding:14px 16px; border-radius:13px;
  background:linear-gradient(180deg,rgba(10,132,255,.09),rgba(10,132,255,.04));
  border:1px solid rgba(10,132,255,.26);
  box-shadow:inset 0 1px 0 rgba(255,255,255,.07);
  font-size:13.5px; line-height:1.65; white-space:pre-wrap; color:var(--fg);
  animation:rise .2s var(--ease);
}
.ai-out.err{background:rgba(255,69,58,.07); border-color:rgba(255,69,58,.28); color:#ff9f9a}
.ai-out .via{display:block; margin-top:9px; font-size:11px; color:var(--dimmer)}

/* ─── detail ──────────────────────────────────────────── */
tr.detail td{padding:0; background:linear-gradient(180deg,rgba(10,132,255,.07),rgba(10,132,255,.025));
  border-bottom:1px solid var(--line-soft)}
.detail-in{padding:17px 22px 21px; animation:rise .2s var(--ease)}
@keyframes rise{from{opacity:0; transform:translateY(-5px)} to{opacity:1; transform:none}}
.meta{display:flex; flex-wrap:wrap; gap:8px 22px; margin-bottom:14px; font-size:12.5px; color:var(--dim)}
.meta b{color:var(--dimmer); font-weight:500; margin-right:6px}
.meta .mono{color:var(--fg)}
.reasons{display:grid; gap:10px; grid-template-columns:repeat(auto-fit,minmax(320px,1fr))}
.rcard{
  background:linear-gradient(180deg,rgba(255,255,255,.055),rgba(255,255,255,.022));
  border:1px solid rgba(255,255,255,.095); border-radius:13px;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.06), 0 10px 24px -18px rgba(0,0,0,.9);
  padding:12px 15px 13px; transition:border-color .18s var(--ease), transform .18s var(--ease);
}
.rcard:hover{border-color:rgba(10,132,255,.4); transform:translateY(-1px)}
.rcard .top{display:flex; align-items:baseline; gap:10px}
.rcard .f{color:var(--cyan); font-weight:700; font-size:13px; letter-spacing:-.1px}
.rcard .vals{margin-left:auto; text-align:right; color:var(--dim);
  font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
  font-size:12px; font-variant-numeric:tabular-nums; white-space:nowrap}
.rcard .vals i{display:block; font-style:normal; color:var(--dimmer); font-size:11px}
.rcard .t{margin-top:5px; font-size:13px; color:var(--fg)}
.rcard .m{margin-top:6px; font-size:11.5px; color:var(--dim)}
.rcard .m span{color:#6eb4ff}

/* ─── dashboard ───────────────────────────────────────── */
.dash{display:grid; gap:13px; grid-template-columns:repeat(12,1fr)}
.dash>.panel{grid-column:span 12}
@media (min-width:960px){
  #p-score,#p-proto,#p-feed{grid-column:span 4}
  #p-tactics,#p-dst{grid-column:span 6}
}
.panel-sub{margin-left:auto; font-size:11.5px; color:var(--dimmer); font-weight:500}

/* top APT groups panel */
#apt-bars{display:flex; flex-wrap:wrap; gap:9px; align-items:center; padding:14px 18px 17px}
.agroup{display:inline-flex; align-items:center; gap:9px; padding:6.5px 14px;
  border-radius:999px; cursor:pointer; font:650 12.5px/1.35 var(--display); color:#ff9f97;
  background:rgba(255,69,58,.12); border:1px solid rgba(255,69,58,.36);
  transition:background .14s var(--ease), border-color .14s var(--ease),
             transform .14s var(--ease)}
.agroup:hover{background:rgba(255,69,58,.20); border-color:rgba(255,69,58,.55);
  transform:translateY(-1px)}
.agroup:focus-visible{outline:2px solid var(--cyan); outline-offset:2px}
.agroup.cand{color:var(--amber); background:rgba(255,159,10,.11);
  border-color:rgba(255,159,10,.34)}
.agroup.cand:hover{background:rgba(255,159,10,.19); border-color:rgba(255,159,10,.5)}
.agc{font:750 11px/1 var(--display); color:#fff; background:rgba(0,0,0,.30);
  border-radius:99px; padding:3.5px 7.5px; font-variant-numeric:tabular-nums}
.agsum{font-size:11.5px; color:var(--dimmer); margin-left:4px}

/* heartbeat + timeline (threat activity) */
.hbzone{
  position:relative; padding:16px 20px 16px; border-radius:14px;
  border:1px solid rgba(255,255,255,.07);
  background:
    repeating-linear-gradient(90deg, rgba(255,255,255,.032) 0 1px, transparent 1px 42px),
    repeating-linear-gradient(0deg, rgba(255,255,255,.032) 0 1px, transparent 1px 22px),
    linear-gradient(180deg, rgba(10,132,255,.045), rgba(255,255,255,.012));
  box-shadow:inset 0 1px 0 rgba(255,255,255,.07), inset 0 0 24px -12px rgba(10,132,255,.5),
    0 12px 30px -22px rgba(0,0,0,.9);
}
#hb-svg{display:block; width:100%; height:58px; overflow:visible}
#hb-path{filter:drop-shadow(0 0 5px rgba(100,210,255,.55))}
#hb-dot{filter:drop-shadow(0 0 6px rgba(255,255,255,.95))}
.bpm{
  display:inline-flex; align-items:center; gap:7px; padding:4.5px 12px;
  border-radius:999px; font-size:11px; font-weight:750; letter-spacing:.4px;
  color:#3ddc6f; background:rgba(48,209,88,.10); border:1px solid rgba(48,209,88,.34);
  font-variant-numeric:tabular-nums;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.08), 0 4px 14px -6px rgba(48,209,88,.4);
}
.bpm svg{display:block}
.bpm b{font-size:12.5px}
.bpm.idle{color:var(--dimmer); background:rgba(255,255,255,.05); border-color:var(--line);
  box-shadow:inset 0 1px 0 rgba(255,255,255,.06)}
.tl{display:flex; gap:4px; align-items:flex-end; height:122px; margin-top:6px}
.tb{
  flex:1; min-height:4px; border-radius:6px 6px 2px 2px; cursor:pointer;
  background:linear-gradient(180deg,rgba(10,132,255,.95),rgba(100,210,255,.5));
  box-shadow:inset 0 1px 0 rgba(255,255,255,.3);
  transition:height .35s var(--ease), filter .15s var(--ease),
             box-shadow .15s var(--ease);
}
.tb:not(.on){background:rgba(255,255,255,.085); cursor:pointer; box-shadow:none}
.tb:hover{filter:brightness(1.35); box-shadow:0 0 0 1px rgba(100,210,255,.6),
  0 6px 16px -6px rgba(100,210,255,.5)}
.tb.sel{box-shadow:0 0 0 2px var(--cyan), 0 6px 16px -6px rgba(100,210,255,.55);
  filter:brightness(1.25)}
.hbzone.beat .tb.on{animation:beatglow .65s var(--ease)}
.hbzone.beat #hb-path{animation:ecgflash .65s var(--ease)}
@keyframes beatglow{
  0%{filter:brightness(1)} 25%{filter:brightness(1.75); transform:scaleY(1.045)}
  100%{filter:brightness(1); transform:scaleY(1)}
}
@keyframes ecgflash{
  0%{filter:drop-shadow(0 0 5px rgba(100,210,255,.55))}
  25%{filter:drop-shadow(0 0 14px rgba(100,210,255,.95))}
  100%{filter:drop-shadow(0 0 5px rgba(100,210,255,.55))}
}
.tl-axis{display:flex; justify-content:space-between; margin-top:8px;
  font-size:10.5px; color:var(--dimmer); letter-spacing:.3px}
.hb{display:grid; grid-template-columns:82px 1fr 46px; gap:12px; align-items:center;
  padding:7px 8px; font-size:12.5px; border-radius:9px;
  transition:background .15s var(--ease), box-shadow .15s var(--ease),
             transform .15s var(--ease)}
.hb.click{cursor:pointer; user-select:none}
.hb.click:hover{background:rgba(255,255,255,.055); transform:translateX(2px)}
.hb.click:active{transform:scale(.995)}
.hb.click.sel{background:rgba(10,132,255,.13); box-shadow:inset 0 0 0 1px rgba(10,132,255,.38)}
.hb .lbl{color:var(--fg); font-size:12px; font-weight:550; white-space:nowrap;
  overflow:hidden; text-overflow:ellipsis}
.hb .track{height:9px; border-radius:999px; background:rgba(255,255,255,.08);
  overflow:hidden; box-shadow:inset 0 1.5px 2.5px rgba(0,0,0,.4)}
.hb .fill{height:100%; border-radius:999px;
  background:linear-gradient(90deg,var(--blue),var(--cyan));
  box-shadow:0 0 10px -2px rgba(10,132,255,.7);
  transition:width .35s var(--ease)}
.hb .fill.tac{background:linear-gradient(90deg,#6eb4ff,#a78bfa);
  box-shadow:0 0 10px -2px rgba(140,120,255,.7)}
.hb .val{text-align:right; color:var(--dim); font-variant-numeric:tabular-nums;
  font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,monospace; font-size:11.5px}
.stack{display:flex; height:16px; gap:2.5px; border-radius:999px; overflow:hidden;
  background:rgba(255,255,255,.06); box-shadow:inset 0 1.5px 3px rgba(0,0,0,.4)}
.stack .sseg{min-width:6px; cursor:pointer; transition:filter .15s var(--ease),
  transform .15s var(--ease)}
.stack .sseg:hover{filter:brightness(1.4) saturate(1.25); transform:scaleY(1.5)}
.stack .sseg.sel{box-shadow:0 0 0 1.5px #fff}
.legend{display:grid; gap:9px; margin-top:15px}
.legend .lg{display:flex; align-items:center; gap:10px; font-size:12.5px; color:var(--fg);
  padding:4px 7px; margin:0 -7px; border-radius:9px;
  transition:background .15s var(--ease), transform .15s var(--ease)}
.legend .lg.click{cursor:pointer; user-select:none}
.legend .lg.click:hover{background:rgba(255,255,255,.055); transform:translateX(2px)}
.legend .lg.sel{background:rgba(10,132,255,.13); box-shadow:inset 0 0 0 1px rgba(10,132,255,.38)}
.legend .sw{width:11px; height:11px; border-radius:4px; flex:none;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.3)}
.legend .n{margin-left:auto; color:var(--dim); font-variant-numeric:tabular-nums;
  font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,monospace; font-size:11.5px}
.feed-meta{display:flex; flex-wrap:wrap; gap:7px 18px; align-items:center;
  font-size:12.5px; color:var(--dim); margin-bottom:13px}
.mode{display:inline-flex; align-items:center; gap:7px; padding:4px 12px;
  border-radius:999px; font-size:10.5px; font-weight:750; letter-spacing:.9px}
.mode.on{color:#3ddc6f; background:rgba(48,209,88,.10);
  border:1px solid rgba(48,209,88,.34);
  box-shadow:inset 0 1px 0 rgba(255,255,255,.07)}
.mode.off{color:var(--amber); background:rgba(255,214,10,.08);
  border:1px solid rgba(255,214,10,.3);
  box-shadow:inset 0 1px 0 rgba(255,255,255,.07)}
.fchips{display:flex; flex-wrap:wrap; gap:9px}
.fchip{display:inline-flex; align-items:center; gap:7px; padding:5.5px 13px;
  border-radius:999px; font-size:12px; border:1px solid rgba(255,255,255,.1);
  background:linear-gradient(180deg,rgba(255,255,255,.07),rgba(255,255,255,.03));
  color:var(--dim); max-width:100%;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.07)}
.fchip b{font-weight:700; color:var(--fg)}
.fchip.ok{border-color:rgba(48,209,88,.32); background:rgba(48,209,88,.075)}
.fchip.ok .mk{color:#3ddc6f}
.fchip.bad{border-color:rgba(255,69,58,.34); background:rgba(255,69,58,.075)}
.fchip.bad .mk{color:#ff6961}
.fchip .mk{font-weight:750}
.fchip .sub{color:var(--dimmer); font-size:11px}
.dst{display:flex; align-items:center; gap:11px; padding:9px 8px; cursor:pointer;
  border-bottom:1px solid var(--line-soft); font-size:12.5px; border-radius:8px}
.dst:last-child{border-bottom:0}
.dst:hover{background:rgba(255,255,255,.05)}
.dst .ip{flex:1; font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,monospace;
  font-size:12.5px}
.dst .star{color:var(--amber)}
.dst .n{color:var(--dim); font-variant-numeric:tabular-nums; font-size:11.5px}
.ph{padding:16px 4px; color:var(--dimmer); font-size:12.5px}
.ph b{color:var(--dim); font-weight:600}

/* ─── affordances, filter pills, insight sheet ─────────── */
button:focus-visible, input:focus-visible,
.stat.click:focus-visible, .tb:focus-visible, .hb.click:focus-visible,
.dst:focus-visible, .sseg:focus-visible, .lg.click:focus-visible,
.fchip.click:focus-visible{
  outline:2px solid rgba(10,132,255,.85); outline-offset:2px; border-radius:6px;
}
.fchip.click{cursor:pointer; transition:border-color .15s var(--ease),
  background .15s var(--ease), transform .15s var(--ease)}
.fchip.click:hover{border-color:rgba(10,132,255,.5); background:rgba(10,132,255,.10);
  transform:translateY(-1px)}
.dst{transition:background .15s var(--ease), transform .15s var(--ease)}
.dst:hover{transform:translateX(3px)}

.fpills{display:inline-flex; flex-wrap:wrap; gap:7px; align-items:center}
.fpills:empty{display:none}
.fp{
  display:inline-flex; align-items:center; gap:8px; cursor:pointer; user-select:none;
  padding:4.5px 12px; border-radius:999px; font-size:11.5px; font-weight:650;
  color:#7cc4ff;
  background:linear-gradient(180deg,rgba(10,132,255,.3),rgba(10,132,255,.16));
  border:1px solid rgba(10,132,255,.42);
  box-shadow:inset 0 1px 0 rgba(255,255,255,.14);
  transition:background .15s var(--ease), border-color .15s var(--ease),
             transform .12s var(--ease);
}
.fp:hover{background:linear-gradient(180deg,rgba(10,132,255,.44),rgba(10,132,255,.26));
  border-color:rgba(10,132,255,.62); transform:translateY(-1px)}
.fp:active{transform:scale(.96)}
.fp .x{font-weight:700; opacity:.75; font-size:12.5px; line-height:1}
.fp:hover .x{opacity:1}

#ins-scrim{position:fixed; inset:0; z-index:64; background:rgba(0,0,0,.5);
  backdrop-filter:blur(7px); -webkit-backdrop-filter:blur(7px);
  animation:fadein .22s var(--ease)}
#ins-scrim[hidden]{display:none}
#insight{
  position:fixed; left:50%; bottom:22px; transform:translateX(-50%);
  z-index:65; width:min(720px,94vw); max-height:min(74vh,660px);
  display:flex; flex-direction:column; border-radius:24px;
  background:linear-gradient(180deg,rgba(30,30,33,.97),rgba(16,16,18,.98));
  border:1px solid rgba(255,255,255,.14);
  box-shadow:0 1px 0 rgba(255,255,255,.1) inset, 0 40px 90px -24px rgba(0,0,0,.9),
    0 0 0 .5px rgba(0,0,0,.4);
  backdrop-filter:blur(32px) saturate(185%);
  -webkit-backdrop-filter:blur(32px) saturate(185%);
  animation:sheet .3s var(--ease);
}
#insight::before{content:''; position:absolute; top:0; left:30px; right:30px; height:1px;
  background:linear-gradient(90deg,transparent,rgba(100,210,255,.55),rgba(10,132,255,.35),transparent);
  pointer-events:none}
#insight[hidden]{display:none}
@keyframes sheet{from{opacity:0; transform:translate(-50%,26px)} to{opacity:1; transform:translate(-50%,0)}}
@keyframes fadein{from{opacity:0} to{opacity:1}}
.ins-grip{width:40px; height:5px; border-radius:999px; background:rgba(255,255,255,.26);
  margin:11px auto 0; flex:none; box-shadow:0 1px 3px rgba(0,0,0,.5)}
.ins-head{display:flex; align-items:flex-start; gap:13px; padding:14px 22px 0; flex:none}
.ins-badge{
  flex:none; padding:5px 13px; border-radius:999px; font-size:10.5px; font-weight:750;
  letter-spacing:.8px; text-transform:uppercase; color:#7cc4ff;
  background:linear-gradient(180deg,rgba(10,132,255,.3),rgba(10,132,255,.16));
  border:1px solid rgba(10,132,255,.42);
  box-shadow:inset 0 1px 0 rgba(255,255,255,.16);
  font-variant-numeric:tabular-nums; max-width:180px; overflow:hidden;
  text-overflow:ellipsis; white-space:nowrap;
}
#ins-title{margin:3px 0 0; font-family:var(--display); font-size:18.5px; font-weight:750;
  letter-spacing:-.55px; color:#fff}
#ins-metric{margin:4px 0 0; font-size:13px; color:var(--dim);
  font-variant-numeric:tabular-nums}
#ins-close{
  margin-left:auto; flex:none; width:31px; height:31px; border-radius:50%; border:0;
  background:rgba(255,255,255,.1); color:var(--dim); font-size:15px; cursor:pointer;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.1);
  transition:background .15s var(--ease), color .15s var(--ease), transform .12s var(--ease)}
#ins-close:hover{background:rgba(255,255,255,.2); color:var(--fg)}
#ins-close:active{transform:scale(.92)}
.ins-body{padding:15px 24px 5px; overflow-y:auto; font-size:13.5px; line-height:1.66}
.ins-body p{margin:0 0 12px}
.ins-body p:last-child{margin-bottom:0}
.ins-sec{
  font-family:var(--display);
  font-size:10.5px; font-weight:750; letter-spacing:1.2px; text-transform:uppercase;
  color:var(--dimmer); margin:16px 0 7px}
.ins-sec.why{color:#7cc4ff}
.ins-body b{font-weight:680; color:#fff}
.ins-body .hl{color:var(--cyan); font-variant-numeric:tabular-nums}
.ins-foot{display:flex; align-items:center; gap:12px; padding:16px 22px 18px; flex:none;
  border-top:1px solid rgba(255,255,255,.09); margin-top:13px}
.ins-cta{
  border:1px solid rgba(255,255,255,.18); border-radius:999px; padding:11px 21px;
  cursor:pointer;
  background:linear-gradient(180deg,#2e9bff,#0070e0); color:#fff;
  font:650 13px/1 var(--sans); letter-spacing:-.1px;
  box-shadow:0 10px 26px -10px rgba(10,132,255,.85), inset 0 1px 0 rgba(255,255,255,.32);
  transition:transform .12s var(--ease), filter .15s var(--ease)}
.ins-cta:hover{filter:brightness(1.12)}
.ins-cta:active{transform:scale(.97)}
.ins-cta[hidden]{display:none}
.ins-note{font-size:11.5px; color:var(--dimmer)}
.ins-prov{margin-left:auto; font-size:11px; color:var(--dimmer); text-align:right;
  font-variant-numeric:tabular-nums}

/* ─── deep analysis window ─────────────────────────────── */
#an-scrim{position:fixed; inset:0; z-index:66; background:rgba(0,0,0,.56);
  backdrop-filter:blur(8px); -webkit-backdrop-filter:blur(8px);
  animation:fadein .2s var(--ease)}
#an-scrim[hidden]{display:none}
#analysis{
  position:fixed; left:50%; top:50%; transform:translate(-50%,-50%);
  z-index:67; width:min(880px,95vw); max-height:90vh;
  display:flex; flex-direction:column; border-radius:26px;
  background:linear-gradient(180deg,rgba(30,30,33,.98),rgba(14,14,16,.99));
  border:1px solid rgba(255,255,255,.15);
  box-shadow:0 1px 0 rgba(255,255,255,.1) inset, 0 50px 120px -30px rgba(0,0,0,.95),
    0 0 0 .5px rgba(0,0,0,.45);
  backdrop-filter:blur(34px) saturate(190%);
  -webkit-backdrop-filter:blur(34px) saturate(190%);
  animation:ansheet .3s var(--ease);
}
#analysis::before{content:''; position:absolute; top:0; left:36px; right:36px; height:1px;
  background:linear-gradient(90deg,transparent,rgba(255,159,10,.75),rgba(255,69,58,.5),transparent);
  pointer-events:none}
#analysis[hidden]{display:none}
@keyframes ansheet{from{opacity:0; transform:translate(-50%,-47%) scale(.97)}
  to{opacity:1; transform:translate(-50%,-50%) scale(1)}}
.an-head{display:flex; align-items:center; gap:18px; padding:21px 25px 9px; flex:none}
.an-id{min-width:0; flex:1}
.an-id h3{margin:7px 0 0; font-family:var(--display); font-size:19px; font-weight:750;
  letter-spacing:-.55px; color:#fff; overflow:hidden; text-overflow:ellipsis; white-space:nowrap}
.an-id p{margin:4px 0 0; font-size:12.5px; color:var(--dim); font-variant-numeric:tabular-nums;
  overflow:hidden; text-overflow:ellipsis; white-space:nowrap}
.an-score{position:relative; width:84px; height:84px; flex:none}
.an-score svg{width:84px; height:84px; transform:rotate(-90deg); display:block}
.an-score circle{fill:none; stroke-width:7; stroke-linecap:round}
.an-score .rbg{stroke:rgba(255,255,255,.09)}
.an-score .rfg{stroke:url(#angr); filter:drop-shadow(0 0 6px rgba(255,90,60,.5));
  transition:stroke-dashoffset .55s var(--ease)}
.an-num{position:absolute; inset:0; display:grid; place-content:center; text-align:center}
.an-num b{font-family:var(--display); font-size:19px; font-weight:750; color:#fff;
  font-variant-numeric:tabular-nums; letter-spacing:-.5px; line-height:1}
.an-num i{display:block; font-style:normal; font-size:9px; letter-spacing:1.25px;
  text-transform:uppercase; color:var(--dimmer); margin-top:3px}
#an-close{flex:none; width:31px; height:31px; border-radius:50%; border:0;
  background:rgba(255,255,255,.1); color:var(--dim); font-size:15px; cursor:pointer;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.1);
  transition:background .15s var(--ease), color .15s var(--ease), transform .12s var(--ease)}
#an-close:hover{background:rgba(255,255,255,.2); color:var(--fg)}
#an-close:active{transform:scale(.92)}
.an-meter{padding:5px 27px 11px; flex:none}
.an-mrow{display:flex; justify-content:space-between; font-size:11.5px; color:var(--dim);
  margin-bottom:7px; font-variant-numeric:tabular-nums}
.an-mrow b{color:var(--amber); font-weight:750}
#an-above{color:#ff8a80}
.an-track{position:relative; height:10px; border-radius:999px; background:rgba(255,255,255,.08);
  box-shadow:inset 0 1.5px 3px rgba(0,0,0,.45)}
.an-fill{position:absolute; top:0; bottom:0; left:0; border-radius:999px;
  background:linear-gradient(90deg,#ff9f0a,#ff453a);
  box-shadow:0 0 12px -2px rgba(255,69,58,.85); transition:width .5s var(--ease)}
.an-mark{position:absolute; top:-2px; bottom:-2px; left:0; width:2px; border-radius:2px;
  background:rgba(255,214,10,.85); box-shadow:0 0 6px rgba(255,214,10,.6)}
.an-scale{display:flex; justify-content:space-between; margin-top:5px; font-size:10px;
  color:var(--dimmer); letter-spacing:.4px}
.an-body{padding:3px 27px 10px; overflow-y:auto; flex:1 1 auto; min-height:0}
.an-sec{font-family:var(--display); font-size:10.5px; font-weight:750; letter-spacing:1.25px;
  text-transform:uppercase; color:var(--dimmer); margin:21px 0 11px;
  display:flex; align-items:center; gap:11px}
.an-sec::after{content:''; flex:1; height:1px;
  background:linear-gradient(90deg,rgba(255,255,255,.13),transparent)}
.facts{display:grid; gap:9px; grid-template-columns:repeat(auto-fit,minmax(155px,1fr))}
.fact{background:linear-gradient(180deg,rgba(255,255,255,.055),rgba(255,255,255,.022));
  border:1px solid rgba(255,255,255,.095); border-radius:11px; padding:9px 13px 10px;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.06)}
.fact b{display:block; font-size:9.5px; font-weight:700; letter-spacing:.95px;
  text-transform:uppercase; color:var(--dimmer); font-family:var(--display)}
.fact span{display:block; margin-top:4px; font-family:ui-monospace,SFMono-Regular,
  "SF Mono",Menlo,Consolas,monospace; font-size:13px; color:#fff;
  font-variant-numeric:tabular-nums; overflow:hidden; text-overflow:ellipsis; white-space:nowrap}
.wf-list{display:grid; gap:10px}
.wf{background:linear-gradient(180deg,rgba(255,255,255,.042),rgba(255,255,255,.016));
  border:1px solid var(--line); border-radius:13px; padding:11px 15px 12px;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.05)}
.wf-top{display:flex; align-items:baseline; gap:10px; flex-wrap:wrap;
  font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace; font-size:12.5px}
.wf-rank{flex:none; width:19px; height:19px; border-radius:50%; display:inline-grid;
  place-content:center; font-family:var(--display); font-size:10px; font-weight:750;
  color:var(--dim); background:rgba(255,255,255,.08); border:1px solid rgba(255,255,255,.1)}
.wf-f{color:var(--cyan); font-weight:700}
.wf-v{color:var(--dim)}
.wf-d{margin-left:auto; font-weight:800; color:#ff8a80; font-variant-numeric:tabular-nums}
.wf.neg .wf-d{color:#4ade80}
.wf.ioc .wf-d{color:var(--amber)}
.wf-track{height:8px; border-radius:999px; background:rgba(255,255,255,.07);
  margin:9px 0 8px; overflow:hidden; box-shadow:inset 0 1.5px 2.5px rgba(0,0,0,.4)}
.wf-bar{display:block; height:100%; border-radius:999px; min-width:4px;
  background:linear-gradient(90deg,#ff9f0a,#ff453a);
  box-shadow:0 0 9px -2px rgba(255,100,70,.8); transition:width .45s var(--ease)}
.wf.neg .wf-bar{background:linear-gradient(90deg,#30d158,#0a84ff); box-shadow:none}
.wf.ioc .wf-bar{background:linear-gradient(90deg,#ffd60a,#ff9f0a); box-shadow:none}
.wf-t{font-size:13.5px; color:var(--fg); line-height:1.5}
.wf .m{margin-top:5px; font-size:11.5px; color:var(--dim)}
.an-card{background:linear-gradient(180deg,rgba(255,255,255,.05),rgba(255,255,255,.02));
  border:1px solid var(--line); border-radius:14px; padding:14px 17px;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.06);
  font-size:13.5px; line-height:1.62}
.an-card p{margin:0 0 9px}
.an-card p:last-child{margin-bottom:0}
.an-card p.dim{color:var(--dim); font-size:12.5px}
.an-card .tactic{margin-right:4px; vertical-align:2px}
.an-tech{font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
  color:var(--cyan); font-size:12.5px}
.ioc-hit{color:var(--amber); font-weight:700}
.an-foot{display:flex; align-items:center; gap:11px; padding:14px 25px 18px; flex:none;
  border-top:1px solid rgba(255,255,255,.09); flex-wrap:wrap}
.an-ghost{border:1px solid rgba(255,255,255,.14); background:rgba(255,255,255,.06);
  color:var(--fg); font:600 12.5px/1 var(--sans); padding:9.5px 16px; border-radius:999px;
  cursor:pointer; box-shadow:inset 0 1px 0 rgba(255,255,255,.07);
  transition:background .15s var(--ease), border-color .15s var(--ease),
             transform .12s var(--ease)}
.an-ghost:hover{background:rgba(255,255,255,.12); border-color:rgba(255,255,255,.26)}
.an-ghost:active{transform:scale(.97)}

/* ─── ML pipeline window (visual train → detect → attribute) ── */
#mp-scrim,#ap-scrim,#fp-scrim,#dw-scrim,#ai-scrim{position:fixed; inset:0; z-index:66; background:rgba(0,0,0,.56);
  backdrop-filter:blur(8px); -webkit-backdrop-filter:blur(8px);
  animation:fadein .2s var(--ease)}
#mp-scrim[hidden],#ap-scrim[hidden],#fp-scrim[hidden],#dw-scrim[hidden],#ai-scrim[hidden]{display:none}
#mlpipe,#aptpipe,#feedpipe,#deep,#aipipe{
  position:fixed; left:50%; top:50%; transform:translate(-50%,-50%);
  z-index:67; width:min(960px,95vw); max-height:91vh;
  display:flex; flex-direction:column; border-radius:26px;
  background:linear-gradient(180deg,rgba(30,30,33,.98),rgba(14,14,16,.99));
  border:1px solid rgba(255,255,255,.15);
  box-shadow:0 1px 0 rgba(255,255,255,.1) inset, 0 50px 120px -30px rgba(0,0,0,.95),
    0 0 0 .5px rgba(0,0,0,.45);
  backdrop-filter:blur(34px) saturate(190%);
  -webkit-backdrop-filter:blur(34px) saturate(190%);
  animation:ansheet .3s var(--ease);
}
#mlpipe::before,#aptpipe::before,#feedpipe::before,#deep::before,#aipipe::before{content:''; position:absolute; top:0; left:36px; right:36px; height:1px;
  background:linear-gradient(90deg,transparent,rgba(191,90,242,.85),rgba(10,132,255,.55),transparent);
  pointer-events:none}
#aptpipe::before{background:linear-gradient(90deg,transparent,rgba(255,69,58,.85),rgba(255,159,10,.55),transparent)}
#feedpipe::before{background:linear-gradient(90deg,transparent,rgba(48,209,88,.85),rgba(100,210,255,.55),transparent)}
#deep::before{background:linear-gradient(90deg,transparent,rgba(10,132,242,.85),rgba(100,210,255,.55),transparent)}
#aipipe::before{background:linear-gradient(90deg,transparent,rgba(10,132,242,.85),rgba(191,90,242,.55),transparent)}
#mlpipe[hidden],#aptpipe[hidden],#feedpipe[hidden],#deep[hidden],#aipipe[hidden]{display:none}
.mp-head{display:flex; align-items:center; gap:14px; padding:21px 25px 6px; flex:none}
.mp-head h2{margin:0; font-family:var(--display); font-size:17.5px; font-weight:750;
  letter-spacing:-.4px}
.mp-sub{font-size:12px; color:var(--dimmer)}
#mp-close,#ap-close,#fp-close,#dw-close,#ai-close{flex:none; width:31px; height:31px; border-radius:50%; border:0; margin-left:auto;
  background:rgba(255,255,255,.12); color:#fff; font-size:14px; cursor:pointer;
  display:grid; place-items:center; transition:background .15s var(--ease)}
#mp-close:hover,#ap-close:hover,#fp-close:hover,#dw-close:hover,#ai-close:hover{background:rgba(255,255,255,.22)}
#mp-close:active,#ap-close:active,#fp-close:active,#dw-close:active,#ai-close:active{transform:scale(.92)}
#dw-cta[hidden]{display:none}
.mp-body{padding:6px 26px 12px; overflow-y:auto; flex:1 1 auto; min-height:0}
.mp-foot{display:flex; align-items:center; gap:11px; padding:13px 25px 17px; flex:none;
  border-top:1px solid rgba(255,255,255,.09); flex-wrap:wrap}
.mp-stage{margin:13px 0 2px}
.mp-stitle{display:flex; align-items:center; gap:9px; font-family:var(--display);
  font-size:10.5px; font-weight:750; letter-spacing:1.3px; text-transform:uppercase;
  color:var(--dim); margin-bottom:10px}
.mp-stitle .n{width:20px; height:20px; border-radius:50%; display:grid; place-items:center;
  background:rgba(191,90,242,.16); border:1px solid rgba(191,90,242,.45); color:#d0a6ff;
  font-size:11px; flex:none}
.mp-flow{display:flex; flex-wrap:wrap; align-items:stretch; gap:7px; margin-bottom:12px}
.mp-node{flex:1 1 128px; min-width:128px; border-radius:13px; padding:10px 12px;
  background:linear-gradient(180deg,rgba(255,255,255,.055),rgba(255,255,255,.02));
  border:1px solid var(--line)}
.mp-node b{display:block; font-family:var(--display); font-size:12.5px; font-weight:700;
  letter-spacing:-.2px; line-height:1.3}
.mp-node i{display:block; font-style:normal; font-size:11px; color:var(--dim);
  margin-top:4px; line-height:1.5}
.mp-node.hl{border-color:rgba(191,90,242,.45); background:rgba(191,90,242,.08)}
.mp-node.ok{border-color:rgba(61,220,111,.4); background:rgba(61,220,111,.07)}
.mp-node.warn{border-color:rgba(255,159,10,.42); background:rgba(255,159,10,.07)}
.mp-arrow{align-self:center; color:var(--dimmer); font-size:15px; flex:none}
.mp-grid{display:grid; gap:12px; margin-bottom:12px}
.mp-g2{grid-template-columns:repeat(auto-fit,minmax(250px,1fr))}
.mp-card{background:linear-gradient(180deg,rgba(255,255,255,.05),rgba(255,255,255,.02));
  border:1px solid var(--line); border-radius:15px; padding:13px 15px}
.mp-card h4{margin:0 0 10px; font-family:var(--display); font-size:10.5px; font-weight:750;
  letter-spacing:1.2px; text-transform:uppercase; color:var(--dim)}
.mp-kpis{display:flex; flex-wrap:wrap; gap:9px}
.mp-kpi{flex:1 1 112px; background:rgba(255,255,255,.045); border:1px solid rgba(255,255,255,.09);
  border-radius:12px; padding:9px 11px; text-align:center}
.mp-kpi b{display:block; font-family:var(--display); font-size:19px; font-weight:750;
  letter-spacing:-.5px; font-variant-numeric:tabular-nums}
.mp-kpi i{display:block; font-style:normal; font-size:9.5px; letter-spacing:.7px;
  text-transform:uppercase; color:var(--dimmer); margin-top:3px}
.mp-kpi.g b{color:#3ddc6f} .mp-kpi.a b{color:var(--amber)} .mp-kpi.r b{color:#ff6961}
.mp-kpi.b b{color:var(--cyan)} .mp-kpi.v b{color:#d0a6ff}
.mp-split{display:flex; height:27px; border-radius:8px; overflow:hidden}
.mp-split span{display:grid; place-items:center; font-size:10.5px; font-weight:700;
  color:#fff; white-space:nowrap; overflow:hidden; transition:width .55s var(--ease)}
.mp-split .tr{background:linear-gradient(90deg,#0a84ff,#64d2ff)}
.mp-split .te{background:rgba(255,255,255,.15)}
.mp-cm{display:grid; grid-template-columns:1fr 1fr; gap:6px}
.mp-cm div{border-radius:10px; padding:9px 8px; text-align:center;
  font-variant-numeric:tabular-nums}
.mp-cm b{display:block; font-family:var(--display); font-size:17px; font-weight:750}
.mp-cm i{font-style:normal; font-size:9.5px; letter-spacing:.8px; text-transform:uppercase;
  opacity:.85}
.mp-cm .tp{background:rgba(61,220,111,.16); border:1px solid rgba(61,220,111,.4); color:#3ddc6f}
.mp-cm .tn{background:rgba(10,132,255,.13); border:1px solid rgba(10,132,255,.36); color:#6eb4ff}
.mp-cm .fp{background:rgba(255,159,10,.15); border:1px solid rgba(255,159,10,.4); color:var(--amber)}
.mp-cm .fn{background:rgba(255,69,58,.15); border:1px solid rgba(255,69,58,.4); color:#ff6961}
.mp-axis{position:relative; height:44px; margin-top:14px}
.mp-track{position:absolute; left:0; right:0; top:14px; height:10px; border-radius:6px;
  background:linear-gradient(90deg,rgba(255,255,255,.07) 0,rgba(255,69,58,.4) 60%,
    rgba(255,159,10,.45) 83.49%,rgba(61,220,111,.55) 100%)}
.mp-tmark{position:absolute; top:8px; height:22px; width:2px; background:#fff;
  box-shadow:0 0 9px rgba(255,255,255,.85); transform:translateX(-1px)}
.mp-tlab{position:absolute; top:-8px; transform:translateX(-50%); font-size:10px;
  font-weight:750; color:#fff; white-space:nowrap; font-variant-numeric:tabular-nums}
.mp-axl{position:absolute; top:28px; font-size:10px; color:var(--dimmer)}
.mp-axl.lo{left:0} .mp-axl.hi{right:0; color:#3ddc6f}
.mp-spec{display:flex; align-items:flex-end; gap:4px; height:72px; margin-top:4px}
.mp-spec .sb{flex:1; min-height:3px; border-radius:4px 4px 2px 2px;
  background:linear-gradient(180deg,#ff9f0a,#ff6961); position:relative;
  transition:height .5s var(--ease)}
.mp-spec .sb:hover::after{content:attr(data-n) ' alert(s)'; position:absolute;
  bottom:calc(100% + 5px); left:50%; transform:translateX(-50%); z-index:4;
  background:#000; border:1px solid var(--line); color:#fff; font-size:10px;
  padding:3px 7px; border-radius:7px; white-space:nowrap}
.mp-speclab{display:flex; justify-content:space-between; font-size:10.5px;
  color:var(--dimmer); margin-top:7px; font-variant-numeric:tabular-nums}
.mp-ibar{display:grid; grid-template-columns:124px 1fr 48px; align-items:center; gap:9px;
  margin-bottom:7px; font-size:11.5px}
.mp-ibar .f{font-family:var(--display); font-weight:650; letter-spacing:-.1px;
  white-space:nowrap; overflow:hidden; text-overflow:ellipsis}
.mp-ibar .b{height:9px; border-radius:5px; background:rgba(255,255,255,.07); overflow:hidden}
.mp-ibar .b span{display:block; height:100%; border-radius:5px;
  background:linear-gradient(90deg,#bf5af2,#0a84ff); transition:width .6s var(--ease)}
.mp-ibar .p{text-align:right; color:var(--dim); font-weight:650;
  font-variant-numeric:tabular-nums}
.mp-ev{display:grid; gap:10px; grid-template-columns:repeat(auto-fit,minmax(185px,1fr));
  margin-bottom:12px}
.mp-ev .e{background:rgba(191,90,242,.07); border:1px solid rgba(191,90,242,.3);
  border-radius:13px; padding:10px 13px}
.mp-ev .e b{display:block; font-family:var(--display); font-size:12px; font-weight:700;
  color:#d0a6ff}
.mp-ev .e i{display:block; font-style:normal; font-size:11px; color:var(--dim);
  margin-top:4px; line-height:1.55}
.mp-gates{display:grid; gap:6px}
.mp-gate{display:flex; gap:9px; align-items:flex-start; font-size:12px; line-height:1.5;
  background:rgba(255,255,255,.04); border:1px solid rgba(255,255,255,.08);
  border-radius:10px; padding:8px 11px}
.mp-gate .mk{flex:none; font-weight:800}
.mp-gate .mk.y{color:#3ddc6f} .mp-gate .mk.n{color:#ff6961}
.mp-gate em{font-style:normal; color:var(--dimmer); display:block; font-size:11px;
  margin-top:1px}
.mp-verds{display:grid; gap:10px; grid-template-columns:repeat(auto-fit,minmax(175px,1fr));
  margin-top:12px}
.mp-verd{border-radius:14px; padding:13px 14px; text-align:center}
.mp-verd b{display:block; font-family:var(--display); font-size:30px; font-weight:780;
  letter-spacing:-1px; font-variant-numeric:tabular-nums}
.mp-verd i{display:block; font-style:normal; font-size:10.5px; letter-spacing:.9px;
  text-transform:uppercase; margin-top:3px; color:var(--fg)}
.mp-verd s{display:block; text-decoration:none; font-size:11px; color:var(--dimmer);
  margin-top:6px; line-height:1.45}
.mp-verd.red{background:rgba(255,69,58,.12); border:1px solid rgba(255,69,58,.42)}
.mp-verd.red b{color:#ff8a80}
.mp-verd.amb{background:rgba(255,159,10,.1); border:1px solid rgba(255,159,10,.38)}
.mp-verd.amb b{color:var(--amber)}
.mp-verd.grey{background:rgba(255,255,255,.05); border:1px solid rgba(255,255,255,.13)}
.mp-verd.grey b{color:var(--dim)}
.mp-verd.grn{background:rgba(48,209,88,.12); border:1px solid rgba(48,209,88,.42)}
.mp-verd.grn b{color:#3ddc6f}
.mp-verd.cur{box-shadow:0 0 0 2px rgba(255,255,255,.55)}
.mp-ex{font-size:11.5px; color:var(--dim); margin-bottom:9px; line-height:1.55}
.mp-ex b{color:#d0a6ff}
.mp-cand{margin-bottom:9px}
.mp-cand .mp-ibar{margin-bottom:3px}
.mp-cmeta{font-size:10.5px; color:var(--dimmer); padding-left:2px;
  display:flex; flex-wrap:wrap; gap:6px; align-items:center}
.mp-cmeta .hit{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  font-size:9.5px; padding:1px 6px; border-radius:6px;
  background:rgba(255,69,58,.14); border:1px solid rgba(255,69,58,.3);
  color:#ff8a80; letter-spacing:.4px}
.mp-cat{display:flex; flex-wrap:wrap; gap:7px; margin-top:8px}
.mp-cat span{font-size:10.5px; padding:3px 9px; border-radius:999px;
  background:rgba(255,255,255,.06); border:1px solid rgba(255,255,255,.12); color:var(--dim)}

/* ─── empty + view transitions ─────────────────────────── */
.empty{display:none; text-align:center; padding:66px 24px 74px}
.empty.show{display:block; animation:fadein .25s var(--ease)}
.empty .ring{width:56px; height:56px; margin:0 auto 17px; border-radius:50%;
  border:1.5px dashed rgba(255,255,255,.24); display:grid; place-items:center;
  color:var(--dimmer); font-size:20px; background:rgba(255,255,255,.03)}
.empty h3{margin:0 0 6px; font-family:var(--display); font-size:17px; font-weight:700;
  letter-spacing:-.35px}
.empty p{margin:0; color:var(--dim); font-size:13.5px}
#dash:not(.hide), #alerts-panel:not(.hide){animation:viewin .22s var(--ease)}
@keyframes viewin{from{opacity:0; transform:translateY(7px)} to{opacity:1; transform:none}}

.hide{display:none}
@media (max-width:900px){
  .hide{display:none}
  .search{width:150px}
  main{padding:18px 12px 60px}
  .topbar{padding:10px 14px; gap:10px}
}
@media (prefers-reduced-motion:reduce){
  *{animation:none !important; transition:none !important}
}
</style></head><body>

<div id="stale-bar" hidden>↻ Dashboard updated — this tab is running old code.
  <button id="stale-go" onclick="location.reload()">refresh</button></div>
<div id="unlock" hidden>
  <div class="unlock-card">
    <div class="mark">◇</div>
    <h3>Locked</h3>
    <p>This console requires the service access token.</p>
    <input id="unlock-input" type="password" placeholder="access token" autocomplete="off">
    <button id="unlock-btn">Unlock</button>
    <div id="unlock-err" hidden></div>
  </div>
</div>

<header class="topbar">
  <div class="brand">
    <div class="mark" aria-hidden="true">
      <svg width="17" height="17" viewBox="0 0 24 24" fill="none">
        <path d="M12 2.6l7.4 2.9v6.1c0 4.55-3.14 8.03-7.4 9.2-4.26-1.17-7.4-4.65-7.4-9.2V5.5L12 2.6z"
              fill="url(#g1)"/>
        <path d="M8.6 12.3l2.4 2.4 4.4-4.8" stroke="#fff" stroke-width="2"
              stroke-linecap="round" stroke-linejoin="round"/>
        <defs><linearGradient id="g1" x1="4" y1="3" x2="20" y2="21">
          <stop stop-color="#0a84ff"/><stop offset="1" stop-color="#64d2ff"/>
        </linearGradient></defs>
      </svg>
    </div>
    <div class="title"><b>APT-CTI</b><span>Security Dashboard</span></div>
  </div>
  <div class="live" id="live" data-f="live" tabindex="0" role="button"
       title="Feed status — click for detail"><span class="dot"></span><span id="live-t">LIVE</span></div>
  <div class="live ai" id="ai-chip" data-f="nim" tabindex="0" role="button"
       title="AI explainability — click for detail" hidden><span class="dot"></span>✦ AI</div>
  <div class="live ml" id="ml-chip" data-f="ml" tabindex="0" role="button"
       title="How the ML trains and decides APT or not — click for the full pipeline"><span class="dot"></span><span id="ml-t">◆ ML</span></div>
  <div class="live apt idle" id="apt-chip" data-f="apt" tabindex="0" role="button"
       title="APT attribution notifications — click for detail"><span class="dot"></span><span id="apt-t">APT 0</span></div>
  <div class="spacer"></div>
  <div class="seg" id="vseg" role="tablist" aria-label="View">
    <button data-v="dash" class="on">Dashboard</button>
    <button data-v="alerts">Alerts</button>
  </div>
  <input class="search" id="q" type="search" placeholder="Filter IP, reason, technique…" autocomplete="off">
  <div class="seg" id="seg" role="tablist" aria-label="Rows">
    <button data-n="50">50</button>
    <button data-n="100" class="on">100</button>
    <button data-n="250">250</button>
  </div>
</header>

<main>
  <section class="overview" aria-label="Top-level status">
    <div class="ov-head">
      <h2>Overview</h2>
      <span class="ov-sub">top-level status · click any card for detail</span>
    </div>
    <div class="stats stats-hero">
      <div class="stat click hero" data-f="all" tabindex="0" role="button">
        <div class="k">Alerts</div><div class="v orange" id="s-alerts">0</div>
        <div class="c" id="s-alerts-c">fired this session · view all</div></div>
      <div class="stat click hero" data-f="recent" tabindex="0" role="button">
        <div class="k">Last 5 min</div><div class="v" id="s-rate">0</div>
        <div class="c" id="s-rate-c">velocity · new alerts</div></div>
      <div class="stat click hero" data-f="ioc" tabindex="0" role="button">
        <div class="k">IoC hits</div><div class="v amber" id="s-iochits">0</div>
        <div class="c" id="s-iochits-c">alerts on flagged IoCs</div></div>
      <div class="stat click hero" data-f="apt" tabindex="0" role="button">
        <div class="k">APT attributed</div><div class="v red" id="s-apt">0</div>
        <div class="c" id="s-apt-c">notifications · view</div></div>
    </div>
    <div class="stats stats-meta">
      <div class="stat click" data-f="profile" tabindex="0" role="button">
        <div class="k">Profile</div><div class="v sm" id="s-profile">–</div>
        <div class="c" id="s-profile-c">model bundle</div></div>
      <div class="stat click" data-f="theta" tabindex="0" role="button">
        <div class="k">Threshold θ</div><div class="v blue" id="s-theta">–</div>
        <div class="c">score ≥ θ fires an alert</div></div>
      <div class="stat click" data-f="flows" tabindex="0" role="button">
        <div class="k">Flows scored</div><div class="v" id="s-flows">0</div>
        <div class="c" id="s-flows-c">this session</div></div>
      <div class="stat click" data-f="iocs" tabindex="0" role="button">
        <div class="k">Feed IoCs</div><div class="v green" id="s-iocs">–</div>
        <div class="c" id="s-iocs-c">in memory · explore</div></div>
      <div class="stat click" data-f="synced" tabindex="0" role="button">
        <div class="k">Feeds synced</div><div class="v sm" id="s-sync">–</div>
        <div class="c" id="s-sync-c">live feeds</div></div>
    </div>
  </section>

  <div class="dash" id="dash">
    <section class="panel" id="p-timeline">
      <div class="panel-head">
        <h2>Threat Activity</h2>
        <span class="bpm" id="hb-bpm" title="heartbeat: alerts in the current minute">
          <svg width="15" height="10" viewBox="0 0 16 11" fill="none" aria-hidden="true">
            <path d="M0 6h3.2l1.7-4.4L7.6 9.8l1.9-5 1.4 2.2H16" stroke="currentColor"
                  stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
          <b id="hb-bpm-n">0</b><span>/min</span>
        </span>
        <span class="panel-sub" id="tl-sum">last 15 min · click a bar</span>
      </div>
      <div class="hbzone" id="hbzone">
        <svg id="hb-svg" viewBox="0 0 600 58" preserveAspectRatio="none" aria-hidden="true">
          <defs><linearGradient id="hbg" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0" stop-color="#30d158"/>
            <stop offset=".72" stop-color="#64d2ff"/>
            <stop offset="1" stop-color="#0a84ff"/>
          </linearGradient></defs>
          <path id="hb-path" d="" fill="none" stroke="url(#hbg)" stroke-width="2"
                vector-effect="non-scaling-stroke" stroke-linejoin="round"
                stroke-linecap="round"/>
          <circle id="hb-dot" r="3.2" cx="-10" cy="-10" fill="#fff" opacity="0"/>
        </svg>
        <div class="tl" id="tl"></div>
        <div class="tl-axis"><span>−15m</span><span>−10m</span><span>−5m</span><span>now</span></div>
      </div>
    </section>
    <section class="panel" id="p-score">
      <div class="panel-head"><h2>Score Distribution</h2>
        <span class="panel-sub">click a band to inspect</span></div>
      <div style="padding:12px 18px 16px" id="hist"></div>
    </section>
    <section class="panel" id="p-proto">
      <div class="panel-head"><h2>Protocol Mix</h2>
        <span class="panel-sub">click to filter</span></div>
      <div style="padding:14px 18px 18px">
        <div class="stack" id="stack"></div>
        <div class="legend" id="proto-legend"></div>
      </div>
    </section>
    <section class="panel" id="p-feed">
      <div class="panel-head"><h2>Intelligence Feeds</h2>
        <span class="panel-sub" id="feed-rec">–</span></div>
      <div style="padding:14px 18px 18px" id="feed-body"></div>
    </section>
    <section class="panel" id="p-tactics">
      <div class="panel-head"><h2>ATT&amp;CK Tactics</h2>
        <span class="panel-sub">top reason · click to filter</span></div>
      <div style="padding:10px 16px 16px" id="tactic-bars"></div>
    </section>
    <section class="panel" id="p-dst">
      <div class="panel-head"><h2>Top Targets</h2>
        <span class="panel-sub">click to filter</span></div>
      <div style="padding:8px 16px 14px" id="dst-list"></div>
    </section>
    <section class="panel" id="p-apt">
      <div class="panel-head"><h2>Top APT Groups</h2>
        <span class="panel-sub" id="apt-sum">attributed notifications</span></div>
      <div id="apt-bars"></div>
    </section>
  </div>

  <section class="panel hide" id="alerts-panel">
    <div class="panel-head">
      <h2>Alerts</h2>
      <span class="count" id="count">…</span>
      <span class="fpills" id="fpills"></span>
    </div>
    <div class="tbl-wrap">
      <table>
        <thead><tr>
          <th>Time</th><th>Score</th><th class="col-wide">Flow</th><th>Top reason</th>
          <th class="col-wide">ATT&amp;CK</th><th class="col-wide">Attribution</th><th>IoC</th>
        </tr></thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
    <div class="empty" id="empty">
      <div class="ring">◇</div>
      <h3>No alerts yet</h3>
      <p>Waiting for score ≥ <span id="e-theta">θ</span> — feed the sensor file and alerts will stream in.</p>
    </div>
  </section>
</main>

<div id="ins-scrim" hidden></div>
<aside id="insight" role="dialog" aria-modal="true" aria-labelledby="ins-title" hidden>
  <div class="ins-grip"></div>
  <div class="ins-head">
    <div style="min-width:0">
      <span class="ins-badge" id="ins-badge">–</span>
      <h3 id="ins-title">–</h3>
      <p id="ins-metric">–</p>
    </div>
    <button id="ins-close" aria-label="Close">✕</button>
  </div>
  <div class="ins-body">
    <div class="ins-sec">What this shows</div>
    <div id="ins-body"></div>
    <div class="ins-sec why">Why it matters</div>
    <div id="ins-why"></div>
  </div>
  <div class="ins-foot">
    <button class="ins-cta" id="ins-cta">Show alerts</button>
    <span class="ins-note" id="ins-note"></span>
    <span class="ins-prov" id="ins-prov"></span>
  </div>
</aside>

<div id="an-scrim" hidden></div>
<section id="analysis" role="dialog" aria-modal="true" aria-label="Deep analysis" hidden>
  <header class="an-head">
    <div class="an-id">
      <span class="ins-badge">deep analysis</span>
      <h3 id="an-title">–</h3>
      <p id="an-sub">–</p>
    </div>
    <div class="an-score">
      <svg viewBox="0 0 84 84" aria-hidden="true">
        <defs><linearGradient id="angr" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stop-color="#ff9f0a"/><stop offset="1" stop-color="#ff453a"/>
        </linearGradient></defs>
        <circle class="rbg" cx="42" cy="42" r="35"/>
        <circle class="rfg" id="an-ring" cx="42" cy="42" r="35"/>
      </svg>
      <div class="an-num"><b id="an-score-n">–</b><i>score</i></div>
    </div>
    <button id="an-close" aria-label="Close">✕</button>
  </header>
  <div class="an-meter">
    <div class="an-mrow"><span>threshold <b id="an-theta">θ</b></span>
      <span id="an-above">–</span></div>
    <div class="an-track"><span class="an-fill" id="an-fill"></span>
      <span class="an-mark"></span></div>
    <div class="an-scale"><span id="an-lo">θ</span><span>1.000</span></div>
  </div>
  <div class="an-body" id="an-body"></div>
  <footer class="an-foot">
    <button class="an-ghost" id="an-p-src">Pivot: source IP</button>
    <button class="an-ghost" id="an-p-dst">Pivot: destination IP</button>
    <span class="ins-prov" id="an-prov">–</span>
  </footer>
</section>

<div id="mp-scrim" hidden></div>
<section id="mlpipe" role="dialog" aria-modal="true" aria-label="ML pipeline" hidden>
  <header class="mp-head">
    <div>
      <h2>ML Pipeline</h2>
      <span class="mp-sub">train → detect → attribute · live from the model bundle and current alerts</span>
    </div>
    <button id="mp-close" aria-label="Close">✕</button>
  </header>
  <div class="mp-body" id="mp-body"></div>
  <footer class="mp-foot">
    <button class="an-ghost" data-f="ml-text">Detailed explanation</button>
    <span class="ins-prov" id="mp-prov">–</span>
  </footer>
</section>

<div id="ap-scrim" hidden></div>
<section id="aptpipe" role="dialog" aria-modal="true" aria-label="APT attribution pipeline" hidden>
  <header class="mp-head">
    <div>
      <h2>APT Attribution</h2>
      <span class="mp-sub">evidence → candidate ranking → notify gates → verdict · live from current alerts</span>
    </div>
    <button id="ap-close" aria-label="Close">✕</button>
  </header>
  <div class="mp-body" id="ap-body"></div>
  <footer class="mp-foot">
    <button class="an-ghost" id="ap-cta">Show notified alerts →</button>
    <span class="ins-prov" id="ap-prov">–</span>
  </footer>
</section>

<div id="fp-scrim" hidden></div>
<section id="feedpipe" role="dialog" aria-modal="true" aria-label="Live feed pipeline" hidden>
  <header class="mp-head">
    <div>
      <h2>Live Intelligence Feeds</h2>
      <span class="mp-sub">poll → extract → dedupe → freshness → fusion · live feed health</span>
    </div>
    <button id="fp-close" aria-label="Close">✕</button>
  </header>
  <div class="mp-body" id="fp-body"></div>
  <footer class="mp-foot">
    <button class="an-ghost" id="fp-cta">Show IoC-hit alerts →</button>
    <span class="ins-prov" id="fp-prov">–</span>
  </footer>
</section>

<div id="dw-scrim" hidden></div>
<section id="deep" role="dialog" aria-modal="true" aria-label="KPI deep dive" hidden>
  <header class="mp-head">
    <div>
      <h2 id="dw-title">–</h2>
      <span class="mp-sub" id="dw-sub">–</span>
    </div>
    <button id="dw-close" aria-label="Close">✕</button>
  </header>
  <div class="mp-body" id="dw-body"></div>
  <footer class="mp-foot">
    <button class="an-ghost" id="dw-cta" hidden>Show →</button>
    <span class="ins-prov" id="dw-prov">–</span>
  </footer>
</section>

<div id="ai-scrim" hidden></div>
<section id="aipipe" role="dialog" aria-modal="true" aria-label="AI explainability pipeline" hidden>
  <header class="mp-head">
    <div>
      <h2>AI Explainability</h2>
      <span class="mp-sub">SHAP reason codes → explicit request → payload gates → analyst brief</span>
    </div>
    <button id="ai-close" aria-label="Close">✕</button>
  </header>
  <div class="mp-body" id="ai-body"></div>
  <footer class="mp-foot">
    <button class="an-ghost" data-f="ml">See where SHAP comes from →</button>
    <span class="ins-prov" id="ai-prov">–</span>
  </footer>
</section>

<script>
let data=[], openId=null, anAlert=null, limit=100, xaiOn=false, st={}, view='dash';
const expl=new Map(), errz=new Map(), loading=new Set();
const $=id=>document.getElementById(id);
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const hhmmss=ts=>new Date(ts*1000).toISOString().slice(11,19);
const relTs=ts=>{const d=Math.max(0,Date.now()/1000-(+ts||0));
  return d<5?'just now':d<60?Math.floor(d)+'s ago'
    :d<3600?Math.floor(d/60)+'m ago':Math.floor(d/3600)+'h ago';};
const num=v=>Number.isFinite(+v)?(+v).toFixed(3):esc(v);

/* ─── auth (unlock) ─────────────────────────────────────── */
const TK=()=>{try{return sessionStorage.getItem('apt_token')||''}catch(e){return ''}};
const setTK=t=>{try{sessionStorage.setItem('apt_token',t)}catch(e){}};
(function(){const m=location.search.match(/[?&]token=([^&]+)/);
  if(m){try{setTK(decodeURIComponent(m[1]))}catch(e){}}})();
function needUnlock(){
  const u=$('unlock'); if(!u.hidden) return;
  u.hidden=false; $('unlock-err').hidden=true;
  $('unlock-input').value=''; $('unlock-input').focus();
}
async function jfetch(url,opts){
  opts=opts||{}; opts.headers=opts.headers||{};
  const t=TK(); if(t) opts.headers['X-Auth-Token']=t;
  const r=await fetch(url,opts);
  if(r.status===401){const e=new Error('auth required'); e.auth=true; throw e;}
  return r;
}
async function tryUnlock(){
  const t=$('unlock-input').value.trim();
  if(!t){$('unlock-err').hidden=false; $('unlock-err').textContent='Enter the access token'; return;}
  setTK(t);
  try{
    const r=await fetch('/__status',{cache:'no-store',headers:{'X-Auth-Token':t}});
    if(r.status===401) throw new Error('Incorrect token');
    if(!r.ok) throw new Error('HTTP '+r.status);
    $('unlock').hidden=true;
    poll();
  }catch(e){
    try{sessionStorage.removeItem('apt_token')}catch(_){}
    $('unlock-err').hidden=false;
    $('unlock-err').textContent=e.message||'Unlock failed';
  }
}

async function poll(){
  try{
    st=await (await jfetch('/__status',{cache:'no-store'})).json();
    $('s-profile').textContent=st.profile||'–';
    $('s-theta').textContent=(+st.theta).toFixed(4);
    $('e-theta').textContent=(+st.theta).toFixed(4);
    $('s-flows').textContent=(st.flows_scored??0).toLocaleString();
    $('s-alerts').textContent=(st.alerts??0).toLocaleString();
    $('s-iocs').textContent=(st.feed_indicators??0).toLocaleString();
    const t=(st.feed_updated_at||'').slice(11,19);
    $('s-sync').textContent=t?t+' UTC':'–';
    $('s-sync-c').textContent=st.feed_error?'feed error · check logs'
      :(st.feed_mode==='online'?'live · every '+(st.poll_interval_min||5)+' min'
        :'offline corpus');
    $('s-flows-c').textContent=(st.batches||0).toLocaleString()+' batches · session';
    $('s-profile-c').textContent=(st.n_features||38)+' features · model bundle';
    $('s-iocs-c').textContent=(st.feed_sources||[]).length
      ? (st.feed_sources||[]).length+' sources · click to explore'
      : 'first poll pending · explore';
    const live=$('live');
    if(st.feed_error){live.classList.add('off'); $('live-t').textContent='FEED ERR'}
    else{live.classList.remove('off'); $('live-t').textContent='LIVE'}
    xaiOn=!!(st.xai&&st.xai.enabled);
    $('ai-chip').hidden=!xaiOn;
    const mlOk=!!st.model;
    $('ml-t').textContent='◆ ML '+(mlOk?((+st.model.theta||+st.theta||0).toFixed(4)):'–');
    $('ml-chip').classList.toggle('idle',!mlOk);
    const mb=document.querySelector('meta[name=app-build]').content;
    if(mb&&mb!=='__BUILD__'&&st.build&&String(st.build)!==String(mb))
      $('stale-bar').hidden=false;
    data=(await (await jfetch('/api/alerts?limit='+limit,{cache:'no-store'})).json())||[];
    if(aptSeen===null){                       // first load: seed, don't spam toasts
      aptSeen=new Set();
      for(const a of data) if(a.attribution&&a.attribution.notify) aptSeen.add(a.alert_id);
    }else{
      const fresh=[];
      for(const a of data){
        const at=a.attribution;
        if(at&&at.notify&&!aptSeen.has(a.alert_id)){aptSeen.add(a.alert_id); fresh.push(a);}
      }
      for(const a of fresh.slice(0,3)) toastApt(a);
    }
    render();
    renderDash();
    const wins=[['deep','dw-body'],['aipipe','ai-body'],['mlpipe','mp-body'],['aptpipe','ap-body'],['feedpipe','fp-body']];
    for(const [wid,bid] of wins){
      if($(wid).hidden) continue;
      const ae=document.activeElement;
      if(!(ae&&$(bid).contains(ae))){
        if(wid==='deep'){ if(dwKey) openDeep(dwKey,true); }
        else if(wid==='mlpipe') openMlPipe(true);
        else if(wid==='aptpipe') openAptPipe(true);
        else openFeedPipe(true);
      }
      break;
    }
  }catch(e){
    if(e&&e.auth){needUnlock(); $('live').classList.add('off');
      $('live-t').textContent='LOCKED'; return;}
    $('live').classList.add('off'); $('live-t').textContent='OFFLINE';
  }
}

/* ─── dashboard ─────────────────────────────────────────── */
let hbTl=[], hbMin=[], hbMeta=[], hbLastSum=null, hbStarted=false;
let aptSeen=null;

function toastApt(a){
  const at=a.attribution||{}, who=(at.actor&&at.actor.name)||'APT activity';
  let el=document.getElementById('apt-toast');
  if(!el){
    el=document.createElement('div');
    el.id='apt-toast'; el.className='apt-toast'; el.setAttribute('role','alert');
    el.onclick=()=>{el.classList.remove('show'); openAnalysis(a);};
    document.body.appendChild(el);
  }
  el.innerHTML='<b>APT ALERT · NOTIFICATION</b><span>'+esc(who)+'</span>'
    +'<small>'+esc(a.alert_id)+' · confidence '
    +(at.confidence!=null?(+at.confidence).toFixed(2):'–')+' · click to open</small>';
  clearTimeout(toastApt._t);
  el.classList.add('show');
  toastApt._t=setTimeout(()=>el.classList.remove('show'),9000);
}

function blankF(){return {minute:null, proto:'', score:null, ioc:false, recent:false, apt:false};}
let filt=blankF(), insFilt=null;

function ecgD(tl){
  const W=600, H=58, mid=42, seg=W/15, max=Math.max(1,...tl);
  let d='M 0 '+mid;
  for(let i=0;i<15;i++){
    const c=tl[i]||0, x0=i*seg;
    if(!c){d+=` L ${(x0+seg).toFixed(1)} ${mid}`; continue;}
    const A=9+(c/max)*27;
    d+=` L ${(x0+seg*.16).toFixed(1)} ${mid}`
     + ` L ${(x0+seg*.25).toFixed(1)} ${(mid-A*.16).toFixed(1)}`
     + ` L ${(x0+seg*.33).toFixed(1)} ${(mid+A*.12).toFixed(1)}`
     + ` L ${(x0+seg*.44).toFixed(1)} ${(mid-A).toFixed(1)}`
     + ` L ${(x0+seg*.53).toFixed(1)} ${(mid+A*.26).toFixed(1)}`
     + ` L ${(x0+seg*.62).toFixed(1)} ${mid}`
     + ` L ${(x0+seg*.76).toFixed(1)} ${(mid-A*.34).toFixed(1)}`
     + ` L ${(x0+seg).toFixed(1)} ${mid}`;
  }
  return d;
}

function startHB(){
  if(hbStarted) return;
  const p=$('hb-path');
  if(typeof p.getTotalLength!=='function') return;   // jsdom: static path only
  hbStarted=true;
  const step=()=>{
    requestAnimationFrame(step);
    try{
      const L=p.getTotalLength();
      if(!L){$('hb-dot').setAttribute('opacity','0'); return;}
      const t=(performance.now()/2800)%1;
      const pt=p.getPointAtLength(t*L);
      $('hb-dot').setAttribute('cx',pt.x);
      $('hb-dot').setAttribute('cy',pt.y);
      $('hb-dot').setAttribute('opacity','1');
    }catch(e){}
  };
  requestAnimationFrame(step);
}

function minuteLabel(k){return hhmmss(k*60).slice(0,5)+' UTC';}

function renderDash(){
  const now=Math.floor(Date.now()/1000);
  let hits=0, recent=0, aptN=0;
  const tl=new Array(15).fill(0);
  const curMin=Math.floor(now/60);
  const minuteKey=[];
  for(let i=0;i<15;i++) minuteKey[i]=curMin-(14-i);
  const meta=[];
  for(let i=0;i<15;i++) meta[i]={ioc:0, proto:{}, tac:{}};
  for(const a of data){
    const c=a.cti||{};
    const ioc=(c.ioc_src_match||0)>0||(c.ioc_dst_match||0)>0;
    if(ioc) hits++;
    if(a.attribution&&a.attribution.notify) aptN++;
    const ts=+(a.flow&&a.flow.ts)||0;
    if(now-ts<=300) recent++;
    /* bucket by absolute minute so the bar's minute key always equals
       floor(ts/60) — otherwise ±1 s rounding breaks the click-through filter */
    const i=14-(curMin-Math.floor(ts/60));
    if(i>=0&&i<15){
      tl[i]++;
      if(ioc) meta[i].ioc++;
      const p=String((a.flow&&a.flow.proto)||'?').toLowerCase();
      meta[i].proto[p]=(meta[i].proto[p]||0)+1;
      const r=(a.reasons||[]).find(x=>x.feature&&!String(x.feature).startsWith('ioc_'))
            ||(a.reasons||[])[0];
      if(r&&r.tactic) meta[i].tac[r.tactic]=(meta[i].tac[r.tactic]||0)+1;
    }
  }
  hbTl=tl; hbMin=minuteKey; hbMeta=meta;
  $('s-iochits').textContent=hits.toLocaleString();
  $('s-iochits-c').textContent=hits+' of '+data.length+' in view · ★ = IoC';
  $('s-rate').textContent=recent.toLocaleString();
  $('s-rate-c').textContent=recent+' in last 5 min · velocity';
  $('s-apt').textContent=aptN.toLocaleString();
  $('apt-t').textContent='APT '+aptN.toLocaleString();
  $('apt-chip').classList.toggle('idle',aptN===0);
  const max=Math.max(1,...tl);
  $('tl').innerHTML=tl.map((c,i)=>
    `<div class="tb${c?' on':''}${filt.minute!=null&&filt.minute===minuteKey[i]?' sel':''}"`
    + ` style="height:${c?Math.max(8,Math.round(c/max*100)):4}%" data-i="${i}" data-n="${c}"`
    + ` tabindex="0" role="button"`
    + ` title="${minuteLabel(minuteKey[i])} · ${c} alert(s)"></div>`).join('');
  const sum15=tl.reduce((a,b)=>a+b,0);
  $('tl-sum').textContent=sum15?`${sum15} alerts · 15 min · click a bar`:'no recent alerts · click a bar';
  $('s-rate-c').textContent=sum15
    ? (recent/(sum15/3)).toFixed(1)+'× the 15-min average'
    : 'no 15-min baseline yet';
  /* heartbeat: same data as an ECG trace + per-minute readout */
  $('hb-path').setAttribute('d', ecgD(tl));
  $('hb-bpm-n').textContent=String(tl[14]||0);
  $('hb-bpm').classList.toggle('idle', !tl[14]);
  if(sum15!==hbLastSum){
    if(hbLastSum!==null){
      const z=$('hbzone'); z.classList.remove('beat'); void z.offsetWidth; z.classList.add('beat');
    }
    hbLastSum=sum15;
  }
  startHB();

  const th=+(st.theta)||0.85, nb=5, step=(1-th)/nb;
  const counts=new Array(nb).fill(0);
  for(const a of data){
    const s=+a.score;
    if(s<th) continue;
    counts[Math.min(nb-1,Math.floor((s-th)/step))]++;
  }
  const cmax=Math.max(1,...counts);
  $('hist').innerHTML=counts.map((c,i)=>{
    const lo=th+i*step;
    const sel=filt.score&&Math.abs(filt.score[0]-lo)<1e-9?' sel':'';
    return `<div class="hb click${sel}" data-i="${i}" data-lo="${lo}" data-hi="${lo+step}"`
      + ` data-n="${c}" tabindex="0" role="button"`
      + ` title="score ${lo.toFixed(2)}–${(lo+step).toFixed(2)}: ${c}">`+
      `<span class="lbl">${lo.toFixed(2)}–${(lo+step).toFixed(2)}</span>`+
      `<div class="track"><div class="fill" style="width:${c?Math.round(c/cmax*100):0}%"></div></div>`+
      `<span class="val">${c}</span></div>`;
  }).join('');

  const PAL={tcp:'#0a84ff',udp:'#64d2ff',icmp:'#ff9f0a',icmp6:'#ff9f0a'};
  const EXTRA=['#30d158','#bf5af2','#ffd60a','#ff453a'];
  const pr={};
  for(const a of data){
    const p=String((a.flow&&a.flow.proto)||'?').toLowerCase();
    pr[p]=(pr[p]||0)+1;
  }
  const prEnt=Object.entries(pr).sort((x,y)=>y[1]-x[1]);
  const prTotal=prEnt.reduce((s,e)=>s+e[1],0);
  if(prTotal){
    let k=0;
    $('stack').innerHTML=prEnt.map(([p,n])=>{
      const col=PAL[p]||EXTRA[k++%EXTRA.length];
      const sel=filt.proto===p?' sel':'';
      return `<div class="sseg${sel}" data-p="${esc(p)}"`
        + ` style="width:${(n/prTotal*100).toFixed(1)}%;background:${col}"`
        + ` title="${esc(p)} ${n} · click to filter"></div>`;
    }).join('');
    k=0;
    $('proto-legend').innerHTML=prEnt.map(([p,n])=>{
      const col=PAL[p]||EXTRA[k++%EXTRA.length];
      const sel=filt.proto===p?' sel':'';
      return `<div class="lg click${sel}" data-p="${esc(p)}" tabindex="0" role="button"`
        + ` title="filter: ${esc(p)}"><span class="sw" style="background:${col}"></span>`
        + `${esc(p)}<span class="n">${n}</span></div>`;
    }).join('');
  }else{
    $('stack').innerHTML='';
    $('proto-legend').innerHTML='<div class="ph">no alerts yet</div>';
  }

  const tac={};
  for(const a of data){
    const r=(a.reasons||[]).find(x=>x.feature&&!x.feature.startsWith('ioc_'))
          ||(a.reasons||[])[0];
    if(r&&r.tactic) tac[r.tactic]=(tac[r.tactic]||0)+1;
  }
  const tacEnt=Object.entries(tac).sort((x,y)=>y[1]-x[1]).slice(0,6);
  if(tacEnt.length){
    const tmax=tacEnt[0][1];
    $('tactic-bars').innerHTML=tacEnt.map(([t,n])=>
      `<div class="hb click" data-q="${esc(t)}" tabindex="0" role="button"`
      + ` title="explore: ${esc(t)}">`+
      `<span class="lbl">${esc(t)}</span>`+
      `<div class="track"><div class="fill tac" style="width:${Math.round(n/tmax*100)}%"></div></div>`+
      `<span class="val">${n}</span></div>`).join('');
  }else{
    $('tactic-bars').innerHTML='<div class="ph">no ATT&amp;CK tactics yet</div>';
  }

  const dst={}, dstIoc={};
  for(const a of data){
    const ip=a.flow&&a.flow.dst_ip; if(!ip) continue;
    dst[ip]=(dst[ip]||0)+1;
    const c=a.cti||{};
    if((c.ioc_src_match||0)>0||(c.ioc_dst_match||0)>0) dstIoc[ip]=1;
  }
  const dstEnt=Object.entries(dst).sort((x,y)=>y[1]-x[1]).slice(0,6);
  if(dstEnt.length){
    $('dst-list').innerHTML=dstEnt.map(([ip,n])=>
      `<div class="dst" data-q="${esc(ip)}" tabindex="0" role="button"`
      + ` title="explore: ${esc(ip)}"><span class="ip">${esc(ip)}</span>`+
      (dstIoc[ip]?'<span class="star" title="IoC hit">★</span>':'')+
      `<span class="n">${n} hit${n>1?'s':''}</span></div>`).join('');
  }else{
    $('dst-list').innerHTML='<div class="ph">no alerts yet</div>';
  }

  const aptG={}, aptC={}; let nNot=0, nCand=0;
  for(const a of data){
    const at=a.attribution; if(!at||!at.actor) continue;
    if(at.notify){aptG[at.actor.name]=(aptG[at.actor.name]||0)+1; nNot++;}
    else if(at.verdict==='apt-candidate'){
      aptC[at.actor.name]=(aptC[at.actor.name]||0)+1; nCand++;
    }
  }
  const gE=Object.entries(aptG).sort((x,y)=>y[1]-x[1]);
  const cE=Object.entries(aptC).sort((x,y)=>y[1]-x[1]);
  $('apt-bars').innerHTML=(gE.length||cE.length)
    ? gE.map(([g,n])=>
        `<div class="agroup" data-g="${esc(g)}" tabindex="0" role="button"`
        + ` title="insight: ${esc(g)} — notified"><span>${esc(g)}</span>`
        + `<span class="agc">×${n}</span></div>`).join('')
      + cE.map(([g,n])=>
        `<div class="agroup cand" data-g="${esc(g)}" tabindex="0" role="button"`
        + ` title="insight: ${esc(g)} — candidate, not notified"><span>${esc(g)}</span>`
        + `<span class="agc">×${n}</span></div>`).join('')
      + `<span class="agsum">${nNot} notified · ${nCand} candidate(s) · `
        + `${gE.length+cE.length} group(s) in view</span>`
    : `<span class="ph">no APT notifications yet</span>`;
  $('apt-sum').textContent=gE.length
    ? `${nNot} notification${nNot===1?'':'s'} · ${gE.length} group${gE.length===1?'':'s'}`
    : 'none named yet';
  $('s-apt-c').textContent=nNot||nCand
    ? `${nNot} notified · ${nCand} candidate(s)`
    : 'no APT evidence in view';

  const online=st.feed_mode==='online';
  const t=(st.feed_updated_at||'').slice(11,19);
  let html=`<div class="feed-meta">`+
    `<span class="mode ${online?'on':'off'}">${online?'● LIVE POLLING':'◐ SNAPSHOT CORPUS'}</span>`+
    `<span>synced ${t?t+' UTC':'–'}</span>`+
    `<span>${(st.feed_records??0).toLocaleString()} indicators</span>`+
    `<span>every ${st.poll_interval_min??5} min</span></div>`;
  const srcs=st.feed_sources||[];
  if(online&&srcs.length){
    html+='<div class="fchips">'+srcs.map(s=>
      `<span class="fchip click ${s.ok?'ok':'bad'}" data-src="${esc(s.source)}"`
      + ` tabindex="0" role="button" title="${esc(s.error||s.url||'')} · click for detail">`+
      `<span class="mk">${s.ok?'✓':'✗'}</span><b>${esc(s.source)}</b>`+
      `<span class="sub">${s.ok?((s.n_records||0).toLocaleString()+' rec'
        +(s.error?' ⚠':''))
        :esc(String(s.error||'failed').slice(0,36))}</span></span>`).join('')+'</div>';
  }else if(online){
    html+='<div class="ph">polling — waiting for first refresh…</div>';
  }else{
    html+='<div class="ph">Offline corpus — set <b>feeds.online: true</b> in '+
          'deploy/config.yaml to poll live feeds.</div>';
  }
  if(st.feed_error){
    html+=`<div class="fchips" style="margin-top:10px"><span class="fchip bad">`+
      `<span class="mk">✗</span><b>error</b><span class="sub">${
        esc(String(st.feed_error).slice(0,70))}</span></span></div>`;
  }
  $('feed-body').innerHTML=html;
  $('feed-rec').textContent=(st.feed_records??0).toLocaleString()+' IoCs';
}

function setView(v){
  view=v;
  $('dash').classList.toggle('hide',v!=='dash');
  $('alerts-panel').classList.toggle('hide',v==='dash');
  $('seg').classList.toggle('hide',v==='dash');
  for(const b of $('vseg').children) b.classList.toggle('on',b.dataset.v===v);
  if(v==='dash') renderDash(); else render();
}

/* ─── deep-explainable insight sheet ──────────────────── */
function matchCount(f){
  const saveF=filt, saveQ=$('q').value;
  filt=Object.assign(blankF(), f||{});
  $('q').value=(f&&f.q)||'';
  const n=data.filter(matches).length;
  filt=saveF; $('q').value=saveQ;
  return n;
}

function openInsight(o){
  $('ins-badge').textContent=o.badge||'explore';
  $('ins-title').textContent=o.title||'';
  $('ins-metric').textContent=o.metric||'';
  $('ins-body').innerHTML=(o.what||[]).map(p=>`<p>${p}</p>`).join('');
  $('ins-why').innerHTML=(o.why||[]).map(p=>`<p>${p}</p>`).join('');
  $('ins-note').textContent=o.note||'';
  $('ins-prov').textContent=data.length
    ? `${data.length} alerts in view · ${new Date().toTimeString().slice(0,8)}`
    : 'no alerts in view';
  insFilt=o.filt||null;
  const cta=$('ins-cta');
  if(insFilt){
    const n=matchCount(insFilt);
    cta.hidden=n<=0;
    cta.textContent=`Show ${n} alert${n===1?'':'s'} →`;
  }else cta.hidden=true;
  $('ins-scrim').hidden=false;
  $('insight').hidden=false;
}

function closeInsight(){
  $('insight').hidden=true; $('ins-scrim').hidden=true; insFilt=null;
}

const TACTIC_INFO={
 'initial access':['How the adversary first gets in — phishing, exposed services, valid accounts, or supply-chain compromise.','The earliest stage you can block: email security, MFA, and patching internet-facing services pay off here.'],
 'execution':['Running attacker-controlled code: command scripts, PowerShell, LOLBins, scheduled tasks.','Execution is where prevention (application control, script constraints) is cheapest — before persistence lands.'],
 'persistence':['Surviving reboots and redeployments — services, run keys, implants, account manipulation.','Look for entries that outlive normal software installs; persistence is a strong signal of intent, not noise.'],
 'privilege escalation':['Gaining higher rights — token abuse, misconfiguration, credential overlap.','Escalation attempts often leave config-change artifacts; correlate with admin-level actions on the host.'],
 'defense evasion':['Hiding the activity — obfuscation, disabling security tooling, log tampering.','An alert with an evasion reason is telling you the behaviour was shaped to avoid exactly your controls.'],
 'credential access':['Stealing secrets — phishing, keylogging, LSASS dumps, brute force.','Credential theft converts one compromised host into lateral movement; treat as high urgency.'],
 'discovery':['Mapping the environment — shares, domain enumeration, network scanning.','Reconnaissance bursts often precede lateral movement; watch for one source touching many destinations.'],
 'lateral movement':['Moving host to host with stolen creds or remote services (RDP, SMB, WinRM).','East–west traffic between workstations/servers that normally never talks is a priority investigate signal.'],
 'collection':['Gathering data of interest before it leaves — staging, screen capture, file access.','Collection volume plus unusual destinations is the classic pre-exfiltration shape.'],
 'command and control':['Beaconing to attacker infrastructure — the channel that keeps a foothold alive.','Rare destinations, odd ports, or periodic DNS/UDP flows are the tell; the heartbeat spike + IoC match makes this urgent.'],
 'exfiltration':['Moving data out — large transfers, staged archives, alternate channels.','Large outbound flows to rare destinations, especially right after collection reasons, warrant immediate containment.'],
 'impact':['Disruption, destruction, or encryption — ransomware and wipers.','Impact-stage activity means the clock is already running; isolate and start recovery procedures.'],
 'reconnaissance':['Target research — scanning, harvesting, gathering victim information.','Usually external-facing noise until it correlates with a later internal alert.'],
 'resource development':['Building attack infrastructure — domains, certificates, payloads.','Early-stage infrastructure often appears in feeds before it is used; IoC matches here are predictive.']
};
const PROTO_INFO={
 tcp:['Reliable, connection-oriented traffic — most application sessions, C2 over HTTP(S), and data transfer ride on TCP.',
      'Watch for TCP flows to rare destinations or unusual ports; encrypted sessions still expose endpoints and timing.'],
 udp:['Connectionless and cheap to spoof — used by DNS, NTP, and covert channels alike.',
      'Bursty UDP to uncommon ports or long-lived low-volume UDP flows deserve a second look.'],
 icmp:['Diagnostics primitive that can also tunnel payloads or scout the network.',
      'ICMP is rare in normal application logs; periodic ICMP with payload size patterns can indicate tunneling.']
};
const FEED_INFO={
 urlhaus:['URLhaus (abuse.ch) tracks live malware-distribution URLs and the hosts serving them.',
       'A match ties a flow to a host actively observed serving malware — high signal for C2 and payload delivery.'],
 threatfox:['ThreatFox (abuse.ch) shares community IOC sightings (IPs, domains) within hours of collection.',
       'Fresh but noisier than curated intel — excellent for catching newly flagged infrastructure early.'],
 feodo:['Feodo Tracker (abuse.ch) follows botnet C2 infrastructure (Emotet, Dridex, Qakbot families) — IPs plus DGA domains.',
       'C2 IPs are the highest-value indicators here: any flow touching one is likely command traffic, not routine business.'],
 binarydefense:['BinaryDefense BAN — attacker IPs observed by their global honeypot/sensor network in near real time.',
       'Sensor-observed sources mean the IP actively connected somewhere; strong for brute-force and scanning correlation.'],
 emerging:['Emerging Threats compromised-ips — hosts confirmed compromised and used for malicious activity.',
       'A hit can mean your peer is compromised rather than hostile — still worth blocking or isolating at the edge.'],
 cins:['CINS Army — "badguys" sources that failed honesty tests across public web traffic (reputation-scored).',
       'High-confidence hostile sources; repeated hits from one subnet usually indicate scanning infrastructure.'],
 blocklist:['blocklist.de — fail2ban-style attacker IPs aggregated from IDS/ban feeds worldwide.',
       'Crowd-banned hosts doing noisy intrusion attempts; useful confirmation when several sources agree.'],
 ipsum:['IPsum — malicious IPs aggregated from 30+ public lists; the count column = how many lists flagged it.',
       'Breadth beats freshness here: an IP on many independent lists is almost certainly hostile.'],
 openphish:['OpenPhish — verified phishing URLs observed live (credential-harvest and payment-fraud pages).',
       'A URL match ties traffic to phishing delivery or click-through — pair with DNS/HTTP context for the victim side.'],
 certpl:['CERT.PL (NASK) — domains hosting malware distribution and exploit kits, curated by the national CERT.',
       'Nationally curated, low-noise domain set; a match is a strong takedown/block candidate.'],
 otx:['AlienVault OTX — crowdsourced threat pulses (requires API key).',
       'Wide coverage; pair with reputation and local context before prioritising.'],
 misp:['MISP instance attributes (requires URL + key).',
       'Your organisation’s own shared intelligence — the most contextually relevant source.']
};

function topEntries(o,k){
  return Object.entries(o||{}).sort((x,y)=>y[1]-x[1]).slice(0,k)
    .map(([kk,v])=>`${kk} (${v})`).join(', ')||'–';
}

function minuteInsight(i){
  const c=hbTl[i]||0, key=hbMin[i], m=hbMeta[i]||{ioc:0, proto:{}, tac:{}};
  const avg=hbTl.reduce((s,x)=>s+x,0)/15;
  const x=avg>0?(c/avg):0;
  const f={minute:key};
  const why=c===0
    ? ['Quiet minute — nothing crossed θ here. The heartbeat trace stays flat when no alerts fire.']
    : [`${c} alert${c===1?'':'s'}, <span class="hl">${x.toFixed(1)}×</span> the 15-minute average (${avg.toFixed(1)}). `
        +(x>=1.5?'A spike like this usually means a burst — C2 retries, a scan sweep, or a triggered script.'
          :x<0.5?'Below baseline — background level activity.'
          :'At baseline — steady, ongoing activity.'),
       `Leads: protocol ${esc(topEntries(m.proto,2))}, tactic ${esc(topEntries(m.tac,2))}`
        +(m.ioc?`; <span class="hl">★ ${m.ioc}</span> alert(s) matched live-feed IoCs.`:'. No IoC matches in this minute.')];
  openInsight({badge:'threat activity', title:'Minute '+minuteLabel(key),
    metric:`${c} alert${c===1?'':'s'} · ${x.toFixed(1)}× 15-min average`,
    what:['Alerts bucketed per minute from the alert log (score ≥ θ). The bars show volume; the <b>heartbeat line</b> renders the same rhythm as an ECG trace — each spike is one busy minute and its height scales with alert count.',
      'The <b>/min</b> readout in the panel header is the current minute’s beat — the live pulse of the environment.',
      'The button below filters the alert table to exactly this minute.'],
    why, filt:f, note:'filter: this minute'});
}

function histInsight(lo,hi,n){
  const th=+(st.theta)||0.85;
  const mid=(lo+hi)/2;
  const level=hi<=th+(1-th)*0.25?'low':(lo>=th+(1-th)*0.65?'high':'mid');
  const f={score:[lo,hi]};
  openInsight({badge:'score '+lo.toFixed(2)+'–'+hi.toFixed(2), title:'Score distribution band',
    metric:`${n} alert${n===1?'':'s'} in band`,
    what:[`Alerts are bucketed into 5 bands between θ = <span class="hl">${th.toFixed(4)}</span> and 1.0. The score is the RandomForest probability (live_netflow profile, 38 sensor features) calibrated so everything ≥ θ fires an alert (offline FPR 0.63 %).`,
      `Band center ≈ <span class="hl">${mid.toFixed(3)}</span>. Every alert’s detail lists its SHAP reason codes — the exact features and values that pushed the score.`],
    why:[level==='high'
        ? 'Most confident detections — review these first; several strong features agree, so they rarely cross θ by accident.'
        :level==='low'
        ? 'Just above threshold — often a single boundary feature. Check the reason cards: one weak feature plus an IoC match still matters.'
        : 'Middle confidence — typical when one strong behavioural feature dominates the score.',
      'Filtering by band lets you triage by confidence instead of clock order.'],
    filt:f, note:'filter: score band'});
}

function protoInsight(p){
  let n=0;
  for(const a of data) if(String((a.flow&&a.flow.proto)||'').toLowerCase()===p) n++;
  const total=data.length||1;
  const info=PROTO_INFO[p]||[`${esc(p.toUpperCase())} traffic among the alerted flows.`,
    'Protocol share helps judge whether activity looks like normal application traffic or something scripted.'];
  const f={proto:p};
  openInsight({badge:'protocol', title:String(p).toUpperCase(),
    metric:`${n} alert${n===1?'':'s'} · ${(n/total*100).toFixed(1)} % of view`,
    what:[info[0],`Stacked share above: ${esc(p)} is <span class="hl">${(n/total*100).toFixed(1)} %</span> of the ${total} alerts currently in view.`],
    why:[info[1],'Filter to this protocol to scan for odd ports or rare destinations riding the same transport.'],
    filt:f, note:'filter: protocol'});
}

function tacInsight(t){
  let n=0;
  for(const a of data){
    const r=(a.reasons||[]).find(x=>x.feature&&!String(x.feature).startsWith('ioc_'))
          ||(a.reasons||[])[0];
    if(r&&r.tactic===t) n++;
  }
  const info=TACTIC_INFO[String(t).toLowerCase()]||[
    `${esc(String(t))} behaviour was the top reason on these alerts (MITRE ATT&CK tactic).`,
    'Filtering groups the alerts where this tactic drove the score — read each reason card for the underlying technique.'];
  const f={q:t};
  openInsight({badge:'ATT&CK', title:String(t),
    metric:`${n} alert${n===1?'':'s'} led by this tactic`,
    what:[info[0],'Derived from each alert’s top non-IoC SHAP reason, mapped to its MITRE technique and tactic — see the ATT&CK column and reason cards per alert.'],
    why:[info[1],'Tactics trending in this panel show which phase of the kill chain your environment is currently touching.'],
    filt:f, note:'text search: tactic name'});
}

function dstInsight(ip){
  let n=0, ioc=0, first=0, last=0;
  const ports={}, protos={};
  for(const a of data){
    if((a.flow&&a.flow.dst_ip)!==ip) continue;
    n++;
    const c=a.cti||{};
    if((c.ioc_src_match||0)>0||(c.ioc_dst_match||0)>0) ioc++;
    ports[a.flow.dst_port]=(ports[a.flow.dst_port]||0)+1;
    const pr=String(a.flow.proto||'?').toLowerCase();
    protos[pr]=(protos[pr]||0)+1;
    const ts=+(a.flow.ts)||0;
    if(!first||ts<first) first=ts;
    if(ts>last) last=ts;
  }
  const f={q:ip};
  openInsight({badge:ioc?'★ IoC':'target', title:String(ip),
    metric:`${n} alert${n===1?'':'s'} · ${ioc} with live-feed IoC match`,
    what:[`Destination of the alerted flows — ports: <span class="hl">${esc(topEntries(ports,3))}</span>; protocols: <span class="hl">${esc(topEntries(protos,3))}</span>.`,
      `Activity window ${hhmmss(first)} → ${hhmmss(last)} UTC.`],
    why:[ioc
        ? 'This address appears in the live threat feeds (URLhaus / ThreatFox / Feodo) — model verdict and external intelligence agree, so treat hits here as top priority.'
        : 'No live-feed match for this address yet. A repeated destination can still indicate scanning or beaconing — correlate frequency with ports and duration.',
      'Use the button below to see every alert involving this destination.'],
    filt:f, note:'filter: destination IP'});
}

function aptGroupInsight(g){
  let nN=0, nC=0, ioc=0, csum=0;
  for(const a of data){
    const at=a.attribution;
    if(!at||!at.actor||at.actor.name!==g) continue;
    if(at.notify){nN++; csum+=(+at.confidence||0); if(at.ioc_backed) ioc++;}
    else if(at.verdict==='apt-candidate') nC++;
  }
  const avg=nN?(csum/nN):0;
  const f={q:g};
  openInsight({badge:'APT attribution', title:String(g),
    metric:`${nN} notified · ${nC} candidate(s)${nN?` · ${avg.toFixed(2)} avg confidence`:''}`,
    what:[`Alerts whose strongest evidence points at <b>${esc(g)}</b>: rarity-weighted ATT&amp;CK technique overlap plus TF-IDF retrieval against the 1,040-actor threat-actor corpus, corroborated by live-feed IoC matches (notify rule: IoC-backed or ≥ 2 independent technique hits + specificity gate).`,
      `IoC-corroborated: <span class="hl">${ioc}</span> of ${nN} notification(s). Open any alert for the full trail — technique hits, runner-up candidates, competitor counts, fallback category.`],
    why:['Netflow carries no ground-truth actor labels: verdicts are evidence-based candidates with stated competitors and confidence — never a claim of certainty.',
      'Filter below to review every alert naming this group; pivot on its IPs via the drill-down before sharing the attribution externally.'],
    filt:f, note:'text search: actor name'});
}

function feedInsight(src){
  const s=(st.feed_sources||[]).find(x=>x.source===src)||{};
  const info=FEED_INFO[src]||[`${esc(String(src))} threat-intelligence source, consumed by the CTI enrichment layer.`,
    'Indicators from this feed drive the ioc_src_match / ioc_dst_match features and the ★ markers.'];
  const f={ioc:true};
  openInsight({badge:s.ok===false?'warning':'feed', title:String(src),
    metric:(s.ok===false?'✗ ':'✓ ')+(s.n_records!=null?s.n_records.toLocaleString()+' records':'')
      +(s.duration_s!=null?' · '+s.duration_s+' s':''),
    what:[info[0],
      `Last poll <b>${s.ok===false?'FAILED':'ok'}</b>${s.error?': '+esc(String(s.error).slice(0,140)):''}.`
      + ` Records feed the in-memory IoC set (TTL ${st.ttl_hours||168} h, freshness half-life 6 h).`],
    why:[info[1],`Feeds refresh every ${st.poll_interval_min||5} minutes; a failed poll keeps the previous sightings — zero-record refreshes are rejected so an outage cannot wipe the IoC set.`],
    filt:f, note:'filter: IoC-correlated alerts'});
}

function closeMlPipe(){ $('mlpipe').hidden=true; $('mp-scrim').hidden=true; }

function openMlPipe(silent){
  const _sc=$('mp-body').scrollTop;
  if(!silent){ closeWins(); if(!$('insight').hidden) closeInsight(); }
  const md=st.model||{}, mt=md.meta||{}, tm=mt.test_metrics||{};
  const th=(+md.theta||+st.theta||0.8349);
  const nFeat=st.n_features||mt.n_features||38;
  const rows=mt.rows||0, nTest=tm.n||0, nTrain=Math.max(0,rows-nTest);
  const pc=(v,d)=>v!=null?(v*100).toFixed(d===undefined?2:d)+'%':'–';
  const num=v=>(v||0).toLocaleString();
  const np=v=>(+v||0).toFixed(2);
  let nNot=0, nCand=0, nNo=0;
  for(const a of data){
    const at=a.attribution; if(!at) continue;
    if(at.notify) nNot++;
    else if(at.verdict==='apt-candidate') nCand++;
    else nNo++;
  }
  const ex=data.find(a=>a.attribution&&a.attribution.notify)
        ||data.find(a=>a.attribution&&(a.attribution.candidates||[]).length)
        ||data[0]||null;
  const exAt=ex&&ex.attribution;
  const exC=exAt&&(exAt.candidates||[])[0];
  const exIoc=ex?(((ex.cti||{}).ioc_src_match||0)>0||((ex.cti||{}).ioc_dst_match||0)>0):false;
  const comb=exC?(+exC.score||0):0, ov=exC?(+exC.tech_overlap||0):0,
        retr=exC?(+exC.retrieval||0):0;
  const hits=exC?(exC.technique_hits||[]):[];
  const rivals=exAt?((exAt.candidates||[]).filter(c=>comb-(+c.score||0)<0.02).length):0;
  const gCorr=exIoc||(hits.length>=2&&ov>=0.7);
  const gOv=ov>=0.5, gComb=comb>=0.25, gSpec=rivals<=(exIoc?3:2);
  const exAct=exAt&&exAt.actor?exAt.actor.name:'–';
  const exVerd=exAt?(exAt.verdict||'–'):'no attribution yet';
  const spec=new Array(12).fill(0);
  let sMin=null, sMax=null, sSum=0, sN=0;
  for(const a of data){
    const s=+(a.score); if(!isFinite(s)) continue;
    if(sMin===null||s<sMin) sMin=s;
    if(sMax===null||s>sMax) sMax=s;
    sSum+=s; sN++;
    let i=Math.floor((s-th)/((1-th)||1e-9)*12);
    if(!(i>=0)) i=0; if(i>11) i=11;
    spec[i]++;
  }
  const specMax=Math.max(1,...spec);
  const specHtml=spec.map(c=>
    `<div class="sb" style="height:0" data-h="${c?Math.max(6,Math.round(c/specMax*100)):3}%" data-n="${c}"></div>`).join('');
  const imp=(md.top_features||[]).slice(0,8);
  const impMax=imp.length?imp[0][1]:1;
  const impHtml=imp.map(x=>
    `<div class="mp-ibar"><span class="f">${esc(String(x[0]))}</span>`
    +`<span class="b"><span style="width:0" data-w="${Math.round(x[1]/impMax*100)}%"></span></span>`
    +`<span class="p">${(x[1]*100).toFixed(1)}%</span></div>`).join('');
  const gate=(ok,t,v)=>`<div class="mp-gate"><span class="mk ${ok?'y':'n'}">${ok?'✓':'✗'}</span>`
    +`<span>${t}<em>${v}</em></span></div>`;
  $('mp-body').innerHTML=`
  <div class="mp-stage">
    <div class="mp-stitle"><span class="n">1</span> Train — offline, once</div>
    <div class="mp-flow">
      <div class="mp-node"><b>UNSW-NB15</b><i>${num(rows)} raw flow records</i></div>
      <span class="mp-arrow">→</span>
      <div class="mp-node"><b>Design matrix</b><i>${nFeat} features · timing, volume, proto/service/state, 6 live-CTI</i></div>
      <span class="mp-arrow">→</span>
      <div class="mp-node hl"><b>RandomForest</b><i>${mt.n_estimators||200} trees · min leaf ${mt.min_samples_leaf??20} · seed ${mt.seed??42} · fit ~${mt.fit_seconds??'–'} s</i></div>
      <span class="mp-arrow">→</span>
      <div class="mp-node"><b>Held-out test</b><i>${num(nTest)} unseen flows · acc ${pc(tm.accuracy)}</i></div>
      <span class="mp-arrow">→</span>
      <div class="mp-node ok"><b>θ = ${th.toFixed(4)}</b><i>chosen for ≥ ${(100*(mt.target_recall||0.96)).toFixed(0)}% recall at ${pc(tm.fpr)} FPR</i></div>
      <span class="mp-arrow">→</span>
      <div class="mp-node"><b>…joblib artifact</b><i>deploy_live_netflow · retrain: scripts/train_artifact.py</i></div>
    </div>
    <div class="mp-grid mp-g2">
      <div class="mp-card"><h4>Train / test split + threshold axis</h4>
        <div class="mp-split"><span class="tr" style="width:0" data-w="80%">train ${num(nTrain)}</span><span class="te" style="width:0" data-w="20%">test ${num(nTest)}</span></div>
        <div class="mp-axis">
          <span class="mp-tlab" style="left:${(th*100).toFixed(2)}%">θ ${th.toFixed(4)}</span>
          <div class="mp-track"></div>
          <div class="mp-tmark" style="left:${(th*100).toFixed(2)}%"></div>
          <span class="mp-axl lo">score 0.0</span><span class="mp-axl hi">≥ θ → alert</span>
        </div>
      </div>
      <div class="mp-card"><h4>Confusion matrix — held-out ${num(nTest)}</h4>
        <div class="mp-cm">
          <div class="tp"><b>${num(tm.tp)}</b><i>true positive</i></div>
          <div class="fn"><b>${num(tm.fn)}</b><i>missed attack</i></div>
          <div class="fp"><b>${num(tm.fp)}</b><i>false alarm</i></div>
          <div class="tn"><b>${num(tm.tn)}</b><i>true negative</i></div>
        </div>
      </div>
    </div>
    <div class="mp-card"><h4>What the model buys</h4>
      <div class="mp-kpis">
        <div class="mp-kpi g"><b>${pc(tm.accuracy)}</b><i>accuracy</i></div>
        <div class="mp-kpi g"><b>${pc(tm.recall,1)}</b><i>recall</i></div>
        <div class="mp-kpi b"><b>${pc(tm.precision)}</b><i>precision</i></div>
        <div class="mp-kpi a"><b>${pc(tm.fpr)}</b><i>false-positive rate</i></div>
        <div class="mp-kpi v"><b>${tm.roc_auc!=null?tm.roc_auc.toFixed(4):'–'}</b><i>ROC-AUC</i></div>
        <div class="mp-kpi r"><b>${num(tm.n_alerts)}</b><i>alerts on test set</i></div>
      </div>
    </div>
  </div>

  <div class="mp-stage">
    <div class="mp-stitle"><span class="n">2</span> Detect — live, per flow</div>
    <div class="mp-flow">
      <div class="mp-node"><b>Flow</b><i>tail of live netflow / Zeek / EVE records</i></div>
      <span class="mp-arrow">→</span>
      <div class="mp-node"><b>${nFeat} features</b><i>design() encodes numeric + categorical + CTI</i></div>
      <span class="mp-arrow">→</span>
      <div class="mp-node hl"><b>predict_proba</b><i>forest votes → one score 0..1</i></div>
      <span class="mp-arrow">→</span>
      <div class="mp-node warn"><b>score ≥ θ ?</b><i>below θ: ignore · at/above θ: escalate</i></div>
      <span class="mp-arrow">→</span>
      <div class="mp-node ok"><b>Alert + TreeSHAP</b><i>reason codes, ATT&amp;CK mapping, CTI features</i></div>
    </div>
    <div class="mp-grid mp-g2">
      <div class="mp-card"><h4>Live alert scores vs θ</h4>
        <div class="mp-spec">${specHtml}</div>
        <div class="mp-speclab"><span>${sN?sMin.toFixed(3):'–'} → ${sN?sMax.toFixed(3):'–'}</span><span>avg ${sN?(sSum/sN).toFixed(3):'–'} · θ ${th.toFixed(4)}</span></div>
      </div>
      <div class="mp-card"><h4>Global feature importance (the forest)</h4>${impHtml||'<div class="mp-ex">not exposed by this bundle</div>'}</div>
    </div>
  </div>

  <div class="mp-stage">
    <div class="mp-stitle"><span class="n">3</span> APT or not — evidence gate, per alert</div>
    <div class="mp-ev">
      <div class="e"><b>① TF-IDF retrieval</b><i>cosine vs 1040-actor corpus<br>example: ${np(retr)}</i></div>
      <div class="e"><b>② Rarity-weighted overlap</b><i>shared ATT&amp;CK techniques — rare ones weigh more<br>example: ${np(ov)} (${hits.length} shared)</i></div>
      <div class="e"><b>③ IoC strength</b><i>live-feed source count × confidence<br>example: ${exIoc?'matched':'no match'}</i></div>
    </div>
    <div class="mp-flow">
      <div class="mp-node hl"><b>combined = 0.6·overlap + 0.4·retrieval</b><i>example: 0.6×${np(ov)} + 0.4×${np(retr)} = <b style="display:inline">${np(comb)}</b></i></div>
      <span class="mp-arrow">→</span>
      <div class="mp-node ${exAt&&exAt.notify?'ok':'warn'}"><b>notify gate — 4 conditions</b><i>all must pass → notification fires</i></div>
      <span class="mp-arrow">→</span>
      <div class="mp-node ${exAt&&exAt.notify?'ok':''}"><b>${esc(exVerd)}</b><i>example: ${esc(exAct)} · ${esc(ex?String(ex.alert_id):'–')}</i></div>
    </div>
    <div class="mp-card"><h4>Gate checklist — worked on a real alert</h4>
      <div class="mp-ex">${ex?`example = <b>${esc(exAt&&exAt.notify?'first notified alert':(exAt?'first alert with candidates':'top alert'))}</b> — verdict <b>${esc(exVerd)}</b>, actor <b>${esc(exAct)}</b>`:'no alerts loaded yet'}</div>
      <div class="mp-gates">
        ${gate(gCorr,'Corroboration — live IoC match, or ≥ 2 shared techniques with overlap ≥ 0.7',exIoc?`IoC match · ${hits.length} shared technique(s), overlap ${np(ov)}`:`no IoC · ${hits.length} shared technique(s), overlap ${np(ov)}`)}
        ${gate(gOv,'Technique overlap ≥ 0.50',`overlap ${np(ov)}`)}
        ${gate(gComb,'Combined evidence ≥ 0.25 (notification floor)',`combined ${np(comb)} = 0.6·${np(ov)} + 0.4·${np(retr)}`)}
        ${gate(gSpec,`Specificity — rivals within Δ 0.02 ≤ ${exIoc?3:2}`,`${rivals} rival(s) in the candidate table`)}
      </div>
      <div class="mp-verds">
        <div class="mp-verd red"><b>${nNot}</b><i>apt-attributed → notified</i><s>corroborated + specific enough to act on</s></div>
        <div class="mp-verd amb"><b>${nCand}</b><i>apt-candidate</i><s>plausible, listed without a ping</s></div>
        <div class="mp-verd grey"><b>${nNo}</b><i>not-apt</i><s>behavioural category fallback (7 rules)</s></div>
      </div>
    </div>
  </div>`;
  $('mp-body').scrollTop=_sc;
  $('mp-prov').textContent='bundle '+esc(md.profile||st.profile||'–')+' · updated '+hhmmss(Date.now()/1000)+' UTC';
  $('mp-scrim').hidden=false; $('mlpipe').hidden=false;
  const ap=()=>{
    document.querySelectorAll('#mp-body [data-w]').forEach(el=>{el.style.width=el.dataset.w;});
    document.querySelectorAll('#mp-body [data-h]').forEach(el=>{el.style.height=el.dataset.h;});
  };
  if(silent) ap(); else requestAnimationFrame(ap);
}

function closeAptPipe(){ $('aptpipe').hidden=true; $('ap-scrim').hidden=true; }

function openAptPipe(silent){
  const _sc=$('ap-body').scrollTop;
  if(!silent){ closeWins(); if(!$('insight').hidden) closeInsight(); }
  const nA=+(st.attribution&&st.attribution.n_actors)||0;
  const nTf=+(st.attribution&&st.attribution.n_features)||0;
  let nNot=0, nCand=0, nNo=0; const ccat={};
  for(const a of data){
    const at=a.attribution; if(!at) continue;
    if(at.notify) nNot++;
    else if(at.verdict==='apt-candidate') nCand++;
    else { nNo++; if(at.category) ccat[at.category]=(ccat[at.category]||0)+1; }
  }
  const ex=data.find(a=>a.attribution&&a.attribution.notify)
        ||data.find(a=>a.attribution&&(a.attribution.candidates||[]).length)
        ||data[0]||null;
  const exAt=ex&&ex.attribution;
  const cs=exAt?(exAt.candidates||[]):[];
  const top=cs[0];
  const comb=top?(+top.score||0):0, ov=top?(+top.tech_overlap||0):0,
        retr=top?(+top.retrieval||0):0;
  const hits=top?(top.technique_hits||[]):[];
  const ioc=exAt?!!exAt.ioc_backed:false;
  const rivals=exAt&&exAt.competitors!=null?+exAt.competitors
    :cs.filter(c=>comb-(+c.score||0)<0.02).length;
  const gCorr=ioc||(hits.length>=2&&ov>=0.7);
  const gOv=ov>=0.5, gComb=comb>=0.25, gSpec=rivals<=(ioc?3:2);
  const passAll=gCorr&&gOv&&gComb&&gSpec;
  const act=exAt&&exAt.actor?exAt.actor:null;
  const verdict=exAt?(exAt.verdict||'–'):'no attribution yet';
  const scoreMax=Math.max(0.001,...cs.map(c=>+c.score||0));
  const nAct=nA||(exAt&&exAt.model&&+exAt.model.n_actors)||1040;
  const candRows=cs.map((c,i)=>
    `<div class="mp-cand">
      <div class="mp-ibar"><span class="f">#${i+1} ${esc(c.name)} <span style="color:var(--dimmer);font-weight:400">${esc(c.mitre_id||'')}</span></span>`
      +`<span class="b"><span style="width:0" data-w="${Math.max(4,Math.round((+c.score||0)/scoreMax*100))}%"></span></span>`
      +`<span class="p">${(+c.score||0).toFixed(3)}</span></div>
      <div class="mp-cmeta"><span>retrieval ${(+c.retrieval||0).toFixed(3)}</span><span>·</span>`
      +`<span>overlap ${(+c.tech_overlap||0).toFixed(3)}</span>`
      +(c.technique_hits&&c.technique_hits.length?`<span>·</span>`
        +c.technique_hits.map(h=>`<span class="hit">${esc(h)}</span>`).join(''):'')
      +`</div></div>`).join('');
  const gate=(ok,t,v)=>`<div class="mp-gate"><span class="mk ${ok?'y':'n'}">${ok?'✓':'✗'}</span>`
    +`<span>${t}<em>${v}</em></span></div>`;
  const evList=(exAt&&exAt.evidence&&exAt.evidence.length)
    ?exAt.evidence.map(e=>`<div class="mp-ex">• ${esc(e)}</div>`).join('')
    :'<div class="mp-ex">no evidence recorded yet</div>';
  const techLine=(exAt&&exAt.techniques&&exAt.techniques.length)
    ?exAt.techniques.map(t=>`<span class="hit">${esc(t)}</span>`).join(' ')
    :'<span style="color:var(--dim)">none mapped</span>';
  const catEnt=Object.entries(ccat).sort((a,b)=>b[1]-a[1]);
  const catChips=catEnt.length?catEnt.map(([k,v])=>`<span>${esc(k)} ×${v}</span>`).join('')
    :'<span>none in view</span>';
  $('ap-body').innerHTML=`
  <div class="mp-stage">
    <div class="mp-stitle"><span class="n">1</span> Evidence extraction — per alert</div>
    <div class="mp-flow">
      <div class="mp-node"><b>Alert + SHAP reasons</b><i>why the forest fired — top non-IoC reason codes</i></div>
      <span class="mp-arrow">→</span>
      <div class="mp-node hl"><b>ATT&amp;CK techniques</b><i>reason codes → MITRE technique IDs · ${techLine}</i></div>
      <span class="mp-arrow">→</span>
      <div class="mp-node ${ioc?'ok':''}"><b>Live IoC feeds</b><i>${ioc?'source/destination matched feeds — corroboration':'no feed match on this example alert'}</i></div>
      <span class="mp-arrow">→</span>
      <div class="mp-node"><b>Rarity weighting</b><i>techniques shared by few groups weigh more</i></div>
    </div>
    <div class="mp-grid mp-g2">
      <div class="mp-card"><h4>Evidence bundle — example ${ex?esc(ex.alert_id):'–'}</h4>${evList}</div>
      <div class="mp-card"><h4>The three evidence sources</h4>
        <div class="mp-ev">
          <div class="e"><b>① TF-IDF retrieval</b><i>cosine similarity of alert text vs ${nAct.toLocaleString()}-actor corpus<br>example: ${retr.toFixed(3)}</i></div>
          <div class="e"><b>② Rarity-weighted overlap</b><i>shared ATT&amp;CK techniques — rare ones weigh more<br>example: ${ov.toFixed(3)} (${hits.length} shared)</i></div>
          <div class="e"><b>③ IoC strength</b><i>live-feed source count × confidence<br>example: ${ioc?'matched':'no match'}</i></div>
        </div>
      </div>
    </div>
  </div>

  <div class="mp-stage">
    <div class="mp-stitle"><span class="n">2</span> Candidate ranking — TF-IDF over the actor corpus</div>
    <div class="mp-card"><h4>Corpus + ranking — live</h4>
      <div class="mp-kpis">
        <div class="mp-kpi v"><b>${nAct.toLocaleString()}</b><i>threat actors</i></div>
        <div class="mp-kpi b"><b>${nTf?nTf.toLocaleString():'–'}</b><i>TF-IDF features</i></div>
        <div class="mp-kpi a"><b>${cs.length}</b><i>candidates · example</i></div>
        <div class="mp-kpi r"><b>${rivals}</b><i>rivals within Δ 0.02</i></div>
        <div class="mp-kpi g"><b>${nNot}</b><i>notified in view</i></div>
      </div>
    </div>
    <div class="mp-card" style="margin-top:12px"><h4>Ranked candidates — ${ex?esc(ex.alert_id):'–'} → ${esc(act?act.name:'no actor named')}</h4>
      ${candRows||'<div class="mp-ex">no attribution on this alert yet</div>'}
      <div class="mp-ex" style="margin:8px 0 0">bar = combined score (0.6·overlap + 0.4·retrieval) · retrieval = TF-IDF cosine · hit = shared ATT&amp;CK technique ID</div>
    </div>
  </div>

  <div class="mp-stage">
    <div class="mp-stitle"><span class="n">3</span> Score + notify gates — all four must pass</div>
    <div class="mp-flow">
      <div class="mp-node hl"><b>combined = 0.6·overlap + 0.4·retrieval</b><i>0.6×${ov.toFixed(3)} + 0.4×${retr.toFixed(3)} = <b style="display:inline">${comb.toFixed(3)}</b></i></div>
      <span class="mp-arrow">→</span>
      <div class="mp-node ${passAll?'ok':'warn'}"><b>4 notify gates</b><i>corroboration · overlap · floor · specificity</i></div>
      <span class="mp-arrow">→</span>
      <div class="mp-node ${exAt&&exAt.notify?'ok':''}"><b>${esc(verdict)}</b><i>${exAt?'example: '+esc(act?act.name:'–')+' · confidence '+(+((act&&act.confidence)||exAt.confidence)||0).toFixed(2):'no attribution yet'}</i></div>
    </div>
    <div class="mp-card"><h4>Gate checklist — worked on a real alert</h4>
      <div class="mp-gates">
        ${gate(gCorr,'Corroboration — live IoC match, or ≥ 2 shared techniques with overlap ≥ 0.7',ioc?`IoC match · ${hits.length} shared technique(s), overlap ${ov.toFixed(3)}`:`no IoC · ${hits.length} shared technique(s), overlap ${ov.toFixed(3)}`)}
        ${gate(gOv,'Technique overlap ≥ 0.50',`overlap ${ov.toFixed(3)}`)}
        ${gate(gComb,'Combined evidence ≥ 0.25 (notification floor)',`combined ${comb.toFixed(3)} = 0.6·${ov.toFixed(3)} + 0.4·${retr.toFixed(3)}`)}
        ${gate(gSpec,`Specificity — rivals within Δ 0.02 ≤ ${ioc?3:2}`,`${rivals} rival(s) in the candidate table`)}
      </div>
      <div class="mp-ex" style="margin:9px 0 0">all pass → <b>apt-attributed + notification</b> (audit: apt_notify, toast, red row tint) · plausible but uncorroborated → <b>apt-candidate</b> (listed, no ping) · otherwise → <b>not-apt</b></div>
    </div>
  </div>

  <div class="mp-stage">
    <div class="mp-stitle"><span class="n">4</span> Verdict tiers — live tallies in view</div>
    <div class="mp-verds">
      <div class="mp-verd red"><b>${nNot}</b><i>apt-attributed → notified</i><s>corroborated + specific enough to act on</s></div>
      <div class="mp-verd amb"><b>${nCand}</b><i>apt-candidate</i><s>plausible, listed without a ping</s></div>
      <div class="mp-verd grey"><b>${nNo}</b><i>not-apt</i><s>behavioural category fallback (7 rules)</s></div>
    </div>
    <div class="mp-card" style="margin-top:12px"><h4>Behavioural categories in view — the 7 non-APT rules</h4>
      <div class="mp-cat">${catChips}</div>
      <div class="mp-ex" style="margin:9px 0 0">brute-force · scanning · exploit · exfiltration · lateral movement · C2 beaconing · evasion — applied when no actor passes the gates.</div>
    </div>
  </div>`;
  $('ap-cta').textContent='Show '+nNot+' notified alert'+(nNot===1?'':'s')+' →';
  $('ap-prov').textContent='evidence-based ranking · no ground-truth labels · corpus trained '
    +String((exAt&&exAt.model&&exAt.model.trained_at)||'–').slice(0,10);
  $('ap-scrim').hidden=false; $('aptpipe').hidden=false;
  $('ap-body').scrollTop=_sc;
  const ap=()=>{
    document.querySelectorAll('#ap-body [data-w]').forEach(el=>{el.style.width=el.dataset.w;});
    document.querySelectorAll('#ap-body [data-h]').forEach(el=>{el.style.height=el.dataset.h;});
  };
  if(silent) ap(); else requestAnimationFrame(ap);
}

function closeFeedPipe(){ $('feedpipe').hidden=true; $('fp-scrim').hidden=true; }

function openFeedPipe(silent){
  const _sc=$('fp-body').scrollTop;
  if(!silent){ closeWins(); if(!$('insight').hidden) closeInsight(); }
  const err=!!st.feed_error;
  const online=(st.feed_mode||'offline')==='online';
  const state=err?'FEED ERR':'LIVE';
  const srcs=st.feed_sources||[];
  const nSrc=srcs.length, nOk=srcs.filter(s=>s.ok).length, nBad=nSrc-nOk;
  const rec=+(st.feed_records||0), ind=+(st.feed_indicators||0);
  const ttl=+(st.ttl_hours||168), hl=+(st.half_life_h||6), pi=+(st.poll_interval_min||5);
  const sync=String(st.feed_updated_at||'').slice(11,19);
  const stCard=(name,cur,cls,desc,metric)=>
    `<div class="mp-verd ${cls}${cur?' cur':''}"><b>${esc(name)}</b><i>${desc}</i><s>${metric}</s></div>`;
  const srcChips=srcs.map(s=>
    `<span class="fchip click ${s.ok?'ok':'bad'}" data-src="${esc(s.source)}"`
    +` tabindex="0" role="button" title="${esc(s.error||s.url||'')} · click for detail">`
    +`<span class="mk">${s.ok?'✓':'✗'}</span><b>${esc(s.source)}</b>`
    +`<span class="sub">${s.ok?((s.n_records||0).toLocaleString()+' rec')
       :esc(String(s.error||'failed')).slice(0,36)}</span></span>`).join('');
  $('fp-body').innerHTML=`
  <div class="mp-stage">
    <div class="mp-stitle"><span class="n">1</span> Chip states — what the header reads</div>
    <div class="mp-verds">
      ${stCard('LIVE',state==='LIVE','grn','online polling · no errors','current header state')}
      ${stCard('FEED ERR',state==='FEED ERR','red','last refresh failed','previous IoC set retained')}
      ${stCard('OFFLINE',false,'amb','health endpoint unreachable','screen shows last known data')}
      ${stCard('LOCKED',false,'grey','auth token required','unlock to poll')}
    </div>
    <div class="mp-flow" style="margin-top:12px">
      <div class="mp-node ok"><b>Scoring never stops</b><i>alerts keep firing against the last good indicator set</i></div>
      <span class="mp-arrow">→</span>
      <div class="mp-node ${err?'warn':''}"><b>Zero-record refreshes rejected</b><i>a network outage cannot wipe the IoC set</i></div>
      <span class="mp-arrow">→</span>
      <div class="mp-node hl"><b>Freshness decays</b><i>feed_age_score down-weights stale sightings · half-life ${hl} h</i></div>
    </div>
  </div>

  <div class="mp-stage">
    <div class="mp-stitle"><span class="n">2</span> Ingestion pipeline — ${online?'online':'offline'} mode</div>
    <div class="mp-flow">
      <div class="mp-node"><b>Poll every ${pi} min</b><i>${online?'live HTTP feeds, async thread':'offline corpus snapshots'}</i></div>
      <span class="mp-arrow">→</span>
      <div class="mp-node"><b>${rec.toLocaleString()} records</b><i>corpus parsed into candidate indicators</i></div>
      <span class="mp-arrow">→</span>
      <div class="mp-node hl"><b>Dedupe + TTL ${ttl} h</b><i>one in-memory set · sightings expire</i></div>
      <span class="mp-arrow">→</span>
      <div class="mp-node"><b>${ind.toLocaleString()} indicators live</b><i>in memory now · freshness half-life ${hl} h</i></div>
      <span class="mp-arrow">→</span>
      <div class="mp-node"><b>Enrichment features</b><i>ioc_src_match · ioc_dst_match · feed_confidence · feed_age_score</i></div>
      <span class="mp-arrow">→</span>
      <div class="mp-node ok"><b>Fusion verdict</b><i>score ≥ θ ∧ feed evidence → ★ · IoC dot · APT corroboration</i></div>
    </div>
  </div>

  <div class="mp-stage">
    <div class="mp-stitle"><span class="n">3</span> Live status — per source</div>
    <div class="mp-card"><h4>Health right now</h4>
      <div class="mp-kpis">
        <div class="mp-kpi ${nBad?'a':'g'}"><b>${nOk}/${nSrc||'–'}</b><i>sources healthy</i></div>
        <div class="mp-kpi b"><b>${ind.toLocaleString()}</b><i>indicators in memory</i></div>
        <div class="mp-kpi v"><b>${rec.toLocaleString()}</b><i>corpus records</i></div>
        <div class="mp-kpi ${err?'r':'g'}"><b>${sync||'–'}</b><i>last sync UTC</i></div>
        <div class="mp-kpi"><b>every ${pi} min</b><i>poll interval</i></div>
      </div>
    </div>
    <div class="mp-card" style="margin-top:12px"><h4>Sources — click a chip for provenance</h4>
      ${srcChips?`<div class="fchips">${srcChips}</div>`
        :`<div class="mp-ex">${online?'polling — waiting for first refresh…':
           'Offline corpus — set <b>feeds.online: true</b> in deploy/config.yaml to poll live feeds.'}</div>`}
      ${err?`<div class="mp-ex" style="margin:9px 0 0">✗ last error: <b>${esc(String(st.feed_error).slice(0,120))}</b></div>`:''}
    </div>
  </div>`;
  $('fp-body').scrollTop=_sc;
  $('fp-cta').textContent='Show IoC-hit alerts →';
  $('fp-prov').textContent=(online?'online':'offline')+' · last sync '+(sync||'–')
    +' UTC · every '+pi+' min';
  $('fp-scrim').hidden=false; $('feedpipe').hidden=false;
}

function closeAiPipe(){ $('aipipe').hidden=true; $('ai-scrim').hidden=true; }

function openAiPipe(silent){
  const _sc=$('ai-body').scrollTop;
  if(!silent){ closeWins(); if(!$('insight').hidden) closeInsight(); }
  const on=!!(st.xai&&st.xai.enabled);
  const rpm=st.explain_per_min||12;
  const cached=expl.size, busy=loading.size;
  const ex=data.find(a=>(a.reasons||[]).length)||data[0]||null;
  const rs=((ex&&ex.reasons)||[]).slice(0,5);
  const maxShap=Math.max(1e-9,...rs.map(r=>Math.abs(+r.shap||0)));
  const reasonRows=rs.map((r,i)=>{
    const sh=+r.shap;
    const pct=Number.isFinite(sh)?Math.max(4,Math.round(Math.abs(sh)/maxShap*100)):40;
    return `<div class="mp-ibar"><span class="f">#${i+1} ${esc(r.feature||'')}</span>`
      +`<span class="b"><span style="width:0" data-w="${pct}%"></span></span>`
      +`<span class="p">${Number.isFinite(sh)?(sh>=0?'+':'−')+Math.abs(sh).toFixed(4):'intel'}</span></div>`;
  }).join('')||'<div class="mp-ex">no reason codes attached to alerts in view</div>';
  const gate=(ok,t,v)=>`<div class="mp-gate"><span class="mk ${ok?'y':'n'}">${ok?'✓':'✗'}</span>`
    +`<span>${t}<em>${v}</em></span></div>`;
  const flowNode=(cls,b,i)=>`<div class="mp-node ${cls||''}"><b>${b}</b><i>${i}</i></div>`;
  const arrow='<span class="mp-arrow">→</span>';
  $('ai-body').innerHTML=`
  <div class="mp-stage">
    <div class="mp-stitle"><span class="n">1</span> Already on the alert — TreeSHAP reason codes</div>
    <div class="mp-card"><h4>Example ${esc(String((ex&&ex.alert_id)||'–'))} · score ${ex?(+ex.score||0).toFixed(3):'–'} · top reasons</h4>
      ${reasonRows}</div>
    <div class="mp-ex">Scoring time already computed the feature contributions — the brief narrates these codes, it never invents features.</div>
  </div>

  <div class="mp-stage">
    <div class="mp-stitle"><span class="n">2</span> Request path — POST /api/explain (explicit click only)</div>
    <div class="mp-flow">
      ${flowNode('','Explain with AI click','alert detail · never called automatically')}
      ${arrow}
      ${flowNode('hl','Payload assembly','flow metadata + SHAP reasons + verdict')}
      ${arrow}
      ${flowNode('','One chat completion','configured model · single round-trip')}
      ${arrow}
      ${flowNode('ok','Plain-English brief','what happened · why flagged · what to check next')}
    </div>
    <div class="mp-card"><h4>Payload gates</h4>
      ${gate(true,'flow metadata','source/destination/proto/timing — the alert’s own fields')}
      ${gate(true,'SHAP reason codes','top features + Δ contributions from scoring')}
      ${gate(true,'threshold verdict','score, θ and the alert decision')}
      ${gate(false,'raw packet bytes','excluded — never leaves the host')}
      ${gate(false,'other alerts / bulk data','excluded — one alert per request')}
    </div>
  </div>

  <div class="mp-stage">
    <div class="mp-stitle"><span class="n">3</span> Controls — cache · rate limit · audit</div>
    <div class="mp-card"><div class="mp-kpis">
      <div class="mp-kpi ${on?'g':'r'}"><b>${on?'enabled':'disabled'}</b><i>xai.api_key configured</i></div>
      <div class="mp-kpi b"><b>${rpm}/min</b><i>rate limit · 429 beyond</i></div>
      <div class="mp-kpi v"><b>${cached}</b><i>briefs cached in this tab</i></div>
      <div class="mp-kpi"><b>${busy}</b><i>requests in flight</i></div>
    </div></div>
    <div class="mp-flow" style="margin-top:12px">
      ${flowNode('ok','Audited server-side','explain_ok / explain_error / rate_limited → audit.log')}
      ${arrow}
      ${flowNode('','Cached per alert','re-click shows the brief without a new request')}
      ${arrow}
      ${flowNode(on?'':'warn',on?'Ready':'Disabled','set xai.api_key in deploy/config.yaml to enable')}
    </div>
    <div class="mp-ex">Disabled state still works: reason cards and per-feature values remain fully readable without any API key.</div>
  </div>

  <div class="mp-stage">
    <div class="mp-stitle"><span class="n">4</span> Brief anatomy — what lands in the detail pane</div>
    <div class="mp-verds">
      <div class="mp-verd grn"><b>what happened</b><i>one-paragraph plain-English summary</i><s>handoffs &amp; tickets</s></div>
      <div class="mp-verd grn"><b>why flagged</b><i>reads the top reason codes back to you</i><s>turns Δ values into narrative</s></div>
      <div class="mp-verd grn"><b>what to check next</b><i>analyst-oriented follow-up hints</i><s>actionable, not decorative</s></div>
    </div>
    <div class="mp-ex">Why it matters: SHAP tells you which features moved the score; the brief turns that into analyst-ready narrative.</div>
  </div>`;
  $('ai-prov').textContent=(on?'enabled':'disabled')+' · cache '+cached
    +' · '+rpm+'/min · audited';
  $('ai-scrim').hidden=false; $('aipipe').hidden=false;
  const ap=()=>{
    document.querySelectorAll('#ai-body [data-w]').forEach(el=>{el.style.width=el.dataset.w;});
    document.querySelectorAll('#ai-body [data-h]').forEach(el=>{el.style.height=el.dataset.h;});
  };
  if(silent) ap(); else requestAnimationFrame(ap);
}

function closeDeep(){ $('deep').hidden=true; $('dw-scrim').hidden=true; }
function closeWins(){
  if(!$('mlpipe').hidden) closeMlPipe();
  if(!$('aptpipe').hidden) closeAptPipe();
  if(!$('feedpipe').hidden) closeFeedPipe();
  if(!$('deep').hidden) closeDeep();
  if(!$('aipipe').hidden) closeAiPipe();
}
const DEEP_KEYS=new Set(['all','recent','ioc','profile','theta','flows','iocs','synced']);
let dwFilt=null;
let dwKey=null;

function openDeep(fkey,silent){
  const _sc=$('dw-body').scrollTop;
  if(!silent){ closeWins(); if(!$('insight').hidden) closeInsight(); }
  dwKey=fkey;
  dwFilt=null;
  const K=(v,l,cls)=>`<div class="mp-kpi ${cls||''}"><b>${v}</b><i>${l}</i></div>`;
  const th=(+st.theta)||0.8349;
  const nf=st.n_features||38;
  let html='', prov='';

  if(fkey==='all'){
    $('dw-title').textContent='Alerts';
    $('dw-sub').textContent='everything the model escalated · system of record';
    let hits=0,nNot=0,nCand=0;
    for(const a of data){const c=a.cti||{};
      if((c.ioc_src_match||0)>0||(c.ioc_dst_match||0)>0) hits++;
      const at=a.attribution; if(at){ if(at.notify)nNot++;
        else if(at.verdict==='apt-candidate') nCand++; }}
    html=`
    <div class="mp-stage">
      <div class="mp-stitle"><span class="n">1</span> Alert lifecycle</div>
      <div class="mp-flow">
        <div class="mp-node hl"><b>score ≥ θ</b><i>${th.toFixed(4)} · forest probability crosses the line</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node"><b>TreeSHAP reasons</b><i>per-feature contributions → top reason + ATT&amp;CK tactic</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node ok"><b>CTI fusion</b><i>model verdict ∧ feed evidence → ★ marker</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node"><b>Attribution gate</b><i>evidence ranking → notified / candidate / not-apt</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node"><b>JSONL + audit</b><i>rotating sink with retention · audit.log events</i></div>
      </div>
    </div>
    <div class="mp-stage">
      <div class="mp-stitle"><span class="n">2</span> In view now</div>
      <div class="mp-card"><div class="mp-kpis">
        ${K(data.length,'alerts in view','g')}${K(hits,'IoC-correlated','b')}
        ${K(nNot,'APT notified','r')}${K(nCand,'APT candidates','a')}
        ${K(th.toFixed(4),'threshold θ','v')}
      </div></div>
    </div>`;
    dwFilt={};
    $('dw-cta').textContent='Open alerts table →';
    prov='rotating JSONL sink · audit: deploy/audit.log';

  }else if(fkey==='recent'){
    $('dw-title').textContent='Last 5 minutes';
    $('dw-sub').textContent='velocity of new detections · flow ts within 300 s';
    const now=Date.now()/1000;
    let r=0, hits5=0;
    const mins=new Array(5).fill(0);
    const mset=new Set();
    for(const a of data){
      const ts=+(a.flow&&a.flow.ts)||0; const c=a.cti||{};
      mset.add(Math.floor(ts/60));
      if(now-ts<=300){ r++;
        if((c.ioc_src_match||0)>0||(c.ioc_dst_match||0)>0) hits5++; }
      const d=Math.floor(now/60)-Math.floor(ts/60);
      if(d>=0&&d<5) mins[4-d]++;
    }
    const mMax=Math.max(1,...mins);
    const bars=mins.map(c=>`<div class="sb" style="height:0" data-h="${c?Math.max(6,Math.round(c/mMax*100)):3}%" data-n="${c}"></div>`).join('');
    const avgMin=mset.size?data.length/mset.size:0;
    const mult=avgMin>0?((r/5)/avgMin):0;
    const t0=new Date((Math.floor(now/60)-4)*60000).toISOString().slice(11,16);
    const t1=new Date(Math.floor(now/60)*60000).toISOString().slice(11,16);
    html=`
    <div class="mp-stage">
      <div class="mp-stitle"><span class="n">1</span> Velocity window</div>
      <div class="mp-flow">
        <div class="mp-node"><b>flow timestamp</b><i>every alert carries its source flow ts</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node hl"><b>now − 300 s</b><i>sliding window · current minute + previous 4</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node ${r?'warn':''}"><b>${r} alert${r===1?'':'s'} in window</b><i>${hits5} with live-feed IoC match</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node ${mult>=1.5?'warn':''}"><b>${mult?mult.toFixed(1)+'× session rate':'—'}</b><i>vs ${avgMin.toFixed(1)} alerts/min average</i></div>
      </div>
      <div class="mp-grid mp-g2">
        <div class="mp-card"><h4>Alerts per minute — last 5</h4>
          <div class="mp-spec">${bars}</div>
          <div class="mp-speclab"><span>${t0}</span><span>${t1} UTC</span></div>
        </div>
        <div class="mp-card"><div class="mp-kpis">
          ${K(r,'alerts · 300 s','a')}${K(hits5,'IoC hits · 300 s','b')}
          ${K(Math.max(...mins),'busiest minute','r')}${K(mult?mult.toFixed(1)+'×':'–','vs session rate','v')}
        </div></div>
      </div>
    </div>`;
    dwFilt={recent:true};
    $('dw-cta').textContent='Show last 5 min →';
    prov='window: now − 300 s · heartbeat reads the same stream';

  }else if(fkey==='ioc'){
    $('dw-title').textContent='IoC hits';
    $('dw-sub').textContent='fusion layer: model verdict ∧ external intelligence';
    let hits=0,srcM=0,dstM=0;
    for(const a of data){const c=a.cti||{};
      const s=(c.ioc_src_match||0)>0, d=(c.ioc_dst_match||0)>0;
      if(s||d){ hits++; if(s) srcM++; if(d) dstM++; }}
    const pct=data.length?(hits/data.length*100).toFixed(1):'0.0';
    html=`
    <div class="mp-stage">
      <div class="mp-stitle"><span class="n">1</span> Correlation flow</div>
      <div class="mp-flow">
        <div class="mp-node"><b>Live feeds</b><i>URLhaus · ThreatFox · Feodo — refreshed every poll</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node hl"><b>In-memory set</b><i>${(st.feed_indicators??0).toLocaleString()} indicators · dedupe + TTL</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node"><b>Enrichment</b><i>ioc_src_match · ioc_dst_match per flow endpoint</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node ok"><b>★ on the alert</b><i>model verdict ∧ feed evidence — strongest signal</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node"><b>Filter pill</b><i>IoC-only view for triage</i></div>
      </div>
      <div class="mp-card"><div class="mp-kpis">
        ${K(hits,'alerts matched','g')}${K(pct+'%','of view','b')}
        ${K(srcM,'source matches','a')}${K(dstM,'destination matches','r')}
        ${K((st.feed_indicators??0).toLocaleString(),'indicators live','v')}
      </div></div>
    </div>`;
    dwFilt={ioc:true};
    $('dw-cta').textContent='Show IoC-correlated alerts →';
    prov='features: ioc_src_match · ioc_dst_match from enrichment';

  }else if(fkey==='profile'){
    const md=st.model||{}, mt=md.meta||{}, tm=mt.test_metrics||{};
    const p=st.profile||'–';
    const pc=v=>v!=null?(v*100).toFixed(2)+'%':'–';
    $('dw-title').textContent='Model profile';
    $('dw-sub').textContent='which bundle runs decides how flows are shaped';
    html=`
    <div class="mp-stage">
      <div class="mp-stitle"><span class="n">1</span> Loaded bundle</div>
      <div class="mp-flow">
        <div class="mp-node"><b>bundle: ${esc(p)}</b><i>selected in deploy/config.yaml</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node hl"><b>${nf} features</b><i>Zeek/EVE/JSONL/CSV vocabulary + 6 live-CTI</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node warn"><b>θ = ${th.toFixed(4)}</b><i>threshold ships with the bundle</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node ok"><b>joblib artifact</b><i>${esc(String(mt.artifact||'deploy_live_netflow'))} · retrain: scripts/train_artifact.py</i></div>
      </div>
      <div class="mp-card"><div class="mp-kpis">
        ${K(pc(tm.accuracy),'held-out accuracy','g')}${K(pc(tm.fpr),'false-positive rate','a')}
        ${K(th.toFixed(4),'threshold θ','v')}${K(nf,'features','b')}
        ${K((mt.rows||0).toLocaleString(),'training rows','r')}
      </div></div>
    </div>
    <div class="mp-stage">
      <div class="mp-stitle"><span class="n">2</span> Profiles &amp; swap</div>
      <div class="mp-flow">
        <div class="mp-node ok"><b>live_netflow — production</b><i>38 sensor-reachable features · θ 0.8349 · everything the sensor sees</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node"><b>deploy_unsw_full — reference</b><i>67 features · θ 0.8802 · host-side fields · benchmarking only</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node hl"><b>swap = bundle:</b><i>model + θ change together · restart to load</i></div>
      </div>
      <div class="mp-ex">Every alert’s reason cards show the SHAP contribution of these features — the model stays auditable per decision.
        <button class="an-ghost" data-f="ml" style="margin-left:8px">Open ML pipeline →</button></div>
    </div>`;
    prov='model selection: deploy/config.yaml · bundle:';

  }else if(fkey==='theta'){
    const pc=v=>v!=null?(v*100).toFixed(2)+'%':'–';
    const md=st.model||{}, tm=(md.meta||{}).test_metrics||{};
    let sMin=null,sMax=null;
    for(const a of data){const s=+a.score; if(!isFinite(s)) continue;
      if(sMin===null||s<sMin) sMin=s; if(sMax===null||s>sMax) sMax=s;}
    $('dw-title').textContent='Threshold θ';
    $('dw-sub').textContent='the policy dial — score ≥ θ fires an alert';
    html=`
    <div class="mp-stage">
      <div class="mp-stitle"><span class="n">1</span> Decision line</div>
      <div class="mp-flow">
        <div class="mp-node"><b>probability 0…1</b><i>RandomForest predict_proba per flow</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node warn"><b>compare vs θ = ${th.toFixed(4)}</b><i>chosen on held-out validation</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node ok"><b>≥ θ → alert + SHAP</b><i>below θ → flow, ignored</i></div>
      </div>
      <div class="mp-card"><h4>Where alerts sit between θ and 1.0</h4>
        <div class="mp-axis">
          <span class="mp-tlab" style="left:${(th*100).toFixed(2)}%">θ ${th.toFixed(4)}</span>
          <div class="mp-track"></div>
          <div class="mp-tmark" style="left:${(th*100).toFixed(2)}%"></div>
          <span class="mp-axl lo">score 0.0</span><span class="mp-axl hi">≥ θ → alert</span>
        </div>
      </div>
    </div>
    <div class="mp-stage">
      <div class="mp-stitle"><span class="n">2</span> Policy trade-offs + live margins</div>
      <div class="mp-grid mp-g2">
        <div class="mp-card"><div class="mp-kpis">
          ${K(th.toFixed(4),'threshold θ','v')}${K(data.length,'alerts in view','g')}
          ${K(sMin!=null?sMin.toFixed(3):'–','lowest score','b')}${K(sMax!=null?sMax.toFixed(3):'–','highest score','a')}
          ${K(pc(tm.target_recall!=null?tm.target_recall:0.96),'target recall','g')}${K(pc(tm.fpr),'FPR at θ','r')}
        </div></div>
        <div class="mp-card"><h4>The dial</h4>
          <div class="mp-flow" style="margin-bottom:0">
            <div class="mp-node warn"><b>lower θ</b><i>recall ↑ · alert fatigue ↑</i></div>
            <div class="mp-node ok"><b>raise θ</b><i>quieter · borderline attacks silenced</i></div>
          </div>
          <div class="mp-ex" style="margin:9px 0 0">θ is a policy dial, not a fact — revisit when the traffic mix changes. Every alert records its score + SHAP reasons, so any crossing can be reconstructed.</div>
        </div>
      </div>
    </div>`;
    prov='rebalance: edit bundle θ or retrain';

  }else if(fkey==='flows'){
    const n=+(st.flows_scored||0), b=+(st.batches||0);
    $('dw-title').textContent='Flows scored';
    $('dw-sub').textContent='session-scoped parse → batch → score → explain';
    html=`
    <div class="mp-stage">
      <div class="mp-stitle"><span class="n">1</span> Throughput path</div>
      <div class="mp-flow">
        <div class="mp-node"><b>Tail input</b><i>Zeek / EVE / JSONL / CSV adapter table</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node hl"><b>design()</b><i>${nf} features · numeric + categorical + CTI</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node"><b>Batching</b><i>${st.batch_max||64} flows or every ${st.flush_s||5} s — whichever first</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node warn"><b>Predict</b><i>forest votes → one score per flow</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node ok"><b>TreeSHAP → sink</b><i>explain alerts · append JSONL</i></div>
      </div>
      <div class="mp-card"><div class="mp-kpis">
        ${K(n.toLocaleString(),'flows scored','g')}${K(b.toLocaleString(),'batches','b')}
        ${K((st.alerts||0).toLocaleString(),'alerts fired','a')}${K(st.batch_max||64,'batch size','v')}
        ${K((st.flush_s||5)+' s','flush window','r')}
      </div></div>
    </div>
    <div class="mp-stage">
      <div class="mp-stitle"><span class="n">2</span> Cost model + health</div>
      <div class="mp-flow">
        <div class="mp-node"><b>batch-64 cost</b><i>prep ≈ 0.05 s · predict ≈ 0.1 s · TreeSHAP ≈ 40 ms/alert</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node hl"><b>bound = explanation</b><i>throughput limited by SHAP, not the forest</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node warn"><b>counter stalls?</b><i>check parse_errors + adapter table (tail format drift)</i></div>
      </div>
      <div class="mp-ex" style="margin-top:2px">Counter resets on restart (default <b>start_at_end</b> skips file history); the alert log itself persists and rotates.</div>
    </div>`;
    prov='session counter · alert log persists + rotates';

  }else if(fkey==='iocs'){
    const ind=+(st.feed_indicators??st.feed_records??0);
    const rec=+(st.feed_records||0);
    const nSrc=(st.feed_sources||[]).length;
    const names=((st.feed_sources||[]).map(s=>s.source).join(' · '))||st.feed_mode||'feeds';
    const ttl=+(st.ttl_hours||168), hl=+(st.half_life_h||6);
    $('dw-title').textContent='Feed IoCs';
    $('dw-sub').textContent='the ∧ external intelligence half of the fusion verdict';
    html=`
    <div class="mp-stage">
      <div class="mp-stitle"><span class="n">1</span> Indicator set</div>
      <div class="mp-flow">
        <div class="mp-node"><b>${nSrc} live sources</b><i>${esc(String(names).slice(0,64))}</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node hl"><b>${rec.toLocaleString()} records</b><i>corpus parsed into candidate indicators</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node"><b>Dedupe + TTL ${ttl} h</b><i>one in-memory set · sightings expire</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node ok"><b>${ind.toLocaleString()} live</b><i>in memory now · freshness half-life ${hl} h</i></div>
      </div>
      <div class="mp-card"><div class="mp-kpis">
        ${K(ind.toLocaleString(),'indicators','g')}${K(nSrc,'sources','b')}
        ${K(ttl+' h','TTL','v')}${K(hl+' h','freshness half-life','a')}
        ${K(st.feed_mode||'–','mode','r')}
      </div></div>
    </div>
    <div class="mp-stage">
      <div class="mp-stitle"><span class="n">2</span> From set to features</div>
      <div class="mp-flow">
        <div class="mp-node hl"><b>enrichment</b><i>ioc_src_match · ioc_dst_match · feed_age_score (+ confidence · source count · reputation)</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node ok"><b>fusion verdict</b><i>IoC-hit KPI · ★ markers · APT corroboration</i></div>
      </div>
      <div class="mp-ex" style="margin-top:2px">0 indicators right after a restart means the first poll is still running; a failed poll keeps the previous sightings — scoring never stops.
        <button class="an-ghost" data-f="live" style="margin-left:8px">Open LIVE feeds window →</button></div>
    </div>`;
    dwFilt={ioc:true};
    $('dw-cta').textContent='Show IoC-correlated alerts →';
    prov='sources: '+String(names).slice(0,60);

  }else if(fkey==='synced'){
    const t=(st.feed_updated_at||'').slice(11,19);
    const iso=st.feed_updated_at;
    let ageMin='–';
    if(iso){const ms=Date.now()-Date.parse(iso); if(isFinite(ms)) ageMin=Math.max(0,Math.round(ms/60000));}
    const pi=+(st.poll_interval_min||5);
    const mode=st.feed_mode==='online'?'● live polling':'◐ snapshot corpus';
    const err=!!st.feed_error;
    $('dw-title').textContent='Feeds synced';
    $('dw-sub').textContent='freshness drives feed_age_score';
    html=`
    <div class="mp-stage">
      <div class="mp-stitle"><span class="n">1</span> Sync cadence</div>
      <div class="mp-flow">
        <div class="mp-node ${err?'warn':'ok'}"><b>last sync ${t||'–'} UTC</b><i>age ${ageMin} min · ${err?'error on last poll':'no feed errors'}</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node hl"><b>every ${pi} min</b><i>${mode} · async poll thread</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node"><b>freshness decay</b><i>half-life 6 h → feed_age_score down-weights stale hits</i></div>
        <span class="mp-arrow">→</span>
        <div class="mp-node ok"><b>fusion stays current</b><i>within one poll interval</i></div>
      </div>
      ${err?`<div class="mp-card" style="margin-top:12px"><div class="mp-ex" style="margin:0">✗ last error: <b>${esc(String(st.feed_error).slice(0,140))}</b> — previous IoC set retained; check deploy/scorer.log.</div></div>`:''}
    </div>
    <div class="mp-stage">
      <div class="mp-stitle"><span class="n">2</span> Live state</div>
      <div class="mp-card"><div class="mp-kpis">
        ${K(t||'–','last sync UTC','g')}${K('every '+pi+' min','interval','b')}
        ${K(ageMin,'age (min)','a')}${K(mode,'mode','v')}
        ${K(err?'error':'healthy','poll state',err?'r':'g')}
      </div></div>
      <div class="mp-ex" style="margin-top:2px">Polling cadence sets the finest resolution at which a new indicator can appear; TTL 168 h keeps old sightings decaying.
        <button class="an-ghost" data-f="live" style="margin-left:8px">Open LIVE feeds window →</button></div>
    </div>`;
    prov='per-source detail: Intelligence Feeds panel chips';
  }

  $('dw-body').innerHTML=html;
  $('dw-body').scrollTop=_sc;
  $('dw-prov').textContent=prov;
  $('dw-cta').hidden=!dwFilt;
  $('dw-scrim').hidden=false; $('deep').hidden=false;
  const ap=()=>{
    document.querySelectorAll('#dw-body [data-w]').forEach(el=>{el.style.width=el.dataset.w;});
    document.querySelectorAll('#dw-body [data-h]').forEach(el=>{el.style.height=el.dataset.h;});
  };
  if(silent) ap(); else requestAnimationFrame(ap);
}

function kpiInsight(fkey){
  if(DEEP_KEYS.has(fkey)){ openDeep(fkey); return; }
  if(fkey==='ml'){ openMlPipe(); return; }
  if(fkey==='ml-text'&&!$('mlpipe').hidden) closeMlPipe();
  if(fkey==='apt'){ openAptPipe(); return; }
  if(fkey==='live'){ openFeedPipe(); return; }
  if(fkey==='nim'){ openAiPipe(); return; }
  if(fkey==='ml-text'){
    const md=st.model||{}, mt=md.meta||{}, tm=mt.test_metrics||{};
    const tf=(md.top_features||[]).slice(0,8)
      .map(x=>`${esc(String(x[0]))} <b>${Math.round(x[1]*100)}%</b>`).join(' · ');
    let nNot=0, nCand=0, nNo=0;
    for(const a of data){
      const at=a.attribution; if(!at) continue;
      if(at.notify) nNot++;
      else if(at.verdict==='apt-candidate') nCand++;
      else nNo++;
    }
    const pc=v=>v!=null?(v*100).toFixed(2)+'%':'—';
    const acc=tm.accuracy!=null?(tm.accuracy*100).toFixed(2)+'%':'—';
    const rec=tm.recall!=null?(tm.recall*100).toFixed(1)+'%':'—';
    const roc=tm.roc_auc!=null?tm.roc_auc.toFixed(4):'—';
    const th=(+md.theta||+st.theta||0);
    const nFeat=st.n_features||mt.n_features||38;
    const ds=String(mt.dataset||'unsw-nb15').replace(/_/g,'-').toUpperCase();
    openInsight({badge:'ml · decision pipeline', title:'How the ML trains and decides',
      metric:`RF ≥ ${th.toFixed(4)} → alert → evidence gate → ${nNot} APT notified of ${data.length} in view`,
      what:[
        `<b>1 · Train (offline, once).</b> RandomForestClassifier — ${mt.n_estimators||200} trees, min leaf ${mt.min_samples_leaf??20}, seed ${mt.seed??42} — fit on ${(mt.rows||0).toLocaleString()} ${ds} rows in ~${mt.fit_seconds??'—'} s: ${nFeat} features (flow timing/volume statistics + protocol/service/state encoding + 6 live-CTI intel features). Held-out test (${(tm.n||0).toLocaleString()} flows): <b>${acc} accuracy · ${rec} recall · ${pc(tm.fpr)} FPR</b>, ROC-AUC ${roc} (${(tm.tp||0).toLocaleString()} TP / ${(tm.fp||0)} FP / ${(tm.fn||0)} FN). θ = ${th.toFixed(4)} is the validation operating point picked for ≥ ${(100*(mt.target_recall||0.96)).toFixed(0)} % recall at that FPR. Artifact: <span class="hl">model/deploy_live_netflow.joblib</span> — retrain with <b>scripts/train_artifact.py</b>.`,
        `<b>2 · Detect (per flow).</b> Every flow → ${nFeat} features → forest probability; <b>score ≥ θ fires an alert</b>, below θ it is just a flow. TreeSHAP reuses the same trees to explain each verdict — the reason waterfall on every alert row. Global feature importance (what the forest leans on most): ${tf||'—'}. CTI features rank in the top tier — the intel half is load-bearing, not decoration.`,
        `<b>3 · APT or not (per alert).</b> Live netflow carries no actor labels, so this stage <b>ranks named candidates</b> on three evidence sources: <b>TF-IDF retrieval</b> over a 1040-actor corpus (names, aliases, sectors, sponsors, summaries — retrain: scripts/train_attribution.py), <b>rarity-weighted ATT&amp;CK technique overlap</b> (alert SHAP reasons → MITRE techniques vs the actor's observed set, shared-by-few groups weigh more), and <b>IoC strength</b> (feed source count × confidence). Combined = <b>0.6 · overlap + 0.4 · retrieval</b>, then the notify gate: corroborated (live IoC match, or ≥ 2 shared techniques with overlap ≥ 0.7) ∧ overlap ≥ 0.5 ∧ combined ≥ 0.25 ∧ specific (≤ 3 near-tied rivals within 0.02 when IoC-backed, ≤ 2 otherwise). Pass → <b>apt-attributed → notification</b>; plausible but uncorroborated → <b>apt-candidate</b> (listed, no ping); otherwise → <b>not-apt</b> with a behavioural category fallback (7 technique rules: brute-force, scanning, exploit, exfiltration, lateral movement, C2 beaconing, evasion). In view now: <b>${nNot}</b> notified · <b>${nCand}</b> candidate(s) · <b>${nNo}</b> not-apt.`
      ],
      why:[
        'Both stages are auditable per decision: SHAP reasons justify the score, the evidence trail + competitor table justify the verdict — open any alert to see each side.',
        'Honest by construction: the attribution stage ranks candidates with stated evidence and confidence; it is never presented as a supervised classifier that “knows” the actor. Swap either artifact and restart to change what the pipeline believes.'
      ],
      note:'artifacts: model/deploy_live_netflow.joblib + model/attribution_tfidf.joblib'});
  }else{ openDeep('all'); }
}

/* ─── filters + alert table ────────────────────────────── */
function matches(a){
  const fl=a.flow||{};
  if(filt.proto && String(fl.proto||'').toLowerCase()!==filt.proto) return false;
  if(filt.minute!=null && Math.floor((+(fl.ts)||0)/60)!==filt.minute) return false;
  if(filt.score){const s=+a.score; if(!(s>=filt.score[0]&&s<filt.score[1])) return false;}
  if(filt.ioc){const c=a.cti||{};
    if(!((c.ioc_src_match||0)>0||(c.ioc_dst_match||0)>0)) return false;}
  if(filt.apt){const at=a.attribution; if(!(at&&at.notify)) return false;}
  if(filt.recent && (Date.now()/1000-(+(fl.ts)||0))>300) return false;
  const q=$('q').value.trim().toLowerCase();
  return !q||JSON.stringify(a).toLowerCase().includes(q);
}
function anyF(){
  return filt.minute!=null||filt.proto||filt.score||filt.ioc||filt.recent||filt.apt
    ||!!$('q').value.trim();
}
function renderPills(){
  const items=[];
  if(filt.minute!=null) items.push(['minute','minute '+hhmmss(filt.minute*60).slice(0,5)]);
  if(filt.proto) items.push(['proto','proto '+filt.proto]);
  if(filt.score) items.push(['score','score '+filt.score[0].toFixed(2)+'–'+filt.score[1].toFixed(2)]);
  if(filt.ioc) items.push(['ioc','IoC hits only']);
  if(filt.apt) items.push(['apt','APT notifications only']);
  if(filt.recent) items.push(['recent','last 5 min']);
  $('fpills').innerHTML=items.map(([k,l])=>
    `<span class="fp" data-k="${k}" role="button" tabindex="0">`
    + `${esc(l)}<span class="x">✕</span></span>`).join('');
}

function render(){
  const list=data.filter(matches);
  renderPills();
  const tb=$('rows'); tb.innerHTML='';
  $('count').textContent=anyF()?`${list.length} of ${data.length}`:`${data.length} alerts`;
  $('empty').classList.toggle('show',list.length===0);
  if(list.length===0) return;
  for(const a of list.slice().reverse()){
    const r=a.reasons||[];
    const top=r.find(x=>!x.feature.startsWith('ioc_'))||r[0]||{};
    const iocHit=a.cti&&(a.cti.ioc_src_match>0||a.cti.ioc_dst_match>0);
    const at=a.attribution||null;
    const th=+(a.model&&a.model.theta)||(+st.theta)||0.85;
    const margin=+a.score-th;
    const tier=margin>=0.15?'':(margin>=0.05?' s-warm':' s-mod');
    const tk=String((top&&top.technique)||'');
    const tkId=tk.includes('·')?tk.split('·')[0].trim()
      :(/^[Tt][0-9]{4}/.test(tk.trim())?tk.trim():'');
    const tkName=tk.includes('·')?tk.split('·').slice(1).join('·').trim():'';
    let atCell='', atMini='';
    if(at&&at.notify&&at.actor){
      atCell='<span class="apt-chip" title="APT attributed — notification fired">APT</span>'
        +`<div class="aline"><b>${esc(at.actor.name)}</b>`
        +(at.actor.mitre_id?`<span class="mid"> · ${esc(at.actor.mitre_id)}</span>`:'')
        +`<span class="mid"> · ${Math.round((+at.confidence||0)*100)}%</span></div>`;
      atMini='<span class="apt-chip apt-mini">APT</span>';
    }else if(at&&at.verdict==='apt-candidate'&&at.actor){
      atCell='<span class="apt-chip cand" title="APT candidate — plausible, not notified">APT?</span>'
        +`<div class="aline"><b>${esc(at.actor.name)}</b>`
        +(at.actor.mitre_id?`<span class="mid"> · ${esc(at.actor.mitre_id)}</span>`:'')
        +`<span class="mid"> · ${Math.round((+at.confidence||0)*100)}%</span></div>`;
      atMini='<span class="apt-chip cand apt-mini">APT?</span>';
    }else if(at&&at.verdict==='not-apt'){
      const cat=String(at.category||'').replace(/\\s*\\(non-APT\\)\\s*$/i,'')
        ||'behavioural category';
      atCell='<span class="ntag" title="no APT corroboration — behavioural fallback">non-APT</span>'
        +`<div class="aline">${esc(cat)}</div>`;
    }else{
      atCell='<span class="anone" title="alert predates the attribution layer">—</span>';
    }
    const srcCount=a.cti?+(a.cti.source_count||0):0;
    const open=openId===a.alert_id;
    const tr=document.createElement('tr');
    tr.className='row'+(open?' open':'')+(at&&at.notify?' apt-notify':'');
    tr.innerHTML=
      `<td class="t-time"><span class="thms">${hhmmss(a.flow.ts)}</span>`
        +`<span class="trel" title="flow time (UTC)">${relTs(a.flow&&a.flow.ts)}</span></td>`+
      `<td class="score-cell"><span class="score${tier}">${(+a.score).toFixed(3)}</span>`
        +`<span class="smg" title="margin above θ = ${th.toFixed(4)}">θ+${margin.toFixed(3)}</span></td>`+
      `<td class="col-wide fcell">`
        +`<span class="fip">${esc(a.flow.src_ip)}</span><span class="farr">→</span>`
        +`<span class="fip dst">${esc(a.flow.dst_ip)}</span>`
        +`<div class="fmeta"><span class="fport">:${esc(a.flow.dst_port)}</span>`
        +`<span class="proto">${esc(String(a.flow.proto||'?').toUpperCase())}</span></div></td>`+
      `<td class="reason-cell"><span class="rtx" title="${esc(top.reason||'')}">${esc(top.reason||'–')}</span>`
        +(top.tactic?`<span class="tactic rc-inline">${esc(top.tactic)}</span>`:'')+atMini
        +(r.length>1?`<div class="rsb">+${r.length-1} more reason code${r.length-1>1?'s':''}</div>`:'')
      +`</td>`+
      `<td class="col-wide">`+(top.tactic?`<span class="tactic">${esc(top.tactic)}</span>`:'')
        +(tkId?`<div class="tsub"><span class="tid">${esc(tkId)}</span>${esc(tkName)}</div>`:'')
      +`</td>`+
      `<td class="col-wide attd">${atCell}</td>`+
      `<td>`+(iocHit
        ?`<span class="ioc" title="live-feed match — freshness ${(+((a.cti||{}).feed_age_score||0)).toFixed(2)} · confidence ${(+((a.cti||{}).feed_confidence||0)).toFixed(2)}${srcCount?' · '+srcCount+' source(s)':''}">●</span>`
          +(srcCount?`<span class="ioc-src">${srcCount} src</span>`:'')
        :`<span class="no-ioc" title="no live-feed match">–</span>`)+`</td>`;
    tr.onclick=()=>{
      if(openId===a.alert_id && !$('analysis').hidden) closeAnalysis();
      else openAnalysis(a);
    };
    tb.appendChild(tr);
  }
}

/* ─── deep analysis window ─────────────────────────────── */
function openAnalysis(a){
  anAlert=a; openId=a.alert_id;
  fillAnalysis(a);
  $('an-scrim').hidden=false; $('analysis').hidden=false;
  document.body.style.overflow='hidden';
  render();
}
function closeAnalysis(){
  $('analysis').hidden=true; $('an-scrim').hidden=true;
  document.body.style.overflow='';
  openId=null; anAlert=null;
  render();
}
function pivotAlert(q){
  closeAnalysis();
  filt=Object.assign(blankF());
  $('q').value=String(q||'');
  setView('alerts');
  render();
}
function anAIState(){
  const btn=$('an-ai-btn'), out=$('an-ai-out');
  if(!btn||!out||!anAlert) return;
  const id=anAlert.alert_id, busy=loading.has(id);
  btn.disabled=busy; btn.classList.toggle('busy',busy);
  btn.innerHTML='✦ '+(busy?'Thinking…':(expl.has(id)?'Regenerate brief':'Explain with AI'));
  if(expl.has(id)) showAI(out,id);
  else if(errz.has(id)) showErr(out,errz.get(id));
  else {out.hidden=true; out.textContent='';}
}
function attHTML(at){
  if(!at) return `<div class="an-sec">APT attribution</div>
    <div class="an-card"><p class="dim">Attribution layer disabled
    (attribution.enabled: false) or this alert predates it.</p></div>`;
  const V={'apt-attributed':['no','APT ATTRIBUTED'],
           'apt-candidate':['mb','APT CANDIDATE'],
           'not-apt':['ok','NOT ATTRIBUTABLE TO APT']};
  const v=V[at.verdict]||['ok',String(at.verdict||'').toUpperCase()];
  const act=at.actor;
  let head;
  if(act){
    head=`<div class="att-head">
        <span class="att-badge ${v[0]}" id="at-verdict">${v[1]}${act.ambiguous?' · TIED':''}</span>
        <span class="att-actor">${esc(act.name)}<span class="dim">${esc(act.mitre_id||'no MITRE ID')}${act.origin?' · '+esc(act.origin):''}${act.ambiguous?' · best guess among tied candidates':''}</span></span>
        <span class="att-conf">${(+at.confidence||0).toFixed(2)}</span></div>
      <div class="att-bar"><span style="width:${Math.min(100,Math.max(3,(+at.confidence||0)*100)).toFixed(0)}%"></span></div>
      ${at.notify?'<p class="dim" style="margin-top:8px">⚑ Analyst notified — IoC-corroborated and specific enough to act on.</p>':''}`;
  }else{
    head=`<div class="att-head">
        <span class="att-badge ${v[0]}" id="at-verdict">${v[1]}</span>
        <span class="att-conf">${(+at.confidence||0).toFixed(2)}</span></div>
      <p class="att-cat">Behavioural category: <b>${esc(at.category||'Unclassified anomalous traffic (non-APT)')}</b></p>`;
  }
  let cands='';
  const cs=at.candidates||[];
  if(cs.length){
    cands=`<div class="att-sub">Top candidates (${cs.length}${at.competitors!=null?', '+at.competitors+' within Δ 0.02':''})</div>
      <div class="att-list">`
      +cs.map((c,i)=>
        `<div class="att-row"><span>#${i+1}</span><b>${esc(c.name)}</b>
          <span class="mid">${esc(c.mitre_id||'–')}${c.origin?' · '+esc(c.origin):''}</span>
          ${c.technique_hits&&c.technique_hits.length?`<span class="hits">${esc(c.technique_hits.join(' '))}</span>`:''}
          <span class="sc">${(+c.score||0).toFixed(2)}</span></div>`).join('')
      +`</div>`;
  }
  const ev=(at.evidence||[]).map(e=>`<li>${esc(e)}</li>`).join('');
  const techs=(at.techniques||[]).map(t=>`<span class="tactic">${esc(t)}</span>`).join(' ');
  return `<div class="an-sec">APT attribution · 1040-actor corpus</div>
    <div class="an-card" id="att-card" data-verdict="${esc(at.verdict||'')}">
      ${head}${cands}
      ${ev?`<ul class="ev">${ev}</ul>`:''}
      ${techs?`<p class="att-meta">Techniques: ${techs}</p>`:''}
      <p class="dim att-meta">Evidence-based candidate ranking — netflow carries no
        ground-truth actor labels. TF-IDF retrieval over ${(+at.model&&at.model.n_actors)||1040}
        actors${at.model&&at.model.trained_at?' · trained '+esc(String(at.model.trained_at)).slice(0,10):''},
        rarity-weighted MITRE ATT&amp;CK technique overlap, live-IoC strength.</p>
    </div>`;
}

function fillAnalysis(a){
  const f=a.flow||{}, c=a.cti||{}, rs=(a.reasons||[]);
  const th=+(a.model&&a.model.theta)||+(st.theta)||0.85;
  const sc=+a.score||0;
  $('an-title').textContent=a.alert_id;
  $('an-sub').textContent=`${hhmmss(f.ts)} UTC · ${f.src_ip} → ${f.dst_ip}:${f.dst_port} · ${String(f.proto||'').toUpperCase()}`;
  $('an-score-n').textContent=sc.toFixed(3);
  const C=2*Math.PI*35;
  $('an-ring').style.strokeDasharray=C.toFixed(1);
  $('an-ring').style.strokeDashoffset=(C*(1-Math.min(1,Math.max(0,sc)))).toFixed(1);
  $('an-theta').textContent=th.toFixed(4);
  const span=Math.max(1e-6,1-th);
  const head=Math.min(100,Math.max(0,(sc-th)/span*100));
  $('an-above').textContent=`+${Math.max(0,sc-th).toFixed(3)} above θ · ${head.toFixed(0)} % of headroom`;
  $('an-fill').style.width=Math.max(1.5,head).toFixed(1)+'%';
  $('an-lo').textContent='θ '+th.toFixed(3);
  $('an-prov').textContent=(a.emitted_at||'').slice(0,19).replace('T',' ')+' UTC';
  const dur=+(f.dur)||0, up=+(f.sbytes)||0, dn=+(f.dbytes)||0;
  const facts=[
    ['source', `${f.src_ip}:${f.src_port}`],
    ['destination', `${f.dst_ip}:${f.dst_port}`],
    ['protocol', String(f.proto||'–').toUpperCase()],
    ['duration', dur>0?(dur<1?(dur*1000).toFixed(4)+' ms':dur.toFixed(4)+' s'):'0'],
    ['uplink bytes', up.toLocaleString()],
    ['downlink bytes', dn.toLocaleString()],
    ['total bytes', (up+dn).toLocaleString()],
    ['emitted', (a.emitted_at||'').slice(11,19)+' UTC']
  ];
  const maxShap=Math.max(1e-9,...rs.map(r=>Math.abs(+r.shap||0)));
  const wf=rs.map((r,i)=>{
    const sh=+r.shap;
    const isIoc=String(r.feature||'').startsWith('ioc_')||String(r.reason||'').includes('CTI feed');
    let pct=0, cls='';
    if(isIoc){pct=70; cls=' ioc';}
    else if(Number.isFinite(sh)){pct=Math.abs(sh)/maxShap*100; if(sh<0) cls=' neg';}
    const d=Number.isFinite(sh)?(sh>=0?'+':'−')+Math.abs(sh).toFixed(4):'intel';
    return `<div class="wf${cls}">
      <div class="wf-top"><span class="wf-rank">${i+1}</span>
        <span class="wf-f">${esc(r.feature||'')}</span>
        <span class="wf-v">${r.value!=null?num(r.value):''}</span>
        <span class="wf-d">Δ ${d}</span></div>
      <div class="wf-track"><span class="wf-bar" style="width:${pct.toFixed(1)}%"></span></div>
      <div class="wf-t">${esc(r.reason||'')}</div>
      <div class="m">${esc(r.tactic||'')}${r.technique&&r.technique!=='-'?' · '+esc(r.technique):''}</div>
    </div>`;}).join('')||
    '<div class="wf"><div class="wf-t">No reason codes attached to this alert.</div></div>';
  const topR=rs.find(r=>r.feature&&!String(r.feature).startsWith('ioc_'))||rs[0]||{};
  const ti=TACTIC_INFO[String(topR.tactic||'').toLowerCase()];
  const hit=(c.ioc_src_match||0)>0||(c.ioc_dst_match||0)>0;
  const which=[c.ioc_src_match>0?'source':null,c.ioc_dst_match>0?'destination':null]
    .filter(Boolean).join(' and ');
  $('an-body').innerHTML=
    `<div class="an-sec">Flow</div>
     <div class="facts">${facts.map(([k,v])=>
       `<div class="fact"><b>${esc(k)}</b><span title="${esc(v)}">${esc(v)}</span></div>`).join('')}</div>
     <div class="an-sec">Why the model flagged it · SHAP contributions</div>
     <div class="wf-list">${wf}</div>
     <div class="an-sec">ATT&amp;CK context</div>
     <div class="an-card">
       <span class="tactic">${esc(topR.tactic||'Uncategorised')}</span>
       <span class="an-tech">${esc(topR.technique&&topR.technique!=='-'?topR.technique:'technique not mapped')}</span>
       <p>${ti?ti[0]:'Behaviour derived from the top non-IoC SHAP reason of this alert.'}</p>
       <p class="dim">${ti?ti[1]:'See the SHAP contributions above for the underlying feature values.'}</p>
     </div>
     <div class="an-sec">Threat intelligence</div>
     <div class="an-card">${hit
       ? `<p><span class="ioc-hit">★ IoC match</span> — ${which} address(es) found in the live CTI set.
          Freshness ${num(c.feed_age_score)} · confidence ${num(c.feed_confidence)} ·
          ${c.source_count||0} independent source(s).</p>
          <p class="dim">Model verdict ∧ independent feed agreement — the strongest signal this
          platform produces; treat hits like this as top priority.</p>`
        : `<p>No live-feed indicator matched this flow's addresses.</p>
           <p class="dim">Behavioural-only detection: the score is driven purely by traffic
           features (SHAP above). Correlate repeated destinations and ports before dismissing.</p>`}
     </div>
     ${attHTML(a.attribution)}
     <div class="an-sec">AI analyst brief</div>
     <button class="ai-btn" id="an-ai-btn">✦ Explain with AI</button>
     <div class="ai-out" id="an-ai-out" hidden></div>`;
  $('an-ai-btn').onclick=()=>askAI(a.alert_id);
  anAIState();
}

function aiRefresh(){
  if(anAlert && !$('analysis').hidden){ anAIState(); return; }
  if(openId!==null) render();
}

function showAI(out, id){
  const e=expl.get(id); if(!e) return;
  out.hidden=false; out.classList.remove('err'); out.textContent=e.text;
  const via=document.createElement('span'); via.className='via';
  via.textContent='via AI model · cached per alert';
  out.appendChild(via);
}

function showErr(out, msg){
  out.hidden=false; out.classList.add('err'); out.textContent=msg;
}

async function askAI(id){
  if(loading.has(id)) return;
  if(expl.has(id)){ aiRefresh(); return; }
  errz.delete(id);
  loading.add(id); aiRefresh();
  try{
    const r=await jfetch('/api/explain',{
      method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({alert_id:id})});
    const j=await r.json();
    if(!r.ok||j.error) throw new Error(j.error||('HTTP '+r.status));
    expl.set(id,{text:j.explanation, model:j.model||'model'});
  }catch(e){
    if(e&&e.auth) needUnlock();
    errz.set(id, (e&&e.message)||'XAI request failed');
  }finally{
    loading.delete(id);
    aiRefresh();
  }
}

$('unlock-btn').onclick=tryUnlock;
$('unlock-input').onkeydown=e=>{if(e.key==='Enter')tryUnlock()};
$('q').oninput=render;
$('vseg').onclick=e=>{
  const b=e.target.closest('button'); if(!b) return;
  setView(b.dataset.v);
};
document.addEventListener('click',e=>{
  if($('insight').contains(e.target)) return;
  let el;
  if((el=e.target.closest('#tl .tb'))){ minuteInsight(+el.dataset.i); return; }
  if((el=e.target.closest('#hist .hb[data-i]'))){ histInsight(+el.dataset.lo,+el.dataset.hi,+el.dataset.n); return; }
  if((el=e.target.closest('[data-p]'))){ protoInsight(el.dataset.p); return; }
  if((el=e.target.closest('#tactic-bars .hb'))){ tacInsight(el.dataset.q); return; }
  if((el=e.target.closest('#dst-list .dst'))){ dstInsight(el.dataset.q); return; }
  if((el=e.target.closest('#apt-bars .agroup'))){ aptGroupInsight(el.dataset.g); return; }
  if((el=e.target.closest('.fchip[data-src]'))){ if(!$('feedpipe').hidden) closeFeedPipe(); feedInsight(el.dataset.src); return; }
  if((el=e.target.closest('[data-f]'))){ kpiInsight(el.dataset.f); return; }
});
document.addEventListener('keydown',e=>{
  if(e.key==='Escape'){
    if(!$('insight').hidden){ closeInsight(); return; }
    if(!$('deep').hidden){ closeDeep(); return; }
    if(!$('aipipe').hidden){ closeAiPipe(); return; }
    if(!$('feedpipe').hidden){ closeFeedPipe(); return; }
    if(!$('aptpipe').hidden){ closeAptPipe(); return; }
    if(!$('mlpipe').hidden){ closeMlPipe(); return; }
    if(!$('analysis').hidden){ closeAnalysis(); return; }
    return;
  }
  if(e.key!=='Enter'&&e.key!==' ') return;
  const t=e.target.closest&&e.target.closest('[data-f],#tl .tb,#hist .hb[data-i],.legend .lg,.dst,#tactic-bars .hb,#apt-bars .agroup,.fchip[data-src]');
  if(t&&t.click){ e.preventDefault(); t.click(); }
});
$('ins-close').onclick=closeInsight;
$('ins-scrim').onclick=closeInsight;
$('an-close').onclick=closeAnalysis;
$('an-scrim').onclick=closeAnalysis;
$('mp-close').onclick=closeMlPipe;
$('mp-scrim').onclick=closeMlPipe;
$('ap-close').onclick=closeAptPipe;
$('ap-scrim').onclick=closeAptPipe;
$('ap-cta').onclick=()=>{
  filt=Object.assign(blankF(),{apt:true});
  $('q').value='';
  closeAptPipe();
  setView('alerts');
  render();
};
$('fp-close').onclick=closeFeedPipe;
$('fp-scrim').onclick=closeFeedPipe;
$('fp-cta').onclick=()=>{
  filt=Object.assign(blankF(),{ioc:true});
  $('q').value='';
  closeFeedPipe();
  setView('alerts');
  render();
};
$('dw-close').onclick=closeDeep;
$('dw-scrim').onclick=closeDeep;
$('ai-close').onclick=closeAiPipe;
$('ai-scrim').onclick=closeAiPipe;
$('dw-cta').onclick=()=>{
  filt=Object.assign(blankF(),dwFilt||{});
  $('q').value='';
  closeDeep();
  setView('alerts');
  render();
};
$('an-p-src').onclick=()=>{ if(anAlert) pivotAlert(anAlert.flow&&anAlert.flow.src_ip); };
$('an-p-dst').onclick=()=>{ if(anAlert) pivotAlert(anAlert.flow&&anAlert.flow.dst_ip); };
$('ins-cta').onclick=()=>{
  if(!insFilt) return;
  const f=insFilt;
  filt=Object.assign(blankF(), f);
  const q=f.q||'';
  $('q').value=q;
  closeInsight();
  setView('alerts');
  render();
};
$('fpills').onclick=e=>{
  const p=e.target.closest('.fp'); if(!p) return;
  const k=p.dataset.k;
  if(k==='minute') filt.minute=null;
  else if(k==='proto') filt.proto='';
  else if(k==='score') filt.score=null;
  else if(k==='ioc') filt.ioc=false;
  else if(k==='apt') filt.apt=false;
  else if(k==='recent') filt.recent=false;
  render();
};
$('seg').onclick=e=>{
  const b=e.target.closest('button'); if(!b) return;
  limit=+b.dataset.n;
  for(const x of $('seg').children) x.classList.toggle('on',x===b);
  poll();
};
poll(); setInterval(poll,3000);
</script>
</body></html>"""

BUILD = str(int(Path(__file__).stat().st_mtime))
INDEX_HTML = INDEX_HTML.replace("__BUILD__", BUILD)
