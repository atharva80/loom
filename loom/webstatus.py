"""Minimal live run-status web server for loom.

Serves a single terminal-style page that polls a JSON endpoint:
  GET /            → the page
  GET /api/status  → JSON snapshot of runs, stages, timers, log tail

Stdlib only (http.server + sqlite3). No framework, no dependencies.
Start with:  loom status-server --workdir <dir> [--port 8080]
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PAGE = """<!doctype html>
<html><head><meta charset="utf-8">
<title>loom — run status</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: #0d0d0d; color: #c8c8c8;
    font: 13px/1.5 ui-monospace, "JetBrains Mono", Menlo, Consolas, monospace;
    padding: 20px 24px 60px; max-width: 1100px; margin: 0 auto;
  }
  header { display: flex; align-items: baseline; gap: 14px; margin-bottom: 18px;
           border-bottom: 1px solid #262626; padding-bottom: 10px; }
  h1 { font-size: 15px; font-weight: 600; color: #e8e8e8; letter-spacing: .02em; }
  #clock { color: #6a6a6a; font-size: 12px; margin-left: auto; }
  #workdir { color: #6a6a6a; font-size: 12px; }
  .run { border: 1px solid #222; margin-bottom: 16px; }
  .run-head { display: flex; gap: 16px; padding: 8px 12px; background: #141414;
              border-bottom: 1px solid #222; align-items: baseline; }
  .run-head .rid { color: #666; }
  .run-head .domain { color: #e8e8e8; font-weight: 600; }
  .run-head .pipeline { color: #7a7a7a; font-size: 12px; }
  .timer { margin-left: auto; color: #9a9a9a; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 4px 12px; font-size: 12.5px;
           border-bottom: 1px solid #1c1c1c; white-space: nowrap; }
  th { color: #555; font-weight: 500; text-transform: uppercase; font-size: 10.5px;
       letter-spacing: .08em; background: #101010; }
  td.tool { color: #d0d0d0; }
  td.stage { color: #888; }
  td.dur { color: #6a6a6a; text-align: right; }
  .err { color: #e05f5f; font-size: 11.5px; padding: 2px 12px 6px 12px;
         white-space: pre-wrap; word-break: break-all; }
  .st { font-weight: 600; }
  .st-done { color: #5fdd5f; } .st-running { color: #e8c15a; }
  .st-failed { color: #e05f5f; } .st-timeout { color: #e05f5f; }
  .st-skipped { color: #555; } .st-pending { color: #555; }
  pre#log { background: #0a0a0a; border: 1px solid #222; padding: 10px 12px;
            margin-top: 18px; max-height: 340px; overflow-y: auto;
            font: 12px/1.55 ui-monospace, Menlo, Consolas, monospace;
            white-space: pre-wrap; word-break: break-all; color: #9a9a9a; }
  .empty { color: #555; padding: 14px 12px; }
  .counts { margin-top: 14px; display: flex; gap: 22px; color: #7a7a7a; font-size: 12px; }
  .counts b { color: #c8c8c8; font-weight: 600; }
</style></head>
<body>
<header>
  <h1>loom — run status</h1>
  <span id="workdir">-</span>
  <span id="clock">-</span>
</header>
<div id="runs"><div class="empty">loading…</div></div>
<div class="counts" id="counts"></div>
<pre id="log"></pre>
<script>
const esc = s => String(s).replace(/[&<>"]/g, c =>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function fmtDur(s) {
  if (s == null) return '—';
  if (s < 1) return Math.round(s*1000) + 'ms';
  if (s < 60) return s.toFixed(1) + 's';
  const m = Math.floor(s/60), r = Math.round(s%60);
  return m + 'm' + String(r).padStart(2,'0') + 's';
}
function cls(st) { return 'st st-' + st; }
function render(d) {
  document.getElementById('workdir').textContent = d.workdir || '';
  document.getElementById('clock').textContent = new Date().toLocaleTimeString();
  const runs = document.getElementById('runs');
  if (!d.runs || !d.runs.length) {
    runs.innerHTML = '<div class="empty">no runs in this workdir</div>';
  } else {
    runs.innerHTML = d.runs.map(r => {
      const stages = (r.stages && r.stages.length)
        ? '<table><tr><th>tool</th><th>stage</th><th>status</th><th>duration</th></tr>' +
          r.stages.map(s =>
            '<tr><td class="tool">' + esc(s.tool) + '</td>' +
            '<td class="stage">' + esc(s.stage) + '</td>' +
            '<td class="' + cls(s.status) + '">' + esc(s.status) + '</td>' +
            '<td class="dur">' + fmtDur(s.duration_s) + '</td></tr>' +
            ((s.status === 'failed' || s.status === 'timeout') && s.error
              ? '<tr><td></td><td class="err" colspan="3">' +
                esc(s.error).slice(0, 500) + '</td></tr>'
              : '')).join('') +
          '</table>'
        : '<div class="empty">no stages yet</div>';
      return '<div class="run"><div class="run-head">' +
        '<span class="rid">run ' + r.id + '</span>' +
        '<span class="domain">' + esc(r.domain) + '</span>' +
        '<span class="pipeline">' + esc(r.pipeline || '') + '</span>' +
        '<span class="' + cls(r.status) + '">' + esc(r.status) + '</span>' +
        '<span class="timer">' + fmtDur(r.elapsed_s) + '</span>' +
        '</div>' + stages + '</div>';
    }).join('');
  }
  const counts = document.getElementById('counts');
  counts.innerHTML = d.event_counts
    ? Object.entries(d.event_counts).map(([k,v]) =>
        '<span>' + esc(k) + ': <b>' + v + '</b></span>').join('')
    : '';
  const log = document.getElementById('log');
  if (d.log_tail && d.log_tail.length) {
    log.textContent = d.log_tail.join('\\n');
    log.scrollTop = log.scrollHeight;
  } else {
    log.textContent = '';
  }
}
async function tick() {
  try {
    const r = await fetch('/api/status');
    render(await r.json());
  } catch (e) { /* server still booting */ }
}
tick();
setInterval(tick, 2000);
</script>
</body></html>
"""

STATUS_COLORS = {"done": "green", "failed": "red", "timeout": "red",
                 "running": "yellow", "pending": "gray", "skipped": "gray"}


def _now():
    return time.time()


def snapshot(workdir: Path) -> dict:
    db = workdir / "loom.sqlite"
    runs_out: list[dict] = []
    log_tail: list[str] = []
    event_counts: dict[str, int] = {}
    now = _now()

    # Log tail: newest run-N/run.log, last 60 lines.
    logs = sorted(workdir.glob("run-*/run.log"), reverse=True)
    if logs:
        try:
            lines = logs[0].read_text(errors="replace").splitlines()
            log_tail = lines[-60:]
        except OSError:
            pass

    if db.exists():
        try:
            # Plain connect: WAL mode needs read-write access to the
            # -wal/-shm sidecars, so mode=ro URI fails silently.
            con = sqlite3.connect(str(db))
            con.row_factory = sqlite3.Row
            runs = con.execute(
                "SELECT id, domain, pipeline, started_at, finished_at "
                "FROM runs ORDER BY id DESC LIMIT 8"
            ).fetchall()
            for r in runs:
                finished = r["finished_at"]
                elapsed = (finished - r["started_at"]) if finished else (now - r["started_at"])
                status = "done" if finished else "running"
                stages = []
                rows = con.execute(
                    "SELECT tool, stage, status, duration_s, started_at, finished_at, error "
                    "FROM tool_runs WHERE run_id=? ORDER BY rowid",
                    (r["id"],),
                ).fetchall()
                for s in rows:
                    dur = s["duration_s"]
                    if dur is None and s["started_at"]:
                        dur = (s["finished_at"] or now) - s["started_at"]
                    stages.append({
                        "tool": s["tool"], "stage": s["stage"], "status": s["status"],
                        "duration_s": round(dur, 2) if dur is not None else None,
                        "error": s["error"],
                    })
                runs_out.append({
                    "id": r["id"], "domain": r["domain"], "pipeline": r["pipeline"],
                    "status": status, "elapsed_s": round(elapsed, 1), "stages": stages,
                })
            # event counts across the newest run
            if runs:
                ev_file = workdir / f"run-{runs[0]['id']}" / "events.jsonl"
                if ev_file.exists():
                    for line in ev_file.read_text(errors="replace").splitlines():
                        try:
                            obj = json.loads(line)
                            t = obj.get("type", "?")
                            event_counts[t] = event_counts.get(t, 0) + 1
                        except json.JSONDecodeError:
                            pass
            con.close()
        except sqlite3.Error:
            pass

    return {"workdir": str(workdir), "runs": runs_out,
            "log_tail": log_tail, "event_counts": event_counts}


class Handler(BaseHTTPRequestHandler):
    workdir: Path = Path(".")

    def do_GET(self):  # noqa: N802
        if self.path.split("?")[0] == "/api/status":
            body = json.dumps(snapshot(self.workdir)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: N802  (keep console quiet)
        pass


def serve(workdir: Path, port: int = 8080) -> None:
    Handler.workdir = workdir
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"loom status: http://127.0.0.1:{port}  workdir={workdir}", flush=True)
    httpd.serve_forever()


def main() -> None:
    p = argparse.ArgumentParser(prog="loom status-server")
    p.add_argument("--workdir", required=True, help="loom workdir to watch")
    p.add_argument("--port", type=int, default=8080)
    args = p.parse_args()
    serve(Path(args.workdir).expanduser(), args.port)
