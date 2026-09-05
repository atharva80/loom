"""loom web console: launch scans from a form or a raw loom command,
watch live progress, browse outputs and findings.

  loom gui [--port 8080]          # workdir from the global --workdir

Stdlib only. Binds 127.0.0.1. Runs execute as supervised subprocesses
of the same `loom` entrypoint (real streaming logs, process-group
kill); the browser polls JSON — no framework, no dependencies.
"""

from __future__ import annotations

import json
import os
import shlex
import signal
import subprocess
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .webstatus import snapshot

LOG_CAP = 200_000       # bytes served per exec-log read
LOG_FULL_CAP = 500_000
FILE_CAP = 200_000
FILES_CAP = 2000
FINDINGS_CAP = 500
AUTOPILOT_TIMEOUT = 7200  # default per-scope cap for autopilot sweeps

# intensity → pipeline for autopilot
AUTOPILOT_PIPELINES = {"quick": "catchall", "standard": "full",
                       "deep": "deep"}

# Commands the browser may execute (no nesting, no shell).
RUN_FAMILY = {"cmd_run", "cmd_resume", "cmd_sweeps"}
READ_ONLY = {"cmd_findings", "cmd_status", "cmd_list_runs",
             "cmd_diff", "cmd_validate"}
ALLOWED_FUNCS = RUN_FAMILY | READ_ONLY


def _loom_argv() -> list[str]:
    """Argv prefix that re-invokes this loom install (no shell)."""
    sibling = Path(sys.executable).parent / "loom"
    if sibling.exists():
        return [str(sibling)]
    return [sys.executable, "-c",
            "import sys; from loom.cli import main; "
            "sys.exit(main(sys.argv[1:]))"]


class GuiState:
    def __init__(self, workdir: Path):
        self.workdir = workdir
        self.logdir = workdir / "gui-logs"
        self.lock = threading.Lock()
        self.execs: dict[int, dict] = {}
        self.next_id = 1

    def spawn(self, argv: list[str], label: str, kind: str) -> dict:
        with self.lock:
            eid = self.next_id
            self.next_id += 1
        self.logdir.mkdir(parents=True, exist_ok=True)
        log_path = self.logdir / f"exec-{eid}.log"
        env = dict(os.environ, PYTHONUNBUFFERED="1")
        fh = open(log_path, "wb")
        try:
            proc = subprocess.Popen(
                _loom_argv() + argv, stdout=fh, stderr=subprocess.STDOUT,
                env=env, start_new_session=True)
        except Exception:
            fh.close()
            raise
        # Parent keeps no handle on the log file; the child holds it.
        fh.close()
        with self.lock:
            self.execs[eid] = {
                "id": eid, "kind": kind, "label": label,
                "argv": argv, "pid": proc.pid, "proc": proc,
                "log": str(log_path), "started": time.time(),
                "finished": None, "rc": None, "killed": False,
            }
            return dict(self.execs[eid])

    def poll(self, eid: int) -> "dict | None":
        with self.lock:
            ex = self.execs.get(eid)
            if ex is None:
                return None
            proc = ex["proc"]
        rc = proc.poll()
        if rc is not None and ex["finished"] is None:
            with self.lock:
                ex["finished"] = time.time()
                ex["rc"] = rc
        with self.lock:
            return {k: v for k, v in ex.items() if k != "proc"}

    def poll_all(self) -> list[dict]:
        with self.lock:
            ids = sorted(self.execs)
        return [self.poll(i) for i in ids]

    def overview(self) -> dict:
        """Cheap rollup for the console header: run counts by status,
        findings by severity (cached 15s — aggregation walks every
        events file)."""
        from .cli import aggregate_findings
        now = time.monotonic()
        with self.lock:
            cached = self._overview_cache if hasattr(self, "_overview_cache") else None
        if cached and now - cached[0] < 15:
            return cached[1]
        try:
            import sqlite3 as _sq
            db = self.workdir / "loom.sqlite"
            by_status: dict[str, int] = {}
            total = 0
            if db.exists():
                con = _sq.connect(str(db))
                try:
                    for st, n in con.execute(
                            "SELECT CASE WHEN finished_at IS NULL THEN "
                            "'running' ELSE 'done' END, COUNT(*) FROM runs "
                            "GROUP BY 1"):
                        by_status[st] = n
                        total += n
                finally:
                    con.close()
        except Exception:
            by_status, total = {}, 0
        sev: dict[str, int] = {}
        if (self.workdir / "loom.sqlite").exists():
            try:
                rows, _ = aggregate_findings(self.workdir)
                for r in rows:
                    s = str(r.get("severity") or "info")
                    sev[s] = sev.get(s, 0) + 1
            except (FileNotFoundError, OSError):
                pass
        out = {"runs_total": total, "runs_by_status": by_status,
               "findings_by_severity": sev,
               "findings_total": sum(sev.values())}
        with self.lock:
            self._overview_cache = (now, out)
        return out

    def kill(self, eid: int) -> bool:
        with self.lock:
            ex = self.execs.get(eid)
            if ex is None:
                return False
            proc, pid = ex["proc"], ex["pid"]
        if proc.poll() is not None:
            return True
        try:
            os.killpg(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            proc.kill()
        except (ProcessLookupError, PermissionError, OSError):
            pass
        with self.lock:
            ex["killed"] = True
        return True

    def read_log(self, eid: int, full: bool = False) -> "str | None":
        with self.lock:
            ex = self.execs.get(eid)
            if ex is None:
                return None
            path = Path(ex["log"])
        try:
            data = path.read_bytes()
        except OSError:
            return ""
        cap = LOG_FULL_CAP if full else LOG_CAP
        if len(data) > cap:
            data = data[-cap:]
        return data.decode("utf-8", "replace")


def _pipeline_dag(pipeline: str):
    """Rebuild a pipeline's DAG for visualization (no execution).

    Stage factories only close over the log; nothing runs at build.
    """
    from . import catchall as _catchall
    from .cli import _build_pipeline
    from .runner import Runner
    dag, _ = _build_pipeline(pipeline, None, _catchall, Runner)
    return dag


def dag_with_state(workdir: Path, run_id: int) -> dict:
    """DAG structure + live node states for one run."""
    import sqlite3 as _sq
    db = workdir / "loom.sqlite"
    pipeline, node_rows, tool_rows = None, {}, {}
    try:
        con = _sq.connect(str(db))
        con.row_factory = _sq.Row
        try:
            r = con.execute("SELECT pipeline FROM runs WHERE id=?",
                            (run_id,)).fetchone()
            if r is None:
                return {"error": "unknown run id"}
            pipeline = r["pipeline"]
            for t in con.execute(
                    "SELECT tool, stage, status, duration_s, error "
                    "FROM tool_runs WHERE run_id=?", (run_id,)):
                d = dict(t)
                if d["tool"] == d["stage"]:
                    node_rows[d["tool"]] = d
                tool_rows.setdefault(d["stage"], []).append(d)
        finally:
            con.close()
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    try:
        dag = _pipeline_dag(pipeline)
    except Exception as e:
        return {"error": f"cannot build {pipeline!r} DAG: {e}"}
    nodes = []
    for n in dag.nodes():
        state = node_rows.get(n.id, {}).get("status") or "pending"
        tools = [{"tool": t["tool"], "status": t["status"],
                  "duration_s": t["duration_s"],
                  "error": (t["error"] or "")[:300]}
                 for t in tool_rows.get(n.id, [])]
        nodes.append({"id": n.id, "inputs": sorted(n.inputs or []),
                      "outputs": sorted(n.outputs or []),
                      "depends_on": list(n.depends_on or []),
                      "status": state,
                      "duration_s": node_rows.get(n.id, {}).get("duration_s"),
                      "tools": tools})
    try:
        levels = dag.levels()
    except Exception:
        levels = [[n["id"] for n in nodes]]
    return {"run_id": run_id, "pipeline": pipeline,
            "levels": levels, "nodes": nodes}


def _parse_command(text: str):
    """Parse a raw loom command string. Returns (argv, func_name) or
    raises ValueError. Only allowlisted subcommands pass."""
    from .cli import build_parser
    try:
        tokens = shlex.split(text.strip())
    except ValueError as e:
        raise ValueError(f"cannot parse command: {e}")
    if tokens and tokens[0] == "loom":
        tokens = tokens[1:]
    if not tokens:
        raise ValueError("empty command — try: run example.com --pipeline web")
    try:
        args = build_parser().parse_args(tokens)
    except SystemExit:
        raise ValueError("unknown command or bad flags (see `loom --help`)")
    func = getattr(args, "func", None)
    name = getattr(func, "__name__", "?")
    if name not in ALLOWED_FUNCS:
        raise ValueError(
            f"`{tokens[0]}` cannot run from the console "
            f"(allowed: run, resume, sweeps, findings, status, "
            f"list-runs, diff, validate)")
    return tokens, name


def _check_scope(domain: str, scope_name: str) -> "str | None":
    """Return an error string when the scope gate refuses the target."""
    from .cli import _resolve_scope
    try:
        scope = _resolve_scope(scope_name, target=domain)
    except SystemExit:
        return f"unknown scope profile {scope_name!r}"
    if not scope.is_host_allowed(domain):
        return (f"target {domain!r} is denied by scope "
                f"{scope.name!r}; refusing to run")
    return None


class Handler(BaseHTTPRequestHandler):
    state: GuiState = None  # type: ignore
    server_version = "loom-gui"

    # ---------- helpers ----------

    def _send_json(self, obj, status: int = 200) -> None:
        body = json.dumps(obj, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_page(self) -> None:
        body = PAGE.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n <= 0 or n > 100_000:
            return {}
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except (json.JSONDecodeError, ValueError):
            return {}

    def _jail(self, *parts: str) -> "Path | None":
        """Resolve run-relative paths, jailed inside the workdir."""
        base = self.state.workdir.resolve()
        try:
            p = (base.joinpath(*parts)).resolve()
        except (ValueError, OSError):
            return None
        try:
            p.relative_to(base)
        except ValueError:
            return None
        # .. segments must not climb out of the run dir either.
        if any(".." in part for part in parts):
            return None
        return p

    def log_message(self, format, *args):  # noqa: N802
        pass

    # ---------- routes ----------

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(url.query)
        path = url.path
        try:
            if path == "/":
                self._send_page()
            elif path == "/api/state":
                self._send_json({
                    "snapshot": snapshot(self.state.workdir),
                    "executions": self.state.poll_all(),
                    "overview": self.state.overview(),
                })
            elif path == "/api/exec":
                eid = int(q.get("id", ["0"])[0])
                full = q.get("full", ["0"])[0] == "1"
                meta = self.state.poll(eid)
                if meta is None:
                    self._send_json({"error": "unknown exec id"}, 404)
                else:
                    meta["log"] = self.state.read_log(eid, full) or ""
                    self._send_json(meta)
            elif path == "/api/dag":
                try:
                    rid = int(q.get("run", ["0"])[0])
                except (ValueError, TypeError):
                    rid = 0
                self._send_json(dag_with_state(self.state.workdir, rid))
            elif path == "/api/findings":
                from .cli import aggregate_findings
                try:
                    rows, _ = aggregate_findings(self.state.workdir)
                except FileNotFoundError:
                    rows = []
                except OSError:
                    rows = []
                self._send_json(rows[:FINDINGS_CAP])
            elif path == "/api/files":
                self._send_json(self._file_tree(q.get("run", [""])[0]))
            elif path == "/api/file":
                self._send_file(q.get("run", [""])[0], q.get("path", [""])[0])
            else:
                self._send_json({"error": "not found"}, 404)
        except (ValueError, OSError) as e:
            self._send_json({"error": f"{type(e).__name__}: {e}"}, 400)

    def do_POST(self):
        url = urllib.parse.urlsplit(self.path)
        try:
            if url.path == "/api/run":
                self._handle_run(self._read_json())
            elif url.path == "/api/autopilot":
                self._handle_autopilot(self._read_json())
            elif url.path == "/api/command":
                self._handle_command(self._read_json())
            elif url.path == "/api/kill":
                eid = int(self._read_json().get("id", 0))
                if not self.state.kill(eid):
                    self._send_json({"error": "unknown exec id"}, 404)
                else:
                    self._send_json(self.state.poll(eid))
            else:
                self._send_json({"error": "not found"}, 404)
        except (ValueError, OSError) as e:
            self._send_json({"error": f"{type(e).__name__}: {e}"}, 400)

    # ---------- handlers ----------

    def _handle_run(self, body: dict) -> None:
        domain = str(body.get("domain") or "").strip()
        if not domain:
            self._send_json({"error": "domain is required"}, 400)
            return
        pipeline = str(body.get("pipeline") or "catchall")
        scope_name = str(body.get("scope") or "default")
        denied = _check_scope(domain, scope_name)
        if denied:
            self._send_json({"error": denied}, 403)
            return
        argv = ["--workdir", str(self.state.workdir), "run", domain,
                "--pipeline", pipeline,
                "--scope", scope_name,
                "--mode", str(body.get("mode") or "recon")]
        try:
            conc = int(body.get("max_concurrency") or 10)
        except (ValueError, TypeError):
            conc = 10
        argv += ["--max-concurrency", str(max(1, min(conc, 50)))]
        ex = self.state.spawn(argv, f"run {domain} --pipeline {pipeline}",
                              "run")
        self._send_json({k: v for k, v in ex.items() if k != "proc"})

    def _handle_autopilot(self, body: dict) -> None:
        raw = body.get("targets", "")
        if isinstance(raw, str):
            targets = [t.strip().lower().rstrip(".")
                       for t in raw.replace(",", "\n").split("\n")]
        else:
            targets = [str(t).strip().lower().rstrip(".") for t in raw]
        targets = [t for t in targets if t and "." in t][:25]
        if not targets:
            self._send_json({"error": "no valid targets (need bare domains)"},
                            400)
            return
        intensity = str(body.get("intensity") or "standard")
        pipeline = AUTOPILOT_PIPELINES.get(intensity, "full")
        scope_name = str(body.get("scope") or "default")
        denied = [t for t in targets
                  if _check_scope(t, scope_name) is not None]
        if denied:
            self._send_json({"error": f"scope {scope_name!r} denies: "
                                      f"{', '.join(denied[:5])}"}, 403)
            return
        self.state.logdir.mkdir(parents=True, exist_ok=True)
        csv_path = self.state.logdir / "autopilot-scopes.csv"
        csv_path.write_text("".join(f"{t},{pipeline},10\n" for t in targets))
        argv = ["--workdir", str(self.state.workdir), "sweeps",
                "--scopes-file", str(csv_path),
                "--timeout", str(AUTOPILOT_TIMEOUT)]
        ex = self.state.spawn(
            argv, f"autopilot {len(targets)} targets → {pipeline}",
            "autopilot")
        self._send_json({k: v for k, v in ex.items() if k != "proc"})

    def _handle_command(self, body: dict) -> None:
        try:
            tokens, name = _parse_command(str(body.get("command") or ""))
        except ValueError as e:
            self._send_json({"error": str(e)}, 400)
            return
        if "--workdir" not in tokens:
            tokens = ["--workdir", str(self.state.workdir)] + tokens
        ex = self.state.spawn(tokens, " ".join(tokens[:6]), "command")
        self._send_json({k: v for k, v in ex.items() if k != "proc"})

    def _file_tree(self, run: str) -> list[dict]:
        try:
            rid = int(run)
        except (ValueError, TypeError):
            return []
        out = []
        for sub in ("outputs", "inputs"):
            root = self._jail(f"run-{rid}", sub)
            if root is None or not root.is_dir():
                continue
            for p in sorted(root.rglob("*")):
                if p.is_file():
                    try:
                        size = p.stat().st_size
                    except OSError:
                        continue
                    out.append({"path": f"{sub}/{p.relative_to(root)}",
                                "size": size})
                    if len(out) >= FILES_CAP:
                        return out
        return out

    def _send_file(self, run: str, rel: str) -> None:
        try:
            rid = int(run)
        except (ValueError, TypeError):
            self._send_json({"error": "bad run id"}, 400)
            return
        if not rel or rel.startswith("/"):
            self._send_json({"error": "bad path"}, 400)
            return
        p = self._jail(f"run-{rid}", rel)
        if p is None or not p.is_file():
            self._send_json({"error": "not found"}, 404)
            return
        try:
            data = p.read_bytes()
        except OSError as e:
            self._send_json({"error": f"cannot read: {e}"}, 400)
            return
        if len(data) > FILE_CAP:
            data = data[:FILE_CAP]
        body = json.dumps({"path": rel, "size": p.stat().st_size,
                           "truncated": len(data) >= FILE_CAP,
                           "content": data.decode("utf-8", "replace")})
        raw = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def cmd_gui(args) -> int:
    """`loom gui`: serve the web console (127.0.0.1 only)."""
    from pathlib import Path as _P
    workdir = _P(getattr(args, "workdir", None)
                 or str(_default_workdir())).expanduser()
    port = int(getattr(args, "port", 8080) or 8080)
    serve_forever(workdir, port)
    return 0


def _default_workdir():
    from .cli import DEFAULT_WORKDIR
    return DEFAULT_WORKDIR


def serve_forever(workdir: Path, port: int = 8080) -> None:
    Handler.state = GuiState(workdir)
    try:
        httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    except OSError as e:
        print(f"error: cannot listen on 127.0.0.1:{port} "
              f"({e.strerror or e}); is something already on it? "
              f"try --port", file=sys.stderr)
        raise SystemExit(2)
    print(f"loom console: http://127.0.0.1:{port}  workdir={workdir}",
          flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


PAGE = """<!doctype html>
<html><head><meta charset="utf-8">
<title>loom console</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0d0d0d; color: #c8c8c8;
    font: 13px/1.5 ui-monospace, "JetBrains Mono", Menlo, Consolas, monospace;
    padding: 20px 24px 80px; max-width: 1100px; margin: 0 auto; }
  header { display: flex; align-items: baseline; gap: 14px; margin-bottom: 18px;
           border-bottom: 1px solid #262626; padding-bottom: 10px; }
  h1 { font-size: 15px; font-weight: 600; color: #e8e8e8; }
  h2 { font-size: 12px; font-weight: 600; color: #7a7a7a; text-transform: uppercase;
       letter-spacing: .08em; margin: 22px 0 10px; }
  #clock, #workdir { color: #6a6a6a; font-size: 12px; }
  #clock { margin-left: auto; }
  .card { border: 1px solid #222; background: #101010; padding: 12px;
          margin-bottom: 12px; }
  label { display: block; color: #6a6a6a; font-size: 11px; margin: 8px 0 3px;
          text-transform: uppercase; letter-spacing: .06em; }
  input[type=text], input[type=number], select {
    background: #0a0a0a; border: 1px solid #2c2c2c; color: #e8e8e8;
    font: inherit; font-size: 13px; padding: 6px 9px; width: 100%; }
  input:focus, select:focus { outline: none; border-color: #4a6a8a; }
  .row { display: flex; gap: 10px; } .row > div { flex: 1; }
  button { background: #1c2f1c; border: 1px solid #2f542f; color: #9fe09f;
    font: inherit; font-size: 13px; padding: 7px 16px; cursor: pointer;
    margin-top: 12px; }
  button:hover { background: #254025; }
  button.danger { background: #2f1c1c; border-color: #542f2f; color: #e09f9f; }
  button.ghost { background: #141414; border-color: #2c2c2c; color: #9a9a9a; }
  button:disabled { opacity: .45; cursor: default; }
  .hint { color: #555; font-size: 11.5px; margin-top: 8px; }
  .err-line { color: #e05f5f; margin-top: 8px; white-space: pre-wrap; }
  .pill { display: inline-block; font-size: 11px; font-weight: 600;
    padding: 1px 8px; border: 1px solid #333; }
  .p-running { color: #e8c15a; border-color: #5a4a1a; }
  .p-done { color: #5fdd5f; border-color: #1f4a1f; }
  .p-failed, .p-timeout, .p-killed { color: #e05f5f; border-color: #4a1f1f; }
  .exec-head { display: flex; gap: 12px; align-items: baseline; flex-wrap: wrap; }
  .exec-head .lbl { color: #e8e8e8; } .exec-head .meta { color: #6a6a6a; font-size: 11.5px; }
  pre.log { background: #0a0a0a; border: 1px solid #222; padding: 10px 12px;
    margin-top: 8px; max-height: 260px; overflow-y: auto;
    font-size: 12px; white-space: pre-wrap; word-break: break-all; color: #9a9a9a; }
  .run { border: 1px solid #222; margin-bottom: 12px; }
  .run-head { display: flex; gap: 14px; padding: 8px 12px; background: #141414;
              border-bottom: 1px solid #222; align-items: baseline; flex-wrap: wrap; }
  .run-head .rid { color: #666; } .run-head .domain { color: #e8e8e8; font-weight: 600; }
  .run-head .pipeline { color: #7a7a7a; font-size: 12px; }
  .timer { margin-left: auto; color: #9a9a9a; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 4px 12px; font-size: 12.5px;
           border-bottom: 1px solid #1c1c1c; }
  th { color: #555; font-weight: 500; text-transform: uppercase; font-size: 10.5px; }
  td.tool { color: #d0d0d0; } td.stage { color: #888; }
  td.dur { color: #6a6a6a; text-align: right; white-space: nowrap; }
  .st { font-weight: 600; } .st-done { color: #5fdd5f; } .st-running { color: #e8c15a; }
  .st-failed, .st-timeout { color: #e05f5f; } .st-skipped { color: #555; }
  .err { color: #e05f5f; font-size: 11.5px; padding: 2px 12px 6px 12px;
         white-space: pre-wrap; word-break: break-all; }
  .sev-critical { color: #ff5f5f; font-weight: 700; } .sev-high { color: #e05f5f; }
  .sev-medium { color: #e8c15a; } .sev-low { color: #7ab8e0; } .sev-info { color: #666; }
  td.val { word-break: break-all; font-size: 12px; }
  .filelist { max-height: 220px; overflow-y: auto; border: 1px solid #222;
    padding: 6px 0; margin-top: 8px; }
  .filelist div { padding: 2px 12px; cursor: pointer; font-size: 12px; color: #9a9a9a; }
  .filelist div:hover { background: #1a1a1a; color: #e8e8e8; }
  .filelist span.sz { color: #555; float: right; }
  pre.view { background: #0a0a0a; border: 1px solid #222; padding: 10px 12px;
    margin-top: 8px; max-height: 400px; overflow: auto; font-size: 12px;
    white-space: pre-wrap; word-break: break-all; color: #9a9a9a; }
  .empty { color: #555; padding: 10px 0; }
  #overview { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 6px; }
  .stat { border: 1px solid #222; background: #101010; padding: 8px 14px;
    min-width: 130px; }
  .stat .v { font-size: 20px; font-weight: 600; color: #e8e8e8; }
  .stat .k { font-size: 11px; color: #6a6a6a; text-transform: uppercase;
    letter-spacing: .06em; }
  textarea { background: #0a0a0a; border: 1px solid #2c2c2c; color: #e8e8e8;
    font: inherit; font-size: 13px; padding: 6px 9px; width: 100%;
    min-height: 64px; resize: vertical; }
  textarea:focus { outline: none; border-color: #4a6a8a; }
  .seg { display: flex; gap: 0; margin-top: 4px; }
  .seg button { flex: 1; margin-top: 0; background: #141414;
    border: 1px solid #2c2c2c; color: #9a9a9a; }
  .seg button.on { background: #1c2f1c; border-color: #2f542f; color: #9fe09f; }
  svg.dag { width: 100%; height: auto; display: block; }
  .dag text { font: 11px ui-monospace, Menlo, Consolas, monospace; }
  .node { cursor: pointer; }
  .node rect { stroke-width: 1.5; }
  .node:hover rect { stroke: #e8e8e8; }
  .node.sel rect { stroke: #e8e8e8; stroke-width: 2.5; }
  #node-detail { margin-top: 8px; }
  canvas.spark { width: 100%; height: 44px; display: block; }
</style></head>
<body>
<header><h1>loom console</h1><span id="workdir">-</span><span id="clock">-</span></header>

<div id="overview">
  <div class="stat"><div class="v" id="ov-runs">-</div><div class="k">runs</div></div>
  <div class="stat"><div class="v" id="ov-running">-</div><div class="k">running</div></div>
  <div class="stat"><div class="v" id="ov-findings">-</div><div class="k">findings</div></div>
  <div class="stat"><div class="v" id="ov-events">-</div><div class="k">events/min</div></div>
  <div class="stat"><svg id="donut" width="44" height="44" viewBox="0 0 44 44"></svg></div>
  <div class="stat" style="flex:1;min-width:220px"><canvas class="spark" id="spark" width="600" height="44"></canvas></div>
</div>

<h2>autopilot</h2>
<div class="card">
  <label>targets — one domain per line (up to 25)</label>
  <textarea id="a-targets" placeholder="example.com&#10;api.example.com"></textarea>
  <div class="row">
    <div><label>intensity</label><div class="seg" id="a-seg">
      <button data-v="quick">quick</button><button data-v="standard" class="on">standard</button><button data-v="deep">deep</button>
    </div></div>
    <div><label>scope profile</label><input type="text" id="a-scope" value="default"></div>
  </div>
  <button id="b-auto">start autopilot</button>
  <span class="hint">quick=catchall · standard=full · deep=deep — one sweep, 2h per-scope cap, scope gate enforced</span>
  <div class="err-line" id="auto-err"></div>
</div>

<h2>launch</h2>
<div class="card">
  <div class="row">
    <div><label>domain</label><input type="text" id="f-domain" placeholder="example.com"></div>
    <div><label>pipeline</label><select id="f-pipe">
      <option>catchall</option><option>subdomain</option><option>web</option>
      <option>full</option><option>deep</option>
    </select></div>
  </div>
  <div class="row">
    <div><label>scope profile</label><input type="text" id="f-scope" value="default"></div>
    <div><label>mode</label><select id="f-mode">
      <option>recon</option><option>fast</option><option>deep</option>
    </select></div>
    <div><label>max concurrency</label><input type="number" id="f-conc" value="10" min="1" max="50"></div>
  </div>
  <button id="b-launch">run scan</button>
  <span class="hint">same as <b>loom run</b> — scope gate enforced server-side</span>
  <div class="err-line" id="launch-err"></div>
</div>
<div class="card">
  <label>loom command</label>
  <input type="text" id="f-cmd" placeholder="loom run example.com --pipeline web">
  <button id="b-cmd">execute</button>
  <div class="hint">run · resume · sweeps · findings · status · list-runs · diff · validate</div>
  <div class="err-line" id="cmd-err"></div>
</div>

<h2>executions</h2>
<div id="execs"><div class="empty">none yet</div></div>

<h2>runs (live)</h2>
<div id="runs"><div class="empty">loading…</div></div>

<h2>findings</h2>
<div class="card">
  <button class="ghost" id="b-findings">refresh findings</button>
  <span class="hint" id="findings-count"></span>
  <div id="findings"><div class="empty">not loaded</div></div>
</div>

<h2>files</h2>
<div class="card">
  <div class="row">
    <div><label>run</label><select id="file-run"></select></div>
    <div><label>&nbsp;</label><button class="ghost" id="b-files">list files</button></div>
  </div>
  <div class="filelist" id="filelist" style="display:none"></div>
  <pre class="view" id="fileview" style="display:none"></pre>
</div>

<script>
const esc = s => String(s == null ? "" : s).replace(/[&<>"]/g, c =>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function fmtDur(s) {
  if (s == null) return '\\u2014';
  if (s < 1) return Math.round(s*1000) + 'ms';
  if (s < 60) return s.toFixed(1) + 's';
  const m = Math.floor(s/60), r = Math.round(s%60);
  return m + 'm' + String(r).padStart(2,'0') + 's';
}
function cls(st) { return 'st st-' + st; }
async function post(url, obj) {
  const r = await fetch(url, {method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(obj)});
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || ('http ' + r.status));
  return j;
}
document.getElementById('b-launch').onclick = async () => {
  const err = document.getElementById('launch-err'); err.textContent = '';
  try {
    await post('/api/run', {
      domain: document.getElementById('f-domain').value,
      pipeline: document.getElementById('f-pipe').value,
      scope: document.getElementById('f-scope').value,
      mode: document.getElementById('f-mode').value,
      max_concurrency: parseInt(document.getElementById('f-conc').value || '10', 10)});
    tick();
  } catch (e) { err.textContent = e.message; }
};
document.getElementById('b-cmd').onclick = async () => {
  const err = document.getElementById('cmd-err'); err.textContent = '';
  try {
    await post('/api/command', {command: document.getElementById('f-cmd').value});
    tick();
  } catch (e) { err.textContent = e.message; }
};
function execStatus(ex) {
  if (ex.finished) {
    if (ex.killed) return ['killed', 'p-killed'];
    return [(ex.rc === 0 ? 'done' : 'failed'), (ex.rc === 0 ? 'p-done' : 'p-failed')];
  }
  return ['running', 'p-running'];
}
let fullLog = {};
async function toggleFull(id) {
  fullLog[id] = !fullLog[id];
  const r = await fetch('/api/exec?id=' + id + (fullLog[id] ? '&full=1' : ''));
  const ex = await r.json();
  document.getElementById('log-' + id).textContent = ex.log || '(empty)';
}
function renderExecs(list) {
  const el = document.getElementById('execs');
  if (!list || !list.length) { el.innerHTML = '<div class="empty">none yet</div>'; return; }
  el.innerHTML = list.slice().reverse().map(ex => {
    const [txt, pc] = execStatus(ex);
    const dur = fmtDur((ex.finished || Date.now()/1000) - ex.started);
    const tail = esc((ex.log_tail || '').slice(-6000));
    return '<div class="card"><div class="exec-head">' +
      '<span class="pill ' + pc + '">' + txt + '</span>' +
      '<span class="lbl">' + esc(ex.label) + '</span>' +
      '<span class="meta">#' + ex.id + ' · ' + dur +
      (ex.finished ? ' · rc=' + ex.rc : '') + '</span>' +
      (!ex.finished ? ' <button class="danger" data-kill="' + ex.id + '">kill</button>' : '') +
      ' <button class="ghost" data-full="' + ex.id + '">full log</button>' +
      '</div><pre class="log" id="log-' + ex.id + '">' + tail + '</pre></div>';
  }).join('');
  el.querySelectorAll('[data-kill]').forEach(b => b.onclick = async () => {
    await post('/api/kill', {id: parseInt(b.dataset.kill, 10)}); tick(); });
  el.querySelectorAll('[data-full]').forEach(b => b.onclick = () =>
    toggleFull(parseInt(b.dataset.full, 10)));
}
const STATUS_FILL = {done:'#1c3a1c', failed:'#3a1c1c', timeout:'#3a1c1c',
  running:'#3a3016', skipped:'#161616', pending:'#101010'};
const STATUS_EDGE = {done:'#2f542f', failed:'#542f2f', timeout:'#542f2f',
  running:'#5a4a1a', skipped:'#2c2c2c', pending:'#222222'};
const STATUS_TX = {done:'#9fe09f', failed:'#e09f9f', timeout:'#e09f9f',
  running:'#e8c15a', skipped:'#555555', pending:'#444444'};
let dagCache = {}, selNode = {};
function dagSvg(runId, dag) {
  const W = 150, H = 44, GAPX = 26, GAPY = 14, PAD = 8;
  const levels = dag.levels || [];
  const byId = {};
  (dag.nodes || []).forEach(n => byId[n.id] = n);
  const maxRows = Math.max.apply(null, levels.map(l => l.length).concat([1]));
  const width = levels.length * (W + GAPX) + PAD * 2 - GAPX;
  const height = maxRows * (H + GAPY) + PAD * 2 - GAPY;
  let s = '<svg class="dag" viewBox="0 0 ' + width + ' ' + height + '">';
  const pos = {};
  levels.forEach((lvl, li) => lvl.forEach((nid, ri) => {
    pos[nid] = {x: PAD + li * (W + GAPX), y: PAD + ri * (H + GAPY)};
  }));
  Object.keys(pos).forEach(nid => {
    const n = byId[nid] || {depends_on: []};
    (n.depends_on || []).forEach(dep => {
      if (!pos[dep]) return;
      const a = pos[dep], b = pos[nid];
      s += '<line x1="' + (a.x + W) + '" y1="' + (a.y + H/2) +
           '" x2="' + b.x + '" y2="' + (b.y + H/2) +
           '" stroke="#333" stroke-width="1.5"/>';
    });
  });
  Object.keys(pos).forEach(nid => {
    const n = byId[nid] || {id: nid, status: 'pending', tools: []};
    const p = pos[nid], st = n.status || 'pending';
    const sel = selNode[runId] === nid ? ' sel' : '';
    const label = nid.length > 18 ? nid.slice(0, 17) + '…' : nid;
    const sub = (n.tools || []).length
      ? n.tools.length + ' tools' : st;
    s += '<g class="node' + sel + '" data-run="' + runId +
         '" data-node="' + esc(nid) + '">' +
      '<rect x="' + p.x + '" y="' + p.y + '" width="' + W + '" height="' + H +
      '" rx="4" fill="' + (STATUS_FILL[st] || '#101010') +
      '" stroke="' + (STATUS_EDGE[st] || '#222') + '"/>' +
      '<text x="' + (p.x + 8) + '" y="' + (p.y + 18) +
      '" fill="' + (STATUS_TX[st] || '#888') + '">' + esc(label) + '</text>' +
      '<text x="' + (p.x + 8) + '" y="' + (p.y + 33) + '" fill="#666">' +
      esc(sub) + '</text></g>';
  });
  return s + '</svg>';
}
function renderNodeDetail(runId, dag) {
  const el = document.getElementById('node-detail-' + runId);
  if (!el) return;
  const nid = selNode[runId];
  const n = (dag.nodes || []).find(x => x.id === nid);
  if (!n) { el.innerHTML = '<div class="hint">click a stage for tool detail</div>'; return; }
  const dur = n.duration_s != null ? ' · ' + fmtDur(n.duration_s) : '';
  let h = '<div class="hint">' + esc(nid) + ' · ' + esc(n.status) + dur + '</div>';
  if (n.tools && n.tools.length) {
    h += '<table><tr><th>tool</th><th>status</th><th>duration</th></tr>' +
      n.tools.map(t =>
        '<tr><td class="tool">' + esc(t.tool) + '</td>' +
        '<td class="' + cls(t.status) + '">' + esc(t.status) + '</td>' +
        '<td class="dur">' + fmtDur(t.duration_s) + '</td></tr>' +
        (t.error ? '<tr><td></td><td class="err" colspan="2">' +
          esc(t.error).slice(0, 300) + '</td></tr>' : '')).join('') +
      '</table>';
  }
  el.innerHTML = h;
}
async function renderRuns(snap) {
  document.getElementById('workdir').textContent = snap.workdir || '';
  const el = document.getElementById('runs');
  const runs = snap.runs || [];
  if (!runs.length) { el.innerHTML = '<div class="empty">no runs in this workdir</div>'; return; }
  let h = '';
  for (const r of runs) {
    let dag = dagCache[r.id];
    try {
      const rr = await fetch('/api/dag?run=' + r.id);
      dag = await rr.json();
      if (!dag.error) dagCache[r.id] = dag;
    } catch (e) { /* keep cached */ }
    if (!dag || dag.error) {
      h += '<div class="run"><div class="run-head"><span class="rid">run ' + r.id +
        '</span><span class="domain">' + esc(r.domain) + '</span></div></div>';
      continue;
    }
    h += '<div class="run"><div class="run-head">' +
      '<span class="rid">run ' + r.id + '</span>' +
      '<span class="domain">' + esc(r.domain) + '</span>' +
      '<span class="pipeline">' + esc(dag.pipeline || r.pipeline || '') + '</span>' +
      '<span class="' + cls(r.status) + '">' + esc(r.status) + '</span>' +
      '<span class="timer">' + fmtDur(r.elapsed_s) + '</span>' +
      '</div>' + dagSvg(r.id, dag) +
      '<div id="node-detail-' + r.id + '"></div></div>';
  }
  el.innerHTML = h;
  el.querySelectorAll('.node').forEach(g => g.onclick = () => {
    const rid = parseInt(g.dataset.run, 10);
    selNode[rid] = g.dataset.node;
    el.querySelectorAll('.node').forEach(x => x.classList.remove('sel'));
    g.classList.add('sel');
    renderNodeDetail(rid, dagCache[rid]);
  });
  runs.forEach(r => { if (dagCache[r.id]) renderNodeDetail(r.id, dagCache[r.id]); });
}
function sevCls(s) { return 'sev-' + (s || 'info'); }
async function loadFindings() {
  const el = document.getElementById('findings');
  el.innerHTML = '<div class="empty">loading…</div>';
  try {
    const r = await fetch('/api/findings');
    const rows = await r.json();
    document.getElementById('findings-count').textContent =
      rows.length + ' findings';
    if (!rows.length) { el.innerHTML = '<div class="empty">none</div>'; return; }
    el.innerHTML = '<table><tr><th>sev</th><th>source</th><th>host</th>' +
      '<th>value</th><th>runs</th></tr>' + rows.slice(0, 200).map(f =>
      '<tr><td class="' + sevCls(f.severity) + '">' + esc(f.severity) + '</td>' +
      '<td class="stage">' + esc(f.source) + '</td>' +
      '<td class="stage">' + esc(f.host) + '</td>' +
      '<td class="val">' + esc(f.value) + '</td>' +
      '<td class="dur">' + esc((f.evidence && f.evidence.runs || []).join(',')) +
      '</td></tr>').join('') + '</table>' +
      (rows.length > 200 ? '<div class="hint">showing 200 of ' + rows.length + '</div>' : '');
  } catch (e) { el.innerHTML = '<div class="err-line">failed to load</div>'; }
}
document.getElementById('b-findings').onclick = loadFindings;
async function refreshFileRuns(runs) {
  const sel = document.getElementById('file-run');
  const cur = sel.value;
  sel.innerHTML = runs.map(r =>
    '<option value="' + r.id + '">run-' + r.id + ' ' + esc(r.domain) + '</option>').join('');
  if (cur) sel.value = cur;
}
document.getElementById('b-files').onclick = async () => {
  const rid = document.getElementById('file-run').value;
  if (!rid) return;
  const r = await fetch('/api/files?run=' + encodeURIComponent(rid));
  const files = await r.json();
  const el = document.getElementById('filelist');
  const fv = document.getElementById('fileview');
  fv.style.display = 'none';
  if (!files.length) {
    el.style.display = 'block';
    el.innerHTML = '<div class="empty">no files</div>';
    return;
  }
  el.style.display = 'block';
  el.innerHTML = files.map(f =>
    '<div data-f="' + esc(f.path) + '">' + esc(f.path) +
    '<span class="sz">' + f.size + '</span></div>').join('');
  el.querySelectorAll('[data-f]').forEach(d => d.onclick = async () => {
    const r2 = await fetch('/api/file?run=' + encodeURIComponent(rid) +
      '&path=' + encodeURIComponent(d.dataset.f));
    const j = await r2.json();
    fv.style.display = 'block';
    fv.textContent = (j.content || '') +
      (j.truncated ? '\\n…[truncated at 200KB]' : '');
  });
};
async function tick() {
  try {
    const r = await fetch('/api/state');
    const d = await r.json();
    document.getElementById('clock').textContent = new Date().toLocaleTimeString();
    renderExecs(d.executions || []);
    renderOverview(d.overview || {}, d.snapshot || {});
    renderRuns(d.snapshot || {});
    refreshFileRuns((d.snapshot && d.snapshot.runs) || []);
  } catch (e) { /* server still booting */ }
}
const SEV_COLORS = {critical:'#ff5f5f', high:'#e05f5f', medium:'#e8c15a',
  low:'#7ab8e0', info:'#555555'};
let evHist = [];
function renderOverview(ov, snap) {
  document.getElementById('ov-runs').textContent = ov.runs_total || 0;
  const rb = ov.runs_by_status || {};
  document.getElementById('ov-running').textContent = rb.running || 0;
  document.getElementById('ov-findings').textContent = ov.findings_total || 0;
  const sev = ov.findings_by_severity || {};
  const total = Object.values(sev).reduce((a, b) => a + b, 0);
  let a0 = -Math.PI / 2, arcs = '';
  Object.keys(sev).forEach(k => {
    const frac = total ? sev[k] / total : 0;
    const a1 = a0 + frac * Math.PI * 2;
    if (frac <= 0) return;
    const large = (a1 - a0) > Math.PI ? 1 : 0;
    const x0 = 22 + 16 * Math.cos(a0), y0 = 22 + 16 * Math.sin(a0);
    const x1 = 22 + 16 * Math.cos(a1), y1 = 22 + 16 * Math.sin(a1);
    arcs += '<path d="M22,22 L' + x0.toFixed(1) + ',' + y0.toFixed(1) +
      ' A16,16 0 ' + large + ',1 ' + x1.toFixed(1) + ',' + y1.toFixed(1) +
      ' Z" fill="' + (SEV_COLORS[k] || '#555') + '"/>';
    a0 = a1;
  });
  document.getElementById('donut').innerHTML = arcs ||
    '<circle cx="22" cy="22" r="16" fill="none" stroke="#222" stroke-width="8"/>';
  let ev = 0;
  Object.values((snap.event_counts) || {}).forEach(v => ev += v);
  const now = Date.now();
  evHist.push([now, ev]);
  evHist = evHist.filter(p => now - p[0] < 10 * 60 * 1000).slice(-120);
  let rate = 0;
  if (evHist.length > 1) {
    const dt = (evHist[evHist.length - 1][0] - evHist[0][0]) / 60000;
    if (dt > 0.02) rate = Math.round((ev - evHist[0][1]) / dt);
  }
  document.getElementById('ov-events').textContent = rate;
  const cv = document.getElementById('spark'), cx = cv.getContext('2d');
  cx.clearRect(0, 0, cv.width, cv.height);
  if (evHist.length > 1) {
    const ys = evHist.map(p => p[1]);
    const lo = Math.min.apply(null, ys), hi = Math.max.apply(null, ys);
    const span = (hi - lo) || 1;
    cx.strokeStyle = '#4a6a8a'; cx.lineWidth = 1.5; cx.beginPath();
    evHist.forEach((p, i) => {
      const x = i / (evHist.length - 1) * cv.width;
      const y = cv.height - 3 - (p[1] - lo) / span * (cv.height - 6);
      i ? cx.lineTo(x, y) : cx.moveTo(x, y);
    });
    cx.stroke();
  }
}
let intensity = 'standard';
document.getElementById('a-seg').querySelectorAll('button').forEach(b =>
  b.onclick = () => {
    intensity = b.dataset.v;
    document.getElementById('a-seg').querySelectorAll('button')
      .forEach(x => x.classList.toggle('on', x === b));
  });
document.getElementById('b-auto').onclick = async () => {
  const err = document.getElementById('auto-err'); err.textContent = '';
  const btn = document.getElementById('b-auto'); btn.disabled = true;
  try {
    await post('/api/autopilot', {
      targets: document.getElementById('a-targets').value,
      intensity: intensity,
      scope: document.getElementById('a-scope').value});
    tick();
  } catch (e) { err.textContent = e.message; }
  btn.disabled = false;
};
tick();
setInterval(tick, 2000);
</script>
</body></html>
"""