"""loom.state — SQLite-backed per-host per-tool resume state.

Schema:
  runs (id PK, domain, started_at, mode, scope_profile)
  tool_runs (run_id FK, host, tool, stage, status, started_at, finished_at,
             output_path, error, PRIMARY KEY (run_id, host, tool, stage))

Statuses: pending | running | done | failed | skipped
"""

import sqlite3
import time
from pathlib import Path
from typing import Optional


SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    started_at REAL NOT NULL,
    finished_at REAL,
    mode TEXT,
    scope_profile TEXT
);
CREATE TABLE IF NOT EXISTS tool_runs (
    run_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    tool TEXT NOT NULL,
    stage TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending','running','done','failed','skipped','timeout')),
    started_at REAL,
    finished_at REAL,
    output_path TEXT,
    error TEXT,
    duration_s REAL,
    PRIMARY KEY (run_id, host, tool, stage),
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_tool_runs_status ON tool_runs(status);
CREATE INDEX IF NOT EXISTS idx_tool_runs_host ON tool_runs(host);
"""


class State:
    def __init__(self, db_path: str | Path):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        # Migrate: add scope_spec column if missing (added in v0.3+).
        cols = {r["name"] for r in self._conn.execute(
            "PRAGMA table_info(runs)"
        ).fetchall()}
        if "scope_spec" not in cols:
            self._conn.execute(
                "ALTER TABLE runs ADD COLUMN scope_spec TEXT"
            )
        if "pipeline" not in cols:
            self._conn.execute(
                "ALTER TABLE runs ADD COLUMN pipeline TEXT"
            )
        if "hosts_json" not in cols:
            self._conn.execute(
                "ALTER TABLE runs ADD COLUMN hosts_json TEXT"
            )
        # WAL for concurrent reader + writer
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")

    def close(self) -> None:
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    # ---- runs ----
    def start_run(self, domain: str, mode: str = "recon", scope_profile: str = "default",
                  scope_spec: Optional[str] = None,
                  pipeline: Optional[str] = None,
                  hosts_json: Optional[str] = None) -> int:
        cur = self._conn.execute(
            "INSERT INTO runs(domain, started_at, mode, scope_profile, "
            "scope_spec, pipeline, hosts_json) VALUES (?,?,?,?,?,?,?)",
            (domain, time.time(), mode, scope_profile,
             scope_spec, pipeline, hosts_json),
        )
        assert cur.lastrowid is not None
        return cur.lastrowid

    def finish_run(self, run_id: int) -> None:
        self._conn.execute("UPDATE runs SET finished_at=? WHERE id=?", (time.time(), run_id))

    def get_run(self, run_id: int) -> Optional[dict]:
        r = self._conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        return dict(r) if r else None

    def list_runs(self, domain: Optional[str] = None) -> list[dict]:
        if domain:
            rows = self._conn.execute(
                "SELECT * FROM runs WHERE domain=? ORDER BY started_at DESC", (domain,)
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM runs ORDER BY started_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    # ---- tool_runs ----
    def mark(self, run_id: int, host: str, tool: str, stage: str, status: str,
             output_path: Optional[str] = None, error: Optional[str] = None,
             duration_s: Optional[float] = None) -> None:
        now = time.time()
        existing = self._conn.execute(
            "SELECT status, started_at FROM tool_runs WHERE run_id=? AND host=? AND tool=? AND stage=?",
            (run_id, host, tool, stage),
        ).fetchone()

        if existing is None:
            self._conn.execute(
                """INSERT INTO tool_runs(run_id, host, tool, stage, status, started_at, finished_at, output_path, error, duration_s)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (run_id, host, tool, stage, status,
                 now if status == "running" else None,
                 now if status in ("done", "failed", "skipped", "timeout") else None,
                 output_path, error, duration_s),
            )
        else:
            old_status, old_started = existing["status"], existing["started_at"]
            new_started = old_started if old_started else (now if status == "running" else None)
            new_finished = now if status in ("done", "failed", "skipped", "timeout") else None
            self._conn.execute(
                """UPDATE tool_runs
                   SET status=?, started_at=?, finished_at=?, output_path=COALESCE(?, output_path),
                       error=COALESCE(?, error), duration_s=COALESCE(?, duration_s)
                   WHERE run_id=? AND host=? AND tool=? AND stage=?""",
                (status, new_started, new_finished, output_path, error, duration_s,
                 run_id, host, tool, stage),
            )

    def is_done(self, run_id: int, host: str, tool: str, stage: str) -> bool:
        r = self._conn.execute(
            "SELECT status FROM tool_runs WHERE run_id=? AND host=? AND tool=? AND stage=?",
            (run_id, host, tool, stage),
        ).fetchone()
        return r is not None and r["status"] == "done"

    def should_skip(self, run_id: int, host: str, tool: str, stage: str) -> bool:
        """Skip if already done OR explicitly skipped in this run."""
        r = self._conn.execute(
            "SELECT status FROM tool_runs WHERE run_id=? AND host=? AND tool=? AND stage=?",
            (run_id, host, tool, stage),
        ).fetchone()
        if r is None:
            return False
        return r["status"] in ("done", "skipped")

    def hosts_done_for(self, run_id: int, tool: str, stage: str) -> set[str]:
        rows = self._conn.execute(
            "SELECT host FROM tool_runs WHERE run_id=? AND tool=? AND stage=? AND status='done'",
            (run_id, tool, stage),
        ).fetchall()
        return {r["host"] for r in rows}

    def hosts_failed_for(self, run_id: int, tool: str, stage: str) -> dict[str, Optional[str]]:
        rows = self._conn.execute(
            "SELECT host, error FROM tool_runs WHERE run_id=? AND tool=? AND stage=? AND status='failed'",
            (run_id, tool, stage),
        ).fetchall()
        return {r["host"]: r["error"] for r in rows}

    # ---- run summary (F23) ----
    def run_summary(self, run_id: int, workdir: Optional[str | Path] = None) -> Optional[dict]:
        """One-line "how did it go?" summary for a run.

        Returns a dict (or None if the run doesn't exist):
          run_id, domain, pipeline, status, tools, done, failed, skipped,
          running, timeout, failed_stages, subdomains, resolved, urls, hosts,
          findings, duration_s
        """
        run = self.get_run(run_id)
        if run is None:
            return None

        rows = self._conn.execute(
            "SELECT status FROM tool_runs WHERE run_id=?",
            (run_id,),
        ).fetchall()
        counts: dict[str, int] = {}
        for r in rows:
            counts[r["status"]] = counts.get(r["status"], 0) + 1

        failed_rows = self._conn.execute(
            "SELECT stage FROM tool_runs WHERE run_id=? AND status='failed'",
            (run_id,),
        ).fetchall()
        failed_stages = sorted({r["stage"] for r in failed_rows})

        # Event counts from events.jsonl (when a workdir is known)
        ev_counts: dict[str, int] = {}
        if workdir is not None:
            ev_file = Path(workdir) / f"run-{run_id}" / "events.jsonl"
            if ev_file.exists():
                import json as _json
                try:
                    for line in ev_file.open():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            ev = _json.loads(line)
                            k = ev.get("type", ev.get("kind", ""))
                            ev_counts[k] = ev_counts.get(k, 0) + 1
                        except Exception:
                            pass
                except Exception:
                    pass

        duration_s = None
        if run.get("finished_at") and run.get("started_at"):
            duration_s = round(run["finished_at"] - run["started_at"], 1)

        return {
            "run_id": run_id,
            "domain": run.get("domain"),
            "pipeline": run.get("pipeline"),
            "status": "finished" if run.get("finished_at") else "running",
            "tools": len(rows),
            "done": counts.get("done", 0),
            "failed": counts.get("failed", 0),
            "skipped": counts.get("skipped", 0),
            "running": counts.get("running", 0),
            "timeout": counts.get("timeout", 0),
            "failed_stages": failed_stages,
            "subdomains": ev_counts.get("subdomain", 0),
            "resolved": ev_counts.get("resolved", 0),
            "urls": ev_counts.get("url", 0),
            "hosts": ev_counts.get("host", 0),
            "findings": ev_counts.get("finding", 0),
            "duration_s": duration_s,
        }

    def stats(self, run_id: int) -> dict:
        rows = self._conn.execute(
            """SELECT stage, status, COUNT(*) as n
               FROM tool_runs WHERE run_id=?
               GROUP BY stage, status""",
            (run_id,),
        ).fetchall()
        out = {}
        for r in rows:
            out.setdefault(r["stage"], {})[r["status"]] = r["n"]
        return out
