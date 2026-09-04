"""loom.manifest — one self-describing file per finished run.

Agents read loom output programmatically. run-<id>/manifest.json is
the single file that answers "what was this run?": identity, timing,
per-stage outcomes, event counts, the run summary, loom version, and
the resolved tool paths. Built purely from the state DB + eventlog
(no subprocesses, never raises on missing data — returns None).
"""

from __future__ import annotations

import collections
import json
from pathlib import Path
from typing import Optional


def build_manifest(workdir: str | Path, run_id: int) -> Optional[dict]:
    """Assemble the manifest dict for a run, or None if unknown."""
    from .state import State

    workdir = Path(workdir).expanduser()
    db_path = workdir / "loom.sqlite"
    if not db_path.exists():
        return None
    with State(db_path) as st:
        run = st.get_run(run_id)
        if run is None:
            return None
        tool_rows = st._conn.execute(
            "SELECT host, tool, stage, status, duration_s, error,"
            " output_path FROM tool_runs WHERE run_id=? ORDER BY stage, tool",
            (run_id,),
        ).fetchall()
        try:
            summary = st.run_summary(run_id, workdir=workdir)
        except Exception:
            summary = None

    from . import __version__ as loom_version
    from .cli import EXPECTED_TOOLS
    from .tools import resolve_tool

    finished = run.get("finished_at")
    stages = [
        {
            "host": r["host"], "tool": r["tool"], "stage": r["stage"],
            "status": r["status"], "duration_s": r["duration_s"],
            "error": r["error"], "output_path": r["output_path"],
        }
        for r in tool_rows
    ]
    return {
        "loom_version": loom_version,
        "run": {
            "id": run["id"],
            "domain": run.get("domain"),
            "pipeline": run.get("pipeline"),
            "mode": run.get("mode"),
            "scope_profile": run.get("scope_profile"),
            "status": "done" if finished else "inflight",
            "started_at": run.get("started_at"),
            "finished_at": finished,
            "duration_s": (finished - run["started_at"])
            if finished and run.get("started_at") else None,
        },
        "stages": stages,
        "events": _event_counts(workdir, run_id),
        "summary": summary,
        "resolved_tools": {t: resolve_tool(t) for t in EXPECTED_TOOLS},
    }


def _event_counts(workdir: Path, run_id: int) -> dict[str, int]:
    ev_file = workdir / f"run-{run_id}" / "events.jsonl"
    counts: dict[str, int] = collections.Counter()
    try:
        lines = ev_file.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {}
    for line in lines:
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        t = ev.get("type")
        if t:
            counts[t] += 1
    return dict(counts)


def write_manifest(workdir: str | Path, run_id: int) -> Optional[Path]:
    """Write run-<id>/manifest.json. Returns the path, or None when
    the run is unknown or the write fails (never raises — a manifest
    must never break a run)."""
    try:
        m = build_manifest(workdir, run_id)
    except Exception:
        return None
    if m is None:
        return None
    out = Path(workdir).expanduser() / f"run-{run_id}" / "manifest.json"
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(m, indent=2, default=str), encoding="utf-8")
    except OSError:
        return None
    return out


def manifest_schema() -> dict:
    """Load the bundled manifest JSON Schema (shipped as package data)."""
    import loom as _loom_pkg
    schema_path = Path(_loom_pkg.__file__).parent / "manifest.schema.json"
    return json.loads(schema_path.read_text(encoding="utf-8"))


def validate_manifest(manifest: dict) -> list[str]:
    """Validate a manifest dict against the schema. Returns a list of
    human-readable errors (empty == valid). jsonschema is a dev
    dependency; production callers should treat this as diagnostic."""
    import jsonschema
    errors = sorted(
        jsonschema.Draft202012Validator(manifest_schema()).iter_errors(manifest),
        key=lambda e: list(e.path),
    )
    return [
        f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}"
        for e in errors
    ]
