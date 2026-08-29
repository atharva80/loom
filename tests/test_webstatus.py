"""Tests for loom.webstatus — the live run-status snapshot + server."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from loom.state import State
from loom.webstatus import snapshot


def _seed_workdir(wd: Path) -> None:
    """One finished run + one running run with stages."""
    with State(wd / "loom.sqlite") as st:
        r1 = st.start_run("done.example.com", pipeline="catchall")
        st.mark(r1, "done.example.com", "catchall", "catchall", "done",
                duration_s=1.5)
        st.finish_run(r1)
        r2 = st.start_run("live.example.com", pipeline="subdomain")
        st.mark(r2, "live.example.com", "subenum", "subenum", "done",
                duration_s=3.2)
        st.mark(r2, "live.example.com", "resolve", "resolve", "running",
                duration_s=None)
        # eventlog for the running run
        ev = wd / f"run-{r2}" / "events.jsonl"
        ev.parent.mkdir(parents=True, exist_ok=True)
        ev.write_text(
            json.dumps({"type": "subdomain", "value": "a.example.com"}) + "\n" +
            json.dumps({"type": "subdomain", "value": "b.example.com"}) + "\n" +
            json.dumps({"type": "finding", "value": "x", "evidence": {}}) + "\n"
        )
        # run.log tail source
        log = wd / f"run-{r2}" / "run.log"
        log.write_text("2026-01-01T00:00:00Z INFO first line\n"
                       "2026-01-01T00:00:01Z STAGE ▶ resolve\n")


class TestSnapshot:
    def test_snapshot_lists_runs_newest_first(self, tmp_path: Path):
        _seed_workdir(tmp_path)
        snap = snapshot(tmp_path)
        assert len(snap["runs"]) == 2
        assert snap["runs"][0]["domain"] == "live.example.com"
        assert snap["runs"][0]["status"] == "running"
        assert snap["runs"][1]["domain"] == "done.example.com"
        assert snap["runs"][1]["status"] == "done"

    def test_snapshot_stage_status_and_duration(self, tmp_path: Path):
        _seed_workdir(tmp_path)
        snap = snapshot(tmp_path)
        live = snap["runs"][0]
        stages = {s["stage"]: s for s in live["stages"]}
        assert stages["subenum"]["status"] == "done"
        assert stages["subenum"]["duration_s"] == 3.2
        assert stages["resolve"]["status"] == "running"
        assert stages["resolve"]["duration_s"] is not None  # computed from started_at

    def test_snapshot_event_counts(self, tmp_path: Path):
        _seed_workdir(tmp_path)
        snap = snapshot(tmp_path)
        assert snap["event_counts"] == {"subdomain": 2, "finding": 1}

    def test_snapshot_log_tail(self, tmp_path: Path):
        _seed_workdir(tmp_path)
        snap = snapshot(tmp_path)
        assert any("STAGE ▶ resolve" in l for l in snap["log_tail"])

    def test_snapshot_empty_workdir(self, tmp_path: Path):
        snap = snapshot(tmp_path)
        assert snap["runs"] == []
        assert snap["event_counts"] == {}

    def test_snapshot_missing_db(self, tmp_path: Path):
        snap = snapshot(tmp_path / "nonexistent")
        assert snap["runs"] == []
