"""Tests for loom.webstatus.snapshot — the /api/status payload that
agents poll during runs. The page hides stage errors today although
the data is there; these tests pin the data contract first."""

from __future__ import annotations

import json
import shutil
import sqlite3
import time
from pathlib import Path

from loom.webstatus import PAGE, snapshot


def _workdir(tmp_path: Path) -> Path:
    now = time.time()
    db = tmp_path / "loom.sqlite"
    con = sqlite3.connect(str(db))
    con.execute("CREATE TABLE runs (id INTEGER PRIMARY KEY, domain TEXT, "
                "pipeline TEXT, started_at REAL, finished_at REAL)")
    con.execute("CREATE TABLE tool_runs (run_id INTEGER, host TEXT, tool TEXT, "
                "stage TEXT, status TEXT, started_at REAL, finished_at REAL, "
                "output_path TEXT, error TEXT, duration_s REAL)")
    con.execute("INSERT INTO runs VALUES (1, 'example.com', 'catchall', ?, ?)",
                (now - 100, None))
    con.execute("INSERT INTO runs VALUES (2, 'example.com', 'web', ?, ?)",
                (now - 200, now - 50))
    con.execute("INSERT INTO tool_runs VALUES (1,'example.com','nuclei','scan',"
                "'failed',?,?,NULL,?,?)",
                (now - 90, now - 80, "exit code 2: boom", 10.0))
    con.execute("INSERT INTO tool_runs VALUES (2,'example.com','katana','crawl',"
                "'done',?,?,NULL,NULL,?)",
                (now - 190, now - 100, 90.0))
    con.commit()
    con.close()
    run1 = tmp_path / "run-1"
    run1.mkdir()
    (run1 / "run.log").write_text("\n".join(f"line {i}" for i in range(100)))
    run2 = tmp_path / "run-2"
    run2.mkdir()
    (run2 / "run.log").write_text("\n".join(f"r2 {i}" for i in range(10)))
    (run2 / "events.jsonl").write_text(
        '{"type":"url","source":"katana","host":"example.com",'
        '"value":"http://example.com/","ts":1,"evidence":{}}\n'
        '{"type":"url","source":"gau","host":"example.com",'
        '"value":"http://example.com/x","ts":2,"evidence":{}}\n'
        '{"type":"finding","source":"nuclei","host":"example.com",'
        '"value":"http://example.com/","ts":3,"evidence":{}}\n')
    return tmp_path


class TestSnapshot:
    def test_runs_newest_first_with_status(self, tmp_path):
        snap = snapshot(_workdir(tmp_path))
        assert [r["id"] for r in snap["runs"]] == [2, 1]
        by_id = {r["id"]: r for r in snap["runs"]}
        assert by_id[1]["status"] == "running"
        assert by_id[2]["status"] == "done"
        assert by_id[1]["elapsed_s"] > 90

    def test_failed_stage_carries_error(self, tmp_path):
        snap = snapshot(_workdir(tmp_path))
        scan = [s for s in snap["runs"][1]["stages"]
                if s["tool"] == "nuclei"][0]
        assert scan["status"] == "failed"
        assert scan["error"] == "exit code 2: boom"
        assert scan["duration_s"] == 10.0

    def test_log_tail_capped_at_60(self, tmp_path):
        wd = _workdir(tmp_path)
        shutil.rmtree(wd / "run-2")  # run-1's 100-line log is newest
        snap = snapshot(wd)
        assert len(snap["log_tail"]) == 60
        assert snap["log_tail"][-1] == "line 99"

    def test_log_tail_reads_newest_run(self, tmp_path):
        wd = _workdir(tmp_path)
        (wd / "run-1" / "run.log").write_text("old\n")
        snap = snapshot(wd)
        assert snap["log_tail"][-1] == "r2 9"

    def test_event_counts(self, tmp_path):
        snap = snapshot(_workdir(tmp_path))
        assert snap["event_counts"] == {"url": 2, "finding": 1}

    def test_empty_workdir(self, tmp_path):
        snap = snapshot(tmp_path)
        assert snap == {"workdir": str(tmp_path), "runs": [],
                        "log_tail": [], "event_counts": {}}

    def test_page_renders_stage_errors(self):
        """The human page must surface what the API already carries."""
        assert "s.error" in PAGE
