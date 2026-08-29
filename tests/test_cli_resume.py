"""Tests for the real `loom resume` executor.

Verify that cmd_resume:
  * picks up the inflight run + reconstructs its scope/mode from the DB
  * actually executes the pipeline (not just prints "resuming")
  * honors should_skip semantics: pre-marked 'done' rows are not
    re-invoked
  * finishes the run (st.finish_run) so subsequent resumes see 'done'
"""

from __future__ import annotations

from pathlib import Path

import pytest

from loom import cli
from loom.dag import DAG, Node
from loom.runner import OutputItem, Runner
from loom.scope import from_dict as scope_from_dict
from loom.state import State


@pytest.fixture
def home_in_tmp(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    return tmp_path


def _seed_inflight_run(wd: Path, domain: str = "example.com") -> int:
    """Create a run + mark one stage as 'done' (simulating a prior run
    that crashed mid-pipeline). Returns the run_id."""
    db = wd / "loom.sqlite"
    with State(db) as st:
        rid = st.start_run(domain, mode="recon", scope_profile="default")
        # Mark a stage as 'done' to test the resume skip path
        st.mark(rid, domain, "catchall", "catchall", "done",
                duration_s=0.5)
        return rid


class TestResumeExecutor:
    def test_resume_with_no_runs_exits_1(self, home_in_tmp, tmp_path, capsys):
        wd = tmp_path
        code = cli.main(["--workdir", str(wd), "resume", "example.com"])
        assert code == 1
        captured = capsys.readouterr()
        # Error messages go to stderr in cmd_resume
        assert "no inflight run" in (captured.out + captured.err) \
            or "nothing to resume" in (captured.out + captured.err)

    def test_resume_actually_executes_pipeline(
            self, home_in_tmp, tmp_path, capsys):
        wd = tmp_path
        rid = _seed_inflight_run(wd)
        # Run resume — should actually execute the pipeline
        code = cli.main(["--workdir", str(wd), "resume", "example.com"])
        assert code == 0
        out = capsys.readouterr().out
        # The new log line is "resume starting" / "resume complete"
        assert "resume starting" in out
        assert "resume complete" in out
        assert f"run_id={rid}" in out
        # The catchall stage (which the catchall pipeline runs) appears
        assert "catchall" in out

    def test_resume_skips_already_done_stages(
            self, home_in_tmp, tmp_path, capsys):
        """The pre-marked 'done' catchall stage must NOT be re-invoked.
        The state DB row should still be 'done' after resume, and
        the runner should not see a new invocation."""
        wd = tmp_path
        rid = _seed_inflight_run(wd)
        # Track what the catchall detector saw by patching it.
        from loom import catchall as catchall_mod
        original_detect = catchall_mod.detect
        calls: list[str] = []
        def spy_detect(host, https=True, timeout=8.0):
            calls.append(host)
            return original_detect(host, https=https, timeout=timeout)
        catchall_mod.detect = spy_detect
        try:
            code = cli.main(["--workdir", str(wd), "resume", "example.com"])
            assert code == 0
        finally:
            catchall_mod.detect = original_detect
        # The catchall stage was pre-marked done, so the detector
        # was NOT called during resume.
        assert calls == [], f"catchall.detect was called {len(calls)} times"
        # Verify the state row is still 'done' (not clobbered to
        # 'skipped' by the synthetic-skip path).
        with State(wd / "loom.sqlite") as st:
            row = st._conn.execute(
                "SELECT status, duration_s FROM tool_runs WHERE run_id=?",
                (rid,),
            ).fetchone()
            assert row["status"] == "done"
            # The original duration is preserved
            assert row["duration_s"] == 0.5

    def test_resume_finishes_run(self, home_in_tmp, tmp_path, capsys):
        """After resume, the run row should be marked finished so a
        second `loom resume` returns 'no inflight run'."""
        wd = tmp_path
        _seed_inflight_run(wd)
        code = cli.main(["--workdir", str(wd), "resume", "example.com"])
        assert code == 0
        capsys.readouterr()
        # Second resume: should fail (run is now finished)
        code2 = cli.main(["--workdir", str(wd), "resume", "example.com"])
        assert code2 == 1
        captured = capsys.readouterr()
        assert "no inflight run" in (captured.out + captured.err) \
            or "nothing to resume" in (captured.out + captured.err)

    def test_resume_creates_log_file(self, home_in_tmp, tmp_path, capsys):
        wd = tmp_path
        rid = _seed_inflight_run(wd)
        cli.main(["--workdir", str(wd), "resume", "example.com"])
        capsys.readouterr()
        # run.log should exist and contain the resume events
        log_path = wd / f"run-{rid}" / "run.log"
        assert log_path.exists()
        content = log_path.read_text()
        assert "resume starting" in content
        assert "resume complete" in content
