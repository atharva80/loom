"""Tests for the v0.3.1 multi-host resume path.

Verifies that cmd_resume:
  * Rebuilds the multi/multiweb pipeline from the persisted pipeline name
  * Uses the persisted hosts_json list (no --subdomains needed on resume)
  * Honors the should_skip gates for already-done per-host stages
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from loom import cli


@pytest.fixture
def home_in_tmp(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    return tmp_path


def _seed_multi_inflight(wd: Path, hosts: list[str], domain: str = "example.com") -> int:
    """Create a multi-host run with all hosts marked 'done' (the
    crashed-then-resumed scenario). Returns the run_id."""
    from loom.state import State
    db = wd / "loom.sqlite"
    with State(db) as st:
        rid = st.start_run(
            domain, mode="recon", scope_profile="default",
            scope_spec=json.dumps({"target": domain, "rate_limit_rps": 1000}),
            pipeline="multi",
        )
        # Persist the host list (what cmd_run would have done)
        st._conn.execute(
            "UPDATE runs SET hosts_json=? WHERE id=?",
            (json.dumps(hosts), rid),
        )
        # Mark each host's probe as 'done' to simulate a prior run
        # that completed all the per-host work.
        for h in hosts:
            st.mark(rid, h, "probe", "probe", "done", duration_s=0.1)
        return rid


class TestMultiResume:
    def test_resume_multi_rebuilds_pipeline_from_persisted_state(
            self, home_in_tmp, tmp_path, capsys):
        wd = tmp_path
        rid = _seed_multi_inflight(
            wd, hosts=["a.example.com", "b.example.com"],
        )
        # Run resume — no --pipeline, no --subdomains; it must
        # reconstruct from the DB.
        code = cli.main(["--workdir", str(wd), "resume", "example.com"])
        assert code == 0
        out = capsys.readouterr().out
        # The log line shows the pipeline + host count from the DB
        assert "resume starting" in out
        assert "pipeline=multi" in out
        assert "hosts=2" in out
        # The multi-resume summary
        assert "multi resume complete" in out
        assert "hosts=2" in out

    def test_resume_multi_skips_already_done_hosts(
            self, home_in_tmp, tmp_path, capsys):
        """All hosts are pre-marked 'done' → probe is NOT re-invoked
        on resume."""
        wd = tmp_path
        rid = _seed_multi_inflight(
            wd, hosts=["a.example.com", "b.example.com", "c.example.com"],
        )
        # Spy on httpx to verify it isn't called
        from loom.stages import make_httpx_stage
        # Replace the runner.run path: count probe invocations
        invocations: list[str] = []
        from loom.runner import Runner as RunnerCls
        orig_run = RunnerCls.run
        def spy_run(self, tool, cmd, *args, **kwargs):
            invocations.append(tool)
            return orig_run(self, tool, cmd, *args, **kwargs)
        RunnerCls.run = spy_run
        try:
            code = cli.main(["--workdir", str(wd), "resume",
                              "example.com"])
            assert code == 0
        finally:
            RunnerCls.run = orig_run
        # The httpx tool (the stage's parser tool) should NOT be called
        # during resume because the per-host probe row is already 'done'.
        assert "httpx" not in invocations, (
            f"httpx was called {invocations.count('httpx')} times on resume"
        )
