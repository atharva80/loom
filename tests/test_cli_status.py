"""Tests for `loom status --run <id>` and `loom list-runs` showing
pipeline + hosts columns (v0.3.1)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from loom import cli
from loom.state import State


@pytest.fixture
def home_in_tmp(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    return tmp_path


def _seed_two_runs(wd: Path) -> tuple[int, int]:
    """Create two runs: one single-host (pipeline=subdomain) and one
    multi-host (pipeline=multi with hosts_json). Returns (rid1, rid2)."""
    with State(wd / "loom.sqlite") as st:
        r1 = st.start_run(
            "example.com", mode="recon", scope_profile="default",
            scope_spec=json.dumps({"target": "example.com", "rate_limit_rps": 100}),
            pipeline="subdomain",
        )
        st.mark(r1, "example.com", "subenum", "subenum", "done")
        st.finish_run(r1)
        r2 = st.start_run(
            "example.com", mode="recon", scope_profile="default",
            scope_spec=json.dumps({"target": "example.com", "rate_limit_rps": 100}),
            pipeline="multi",
            hosts_json=json.dumps(["a.example.com", "b.example.com", "c.example.com"]),
        )
        st.mark(r2, "a.example.com", "probe", "probe", "done")
        return r1, r2


class TestStatusRunFlag:
    def test_status_defaults_to_newest(self, home_in_tmp, tmp_path, capsys):
        wd = tmp_path
        r1, r2 = _seed_two_runs(wd)
        code = cli.main(["--workdir", str(wd), "status", "example.com"])
        assert code == 0
        out = capsys.readouterr().out
        # Newest run is r2 (multi, hosts_json)
        assert f"run {r2}" in out

    def test_status_with_run_flag(self, home_in_tmp, tmp_path, capsys):
        wd = tmp_path
        r1, r2 = _seed_two_runs(wd)
        code = cli.main(["--workdir", str(wd), "status", "example.com",
                          "--run", str(r1)])
        assert code == 0
        out = capsys.readouterr().out
        assert f"run {r1}" in out

    def test_status_unknown_run_exits_1(self, home_in_tmp, tmp_path, capsys):
        wd = tmp_path
        _seed_two_runs(wd)
        code = cli.main(["--workdir", str(wd), "status", "example.com",
                          "--run", "999"])
        assert code == 1
        captured = capsys.readouterr()
        assert "not found" in (captured.out + captured.err)

    def test_status_shows_summary_line(self, home_in_tmp, tmp_path, capsys):
        """F23: `status --run N` prints a one-line summary with findings."""
        wd = tmp_path
        with State(wd / "loom.sqlite") as st:
            r = st.start_run("example.com", mode="recon",
                             scope_profile="default", pipeline="subdomain")
            st.mark(r, "example.com", "subfinder", "subenum_subfinder", "done")
            st.mark(r, "example.com", "dnsx", "resolve", "done")
            st.mark(r, "example.com", "httpx", "probe", "done")
            st.finish_run(r)
        # events.jsonl with 2 findings
        evdir = wd / f"run-{r}"
        evdir.mkdir(parents=True, exist_ok=True)
        with (evdir / "events.jsonl").open("w") as f:
            f.write(json.dumps({"type": "finding", "value": "http://x.com",
                                "evidence": {"severity": "high"},
                                "stage": "vulnscan"}) + "\n")
            f.write(json.dumps({"type": "finding", "value": "http://y.com",
                                "evidence": {"severity": "medium"},
                                "stage": "vulnscan"}) + "\n")
        code = cli.main(["--workdir", str(wd), "status", "example.com",
                          "--run", str(r)])
        assert code == 0
        out = capsys.readouterr().out
        assert "summary" in out
        assert "3 tools" in out
        assert "2 findings" in out


class TestListRunsColumns:
    def test_list_runs_shows_pipeline(self, home_in_tmp, tmp_path, capsys):
        wd = tmp_path
        r1, r2 = _seed_two_runs(wd)
        code = cli.main(["--workdir", str(wd), "list-runs"])
        assert code == 0
        out = capsys.readouterr().out
        # Both pipelines appear
        assert "subdomain" in out
        assert "multi" in out

    def test_list_runs_shows_host_count(self, home_in_tmp, tmp_path, capsys):
        wd = tmp_path
        r1, r2 = _seed_two_runs(wd)
        code = cli.main(["--workdir", str(wd), "list-runs"])
        assert code == 0
        out = capsys.readouterr().out
        # The multi run shows "3 hosts"
        assert "3 hosts" in out
