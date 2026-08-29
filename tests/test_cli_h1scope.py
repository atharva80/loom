"""Tests for `loom run --h1-scope` — HackerOne CSV → Scope wiring."""

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


H1_CSV = """identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission
api.example.com,API,,true,true
*.example.com,WILDCARD,,true,true
status.example.com,URL,,false,false
https://play.google.com/store/apps/details?id=com.example.app,GOOGLE_PLAY_APP_ID,,true,true
Example Category,OTHER,,true,true
"""


class TestCliH1Scope:
    def test_h1_scope_prints_summary_and_creates_run(self, home_in_tmp, tmp_path, capsys):
        wd = tmp_path / "wd"
        h1 = tmp_path / "h1.csv"
        h1.write_text(H1_CSV)
        code = cli.main(["--workdir", str(wd), "run", "example.com",
                         "--h1-scope", str(h1), "--pipeline", "catchall"])
        assert code == 0
        out = capsys.readouterr().out
        assert "program scope" in out
        assert "2 in-scope hosts" in out
        assert "1 denied" in out
        assert "1 mobile apps" in out
        # run row exists
        assert (wd / "loom.sqlite").exists()

    def test_h1_scope_persists_denied_hosts_and_headers(self, home_in_tmp, tmp_path, capsys):
        """The scope_spec persisted for the run must carry the H1
        headers (drstrangexd) and the OOS denied host."""
        wd = tmp_path / "wd"
        h1 = tmp_path / "h1.csv"
        h1.write_text(H1_CSV)
        code = cli.main(["--workdir", str(wd), "run", "example.com",
                         "--h1-scope", str(h1), "--pipeline", "catchall"])
        assert code == 0
        capsys.readouterr()
        with State(wd / "loom.sqlite") as st:
            runs = st.list_runs(domain="example.com")
            assert runs
            spec = json.loads(runs[0]["scope_spec"])
        assert spec["headers"]["X-Bug-Bounty"] == "drstrangexd"
        assert spec["headers"]["X-HackerOne-Research"] == "drstrangexd"
        assert "status.example.com" in spec["denied_hosts"]

    def test_h1_scope_blocks_denied_host(self, home_in_tmp, tmp_path, capsys):
        """Running a denied (OOS) host must fail fast — the runner's
        scope gate refuses it."""
        wd = tmp_path / "wd"
        h1 = tmp_path / "h1.csv"
        h1.write_text(H1_CSV)
        code = cli.main(["--workdir", str(wd), "run", "status.example.com",
                         "--h1-scope", str(h1), "--pipeline", "catchall"])
        assert code != 0
        captured = capsys.readouterr()
        assert "blocked" in (captured.out + captured.err).lower() or \
            "not in scope" in (captured.out + captured.err).lower() or \
            "denied" in (captured.out + captured.err).lower()
