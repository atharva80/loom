"""Tests for `loom sweeps` — overnight multi-scope orchestrator.

Wraps the existing --scopes-file mode behind its own subcommand so
cron / overseer scripts can invoke it without remembering the flag.
Adds: per-scope wall-clock timeout, post-run summary table, and
exit code reflecting failed-scope count.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from loom import cli


@pytest.fixture
def home_in_tmp(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    return tmp_path


class TestSweepsCLI:
    def test_sweeps_appears_in_choices(self, capsys):
        with pytest.raises(SystemExit):
            cli.main(["sweeps", "--help"])
        out = capsys.readouterr().out
        assert "--scopes-file" in out or "scopes" in out

    def test_sweeps_missing_file_exits_1(self, home_in_tmp, tmp_path, capsys):
        code = cli.main(["--workdir", str(tmp_path), "sweeps",
                          "--scopes-file", str(tmp_path / "nope.csv")])
        assert code == 1
        out = capsys.readouterr().err
        assert "no scopes" in out.lower() or "not found" in out.lower()

    def test_sweeps_runs_each_scope_and_prints_table(
            self, home_in_tmp, tmp_path, capsys):
        csv = tmp_path / "scopes.csv"
        csv.write_text(
            "vulnweb.com,web,1\n"
            "example.com,web,1\n"
        )
        code = cli.main(["--workdir", str(tmp_path), "sweeps",
                          "--scopes-file", str(csv), "--rate-limit", "1000"])
        out = capsys.readouterr().out
        # Header + one row per scope (or skip on real network failure)
        assert "sweeps" in out.lower() or "scope" in out.lower()
        # Per-scope summary line
        assert "vulnweb.com" in out or "example.com" in out

    def test_sweeps_skips_comments(self, home_in_tmp, tmp_path, capsys):
        csv = tmp_path / "scopes.csv"
        csv.write_text(
            "# overnight — ignore me\n"
            "vulnweb.com,web,1\n"
            "\n"
            "  # indented comment\n"
        )
        code = cli.main(["--workdir", str(tmp_path), "sweeps",
                          "--scopes-file", str(csv), "--rate-limit", "1000"])
        out = capsys.readouterr().out
        # Only one scope, not two
        assert out.count("vulnweb.com") == 1
