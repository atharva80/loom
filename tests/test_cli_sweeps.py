"""Tests for `loom sweeps` — overnight multi-scope orchestrator.

Wraps the existing --scopes-file mode behind its own subcommand so
cron / overseer scripts can invoke it without remembering the flag.
Adds: per-scope wall-clock timeout, post-run summary table, and
exit code reflecting failed-scope count.
"""

from __future__ import annotations

import re
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
        # Only one scope row, not two (comments/blank lines skipped).
        # (Counts table rows, not bare mentions — a real run logs the
        # domain on stage lines too.)
        rows = re.findall(r"(?m)^\s*\d+\s+vulnweb\.com\s+\w+", out)
        assert len(rows) == 1


class TestSweepsChildNamespace:
    """cmd_sweeps clones its argv into a `run`-shaped namespace for
    _run_one. Every attr _run_one touches must exist — live 2026-09-05:
    both scopes crashed with AttributeError (no `scope`) and rc=2,
    while the old table-output test still passed on loose asserts."""

    def test_child_namespace_satisfies_run_one(
            self, home_in_tmp, tmp_path, monkeypatch, capsys):
        csv = tmp_path / "scopes.csv"
        csv.write_text("example.com,catchall,1\n")
        seen = []
        monkeypatch.setattr(cli, "_run_one", lambda child: seen.append(child) or 0)
        code = cli.main(["--workdir", str(tmp_path), "sweeps",
                         "--scopes-file", str(csv)])
        assert code == 0
        assert len(seen) == 1
        child = seen[0]
        for attr in ("domain", "pipeline", "scope", "mode", "workdir",
                     "max_concurrency", "max_ram_gb", "scopes_file",
                     "subdomains", "from_eventlog"):
            assert hasattr(child, attr), f"child missing {attr!r}"
        assert child.domain == "example.com"
        assert child.pipeline == "catchall"
        assert child.scopes_file is None

    def test_global_workdir_survives_sweeps_subparser(
            self, home_in_tmp, tmp_path, monkeypatch):
        """Live 2026-09-05: `loom --workdir X sweeps` silently ran in
        the default workdir — the subparser --workdir default clobbered
        the global. The sweep landed 7 runs in ~/.local/share/loom."""
        csv = tmp_path / "scopes.csv"
        csv.write_text("example.com,catchall,1\n")
        seen = []
        monkeypatch.setattr(cli, "_run_one", lambda child: seen.append(child) or 0)
        wd = tmp_path / "w"
        code = cli.main(["--workdir", str(wd), "sweeps",
                         "--scopes-file", str(csv)])
        assert code == 0
        assert seen[0].workdir == str(wd)

    def test_sweeps_level_workdir_overrides_global(
            self, home_in_tmp, tmp_path, monkeypatch):
        csv = tmp_path / "scopes.csv"
        csv.write_text("example.com,catchall,1\n")
        seen = []
        monkeypatch.setattr(cli, "_run_one", lambda child: seen.append(child) or 0)
        wd = tmp_path / "w2"
        code = cli.main(["sweeps", "--scopes-file", str(csv),
                         "--workdir", str(wd)])
        assert code == 0
        assert seen[0].workdir == str(wd)


class TestSweepsTimeout:
    """--timeout abandons hung scopes (rc=124) and continues the sweep."""

    def test_hung_scope_abandoned_next_runs(
            self, home_in_tmp, tmp_path, monkeypatch, capsys):
        import time
        csv = tmp_path / "scopes.csv"
        csv.write_text("slow.example.com,catchall,1\nfast.example.com,catchall,1\n")
        calls = []

        def fake_run_one(child):
            calls.append(child.domain)
            if child.domain.startswith("slow"):
                time.sleep(30)
            return 0

        monkeypatch.setattr(cli, "_run_one", fake_run_one)
        t0 = time.monotonic()
        code = cli.main(["--workdir", str(tmp_path), "sweeps",
                         "--scopes-file", str(csv), "--timeout", "1"])
        dt = time.monotonic() - t0
        assert code == 1  # one scope non-zero
        assert calls == ["slow.example.com", "fast.example.com"]
        assert dt < 15, f"sweep waited out the hung scope ({dt:.1f}s)"
        err = capsys.readouterr().err
        assert "124" in err

    def test_no_timeout_runs_straight_through(
            self, home_in_tmp, tmp_path, monkeypatch):
        csv = tmp_path / "scopes.csv"
        csv.write_text("a.example.com,catchall,1\nb.example.com,catchall,1\n")
        calls = []
        monkeypatch.setattr(
            cli, "_run_one", lambda child: calls.append(child.domain) or 0)
        code = cli.main(["--workdir", str(tmp_path), "sweeps",
                         "--scopes-file", str(csv)])
        assert code == 0
        assert calls == ["a.example.com", "b.example.com"]
