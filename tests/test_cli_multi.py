"""Tests for the new v0.3 CLI features:
  * --subdomains / --from-eventlog host sources
  * --max-concurrency / --max-ram-gb flags
  * `multi` pipeline wired to Fanout
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from loom import cli
from loom.eventlog import EventLog


@pytest.fixture
def home_in_tmp(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    return tmp_path


# ============================================================
# _resolve_hosts unit tests
# ============================================================


class TestResolveHosts:
    def test_subdomains_file(self, home_in_tmp, tmp_path, capsys):
        # Write a subs file
        subs_file = tmp_path / "subs.txt"
        subs_file.write_text(
            "# comment line\n"
            "a.example.com\n"
            "b.example.com\n"
            "\n"  # blank line
            "c.example.com\n"
        )
        from loom.cli import _resolve_hosts
        # Build minimal args
        class Args:
            subdomains = str(subs_file)
            from_eventlog = None
        el = EventLog(home_in_tmp / "el.jsonl")
        # capsys for the logger
        from loom.live import LiveLogger
        from loom.state import State
        log = LiveLogger(home_in_tmp, also_stdout=True)
        with State(home_in_tmp / "state.db") as st:
            hosts = _resolve_hosts(Args(), home_in_tmp, st, log)
        assert hosts == ["a.example.com", "b.example.com", "c.example.com"]

    def test_subdomains_file_missing(self, home_in_tmp, tmp_path, capsys):
        from loom.cli import _resolve_hosts
        from loom.live import LiveLogger
        from loom.state import State

        class Args:
            subdomains = "/nonexistent/file.txt"
            from_eventlog = None
        el = EventLog(home_in_tmp / "el.jsonl")
        log = LiveLogger(home_in_tmp, also_stdout=True)
        with State(home_in_tmp / "state.db") as st:
            hosts = _resolve_hosts(Args(), home_in_tmp, st, log)
        assert hosts == []

    def test_from_eventlog(self, home_in_tmp, tmp_path):
        # Set up: prior run with subdomain events
        from loom.cli import _resolve_hosts
        from loom.live import LiveLogger
        from loom.state import State

        workdir = home_in_tmp
        run1_dir = workdir / "run-1"
        run1_dir.mkdir(parents=True, exist_ok=True)
        el = EventLog(run1_dir / "events.jsonl")
        for sub in ("a.example.com", "b.example.com", "a.example.com"):
            el.append(type="subdomain", source="subfinder",
                      host="example.com", value=sub, evidence={})
        el.append(type="url", source="katana", host="example.com",
                  value="https://x/", evidence={})

        class Args:
            subdomains = None
            from_eventlog = 1
        log = LiveLogger(home_in_tmp, also_stdout=False)
        with State(workdir / "state.db") as st:
            # First seed a run row in the state DB so get_run works
            st.start_run("example.com")
            hosts = _resolve_hosts(Args(), workdir, st, log)
        # Deduped, order preserved
        assert hosts == ["a.example.com", "b.example.com"]

    def test_no_source_returns_empty(self, home_in_tmp):
        from loom.cli import _resolve_hosts
        from loom.live import LiveLogger
        from loom.state import State
        el = EventLog(home_in_tmp / "el.jsonl")
        log = LiveLogger(home_in_tmp, also_stdout=False)

        class Args:
            subdomains = None
            from_eventlog = None
        with State(home_in_tmp / "state.db") as st:
            hosts = _resolve_hosts(Args(), home_in_tmp, st, log)
        assert hosts == []


# ============================================================
# CLI flag parsing
# ============================================================


class TestCLIFlags:
    def test_run_help_lists_all_new_flags(self, capsys):
        with pytest.raises(SystemExit) as exc:
            cli.main(["run", "--help"])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        # All the new flags must appear in `run --help`
        assert "--subdomains" in out
        assert "--from-eventlog" in out
        assert "--max-concurrency" in out
        assert "--max-ram-gb" in out
        assert "--pipeline" in out
        # And the `multi` choice
        assert "multi" in out

    def test_run_multi_without_hosts_exits_1(self, home_in_tmp, tmp_path, capsys):
        wd = tmp_path
        code = cli.main(["--workdir", str(wd), "run", "example.com",
                          "--pipeline", "multi"])
        # No --subdomains and no --from-eventlog → error
        assert code == 1
        out = capsys.readouterr().out
        # The error message is in stdout (LiveLogger)
        assert "no hosts" in out or "empty" in out

    def test_run_multi_with_subdomains_file(self, home_in_tmp, tmp_path, capsys):
        wd = tmp_path
        # Subs file with 1 host (the target itself so httpx doesn't fail on DNS)
        subs_file = wd / "subs.txt"
        subs_file.write_text("example.com\n")
        code = cli.main(["--workdir", str(wd), "run", "example.com",
                          "--pipeline", "multi",
                          "--subdomains", str(subs_file),
                          "--max-concurrency", "1"])
        # The fanout ran without crashing
        assert code == 0
        out = capsys.readouterr().out
        assert "multi run complete" in out
        assert "hosts=1" in out
        # Per-host log lines
        assert "host=example.com" in out

    def test_run_multi_max_concurrency_passed_through(
            self, home_in_tmp, tmp_path, capsys):
        wd = tmp_path
        subs_file = wd / "subs.txt"
        subs_file.write_text("a.example.com\nb.example.com\nc.example.com\n")
        code = cli.main(["--workdir", str(wd), "run", "example.com",
                          "--pipeline", "multi",
                          "--subdomains", str(subs_file),
                          "--max-concurrency", "2"])
        assert code == 0
        out = capsys.readouterr().out
        # We should see 3 hosts fanned out
        assert "hosts=3" in out
        # Each host should appear in a stage_end line
        for h in ("a.example.com", "b.example.com", "c.example.com"):
            assert h in out


# ============================================================
# Multi pipeline state DB
# ============================================================


class TestMultiStateDB:
    def test_state_records_per_host(self, home_in_tmp, tmp_path, capsys):
        from loom.state import State

        wd = tmp_path
        subs_file = wd / "subs.txt"
        subs_file.write_text("host1.example.com\nhost2.example.com\n")
        code = cli.main(["--workdir", str(wd), "run", "example.com",
                          "--pipeline", "multi",
                          "--subdomains", str(subs_file),
                          "--max-concurrency", "2"])
        assert code == 0
        capsys.readouterr()
        # Open the state DB and check per-host rows
        with State(wd / "loom.sqlite") as st:
            rows = st._conn.execute(
                "SELECT host, tool, status FROM tool_runs ORDER BY host"
            ).fetchall()
            hosts_seen = {r["host"] for r in rows}
            assert "host1.example.com" in hosts_seen
            assert "host2.example.com" in hosts_seen
            # Each host has at least one tool_runs row
            for h in ("host1.example.com", "host2.example.com"):
                host_rows = [r for r in rows if r["host"] == h]
                assert len(host_rows) >= 1
