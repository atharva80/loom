"""Tests for the multiweb pipeline."""

from __future__ import annotations

from pathlib import Path

import pytest

from loom import cli


@pytest.fixture
def home_in_tmp(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    return tmp_path


class TestMultiwebCLI:
    def test_multiweb_appears_in_choices(self, capsys):
        with pytest.raises(SystemExit) as exc:
            cli.main(["run", "--help"])
        out = capsys.readouterr().out
        assert "multiweb" in out

    def test_multiweb_without_hosts_exits_1(self, home_in_tmp, tmp_path, capsys):
        wd = tmp_path
        code = cli.main(["--workdir", str(wd), "run", "example.com",
                          "--pipeline", "multiweb"])
        assert code == 1
        out = capsys.readouterr().out
        assert "no hosts" in out or "empty" in out

    def test_multiweb_with_subdomains_runs_end_to_end(
            self, home_in_tmp, tmp_path, capsys):
        wd = tmp_path
        # Use example.com as the only "host" — it's a real, reachable
        # domain so catchall can classify it and httpx can probe it.
        subs_file = wd / "subs.txt"
        subs_file.write_text("example.com\n")
        code = cli.main(["--workdir", str(wd), "run", "example.com",
                          "--pipeline", "multiweb",
                          "--subdomains", str(subs_file),
                          "--max-concurrency", "1"])
        assert code == 0
        out = capsys.readouterr().out
        assert "multi run complete" in out
        assert "hosts=1" in out
        # The summary mentions probe (and likely catchall classified)
        # Note: nuclei may or may not actually run depending on whether
        # the binary is installed and whether probe got items. We just
        # verify the run completed cleanly.
        assert "host=example.com" in out

    def test_multiweb_state_db_records_per_host_per_stage(
            self, home_in_tmp, tmp_path, capsys):
        from loom.state import State

        wd = tmp_path
        subs_file = wd / "subs.txt"
        subs_file.write_text("host1.example.com\nhost2.example.com\n")
        code = cli.main(["--workdir", str(wd), "run", "example.com",
                          "--pipeline", "multiweb",
                          "--subdomains", str(subs_file),
                          "--max-concurrency", "2"])
        assert code == 0
        capsys.readouterr()
        with State(wd / "loom.sqlite") as st:
            # Each host should have at least the catchall stage
            rows = st._conn.execute(
                "SELECT host, tool, status FROM tool_runs ORDER BY host, tool"
            ).fetchall()
            hosts_seen = {r["host"] for r in rows}
            assert "host1.example.com" in hosts_seen
            assert "host2.example.com" in hosts_seen
            # Each host has the catchall stage
            for h in ("host1.example.com", "host2.example.com"):
                host_rows = [r for r in rows if r["host"] == h]
                tools = {r["tool"] for r in host_rows}
                assert "catchall" in tools
