"""Tests for the CSV scope-list parser + `loom run --scopes-file`."""

from __future__ import annotations

from pathlib import Path

import pytest

from loom import cli
from loom.scopecsv import ScopeEntry, parse_scopes_csv


@pytest.fixture
def home_in_tmp(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    return tmp_path


class TestParseScopesCsv:
    def test_basic(self, tmp_path: Path):
        f = tmp_path / "scopes.csv"
        f.write_text(
            "# overnight list\n"
            "vulnweb.com\n"
            "example.org,subdomain\n"
            "testphp.vulnweb.com,web,2\n"
        )
        entries = parse_scopes_csv(f)
        assert entries == [
            ScopeEntry("vulnweb.com", "subdomain", 10),
            ScopeEntry("example.org", "subdomain", 10),
            ScopeEntry("testphp.vulnweb.com", "web", 2),
        ]

    def test_empty_and_comments_only(self, tmp_path: Path):
        f = tmp_path / "empty.csv"
        f.write_text("# nothing here\n\n")
        assert parse_scopes_csv(f) == []

    def test_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            parse_scopes_csv(tmp_path / "nope.csv")

    def test_bad_concurrency_defaults_10(self, tmp_path: Path):
        f = tmp_path / "s.csv"
        f.write_text("example.com,web,abc\n")
        entries = parse_scopes_csv(f)
        assert entries[0].max_concurrency == 10


class TestCliScopesFile:
    def test_no_scopes_file_exits_1(self, home_in_tmp, tmp_path, capsys):
        empty = tmp_path / "empty.csv"
        empty.write_text("# only a comment\n")
        code = cli.main(["--workdir", str(tmp_path / "wd"), "run",
                          "example.com", "--scopes-file", str(empty)])
        assert code == 1
        captured = capsys.readouterr()
        assert "no scopes found" in (captured.out + captured.err)

    def test_runs_each_scope_creates_run_rows(self, home_in_tmp, tmp_path, capsys):
        """Each scope in the CSV gets its own run row in loom.sqlite."""
        from loom.state import State
        wd = tmp_path / "wd"
        scopes = tmp_path / "scopes.csv"
        scopes.write_text(
            "a.example.com,catchall\n"
            "b.example.com,catchall\n"
        )
        # catchall needs network; use the catchall pipeline but the
        # run rows are created regardless of stage outcome.
        code = cli.main(["--workdir", str(wd), "run", "example.com",
                          "--scopes-file", str(scopes)])
        assert code == 0
        with State(wd / "loom.sqlite") as st:
            runs = st.list_runs()
            assert len(runs) == 2
            domains = {r["domain"] for r in runs}
            assert domains == {"a.example.com", "b.example.com"}
