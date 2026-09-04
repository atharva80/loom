"""Tests for the AssetNote wordlist layer (v0.6.1): tech-gated
selection, stable-name resolution, amass brute wiring, arjun -w.

Rule: wordlists live OUTSIDE the repo (/opt/tools/wordlists or
LOOM_WORDLISTS); the repo only carries the mapping + resolution.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from loom.pipeline import PipelineContext
from loom.runner import Runner
from loom.scope import from_dict as scope_from_dict
from loom.wordlists import (
    ARJUN_PARAMS_FILE,
    TECH_WORDLISTS,
    arjun_params_wordlist,
    wordlist_dir,
    wordlist_for,
    wordlist_status,
)


def _scope():
    return scope_from_dict({"name": "t", "target": "example.com",
                            "rate_limit_rps": 1000})


@pytest.fixture
def wldir(tmp_path, monkeypatch):
    d = tmp_path / "wl"
    d.mkdir()
    monkeypatch.setenv("LOOM_WORDLISTS", str(d))
    return d


class TestResolution:
    def test_env_dir_wins(self, tmp_path, monkeypatch):
        d = tmp_path / "custom"
        d.mkdir()
        monkeypatch.setenv("LOOM_WORDLISTS", str(d))
        assert wordlist_dir() == d

    def test_missing_env_falls_back_without_raising(self, monkeypatch):
        monkeypatch.delenv("LOOM_WORDLISTS", raising=False)
        assert isinstance(wordlist_dir(), Path)

    def test_tech_gated_selection(self, wldir):
        (wldir / "php-top15k.txt").write_text("index.php\n")
        (wldir / "api-routes-top20k.txt").write_text("/api/v1\n")
        got = wordlist_for({"php", "apache"}, tech_map=TECH_WORDLISTS)
        assert got is not None and got.name == "php-top15k.txt"

    def test_unknown_tech_falls_back_to_api_routes(self, wldir):
        (wldir / "api-routes-top20k.txt").write_text("/api/v1\n")
        got = wordlist_for({"cobol"}, tech_map=TECH_WORDLISTS)
        assert got is not None and got.name == "api-routes-top20k.txt"

    def test_nothing_available_returns_none(self, wldir):
        assert wordlist_for({"php"}, tech_map=TECH_WORDLISTS) is None
        assert wordlist_for(set(), tech_map=TECH_WORDLISTS) is None

    def test_arjun_params_selection(self, wldir):
        assert arjun_params_wordlist() is None
        (wldir / ARJUN_PARAMS_FILE).write_text("id\n")
        assert arjun_params_wordlist() == wldir / ARJUN_PARAMS_FILE

    def test_status_reports_present_and_missing(self, wldir):
        (wldir / "api-routes-top20k.txt").write_text("x\n")
        present, missing = wordlist_status()
        assert "api-routes-top20k.txt" in present
        assert "best-dns-top20k.txt" in missing


class TestFfufTechGating:
    async def test_uses_tech_wordlist(self, tmp_path, monkeypatch, wldir):
        """httpx-detected php → php wordlist in the ffuf argv."""
        import json as _json
        from loom import stages as st
        (wldir / "php-top15k.txt").write_text("index.php\n")
        _pin = tmp_path / "binff"
        _pin.mkdir()
        p = _pin / "ffuf"
        p.write_text('#!/bin/sh\nexit 0\n')
        import os
        import stat as _stat
        p.chmod(p.stat().st_mode | _stat.S_IEXEC)
        monkeypatch.setenv("LOOM_TOOL_FFUF", str(p))
        # force the candidates away so only the tech list can win
        monkeypatch.setattr(st, "_FFUF_WORDLIST_CANDIDATES", ())
        ctx = PipelineContext(scope=_scope())
        ctx.extras["tech"] = {"php", "apache"}
        runner = Runner(_scope(), workdir=tmp_path)
        await st.make_ffuf_stage()(runner, "example.com", ctx)
        meta = _json.loads(next(tmp_path.rglob("ffuf.*.cmd.txt")).read_text())
        assert "php-top15k.txt" in " ".join(meta["cmd"])


class TestAmassBrute:
    def test_brute_command(self):
        from loom.stages import amass_command
        cmd = amass_command("example.com", brute=True,
                            wordlist="/wl/best-dns.txt")
        assert cmd[:2] == ["amass", "enum"]
        assert "-brute" in cmd and "-w" in cmd and "/wl/best-dns.txt" in cmd
        assert "-d" in cmd and "example.com" in cmd

    def test_passive_command_unchanged(self):
        from loom.stages import amass_command
        cmd = amass_command("example.com")
        assert "-brute" not in cmd
        assert "-passive" in cmd

    async def test_brute_shares_subdomains(self, tmp_path, monkeypatch, wldir):
        """amass results (passive AND brute) join the subdomains pool
        so resolve/probe see them — previously amass never shared."""
        from loom.stages import make_amass_stage
        import os
        import stat as _stat
        bindir = tmp_path / "binam"
        bindir.mkdir()
        p = bindir / "amass"
        p.write_text('#!/bin/sh\ncat <<\'__OUT__\'\nsub.example.com\n__OUT__\nexit 0\n')
        p.chmod(p.stat().st_mode | _stat.S_IEXEC)
        monkeypatch.setenv("LOOM_TOOL_AMASS", str(p))
        (wldir / "best-dns-top20k.txt").write_text("sub\n")
        ctx = PipelineContext(scope=_scope())
        runner = Runner(_scope(), workdir=tmp_path)
        items = await make_amass_stage(brute=True)(
            runner, "example.com", ctx)
        assert [i.value for i in items] == ["sub.example.com"]
        assert "sub.example.com" in ctx.extras["subdomains"]


class TestArjunWordlist:
    async def test_w_flag_when_params_present(self, tmp_path, monkeypatch, wldir):
        import json as _json
        from loom.stages import make_arjun_stage
        import os
        import stat as _stat
        bindir = tmp_path / "binaj"
        bindir.mkdir()
        p = bindir / "arjun"
        p.write_text('#!/bin/sh\nexit 0\n')
        p.chmod(p.stat().st_mode | _stat.S_IEXEC)
        monkeypatch.setenv("LOOM_TOOL_ARJUN", str(p))
        (wldir / ARJUN_PARAMS_FILE).write_text("id\n")
        ctx = PipelineContext(scope=_scope())
        ctx.extras["urls"] = ["https://a.com/plain"]
        runner = Runner(_scope(), workdir=tmp_path)
        await make_arjun_stage(max_urls=1)(runner, "a.com", ctx)
        meta = _json.loads(next(tmp_path.rglob("arjun.*.cmd.txt")).read_text())
        argv = meta["cmd"]
        assert "-w" in argv
        assert ARJUN_PARAMS_FILE in " ".join(argv)
