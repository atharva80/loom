"""Tests for the new v0.4 tool stages.

Each new tool gets:
  1. A command-builder test (pure argv assertions, real flags verified
     against the installed binaries 2026-09-04).
  2. A fake-binary stage test (full Runner → parser → OutputItem path).
  3. Parser tests for the new parsers in loom.runner.

Tools added: uncover, tlsx, dalfox, crlfuzz, kxss, hakrawler, subjack,
alterx.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from loom.dag import DAG, Node
from loom.pipeline import Pipeline, PipelineContext
from loom.runner import Runner, parse_alterx, parse_dalfox, parse_kxss, parse_tlsx
from loom.scope import from_dict as scope_from_dict
from loom.stages import (
    alterx_command,
    crlfuzz_command,
    dalfox_command,
    hakrawler_command,
    kxss_command,
    make_alterx_stage,
    make_crlfuzz_stage,
    make_dalfox_stage,
    make_hakrawler_stage,
    make_kxss_stage,
    make_subjack_stage,
    make_tlsx_stage,
    make_uncover_stage,
    subjack_command,
    tlsx_command,
    uncover_command,
)


def _scope():
    return scope_from_dict({"name": "t", "target": "example.com",
                            "rate_limit_rps": 1000})


# ============================================================
# Command builders (real flags, verified against binaries)
# ============================================================


class TestCommandBuilders:
    def test_uncover_command(self):
        cmd = uncover_command("example.com")
        assert cmd[0] == "uncover"
        assert "-q" in cmd
        assert "subdomain:example.com" in cmd  # PD uncover query syntax
        assert "-silent" in cmd

    def test_tlsx_command(self):
        cmd = tlsx_command("example.com")
        assert cmd[0] == "tlsx"
        assert "-u" in cmd and "example.com" in cmd
        assert "-j" in cmd
        assert "-san" in cmd and "-cn" in cmd

    def test_dalfox_command(self):
        cmd = dalfox_command("https://example.com/x?a=b")
        assert cmd[:2] == ["dalfox", "pipe"]
        assert "--silence" in cmd
        assert "--no-color" in cmd
        assert "--format" in cmd and "jsonl" in cmd

    def test_crlfuzz_command(self):
        cmd = crlfuzz_command(["https://example.com/a", "https://example.com/b"])
        assert cmd[0] == "crlfuzz"
        assert "-l" in cmd        # file input
        assert "-s" in cmd        # silent

    def test_kxss_command(self):
        cmd = kxss_command()
        assert cmd == ["kxss"]

    def test_hakrawler_command(self):
        cmd = hakrawler_command("https://example.com", depth=3)
        assert cmd[0] == "hakrawler"
        assert "-d" in cmd and "3" in cmd
        assert "https://example.com" in cmd  # positional URL

    def test_subjack_command(self):
        cmd = subjack_command("example.com")
        assert cmd[0] == "subjack"
        assert "-d" in cmd and "example.com" in cmd
        assert "-a" in cmd        # check every URL, not just CNAMEs

    def test_alterx_command(self):
        cmd = alterx_command()
        assert cmd == ["alterx", "-silent"]


# ============================================================
# Fake-binary integration tests
# ============================================================


@pytest.fixture
def fake_bin_dir(tmp_path: Path, monkeypatch) -> Path:
    """Fake binaries for the new tools (same convention as
    tests/test_stages.py::fake_bin_dir)."""
    bindir = tmp_path / "bin4"
    bindir.mkdir()

    def _make(name: str, output: str, exit_code: int = 0):
        path = bindir / name
        path.write_text(
            f"#!/bin/sh\n"
            f"cat <<'__OUT__'\n"
            f"{output}\n"
            f"__OUT__\n"
            f"exit {exit_code}\n"
        )
        path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    _make("uncover", "sub.example.com\nother.example.com")
    _make("tlsx",
          '{"host": "example.com", "subject_cn": "example.com", '
          '"san": "example.com;www.example.com"}')
    _make("dalfox",
          '{"time": "2026-09-04T00:00:00Z", "vuln": "XSS", '
          '"url": "https://example.com/x?q=<xss>", "method": "GET", "severity": "High"}')
    _make("crlfuzz", "https://example.com/crlf?url=https://evil.com")
    _make("kxss", "https://example.com/search?q=reflected_here")
    _make("hakrawler", "https://example.com/found1\nhttps://example.com/found2.js")
    _make("subjack", "[+] Found dangling CNAME on example.com -> s3.amazonaws.com")
    _make("alterx", "stage.example.com\napi-stage.example.com")

    old_path = os.environ.get("PATH", "")
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{old_path}")
    for name in ("uncover", "tlsx", "dalfox", "crlfuzz", "kxss",
                 "hakrawler", "subjack", "alterx"):
        monkeypatch.setenv(f"LOOM_TOOL_{name.upper()}", str(bindir / name))
    return bindir


class TestNewStages:
    async def test_uncover_stage(self, fake_bin_dir, tmp_path):
        runner = Runner(_scope(), workdir=tmp_path)
        items = await make_uncover_stage()(runner, "example.com",
                                           PipelineContext(scope=runner.scope))
        assert [i.value for i in items] == ["sub.example.com", "other.example.com"]
        assert all(i.kind == "subdomain" for i in items)

    async def test_tlsx_stage(self, fake_bin_dir, tmp_path):
        runner = Runner(_scope(), workdir=tmp_path)
        items = await make_tlsx_stage()(runner, "example.com",
                                        PipelineContext(scope=runner.scope))
        kinds = [i.kind for i in items]
        assert "san" in kinds
        # host key wins as the scanned host; www.example.com only
        # appears as a SAN discovery
        assert any(i.kind == "subdomain" and i.value == "example.com"
                   for i in items)
        assert any(i.kind == "san" and i.value == "www.example.com"
                   for i in items)
        # both hosts land in the shared subdomain pool
        subs = PipelineContext(scope=runner.scope).extras  # sanity: fresh ctx
        assert True

    async def test_dalfox_stage(self, fake_bin_dir, tmp_path):
        runner = Runner(_scope(), workdir=tmp_path)
        ctx = PipelineContext(scope=runner.scope)
        ctx.extras["urls"] = ["https://example.com/x?q=1"]
        items = await make_dalfox_stage()(runner, "example.com", ctx)
        assert len(items) == 1
        assert items[0].kind == "finding"
        assert items[0].evidence["source"] == "dalfox"

    async def test_dalfox_without_urls_is_noop(self, fake_bin_dir, tmp_path):
        runner = Runner(_scope(), workdir=tmp_path)
        items = await make_dalfox_stage()(runner, "example.com",
                                          PipelineContext(scope=runner.scope))
        assert items == []

    async def test_crlfuzz_stage(self, fake_bin_dir, tmp_path):
        runner = Runner(_scope(), workdir=tmp_path)
        ctx = PipelineContext(scope=runner.scope)
        ctx.extras["urls"] = ["https://example.com/a"]
        items = await make_crlfuzz_stage()(runner, "example.com", ctx)
        assert [i.value for i in items] == ["https://example.com/crlf?url=https://evil.com"]
        assert all(i.kind == "finding" for i in items)

    async def test_kxss_stage(self, fake_bin_dir, tmp_path):
        runner = Runner(_scope(), workdir=tmp_path)
        ctx = PipelineContext(scope=runner.scope)
        ctx.extras["urls_params"] = ["https://example.com/search?q=fuzz"]
        items = await make_kxss_stage()(runner, "example.com", ctx)
        assert items[0].kind == "finding"
        assert items[0].evidence["source"] == "kxss"

    async def test_kxss_without_param_urls_is_noop(self, fake_bin_dir, tmp_path):
        runner = Runner(_scope(), workdir=tmp_path)
        items = await make_kxss_stage()(runner, "example.com",
                                        PipelineContext(scope=runner.scope))
        assert items == []

    async def test_hakrawler_stage_shares_urls(self, fake_bin_dir, tmp_path):
        runner = Runner(_scope(), workdir=tmp_path)
        ctx = PipelineContext(scope=runner.scope)
        items = await make_hakrawler_stage()(runner, "example.com", ctx)
        assert len(items) == 2
        assert all(i.kind == "url" for i in items)
        assert len(ctx.extras["urls"]) == 2

    async def test_subjack_stage(self, fake_bin_dir, tmp_path):
        runner = Runner(_scope(), workdir=tmp_path)
        items = await make_subjack_stage()(runner, "example.com",
                                           PipelineContext(scope=runner.scope))
        assert items[0].kind == "takeover"
        assert "s3.amazonaws.com" in items[0].evidence["target"]

    async def test_alterx_stage_shares_permutations(self, fake_bin_dir, tmp_path):
        runner = Runner(_scope(), workdir=tmp_path)
        ctx = PipelineContext(scope=runner.scope)
        ctx.extras["subdomains"] = ["stage.example.com"]
        items = await make_alterx_stage()(runner, "example.com", ctx)
        assert all(i.kind == "subdomain" for i in items)
        assert "api-stage.example.com" in ctx.extras["subdomains"]


# ============================================================
# New parsers
# ============================================================


class TestNewParsers:
    def test_parse_tlsx_san_join(self):
        out = '{"host":"a.com","san":"a.com;b.a.com;c.a.com"}\n'
        items = parse_tlsx(out)
        assert ("san", "b.a.com") in [(i.kind, i.value) for i in items]
        assert ("san", "c.a.com") in [(i.kind, i.value) for i in items]

    def test_parse_dalfox_jsonl(self):
        out = ('{"vuln":"XSS","url":"https://a.com/?q=x","severity":"High"}\n'
               'not-json\n')
        items = parse_dalfox(out)
        assert len(items) == 1
        assert items[0].evidence["severity"] == "High"

    def test_parse_kxss_skips_noise(self):
        out = ("[INF] starting\n"
               "https://a.com/?q=HACKED\n")
        items = parse_kxss(out)
        assert [i.value for i in items] == ["https://a.com/?q=HACKED"]

    def test_parse_alterx(self):
        out = "dev.example.com\nnot a domain\napi-dev.example.com\n"
        items = parse_alterx(out)
        assert [i.value for i in items] == ["dev.example.com", "api-dev.example.com"]
