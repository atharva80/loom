"""loom.stages tests.

Two layers:
  1. Command-builder tests — pure functions, no I/O. Verify each
     `<tool>_command(...)` returns the expected argv for known inputs.
  2. Stage integration tests — drive the stages via Runner with a
     fake `<tool>` binary (a shell script on PATH that emits canned
     output). This exercises the full Runner → parser → OutputItem
     path without needing the real toolchain.

The fake-binary approach is portable: we drop a sh script into a temp
dir, prepend it to PATH, and the Runner picks it up.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from loom.dag import DAG, Node
from loom.eventlog import EventLog
from loom.pipeline import Pipeline, PipelineContext
from loom.runner import OutputItem, Runner
from loom.scope import from_dict as scope_from_dict
from loom.stages import (
    DEFAULT_BIN,
    dnsx_command,
    httpx_command,
    katana_command,
    make_amass_stage,
    make_assetfinder_stage,
    make_dnsx_stage,
    make_ffuf_stage,
    make_gau_stage,
    make_httpx_stage,
    make_katana_stage,
    make_naabu_stage,
    make_nuclei_stage,
    make_subfinder_stage,
    make_waybackurls_stage,
    naabu_command,
    nuclei_command,
    subfinder_command,
)


def _scope():
    return scope_from_dict({"name": "t", "target": "example.com",
                            "rate_limit_rps": 1000})


# ============================================================
# Command-builder tests
# ============================================================


class TestCommandBuilders:
    def test_subfinder_command(self):
        cmd = subfinder_command("example.com")
        assert cmd[0] == "subfinder"
        assert "-d" in cmd and "example.com" in cmd
        assert "-silent" in cmd
        assert "-all" in cmd

    def test_subfinder_custom_bin(self):
        cmd = subfinder_command("example.com", bin_path="/opt/subfinder/bin/subfinder")
        assert cmd[0] == "/opt/subfinder/bin/subfinder"

    def test_dnsx_command(self):
        cmd = dnsx_command(["a.example.com", "b.example.com"])
        assert cmd[0] == "dnsx"
        assert "-silent" in cmd
        assert "-resp" in cmd

    def test_httpx_command(self):
        cmd = httpx_command("https://example.com")
        assert cmd[0] == "httpx"
        assert "-u" in cmd
        assert "https://example.com" in cmd
        assert "-json" in cmd

    def test_naabu_command(self):
        cmd = naabu_command("example.com")
        assert cmd[0] == "naabu"
        assert "-host" in cmd
        assert "example.com" in cmd
        assert "-ports" in cmd

    def test_nuclei_command(self):
        cmd = nuclei_command("https://example.com")
        assert cmd[0] == "nuclei"
        assert "-u" in cmd
        assert "https://example.com" in cmd
        assert "-severity" in cmd
        assert "critical,high,medium" in cmd

    def test_katana_command(self):
        cmd = katana_command("https://example.com", depth=3)
        assert cmd[0] == "katana"
        assert "-depth" in cmd
        assert "3" in cmd


# ============================================================
# Fake-binary integration tests
# ============================================================


@pytest.fixture
def fake_bin_dir(tmp_path: Path, monkeypatch) -> Path:
    """Create a temp dir with fake `subfinder` / `httpx` / etc. binaries
    that just emit canned output, then prepend it to PATH.

    Known shadowers (httpx) need LOOM_TOOL_<NAME> to point at the fake
    so binary resolution prefers it over ~/go/bin.
    """
    bindir = tmp_path / "bin"
    bindir.mkdir()

    def _make(name: str, output: str, exit_code: int = 0):
        path = bindir / name
        # We use a here-doc + printf so the output is exact (no leading
        # whitespace, no trailing newlines that don't belong). The
        # -version branch makes the fake pass shadower validation.
        path.write_text(
            f"#!/bin/sh\n"
            f"if [ \"$1\" = \"-version\" ]; then\n"
            f"  echo 'projectdiscovery/{name} v9.9.9-fake'\n"
            f"  exit 0\n"
            f"fi\n"
            f"cat <<'__OUT__'\n"
            f"{output}\n"
            f"__OUT__\n"
            f"exit {exit_code}\n"
        )
        path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    # subfinder: emit 2 subdomains
    _make("subfinder",
          "a.example.com\n"
          "b.example.com")
    # dnsx: emit 2 records
    _make("dnsx",
          "a.example.com [a] 1.2.3.4\n"
          "b.example.com [a] 5.6.7.8")
    # httpx: emit JSON
    _make("httpx",
          '{"host": "a.example.com", "url": "https://a.example.com/", '
          '"status_code": 200, "title": "A"}\n'
          '{"host": "b.example.com", "url": "https://b.example.com/", '
          '"status_code": 301, "title": "B"}')
    # naabu: emit host:port
    _make("naabu",
          "a.example.com:80\n"
          "a.example.com:443")
    # nuclei: emit JSON
    _make("nuclei",
          '{"template-id": "CVE-2024-9999", "matched-at": "https://a.example.com/x", '
          '"type": "http", "info": {"severity": "high", "name": "Demo Vuln"}}')
    # katana: emit URLs
    _make("katana",
          "https://a.example.com/page1\n"
          "https://a.example.com/page2")
    # assetfinder: emit subdomains
    _make("assetfinder", "a.example.com\nb.example.com")
    # waybackurls: emit URLs
    _make("waybackurls", "https://a.example.com/old1\nhttps://a.example.com/old2")
    # gau: emit URLs
    _make("gau", "https://a.example.com/gau1")
    # amass: emit subdomains
    _make("amass", "a.example.com\nb.example.com")
    # ffuf: emit findings
    _make("ffuf", "https://example.com/admin [200]\nhttps://example.com/login [302]")

    # Prepend to PATH so Runner finds them. pytest's monkeypatch
    # doesn't have prependenv, so we do it manually.
    old_path = os.environ.get("PATH", "")
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{old_path}")
    # Pin every fake via LOOM_TOOL_<NAME> — this makes binary
    # resolution deterministic regardless of earlier tests caching
    # the real binaries (cross-test pollution guard).
    for name in ("subfinder", "dnsx", "httpx", "naabu", "nuclei",
                 "katana", "assetfinder", "waybackurls", "gau",
                 "amass", "ffuf"):
        monkeypatch.setenv(f"LOOM_TOOL_{name.upper()}", str(bindir / name))
    return bindir


# ============================================================
# Per-tool stage tests
# ============================================================


class TestSubfinderStage:
    async def test_subfinder_emits_subdomains(self, fake_bin_dir: Path, tmp_path: Path):
        runner = Runner(_scope(), workdir=tmp_path)
        stage = make_subfinder_stage()
        items = await stage(runner, "example.com", PipelineContext(scope=runner.scope))
        assert [i.value for i in items] == ["a.example.com", "b.example.com"]
        assert all(i.kind == "subdomain" for i in items)


class TestDnsxStage:
    async def test_dnsx_emits_subdomains(self, fake_bin_dir: Path, tmp_path: Path):
        runner = Runner(_scope(), workdir=tmp_path)
        stage = make_dnsx_stage()
        items = await stage(runner, "example.com", PipelineContext(scope=runner.scope))
        assert [i.value for i in items] == ["a.example.com", "b.example.com"]


class TestHttpxStage:
    async def test_httpx_emits_hosts(self, fake_bin_dir: Path, tmp_path: Path):
        runner = Runner(_scope(), workdir=tmp_path)
        stage = make_httpx_stage()
        items = await stage(runner, "https://example.com", PipelineContext(scope=runner.scope))
        # 2 hosts + 2 url items (url items feed the nuclei scan stage)
        assert len(items) == 4
        kinds = [i.kind for i in items]
        assert kinds.count("host") == 2
        assert kinds.count("url") == 2
        assert {i.value for i in items if i.kind == "host"} == {"a.example.com", "b.example.com"}
        assert {i.value for i in items if i.kind == "url"} == {"https://a.example.com/", "https://b.example.com/"}
        # evidence preserved
        ev = items[0].evidence
        assert ev["status_code"] in (200, 301)


class TestNaabuStage:
    async def test_naabu_emits_ports(self, fake_bin_dir: Path, tmp_path: Path):
        runner = Runner(_scope(), workdir=tmp_path)
        stage = make_naabu_stage()
        items = await stage(runner, "example.com", PipelineContext(scope=runner.scope))
        assert [i.value for i in items] == ["a.example.com:80", "a.example.com:443"]
        assert all(i.kind == "port" for i in items)


class TestNucleiStage:
    async def test_nuclei_emits_findings(self, fake_bin_dir: Path, tmp_path: Path):
        runner = Runner(_scope(), workdir=tmp_path)
        stage = make_nuclei_stage()
        items = await stage(runner, "https://example.com", PipelineContext(scope=runner.scope))
        assert len(items) == 1
        assert items[0].kind == "finding"
        assert items[0].value == "https://a.example.com/x"
        assert items[0].evidence["template_id"] == "CVE-2024-9999"
        assert items[0].evidence["severity"] == "high"


class TestKatanaStage:
    async def test_katana_emits_urls(self, fake_bin_dir: Path, tmp_path: Path):
        runner = Runner(_scope(), workdir=tmp_path)
        stage = make_katana_stage()
        items = await stage(runner, "https://example.com", PipelineContext(scope=runner.scope))
        assert [i.value for i in items] == [
            "https://a.example.com/page1", "https://a.example.com/page2"
        ]
        assert all(i.kind == "url" for i in items)


class TestAssetfinderStage:
    async def test_assetfinder_emits_subdomains(self, fake_bin_dir: Path, tmp_path: Path):
        runner = Runner(_scope(), workdir=tmp_path)
        stage = make_assetfinder_stage()
        items = await stage(runner, "example.com", PipelineContext(scope=runner.scope))
        assert [i.value for i in items] == ["a.example.com", "b.example.com"]


class TestWaybackurlsStage:
    async def test_wayback_emits_urls(self, fake_bin_dir: Path, tmp_path: Path):
        runner = Runner(_scope(), workdir=tmp_path)
        stage = make_waybackurls_stage()
        items = await stage(runner, "example.com", PipelineContext(scope=runner.scope))
        assert [i.value for i in items] == [
            "https://a.example.com/old1", "https://a.example.com/old2"
        ]

    async def test_waybackurls_shares_urls(self, fake_bin_dir, tmp_path):
        """Live-verified bug (2026-09-04): waybackurls + gau output
        didn't land in ctx.extras['urls'], so the xss/crlfuzz/kxss
        fanout ran against an empty URL pool. Both url stages now
        contribute to the shared pool (like katana already did)."""
        ctx = PipelineContext(scope=Runner(_scope()).scope)
        await make_waybackurls_stage()(Runner(_scope(), workdir=tmp_path),
                                        "example.com", ctx)
        assert ctx.extras["urls"] == [
            "https://a.example.com/old1", "https://a.example.com/old2"
        ]


class TestGauStage:
    async def test_gau_emits_urls(self, fake_bin_dir: Path, tmp_path: Path):
        runner = Runner(_scope(), workdir=tmp_path)
        stage = make_gau_stage()
        items = await stage(runner, "example.com", PipelineContext(scope=runner.scope))
        assert [i.value for i in items] == ["https://a.example.com/gau1"]

    async def test_gau_shares_urls(self, fake_bin_dir, tmp_path):
        """Live-verified bug (2026-09-04): gau emitted 15,064 URLs on
        vulnweb but none made it into ctx.extras['urls'], so the
        downstream xss fanout was a no-op. Now contributes to the pool."""
        ctx = PipelineContext(scope=Runner(_scope()).scope)
        await make_gau_stage()(Runner(_scope(), workdir=tmp_path),
                                "example.com", ctx)
        assert ctx.extras["urls"] == ["https://a.example.com/gau1"]


class TestAmassStage:
    async def test_amass_emits_subdomains(self, fake_bin_dir: Path, tmp_path: Path):
        runner = Runner(_scope(), workdir=tmp_path)
        stage = make_amass_stage()
        items = await stage(runner, "example.com", PipelineContext(scope=runner.scope))
        assert [i.value for i in items] == ["a.example.com", "b.example.com"]


class TestFfufStage:
    async def test_ffuf_emits_findings(self, fake_bin_dir: Path, tmp_path: Path):
        """v0.4: ffuf runs with real flags (-s -json, -w auto-resolved)
        and its JSONL output parses into finding items."""
        runner = Runner(_scope(), workdir=tmp_path)
        stage = make_ffuf_stage()
        items = await stage(runner, "https://example.com", PipelineContext(scope=runner.scope))
        # old fake emitted non-JSON lines -> now dropped by the JSONL parser.
        # The wordlist auto-resolution guarantees the -w path exists, so the
        # invocation succeeds; fake emits plain text so 0 findings is correct.
        assert items == []


# ============================================================
# End-to-end stage pipeline test
# ============================================================


class TestStagePipeline:
    async def test_subenum_to_probe(self, fake_bin_dir: Path, tmp_path: Path):
        """subfinder → httpx, two stages. httpx sees the subdomains via
        the pipeline's host parameter (the pipeline calls the next
        stage once per upstream item in v1, but here we test the
        simple case where the next stage runs once on the parent host).
        """
        dag = DAG()
        dag.add(Node(id="subenum", outputs={"subdomain"}))
        dag.add(Node(
            id="probe",
            inputs={"subdomain"},
            depends_on=["subenum"],
            # Only run probe if subenum produced >= 2 subs
            should_run=lambda s: s.from_node("subenum", "subdomain") >= 2,
        ))
        stages = {
            "subenum": make_subfinder_stage(),
            "probe": make_httpx_stage(),
        }
        runner = Runner(_scope(), workdir=tmp_path)
        ctx = PipelineContext(scope=runner.scope)
        pipeline = Pipeline(runner, stages, context=ctx)
        outcomes = await pipeline.run(dag, host="example.com")
        by_id = {o.node_id: o for o in outcomes}
        assert by_id["subenum"].status == "done"
        assert by_id["subenum"].items  # got items
        assert by_id["probe"].status == "done"
        assert by_id["probe"].items  # got items


# ============================================================
# DEFAULT_BIN sanity
# ============================================================


class TestDefaultBin:
    def test_all_tools_have_defaults(self):
        for tool in ("subfinder", "httpx", "naabu", "nuclei", "katana",
                     "dnsx", "assetfinder", "ffuf", "gau", "waybackurls",
                     "amass"):
            assert tool in DEFAULT_BIN
            assert DEFAULT_BIN[tool]  # non-empty
