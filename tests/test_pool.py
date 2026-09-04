"""Tests for the Tier-1 optimization pass (v0.5): URL pool
normalization, per-host fanout helpers, stdin persistence.

Guiding constraint: optimization must NEVER lose information.
- The raw `urls` pool is append-only and untouched.
- Normalization only shapes *tool inputs*; every raw URL stays in
  the pool, the eventlog, and the variants map.
- Per-host expansion only ADDS targets (root-only scanning was the
  coverage hole).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from loom.pipeline import PipelineContext
from loom.runner import Runner
from loom.scope import from_dict as scope_from_dict
from loom.stages import (
    _live_hosts,
    _target_for,
    _xss_pool,
    normalize_urls,
    scan_pool,
)


def _scope():
    return scope_from_dict({"name": "t", "target": "example.com",
                            "rate_limit_rps": 1000})


def _ctx():
    return PipelineContext(scope=_scope())


class TestNormalizeUrls:
    async def test_collapses_param_value_variants(self):
        urls = [f"https://a.com/s?q={i}" for i in range(50)]
        urls += [f"https://a.com/s?q={i}&page={i}" for i in range(50)]
        reps, variants = normalize_urls(urls)
        # ?q=* collapses to one rep, ?q=*&page=* to another
        assert len(reps) == 2
        # nothing lost: every raw URL is in the variants map
        flat = [u for vs in variants.values() for u in vs]
        assert sorted(flat) == sorted(urls)

    async def test_keeps_distinct_paths_hosts_and_static(self):
        urls = [
            "https://a.com/admin",
            "https://a.com/login",
            "https://b.com/admin",      # same path, other host
            "https://a.com/app.js",     # static kept — JS is secret-scan fuel
            "https://a.com/style.css",  # static kept — no filtering, ever
            "http://a.com/admin",       # scheme variant collapses...
        ]
        reps, variants = normalize_urls(urls)
        assert len(reps) == 5
        assert "https://a.com/app.js" in reps
        assert "https://a.com/style.css" in reps
        # https preferred as representative
        admin_rep = [r for r in reps if r.endswith("/admin")
                     and "b.com" not in r][0]
        assert admin_rep.startswith("https://")

    async def test_representative_prefers_params_then_shortest(self):
        # Different param-name SETS are different surfaces: both kept.
        reps, _ = normalize_urls(["https://a.com/s", "https://a.com/s?q=1&r=2"])
        assert sorted(reps) == ["https://a.com/s", "https://a.com/s?q=1&r=2"]
        # Same key → shortest representative wins.
        reps, variants = normalize_urls(
            ["https://a.com/s?q=bbbb", "https://a.com/s?q=a"])
        assert reps == ["https://a.com/s?q=a"]
        assert sorted(variants["https://a.com/s?q=a"]) == [
            "https://a.com/s?q=a", "https://a.com/s?q=bbbb"]

    async def test_empty_in_empty_out(self):
        assert normalize_urls([]) == ([], {})

    async def test_raw_pool_never_mutated(self):
        urls = ["https://a.com/?x=1", "https://a.com/?x=2"]
        before = list(urls)
        normalize_urls(urls)
        assert urls == before


class TestScanPool:
    async def test_scan_pool_caps_but_keeps_raw(self):
        ctx = _ctx()
        ctx.extras["urls"] = [f"https://a.com/p{i}?x=1" for i in range(100)]
        pool = scan_pool(ctx, cap=10)
        assert len(pool) == 10
        assert len(ctx.extras["urls"]) == 100  # raw untouched
        assert "url_variants" in ctx.extras     # attribution preserved

    async def test_scan_pool_empty_without_urls(self):
        assert scan_pool(_ctx()) == []

    async def test_xss_pool_still_prefers_params(self):
        # 10 same-key param variants normalize to ONE rep (that's the
        # point) which still sorts first; nothing is lost.
        plain = [f"https://a.com/{i}" for i in range(300)]
        params = [f"https://a.com/s?q={i}" for i in range(10)]
        pool = _xss_pool(plain + params, cap=100)
        assert len(pool) == 100
        assert pool[0] == "https://a.com/s?q=0"
        from loom.stages import normalize_urls as _n
        _, variants = _n(params)
        assert len(variants["https://a.com/s?q=0"]) == 10


class TestLiveHosts:
    async def test_extracts_hosts_root_first_by_frequency(self):
        ctx = _ctx()
        ctx.extras["urls"] = [
            "http://b.com/x", "https://a.com/y", "http://b.com/z",
            "https://a.com/w?q=1",
        ]
        ctx.extras["resolved_subs"] = ["c.com"]
        hosts = _live_hosts(ctx, "root.com")
        assert hosts[0] == "root.com"
        # b.com (2 urls) before a.com (2 urls)? tie → alpha
        assert hosts.index("a.com") < hosts.index("c.com")
        assert "c.com" in hosts

    async def test_strips_default_ports_keeps_alt(self):
        ctx = _ctx()
        ctx.extras["urls"] = ["http://a.com:80/x", "https://b.com:8443/y"]
        hosts = _live_hosts(ctx, "root.com")
        assert "a.com" in hosts
        assert "b.com:8443" in hosts

    async def test_target_for_prefers_probed_scheme(self):
        ctx = _ctx()
        ctx.extras["urls"] = ["http://a.com/login", "https://b.com/"]
        assert _target_for(ctx, "a.com") == "http://a.com"
        assert _target_for(ctx, "b.com") == "https://b.com"
        assert _target_for(ctx, "unseen.com") == "https://unseen.com"

    async def test_bare_host_falls_back_to_root(self):
        assert _live_hosts(_ctx(), "root.com") == ["root.com"]


class TestStdinPersistence:
    async def test_cmd_meta_records_stdin(self, tmp_path: Path):
        """Every invocation's stdin is persisted in the .cmd.txt meta —
        full reproducibility (the 'never lose info' rule for inputs)."""
        runner = Runner(_scope(), workdir=tmp_path)
        await runner.run("sh", ["sh", "-c", "cat"], stage="t", host="h",
                   parser="raw", stdin="hello\nworld")
        metas = list(tmp_path.rglob("*.cmd.txt"))
        assert len(metas) == 1
        meta = json.loads(metas[0].read_text())
        assert meta["stdin"] == "hello\nworld"

    async def test_cmd_meta_stdin_null_when_none(self, tmp_path: Path):
        runner = Runner(_scope(), workdir=tmp_path)
        await runner.run("sh", ["sh", "-c", "true"], stage="t", host="h",
                   parser="raw")
        meta = json.loads(next(tmp_path.rglob("*.cmd.txt")).read_text())
        assert meta["stdin"] is None


class TestTimestampedOutputs:
    async def test_repeated_invocations_do_not_overwrite(self, tmp_path: Path):
        """Live-theme bug: `{tool}.{ts}` + with_suffix('.cmd.txt')
        replaced the timestamp, so re-runs overwrote prior outputs.
        Filenames must keep the timestamp."""
        import time
        runner = Runner(_scope(), workdir=tmp_path)
        await runner.run("sh", ["sh", "-c", "echo one"], stage="t", host="h",
                   parser="raw")
        time.sleep(0.002)
        await runner.run("sh", ["sh", "-c", "echo two"], stage="t", host="h",
                   parser="raw")
        cmds = sorted(tmp_path.rglob("*.cmd.txt"))
        assert len(cmds) == 2
        assert cmds[0].name != cmds[1].name


def _pin_fake(tmp_path: Path, monkeypatch, name: str, output: str):
    """Pin a fake binary via LOOM_TOOL_<NAME> (repo convention)."""
    import os
    import stat as _stat
    bindir = tmp_path / f"bin-{name}"
    bindir.mkdir(exist_ok=True)
    p = bindir / name
    p.write_text(f"#!/bin/sh\ncat <<'__OUT__'\n{output}\n__OUT__\nexit 0\n")
    p.chmod(p.stat().st_mode | _stat.S_IEXEC)
    monkeypatch.setenv(f"LOOM_TOOL_{name.upper()}", str(p))
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}")
    return p


class TestPerHostFanout:
    # Real ffuf -json shape (live 2026-09-05): input values are b64.
    FFUF_JSONL = ('{"url": "PLACEHOLDER", "status": 200, "length": 10, '
                  '"words": 5, "input": {"FUZZ": "YWRtaW4="}}')

    async def test_ffuf_scans_every_live_host(self, tmp_path, monkeypatch):
        """Coverage hole (live 2026-09-05): deep fuzzed only the root
        domain. Now every live host gets its own invocation + dir."""
        from loom.stages import make_ffuf_stage
        _pin_fake(tmp_path, monkeypatch, "ffuf", self.FFUF_JSONL.replace(
            "PLACEHOLDER", "https://x/admin"))
        ctx = PipelineContext(scope=_scope())
        ctx.extras["urls"] = ["http://a.com/", "https://b.com/app"]
        runner = Runner(_scope(), workdir=tmp_path)
        items = await make_ffuf_stage()(runner, "root.com", ctx)
        fuzzdir = tmp_path / "fuzz"
        hosts_done = sorted(d.name for d in fuzzdir.iterdir() if d.is_dir())
        # root + a.com + b.com each got an invocation
        assert "root.com" in hosts_done
        assert "a.com" in hosts_done
        assert "b.com" in hosts_done
        for h in hosts_done:
            assert list((fuzzdir / h).glob("ffuf.*.cmd.txt")), h
        assert len(items) == 3  # one canned hit per host

    async def test_naabu_scans_every_live_host(self, tmp_path, monkeypatch):
        from loom.stages import make_naabu_stage
        _pin_fake(tmp_path, monkeypatch, "naabu", "a.com:80")
        ctx = PipelineContext(scope=_scope())
        ctx.extras["resolved_subs"] = ["a.com", "b.com"]
        runner = Runner(_scope(), workdir=tmp_path)
        items = await make_naabu_stage()(runner, "root.com", ctx)
        psdir = tmp_path / "portscan"
        hosts_done = sorted(d.name for d in psdir.iterdir() if d.is_dir())
        assert "a.com" in hosts_done
        assert "b.com" in hosts_done
        assert "root.com" in hosts_done
        assert any(i.value == "a.com:80" for i in items)

    async def test_nuclei_scans_normalized_pool(self, tmp_path, monkeypatch):
        """50 param-value variants collapse to 1 nuclei target —
        assertable via the persisted stdin (v0.5 meta)."""
        from loom.stages import make_nuclei_stage
        _pin_fake(tmp_path, monkeypatch, "nuclei",
                  '{"template-id": "t", "matched-at": "https://a.com/s?q=1", '
                  '"type": "http", "info": {"severity": "high"}}')
        ctx = PipelineContext(scope=_scope())
        ctx.extras["urls"] = [f"https://a.com/s?q={i}" for i in range(50)]
        runner = Runner(_scope(), workdir=tmp_path)
        items = await make_nuclei_stage()(runner, "a.com", ctx)
        assert len(items) == 1
        meta = json.loads(next(tmp_path.rglob("nuclei.*.cmd.txt")).read_text())
        assert meta["stdin"].strip().splitlines() == ["https://a.com/s?q=0"]
        # raw pool intact
        assert len(ctx.extras["urls"]) == 50


class TestGowitnessStage:
    async def test_command_builder(self, tmp_path):
        from loom.stages import gowitness_command
        cmd = gowitness_command(tmp_path / "t.txt", tmp_path / "shots",
                                chrome_path="/c/chrome", threads=2)
        assert cmd[:4] == ["gowitness", "scan", "file", "-f"]
        assert "-s" in cmd and "--chrome-path" in cmd and "/c/chrome" in cmd
        assert "2" in cmd

    async def test_invocation_writes_targets_and_returns_shots(
            self, tmp_path, monkeypatch):
        from loom.stages import make_gowitness_stage
        _pin_fake(tmp_path, monkeypatch, "gowitness", "")
        ctx = PipelineContext(scope=_scope())
        ctx.extras["urls"] = ["http://a.com/", "https://b.com/x"]
        runner = Runner(_scope(), workdir=tmp_path)
        items = await make_gowitness_stage()(runner, "root.com", ctx)
        # targets file lists root + both live hosts
        targets = (tmp_path / "inputs" / "root.com"
                   / "gowitness-targets.txt").read_text().splitlines()
        assert targets[0] == "https://root.com"
        assert "http://a.com" in targets and "https://b.com" in targets
        # fake produced no shots → no items, but invocation recorded
        assert items == []
        assert list(tmp_path.rglob("gowitness.*.cmd.txt"))

    async def test_screenshots_in_finds_images(self, tmp_path):
        from loom.stages import _screenshots_in
        d = tmp_path / "shots"
        d.mkdir()
        (d / "a.jpeg").write_bytes(b"x")
        (d / "b.png").write_bytes(b"x")
        (d / "notes.txt").write_text("nope")
        found = _screenshots_in(d)
        assert [p.name for p in found] == ["a.jpeg", "b.png"]
        assert _screenshots_in(tmp_path / "missing") == []
