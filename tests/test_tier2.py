"""Tests for the Tier-2 pass (v0.6): Arjun param discovery, JS secret
scanning (gitleaks + jsluice), asnmap key-gated ASN harvest.

Constraint carried over from v0.5: raw pools append-only, stages only
shape tool inputs; every raw artifact stays stored and attributable.
"""

from __future__ import annotations

import functools
import json
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from loom.pipeline import PipelineContext
from loom.runner import (
    Runner,
    parse_arjun,
    parse_asnmap,
    parse_gitleaks,
    parse_jsluice_secrets,
    parse_jsluice_urls,
)
from loom.scope import from_dict as scope_from_dict


def _scope():
    return scope_from_dict({"name": "t", "target": "example.com",
                            "rate_limit_rps": 1000})


def _ctx():
    return PipelineContext(scope=_scope())


@pytest.fixture
def file_server(tmp_path):
    """Local HTTP server rooted at tmp_path/www (hermetic, no net)."""
    www = tmp_path / "www"
    www.mkdir()
    handler = functools.partial(SimpleHTTPRequestHandler, directory=str(www))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}", www
    srv.shutdown()


def _pin_fake(tmp_path: Path, monkeypatch, name: str, body: str):
    import os
    import stat as _stat
    bindir = tmp_path / f"bin2-{name}"
    bindir.mkdir(exist_ok=True)
    p = bindir / name
    p.write_text(f"#!/bin/sh\n{body}\n")
    p.chmod(p.stat().st_mode | _stat.S_IEXEC)
    monkeypatch.setenv(f"LOOM_TOOL_{name.upper()}", str(p))
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}")
    return p


class TestArjunParser:
    def test_get_lines_become_urls(self):
        out = ("https://a.com/s.php?id=1&name=x\n"
               "https://a.com/other\n"
               "not a url\n")
        items = parse_arjun(out)
        assert [i.value for i in items] == [
            "https://a.com/s.php?id=1&name=x", "https://a.com/other"]
        assert all(i.kind == "url" for i in items)
        assert items[0].evidence["source"] == "arjun"

    def test_post_lines_keep_method_and_params(self):
        out = "https://a.com/login\tuser=1&pass=2\n"
        items = parse_arjun(out)
        assert len(items) == 1
        assert items[0].value == "https://a.com/login"
        assert items[0].evidence["method"] == "POST"
        assert "user" in items[0].evidence["params"]


class TestArjunStage:
    def test_discovers_params_into_pools(self, tmp_path, monkeypatch):
        """Fake arjun emulates -oT by writing canned URLs to the .txt
        argv; discovered params must land in urls AND urls_params."""
        import asyncio
        from loom.stages import make_arjun_stage
        _pin_fake(tmp_path, monkeypatch, "arjun",
                  'for a in "$@"; do case "$a" in *.txt)\n'
                  '  printf "https://a.com/s.php?id=1\\n" > "$a";; esac; done\n'
                  'exit 0')
        ctx = _ctx()
        ctx.extras["urls"] = ["https://a.com/s.php", "https://a.com/s.php?id=9"]
        runner = Runner(_scope(), workdir=tmp_path)
        items = asyncio.run(make_arjun_stage(max_urls=2)(
            runner, "a.com", ctx))
        assert any(i.value == "https://a.com/s.php?id=1" for i in items)
        assert "https://a.com/s.php?id=1" in ctx.extras["urls_params"]
        assert "https://a.com/s.php?id=1" in ctx.extras["urls"]
        # raw pool keeps the original paramless URL too
        assert "https://a.com/s.php" in ctx.extras["urls"]

    def test_arjun_targets_paramless_reps_only(self, tmp_path, monkeypatch):
        """Arjun is request-heavy: feed it paramless normalized reps,
        never the full variant flood."""
        import asyncio
        import json as _json
        from loom.stages import make_arjun_stage
        _pin_fake(tmp_path, monkeypatch, "arjun", "exit 0")
        ctx = _ctx()
        ctx.extras["urls"] = ([f"https://a.com/s?q={i}" for i in range(20)]
                              + ["https://a.com/plain"])
        runner = Runner(_scope(), workdir=tmp_path)
        asyncio.run(make_arjun_stage(max_urls=5)(runner, "a.com", ctx))
        metas = list(tmp_path.rglob("arjun.*.cmd.txt"))
        assert len(metas) == 1  # only the paramless rep scanned
        stdin_targets = tmp_path / "inputs" / "a.com" / "arjun-targets.txt"
        assert stdin_targets.read_text().splitlines() == ["https://a.com/plain"]


class TestFetchJs:
    def test_downloads_only_js_with_caps(self, file_server):
        from loom.stages import _fetch_js
        from pathlib import Path as _P
        base, www = file_server
        (www / "a.js").write_text("var x=1;")
        (www / "b.js").write_text("var y=2;")
        (www / "big.js").write_bytes(b"x" * (2 * 1024 * 1024))
        dest = _P(str(www) + "-dl")
        # _fetch_js is a dumb capped fetcher: downloads what's listed,
        # enforces count + size caps. Extension filtering is the
        # caller's job (the stage selects .js URLs from the pool).
        got = _fetch_js([f"{base}/a.js", f"{base}/big.js", f"{base}/b.js"],
                        dest, max_files=10, max_bytes=1024 * 1024)
        names = sorted(p.name for _, p in got)
        assert len(names) == 2  # big.js over the size cap
        assert names[0].endswith("_a.js.js") and names[1].endswith("_b.js.js")

    def test_fetch_js_never_raises(self, tmp_path):
        from loom.stages import _fetch_js
        # dead host, bad scheme, garbage — all skipped silently
        got = _fetch_js(["http://127.0.0.1:1/x.js", "notaurl",
                         "ftp://x/y.js"],
                        tmp_path / "dl", timeout=2)
        assert got == []


class TestGitleaksParser:
    def test_array_becomes_high_findings(self):
        out = json.dumps([{
            "Description": "Generic API Key", "Match": "api_key = \"X\"",
            "Secret": "Xy9mK2pL5vN8qR4tW7yU1iO3pA6sD9fG2hJ5kL8mN",
            "File": "a.js", "StartLine": 3, "RuleID": "generic-api-key",
        }])
        items = parse_gitleaks(out)
        assert len(items) == 1
        assert items[0].kind == "finding"
        assert items[0].evidence["severity"] == "high"
        assert items[0].evidence["rule"] == "generic-api-key"
        assert items[0].evidence["source"] == "gitleaks"

    def test_empty_and_garbage(self):
        assert parse_gitleaks("[]") == []
        assert parse_gitleaks("not json") == []


class TestJsluiceParsers:
    def test_urls_parser(self):
        out = ('{"url": "https://a.com/v1/x", "method": "", "type": "stringLiteral"}\n'
               '{"url": "/api/u?page=1", "method": "GET", "type": "fetch"}\n'
               'garbage\n')
        items = parse_jsluice_urls(out)
        assert [i.value for i in items] == [
            "https://a.com/v1/x", "/api/u?page=1"]
        assert all(i.kind == "url" for i in items)

    def test_secrets_parser_keeps_tool_severity(self):
        out = ('{"kind": "AWSAccessKey", "data": {"key": "AKIAIO...MPLE"}, '
               '"filename": "a.js", "severity": "low"}\n'
               '{"kind": "PrivateKey", "data": {}}\n')
        items = parse_jsluice_secrets(out)
        assert items[0].evidence["severity"] == "low"
        assert items[0].evidence["vuln"] == "AWSAccessKey"
        assert items[1].evidence["severity"] == "medium"  # default


class TestJsSecretsStage:
    PROBE_JS = ('var u="https://api.example.com/v1/x";\n'
                'var k="AKIA4Q7X9M2P5R8T1W6";\n'
                'fetch("/api/users?page=1");\n')

    def test_end_to_end_over_local_server(self, tmp_path, monkeypatch,
                                          file_server):
        """Full chain over localhost: download → gitleaks + jsluice →
        findings + pool sharing. jsluice is real; gitleaks is faked
        (needs realistic secret shapes, verified live separately)."""
        import asyncio
        import shutil
        from loom.stages import make_jssecrets_stage
        base, www = file_server
        (www / "probe.js").write_text(self.PROBE_JS)
        real_jsluice = shutil.which("jsluice") or str(
            Path.home() / "go/bin/jsluice")
        monkeypatch.setenv("LOOM_TOOL_JSLUICE", real_jsluice)
        _pin_fake(tmp_path, monkeypatch, "gitleaks",
                  'printf \'[{"Description": "d", "Match": "m", '
                  '"Secret": "AKIA4Q7X9M2P5R8T1W6", "File": "probe.js", '
                  '"StartLine": 2, "RuleID": "aws-access-token"}]\'')
        ctx = _ctx()
        ctx.extras["urls"] = [f"{base}/probe.js", f"{base}/index.html"]
        runner = Runner(_scope(), workdir=tmp_path)
        items = asyncio.run(make_jssecrets_stage(max_js=5)(
            runner, "example.com", ctx))
        kinds = {i.kind for i in items}
        assert "finding" in kinds  # gitleaks hit
        # jsluice absolute URL shared into pool...
        assert "https://api.example.com/v1/x" in ctx.extras["urls"]
        # ...parameterized relative URL resolved + fed to urls_params
        assert f"{base}/api/users?page=1" in ctx.extras["urls_params"]
        # raw pool keeps the .js file itself
        assert f"{base}/probe.js" in ctx.extras["urls"]


class TestResolveJsUrl:
    def test_shapes(self):
        from loom.stages import _resolve_js_url
        base = "https://a.com/static/app.js"
        assert _resolve_js_url("https://b.com/x", base) == "https://b.com/x"
        assert _resolve_js_url("/api/u?page=1", base) == "https://a.com/api/u?page=1"
        assert _resolve_js_url("rel/path.js", base) == "https://a.com/static/rel/path.js"
        assert _resolve_js_url("data:text/plain,x", base) is None
        assert _resolve_js_url("javascript:void(0)", base) is None
        assert _resolve_js_url("", base) is None


class TestAsnmap:
    def test_skips_cleanly_without_key(self, tmp_path, monkeypatch):
        """No PDCP key anywhere → no invocation, no failure, []."""
        import asyncio
        from loom.stages import make_asnmap_stage
        home = tmp_path / "emptyhome"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.delenv("PDCP_API_KEY", raising=False)
        monkeypatch.setattr(Path, "home", lambda: home)
        ctx = _ctx()
        runner = Runner(_scope(), workdir=tmp_path)
        assert asyncio.run(make_asnmap_stage()(
            runner, "example.com", ctx)) == []
        assert list(tmp_path.rglob("asnmap.*.cmd.txt")) == []

    def test_parser_extracts_cidrs_leniently(self):
        out = ('{"input": "example.com", "asn": "AS15169", '
               '"prefixes": ["8.8.8.0/24", "2001:4860::/32"]}\n'
               'not-json\n')
        items = parse_asnmap(out)
        cidrs = [i.value for i in items if i.kind == "cidr"]
        assert "8.8.8.0/24" in cidrs
        assert any(i.kind == "asn" and "AS15169" in i.value for i in items)

    def test_parser_never_raises(self):
        assert parse_asnmap("") == []
        assert parse_asnmap("{{{") == []


class TestTier2Wiring:
    def test_expected_tools_lists_new_binaries(self):
        from loom.cli import EXPECTED_TOOLS
        for tool in ("arjun", "gitleaks", "jsluice", "asnmap"):
            assert tool in EXPECTED_TOOLS, tool

    def test_deep_has_new_nodes(self):
        from pathlib import Path as _P
        from loom import cli
        from loom.live import LiveLogger
        dag, stages = cli._build_pipeline(
            "deep", LiveLogger(_P("/tmp")), None, None)
        dag.validate()
        for node in ("params", "jssecrets", "asn"):
            assert node in stages, node
            assert node in dag.ids(), node
        assert set(stages) == set(dag.ids())

    def test_user_bin_dir_in_fallbacks(self):
        from loom import tools
        from pathlib import Path as _P
        assert _P.home() / ".local" / "bin" in tools.GO_BIN_DIRS
