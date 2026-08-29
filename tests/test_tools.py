"""Tests for loom.tools — binary resolution + shadower detection.

Critical regression (found live 2026-08-29): the Hermes desktop venv
ships a Python package `httpx` whose console script shadows
ProjectDiscovery's httpx when the venv bin dir precedes ~/go/bin on
PATH. resolve_tool must prefer the real tool.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from loom import tools
from loom.runner import Runner, ToolBlocked
from loom.scope import from_dict as scope_from_dict


@pytest.fixture
def fake_bins(tmp_path):
    """Create a fake Go bin dir + a fake shadowing dir.

    Returns (go_dir, shadow_dir, make) where make(name, output, dir_)
    writes an executable shell script that echoes `output` and exits 0.
    """
    go_dir = tmp_path / "go_bin"
    shadow_dir = tmp_path / "shadow"
    go_dir.mkdir()
    shadow_dir.mkdir()

    def make(name: str, output: str, dir_: Path) -> Path:
        p = dir_ / name
        # one echo per line so multi-line outputs really are multi-line
        lines = output.split("\n")
        body = "\n".join(f"echo '{l}'" for l in lines)
        p.write_text(f"#!/bin/sh\n{body}\nexit 0\n")
        p.chmod(0o755)
        return p

    return go_dir, shadow_dir, make


class TestResolveTool:
    def test_prefers_go_bin_over_shadowing_path(self, fake_bins, monkeypatch):
        go_dir, shadow_dir, make = fake_bins
        make("mytool", "projectdiscovery/mytool v1.0", go_dir)
        make("mytool", "Usage: mytool [OPTIONS] URL", shadow_dir)
        monkeypatch.setenv("PATH", f"{shadow_dir}{os.pathsep}{go_dir}")
        monkeypatch.delenv("GOPATH", raising=False)
        monkeypatch.delenv("GOBIN", raising=False)
        monkeypatch.setattr(tools, "GO_BIN_DIRS", (go_dir,))
        monkeypatch.setitem(tools.KNOWN_SHADOWERS, "mytool", "projectdiscovery")
        tools._validate_cache.clear()
        resolved = tools.resolve_tool("mytool")
        assert resolved is not None
        # Must NOT be the shadow (python mytool) — it's on PATH but
        # validation rejects it; the Go bin one passes and wins.
        assert "shadow" not in resolved
        assert str(go_dir / "mytool") in resolved

    def test_env_override_wins(self, fake_bins, monkeypatch):
        """Env override is the first candidate for known shadowers,
        and it wins when it passes validation."""
        go_dir, shadow_dir, make = fake_bins
        make("httpx", "projectdiscovery/httpx v1.6.0", go_dir)
        make("httpx", "projectdiscovery/httpx v9.9.9", shadow_dir)
        # Override points at the shadow dir — but since it passes the
        # -version marker validation, it's accepted as the tool.
        monkeypatch.setenv("LOOM_TOOL_HTTPX", str(shadow_dir / "httpx"))
        monkeypatch.setenv("PATH", str(go_dir))
        tools._validate_cache.clear()
        resolved = tools.resolve_tool("httpx")
        assert resolved == str(shadow_dir / "httpx")

    def test_shadow_only_path_still_resolves(self, fake_bins, monkeypatch, tmp_path):
        """If ONLY the shadow exists, resolve_tool falls back to it
        (better than nothing) but validate_report flags it."""
        go_dir, shadow_dir, make = fake_bins
        make("httpx", "Usage: httpx [OPTIONS] URL", shadow_dir)
        monkeypatch.setenv("PATH", str(shadow_dir))
        monkeypatch.delenv("GOPATH", raising=False)
        monkeypatch.delenv("GOBIN", raising=False)
        # Point GO_BIN_DIRS away (no real one)
        monkeypatch.setattr(tools, "GO_BIN_DIRS", (tmp_path / "nope",))
        tools._validate_cache.clear()
        resolved = tools.resolve_tool("httpx")
        assert resolved == str(shadow_dir / "httpx")

    def test_validate_report_flags_shadowed(self, fake_bins, monkeypatch):
        go_dir, shadow_dir, make = fake_bins
        make("httpx", "projectdiscovery/httpx v1.6.0", go_dir)
        make("httpx", "Usage: httpx [OPTIONS] URL", shadow_dir)
        monkeypatch.setenv("PATH", f"{shadow_dir}{os.pathsep}{os.environ.get('PATH','')}")
        monkeypatch.setenv("GOPATH", str(go_dir.parent))
        tools._validate_cache.clear()
        report = dict((t, (status, path, note)) for t, status, path, note
                      in tools.validate_report())
        status, path, note = report["httpx"]
        assert status == "ok"
        assert "shadow" not in str(path)  # resolved to the real one
        assert "shadow" in note.lower() or "warning" in note.lower()

    def test_unknown_tool_returns_none(self, monkeypatch):
        tools._validate_cache.clear()
        monkeypatch.delenv("LOOM_TOOL_NOTAREALTOOL", raising=False)
        assert tools.resolve_tool("definitely-not-a-real-tool-xyz") is None


class TestRunnerUsesResolvedBinary:
    def test_runner_rewrites_cmd0_to_resolved_path(self, fake_bins, monkeypatch):
        """The Runner must invoke the resolved binary, not the PATH
        shadow."""
        go_dir, shadow_dir, make = fake_bins
        # Use a tool name that does NOT exist on the real system
        # so the test is deterministic.
        make("mytool", "result=ok", go_dir)
        make("mytool", "SHADOWED", shadow_dir)
        monkeypatch.setenv("PATH", f"{shadow_dir}{os.pathsep}{go_dir}")
        monkeypatch.setenv("GOPATH", str(go_dir.parent))
        monkeypatch.setattr(tools, "GO_BIN_DIRS", (go_dir,))
        # Register mytool as a known shadower so resolution prefers
        # the validated Go-bin binary over the PATH shadow.
        monkeypatch.setitem(tools.KNOWN_SHADOWERS, "mytool", "projectdiscovery")
        tools._validate_cache.clear()

        scope = scope_from_dict({"name": "t", "target": "example.com",
                                 "rate_limit_rps": 1000})
        runner = Runner(scope)
        result = runner.run(
            "mytool", ["mytool", "-silent", "-d", "example.com"],
            stage="subenum", parser="raw",
        )
        assert result.exit_code == 0
        assert "result=ok" in result.stdout_tail
        assert "SHADOWED" not in result.stdout_tail

    def test_streaming_uses_resolved_binary(self, fake_bins, monkeypatch):
        go_dir, shadow_dir, make = fake_bins
        make("mytool", "result=ok\nline2", go_dir)
        make("mytool", "SHADOWED", shadow_dir)
        monkeypatch.setenv("PATH", f"{shadow_dir}{os.pathsep}{go_dir}")
        monkeypatch.setenv("GOPATH", str(go_dir.parent))
        monkeypatch.setattr(tools, "GO_BIN_DIRS", (go_dir,))
        monkeypatch.setitem(tools.KNOWN_SHADOWERS, "mytool", "projectdiscovery")
        tools._validate_cache.clear()

        scope = scope_from_dict({"name": "t", "target": "example.com",
                                 "rate_limit_rps": 1000})
        runner = Runner(scope)
        items = []
        result = runner.run_streaming(
            "mytool", ["mytool", "-silent", "-d", "example.com"],
            stage="resolve", parser="raw",
            on_item=lambda it: items.append(it),
        )
        assert result.exit_code == 0
        # parse_raw returns the whole stdout as one raw item
        assert any("result=ok" in it.value for it in items)
        assert not any("SHADOWED" in it.value for it in items)
