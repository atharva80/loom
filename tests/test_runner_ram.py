"""Tests for Runner RAM-budget enforcement (loom.rambudget wired in)."""

from __future__ import annotations

from pathlib import Path

import pytest

from loom.rambudget import RamBudget
from loom.runner import Runner
from loom.scope import from_dict as scope_from_dict


def _scope():
    return scope_from_dict({"name": "t", "target": "example.com",
                            "rate_limit_rps": 1000})


def _make_fake(tmp_path: Path, name: str) -> Path:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    p = bindir / name
    p.write_text("#!/bin/sh\nif [ \"$1\" = \"-version\" ]; then echo 'projectdiscovery/x v1'; exit 0; fi\necho ok\n")
    p.chmod(0o755)
    return p


class TestRunnerRamBudget:
    def test_acquires_and_releases(self, tmp_path, monkeypatch):
        fake = _make_fake(tmp_path, "mytool")
        monkeypatch.setenv("LOOM_TOOL_MYTOOL", str(fake))
        budget = RamBudget(max_bytes=1024**3)  # 1GB
        runner = Runner(_scope(), ram_budget=budget)
        runner.run("mytool", ["mytool"], stage="manual", parser="raw")
        # after the run, the reservation is released
        assert budget.used_bytes == 0

    def test_releases_on_error(self, tmp_path, monkeypatch):
        """Even when the tool fails (nonzero exit), RAM is released."""
        bindir = tmp_path / "bin"
        bindir.mkdir()
        fake = bindir / "mytool"
        fake.write_text("#!/bin/sh\necho boom\nexit 3\n")
        fake.chmod(0o755)
        monkeypatch.setenv("LOOM_TOOL_MYTOOL", str(fake))
        budget = RamBudget(max_bytes=1024**3)
        runner = Runner(_scope(), ram_budget=budget)
        res = runner.run("mytool", ["mytool"], stage="manual", parser="raw")
        assert res.exit_code == 3
        assert budget.used_bytes == 0

    def test_budget_cap_blocks(self, tmp_path, monkeypatch):
        """With a tiny budget, a concurrent invocation of a heavy tool
        is blocked."""
        fake = _make_fake(tmp_path, "katana")
        monkeypatch.setenv("LOOM_TOOL_KATANA", str(fake))
        # katana is ~200MB; a 350MB budget fits one instance but not two
        budget = RamBudget(max_bytes=350 * 1024**2)
        runner = Runner(_scope(), ram_budget=budget)
        # hold one katana's reservation manually (simulating a running
        # instance) then try to start another via the Runner
        budget.acquire("katana")
        with pytest.raises(RuntimeError, match="RAM budget exceeded"):
            runner.run("katana", ["katana"], stage="manual", parser="raw",
                       check=False)
        # release the held reservation → can start again
        budget.release("katana")
        runner.run("katana", ["katana"], stage="manual", parser="raw",
                   check=False)
