"""Regression test: BrokenPipeError must not propagate when a subprocess
closes stdin early (e.g. dnsx exits before consuming all subdomains).

Found live: twilio.com subenum found 4705 subs → resolve stage failed
with BrokenPipeError because dnsx exited before all stdin was consumed.
"""

import os
import pytest

from loom.runner import Runner
from loom.scope import bundled


def _runner(tmp_path):
    """Build a Runner with a permissive scope (default — allows all)."""
    scope = bundled("default", target="example.com")
    return Runner(scope=scope, workdir=tmp_path)


async def test_broken_pipe_on_stdin_does_not_fail(monkeypatch, tmp_path):
    """A child that closes stdin immediately must not raise BrokenPipeError
    on the parent side."""
    # Create a fake tool that closes stdin immediately and outputs nothing.
    fake = tmp_path / "fast_eof_tool"
    fake.write_text("#!/bin/sh\nexec 0<&-\necho done\n")
    os.chmod(fake, 0o755)

    # Use a stdin payload large enough that the write would block if the
    # child hadn't closed stdin.
    stdin_payload = "a.example.com\n" * 1000

    runner = _runner(tmp_path)
    result = await runner.run(
        "fast_eof", [str(fake)], stage="test", host="x",
        parser="raw", stdin=stdin_payload,
    )
    # No BrokenPipeError raised; command completed.
    assert result.exit_code == 0
    assert result.error is None


async def test_normal_stdin_still_works(monkeypatch, tmp_path):
    """A normal stdin-consuming child must still get the full payload."""
    fake = tmp_path / "echo_tool"
    fake.write_text("#!/bin/sh\ncat\necho done\n")
    os.chmod(fake, 0o755)

    stdin_payload = "a.example.com\nb.example.com\nc.example.com\n"

    runner = _runner(tmp_path)
    result = await runner.run(
        "echo", [str(fake)], stage="test", host="x",
        parser="raw", stdin=stdin_payload,
    )
    assert result.exit_code == 0
    # raw parser produces one item with full stdout
    assert any("a.example.com" in it.value for it in result.items)
    assert any("b.example.com" in it.value for it in result.items)
    assert any("c.example.com" in it.value for it in result.items)
