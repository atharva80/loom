"""Timeouts must kill the whole process tree, not just the direct child.

Live 2026-09-05: dalfox (600s timeout) escaped as a traceback-carrying
stage failure, and tools like dalfox spawn surviving grandchildren
(headless chrome). `proc.kill()` alone orphans them — they eat RAM/CPU
through the rest of an overnight sweep. The Runner must SIGKILL the
process group (start_new_session + killpg).
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from loom.runner import Runner
from loom.scope import from_dict as scope_from_dict

pytestmark = pytest.mark.skipif(
    shutil.which("pgrep") is None, reason="needs pgrep")

# Distinctive sleep durations so pgrep can't match unrelated processes.
KID_SLEEP = "47"
STREAM_SLEEP = "48"


def _scope():
    return scope_from_dict({"name": "t", "target": "example.com",
                            "rate_limit_rps": 1000})


def _tree_alive(marker: str) -> bool:
    out = subprocess.run(["pgrep", "-f", f"sleep {marker}"],
                         capture_output=True, text=True)
    return out.returncode == 0


class TestStreamingTimeout:
    async def test_streaming_timeout_returns_not_raises(self):
        """Old run_streaming raised TimeoutExpired out of the stage
        (live: dalfox xss node → failed + traceback + no outputs).
        Now it must return a timed-out RunResult like run() does."""
        runner = Runner(_scope())
        res = await runner.run_streaming(
            "sh", ["sh", "-c", "sleep 10"],
            stage="t", host="example.com", parser="raw", timeout=0.5)
        assert res.timed_out
        assert res.exit_code == -9  # SIGKILLed, not natural exit
        assert res.error and "timeout" in res.error.lower()
        assert res.duration_s < 5.0, \
            f"timeout handling took {res.duration_s:.1f}s (inherited fds held pipes?)"

    async def test_streaming_timeout_kills_tree(self):
        runner = Runner(_scope())
        assert not _tree_alive(STREAM_SLEEP)
        res = await runner.run_streaming(
            "sh", ["sh", "-c", f"sleep {STREAM_SLEEP} & wait"],
            stage="t", host="example.com", parser="raw", timeout=1.0)
        assert res.timed_out
        assert res.duration_s < 6.0, \
            f"timeout took {res.duration_s:.1f}s — grandchildren held the pipes"
        assert not _tree_alive(STREAM_SLEEP), \
            "grandchild survived the timeout — process group not killed"


class TestRunTimeout:
    async def test_run_timeout_kills_tree(self):
        runner = Runner(_scope())
        assert not _tree_alive(KID_SLEEP)
        res = await runner.run(
            "sh", ["sh", "-c", f"sleep {KID_SLEEP} & wait"],
            stage="t", host="example.com", parser="raw", timeout=1.0)
        assert res.timed_out
        assert res.duration_s < 6.0, \
            f"timeout took {res.duration_s:.1f}s — grandchildren held the pipes"
        assert not _tree_alive(KID_SLEEP), \
            "grandchild survived the timeout — process group not killed"
