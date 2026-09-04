"""Tests for loom.runner error classification (F24).

Found live: a dnsx run failed with `flag provided but not defined: -H`
(exit 2, non-zero) but the recorded error was EMPTY — because error was
only assigned as a side-effect at mark() from stderr[-500:], and when
stderr is empty (or the failure is a signal/timeout) the reason was lost.

F24: _classify_error() produces a structured, non-empty error string for:
  - non-zero exit code (with stderr tail)
  - killed by signal (negative returncode)
  - timeout (timed_out=True)
  - binary not found (FileNotFoundError)
"""

import os
import signal
import time
from pathlib import Path

import pytest

from loom.runner import Runner, _classify_error
from loom.scope import bundled


@pytest.fixture
def runner(tmp_path):
    return Runner(scope=bundled("default", target="example.com"),
                  workdir=tmp_path)


def _fake(name, content, chmod=0o755):
    p = Path(name)
    p.write_text(content)
    os.chmod(p, chmod)
    return str(p)


# ---------- _classify_error unit tests ----------

async def test_classify_nonzero_exit_with_stderr():
    err = _classify_error(exit_code=2, stderr="flag provided but not defined: -H\n")
    assert err == "exit code 2: flag provided but not defined: -H"


async def test_classify_nonzero_exit_no_stderr():
    """The dnsx case: exit 2 but empty stderr must NOT produce empty error."""
    err = _classify_error(exit_code=2, stderr="")
    assert err is not None
    assert "exit code 2" in err
    assert "(no stderr output)" in err


async def test_classify_signal_kill():
    err = _classify_error(exit_code=-9, stderr="")
    assert "killed by" in err
    assert "signal" in err or "SIG" in err
    assert "9" in err or "SIGKILL" in err


async def test_classify_timeout():
    err = _classify_error(exit_code=-1, stderr="", timed_out=True)
    assert "timeout" in err


async def test_classify_success_is_none():
    err = _classify_error(exit_code=0, stderr="")
    assert err is None


async def test_classify_stderr_truncated():
    err = _classify_error(exit_code=1, stderr="x" * 2000)
    assert len(err) < 600  # truncated to ~500 chars + prefix


# ---------- integration: Runner.run records the classified error ----------

async def test_run_records_error_on_nonzero_exit(runner, tmp_path):
    """RunResult.error must carry the classified reason, not be empty."""
    fake = _fake(tmp_path / "failer", "#!/bin/sh\necho 'boom: bad flag' >&2\nexit 3\n")
    res = await runner.run("failer", [fake], stage="t", host="h", parser="raw")
    assert res.exit_code == 3
    assert res.error is not None
    assert "exit code 3" in res.error
    assert "boom: bad flag" in res.error


async def test_run_records_signal_kill(runner, tmp_path):
    """A tool killed by SIGKILL reports the signal info."""
    fake = _fake(tmp_path / "sigkiller",
                 "#!/bin/sh\nkill -9 $$\n", chmod=0o755)
    res = await runner.run("sigkiller", [fake], stage="t", host="h", parser="raw")
    assert res.exit_code < 0
    assert res.error is not None
    assert "killed" in res.error.lower()


async def test_run_records_timeout(runner, tmp_path):
    """A timed-out tool reports 'timeout' in the error."""
    fake = _fake(tmp_path / "sleeper", "#!/bin/sh\nsleep 30\n")
    res = await runner.run("sleeper", [fake], stage="t", host="h",
                     parser="raw", timeout=1)
    assert res.timed_out is True
    assert res.error is not None
    assert "timeout" in res.error.lower()
