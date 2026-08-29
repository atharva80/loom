"""loom.live tests.

Verify the LiveLogger:
  * Writes to both stdout (when enabled) and the log file
  * Produces ISO-8601 timestamps with ms precision
  * Includes the right event-type tags and payloads
  * Stage/tool/finding helpers format correctly
  * Progress bar renders the right width
  * Color is suppressed when NO_COLOR is set (covered indirectly:
    we only assert on the content, not the ANSI codes)
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from loom.live import LiveLogger


def test_logger_writes_to_file(tmp_path: Path):
    log = LiveLogger(tmp_path, also_stdout=False)
    log.info("hello", target="x.com")
    log.close()
    content = (tmp_path / "run.log").read_text()
    assert "INFO" in content
    assert "hello" in content
    assert "target=x.com" in content


def test_logger_writes_to_stdout(tmp_path: Path, capsys):
    log = LiveLogger(tmp_path, also_stdout=True)
    log.info("to-stdout", n=1)
    log.close()
    out = capsys.readouterr().out
    assert "to-stdout" in out
    assert "n=1" in out


def test_logger_helpers_format(tmp_path: Path, capsys):
    log = LiveLogger(tmp_path, also_stdout=True, run_id=42)
    log.stage_start("probe", host="x.com")
    log.tool_call("httpx", host="x.com", cmd=["curl", "x.com"])
    log.tool_done("httpx", host="x.com", items=3, duration_s=0.5)
    log.finding("subdomain", "a.x.com", host="x.com", source="subfinder")
    log.stage_end("probe", host="x.com", status="done", items=3, duration_s=0.5)
    log.warn("something off", host="x.com")
    log.error("broke", host="x.com")
    log.close()
    content = (tmp_path / "run.log").read_text()
    assert "STAGE ▶ probe" in content
    assert "TOOL   ⤷ httpx" in content
    assert "TOOL   ✓ httpx" in content
    assert "FIND" in content and "a.x.com" in content
    assert "STAGE ■ probe → done" in content
    assert "WARN" in content
    assert "ERROR" in content
    assert "run_id=42" in content


def test_logger_progress_bar(tmp_path: Path):
    log = LiveLogger(tmp_path, also_stdout=False)
    log.progress(3, 10, label="hosts")
    log.close()
    content = (tmp_path / "run.log").read_text()
    assert "PROG" in content
    assert "3/10" in content
    assert "30%" in content
    assert "hosts" in content
    # The bar should contain the filled and empty chars
    assert "█" in content
    assert "░" in content


def test_logger_timestamp_is_iso8601(tmp_path: Path):
    log = LiveLogger(tmp_path, also_stdout=False)
    log.info("ts-test")
    log.close()
    content = (tmp_path / "run.log").read_text()
    # Format: 2026-08-29T14:15:08.106Z
    import re
    m = re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", content)
    assert m is not None, f"no ISO-8601 ms timestamp in: {content!r}"


def test_logger_thread_safe(tmp_path: Path):
    """Concurrent writes from multiple threads should not tear lines."""
    import threading
    log = LiveLogger(tmp_path, also_stdout=False)

    def worker(n: int):
        for i in range(20):
            log.info(f"thread={n} iter={i}")

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    log.close()
    content = (tmp_path / "run.log").read_text()
    lines = content.splitlines()
    assert len(lines) == 8 * 20
    # Every line should contain a valid "thread=N iter=M"
    import re
    pat = re.compile(r"thread=\d+ iter=\d+")
    assert all(pat.search(l) for l in lines), "torn or missing line"


def test_logger_no_color_when_not_tty(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdout.isatty", lambda: False)
    log = LiveLogger(tmp_path, also_stdout=True)
    log.info("plain")
    log.close()
    out = capsys.readouterr().out
    # No ANSI escape codes
    assert "\033[" not in out


def test_logger_appends(tmp_path: Path):
    log1 = LiveLogger(tmp_path, also_stdout=False)
    log1.info("first")
    log1.close()
    log2 = LiveLogger(tmp_path, also_stdout=False)
    log2.info("second")
    log2.close()
    content = (tmp_path / "run.log").read_text()
    assert "first" in content
    assert "second" in content
    # The order should be preserved
    assert content.index("first") < content.index("second")


def test_logger_creates_workdir(tmp_path: Path):
    # Nested workdir that doesn't exist yet
    wd = tmp_path / "nested" / "deeper"
    log = LiveLogger(wd, also_stdout=False)
    log.info("nested")
    log.close()
    assert (wd / "run.log").exists()
