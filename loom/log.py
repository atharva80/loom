"""loom.log — Live logger for in-progress runs.

The logger is a thin wrapper over Python's `logging` module. It writes
two streams:

  1. A per-run log file at <workdir>/<run_dir>/run.log (rotates never;
     v1 is small enough that we just append).
  2. Optional stderr output, controlled by LOOM_VERBOSE=1.

Every line has the form:
  <ISO timestamp> <LEVEL> <stage>/<host>/<tool> <message>

Use `setup_run_logger(workdir, run_id)` to get a logger and a file
handler. Pass the same logger into `Runner` and `Pipeline` (constructor
param) so they can emit per-tool progress.

Example:
    log, log_path = setup_run_logger(workdir, run_id)
    runner = Runner(scope, log=log, ...)
    log.info("catchall/example.com start")
    log.info("catchall/example.com done kind=clean conf=0.95 dur=1.36s")
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


_RUN_LOGGER_NAME = "loom.run"


def setup_run_logger(
    workdir: Path,
    run_id: int,
    *,
    also_stderr: Optional[bool] = None,
) -> tuple[logging.Logger, Path]:
    """Create or fetch the run logger. Idempotent: calling twice with
    the same (workdir, run_id) returns the same logger and the same
    log file path (avoids double-handler-attachment).

    `also_stderr` defaults to LOOM_VERBOSE=1 or stderr-attached TTY.
    """
    run_dir = Path(workdir) / f"run-{run_id}"
    run_dir.mkdir(parents=True, exist_ok=True)
    log_path = run_dir / "run.log"

    logger = logging.getLogger(f"{_RUN_LOGGER_NAME}.{run_id}")
    logger.setLevel(logging.INFO)
    logger.propagate = False  # don't double-emit via root

    if not logger.handlers:
        fmt = logging.Formatter(
            fmt="%(asctime)s.%(msecs)03d %(levelname)-5s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        fmt.converter = _utc_converter

        fh = logging.FileHandler(log_path, mode="a", encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)

        if also_stderr is None:
            also_stderr = bool(os.environ.get("LOOM_VERBOSE")) or sys.stderr.isatty()
        if also_stderr:
            sh = logging.StreamHandler(sys.stderr)
            sh.setFormatter(fmt)
            logger.addHandler(sh)

    return logger, log_path


def _utc_converter(timestamp):
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).timetuple()


def stage_event(log: Optional[logging.Logger], stage: str, host: str,
                tool: str, message: str, level: int = logging.INFO) -> None:
    """Emit a structured log line for a stage event. Silently no-op if
    no logger was provided (so test code can pass log=None)."""
    if log is None:
        return
    prefix = f"{stage}/{host or '_'}/{tool}"
    log.log(level, f"{prefix} {message}")


def tool_start(log: Optional[logging.Logger], stage: str, host: str,
               tool: str, cmd: list[str]) -> None:
    if log is None:
        return
    stage_event(log, stage, host, tool,
                f"start cmd={' '.join(repr(c) for c in cmd)[:200]}")


def tool_done(log: Optional[logging.Logger], stage: str, host: str,
              tool: str, *, exit_code: int, duration_s: float,
              items: int, timed_out: bool, status: str) -> None:
    if log is None:
        return
    msg = (f"done status={status} exit={exit_code} dur={duration_s:.2f}s "
           f"items={items} timed_out={timed_out}")
    stage_event(log, stage, host, tool, msg)


def tool_failed(log: Optional[logging.Logger], stage: str, host: str,
                tool: str, error: str) -> None:
    if log is None:
        return
    stage_event(log, stage, host, tool, f"failed err={error[:200]}",
                level=logging.WARNING)
