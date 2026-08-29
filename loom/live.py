"""loom.live — Live-run helpers: a streaming logger + a demo pipeline
that exercises the orchestrator end-to-end against a real target.

The logger is the key piece. It writes a single line per event to:

  * stdout  — for tail -f / docker logs / your eyes
  * <workdir>/run.log  — for post-mortem analysis

Every line is timestamped (ISO 8601 + ms), colored if stdout is a TTY,
and includes the event type + a small structured payload.

Usage from any stage:

    from loom.live import LiveLogger
    log = LiveLogger(workdir)
    log.stage_start("probe", host="example.com")
    log.tool_call("httpx", host="example.com", cmd=[...])
    log.tool_done("httpx", host="example.com", items=17, duration_s=0.9)
    log.stage_end("probe", host="example.com", status="done", items=17)
    log.warn("catchall detected — skipping nuclei", host="example.com")
"""
from __future__ import annotations

import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, TextIO


# ANSI color codes (off when stdout isn't a TTY).
_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
if _USE_COLOR:
    _C_RESET = "\033[0m"
    _C_DIM = "\033[2m"
    _C_RED = "\033[31m"
    _C_GREEN = "\033[32m"
    _C_YELLOW = "\033[33m"
    _C_BLUE = "\033[34m"
    _C_MAGENTA = "\033[35m"
    _C_CYAN = "\033[36m"
    _C_BOLD = "\033[1m"
else:
    _C_RESET = _C_DIM = _C_RED = _C_GREEN = _C_YELLOW = ""
    _C_BLUE = _C_MAGENTA = _C_CYAN = _C_BOLD = ""


def _now_iso() -> str:
    """ISO 8601 timestamp with millisecond precision, UTC."""
    dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{dt.microsecond // 1000:03d}Z"


def _colorize(text: str, color: str) -> str:
    if not _USE_COLOR:
        return text
    return f"{color}{text}{_C_RESET}"


class LiveLogger:
    """Thread-safe, line-buffered, dual-sink (stdout + file) logger.

    One instance per run. Construct once at the top of the run; pass it
    through `ctx.extras["log"]` to every stage.
    """
    def __init__(self, workdir: Path, *, run_id: Optional[int] = None,
                 also_stdout: bool = True):
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.workdir / "run.log"
        self.run_id = run_id
        self._lock = threading.Lock()
        self._fh = open(self.log_path, "a", encoding="utf-8")
        self._stdout = sys.stdout if also_stdout else None
        self._t0 = time.monotonic()

    def close(self) -> None:
        with self._lock:
            self._fh.close()

    def _emit(self, level: str, color: str, msg: str,
              fields: Optional[dict[str, Any]] = None) -> None:
        ts = _now_iso()
        elapsed = time.monotonic() - self._t0
        payload = " ".join(f"{k}={v}" for k, v in (fields or {}).items())
        line = (
            f"{_colorize(ts, _C_DIM)} "
            f"{_colorize(level, color)} "
            f"{msg}"
        )
        if payload:
            line += f" {_colorize(payload, _C_DIM)}"
        with self._lock:
            if self._stdout is not None:
                self._stdout.write(line + "\n")
                self._stdout.flush()
            self._fh.write(line + "\n")
            self._fh.flush()

    # ---- public API ----
    def info(self, msg: str, **fields: Any) -> None:
        self._emit("INFO", _C_BLUE, msg, fields)

    def warn(self, msg: str, **fields: Any) -> None:
        self._emit("WARN", _C_YELLOW, msg, fields)

    def error(self, msg: str, **fields: Any) -> None:
        self._emit("ERROR", _C_RED, msg, fields)

    def stage_start(self, stage: str, *, host: str = "", **fields: Any) -> None:
        self._emit("STAGE", _C_MAGENTA, f"▶ {stage}",
                   {"host": host, "run_id": self.run_id, **fields})

    def stage_end(self, stage: str, *, host: str = "", status: str,
                  items: int = 0, duration_s: float = 0.0,
                  **fields: Any) -> None:
        col = _C_GREEN if status == "done" else (
            _C_YELLOW if status == "skipped" else _C_RED
        )
        self._emit("STAGE", col, f"■ {stage} → {status}",
                   {"host": host, "items": items,
                    "duration_s": round(duration_s, 3), **fields})

    def tool_call(self, tool: str, *, host: str = "", cmd: list[str],
                  **fields: Any) -> None:
        cmd_str = " ".join(cmd)
        if len(cmd_str) > 200:
            cmd_str = cmd_str[:197] + "..."
        self._emit("TOOL", _C_CYAN, f"  ⤷ {tool}",
                   {"host": host, "cmd": cmd_str, **fields})

    def tool_done(self, tool: str, *, host: str = "", items: int = 0,
                  duration_s: float = 0.0, **fields: Any) -> None:
        self._emit("TOOL", _C_GREEN, f"  ✓ {tool}",
                   {"host": host, "items": items,
                    "duration_s": round(duration_s, 3), **fields})

    def finding(self, kind: str, value: str, *, host: str = "",
                source: str = "", **fields: Any) -> None:
        self._emit("FIND", _C_GREEN, f"  ★ {kind}: {value}",
                   {"host": host, "source": source, **fields})

    def progress(self, current: int, total: int, *, label: str = "",
                 **fields: Any) -> None:
        pct = 100 * current / total if total else 0
        bar_w = 20
        filled = int(bar_w * current / total) if total else 0
        bar = "█" * filled + "░" * (bar_w - filled)
        msg = f"[{bar}] {current}/{total} ({pct:.0f}%) {label}".strip()
        self._emit("PROG", _C_CYAN, msg, fields)
