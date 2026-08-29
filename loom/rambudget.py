"""loom.rambudget — RAM-aware concurrency budget.

Keep total RSS of all running tool subprocesses under a configured cap
(default 20 GB). Each tool has an estimated RSS footprint; the budget
is shared across all running instances.

Usage:
    budget = RamBudget(max_bytes=20 * 1024**3)
    budget.estimate("nuclei", default_mb=104)  # 104 MB per nuclei
    if budget.can_start("nuclei"):
        budget.acquire("nuclei")
        try:
            ... run tool ...
        finally:
            budget.release("nuclei")

The budget is best-effort: estimates come from prior measurement, not
/proc polling. A real implementation would read /proc/<pid>/status or
use psutil; for v0.2 we trust the operator's config.
"""
from __future__ import annotations

import threading
from typing import Optional


# Default RSS estimates (in MB) per concurrent instance of each tool.
# Sourced from earlier measurements (see LOOM_ARCHITECTURE.md).
DEFAULT_RSS_MB = {
    "subfinder": 50,
    "assetfinder": 30,
    "dnsx": 40,
    "httpx": 80,
    "naabu": 100,
    "nuclei": 104,        # 13,619 templates measured at 104MB / worker
    "katana": 200,
    "amass": 400,
    "ffuf": 50,
    "gau": 30,
    "waybackurls": 20,
    "assetfinder": 30,
    "catchall": 10,
}


class RamBudget:
    """Thread-safe + async-safe RAM budget tracker.

    All public methods are coroutine-safe via a single lock. Acquisition
    is *speculative* — the caller must call `can_start()` first to check,
    then `acquire()` to reserve. Release is in a `finally`.
    """
    def __init__(self, max_bytes: int = 20 * 1024**3):
        self.max_bytes = max_bytes
        self._used = 0
        self._lock = threading.Lock()
        # Per-tool instance counts for diagnostics.
        self._instances: dict[str, int] = {}

    @staticmethod
    def estimate(tool: str, default_mb: Optional[int] = None) -> int:
        """Estimated RSS for one instance of `tool`, in bytes."""
        mb = default_mb or DEFAULT_RSS_MB.get(tool, 50)
        return mb * 1024 * 1024

    def can_start(self, tool: str, default_mb: Optional[int] = None) -> bool:
        """True if a new instance of `tool` would fit under the budget."""
        needed = self.estimate(tool, default_mb)
        with self._lock:
            return (self._used + needed) <= self.max_bytes

    def acquire(self, tool: str, default_mb: Optional[int] = None) -> int:
        """Reserve memory for one instance of `tool`. Returns the
        bytes reserved. Raises RuntimeError if the budget is exceeded."""
        needed = self.estimate(tool, default_mb)
        with self._lock:
            if (self._used + needed) > self.max_bytes:
                raise RuntimeError(
                    f"RAM budget exceeded: would use "
                    f"{(self._used + needed) / 1024**3:.2f} GB "
                    f"(cap {self.max_bytes / 1024**3:.2f} GB)"
                )
            self._used += needed
            self._instances[tool] = self._instances.get(tool, 0) + 1
            return needed

    def release(self, tool: str) -> None:
        with self._lock:
            needed = self.estimate(tool)
            self._used = max(0, self._used - needed)
            self._instances[tool] = max(0, self._instances.get(tool, 0) - 1)

    @property
    def used_bytes(self) -> int:
        with self._lock:
            return self._used

    @property
    def remaining_bytes(self) -> int:
        with self._lock:
            return self.max_bytes - self._used

    def snapshot(self) -> dict:
        """Diagnostics: current usage + per-tool instance counts."""
        with self._lock:
            return {
                "used_gb": round(self._used / 1024**3, 2),
                "max_gb": round(self.max_bytes / 1024**3, 2),
                "remaining_gb": round((self.max_bytes - self._used) / 1024**3, 2),
                "instances": dict(self._instances),
            }
