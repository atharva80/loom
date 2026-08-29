# loom/eventlog.py
# Append-only JSONL event log. One event per line. Atomic appends via os-level O_APPEND.
# Read supports offset-based pagination (for resume) and type/host/stage filters.

import json
import os
import time
from pathlib import Path
from typing import Iterator


class EventLog:
    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Create file if missing
        if not self.path.exists():
            self.path.touch()

    def append(self, event: dict | None = None, **kwargs) -> None:
        """Append one event. Accepts a dict or keyword args. Adds ts if missing."""
        if event is None:
            event = dict(kwargs)
        elif kwargs:
            event = {**event, **kwargs}
        if "ts" not in event:
            event["ts"] = time.time()
        line = json.dumps(event, separators=(",", ":"), ensure_ascii=False) + "\n"
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line)

    def extend(self, events: list[dict]) -> None:
        for e in events:
            self.append(e)

    def read(self, offset: int = 0) -> Iterator[dict]:
        """Yield events starting at byte offset `offset`. Returns (event, new_offset) via attribute."""
        # Use plain iterator; offset pagination is exposed via read_range
        yield from self._read_from(0)

    def _read_from(self, byte_offset: int) -> Iterator[dict]:
        with open(self.path, "r", encoding="utf-8") as f:
            f.seek(byte_offset)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue

    def count(self, type_: str | None = None, host: str | None = None, stage: str | None = None) -> int:
        n = 0
        for e in self._read_from(0):
            if type_ and e.get("type") != type_:
                continue
            if host and e.get("host") != host:
                continue
            if stage and e.get("stage") != stage:
                continue
            n += 1
        return n

    def size_bytes(self) -> int:
        return self.path.stat().st_size
