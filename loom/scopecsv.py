"""CSV scope-list runner for overnight multi-scope operation.

Format: one scope per line, `domain[,pipeline[,max_concurrency]]`,
`#` comments and blank lines ignored. Example:

    # overnight scope list
    vulnweb.com,subdomain,8
    example.org,multiweb,4
    testphp.vulnweb.com,web,2

`loom run --scopes-file scopes.csv` runs each scope's pipeline in
sequence, reusing the same workdir (each scope gets its own run row
in loom.sqlite). A failing scope is logged and skipped — one bad
target never stops the overnight sweep.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ScopeEntry:
    domain: str
    pipeline: str = "subdomain"
    max_concurrency: int = 10


def parse_scopes_csv(path: str | Path) -> list[ScopeEntry]:
    """Parse a scope CSV. Returns [] on empty/comment-only files."""
    entries: list[ScopeEntry] = []
    with open(path, newline="") as f:
        for row in csv.reader(f):
            if not row:
                continue
            cells = [c.strip() for c in row if c.strip()]
            if not cells:
                continue
            first = cells[0]
            if first.startswith("#"):
                continue
            domain = first.strip()
            if not domain:
                continue
            pipeline = cells[1].strip() if len(cells) > 1 and cells[1].strip() else "subdomain"
            try:
                concurrency = int(cells[2]) if len(cells) > 2 and cells[2].strip() else 10
            except ValueError:
                concurrency = 10
            entries.append(ScopeEntry(domain=domain, pipeline=pipeline,
                                      max_concurrency=concurrency))
    return entries
