"""Tool binary resolution for loom.

Real bug found live (2026-08-29): the Hermes desktop venv ships a
Python package named `httpx` whose console script shadows ProjectDiscovery's
`httpx` when the venv bin dir precedes ~/go/bin on PATH. Every loom httpx
probe silently invoked the Python CLI (which takes different flags) and
returned 0 items / exit != 0.

Fix: resolve tool binaries with an explicit preference order instead of
blind `shutil.which`:

  1. env var override  LOOM_TOOL_<TOOL>  (uppercased, e.g. LOOM_TOOL_HTTPX)
  2. known Go bin dirs ( ~/go/bin, GOPATH/bin, GOBIN, /usr/local/go/bin )
     — ProjectDiscovery + friends install here
  3. PATH (last resort, but validate the binary first for known shadowers)

For tools with a known-shadower problem (httpx), validate the resolved
binary by inspecting `-version` output for a distinguishing marker
(projectdiscovery). If the PATH candidate fails validation and a Go-bin
candidate exists, prefer the Go-bin one.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

# Tools that have a known shadowing problem (a different tool/CLI that
# happens to install a same-named binary earlier on PATH). Each maps to
# a marker string that MUST appear in the real tool's `-version` output.
KNOWN_SHADOWERS: dict[str, str] = {
    "httpx": "projectdiscovery",  # vs python -m httpx "Usage: httpx [OPTIONS] URL"
}

# Fallback dirs checked before PATH (preference order).
GO_BIN_DIRS: tuple[Path, ...] = tuple(
    dict.fromkeys(
        Path(p)
        for p in (
            os.environ.get("GOBIN", ""),
            os.path.join(os.environ.get("GOPATH", str(Path.home() / "go")), "bin"),
            str(Path.home() / "go" / "bin"),
            "/usr/local/go/bin",
            "/usr/local/bin",
        )
        if p
    )
)

_validate_cache: dict[str, Optional[str]] = {}


def _version_output(bin_path: str) -> str:
    """Best-effort `-version` output for a binary (never raises)."""
    try:
        r = subprocess.run(
            [bin_path, "-version"],
            capture_output=True, text=True, timeout=8,
        )
        return (r.stdout or "") + (r.stderr or "")
    except Exception:
        return ""


def _looks_real(bin_path: str, tool: str) -> bool:
    """For known shadowers, verify the binary is the real tool."""
    marker = KNOWN_SHADOWERS.get(tool)
    if marker is None:
        return True
    out = _version_output(bin_path)
    return marker.lower() in out.lower()


def resolve_tool(tool: str) -> Optional[str]:
    """Resolve the real binary for `tool`, or None if not found.

    For KNOWN_SHADOWERS (httpx etc.): prefer LOOM_TOOL_<TOOL> env
    override → known Go bin dirs → PATH, validating `-version` so a
    shadowing console script never wins over the real binary.

    For all other tools: plain PATH lookup (shutil.which) — this keeps
    user-controlled PATH precedence intact (tests rely on it) while
    fixing the one real shadowing hazard. Result cached per tool.
    """
    tool_up = tool.upper()
    env_override = os.environ.get(f"LOOM_TOOL_{tool_up}")

    # Env override invalidates any cached result (tests and users pin
    # a specific binary with LOOM_TOOL_<NAME>).
    if env_override:
        cached = _validate_cache.get(f"{tool}|{env_override}")
        if cached is not None:
            return cached or None
    else:
        cached = _validate_cache.get(tool)
        if cached is not None:
            return cached or None

    if tool not in KNOWN_SHADOWERS:
        # Env override applies to every tool, not just shadowers —
        # tests and users pin fakes/alternates with LOOM_TOOL_<NAME>.
        if env_override:
            key = f"{tool}|{env_override}"
            _validate_cache[key] = env_override
            return env_override
        # PATH precedence stays intact for non-shadowers (tests rely on
        # it) — but a which() MISS must fall back to the known Go bin
        # dirs. Bug found live 2026-09-04: tools installed in ~/go/bin
        # but absent from PATH resolved to None.
        which = shutil.which(tool)
        if which:
            _validate_cache[tool] = which
            return which
        for d in GO_BIN_DIRS:
            p = d / tool
            if p.is_file() and os.access(p, os.X_OK):
                _validate_cache[tool] = str(p)
                return str(p)
        _validate_cache[tool] = ""
        return None

    candidates: list[str] = []

    # 1. env override
    if env_override:
        candidates.append(env_override)

    # 2. Go bin dirs (before PATH so real PD binaries win over
    #    shadowing Python/Node console scripts)
    for d in GO_BIN_DIRS:
        p = d / tool
        if p.is_file() and os.access(p, os.X_OK):
            candidates.append(str(p))

    # 3. PATH
    which = shutil.which(tool)
    if which:
        candidates.append(which)

    # De-dupe preserving order
    seen: set[str] = set()
    ordered: list[str] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            ordered.append(c)

    # Prefer the first candidate that looks real (for shadowers).
    key = f"{tool}|{env_override}" if env_override else tool
    for c in ordered:
        if _looks_real(c, tool):
            _validate_cache[key] = c
            return c

    # Nothing validated: fall back to the first candidate anyway
    # (better than nothing; e.g. a shadowed httpx still gets called,
    # but the user sees a validate warning).
    if ordered:
        _validate_cache[key] = ordered[0]
        return ordered[0]

    _validate_cache[key] = ""
    return None


def resolve_tools(tools: list[str]) -> dict[str, Optional[str]]:
    """Resolve many tools at once. Returns {tool: path or None}."""
    return {t: resolve_tool(t) for t in tools}


def validate_report() -> list[tuple[str, str, Optional[str], str]]:
    """Return (tool, status, resolved_path, note) for loom's `validate`.

    status: "ok" | "missing" | "shadowed"
    """
    from .cli import EXPECTED_TOOLS  # avoid import cycle

    report: list[tuple[str, str, Optional[str], str]] = []
    for tool in EXPECTED_TOOLS:
        path = resolve_tool(tool)
        if path is None:
            report.append((tool, "missing", None, ""))
            continue
        which_path = shutil.which(tool)
        note = ""
        if tool in KNOWN_SHADOWERS:
            if which_path and os.path.realpath(which_path) != os.path.realpath(path):
                note = (f"warning: PATH has {which_path} which shadows the real "
                        f"tool; loom uses {path}")
            elif not _looks_real(path, tool):
                note = "warning: resolved binary does not pass -version validation"
        report.append((tool, "ok", path, note))
    return report
