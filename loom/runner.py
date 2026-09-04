"""loom.runner — Tool runner: subprocess wrapper with scope, throttling, and
structured output.

The runner is the abstraction that every recon tool gets wrapped in. The
runner:

  1. Validates the tool is allowed by the active scope (banned_tools).
  2. Injects mandatory headers (User-Agent, X-Bug-Bounty, etc.).
  3. Optionally throttles via a shared RateLimiter (per-program budget).
  4. Runs the subprocess with a hard timeout.
  5. Captures stdout, classifies output by line (URL? subdomain? JSON?),
     and emits EventLog entries.
  6. Reports back a Result dataclass with: command, exit_code, duration,
     output lines, parsed items, error.

Output classification is tool-specific via a registered parser. Built-in
parsers cover the tools loom will use directly (subfinder, httpx, naabu,
nuclei, ffuf, katana, dnsx, amass). For anything else, pass
parser="raw" and the runner returns the entire stdout as one item.

This is the seam where streaming happens: a tool can return early with
a partial result if a parser is registered for it.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import shlex
import signal
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .eventlog import EventLog
from .log import tool_done, tool_failed, tool_start
from .ratelimit import RateLimiter
from .rambudget import RamBudget
from .scope import Scope
from .state import State
from .tools import resolve_tool


# -------- output item types --------

@dataclass
class OutputItem:
    kind: str           # "subdomain" | "url" | "host" | "port" | "finding" | "raw"
    value: str
    evidence: dict = field(default_factory=dict)


def _classify_error(exit_code: int, stderr: str, timed_out: bool = False) -> Optional[str]:
    """Produce a structured, non-empty error string for a failed tool run.

    F24: before this, the error was only assigned as a side-effect at
    mark() from `stderr[-500:]` — so a non-zero exit with EMPTY stderr
    (e.g. dnsx `-H` bug) recorded an empty error and the real reason was
    lost. This returns:
      - None                     for success (exit 0, not timed out)
      - "timeout after Ns"       when timed_out
      - "killed by signal N"     when exit_code < 0 (negative returncode)
      - "exit code N: <stderr>"  otherwise, with a truncation guard
    """
    if timed_out:
        return "timeout (process killed)"
    if exit_code == 0:
        return None
    if exit_code < 0:
        try:
            signame = signal.Signals(-exit_code).name
        except (ValueError, AttributeError):
            signame = f"signal {-exit_code}"
        return f"killed by {signame} (exit code {exit_code})"
    tail = stderr.strip()[-500:] if stderr.strip() else "(no stderr output)"
    return f"exit code {exit_code}: {tail}"


def _kill_tree(proc: "asyncio.subprocess.Process") -> None:
    """SIGKILL a timed-out tool AND its children.

    Live 2026-09-05: dalfox spawns headless-chrome grandchildren that
    inherit the stdout/stderr pipes. `proc.kill()` alone leaves them
    alive — post-kill `communicate()`/stderr-drain then blocks until
    the grandchildren exit on their own (measured: 1s timeout took
    47s), and the orphans eat RAM through the rest of the sweep.
    Spawns use start_new_session=True so killpg hits exactly this
    tool's group and nothing else.
    """
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass
    try:
        proc.kill()
    except ProcessLookupError:
        pass


@dataclass
class RunResult:
    tool: str
    command: list[str]
    exit_code: int
    duration_s: float
    items: list[OutputItem]
    stdout_tail: str = ""    # last 2KB of stdout (for debugging)
    stderr_tail: str = ""
    error: Optional[str] = None
    timed_out: bool = False

    def subdomains(self) -> list[str]:
        return [i.value for i in self.items if i.kind == "subdomain"]

    def urls(self) -> list[str]:
        return [i.value for i in self.items if i.kind == "url"]

    def hosts(self) -> list[str]:
        return [i.value for i in self.items if i.kind == "host"]

    def findings(self) -> list[OutputItem]:
        return [i for i in self.items if i.kind == "finding"]


# -------- parsers --------

# Each parser takes raw stdout (string) and returns list[OutputItem].
# Parsers should be PURE and FAST. They run in the main thread.

_SUBDOMAIN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$")
_URL_RE = re.compile(r"^https?://[^\s]+$")
_HOST_PORT_RE = re.compile(r"^([a-zA-Z0-9.\-]+):(\d+)$")
_NUCLEI_FINDING_RE = re.compile(r"^\[([a-z0-9\-]+)\]\s+\[([a-zA-Z0-9_.\-]+)\]\s+\[([a-zA-Z0-9_.\-/]+)\]\s+(.+?)(?:\s+\[.*\])?$")


def parse_subfinder(stdout: str) -> list[OutputItem]:
    items: list[OutputItem] = []
    for line in stdout.splitlines():
        s = line.strip()
        if not s or s.startswith("["):
            continue
        if _SUBDOMAIN_RE.match(s):
            items.append(OutputItem(kind="subdomain", value=s.lower(), evidence={"source": "subfinder"}))
    return items


def parse_httpx(stdout: str) -> list[OutputItem]:
    """httpx -json output: each line is a JSON object with url, host, status, title, tech, etc."""
    items: list[OutputItem] = []
    for line in stdout.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except json.JSONDecodeError:
            continue
        host = obj.get("host") or obj.get("input")
        url = obj.get("url")
        if host:
            items.append(OutputItem(kind="host", value=host, evidence={
                "url": url,
                "status_code": obj.get("status_code"),
                "title": obj.get("title"),
                "tech": obj.get("tech", []),
                "source": "httpx",
            }))
    return items


def parse_naabu(stdout: str) -> list[OutputItem]:
    items: list[OutputItem] = []
    for line in stdout.splitlines():
        s = line.strip()
        if not s:
            continue
        m = _HOST_PORT_RE.match(s)
        if m:
            items.append(OutputItem(kind="port", value=f"{m.group(1)}:{m.group(2)}", evidence={"source": "naabu"}))
    return items


def parse_nuclei(stdout: str) -> list[OutputItem]:
    """nuclei -json output: each line a JSON object with template-id, info, etc."""
    items: list[OutputItem] = []
    for line in stdout.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except json.JSONDecodeError:
            continue
        template_id = obj.get("template-id") or obj.get("templateID")
        matched_at = obj.get("matched-at") or obj.get("matched")
        info = obj.get("info", {})
        if template_id and matched_at:
            items.append(OutputItem(kind="finding", value=str(matched_at), evidence={
                "template_id": template_id,
                "severity": info.get("severity"),
                "name": info.get("name"),
                "type": obj.get("type"),
                "source": "nuclei",
                "raw": obj,
            }))
    return items


def parse_katana(stdout: str) -> list[OutputItem]:
    items: list[OutputItem] = []
    for line in stdout.splitlines():
        s = line.strip()
        if _URL_RE.match(s):
            items.append(OutputItem(kind="url", value=s, evidence={"source": "katana"}))
    return items


def parse_gau(stdout: str) -> list[OutputItem]:
    return parse_katana(stdout)  # same shape


def parse_wayback(stdout: str) -> list[OutputItem]:
    return parse_katana(stdout)


def parse_dnsx(stdout: str) -> list[OutputItem]:
    items: list[OutputItem] = []
    for line in stdout.splitlines():
        s = line.strip()
        if not s:
            continue
        # dnsx -resp output: "sub.example.com [a] 1.2.3.4"
        parts = s.split()
        if parts and _SUBDOMAIN_RE.match(parts[0]):
            items.append(OutputItem(kind="subdomain", value=parts[0].lower(), evidence={"source": "dnsx"}))
    return items


def parse_assetfinder(stdout: str) -> list[OutputItem]:
    return parse_subfinder(stdout)


def parse_amass(stdout: str) -> list[OutputItem]:
    return parse_subfinder(stdout)


def parse_raw(stdout: str) -> list[OutputItem]:
    """No parsing — return entire stdout as a single raw item."""
    if stdout.strip():
        return [OutputItem(kind="raw", value=stdout.strip())]
    return []


def parse_tlsx(stdout: str) -> list[OutputItem]:
    """tlsx -json output: one JSON object per host with san/cn fields.

    Emits:
      kind="san"       — every SAN entry (feeds permute/subenum)
      kind="subdomain" — the subject_cn as a resolved host name
    """
    items: list[OutputItem] = []
    for line in stdout.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except json.JSONDecodeError:
            continue
        host = obj.get("host") or obj.get("subject_cn")
        if not host:
            continue
        san = obj.get("san") or ""
        for entry in str(san).split(";"):
            entry = entry.strip().lower()
            if entry:
                items.append(OutputItem(kind="san", value=entry,
                                        evidence={"source": "tlsx"}))
        if _SUBDOMAIN_RE.match(host):
            items.append(OutputItem(kind="subdomain", value=host.lower(),
                                    evidence={"source": "tlsx",
                                              "subject_cn": obj.get("subject_cn")}))
    return items


def parse_dalfox(stdout: str) -> list[OutputItem]:
    """dalfox --format jsonl: one JSON object per finding."""
    items: list[OutputItem] = []
    for line in stdout.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except json.JSONDecodeError:
            continue
        url = obj.get("url") or obj.get("data")
        vuln = obj.get("vuln") or obj.get("vulnerability") or "XSS"
        if url:
            items.append(OutputItem(kind="finding", value=str(url), evidence={
                "source": "dalfox",
                "vuln": vuln,
                "method": obj.get("method"),
                "payload": obj.get("payload"),
                "severity": obj.get("severity"),
                "raw": obj,
            }))
    return items


def parse_kxss(stdout: str) -> list[OutputItem]:
    """kxss output: one reflected-parameter URL per line; skips
    [INF]/[WRN]/[ERR] progress noise."""
    items: list[OutputItem] = []
    for line in stdout.splitlines():
        s = line.strip()
        if not s or s.startswith("["):
            continue
        if _URL_RE.match(s):
            items.append(OutputItem(kind="finding", value=s,
                                    evidence={"source": "kxss",
                                              "vuln": "reflected-xss"}))
    return items


def parse_alterx(stdout: str) -> list[OutputItem]:
    """alterx output: one permutation subdomain per line."""
    items: list[OutputItem] = []
    for line in stdout.splitlines():
        s = line.strip()
        if not s or s.startswith("["):
            continue
        if _SUBDOMAIN_RE.match(s):
            items.append(OutputItem(kind="subdomain", value=s.lower(),
                                    evidence={"source": "alterx"}))
    return items


def parse_subjack(stdout: str) -> list[OutputItem]:
    """subjack -v output: takeover hits are the lines containing [+].

    A real parser (not stage-side conversion) so takeovers flow into
    the eventlog/jsonl/DAG counts like every other finding — stage
    return values alone never reach the eventlog (single-emitter
    rule), which previously made takeovers invisible to
    `loom findings`. Raw stdout.txt always keeps the full output.
    """
    items: list[OutputItem] = []
    for line in stdout.splitlines():
        s = line.strip()
        if "[+]" in s:
            items.append(OutputItem(kind="takeover", value=s,
                                    evidence={"source": "subjack",
                                              "target": s}))
    return items


def parse_arjun(stdout: str) -> list[OutputItem]:
    """Arjun -oT text export: one URL per line (GET), or
    `<url>\\t<query>` for POST-found params.

    GET lines become url items directly. POST lines keep the method +
    param names in evidence (dalfox pipe only speaks GET, but the
    endpoint + params are still discovery value).
    """
    items: list[OutputItem] = []
    for line in stdout.splitlines():
        s = line.strip()
        if not s:
            continue
        url, _, rest = s.partition("\t")
        url = url.strip()
        if not _URL_RE.match(url):
            continue
        if rest.strip():
            params = rest.strip()
            items.append(OutputItem(
                kind="url", value=url,
                evidence={"source": "arjun", "method": "POST",
                          "params": params}))
        else:
            items.append(OutputItem(
                kind="url", value=url,
                evidence={"source": "arjun", "method": "GET"}))
    return items


def parse_gitleaks(stdout: str) -> list[OutputItem]:
    """gitleaks `-f json` report: a JSON ARRAY of findings.

    No severity field upstream — verified credential-shape matches
    are high-signal, so severity=high (documented, not inflated:
    gitleaks only fires on strong rules + entropy).
    """
    try:
        data = json.loads(stdout.strip() or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    items: list[OutputItem] = []
    for f in data:
        if not isinstance(f, dict):
            continue
        secret = str(f.get("Secret") or f.get("Match") or "")[:200]
        if not secret:
            continue
        items.append(OutputItem(
            kind="finding",
            value=f"{f.get('File', '?')}:{f.get('StartLine', '?')}",
            evidence={
                "source": "gitleaks",
                "vuln": "exposed-secret",
                "rule": f.get("RuleID"),
                "severity": "high",
                "secret_redacted": secret[:4] + "...",
                "description": f.get("Description"),
            },
        ))
    return items


def parse_jsluice_urls(stdout: str) -> list[OutputItem]:
    """jsluice `urls` mode: JSONL {url, queryParams, method, ...}.

    Relative URLs pass through unresolved (the stage joins them
    against the JS file's origin — the parser stays pure).
    """
    items: list[OutputItem] = []
    for line in stdout.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except json.JSONDecodeError:
            continue
        url = obj.get("url")
        if not url or not isinstance(url, str):
            continue
        items.append(OutputItem(
            kind="url", value=url,
            evidence={
                "source": "jsluice",
                "method": obj.get("method") or "GET",
                "params": obj.get("queryParams") or [],
                "js_type": obj.get("type"),
            },
        ))
    return items


def parse_jsluice_secrets(stdout: str) -> list[OutputItem]:
    """jsluice `secrets` mode: JSONL {kind, data, severity, ...}.

    Tool severity kept as-is; missing → medium (a secret-shaped match
    with no confidence signal deserves eyes, not the top slot).
    """
    items: list[OutputItem] = []
    for line in stdout.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except json.JSONDecodeError:
            continue
        kind = obj.get("kind")
        if not kind:
            continue
        items.append(OutputItem(
            kind="finding",
            value=f"{obj.get('filename', '?')}:{kind}",
            evidence={
                "source": "jsluice",
                "vuln": str(kind),
                "severity": str(obj.get("severity") or "medium").lower(),
                "data": obj.get("data"),
            },
        ))
    return items


def parse_asnmap(stdout: str) -> list[OutputItem]:
    """asnmap -json output, parsed leniently.

    The exact schema can't be verified without a PDCP key (none on
    this box), so every plausible key is tried (asn/as_number,
    prefixes/cidr/ranges) and anything unrecognized is skipped —
    never raises. stdout.txt always preserves the raw output for
    re-parsing later.
    """
    items: list[OutputItem] = []
    for line in stdout.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        src = obj.get("input") or obj.get("host") or ""
        asn = obj.get("asn") or obj.get("as_number") or obj.get("as-number")
        if asn:
            items.append(OutputItem(
                kind="asn", value=str(asn),
                evidence={"source": "asnmap", "input": src,
                          "as_name": obj.get("as_name") or obj.get("org")}))
        cidrs: list = []
        for key in ("prefixes", "cidr", "cidrs", "ranges", "prefix"):
            v = obj.get(key)
            if isinstance(v, str):
                cidrs.append(v)
            elif isinstance(v, list):
                cidrs.extend(str(x) for x in v if isinstance(x, str))
        for c in dict.fromkeys(cidrs):
            items.append(OutputItem(
                kind="cidr", value=c,
                evidence={"source": "asnmap", "input": src, "asn": asn}))
    return items


def parse_ffuf_jsonl(stdout: str) -> list[OutputItem]:
    """ffuf -json output: newline-delimited JSON records.

    Emits finding items for fuzz hits (url, status, input, length).
    ffuf base64-encodes the input map values — decoded for evidence
    (live-verified 2026-09-05: {"FUZZ": "ZGVmYXVsdC5hc3A="}).
    """
    items: list[OutputItem] = []
    for line in stdout.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except json.JSONDecodeError:
            continue
        url = obj.get("url")
        if not url:
            continue
        raw_input = (obj.get("input") or {}).get("FUZZ")
        decoded = _b64_or_raw(raw_input)
        items.append(OutputItem(
            kind="finding", value=str(url),
            evidence={
                "source": "ffuf",
                "vuln": "content-discovery",
                "status": obj.get("status"),
                "input": decoded,
                "length": obj.get("length"),
                "words": obj.get("words"),
            },
        ))
    return items


def _b64_or_raw(value) -> object:
    """Base64-decode ffuf's input values; pass through on failure."""
    if not isinstance(value, str):
        return value
    try:
        return base64.b64decode(value).decode("utf-8", "replace")
    except Exception:
        return value


PARSERS: dict[str, Callable[[str], list[OutputItem]]] = {
    "subfinder": parse_subfinder,
    "httpx": parse_httpx,
    "naabu": parse_naabu,
    "nuclei": parse_nuclei,
    "katana": parse_katana,
    "gau": parse_gau,
    "waybackurls": parse_wayback,
    "dnsx": parse_dnsx,
    "assetfinder": parse_assetfinder,
    "amass": parse_amass,
    "ffuf": parse_ffuf_jsonl,  # v0.4: real JSONL parser (was raw)
    "subjack": parse_subjack,  # v0.5: [+] lines → takeover items (was raw)
    "arjun": parse_arjun,
    "gitleaks": parse_gitleaks,
    "jsluice_urls": parse_jsluice_urls,
    "jsluice_secrets": parse_jsluice_secrets,
    "asnmap": parse_asnmap,
    "tlsx": parse_tlsx,
    "dalfox": parse_dalfox,
    "kxss": parse_kxss,
    "alterx": parse_alterx,
    "raw": parse_raw,
}


# -------- header injection --------

def _safe_host(host: str) -> str:
    """Sanitize a host string for use as a directory name. Replaces any
    character that isn't [A-Za-z0-9._-] with '_'."""
    if not host:
        return "_no_host_"
    return re.sub(r"[^A-Za-z0-9._-]", "_", host)


def _tool_outputs(
    workdir: Path, stage: str, host: str, tool: str, ts_ms: int,
) -> dict[str, Path]:
    """Compute the output paths for a single tool invocation. The layout:
        <workdir>/<stage>/<host>/<tool>.<ts_ms>.stdout.txt
        <workdir>/<stage>/<host>/<tool>.<ts_ms>.stderr.txt
        <workdir>/<stage>/<host>/<tool>.<ts_ms>.jsonl       (parsed items)
        <workdir>/<stage>/<host>/<tool>.<ts_ms>.cmd.txt     (cmd + meta)
    Directories are created on demand by the caller.

    NOTE: names are built explicitly — Path.with_suffix() would REPLACE
    the .<ts_ms> suffix (info-loss bug: re-runs overwrote prior outputs).
    """
    safe_host = _safe_host(host)
    out_dir = workdir / stage / safe_host
    out_dir.mkdir(parents=True, exist_ok=True)
    base = f"{tool}.{ts_ms}"
    return {
        "stdout": out_dir / f"{base}.stdout.txt",
        "stderr": out_dir / f"{base}.stderr.txt",
        "jsonl": out_dir / f"{base}.jsonl",
        "cmd": out_dir / f"{base}.cmd.txt",
    }


def _write_outputs(
    paths: dict[str, Path],
    *,
    stdout: str,
    stderr: str,
    items: list[OutputItem],
    cmd: list[str],
    duration_s: float,
    exit_code: int,
    timed_out: bool,
    stdin: Optional[str] = None,
) -> None:
    """Persist the four files for a single tool invocation.

    stdin is recorded in the cmd meta so every invocation is fully
    reproducible (inputs are information too).
    """
    paths["stdout"].write_text(stdout, encoding="utf-8", errors="replace")
    paths["stderr"].write_text(stderr, encoding="utf-8", errors="replace")
    with open(paths["jsonl"], "w", encoding="utf-8") as f:
        for it in items:
            f.write(json.dumps({
                "kind": it.kind, "value": it.value, "evidence": it.evidence,
            }, ensure_ascii=False) + "\n")
    meta = {
        "cmd": cmd,
        "stdin": stdin,
        "duration_s": duration_s,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "stdout_bytes": len(stdout.encode("utf-8", "replace")),
        "stderr_bytes": len(stderr.encode("utf-8", "replace")),
        "item_count": len(items),
    }
    paths["cmd"].write_text(json.dumps(meta, indent=2), encoding="utf-8")


def _inject_headers(cmd: list[str], headers: dict[str, str]) -> list[str]:
    """For tools that accept -H 'Key: Value' (httpx, nuclei, katana, naabu),
    append any scope headers that aren't already in the command.
    """
    if not headers:
        return cmd

    # Tools that support -H (alphabetical by binary name).
    # dnsx/naabu are DNS/port scanners that don't accept HTTP headers.
    # Verified 2026-08-30: dnsx errors "flag provided but not defined: -H".
    HEADER_TOOLS = {"httpx", "nuclei", "katana", "ffuf"}
    if not cmd:
        return cmd
    binary = Path(cmd[0]).name
    if binary not in HEADER_TOOLS:
        return cmd

    # Build set of already-present header names
    already: set[str] = set()
    for tok in cmd:
        if tok.startswith("-H") or tok.startswith("--header"):
            pass  # we don't try to parse the value out of the next token
    out = list(cmd)
    for k, v in headers.items():
        if k.lower() in {t.lower() for t in already}:
            continue
        out += ["-H", f"{k}: {v}"]
    return out


# -------- Runner --------

class ToolBlocked(Exception):
    """Raised when a tool is not allowed by the active scope."""


class Runner:
    def __init__(
        self,
        scope: Scope,
        eventlog: Optional[EventLog] = None,
        state: Optional[State] = None,
        rate_limiter: Optional[RateLimiter] = None,
        run_id: Optional[int] = None,
        workdir: Optional[Path] = None,
        log: Optional[logging.Logger] = None,
        ram_budget: Optional["RamBudget"] = None,
    ):
        self.scope = scope
        self.eventlog = eventlog
        self.state = state
        self.rate_limiter = rate_limiter
        self.run_id = run_id
        # When set, every tool invocation writes its stdout/stderr/parsed
        # items/cmd to <workdir>/<stage>/<host>/<tool>.<ts>.<ext>.
        self.workdir = Path(workdir) if workdir else None
        # Live logger; one structured line per tool invocation.
        self.log = log
        # RAM budget (loom.rambudget.RamBudget). When set, each tool
        # invocation reserves its estimated RSS before launch and
        # releases it when the process exits — enforces the 20GB cap
        # across concurrent fanout hosts.
        self.ram_budget = ram_budget

    async def run(
        self,
        tool: str,
        cmd: list[str],
        *,
        stage: str = "manual",
        host: str = "",
        parser: Optional[str] = None,
        timeout: float = 600.0,
        cwd: Optional[str] = None,
        env_extra: Optional[dict[str, str]] = None,
        check: bool = True,
        stdin: Optional[str] = None,
    ) -> RunResult:
        """Run a tool. Returns RunResult.

        v0.8: fully async (asyncio subprocess). The old blocking
        subprocess.run held the event-loop thread, so one long stage
        starved its entire DAG level (live: amass-brute, 15 min).

        - `parser`: name of the registered parser (default: tool name).
        - `check`: if True, raises ToolBlocked when scope forbids the tool.
        - `host`: per-host context for resume bookkeeping (Stage/host).

        Throws ToolBlocked if check=True and scope disallows the tool.
        """
        if check and not self.scope.is_tool_allowed(tool):
            raise ToolBlocked(f"tool {tool!r} blocked by scope {self.scope.name!r}")

        # resolve the real binary (fixes e.g. python httpx shadowing
        # projectdiscovery httpx on PATH) — only when the command is
        # actually invoking the tool by name (stage builders pass
        # [tool, ...flags]); tests that pass ["sh", "-c", ...] with a
        # parser override must NOT be rewritten.
        resolved = None
        if cmd and Path(cmd[0]).name == tool:
            resolved = resolve_tool(tool)
        if resolved:
            cmd = [resolved, *cmd[1:]]

        # RAM budget: reserve estimated RSS for this invocation.
        budget_reserved = False
        if self.ram_budget is not None:
            if not self.ram_budget.can_start(tool):
                raise RuntimeError(
                    f"RAM budget exceeded: {tool} cannot start "
                    f"(cap {self.ram_budget.max_bytes / 1024**3:.1f} GB)"
                )
            self.ram_budget.acquire(tool)
            budget_reserved = True

        # throttle (async: never block the event loop)
        if self.rate_limiter is not None:
            await self.rate_limiter.aacquire(timeout=timeout)

        # inject scope headers
        full_cmd = _inject_headers(list(cmd), self.scope.request_headers())

        # merge env
        env = os.environ.copy()
        if env_extra:
            env.update(env_extra)

        # Live log: tool start (the only log call before the work happens)
        tool_start(self.log, stage, host, tool, full_cmd)

        t0 = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *full_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=(asyncio.subprocess.PIPE
                       if stdin is not None else None),
                cwd=cwd,
                env=env,
                # Own process group so timeouts can SIGKILL the whole
                # tree (see _kill_tree) — tools spawn children that
                # inherit our pipes.
                start_new_session=True,
            )
        except FileNotFoundError as e:
            duration = time.monotonic() - t0
            err = f"binary not found: {e}"
            tool_failed(self.log, stage, host, tool, err)
            if budget_reserved and self.ram_budget is not None:
                self.ram_budget.release(tool)
            return RunResult(
                tool=tool, command=full_cmd, exit_code=127, duration_s=duration,
                items=[], error=err,
            )
        try:
            out_b, err_b = await asyncio.wait_for(
                proc.communicate(
                    input=stdin.encode("utf-8") if stdin is not None else None),
                timeout=timeout,
            )
            duration = time.monotonic() - t0
            stdout = out_b.decode("utf-8", "replace") if out_b else ""
            stderr = err_b.decode("utf-8", "replace") if err_b else ""
            exit_code = proc.returncode if proc.returncode is not None else -1
            timed_out = False
            error = _classify_error(exit_code, stderr, timed_out)
        except asyncio.TimeoutError:
            duration = time.monotonic() - t0
            _kill_tree(proc)
            try:
                out_b, err_b = await proc.communicate()
            except Exception:
                out_b, err_b = b"", b""
            stdout = out_b.decode("utf-8", "replace") if out_b else ""
            stderr = err_b.decode("utf-8", "replace") if err_b else ""
            exit_code = -1
            error = _classify_error(exit_code, stderr, timed_out=True)
            timed_out = True
            tool_failed(self.log, stage, host, tool, error)

        try:
            parser_name = parser or tool
            parse_fn = PARSERS.get(parser_name, parse_raw)
            items = parse_fn(stdout)
        finally:
            # Release the RAM reservation no matter what.
            if budget_reserved and self.ram_budget is not None:
                self.ram_budget.release(tool)

        # Write structured outputs if a workdir is configured.
        output_path: Optional[str] = None
        if self.workdir is not None:
            ts_ms = int(time.time() * 1000)
            paths = _tool_outputs(self.workdir, stage, host, tool, ts_ms)
            try:
                _write_outputs(
                    paths,
                    stdout=stdout,
                    stderr=stderr,
                    items=items,
                    cmd=full_cmd,
                    duration_s=duration,
                    exit_code=exit_code,
                    timed_out=timed_out,
                    stdin=stdin,
                )
                output_path = str(paths["jsonl"])
            except Exception:
                # Don't let an output-write error break the run.
                output_path = None

        # log to event log
        if self.eventlog is not None:
            for it in items:
                self.eventlog.append(
                    type=it.kind,
                    source=tool,
                    host=host,
                    value=it.value,
                    evidence=it.evidence,
                    stage=stage,
                )

        # mark in state
        if self.state is not None and self.run_id is not None and host:
            status = "done" if exit_code == 0 and not timed_out else ("timeout" if timed_out else "failed")
            self.state.mark(
                run_id=self.run_id,
                host=host, tool=tool, stage=stage,
                status=status,
                duration_s=duration,
                error=error or (stderr[-500:] if exit_code != 0 else None),
                output_path=output_path,
            )

        # Live log: tool done (or failed for non-zero exit)
        status = "done" if exit_code == 0 and not timed_out else (
            "timeout" if timed_out else "failed"
        )
        tool_done(self.log, stage, host, tool,
                  exit_code=exit_code, duration_s=duration,
                  items=len(items), timed_out=timed_out, status=status)

        return RunResult(
            tool=tool,
            command=full_cmd,
            exit_code=exit_code,
            duration_s=duration,
            items=items,
            stdout_tail=stdout[-2000:],
            stderr_tail=stderr[-2000:],
            error=error,
            timed_out=timed_out,
        )

    async def run_streaming(
        self,
        tool: str,
        cmd: list[str],
        *,
        stage: str = "manual",
        host: str = "",
        parser: Optional[str] = None,
        timeout: float = 600.0,
        on_item: Optional[Callable[[OutputItem], None]] = None,
        cwd: Optional[str] = None,
        check: bool = True,
        stdin: Optional[str] = None,
    ) -> RunResult:
        """Run a tool and stream items to `on_item` as they are parsed line by line.
        This is what makes the DAG streaming work: katana can start feeding nuclei
        before the crawl finishes.

        v0.8: fully async like run() (same event-loop-starvation fix).
        """
        if check and not self.scope.is_tool_allowed(tool):
            raise ToolBlocked(f"tool {tool!r} blocked by scope {self.scope.name!r}")
        # resolve the real binary (see resolve_tool) — only when the
        # command invokes the tool by name, not when tests pass
        # ["sh", "-c", ...] with a parser override
        resolved = None
        if cmd and Path(cmd[0]).name == tool:
            resolved = resolve_tool(tool)
        if resolved:
            cmd = [resolved, *cmd[1:]]

        # RAM budget: reserve estimated RSS for this invocation.
        budget_reserved = False
        if self.ram_budget is not None:
            if not self.ram_budget.can_start(tool):
                raise RuntimeError(
                    f"RAM budget exceeded: {tool} cannot start "
                    f"(cap {self.ram_budget.max_bytes / 1024**3:.1f} GB)"
                )
            self.ram_budget.acquire(tool)
            budget_reserved = True

        if self.rate_limiter is not None:
            await self.rate_limiter.aacquire(timeout=timeout)

        full_cmd = _inject_headers(list(cmd), self.scope.request_headers())
        env = os.environ.copy()

        # Live log: tool start
        tool_start(self.log, stage, host, tool, full_cmd)

        t0 = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *full_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=(asyncio.subprocess.PIPE
                       if stdin is not None else None),
                cwd=cwd,
                env=env,
                # Own process group so timeouts can SIGKILL the whole
                # tree (see _kill_tree) — tools spawn children that
                # inherit our pipes.
                start_new_session=True,
            )
        except FileNotFoundError as e:
            err = f"binary not found: {e}"
            tool_failed(self.log, stage, host, tool, err)
            if budget_reserved and self.ram_budget is not None:
                self.ram_budget.release(tool)
            return RunResult(
                tool=tool, command=full_cmd, exit_code=127, duration_s=0,
                items=[], error=err,
            )

        # Feed stdin from a background task while we read stdout: writing
        # the whole input before reading (the old blocking order) deadlocks
        # as soon as input + output both exceed the 64K pipe buffers.
        # BrokenPipe = child exited early (e.g. dnsx); ignore, as before.
        feed_task = None
        if stdin is not None and proc.stdin is not None:
            stdin_data = stdin.encode("utf-8")

            async def _feed() -> None:
                assert proc.stdin is not None
                try:
                    proc.stdin.write(stdin_data)
                    await proc.stdin.drain()
                except (BrokenPipeError, ConnectionResetError):
                    # Child closed stdin early (e.g. dnsx exited before
                    # consuming all subdomains). Ignore — the child
                    # decided it had enough input.
                    pass
                finally:
                    try:
                        proc.stdin.close()
                    except OSError:
                        pass

            feed_task = asyncio.create_task(_feed())

        items: list[OutputItem] = []
        parser_name = parser or tool
        parse_fn = PARSERS.get(parser_name, parse_raw)
        stdout_buf: list[str] = []
        stderr_buf: list[str] = []

        # We need to parse line-by-line but most parsers want full stdout.
        # Compromise: collect lines, but as each line arrives, run a per-line
        # parser if available, otherwise accumulate and parse at the end.
        line_parsers = {
            "subfinder": lambda l: _SUBDOMAIN_RE.match(l.strip()) and l.strip().lower(),
            "assetfinder": lambda l: _SUBDOMAIN_RE.match(l.strip()) and l.strip().lower(),
            "amass": lambda l: _SUBDOMAIN_RE.match(l.strip()) and l.strip().lower(),
            "katana": lambda l: l.strip() if _URL_RE.match(l.strip()) else None,
            "gau": lambda l: l.strip() if _URL_RE.match(l.strip()) else None,
            "waybackurls": lambda l: l.strip() if _URL_RE.match(l.strip()) else None,
            "naabu": lambda l: (_HOST_PORT_RE.match(l.strip()) and l.strip()),
        }
        per_line = line_parsers.get(parser_name)

        deadline = t0 + timeout
        stream_timed_out = False
        try:
            assert proc.stdout is not None
            while True:
                now = time.monotonic()
                if now >= deadline:
                    stream_timed_out = True
                    break
                try:
                    raw_b = await asyncio.wait_for(
                        proc.stdout.readline(), timeout=deadline - now)
                except asyncio.TimeoutError:
                    stream_timed_out = True
                    break
                if not raw_b:
                    break  # EOF
                raw_line = raw_b.decode("utf-8", "replace")
                # Keep the raw line (WITH newline) in the buffer so
                # the saved .stdout.txt / full_stdout stays intact —
                # stripping here glued every URL together when the
                # workdir writer joined the buffer (found live:
                # katana output on help.twilio.com).
                stdout_buf.append(raw_line)
                if per_line is None:
                    continue  # accumulate; parse at end
                val = per_line(raw_line.rstrip("\n"))
                if val:
                    item = OutputItem(kind=("subdomain" if parser_name in ("subfinder", "assetfinder", "amass") else ("url" if parser_name in ("katana", "gau", "waybackurls") else "port")),
                                      value=val, evidence={"source": tool})
                    items.append(item)
                    if self.eventlog is not None:
                        self.eventlog.append(type=item.kind, source=tool, host=host, value=item.value, evidence=item.evidence, stage=stage)
                    if on_item is not None:
                        on_item(item)
        finally:
            if stream_timed_out:
                _kill_tree(proc)
            if feed_task is not None:
                try:
                    await asyncio.wait_for(feed_task, timeout=10)
                except (asyncio.TimeoutError, Exception):
                    pass
            try:
                err_b = await proc.stderr.read() if proc.stderr else b""
                if err_b:
                    stderr_buf.append(err_b.decode("utf-8", "replace"))
            except Exception:
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=10)
            except asyncio.TimeoutError:
                pass
            # Release the RAM reservation once the process is gone.
            if budget_reserved and self.ram_budget is not None:
                self.ram_budget.release(tool)

        duration = time.monotonic() - t0
        timed_out = stream_timed_out or proc.returncode is None or (duration >= timeout and proc.returncode == -9)
        exit_code = proc.returncode if proc.returncode is not None else -1
        if per_line is None:
            full_stdout = "".join(stdout_buf)
            items = parse_fn(full_stdout)
            if self.eventlog is not None:
                for it in items:
                    self.eventlog.append(type=it.kind, source=tool, host=host, value=it.value, evidence=it.evidence, stage=stage)
            for it in items:
                if on_item is not None:
                    on_item(it)

        # F24: structured error — non-empty even when stderr is empty
        error = _classify_error(
            exit_code,
            "".join(stderr_buf),
            timed_out=timed_out,
        )

        # Write structured outputs if a workdir is configured.
        output_path: Optional[str] = None
        if self.workdir is not None:
            ts_ms = int(time.time() * 1000)
            paths = _tool_outputs(self.workdir, stage, host, tool, ts_ms)
            try:
                _write_outputs(
                    paths,
                    stdout="".join(stdout_buf),
                    stderr="".join(stderr_buf),
                    items=items,
                    cmd=full_cmd,
                    duration_s=duration,
                    exit_code=exit_code,
                    timed_out=timed_out,
                    stdin=stdin,
                )
                output_path = str(paths["jsonl"])
            except Exception:
                output_path = None

        if self.state is not None and self.run_id is not None and host:
            status = "done" if exit_code == 0 and not timed_out else ("timeout" if timed_out else "failed")
            self.state.mark(
                run_id=self.run_id,
                host=host, tool=tool, stage=stage,
                status=status,
                duration_s=duration,
                error=error or (("".join(stderr_buf))[-500:] if exit_code != 0 else None),
                output_path=output_path,
            )

        # Live log: tool done
        if not timed_out and exit_code != 0:
            tool_failed(self.log, stage, host, tool, error or f"exit {exit_code}")
        tool_done(self.log, stage, host, tool,
                  exit_code=exit_code, duration_s=duration,
                  items=len(items), timed_out=timed_out,
                  status="done" if exit_code == 0 and not timed_out else (
                      "timeout" if timed_out else "failed"))

        return RunResult(
            tool=tool, command=full_cmd, exit_code=exit_code, duration_s=duration,
            items=items, stdout_tail=("".join(stdout_buf))[-2000:],
            stderr_tail=("".join(stderr_buf))[-2000:],
            error=error, timed_out=timed_out,
        )
