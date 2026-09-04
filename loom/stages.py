"""loom.stages — StageFn factory functions for real recon tools.

Each function here returns a `StageFn` that the Pipeline can call. The
stage uses the `Runner` to invoke the tool, parses the output, and
returns the list of `OutputItem`s.

The contract:
    async def stage(runner, host, ctx) -> list[OutputItem]

The `host` parameter is the target (e.g. "example.com" or "*.example.com").
The `ctx` is a `PipelineContext`; stages can pull the EventLog, State,
Runner scope, and Pipeline workdir from it.

For each tool, we expose two factories:
  * `make_<tool>_stage(...)` — returns a StageFn for one target
  * `<tool>_command(host, **opts)` — returns the subprocess argv (so
    tests can assert on the exact command)

The actual binary names are in the Runner's PATH; stages don't try to
locate them (the Runner raises FileNotFoundError → exit 127 if missing).
"""
from __future__ import annotations

import asyncio
import os
import shlex
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qsl, urlsplit

from .pipeline import PipelineContext, StageFn
from .runner import OutputItem, Runner, _safe_host as _safe_name


# Default binary path for each tool. If the binary isn't in PATH, the
# Runner will return exit_code=127 and the stage will be marked failed.
DEFAULT_BIN = {
    "subfinder": "subfinder",
    "httpx": "httpx",
    "naabu": "naabu",
    "nuclei": "nuclei",
    "katana": "katana",
    "dnsx": "dnsx",
    "assetfinder": "assetfinder",
    "ffuf": "ffuf",
    "gau": "gau",
    "waybackurls": "waybackurls",
    "amass": "amass",
    "uncover": "uncover",
    "tlsx": "tlsx",
    "dalfox": "dalfox",
    "crlfuzz": "crlfuzz",
    "kxss": "kxss",
    "hakrawler": "hakrawler",
    "subjack": "subjack",
    "alterx": "alterx",
    "gowitness": "gowitness",
}


# ============================================================
# subfinder
# ============================================================


def subfinder_command(domain: str, *, bin_path: str = "subfinder",
                      timeout: float = 300.0) -> list[str]:
    """subfinder -d <domain> -silent -all (no sources flag → uses defaults)."""
    return [bin_path, "-d", domain, "-silent", "-all"]


def make_subfinder_stage(*, bin_path: Optional[str] = None,
                         timeout: float = 300.0,
                         parser: str = "subfinder") -> StageFn:
    """Returns a StageFn that runs subfinder once per host it receives.

    Note: in the canonical subdomain pipeline, subfinder is called
    ONCE on the root domain, not per-host. This factory returns a
    stage that runs subfinder on `host` (which is typically the
    root domain passed by the caller).
    """
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        # `host` here is the target domain (e.g. "example.com").
        cmd = subfinder_command(host, bin_path=bin_path or DEFAULT_BIN["subfinder"],
                                timeout=timeout)
        result = runner.run(
            "subfinder", cmd, stage="subenum", host=host,
            parser=parser, timeout=timeout, check=True,
        )
        # Share discovered subdomains with downstream stages (resolve).
        subs = ctx.extras.setdefault("subdomains", [])
        for it in result.items:
            if it.kind == "subdomain" and it.value not in subs:
                subs.append(it.value)
        return result.items
    return _stage


# ============================================================
# dnsx
# ============================================================


def dnsx_command(input_hosts: list[str], *, bin_path: str = "dnsx",
                 timeout: float = 120.0) -> list[str]:
    """dnsx -silent -resp -l - (stdin) — pass hosts via stdin.
    The runner's `host` param is the *target*; we pass via stdin.
    For one-off use, prefer passing a single host via -d.
    """
    return [bin_path, "-silent", "-resp"]


def make_dnsx_stage(*, bin_path: Optional[str] = None,
                    timeout: float = 120.0) -> StageFn:
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        # Resolve the subdomains discovered by the subenum stages
        # (shared via ctx.extras["subdomains"]), falling back to the
        # host itself. Feed them to dnsx via stdin (`-l -`).
        subs = ctx.extras.get("subdomains") or [host]
        cmd = [
            bin_path or DEFAULT_BIN["dnsx"],
            "-silent", "-resp",
            "-l", "-",
        ]
        result = runner.run_streaming(
            "dnsx", cmd, stage="resolve", host=host,
            parser="dnsx", timeout=timeout, check=True,
            stdin="\n".join(subs),
        )
        # Share resolved subdomains with downstream stages (probe).
        resolved = ctx.extras.setdefault("resolved_subs", [])
        for it in result.items:
            if it.kind == "subdomain" and it.value not in resolved:
                resolved.append(it.value)
        return result.items
    return _stage


# ============================================================
# httpx
# ============================================================


def httpx_command(targets: list[str] | str, *, bin_path: str = "httpx",
                  timeout: float = 180.0) -> list[str]:
    """httpx -json (stdin, list) or -u <target> (single), no follow.

    NOTE: PD httpx reads stdin when piped WITHOUT -l. `-l -` is
    interpreted as a file literally named "-" and fails with
    "No input provided". Verified live 2026-08-30.
    """
    if isinstance(targets, str):
        return [
            bin_path, "-silent", "-json", "-no-color",
            "-timeout", "5", "-retries", "1",
            "-u", targets,
        ]
    return [
        bin_path, "-silent", "-json", "-no-color",
        "-timeout", "5", "-retries", "1",
    ]


def make_httpx_stage(*, bin_path: Optional[str] = None,
                     timeout: float = 180.0) -> StageFn:
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        # Probe the subdomains resolved by earlier stages when
        # available (ctx.extras["resolved_subs"]), else the host.
        subs = ctx.extras.get("resolved_subs")
        if subs:
            cmd = httpx_command(subs, bin_path=bin_path or DEFAULT_BIN["httpx"],
                                timeout=timeout)
            result = runner.run(
                "httpx", cmd, stage="probe", host=host,
                parser="httpx", timeout=timeout, check=True,
                stdin="\n".join(subs),
            )
        else:
            url = host if host.startswith(("http://", "https://")) else f"https://{host}"
            cmd = httpx_command(url, bin_path=bin_path or DEFAULT_BIN["httpx"],
                                timeout=timeout)
            result = runner.run(
                "httpx", cmd, stage="probe", host=host,
                parser="httpx", timeout=timeout, check=True,
            )
        # Share live URLs + detected tech with downstream stages
        # (nuclei scan uses tech to pick templates).
        urls = ctx.extras.setdefault("urls", [])
        techs = ctx.extras.setdefault("tech", set())
        emitted: list[OutputItem] = list(result.items)
        for it in result.items:
            ev = it.evidence if isinstance(it.evidence, dict) else {}
            url = ev.get("url")
            if url and url not in urls:
                urls.append(url)
                emitted.append(OutputItem(kind="url", value=url,
                                          evidence={"source": "httpx"}))
            for t in ev.get("tech", []) or []:
                techs.add(str(t).lower())
        return emitted
    return _stage


# ============================================================
# naabu
# ============================================================


def naabu_command(host: str, *, bin_path: str = "naabu",
                  ports: str = "100", timeout: float = 180.0) -> list[str]:
    """naabu -host <h> -top-ports <n> -silent -no-color.

    Live-verified 2026-09-05: naabu has no -ports flag (exit 2,
    'flag provided but not defined') and 'top-100' is not a valid
    -p value. The correct form is -top-ports 100.
    """
    return [bin_path, "-host", host, "-top-ports", ports, "-silent", "-no-color"]


def make_naabu_stage(*, bin_path: Optional[str] = None, ports: str = "100",
                     timeout: float = 180.0,
                     max_hosts: int = 20) -> StageFn:
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        # Port-scan every known live host, not just the pipeline root
        # (live-verified coverage hole: the deep run scanned only
        # vulnweb.com while testasp/testaspnet/rest went unscanned).
        # Each host gets its own invocation (own output dir + events).
        targets = [h.split(":")[0] for h in _live_hosts(ctx, host)][:max_hosts]
        if not targets:
            targets = [host]
        items: list[OutputItem] = []
        for target in targets:
            cmd = naabu_command(target, bin_path=bin_path or DEFAULT_BIN["naabu"],
                                ports=ports, timeout=timeout)
            result = runner.run(
                "naabu", cmd, stage="portscan", host=target,
                parser="naabu", timeout=timeout, check=True,
            )
            items.extend(result.items)
        return items
    return _stage


# ============================================================
# nuclei
# ============================================================


def nuclei_command(targets: list[str] | str, *, bin_path: str = "nuclei",
                   severity: str = "critical,high,medium",
                   timeout: float = 600.0,
                   tags: Optional[str] = None) -> list[str]:
    """nuclei -u <target> (single) or stdin (list).

    NOTE: like httpx, nuclei reads stdin when piped without -l/-list;
    `-l -` is treated as a literal file named "-".
    """
    tag_args = ["-tags", tags] if tags else []
    if isinstance(targets, str):
        return [
            bin_path, "-u", targets, "-silent", "-j", "-no-color",
            "-severity", severity,
            "-stats", "-stats-interval", "10",
            "-timeout", "5",
            *tag_args,
        ]
    return [
        bin_path, "-silent", "-j", "-no-color",
        "-severity", severity,
        "-stats", "-stats-interval", "10",
        "-timeout", "5",
        *tag_args,
    ]


# Tech name → nuclei template tag(s). Used to focus the scan when
# httpx fingerprinting detected a stack (e.g. IIS/ASP.NET on the
# vulnweb test targets). Unknown tech → no tag filter (full scan).
TECH_TAGS: dict[str, str] = {
    "iis": "iis",
    "microsoft asp.net": "aspnet",
    "asp.net": "aspnet",
    "php": "php",
    "wordpress": "wordpress",
    "apache": "apache",
    "nginx": "nginx",
    "tomcat": "tomcat",
    "java": "java",
    "spring": "spring",
    "laravel": "laravel",
    "django": "django",
    "ruby": "ruby",
    "node.js": "nodejs",
    "express": "nodejs",
    "go": "go",
    "cloudflare": "cloudflare",
    "google frontend": "google",
}


def _tech_tags(tech: set[str]) -> Optional[str]:
    """Map detected tech names to nuclei -tags value (comma-joined)."""
    if not tech:
        return None
    tags: set[str] = set()
    for t in tech:
        for key, tag in TECH_TAGS.items():
            if key in t:
                tags.add(tag)
    return ",".join(sorted(tags)) if tags else None


def make_nuclei_stage(*, bin_path: Optional[str] = None,
                      severity: str = "critical,high,medium",
                      timeout: float = 600.0,
                      max_urls: int = 2000) -> StageFn:
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        # Scan the NORMALIZED URL pool when available (param-value
        # variants and pagination collapse — same attack surface,
        # fraction of the requests), else the host. Focus templates on
        # the detected tech stack when fingerprinting produced one.
        # The raw pool is untouched; variants map kept for attribution.
        tags = _tech_tags(ctx.extras.get("tech", set()))
        urls = scan_pool(ctx, cap=max_urls)
        if urls:
            cmd = nuclei_command(urls, bin_path=bin_path or DEFAULT_BIN["nuclei"],
                                 severity=severity, timeout=timeout, tags=tags)
            result = runner.run_streaming(
                "nuclei", cmd, stage="scan", host=host,
                parser="nuclei", timeout=timeout, check=True,
                stdin="\n".join(urls),
            )
        else:
            target = host if host.startswith(("http://", "https://")) else f"https://{host}"
            cmd = nuclei_command(target, bin_path=bin_path or DEFAULT_BIN["nuclei"],
                                 severity=severity, timeout=timeout, tags=tags)
            result = runner.run_streaming(
                "nuclei", cmd, stage="scan", host=host,
                parser="nuclei", timeout=timeout, check=True,
            )
        return result.items
    return _stage


# ============================================================
# katana
# ============================================================


def katana_command(target: str, *, bin_path: str = "katana",
                   depth: int = 2, timeout: float = 300.0) -> list[str]:
    return [
        bin_path, "-u", target, "-silent", "-no-color",
        "-depth", str(depth), "-js-crawl", "-known-files", "all",
    ]


def make_katana_stage(*, bin_path: Optional[str] = None, depth: int = 2,
                      timeout: float = 300.0) -> StageFn:
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        target = host if host.startswith(("http://", "https://")) else f"https://{host}"
        cmd = katana_command(target, bin_path=bin_path or DEFAULT_BIN["katana"],
                             depth=depth, timeout=timeout)
        result = runner.run_streaming(
            "katana", cmd, stage="crawl", host=host,
            parser="katana", timeout=timeout, check=True,
        )
        # Share crawled URLs with downstream stages (nuclei scan).
        urls = ctx.extras.setdefault("urls", [])
        for it in result.items:
            if it.kind == "url" and it.value not in urls:
                urls.append(it.value)
        return result.items
    return _stage


# ============================================================
# assetfinder / waybackurls / gau / amass
# ============================================================


def make_assetfinder_stage(*, bin_path: Optional[str] = None,
                           timeout: float = 30.0) -> StageFn:
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        cmd = [bin_path or DEFAULT_BIN["assetfinder"], "--subs-only", host]
        result = runner.run(
            "assetfinder", cmd, stage="subenum", host=host,
            parser="assetfinder", timeout=timeout, check=True,
        )
        # Share discovered subdomains with downstream stages (resolve).
        subs = ctx.extras.setdefault("subdomains", [])
        for it in result.items:
            if it.kind == "subdomain" and it.value not in subs:
                subs.append(it.value)
        return result.items
    return _stage


def make_waybackurls_stage(*, bin_path: Optional[str] = None,
                           timeout: float = 120.0) -> StageFn:
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        cmd = [bin_path or DEFAULT_BIN["waybackurls"], host]
        result = runner.run(
            "waybackurls", cmd, stage="urls", host=host,
            parser="waybackurls", timeout=timeout, check=True,
        )
        # Share with the downstream xss fanout (live-verified bug
        # 2026-09-04: output never reached ctx.extras['urls']).
        urls = ctx.extras.setdefault("urls", [])
        for it in result.items:
            if it.kind == "url" and it.value not in urls:
                urls.append(it.value)
        return result.items
    return _stage


def make_gau_stage(*, bin_path: Optional[str] = None,
                   timeout: float = 120.0) -> StageFn:
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        cmd = [bin_path or DEFAULT_BIN["gau"], "--subs", host]
        result = runner.run(
            "gau", cmd, stage="urls", host=host,
            parser="gau", timeout=timeout, check=True,
        )
        # Share with the downstream xss fanout (live-verified bug
        # 2026-09-04: 15k gau URLs on vulnweb never reached the pool).
        urls = ctx.extras.setdefault("urls", [])
        for it in result.items:
            if it.kind == "url" and it.value not in urls:
                urls.append(it.value)
        return result.items
    return _stage


def make_amass_stage(*, bin_path: Optional[str] = None,
                     timeout: float = 600.0) -> StageFn:
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        cmd = [bin_path or DEFAULT_BIN["amass"], "enum", "-passive", "-d", host]
        result = runner.run(
            "amass", cmd, stage="subenum", host=host,
            parser="amass", timeout=timeout, check=True,
        )
        return result.items
    return _stage


# ============================================================
# ffuf
# ============================================================


# ============================================================
# ffuf — directory/content fuzzing (wordlist auto-resolution)
# ============================================================

# Candidates in preference order; the first one that exists on disk
# wins (verified live 2026-09-04: /usr/share/wordlists/dirb/common.txt
# is absent on stock Ubuntu; SecLists ships with the BB arsenal).
_FFUF_WORDLIST_CANDIDATES: tuple[str, ...] = (
    "/usr/share/wordlists/dirb/common.txt",
    "/opt/tools/SecLists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
)

_FFUF_MINI_WORDLIST = "admin\nbackup\ndev\ndb.sql\nphpinfo.php\ntest\n.git\n.env\n"


def make_ffuf_stage(*, bin_path: Optional[str] = None,
                    wordlist: Optional[str] = None,
                    timeout: float = 180.0,
                    max_hosts: int = 10) -> StageFn:
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        nonlocal wordlist
        host = _bare_host(host)
        if not wordlist:
            for cand in _FFUF_WORDLIST_CANDIDATES:
                if Path(cand).is_file():
                    wordlist = cand
                    break
            else:
                # No wordlist on disk: write a minimal built-in one into
                # the run's inputs dir so ffuf still runs. Prefer the
                # Runner's output workdir, then ctx.workdir, then cwd.
                base = (runner.workdir or ctx.workdir or Path.cwd())
                wl = base / "inputs" / _safe_name(host) / "mini-wordlist.txt"
                wl.parent.mkdir(parents=True, exist_ok=True)
                wl.write_text(_FFUF_MINI_WORDLIST, encoding="utf-8")
                wordlist = str(wl)
        # Fuzz every known live host, not just the pipeline root
        # (live-verified coverage hole: the deep run fuzzed only
        # vulnweb.com's root, which exposes no common paths, while the
        # live app hosts went unfuzzed). Root first, busiest hosts
        # next; each host gets its own invocation + output dir.
        items: list[OutputItem] = []
        for h in _live_hosts(ctx, host)[:max_hosts]:
            target = _target_for(ctx, h)
            # NOTE: -json WITHOUT -s. Live-verified 2026-09-05: -s
            # (silent) suppresses the JSON and prints plain matched
            # words, which silently zeroed every ffuf finding.
            # -noninteractive keeps it non-TTY-safe instead.
            cmd = [
                bin_path or DEFAULT_BIN["ffuf"],
                "-u", f"{target}/FUZZ",
                "-w", wordlist,
                "-json", "-noninteractive",
                "-mc", "200,201,204,301,302,307,401,403,405",
            ]
            result = runner.run(
                "ffuf", cmd, stage="fuzz", host=h,
                parser="ffuf", timeout=timeout, check=True,
            )
            items.extend(result.items)
        return items
    return _stage




# ============================================================
# uncover — passive exposed-asset discovery (multi search engine)
# ============================================================


def uncover_command(domain: str, *, bin_path: str = "uncover",
                    timeout: float = 120.0) -> list[str]:
    """uncover -q 'subdomain:<domain>' -silent (PD query syntax)."""
    return [bin_path, "-q", f"subdomain:{domain}", "-silent"]


def make_uncover_stage(*, bin_path: Optional[str] = None,
                       timeout: float = 120.0) -> StageFn:
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        cmd = uncover_command(host, bin_path=bin_path or DEFAULT_BIN["uncover"],
                              timeout=timeout)
        result = runner.run(
            "uncover", cmd, stage="subenum", host=host,
            parser="subfinder", timeout=timeout, check=True,
        )
        # Share with resolve, like the other subenum stages.
        subs = ctx.extras.setdefault("subdomains", [])
        for it in result.items:
            if it.kind == "subdomain" and it.value not in subs:
                subs.append(it.value)
        return result.items
    return _stage


# ============================================================
# tlsx — TLS certificate SAN/CN harvesting (discovers hidden hosts)
# ============================================================


def tlsx_command(host: str, *, bin_path: str = "tlsx",
                 timeout: float = 120.0) -> list[str]:
    """tlsx -u <host> -j -san -cn — JSON out, SAN + CN fields."""
    return [bin_path, "-u", host, "-j", "-san", "-cn", "-silent"]


def make_tlsx_stage(*, bin_path: Optional[str] = None,
                    timeout: float = 120.0) -> StageFn:
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        cmd = tlsx_command(host, bin_path=bin_path or DEFAULT_BIN["tlsx"],
                           timeout=timeout)
        result = runner.run(
            "tlsx", cmd, stage="tls", host=host,
            parser="tlsx", timeout=timeout, check=True,
        )
        # SAN entries may reveal hosts not in passive sources; feed
        # them into the subdomain pool for later resolution/probing.
        subs = ctx.extras.setdefault("subdomains", [])
        for it in result.items:
            if it.kind in ("san", "subdomain") and it.value not in subs:
                subs.append(it.value)
        return result.items
    return _stage


# ============================================================
# dalfox — XSS scanner (stdin pipe mode over parameterized URLs)
# ============================================================


def dalfox_command(url: str, *, bin_path: str = "dalfox",
                   timeout: float = 600.0) -> list[str]:
    """dalfox pipe --silence --no-color --format jsonl (URL on stdin)."""
    return [bin_path, "pipe", "--silence", "--no-color", "--format", "jsonl"]


def _xss_pool(urls: list[str], *, cap: int = 500) -> list[str]:
    """Build the URL list for xss fanout stages (dalfox/kxss/crlfuzz).

    Normalizes first (param-value variants collapse — ?q=1 and ?q=2
    test identically), then puts parameterized URLs first (the only
    ones XSS tools can actually test), then caps so a huge archive
    dump can't stall the pipeline.

    The raw pool is never touched: normalization only shapes tool
    input. Every raw URL stays in ctx.extras['urls'], the eventlog,
    and the variants map.
    """
    reps, _ = normalize_urls(urls)
    params = [u for u in reps if "?" in u]
    plain = [u for u in reps if "?" not in u]
    return (params + plain)[:cap]


def normalize_urls(urls: list[str]) -> tuple[list[str], dict[str, list[str]]]:
    """Collapse URL variants to one representative per attack surface.

    Key = (host[:port], path, sorted query-param NAMES). Collapsed:
    same path with different param values (?q=1 vs ?q=2), pagination
    (?page=1..500), http/https scheme duplicates. NEVER dropped as a
    class: every distinct host, path, param-set, and static asset
    (.js/.css/...) survives — JS is secret-scan fuel.

    Returns (representatives in first-seen order, {rep: [all variants]}).
    Pure function: the input list is never mutated.
    """
    groups: dict[tuple, list[str]] = {}
    order: list[tuple] = []
    for u in urls:
        try:
            p = urlsplit(u)
        except ValueError:
            continue
        host = (p.netloc or "").lower()
        if not host:
            continue
        try:
            names = tuple(sorted({k for k, _ in parse_qsl(p.query, keep_blank_values=True)}))
        except ValueError:
            names = ()
        key = (host, p.path or "/", names)
        if key not in groups:
            groups[key] = []
            order.append(key)
        if u not in groups[key]:
            groups[key].append(u)

    reps: list[str] = []
    variants: dict[str, list[str]] = {}
    for key in order:
        vs = groups[key]
        # Representative preference: https > has-query > shortest >
        # lexicographic (fully deterministic).
        rep = min(vs, key=lambda v: (
            not v.lower().startswith("https://"),
            "?" not in v,
            len(v),
            v,
        ))
        reps.append(rep)
        variants[rep] = list(vs)
    return reps, variants


def scan_pool(ctx: PipelineContext, *, cap: int = 2000) -> list[str]:
    """Normalized URL list for breadth scanners (nuclei).

    Same collapse as the xss pool but in first-seen order with a
    roomier cap. Records the variants map in extras for finding
    attribution. The raw `urls` pool is left intact.
    """
    urls = ctx.extras.get("urls") or []
    reps, variants = normalize_urls(urls)
    ctx.extras["url_variants"] = variants
    return reps[:cap]


def _bare_host(host: str) -> str:
    """Strip scheme/path: 'https://a.com/x' → 'a.com'. Idempotent."""
    h = host.strip()
    if "://" in h:
        try:
            netloc = urlsplit(h).netloc or h
        except ValueError:
            netloc = h
        h = netloc.split("@")[-1].split(":")[0]
    return h.lower().rstrip("/")


def _live_hosts(ctx: PipelineContext, host: str) -> list[str]:
    """Live-host set for per-host fanout (ffuf/naabu/gowitness).

    Union of the pipeline root, probed URL hosts, and resolved subs —
    root first, then by URL frequency, then alphabetical. Default ports
    are stripped; non-default ports are kept (they're distinct
    surfaces). Pure expansion: never drops a known host.
    """
    host = _bare_host(host)
    counts: dict[str, int] = {}
    for u in ctx.extras.get("urls") or []:
        try:
            p = urlsplit(u)
        except ValueError:
            continue
        netloc = (p.netloc or "").lower()
        if not netloc:
            continue
        if "@" in netloc:  # strip userinfo
            netloc = netloc.rsplit("@", 1)[1]
        bare, _, port = netloc.partition(":")
        default = (p.scheme == "http" and port == "80") or (
            p.scheme == "https" and port == "443")
        key = bare if (not port or default) else f"{bare}:{port}"
        if bare:
            counts[key] = counts.get(key, 0) + 1
    for s in ctx.extras.get("resolved_subs") or []:
        s = str(s).lower().strip()
        if s:
            counts.setdefault(s, 0)
    ordered = sorted(counts, key=lambda h: (-counts[h], h))
    out = [host.lower()]
    out.extend(h for h in ordered if h != host.lower())
    return out


def _target_for(ctx: PipelineContext, host: str) -> str:
    """Preferred base URL for a host: the first probed URL's
    scheme://host (preserves http-vs-https reality), else https."""
    for u in ctx.extras.get("urls") or []:
        try:
            p = urlsplit(u)
        except ValueError:
            continue
        if (p.netloc or "").lower() == host.lower() and p.scheme in ("http", "https"):
            return f"{p.scheme}://{p.netloc}"
    return f"https://{host}"


def make_dalfox_stage(*, bin_path: Optional[str] = None,
                      timeout: float = 600.0,
                      max_urls: int = 500) -> StageFn:
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        pool = _xss_pool(ctx.extras.get("urls") or [], cap=max_urls)
        if not pool:
            return []
        cmd = dalfox_command(pool[0], bin_path=bin_path or DEFAULT_BIN["dalfox"],
                             timeout=timeout)
        result = runner.run_streaming(
            "dalfox", cmd, stage="xss", host=host,
            parser="dalfox", timeout=timeout, check=True,
            stdin="\n".join(pool),
        )
        return result.items
    return _stage


# ============================================================
# crlfuzz — CRLF injection over a URL list (via -l file)
# ============================================================


def crlfuzz_command(urls: list[str], *, bin_path: str = "crlfuzz",
                    timeout: float = 300.0) -> list[str]:
    """crlfuzz -l <file> -s — file input so targets persist on disk."""
    return [bin_path, "-l", "<URLS_FILE>", "-s"]


def make_crlfuzz_stage(*, bin_path: Optional[str] = None,
                       timeout: float = 300.0,
                       max_urls: int = 500) -> StageFn:
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        urls = _xss_pool(ctx.extras.get("urls") or [], cap=max_urls)
        if not urls:
            return []
        # crlfuzz takes -l FILE (not stdin); write the URL list to the
        # workdir so the invocation is reproducible.
        base = Path(ctx.workdir) if ctx.workdir else Path(".")
        list_path = base / "inputs" / _safe_name(host) / "crlfuzz-urls.txt"
        list_path.parent.mkdir(parents=True, exist_ok=True)
        list_path.write_text("\n".join(urls), encoding="utf-8")
        cmd = [bin_path or DEFAULT_BIN["crlfuzz"], "-l", str(list_path), "-s"]
        result = runner.run(
            "crlfuzz", cmd, stage="xss", host=host,
            parser="kxss", timeout=timeout, check=True,
        )
        return result.items
    return _stage


# ============================================================
# kxss — reflected-parameter detection over URLs with querystrings
# ============================================================


def kxss_command(*, bin_path: str = "kxss") -> list[str]:
    """kxss reads URLs from stdin; no flags."""
    return [bin_path]


def make_kxss_stage(*, bin_path: Optional[str] = None,
                    timeout: float = 300.0,
                    max_urls: int = 500) -> StageFn:
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        raw = ctx.extras.get("urls_params") or ctx.extras.get("urls") or []
        # kxss only makes sense on parameterized URLs; cap the rest.
        urls = [u for u in _xss_pool(raw, cap=max_urls) if "?" in u]
        if not urls:
            return []
        result = runner.run_streaming(
            "kxss", ["kxss"], stage="xss", host=host,
            parser="kxss", timeout=timeout, check=True,
            stdin="\n".join(urls),
        )
        return result.items
    return _stage


# ============================================================
# hakrawler — second crawler (js-crawl, in-scope only)
# ============================================================


def hakrawler_command(target: str, *, bin_path: str = "hakrawler",
                      depth: int = 2, timeout: float = 300.0) -> list[str]:
    """hakrawler -d <depth> -sink <url> (positional URL, stdin unused)."""
    return [bin_path, "-d", str(depth), "-i", "-sink", target]


def make_hakrawler_stage(*, bin_path: Optional[str] = None, depth: int = 2,
                         timeout: float = 300.0) -> StageFn:
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        target = host if host.startswith(("http://", "https://")) else f"https://{host}"
        cmd = hakrawler_command(target, bin_path=bin_path or DEFAULT_BIN["hakrawler"],
                                depth=depth, timeout=timeout)
        result = runner.run_streaming(
            "hakrawler", cmd, stage="crawl", host=host,
            parser="katana", timeout=timeout, check=True,
            stdin=f"{target}\n",
        )
        # Share crawled URLs with downstream stages (nuclei/xss).
        urls = ctx.extras.setdefault("urls", [])
        for it in result.items:
            if it.kind == "url" and it.value not in urls:
                urls.append(it.value)
        return result.items
    return _stage


# ============================================================
# subjack — subdomain takeover checks (CNAME + every-URL mode)
# ============================================================


def subjack_command(domain: str, *, bin_path: str = "subjack",
                    timeout: float = 300.0) -> list[str]:
    """subjack -d <domain> -a -v — all-URL mode with verbose findings."""
    return [bin_path, "-d", domain, "-a", "-v"]


def make_subjack_stage(*, bin_path: Optional[str] = None,
                       timeout: float = 300.0) -> StageFn:
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        cmd = subjack_command(host, bin_path=bin_path or DEFAULT_BIN["subjack"],
                              timeout=timeout)
        result = runner.run(
            "subjack", cmd, stage="takeover", host=host,
            parser="subjack", timeout=timeout, check=True,
        )
        return result.items
    return _stage


# ============================================================
# alterx — subdomain permutation generator (feeds dnsx re-resolve)
# ============================================================


def alterx_command(*, bin_path: str = "alterx") -> list[str]:
    """alterx -silent (subs on stdin, permutations on stdout)."""
    return [bin_path, "-silent"]


def make_alterx_stage(*, bin_path: Optional[str] = None,
                      timeout: float = 120.0,
                      max_perms: int = 5000) -> StageFn:
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        subs = ctx.extras.get("subdomains") or []
        if not subs:
            return []
        # Cap permutations: live-verified 2026-09-04 — alterx happily
        # generated 109,705 perms from 190 subs and starved the dnsx
        # resolve stage. -limit N bounds output at the source.
        result = runner.run_streaming(
            "alterx", ["alterx", "-silent", "-limit", str(max_perms)],
            stage="permute", host=host,
            parser="alterx", timeout=timeout, check=True,
            stdin="\n".join(subs),
        )
        # New permutations join the subdomain pool; the DAG's permute
        # node feeds resolve so they get checked for existence.
        subs = ctx.extras.setdefault("subdomains", [])
        for it in result.items:
            if it.kind == "subdomain" and it.value not in subs:
                subs.append(it.value)
        return result.items
    return _stage


# ============================================================
# gowitness — screenshots of live hosts (evidence capture)
# ============================================================


def _chrome_path() -> Optional[str]:
    """Resolve a usable Chrome binary for gowitness.

    Preference: LOOM_CHROME_PATH override → Playwright's bundled
    chromium (live-verified working headless 2026-09-05) → system
    chromium-browser → snap chromium. Returns None if nothing found
    (gowitness then falls back to downloading its own, which needs
    network + cache perms).
    """
    cands = [
        os.environ.get("LOOM_CHROME_PATH", ""),
        str(Path.home() / ".cache/ms-playwright/chromium-1234"
            / "chrome-linux64/chrome"),
        "/usr/bin/chromium-browser",
        "/snap/bin/chromium",
    ]
    for c in cands:
        if c and Path(c).is_file() and os.access(c, os.X_OK):
            return c
    return None


def gowitness_command(targets_file: Path | str, shot_dir: Path | str, *,
                      bin_path: str = "gowitness",
                      chrome_path: Optional[str] = None,
                      threads: int = 4,
                      timeout: float = 600.0) -> list[str]:
    """gowitness scan file -f <targets> -s <shotdir> (batch mode).

    Live-verified 2026-09-05 against public-firing-range: writes one
    .jpeg per target into shot_dir with -q --write-stdout.
    """
    cmd = [
        bin_path, "scan", "file", "-f", str(targets_file),
        "-s", str(shot_dir), "-q", "--write-stdout",
        "-t", str(threads),
    ]
    if chrome_path:
        cmd += ["--chrome-path", chrome_path]
    return cmd


def _screenshots_in(shot_dir: Path) -> list[Path]:
    """Screenshot files under a dir (deterministic order)."""
    if not shot_dir.is_dir():
        return []
    return sorted(
        p for p in shot_dir.rglob("*")
        if p.is_file() and p.suffix.lower() in (".png", ".jpeg", ".jpg")
    )


def make_gowitness_stage(*, bin_path: Optional[str] = None,
                         timeout: float = 600.0,
                         max_hosts: int = 25,
                         threads: int = 4) -> StageFn:
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        # Screenshot every known live host (root first). Shots persist
        # under screenshots/<host>/; one screenshot item per file is
        # returned for DAG counts (the raw run event records the
        # invocation itself, per the single-emitter rule).
        # LIMITATION (live 2026-09-05): Chrome Safe Browsing refuses to
        # render flagged vuln targets (ERR_BLOCKED_BY_CLIENT on
        # testasp.vulnweb.com) and gowitness exposes no override flag —
        # those hosts yield no shots on ANY chrome-based tool.
        host = _bare_host(host)
        targets = [_target_for(ctx, h)
                   for h in _live_hosts(ctx, host)][:max_hosts]
        if not targets:
            return []
        base = runner.workdir or ctx.workdir or Path.cwd()
        tdir = base / "inputs" / _safe_name(host)
        tdir.mkdir(parents=True, exist_ok=True)
        tfile = tdir / "gowitness-targets.txt"
        tfile.write_text("\n".join(targets), encoding="utf-8")
        shot_dir = base / "screenshots" / _safe_name(host)
        shot_dir.mkdir(parents=True, exist_ok=True)
        cmd = gowitness_command(
            tfile, shot_dir,
            bin_path=bin_path or DEFAULT_BIN["gowitness"],
            chrome_path=_chrome_path(), threads=threads, timeout=timeout,
        )
        runner.run(
            "gowitness", cmd, stage="screenshot", host=host,
            parser="raw", timeout=timeout, check=True,
        )
        return [
            OutputItem(kind="screenshot", value=str(p),
                       evidence={"source": "gowitness", "host": host})
            for p in _screenshots_in(shot_dir)
        ]
    return _stage
