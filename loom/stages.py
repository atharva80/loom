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
import shlex
from typing import Optional

from .pipeline import PipelineContext, StageFn
from .runner import OutputItem, Runner


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
                  ports: str = "top-100", timeout: float = 180.0) -> list[str]:
    return [bin_path, "-host", host, "-ports", ports, "-silent", "-no-color"]


def make_naabu_stage(*, bin_path: Optional[str] = None, ports: str = "top-100",
                     timeout: float = 180.0) -> StageFn:
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        cmd = naabu_command(host, bin_path=bin_path or DEFAULT_BIN["naabu"],
                            ports=ports, timeout=timeout)
        result = runner.run(
            "naabu", cmd, stage="portscan", host=host,
            parser="naabu", timeout=timeout, check=True,
        )
        return result.items
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
                      timeout: float = 600.0) -> StageFn:
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        # Scan the URLs collected by earlier stages when available
        # (ctx.extras["urls"]), else the host. Focus templates on the
        # detected tech stack when fingerprinting produced one.
        tags = _tech_tags(ctx.extras.get("tech", set()))
        urls = ctx.extras.get("urls")
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


def make_ffuf_stage(*, bin_path: Optional[str] = None, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                    timeout: float = 300.0) -> StageFn:
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        url = host if host.startswith(("http://", "https://")) else f"https://{host}"
        cmd = [
            bin_path or DEFAULT_BIN["ffuf"],
            "-u", f"{url}/FUZZ",
            "-w", wordlist,
            "-silent", "-noninteractive",
            "-mc", "200,201,204,301,302,307,401,403,405",
        ]
        result = runner.run(
            "ffuf", cmd, stage="fuzz", host=host,
            parser="raw", timeout=timeout, check=True,
        )
        return result.items
    return _stage
