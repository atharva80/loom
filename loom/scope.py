"""loom.scope — Scope profile loader and enforcer.

A scope profile is a YAML file describing per-program ROE:
  - target (root domain)
  - allowed_hosts / denied_hosts (subdomain patterns)
  - headers (mandatory on every request, e.g. X-Bug-Bounty)
  - rate_limit_rps (global cap, distributed across tools)
  - banned_tools (program forbids)
  - banned_techniques (e.g. 'dns_brute', 'active_sub_enum')
  - required_user_agent

The Scope object is consulted by:
  - tool runner (to add headers, throttle, refuse banned tools)
  - pipeline (to skip stages that use banned techniques)
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import re
import yaml


def _glob_match(host: str, pattern: str) -> bool:
    """Glob match for host patterns.

    - `*` matches any number of characters INCLUDING dots
    - A leading `*.<rest>` matches both `<rest>` (zero-length prefix) and
      `prefix.<rest>` (any prefix) — so `*.api.example.com` denies both
      `api.example.com` and `v1.api.example.com` (matches ROE doc intent).
    - A bare `*` matches everything.
    - A pattern with no `*` must match exactly.
    """
    if pattern == "*":
        return True

    # Build a regex from the glob parts.
    parts = pattern.split(".")
    seg_patterns = []
    for p in parts:
        if p == "*":
            seg_patterns.append("__STAR__")
        else:
            seg_patterns.append(re.escape(p))

    # A leading `*.<seg>...` should be optional at the start: pattern can be
    # either just the tail segments, or the tail with arbitrary additional
    # segments before. We model that by allowing the entire regex to be
    # prefixed with `(?:.+\.)?`.
    if seg_patterns and seg_patterns[0] == "__STAR__":
        head = r"(?:.+\.)?"
        seg_patterns = seg_patterns[1:]
    else:
        head = ""

    # Join segments with literal dots
    body = r"\.".join(seg_patterns)
    regex = head + body

    return re.fullmatch(regex, host) is not None


@dataclass
class Scope:
    name: str
    target: str
    allowed_hosts: list[str] = field(default_factory=list)
    denied_hosts: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    rate_limit_rps: int = 100
    banned_tools: list[str] = field(default_factory=list)
    banned_techniques: list[str] = field(default_factory=list)
    required_user_agent: Optional[str] = None
    follow_redirects: bool = True
    verify_tls: bool = True

    def is_host_allowed(self, host: str) -> bool:
        """Returns True if host is in scope (matches target or allowed pattern, not denied)."""
        host = host.lower().strip()
        target = self.target.lower().strip()
        # exact or subdomain match
        if host == target or host.endswith("." + target):
            in_scope = True
        else:
            in_scope = any(_glob_match(host, p.lower()) for p in self.allowed_hosts)

        if not in_scope:
            return False

        # denied takes precedence
        for pat in self.denied_hosts:
            if _glob_match(host, pat.lower()):
                return False
        return True

    def is_tool_allowed(self, tool: str) -> bool:
        return tool.lower() not in {t.lower() for t in self.banned_tools}

    def is_technique_allowed(self, technique: str) -> bool:
        return technique.lower() not in {t.lower() for t in self.banned_techniques}

    def request_headers(self) -> dict[str, str]:
        h = dict(self.headers)
        if self.required_user_agent:
            h["User-Agent"] = self.required_user_agent
        return h

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "target": self.target,
            "allowed_hosts": self.allowed_hosts,
            "denied_hosts": self.denied_hosts,
            "headers": self.headers,
            "rate_limit_rps": self.rate_limit_rps,
            "banned_tools": self.banned_tools,
            "banned_techniques": self.banned_techniques,
            "required_user_agent": self.required_user_agent,
            "follow_redirects": self.follow_redirects,
            "verify_tls": self.verify_tls,
        }


def _validate(scope: Scope) -> None:
    if not scope.target:
        raise ValueError("scope.target is required")
    if scope.rate_limit_rps < 0:
        raise ValueError("rate_limit_rps must be >= 0")


def from_file(path: str | Path) -> Scope:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"scope file not found: {p}")
    data = yaml.safe_load(p.read_text()) or {}
    if "target" not in data:
        raise ValueError(f"scope file {p} missing required field: target")
    name = data.get("name", p.stem)
    scope = Scope(
        name=name,
        target=data["target"],
        allowed_hosts=data.get("allowed_hosts", []),
        denied_hosts=data.get("denied_hosts", []),
        headers=data.get("headers", {}),
        rate_limit_rps=int(data.get("rate_limit_rps", 100)),
        banned_tools=data.get("banned_tools", []),
        banned_techniques=data.get("banned_techniques", []),
        required_user_agent=data.get("required_user_agent"),
        follow_redirects=bool(data.get("follow_redirects", True)),
        verify_tls=bool(data.get("verify_tls", True)),
    )
    _validate(scope)
    return scope


def from_dict(data: dict) -> Scope:
    if "target" not in data:
        raise ValueError("scope dict missing required field: target")
    scope = Scope(
        name=data.get("name", "ad-hoc"),
        target=data["target"],
        allowed_hosts=data.get("allowed_hosts", []),
        denied_hosts=data.get("denied_hosts", []),
        headers=data.get("headers", {}),
        rate_limit_rps=int(data.get("rate_limit_rps", 100)),
        banned_tools=data.get("banned_tools", []),
        banned_techniques=data.get("banned_techniques", []),
        required_user_agent=data.get("required_user_agent"),
        follow_redirects=bool(data.get("follow_redirects", True)),
        verify_tls=bool(data.get("verify_tls", True)),
    )
    _validate(scope)
    return scope


# Built-in profiles (loadable by name from loom.scopes.bundled())
BUNDLED = {
    "default": {
        "target": "REQUIRED",
        "rate_limit_rps": 100,
        "headers": {},
    },
    "verily": {
        "name": "verily",
        "target": "verily.com",
        "rate_limit_rps": 50,
        "headers": {
            "X-Bug-Bounty": "axrva-drstrangexd",
            "X-HackerOne-Research": "axrva",
        },
        "banned_techniques": ["dns_brute", "high_volume_scan"],
        "denied_hosts": ["*.api.verily.com"],
        "required_user_agent": "axrva-recon/1.0 (axrva@hackerone)",
    },
    "fast": {
        "name": "fast",
        "target": "REQUIRED",
        "rate_limit_rps": 300,
        "headers": {},
    },
}


def bundled(name: str, target: Optional[str] = None) -> Scope:
    if name not in BUNDLED:
        raise KeyError(f"unknown bundled scope: {name}; available: {list(BUNDLED)}")
    data = dict(BUNDLED[name])
    if target:
        data["target"] = target
    if data["target"] == "REQUIRED":
        raise ValueError(f"bundled scope {name} requires a target")
    return from_dict(data)
