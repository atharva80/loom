"""HackerOne scope CSV parser — turns a real program scope export
(like Twilio's or Verily's) into loom-ready target lists.

The H1 scope CSV mixes asset types on purpose:
  - WILDCARD          → expand to a base domain for subdomain enum
  - URL               → exact host (strip scheme/path)
  - API               → may be a bare hostname OR a category label
  - GOOGLE_PLAY/APPLE_STORE_APP_ID → mobile app (web-unreachable;
                       kept separate so web scans skip them)
  - OTHER             → free-text category, no host (skipped for web)

Eligibility flags are authoritative:
  - eligible_for_bounty=false  OR
  - eligible_for_submission=false
  → the row is OUT OF SCOPE; its host (if any) becomes a denied_host
    so the runner refuses to touch it.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field
from pathlib import Path

# Asset types that can produce a web-reachable host.
WEB_TYPES = {"WILDCARD", "URL", "API"}
# Asset types that are mobile apps (web scans must skip them).
MOBILE_TYPES = {"GOOGLE_PLAY_APP_ID", "APPLE_STORE_APP_ID"}

_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)


def strip_scheme(s: str) -> str:
    """Remove scheme + path; keep host[:port]. 'https://x.com/a' → 'x.com'."""
    s = _SCHEME_RE.sub("", s.strip())
    s = s.split("/", 1)[0]
    s = s.split("?", 1)[0]
    s = s.split("#", 1)[0]
    return s.strip()


_CC_TLD = {"com", "co", "net", "org", "gov", "edu", "ac", "mil", "gen", "id", "or"}


def wildcard_base(s: str) -> str:
    """'*.sip.*.twilio.com' → 'twilio.com'; 'https://*.verily.com/' → 'verily.com'.

    Handles multi-level wildcards AND ccTLD second-level domains:
    '*.anduril.com.au' → 'anduril.com.au' (not 'com.au').
    """
    s = strip_scheme(s)
    s = s.lstrip("*.")
    parts = [p for p in s.split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    # 3+ labels: if it's a ccTLD domain (last = 2-letter ccTLD and
    # second-last in the commercial set), keep 3 labels.
    if len(parts[-1]) == 2 and parts[-2].lower() in _CC_TLD:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def host_from_row(identifier: str, asset_type: str) -> str | None:
    """Extract a web host from one scope row, or None if the row has
    no web-reachable host (category labels, mobile apps, OOS text)."""
    if asset_type not in WEB_TYPES:
        return None
    id_ = identifier.strip()
    if not id_:
        return None
    if asset_type == "WILDCARD":
        return wildcard_base(id_)
    # URL / API: strip scheme + path; must look like a host
    host = strip_scheme(id_)
    if not host or " " in host or host.startswith("*"):
        # category label like "Twilio APIs" or bare "*"
        return None
    if "." not in host:
        return None
    return host.lower()


@dataclass
class H1Scope:
    """Parsed program scope."""

    program: str = ""
    in_scope_hosts: list[str] = field(default_factory=list)
    in_scope_host_set: set[str] = field(default_factory=set)
    mobile_apps: list[str] = field(default_factory=list)
    denied_hosts: list[str] = field(default_factory=list)
    other_in_scope: list[str] = field(default_factory=list)
    other_out_of_scope: list[str] = field(default_factory=list)

    def add_host(self, host: str) -> None:
        if host not in self.in_scope_host_set:
            self.in_scope_host_set.add(host)
            self.in_scope_hosts.append(host)


def parse_h1_scope_csv(path: str | Path) -> H1Scope:
    """Parse an H1 scope CSV into an H1Scope.

    Column order in H1 exports (as of 2026):
      identifier, asset_type, instruction, eligible_for_bounty,
      eligible_for_submission, ...
    Older exports may lack headers (identifier first). We detect the
    header row by looking for 'identifier' / 'asset_type' / 'eligible'.
    """
    scope = H1Scope(program=Path(path).stem)
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        rows = list(reader)
    if not rows:
        return scope

    # Find header row: the row containing 'identifier' and 'asset_type'.
    header_idx = None
    header = None
    for i, row in enumerate(rows[:5]):
        lowered = [c.lower().strip() for c in row]
        if "identifier" in lowered and "asset_type" in lowered:
            header_idx = i
            header = lowered
            break
    if header is None:
        # No header — assume columns are [identifier, asset_type, ...]
        header = ["identifier", "asset_type"]
        header_idx = -1
        data_rows = rows
    else:
        data_rows = rows[header_idx + 1:]

    def col(name: str) -> int | None:
        try:
            return header.index(name)
        except ValueError:
            return None

    i_id = col("identifier")
    i_type = col("asset_type")
    i_bounty = col("eligible_for_bounty")
    i_submit = col("eligible_for_submission")
    if i_id is None or i_type is None:
        return scope

    i_id = int(i_id)
    i_type = int(i_type)

    for row in data_rows:
        if len(row) <= max(i_id, i_type):
            continue
        identifier = row[i_id].strip()
        asset_type = row[i_type].strip().upper()
        if not identifier or not asset_type:
            continue

        eligible = True
        if i_bounty is not None and len(row) > i_bounty:
            v = row[i_bounty].strip().lower()
            if v in ("false", "0", "no", ""):
                eligible = False
        if i_submit is not None and len(row) > i_submit:
            v = row[i_submit].strip().lower()
            if v in ("false", "0", "no", ""):
                eligible = False

        host = host_from_row(identifier, asset_type)
        if host:
            if eligible:
                scope.add_host(host)
            else:
                # OOS host → denied ONLY if it's not already in-scope.
                # Path-level OOS rows (e.g. "http://twilio.com/labs")
                # share the host with an in-scope wildcard — denying
                # the whole host would block a legit target.
                if host not in scope.in_scope_host_set and host not in scope.denied_hosts:
                    scope.denied_hosts.append(host)
        elif asset_type in MOBILE_TYPES:
            if eligible and identifier not in scope.mobile_apps:
                scope.mobile_apps.append(identifier)
        elif asset_type == "OTHER":
            (scope.other_in_scope if eligible
             else scope.other_out_of_scope).append(identifier)
        elif asset_type in WEB_TYPES:
            # API/URL row that didn't parse to a host (category label)
            if eligible:
                scope.other_in_scope.append(identifier)

    return scope


def scope_to_profile(scope: H1Scope, *, h1_username: str = "drstrangexd",
                     rate_limit_rps: int = 30) -> dict:
    """Build a loom Scope profile dict from an H1Scope.

    Headers follow HackerOne's researcher-identification convention
    (X-Bug-Bounty / X-HackerOne-Research). Rate limit defaults low —
    real programs enforce per-IP limits and ban aggressive scanners.
    """
    return {
        "name": scope.program,
        "target": scope.in_scope_hosts[0] if scope.in_scope_hosts else "REQUIRED",
        "rate_limit_rps": rate_limit_rps,
        "headers": {
            "X-Bug-Bounty": h1_username,
            "X-HackerOne-Research": h1_username,
        },
        "denied_hosts": scope.denied_hosts,
        "required_user_agent": f"{h1_username}-recon/1.0 ({h1_username}@hackerone)",
    }
