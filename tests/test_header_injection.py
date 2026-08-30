"""Regression test: header injection must skip tools that don't support -H.

Found live: dnsx errors "flag provided but not defined: -H" when scope
headers are auto-injected. dnsx is a DNS resolver, not an HTTP client.
Same applies to naabu (port scanner). The fix restricts HEADER_TOOLS
to {httpx, nuclei, katana, ffuf}.
"""

import os
import pytest

from loom.runner import _inject_headers


def test_dnsx_does_not_get_headers_injected():
    """dnsx must never receive -H flags — it errors out."""
    headers = {"X-Bug-Bounty": "drstrangexd", "X-HackerOne-Research": "drstrangexd"}
    cmd = ["/home/axrva/go/bin/dnsx", "-silent", "-resp", "-l", "-"]
    out = _inject_headers(list(cmd), headers)

    # dnsx not in HEADER_TOOLS → cmd unchanged
    assert out == cmd, f"dnsx should not be touched; got {out}"


def test_naabu_does_not_get_headers_injected():
    """naabu must never receive -H flags — it's a port scanner."""
    headers = {"X-Bug-Bounty": "test"}
    cmd = ["/home/axrva/go/bin/naabu", "-silent", "-p", "80,443"]
    out = _inject_headers(list(cmd), headers)
    assert out == cmd


def test_httpx_does_get_headers_injected():
    """httpx supports -H and must receive scope headers."""
    headers = {"X-Bug-Bounty": "test"}
    cmd = ["/home/axrva/go/bin/httpx", "-silent", "-u", "https://x.com"]
    out = _inject_headers(list(cmd), headers)
    assert "-H" in out
    assert any("X-Bug-Bounty: test" in t for t in out)


def test_nuclei_does_get_headers_injected():
    """nuclei supports -H and must receive scope headers."""
    headers = {"X-Bug-Bounty": "test"}
    cmd = ["/home/axrva/go/bin/nuclei", "-u", "https://x.com"]
    out = _inject_headers(list(cmd), headers)
    assert "-H" in out


def test_katana_does_get_headers_injected():
    """katana supports -H and must receive scope headers."""
    headers = {"X-Bug-Bounty": "test"}
    cmd = ["/home/axrva/go/bin/katana", "-u", "https://x.com"]
    out = _inject_headers(list(cmd), headers)
    assert "-H" in out


def test_ffuf_does_get_headers_injected():
    """ffuf supports -H and must receive scope headers."""
    headers = {"X-Bug-Bounty": "test"}
    cmd = ["/home/axrva/go/bin/ffuf", "-u", "https://x.com/FUZZ"]
    out = _inject_headers(list(cmd), headers)
    assert "-H" in out
