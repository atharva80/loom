"""Test suite for loom.scope — scope profile loader and enforcer."""
import pytest
from pathlib import Path

from loom.scope import Scope, from_dict, from_file, bundled, _glob_match


# ---------- _glob_match unit tests ----------

def test_glob_match_bare_star():
    assert _glob_match("anything.com", "*")
    assert _glob_match("a.b.c", "*")


def test_glob_match_exact():
    assert _glob_match("api.example.com", "api.example.com")
    assert not _glob_match("www.example.com", "api.example.com")


def test_glob_match_leading_star_matches_prefix():
    # *.api.example.com should match api.example.com (no prefix) and any prefix
    assert _glob_match("api.example.com", "*.api.example.com")
    assert _glob_match("v1.api.example.com", "*.api.example.com")
    assert _glob_match("v1.v2.api.example.com", "*.api.example.com")
    assert not _glob_match("www.example.com", "*.api.example.com")


def test_glob_match_no_star():
    assert _glob_match("foo.bar.com", "foo.bar.com")
    assert not _glob_match("xfoo.bar.com", "foo.bar.com")


def test_glob_match_case_sensitive():
    assert not _glob_match("API.example.com", "*.api.example.com")
    # (caller lowercases before calling)


def test_from_dict_minimal():
    s = from_dict({"target": "example.com"})
    assert s.target == "example.com"
    assert s.rate_limit_rps == 100  # default
    assert s.allowed_hosts == []
    assert s.banned_tools == []


def test_from_dict_requires_target():
    with pytest.raises(ValueError, match="target"):
        from_dict({})


def test_from_dict_validates_rate_limit():
    with pytest.raises(ValueError, match="rate_limit_rps"):
        from_dict({"target": "x.com", "rate_limit_rps": -1})


def test_from_file_loads_yaml(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text("""
name: test
target: example.com
rate_limit_rps: 25
headers:
  X-Bug-Bounty: axrva
banned_tools: [nmap, sqlmap]
banned_techniques: [dns_brute]
""")
    s = from_file(p)
    assert s.name == "test"
    assert s.target == "example.com"
    assert s.rate_limit_rps == 25
    assert s.headers == {"X-Bug-Bounty": "axrva"}
    assert s.banned_tools == ["nmap", "sqlmap"]
    assert s.banned_techniques == ["dns_brute"]


def test_from_file_missing_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        from_file(tmp_path / "nope.yaml")


def test_is_host_allowed_subdomain_match():
    s = from_dict({"target": "example.com"})
    assert s.is_host_allowed("example.com")
    assert s.is_host_allowed("api.example.com")
    assert s.is_host_allowed("a.b.c.example.com")


def test_is_host_allowed_denied_pattern():
    s = from_dict({
        "target": "example.com",
        "denied_hosts": ["*.api.example.com", "staging.example.com"],
    })
    assert s.is_host_allowed("example.com")
    assert s.is_host_allowed("www.example.com")
    assert not s.is_host_allowed("api.example.com")
    assert not s.is_host_allowed("v1.api.example.com")
    assert not s.is_host_allowed("staging.example.com")


def test_is_host_allowed_explicit_allowed_hosts():
    s = from_dict({
        "target": "example.com",
        "allowed_hosts": ["*.partner.io", "cdn.example.com"],
    })
    assert s.is_host_allowed("api.partner.io")
    assert s.is_host_allowed("cdn.example.com")
    assert not s.is_host_allowed("random.com")


def test_is_host_allowed_case_insensitive():
    s = from_dict({"target": "Example.com"})
    assert s.is_host_allowed("API.example.com")
    assert s.is_host_allowed("Api.Example.Com")


def test_is_tool_allowed():
    s = from_dict({"target": "x.com", "banned_tools": ["nmap", "sqlmap"]})
    assert not s.is_tool_allowed("nmap")
    assert not s.is_tool_allowed("NMAP")
    assert not s.is_tool_allowed("sqlmap")
    assert s.is_tool_allowed("nuclei")
    assert s.is_tool_allowed("httpx")


def test_is_technique_allowed():
    s = from_dict({"target": "x.com", "banned_techniques": ["dns_brute"]})
    assert not s.is_technique_allowed("dns_brute")
    assert not s.is_technique_allowed("DNS_BRUTE")
    assert s.is_technique_allowed("dns_resolve")


def test_request_headers_includes_ua():
    s = from_dict({
        "target": "x.com",
        "headers": {"X-Custom": "value"},
        "required_user_agent": "loom/1.0",
    })
    h = s.request_headers()
    assert h["X-Custom"] == "value"
    assert h["User-Agent"] == "loom/1.0"


def test_request_headers_no_ua_means_no_ua():
    s = from_dict({"target": "x.com", "headers": {"X-Custom": "v"}})
    h = s.request_headers()
    assert "User-Agent" not in h
    assert h["X-Custom"] == "v"


def test_bundled_default_requires_target():
    with pytest.raises(ValueError, match="target"):
        bundled("default")


def test_bundled_default_with_target():
    s = bundled("default", target="example.com")
    assert s.target == "example.com"
    assert s.rate_limit_rps == 100


def test_bundled_verily():
    s = bundled("verily", target="verily.com")
    assert s.target == "verily.com"
    assert s.rate_limit_rps == 50
    assert s.banned_techniques == ["dns_brute", "high_volume_scan"]
    assert "X-Bug-Bounty" in s.headers
    assert "*.api.verily.com" in s.denied_hosts
    assert not s.is_host_allowed("api.verily.com")
    assert s.is_host_allowed("www.verily.com")


def test_bundled_fast():
    s = bundled("fast", target="example.com")
    assert s.rate_limit_rps == 300


def test_bundled_unknown_raises():
    with pytest.raises(KeyError, match="unknown bundled scope"):
        bundled("nope", target="x.com")


def test_scope_to_dict_roundtrip():
    s = from_dict({
        "target": "example.com",
        "rate_limit_rps": 50,
        "headers": {"X-A": "B"},
        "banned_tools": ["nmap"],
    })
    d = s.to_dict()
    s2 = from_dict(d)
    assert s2.target == s.target
    assert s2.rate_limit_rps == s.rate_limit_rps
    assert s2.headers == s.headers
    assert s2.banned_tools == s.banned_tools
