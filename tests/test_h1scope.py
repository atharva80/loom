"""Tests for the HackerOne scope CSV parser.

Uses the real Twilio + Verily scope exports (the actual files the
user pasted) to verify mixed-asset handling: wildcards, URLs, APIs,
mobile app IDs, OTHER categories, and out-of-scope denials.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from loom.h1scope import (
    H1Scope,
    host_from_row,
    parse_h1_scope_csv,
    scope_to_profile,
    strip_scheme,
    wildcard_base,
)


TWILIO_CSV = """identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,availability_requirement,confidentiality_requirement,integrity_requirement,max_severity,system_tags,created_at,updated_at
api.twilio.com,API,Twilio Primary Targets,true,true,,,,critical,,2025-10-20 18:08:31 UTC,2025-10-23 14:54:47 UTC
Twilio APIs,API,Twilio Primary Targets,true,true,,,,critical,,2025-10-20 18:08:55 UTC,2025-10-23 14:51:46 UTC
http://tsock.us1.twilio.com,URL,,true,true,,,,critical,,2025-10-20 18:09:28 UTC,2025-10-23 14:54:04 UTC
*.sip.*.twilio.com,WILDCARD,,true,true,,,,critical,,2025-10-20 18:09:49 UTC,2025-10-23 14:55:16 UTC
https://www.twilio.com/en-us/blog/get-started-webrtc,OTHER,,true,true,,,,critical,,2025-10-20 18:11:25 UTC,2025-10-23 14:52:58 UTC
static*.twilio.com,WILDCARD,Twilio CDNs,true,true,,,,critical,,2025-10-20 18:17:39 UTC,2025-10-20 18:17:39 UTC
https://www.authy.com/download/,GOOGLE_PLAY_APP_ID,,true,true,,,,critical,,2025-10-20 18:22:25 UTC,2025-10-20 18:22:25 UTC
status.twilio.com,URL,,false,false,,,,critical,,2025-10-20 21:33:31 UTC,2025-10-20 21:33:31 UTC
store.twilio.com,URL,,false,false,,,,critical,,2025-10-20 21:33:40 UTC,2025-10-20 21:33:40 UTC
Twilio Quest,OTHER,,false,false,,,,critical,,2025-10-20 21:40:46 UTC,2025-10-20 21:40:46 UTC
"""

VERILY_CSV = """identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,availability_requirement,confidentiality_requirement,integrity_requirement,max_severity,system_tags,created_at,updated_at
https://*.verily.com/,WILDCARD,helix out of scope,true,true,,,,critical,,2024-11-11 19:13:30 UTC,2026-01-02 22:01:52 UTC
https://*.projectbaseline.com/,WILDCARD,,true,true,,,,low,,2024-11-11 19:16:27 UTC,2025-11-17 18:40:02 UTC
https://*.signalpath.com/,WILDCARD,,true,true,,,,critical,,2024-11-11 19:17:02 UTC,2024-11-11 19:17:02 UTC
https://apps.apple.com/us/app/verily-me/id6448808133,APPLE_STORE_APP_ID,,true,true,,,,critical,,2024-11-11 19:27:12 UTC,2024-11-11 19:27:12 UTC
https://play.google.com/store/apps/details?id=com.verily.me,GOOGLE_PLAY_APP_ID,,true,true,,,,critical,,2024-11-13 18:40:32 UTC,2024-11-13 18:40:32 UTC
https://*.verilyme.com/,WILDCARD,,true,true,,,,critical,,2025-11-17 18:39:33 UTC,2025-11-17 18:39:33 UTC
"""


class TestParsers:
    def test_strip_scheme(self):
        assert strip_scheme("https://x.com/a?b=1#c") == "x.com"
        assert strip_scheme("http://tsock.us1.twilio.com") == "tsock.us1.twilio.com"
        assert strip_scheme("api.twilio.com") == "api.twilio.com"

    def test_wildcard_base(self):
        assert wildcard_base("*.twilio.com") == "twilio.com"
        assert wildcard_base("*.sip.*.twilio.com") == "twilio.com"
        assert wildcard_base("https://*.verily.com/") == "verily.com"
        assert wildcard_base("static*.twilio.com") == "twilio.com"
        assert wildcard_base("*.verilyme.com/") == "verilyme.com"
        # ccTLD second-level: anduril.com.au stays 3 labels
        assert wildcard_base("*.anduril.com.au") == "anduril.com.au"
        assert wildcard_base("https://*.anduril.au/") == "anduril.au"

    def test_host_from_row(self):
        assert host_from_row("api.twilio.com", "API") == "api.twilio.com"
        assert host_from_row("https://help.twilio.com", "URL") == "help.twilio.com"
        assert host_from_row("*.twilio.com", "WILDCARD") == "twilio.com"
        assert host_from_row("Twilio APIs", "API") is None  # category label
        assert host_from_row("https://www.authy.com/download/", "GOOGLE_PLAY_APP_ID") is None
        assert host_from_row("Twilio Quest", "OTHER") is None


class TestParseTwilio:
    def test_real_twilio_csv(self, tmp_path: Path):
        f = tmp_path / "twilio.csv"
        f.write_text(TWILIO_CSV)
        scope = parse_h1_scope_csv(f)
        assert scope.program == "twilio"
        # in-scope web hosts
        assert "api.twilio.com" in scope.in_scope_hosts
        assert "tsock.us1.twilio.com" in scope.in_scope_hosts
        assert "twilio.com" in scope.in_scope_hosts          # wildcard base
        assert "static*.twilio.com" not in scope.in_scope_hosts  # weird wildcard → twilio.com
        # OOS hosts are denied, not in-scope
        assert "status.twilio.com" not in scope.in_scope_hosts
        assert "status.twilio.com" in scope.denied_hosts
        assert "store.twilio.com" in scope.denied_hosts
        # path-level OOS rows must NOT deny the in-scope wildcard host
        assert "twilio.com" in scope.in_scope_hosts
        assert "twilio.com" not in scope.denied_hosts
        assert "segment.com" not in scope.denied_hosts
        # mobile apps separated + deduped (Play + Store rows → same URL)
        assert scope.mobile_apps == ["https://www.authy.com/download/"]
        # OTHER categories
        assert any("get-started-webrtc" in s for s in scope.other_in_scope)
        assert any("Twilio Quest" in s for s in scope.other_out_of_scope)
        # dedup: wildcard base == bare twilio.com rows collapse
        assert scope.in_scope_hosts.count("twilio.com") == 1

    def test_twilio_profile(self, tmp_path: Path):
        f = tmp_path / "twilio.csv"
        f.write_text(TWILIO_CSV)
        scope = parse_h1_scope_csv(f)
        prof = scope_to_profile(scope)
        assert prof["headers"]["X-Bug-Bounty"] == "drstrangexd"
        assert prof["headers"]["X-HackerOne-Research"] == "drstrangexd"
        assert "status.twilio.com" in prof["denied_hosts"]
        assert prof["rate_limit_rps"] == 30


class TestParseVerily:
    def test_real_verily_csv(self, tmp_path: Path):
        f = tmp_path / "verily.csv"
        f.write_text(VERILY_CSV)
        scope = parse_h1_scope_csv(f)
        assert "verily.com" in scope.in_scope_hosts
        assert "projectbaseline.com" in scope.in_scope_hosts
        assert "signalpath.com" in scope.in_scope_hosts
        assert "verilyme.com" in scope.in_scope_hosts
        # 2 mobile apps
        assert len(scope.mobile_apps) == 2
        assert any("id6448808133" in a for a in scope.mobile_apps)
        assert any("com.verily.me" in a for a in scope.mobile_apps)
        # no OOS hosts in this file
        assert scope.denied_hosts == []


class TestRobustness:
    def test_headerless_csv(self, tmp_path: Path):
        """Older H1 exports have no header row: [identifier, asset_type]."""
        f = tmp_path / "noheader.csv"
        f.write_text("api.example.com,URL\n*.example.org,WILDCARD\n")
        scope = parse_h1_scope_csv(f)
        assert "api.example.com" in scope.in_scope_hosts
        assert "example.org" in scope.in_scope_hosts

    def test_empty_file(self, tmp_path: Path):
        f = tmp_path / "empty.csv"
        f.write_text("")
        assert parse_h1_scope_csv(f).in_scope_hosts == []

    def test_missing_file(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            parse_h1_scope_csv(tmp_path / "nope.csv")
