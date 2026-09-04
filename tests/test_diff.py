"""Tests for `loom diff` — run-over-run delta for overnight triage.

An agent watching nightly sweeps asks "what's NEW since yesterday?":
new subdomains, urls, hosts, findings (and what disappeared).
Pure set-diffs on (type, value, source) over two runs' eventlogs.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from loom.state import State


def _seed_run(tmp_path: Path, domain: str, subs: list[str],
              findings: list[str]) -> int:
    st = State(tmp_path / "loom.sqlite")
    rid = st.start_run(domain, mode="recon", scope_profile="default",
                       pipeline="deep")
    st.finish_run(rid)
    evdir = tmp_path / f"run-{rid}"
    evdir.mkdir(parents=True, exist_ok=True)
    with (evdir / "events.jsonl").open("w") as f:
        for s in subs:
            f.write(json.dumps({"type": "subdomain", "value": s,
                                "source": "subfinder", "host": domain,
                                "ts": 1.0}) + "\n")
        for fl in findings:
            f.write(json.dumps({"type": "finding", "value": fl,
                                "source": "nuclei", "host": domain,
                                "evidence": {"severity": "high"},
                                "ts": 2.0}) + "\n")
    st.close()
    return rid


class TestDiff:
    def test_new_and_removed(self, tmp_path, capsys):
        from loom import cli
        _seed_run(tmp_path, "example.com",
                  ["a.example.com", "b.example.com"], ["https://a.example.com/x"])
        _seed_run(tmp_path, "example.com",
                  ["b.example.com", "c.example.com"], ["https://a.example.com/x"])
        code = cli.main(["--workdir", str(tmp_path), "diff",
                         "--from", "1", "--to", "2"])
        assert code == 0
        out = capsys.readouterr().out
        assert "c.example.com" in out      # new sub
        assert "a.example.com" in out      # removed sub
        assert "b.example.com" not in out  # unchanged: silent

    def test_json_shape(self, tmp_path, capsys):
        from loom import cli
        _seed_run(tmp_path, "example.com", ["a.example.com"], [])
        _seed_run(tmp_path, "example.com", ["a.example.com", "n.example.com"],
                  ["https://n.example.com/y"])
        code = cli.main(["--workdir", str(tmp_path), "diff",
                         "--from", "1", "--to", "2", "--json"])
        assert code == 0
        data = json.loads(capsys.readouterr().out)
        assert data["from"] == 1 and data["to"] == 2
        assert "n.example.com" in data["added"]["subdomain"]
        assert "https://n.example.com/y" in [
            f["value"] for f in data["added"]["finding"]]
        assert data["removed"] == {"subdomain": [], "url": [], "host": [],
                                   "finding": [], "takeover": []}

    def test_defaults_to_newest_two(self, tmp_path, capsys):
        from loom import cli
        _seed_run(tmp_path, "example.com", ["a.example.com"], [])
        _seed_run(tmp_path, "example.com", ["a.example.com", "z.example.com"], [])
        code = cli.main(["--workdir", str(tmp_path), "diff"])
        assert code == 0
        assert "z.example.com" in capsys.readouterr().out

    def test_unknown_run_is_1(self, tmp_path, capsys):
        from loom import cli
        _seed_run(tmp_path, "example.com", ["a.example.com"], [])
        code = cli.main(["--workdir", str(tmp_path), "diff",
                         "--from", "1", "--to", "99"])
        assert code == 1

    def test_identical_runs_report_clean(self, tmp_path, capsys):
        from loom import cli
        _seed_run(tmp_path, "example.com", ["a.example.com"], [])
        _seed_run(tmp_path, "example.com", ["a.example.com"], [])
        code = cli.main(["--workdir", str(tmp_path), "diff",
                         "--from", "1", "--to", "2"])
        assert code == 0
        assert "no changes" in capsys.readouterr().out.lower()
