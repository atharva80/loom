"""Tests for `loom findings` — cross-run aggregated findings report.

F31: after sweeps, the question is "what did I find?" — not per-run
grep-ing of events.jsonl. loom findings scans every run's eventlog in
a workdir, dedupes, severity-sorts, and prints one table.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from loom.state import State


def _seed_run(tmp_path: Path, run_domain: str, events: list[dict]) -> int:
    st = State(tmp_path / "loom.sqlite")
    run_id = st.start_run(run_domain, mode="recon",
                          scope_profile="ad-hoc", pipeline="full")
    st.finish_run(run_id)
    evdir = tmp_path / f"run-{run_id}"
    evdir.mkdir(parents=True, exist_ok=True)
    with (evdir / "events.jsonl").open("w") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")
    return run_id


class TestFindingsCLI:
    def test_no_runs_exits_1(self, tmp_path, capsys):
        from loom import cli
        wd = tmp_path / "empty"
        wd.mkdir()
        code = cli.main(["--workdir", str(wd), "findings"])
        assert code == 1
        assert "no runs" in capsys.readouterr().err.lower()

    def test_findings_sorted_by_severity(self, tmp_path, capsys):
        from loom import cli
        _seed_run(tmp_path, "vulnweb.com", [
            {"type": "finding", "value": "https://a.vulnweb.com/",
             "source": "nuclei", "host": "a.vulnweb.com",
             "evidence": {"severity": "low", "template_id": "tech-detect"},
             "ts": 1.0},
            {"type": "finding", "value": "https://b.vulnweb.com/db.sql",
             "source": "nuclei", "host": "b.vulnweb.com",
             "evidence": {"severity": "critical", "template_id": "db-exposed"},
             "ts": 2.0},
            {"type": "finding", "value": "https://c.vulnweb.com/x.php",
             "source": "nuclei", "host": "c.vulnweb.com",
             "evidence": {"severity": "medium", "template_id": "php-dump"},
             "ts": 3.0},
        ])
        code = cli.main(["--workdir", str(tmp_path), "findings"])
        assert code == 0
        out = capsys.readouterr().out
        lines = [l for l in out.splitlines() if "vulnweb.com" in l]
        # critical first, low last
        assert "db-exposed" in lines[0]
        assert "critical" in lines[0].lower()
        assert "tech-detect" in lines[-1]

    def test_findings_dedupe_across_runs(self, tmp_path, capsys):
        from loom import cli
        ev = [{"type": "finding", "value": "https://b.vulnweb.com/db.sql",
               "source": "nuclei", "host": "b.vulnweb.com",
               "evidence": {"severity": "critical", "template_id": "db-exposed"},
               "ts": 2.0}]
        _seed_run(tmp_path, "vulnweb.com", ev)
        _seed_run(tmp_path, "vulnweb.com", ev)
        code = cli.main(["--workdir", str(tmp_path), "findings"])
        assert code == 0
        out = capsys.readouterr().out
        # deduped to one row, runs column shows 2
        assert out.count("db-exposed") == 1
        assert "2" in out  # runs count in row or summary

    def test_takeover_events_included_as_high(self, tmp_path, capsys):
        from loom import cli
        _seed_run(tmp_path, "vulnweb.com", [
            {"type": "takeover", "value": "[+] dangling example.com -> s3",
             "source": "subjack", "host": "vulnweb.com",
             "evidence": {"source": "subjack"}, "ts": 1.0},
        ])
        code = cli.main(["--workdir", str(tmp_path), "findings"])
        assert code == 0
        out = capsys.readouterr().out
        assert "takeover" in out.lower() or "s3" in out
        assert "high" in out.lower()

    def test_json_output(self, tmp_path, capsys):
        from loom import cli
        _seed_run(tmp_path, "vulnweb.com", [
            {"type": "finding", "value": "https://b.vulnweb.com/db.sql",
             "source": "nuclei", "host": "b.vulnweb.com",
             "evidence": {"severity": "critical", "template_id": "db-exposed"},
             "ts": 2.0},
        ])
        code = cli.main(["--workdir", str(tmp_path), "findings", "--json"])
        assert code == 0
        data = json.loads(capsys.readouterr().out)
        assert isinstance(data, list) and len(data) == 1
        assert data[0]["severity"] == "critical"
        assert data[0]["value"] == "https://b.vulnweb.com/db.sql"
