"""Tests for the v0.7 agent-grade surface: run manifest.json,
--json on status/list-runs/validate, manifest-on-resume wiring.

Agents (and overnight scripts) read loom output programmatically —
every read command must offer stable JSON, and every finished run
must leave a single manifest file describing itself.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from loom.state import State


def _seed_run(tmp_path: Path, domain: str = "example.com",
              pipeline: str = "deep", finish: bool = True,
              events: list[dict] | None = None) -> int:
    from loom import cli
    from loom.live import LiveLogger
    st = State(tmp_path / "loom.sqlite")
    run_id = st.start_run(domain, mode="recon", scope_profile="default",
                          pipeline=pipeline)
    # Pipeline-level marks (tool == stage == node id), exactly what
    # Pipeline._mark_state writes on real runs — this is what resume's
    # should_skip gate reads.
    dag, _ = cli._build_pipeline(pipeline, LiveLogger(tmp_path), None, None)
    for nid in dag.ids():
        st.mark(run_id, domain, nid, nid, "done", duration_s=1.0)
    if finish:
        st.finish_run(run_id)
    evdir = tmp_path / f"run-{run_id}"
    evdir.mkdir(parents=True, exist_ok=True)
    with (evdir / "events.jsonl").open("w") as f:
        for ev in (events or [
                {"type": "subdomain", "value": "a.example.com",
                 "source": "subfinder", "host": domain, "ts": 1.0},
                {"type": "finding", "value": "https://a.example.com/x",
                 "source": "nuclei", "host": "a.example.com",
                 "evidence": {"severity": "high"}, "ts": 2.0},
        ]):
            f.write(json.dumps(ev) + "\n")
    st.close()
    return run_id


class TestManifestBuilder:
    def test_build_manifest_shape(self, tmp_path):
        from loom import cli
        from loom.live import LiveLogger
        from loom.manifest import build_manifest
        rid = _seed_run(tmp_path)
        m = build_manifest(tmp_path, rid)
        assert m is not None
        assert m["run"]["id"] == rid
        assert m["run"]["domain"] == "example.com"
        assert m["run"]["pipeline"] == "deep"
        assert m["run"]["status"] == "done"
        assert m["loom_version"]
        dag, _ = cli._build_pipeline("deep", LiveLogger(tmp_path), None, None)
        assert {s["stage"] for s in m["stages"]} == set(dag.ids())
        assert m["events"] == {"subdomain": 1, "finding": 1}
        assert m["summary"]["findings"] == 1
        assert "subfinder" in m["resolved_tools"]

    def test_build_manifest_missing_run(self, tmp_path):
        from loom.manifest import build_manifest
        State(tmp_path / "loom.sqlite").close()
        assert build_manifest(tmp_path, 999) is None

    def test_build_manifest_inflight(self, tmp_path):
        from loom.manifest import build_manifest
        rid = _seed_run(tmp_path, finish=False)
        m = build_manifest(tmp_path, rid)
        assert m["run"]["status"] == "inflight"

    def test_write_manifest_roundtrip(self, tmp_path):
        from loom.manifest import write_manifest
        rid = _seed_run(tmp_path)
        p = write_manifest(tmp_path, rid)
        assert p is not None and p.name == "manifest.json"
        assert json.loads(p.read_text())["run"]["id"] == rid

    def test_write_manifest_missing_run_returns_none(self, tmp_path):
        from loom.manifest import write_manifest
        State(tmp_path / "loom.sqlite").close()
        assert write_manifest(tmp_path, 999) is None


class TestJsonSurface:
    def test_status_json(self, tmp_path, capsys):
        from loom import cli
        _seed_run(tmp_path)
        code = cli.main(["--workdir", str(tmp_path), "status",
                         "example.com", "--json"])
        assert code == 0
        data = json.loads(capsys.readouterr().out)
        assert data["run_id"] == 1
        assert data["domain"] == "example.com"

    def test_list_runs_json(self, tmp_path, capsys):
        from loom import cli
        _seed_run(tmp_path)
        _seed_run(tmp_path, domain="other.com")
        code = cli.main(["--workdir", str(tmp_path), "list-runs", "--json"])
        assert code == 0
        data = json.loads(capsys.readouterr().out)
        assert isinstance(data, list) and len(data) == 2
        assert {r["domain"] for r in data} == {"example.com", "other.com"}

    def test_validate_json(self, tmp_path, capsys):
        from loom import cli
        code = cli.main(["--workdir", str(tmp_path), "validate", "--json"])
        assert code in (0, 1)  # depends on box tools, both fine
        data = json.loads(capsys.readouterr().out)
        assert "tools" in data and "wordlists" in data
        assert isinstance(data["tools"], list)
        assert data["tools"], "expected at least one tool entry"


class TestResumeWritesManifest:
    def test_resume_leaves_manifest(self, tmp_path, capsys):
        """Resume of an inflight deep run (all stages already done →
        all skipped, no network) must leave manifest.json behind."""
        from loom import cli
        rid = _seed_run(tmp_path, pipeline="deep", finish=False)
        code = cli.main(["--workdir", str(tmp_path), "resume", "example.com"])
        assert code == 0
        capsys.readouterr()
        mp = tmp_path / f"run-{rid}" / "manifest.json"
        assert mp.is_file(), "resume must write manifest.json"
        assert json.loads(mp.read_text())["run"]["id"] == rid
