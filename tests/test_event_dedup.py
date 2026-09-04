"""Regression: events must be written exactly once per item.

Found live 2026-08-30: nuclei findings appeared twice in events.jsonl
because BOTH the Runner (per-item, source=tool) AND the Pipeline
(_emit_events, source=node_id) appended events. The Runner is the
single event emitter.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from loom.dag import DAG, Node
from loom.eventlog import EventLog
from loom.pipeline import Pipeline, PipelineContext
from loom.runner import OutputItem, Runner
from loom.scope import from_dict as scope_from_dict


def _scope():
    return scope_from_dict({"name": "t", "target": "example.com",
                            "rate_limit_rps": 1000})


async def _emitter_stage(runner, host, ctx):
    return [OutputItem("finding", "https://x.example.com/",
                       evidence={"template_id": "CVE-1"})]


class TestSingleEventWriter:
    async def test_runner_backed_stage_writes_once(self, tmp_path: Path, monkeypatch):
        """A stage that shells out via the Runner (streaming parser)
        writes exactly one event per item — not two."""
        el = EventLog(tmp_path / "events.jsonl")
        bindir = tmp_path / "bin"
        bindir.mkdir()
        fake = bindir / "mytool"
        fake.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = \"-version\" ]; then echo 'projectdiscovery/mytool v1'; exit 0; fi\n"
            "echo '{\"template-id\": \"CVE-1\", \"matched-at\": \"https://x.example.com/\", "
            "\"type\": \"http\", \"info\": {\"severity\": \"high\", \"name\": \"X\"}}'\n"
        )
        fake.chmod(0o755)
        monkeypatch.setenv("LOOM_TOOL_MYTOOL", str(fake))

        async def stage(runner, host, ctx):
            return runner.run_streaming(
                "mytool", ["mytool", "-silent"],
                stage="scan", host=host, parser="nuclei",
                timeout=10,
            ).items

        dag = DAG().add(Node(id="scan", outputs={"finding"}))
        stages = {"scan": stage}
        runner = Runner(_scope(), eventlog=el)
        ctx = PipelineContext(scope=runner.scope, eventlog=el)
        pipeline = Pipeline(runner, stages, context=ctx)
        await pipeline.run(dag, host="example.com")
        # exactly one event per finding — no double-write
        assert el.count() == 1
        assert el.count(type_="finding") == 1

    async def test_streaming_stdout_not_glued(self, tmp_path: Path, monkeypatch):
        """Per-line parsers must not glue the saved stdout: katana's
        URLs were concatenated into one line in the workdir output
        (found live on help.twilio.com)."""
        bindir = tmp_path / "bin"
        bindir.mkdir()
        fake = bindir / "katana"
        fake.write_text(
            "#!/bin/sh\n"
            "printf 'https://a.example.com/\\nhttps://b.example.com/\\n'\n"
        )
        fake.chmod(0o755)
        monkeypatch.setenv("LOOM_TOOL_KATANA", str(fake))

        runner = Runner(_scope(), workdir=tmp_path)
        res = runner.run_streaming(
            "katana", ["katana", "-u", "https://x.example.com"],
            stage="crawl", host="x.example.com", parser="katana",
            timeout=10,
        )
        assert res.exit_code == 0
        assert len(res.items) == 2
        # saved stdout must have the newlines intact (v0.5 filenames
        # carry a timestamp: katana.<ts>.stdout.txt)
        saved = sorted((tmp_path / "crawl" / "x.example.com").glob("katana.*.stdout.txt"))
        assert len(saved) == 1
        text = saved[0].read_text()
        assert "https://a.example.com/\nhttps://b.example.com/" in text

    async def test_synthetic_stage_writes_nothing(self, tmp_path: Path):
        """A synthetic stage (no Runner subprocess) writes no events —
        the pipeline does not emit them."""
        el = EventLog(tmp_path / "events.jsonl")
        dag = DAG().add(Node(id="a", outputs={"finding"}))
        stages = {"a": _emitter_stage}
        runner = Runner(_scope())
        ctx = PipelineContext(scope=runner.scope, eventlog=el)
        pipeline = Pipeline(runner, stages, context=ctx)
        await pipeline.run(dag, host="example.com")
        assert el.count() == 0
