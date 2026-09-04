"""Fuzz must run on known hosts, not just probe output.

Same incident class as the scan gate (v0.8.4, live 2026-09-05): the
deep sweep's `fuzz` (ffuf) node gated only on probe urls, so it
skipped while passive sources named hundreds of hosts. The stage
fuzzes `_live_hosts(ctx)` ← extras["urls"] (any source) +
extras["resolved_subs"] + root — the gate must match that set.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from loom import cli
from loom.dag import DAG, Node, RunState
from loom.live import LiveLogger
from loom.pipeline import Pipeline, PipelineContext
from loom.runner import OutputItem, Runner
from loom.scope import from_dict as scope_from_dict


def _fuzz_predicate():
    dag, _ = cli._build_pipeline("deep", LiveLogger(Path("/tmp")),
                                 None, None)
    pred = dag.get("fuzz").should_run
    assert pred is not None
    return pred


def _state(*, probe: int = 0, urls: int = 0, urls_gau: int = 0,
           resolved: int = 0) -> RunState:
    st = RunState()
    st.artifacts = {("probe", "url"): probe,
                    ("urls", "url"): urls,
                    ("urls_gau", "url"): urls_gau,
                    ("resolve", "subdomain"): resolved}
    return st


class TestFuzzGate:
    def test_fuzz_runs_on_passive_urls_without_probe(self):
        assert _fuzz_predicate()(_state(urls=15161)) is True

    def test_fuzz_runs_on_resolved_subs_without_urls(self):
        assert _fuzz_predicate()(_state(resolved=40)) is True

    def test_fuzz_runs_on_probe_urls(self):
        assert _fuzz_predicate()(_state(probe=5)) is True

    def test_fuzz_skips_when_nothing_known(self):
        assert _fuzz_predicate()(_state()) is False


class TestFuzzGateEndToEnd:
    """The real deep `fuzz` predicate inside a live Pipeline."""

    async def test_fuzz_executes_on_passive_hosts(self):
        pred = _fuzz_predicate()
        mini = DAG()
        mini.add(Node(id="urls", outputs={"url"}))
        mini.add(Node(id="probe", outputs={"url"}))
        mini.add(Node(id="fuzz", depends_on=["urls", "probe"],
                      should_run=pred))

        scope = scope_from_dict({"name": "t", "target": "example.com",
                                 "rate_limit_rps": 1000})
        runner = Runner(scope)
        ctx = PipelineContext(scope=scope)
        ran = []

        async def urls_stage(r, host, c):
            c.extras.setdefault("urls", []).append(
                "http://example.com/?q=1")
            return [OutputItem(kind="url",
                               value="http://example.com/?q=1")]

        async def probe_stage(r, host, c):
            return []

        async def fuzz_stage(r, host, c):
            ran.append(True)
            return []

        pipe = Pipeline(runner,
                        {"urls": urls_stage, "probe": probe_stage,
                         "fuzz": fuzz_stage},
                        context=ctx)
        outcomes = await pipe.run(mini, host="example.com")
        by_id = {o.node_id: o for o in outcomes}
        assert by_id["fuzz"].status == "done", \
            f"fuzz {by_id['fuzz'].status}: {by_id['fuzz'].error}"
        assert ran == [True]
