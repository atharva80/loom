"""Scan must run on the URL pool, not just probe output.

Live 2026-09-05 (deep sweep on vulnweb.com): probe yielded 0 urls
(tarpitted apex) while wayback/gau amassed 15,161 urls — and the
`scan` (nuclei) node skipped because its predicate only counted
probe urls. The flagship scanner sat out the run; xss stages with the
identical url pool ran fine. The predicate must match the pool the
stage consumes (scan_pool ← extras["urls"] ← probe+urls+urls_gau).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from loom import cli
from loom.dag import DAG, Node, RunState
from loom.live import LiveLogger
from loom.pipeline import Pipeline, PipelineContext
from loom.runner import OutputItem


def _scan_predicate(pipeline: str):
    dag, _ = cli._build_pipeline(pipeline, LiveLogger(Path("/tmp")),
                                 None, None)
    pred = dag.get("scan").should_run
    assert pred is not None
    return pred


def _state(*, probe: int = 0, urls: int = 0, urls_gau: int = 0) -> RunState:
    st = RunState()
    st.artifacts = {("probe", "url"): probe,
                    ("urls", "url"): urls,
                    ("urls_gau", "url"): urls_gau}
    return st


@pytest.mark.parametrize("pipeline", ["full", "deep"])
class TestScanRunsOnUrlPool:
    def test_scan_runs_on_passive_urls_without_probe(self, pipeline):
        """The live incident: 15k passive urls, 0 probe urls → must run."""
        assert _scan_predicate(pipeline)(_state(urls=15161)) is True

    def test_scan_runs_on_probe_urls(self, pipeline):
        assert _scan_predicate(pipeline)(_state(probe=5)) is True

    def test_scan_skips_when_pool_empty(self, pipeline):
        assert _scan_predicate(pipeline)(_state()) is False


class TestVulnscanGate:
    """The `subdomain` pipeline's `vulnscan` node is make_nuclei_stage
    (consumes scan_pool) behind a probe-only gate — same hole."""

    def _pred(self):
        dag, _ = cli._build_pipeline("subdomain",
                                     LiveLogger(Path("/tmp")), None, None)
        pred = dag.get("vulnscan").should_run
        assert pred is not None
        return pred

    def test_runs_on_passive_urls_without_probe(self):
        assert self._pred()(_state(urls=200)) is True

    def test_runs_on_probe_urls(self):
        assert self._pred()(_state(probe=3)) is True

    def test_skips_when_pool_empty(self):
        assert self._pred()(_state()) is False


class TestScanGateEndToEnd:
    """The real deep `scan` predicate inside a live Pipeline: passive
    urls flow, probe is empty, scan must execute (not skip)."""

    async def test_scan_executes_on_passive_pool(self):
        from loom.scope import from_dict as scope_from_dict

        dag, _ = cli._build_pipeline("deep", LiveLogger(Path("/tmp")),
                                     None, None)
        scan_pred = dag.get("scan").should_run
        assert scan_pred is not None

        mini = DAG()
        mini.add(Node(id="urls", outputs={"url"}))
        mini.add(Node(id="probe", outputs={"url"}))
        mini.add(Node(id="scan", inputs={"url"},
                      depends_on=["urls", "probe"],
                      should_run=scan_pred))

        scope = scope_from_dict({"name": "t", "target": "example.com",
                                 "rate_limit_rps": 1000})
        from loom.runner import Runner
        runner = Runner(scope)
        ctx = PipelineContext(scope=scope)
        ran = []

        async def urls_stage(r, host, c):
            c.extras.setdefault("urls", []).append(
                "http://example.com/?q=1")
            return [OutputItem(kind="url",
                               value="http://example.com/?q=1")]

        async def probe_stage(r, host, c):
            return []  # tarpit: probe finds nothing live

        async def scan_stage(r, host, c):
            ran.append(True)
            pool = c.extras.get("urls", [])
            assert pool, "scan ran with an empty pool"
            return [OutputItem(kind="finding", value="x")]

        pipe = Pipeline(runner,
                        {"urls": urls_stage, "probe": probe_stage,
                         "scan": scan_stage},
                        context=ctx)
        outcomes = await pipe.run(mini, host="example.com")
        by_id = {o.node_id: o for o in outcomes}
        assert by_id["scan"].status == "done", \
            f"scan {by_id['scan'].status}: {by_id['scan'].error}"
        assert ran == [True]
