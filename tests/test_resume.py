"""loom.resume tests.

Cover:
  * latest_inflight_run: finds unfinished runs, ignores finished
  * seed_run_state_from_db: builds correct results map
  * ResumablePipeline:
      - Fresh run: no skips
      - Resume: stages already `done` are NOT re-invoked
      - Resume: stages in `skipped` are NOT re-invoked
      - Resume: stages in `running` (crashed) ARE re-invoked
      - Resume: stages in `failed` ARE re-invoked
      - Cross-host: a row for host A doesn't block host B
  * Stage invocation counter — the key efficiency win
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Awaitable, Callable

import pytest

from loom.dag import DAG, Node, add_subdomain_pipeline
from loom.eventlog import EventLog
from loom.pipeline import Pipeline, PipelineContext, StageFn
from loom.resume import (
    ResumablePipeline,
    latest_inflight_run,
    make_resumable,
    seed_run_state_from_db,
)
from loom.runner import OutputItem, Runner
from loom.scope import Scope, from_dict as scope_from_dict
from loom.state import State


def _scope() -> Scope:
    return scope_from_dict({"name": "t", "target": "example.com", "rate_limit_rps": 1000})


# ============================================================
# latest_inflight_run
# ============================================================


class TestLatestInflight:
    def test_no_runs(self, tmp_path: Path):
        with State(tmp_path / "s.db") as st:
            assert latest_inflight_run(st, "example.com") is None

    def test_finished_run_not_inflight(self, tmp_path: Path):
        with State(tmp_path / "s.db") as st:
            rid = st.start_run("example.com")
            st.finish_run(rid)
            assert latest_inflight_run(st, "example.com") is None

    def test_unfinished_run_is_inflight(self, tmp_path: Path):
        with State(tmp_path / "s.db") as st:
            rid = st.start_run("example.com")
            assert latest_inflight_run(st, "example.com") == rid

    def test_returns_most_recent(self, tmp_path: Path):
        with State(tmp_path / "s.db") as st:
            r1 = st.start_run("example.com")
            st.finish_run(r1)
            r2 = st.start_run("example.com")  # this one is unfinished
            assert latest_inflight_run(st, "example.com") == r2
            st.finish_run(r2)
            r3 = st.start_run("example.com")
            assert latest_inflight_run(st, "example.com") == r3

    def test_filters_by_domain(self, tmp_path: Path):
        with State(tmp_path / "s.db") as st:
            st.start_run("other.com")
            my = st.start_run("example.com")
            assert latest_inflight_run(st, "example.com") == my
            assert latest_inflight_run(st, "nope.com") is None


# ============================================================
# seed_run_state_from_db
# ============================================================


class TestSeedFromDB:
    def test_empty_state(self, tmp_path: Path):
        with State(tmp_path / "s.db") as st:
            rid = st.start_run("example.com")
            dag = DAG().add(Node(id="a"))
            assert seed_run_state_from_db(st, rid, dag) == {}

    def test_includes_done_nodes(self, tmp_path: Path):
        with State(tmp_path / "s.db") as st:
            rid = st.start_run("example.com")
            st.mark(rid, "", "a", "a", "done")
            st.mark(rid, "", "b", "b", "done")
            dag = DAG()
            dag.add(Node(id="a"))
            dag.add(Node(id="b"))
            dag.add(Node(id="c"))  # not marked
            seed = seed_run_state_from_db(st, rid, dag)
            assert seed == {"a": "done", "b": "done"}

    def test_includes_skipped_nodes(self, tmp_path: Path):
        with State(tmp_path / "s.db") as st:
            rid = st.start_run("example.com")
            st.mark(rid, "", "a", "a", "skipped")
            dag = DAG().add(Node(id="a"))
            assert seed_run_state_from_db(st, rid, dag) == {"a": "done"}


# ============================================================
# ResumablePipeline
# ============================================================


class TestResumablePipeline:
    async def test_fresh_run_no_skips(self, tmp_path: Path):
        # Count stage invocations: should be N for fresh, < N for resumed.
        invocation_count: dict[str, int] = {}
        def counting_stage(name: str) -> StageFn:
            async def _stage(runner, host, ctx):
                invocation_count[name] = invocation_count.get(name, 0) + 1
                return [OutputItem("x", name)]
            return _stage

        dag = DAG()
        dag.add(Node(id="a"))
        dag.add(Node(id="b", depends_on=["a"]))
        stages = {"a": counting_stage("a"), "b": counting_stage("b")}

        with State(tmp_path / "s.db") as st:
            rid = st.start_run("example.com")
            runner = Runner(_scope())
            ctx = PipelineContext(scope=runner.scope, state=st, run_id=rid)
            rp = ResumablePipeline(runner, stages, context=ctx)
            await rp.run_resumable(dag, host="example.com")
            assert invocation_count == {"a": 1, "b": 1}

    async def test_resume_skips_done_stages(self, tmp_path: Path):
        invocation_count: dict[str, int] = {}
        def counting_stage(name: str) -> StageFn:
            async def _stage(runner, host, ctx):
                invocation_count[name] = invocation_count.get(name, 0) + 1
                return [OutputItem("x", name)]
            return _stage

        dag = DAG()
        dag.add(Node(id="a"))
        dag.add(Node(id="b", depends_on=["a"]))
        stages = {"a": counting_stage("a"), "b": counting_stage("b")}

        with State(tmp_path / "s.db") as st:
            rid = st.start_run("example.com")
            # Pre-mark a as done (as if a previous run finished it)
            st.mark(rid, "example.com", "a", "a", "done")
            runner = Runner(_scope())
            ctx = PipelineContext(scope=runner.scope, state=st, run_id=rid)
            rp = ResumablePipeline(runner, stages, context=ctx)
            outcomes = await rp.run_resumable(dag, host="example.com")
            # a is NOT re-invoked; b IS re-invoked
            assert invocation_count == {"b": 1}
            by_id = {o.node_id: o for o in outcomes}
            assert by_id["a"].status == "skipped"  # synth-skipped
            assert by_id["b"].status == "done"

    async def test_resume_skips_previously_skipped_stages(self, tmp_path: Path):
        invocation_count: dict[str, int] = {}
        def counting_stage(name: str) -> StageFn:
            async def _stage(runner, host, ctx):
                invocation_count[name] = invocation_count.get(name, 0) + 1
                return []
            return _stage

        dag = DAG().add(Node(id="a"))
        stages = {"a": counting_stage("a")}

        with State(tmp_path / "s.db") as st:
            rid = st.start_run("example.com")
            st.mark(rid, "example.com", "a", "a", "skipped")
            runner = Runner(_scope())
            ctx = PipelineContext(scope=runner.scope, state=st, run_id=rid)
            rp = ResumablePipeline(runner, stages, context=ctx)
            await rp.run_resumable(dag, host="example.com")
            assert invocation_count == {}  # never invoked

    async def test_resume_reruns_running_stages(self, tmp_path: Path):
        # A 'running' row from a crashed run should NOT be skipped.
        invocation_count: dict[str, int] = {}
        def counting_stage(name: str) -> StageFn:
            async def _stage(runner, host, ctx):
                invocation_count[name] = invocation_count.get(name, 0) + 1
                return []
            return _stage

        dag = DAG().add(Node(id="a"))
        stages = {"a": counting_stage("a")}

        with State(tmp_path / "s.db") as st:
            rid = st.start_run("example.com")
            # Simulate a crashed prior run: row left as 'running'
            st.mark(rid, "example.com", "a", "a", "running")
            runner = Runner(_scope())
            ctx = PipelineContext(scope=runner.scope, state=st, run_id=rid)
            rp = ResumablePipeline(runner, stages, context=ctx)
            await rp.run_resumable(dag, host="example.com")
            assert invocation_count == {"a": 1}  # RE-RAN

    async def test_resume_reruns_failed_stages(self, tmp_path: Path):
        invocation_count: dict[str, int] = {}
        def counting_stage(name: str) -> StageFn:
            async def _stage(runner, host, ctx):
                invocation_count[name] = invocation_count.get(name, 0) + 1
                return []
            return _stage

        dag = DAG().add(Node(id="a"))
        stages = {"a": counting_stage("a")}

        with State(tmp_path / "s.db") as st:
            rid = st.start_run("example.com")
            st.mark(rid, "example.com", "a", "a", "failed", error="crash")
            runner = Runner(_scope())
            ctx = PipelineContext(scope=runner.scope, state=st, run_id=rid)
            rp = ResumablePipeline(runner, stages, context=ctx)
            await rp.run_resumable(dag, host="example.com")
            assert invocation_count == {"a": 1}  # RE-RAN

    async def test_resume_cross_host_isolation(self, tmp_path: Path):
        # A 'done' row for host A should not skip host B
        invocation_count: dict[str, int] = {}
        def counting_stage(name: str) -> StageFn:
            async def _stage(runner, host, ctx):
                invocation_count[host] = invocation_count.get(host, 0) + 1
                return []
            return _stage

        dag = DAG().add(Node(id="a"))
        stages = {"a": counting_stage("a")}

        with State(tmp_path / "s.db") as st:
            rid = st.start_run("example.com")
            st.mark(rid, "hostA.com", "a", "a", "done")
            runner = Runner(_scope())
            ctx = PipelineContext(scope=runner.scope, state=st, run_id=rid)
            rp = ResumablePipeline(runner, stages, context=ctx)
            # First resume against hostA.com — should skip
            await rp.run_resumable(dag, host="hostA.com")
            # Then against hostB.com — should run
            await rp.run_resumable(dag, host="hostB.com")
            assert invocation_count == {"hostB.com": 1}

    async def test_resume_full_pipeline_partial_done(self, tmp_path: Path):
        # subenum done, resolve done, probe NOT done, screenshot not done
        # → on resume: subenum skipped, resolve skipped, probe runs, screenshot runs
        invocation_count: dict[str, int] = {}
        def counting_stage(name: str) -> StageFn:
            async def _stage(runner, host, ctx):
                invocation_count[name] = invocation_count.get(name, 0) + 1
                if name == "probe":
                    return [OutputItem("live_host", f"https://a.{host}/")]
                return []
            return _stage

        dag = add_subdomain_pipeline(DAG())
        stages = {nid: counting_stage(nid) for nid in ("subenum", "resolve", "probe", "screenshot")}

        with State(tmp_path / "s.db") as st:
            rid = st.start_run("example.com")
            st.mark(rid, "example.com", "subenum", "subenum", "done")
            st.mark(rid, "example.com", "resolve", "resolve", "done")
            runner = Runner(_scope())
            ctx = PipelineContext(scope=runner.scope, state=st, run_id=rid)
            rp = ResumablePipeline(runner, stages, context=ctx)
            outcomes = await rp.run_resumable(dag, host="example.com")
            # Only probe and screenshot ran
            assert invocation_count == {"probe": 1, "screenshot": 1}
            by_id = {o.node_id: o for o in outcomes}
            assert by_id["subenum"].status == "skipped"
            assert by_id["resolve"].status == "skipped"
            assert by_id["probe"].status == "done"
            assert by_id["screenshot"].status == "done"


# ============================================================
# make_resumable promotion
# ============================================================


class TestMakeResumable:
    async def test_promote_preserves_stages(self, tmp_path: Path):
        called: list[str] = []
        async def stage_a(runner, host, ctx):
            called.append("a")
            return []
        async def stage_b(runner, host, ctx):
            called.append("b")
            return []
        dag = DAG()
        dag.add(Node(id="a"))
        dag.add(Node(id="b", depends_on=["a"]))

        runner = Runner(_scope())
        pipeline = Pipeline(runner, {"a": stage_a, "b": stage_b})
        rp = make_resumable(pipeline)
        assert isinstance(rp, ResumablePipeline)
        # Same stages reference
        assert rp.stages is pipeline.stages
        # Original pipeline is not mutated
        assert not isinstance(pipeline, ResumablePipeline)

    async def test_promoted_pipeline_runs_same_as_base(self, tmp_path: Path):
        # No state → no skips → behaves like base Pipeline
        called: list[str] = []
        async def stage(runner, host, ctx):
            called.append(host)
            return []
        dag = DAG().add(Node(id="a"))
        runner = Runner(_scope())
        pipeline = Pipeline(runner, {"a": stage})
        rp = make_resumable(pipeline)
        await rp.run(dag, host="example.com")
        assert called == ["example.com"]
