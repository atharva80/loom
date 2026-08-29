"""loom.pipeline tests.

End-to-end async tests for the orchestrator. Each test uses a DAG of
synthetic stages (no subprocess) so we can verify:

  * Topological order
  * Concurrent execution within a level (timing-based check)
  * should_run predicates cause skips
  * Per-node failure does NOT crash the level
  * State + eventlog get written
  * Concurrency semaphore is respected
  * Stages can communicate via ctx.extras (cross-stage state)

Subprocess-backed integration tests live in test_pipeline_integration.py
so this file stays fast and free of network/tool dependencies.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Awaitable, Callable

import pytest

from loom.dag import DAG, Node, RunState, add_subdomain_pipeline
from loom.eventlog import EventLog
from loom.pipeline import NodeOutcome, Pipeline, PipelineContext, StageFn
from loom.runner import OutputItem, Runner
from loom.scope import Scope, from_dict as scope_from_dict
from loom.state import State


# Helper: a stage that emits fixed items, optionally with a delay.
def make_emitter_stage(items: list[OutputItem], delay: float = 0.0) -> StageFn:
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        if delay:
            await asyncio.sleep(delay)
        return list(items)
    return _stage


def _scope() -> Scope:
    return scope_from_dict({"name": "t", "target": "example.com", "rate_limit_rps": 1000})


# ============================================================
# Basic linear pipeline
# ============================================================


class TestLinearPipeline:
    async def test_single_node_pipeline(self):
        items = [OutputItem("subdomain", "a.example.com")]
        dag = DAG().add(Node(id="subenum", outputs={"subdomain"}))
        stages = {"subenum": make_emitter_stage(items)}
        runner = Runner(_scope())
        pipeline = Pipeline(runner, stages)
        outcomes = await pipeline.run(dag, host="example.com")
        assert len(outcomes) == 1
        assert outcomes[0].node_id == "subenum"
        assert outcomes[0].status == "done"
        assert outcomes[0].items == items

    async def test_chain_respects_topological_order(self):
        # a → b → c. Verify that b's stage starts AFTER a finishes,
        # c starts after b finishes.
        order_log: list[str] = []
        def tracker(name: str, items: list[OutputItem]) -> StageFn:
            async def _stage(runner, host, ctx):
                order_log.append(f"start:{name}")
                await asyncio.sleep(0.01)
                order_log.append(f"end:{name}")
                return items
            return _stage

        dag = DAG()
        dag.add(Node(id="a"))
        dag.add(Node(id="b", depends_on=["a"]))
        dag.add(Node(id="c", depends_on=["b"]))
        stages = {
            "a": tracker("a", [OutputItem("x", "x1")]),
            "b": tracker("b", [OutputItem("y", "y1")]),
            "c": tracker("c", [OutputItem("z", "z1")]),
        }
        runner = Runner(_scope())
        pipeline = Pipeline(runner, stages)
        await pipeline.run(dag, host="example.com")
        # Must be strictly: a(before b), b(before c), c is last
        assert order_log == [
            "start:a", "end:a", "start:b", "end:b", "start:c", "end:c",
        ]


# ============================================================
# Concurrent execution
# ============================================================


class TestConcurrent:
    async def test_independent_nodes_run_concurrently(self):
        # a and b have no deps → they should run in parallel.
        # Total wall time should be ~ delay, not 2*delay.
        delay = 0.10

        def slow(name: str) -> StageFn:
            async def _stage(runner, host, ctx):
                await asyncio.sleep(delay)
                return [OutputItem("x", name)]
            return _stage

        dag = DAG()
        dag.add(Node(id="a"))
        dag.add(Node(id="b"))
        stages = {"a": slow("a"), "b": slow("b")}
        runner = Runner(_scope())
        pipeline = Pipeline(runner, stages)
        t0 = time.monotonic()
        outcomes = await pipeline.run(dag, host="example.com")
        elapsed = time.monotonic() - t0
        assert len(outcomes) == 2
        assert all(o.status == "done" for o in outcomes)
        # If they ran sequentially, elapsed would be ~2*delay. In parallel,
        # ~1*delay. Allow 50% slack for scheduler noise.
        assert elapsed < delay * 1.5, f"expected parallel, got {elapsed:.3f}s"

    async def test_concurrency_cap_respected(self):
        # 4 slow nodes, cap=2 → should take ~2*delay, not ~delay.
        delay = 0.10
        cap = 2

        def slow(name: str) -> StageFn:
            async def _stage(runner, host, ctx):
                await asyncio.sleep(delay)
                return [OutputItem("x", name)]
            return _stage

        dag = DAG()
        for x in "abcd":
            dag.add(Node(id=x))
        stages = {x: slow(x) for x in "abcd"}
        runner = Runner(_scope())
        pipeline = Pipeline(runner, stages, max_concurrency=cap)
        t0 = time.monotonic()
        await pipeline.run(dag, host="example.com")
        elapsed = time.monotonic() - t0
        # With cap=2 and 4 nodes of delay, expect ~2*delay wall.
        # Allow generous range: not less than delay (would be 4-parallel),
        # not more than 3*delay (would be fully sequential).
        assert delay < elapsed < delay * 3, f"cap not respected: {elapsed:.3f}s"


# ============================================================
# should_run predicates
# ============================================================


class TestShouldRun:
    async def test_predicate_skip_propagates(self):
        # a → b; b has should_run = False (no upstream artifacts)
        dag = DAG()
        dag.add(Node(id="a"))
        dag.add(Node(
            id="b", depends_on=["a"],
            should_run=lambda s: s.total("subdomain") > 0,
        ))
        stages = {
            "a": make_emitter_stage([]),  # no artifacts
            "b": make_emitter_stage([OutputItem("x", "should-not-emit")]),
        }
        runner = Runner(_scope())
        pipeline = Pipeline(runner, stages)
        outcomes = await pipeline.run(dag, host="example.com")
        a_out, b_out = outcomes
        assert a_out.status == "done"
        assert b_out.status == "skipped"
        assert b_out.items == []  # stage was NOT invoked

    async def test_predicate_runs_when_upstream_has_data(self):
        dag = DAG()
        dag.add(Node(id="a"))
        dag.add(Node(
            id="b", depends_on=["a"],
            should_run=lambda s: s.from_node("a", "subdomain") >= 2,
        ))
        stages = {
            "a": make_emitter_stage([
                OutputItem("subdomain", "x.example.com"),
                OutputItem("subdomain", "y.example.com"),
            ]),
            "b": make_emitter_stage([OutputItem("url", "https://x.example.com/")]),
        }
        runner = Runner(_scope())
        pipeline = Pipeline(runner, stages)
        outcomes = await pipeline.run(dag, host="example.com")
        assert outcomes[1].status == "done"
        assert outcomes[1].items[0].value == "https://x.example.com/"


# ============================================================
# Failure handling
# ============================================================


class TestFailure:
    async def test_stage_exception_becomes_failed_outcome(self):
        async def boom(runner, host, ctx):
            raise RuntimeError("kaboom")
        dag = DAG().add(Node(id="a"))
        stages = {"a": boom}
        runner = Runner(_scope())
        pipeline = Pipeline(runner, stages)
        outcomes = await pipeline.run(dag, host="example.com")
        assert outcomes[0].status == "failed"
        assert "kaboom" in (outcomes[0].error or "")

    async def test_failure_does_not_stop_level(self):
        # a fails, b succeeds → both reported
        async def boom(runner, host, ctx):
            raise RuntimeError("a died")
        async def good(runner, host, ctx):
            return [OutputItem("x", "ok")]
        dag = DAG()
        dag.add(Node(id="a"))
        dag.add(Node(id="b"))
        stages = {"a": boom, "b": good}
        runner = Runner(_scope())
        pipeline = Pipeline(runner, stages)
        outcomes = await pipeline.run(dag, host="example.com")
        by_id = {o.node_id: o for o in outcomes}
        assert by_id["a"].status == "failed"
        assert by_id["b"].status == "done"

    async def test_missing_stage_is_failed(self):
        dag = DAG().add(Node(id="a"))
        # no entry in stages
        runner = Runner(_scope())
        pipeline = Pipeline(runner, stages={})
        outcomes = await pipeline.run(dag, host="example.com")
        assert outcomes[0].status == "failed"
        assert "no stage registered" in (outcomes[0].error or "")


# ============================================================
# State + eventlog integration
# ============================================================


class TestPersistence:
    async def test_pipeline_does_not_double_emit_events(self, tmp_path: Path):
        """The Runner is the single event emitter. A pipeline whose
        stages return items (synthetic, no Runner) must NOT write
        events itself — otherwise runner-backed stages double-write
        (verified live: nuclei findings appeared twice)."""
        el = EventLog(tmp_path / "events.jsonl")
        dag = DAG().add(Node(id="a", outputs={"subdomain"}))
        stages = {"a": make_emitter_stage([
            OutputItem("subdomain", "x.example.com"),
            OutputItem("subdomain", "y.example.com"),
        ])}
        runner = Runner(_scope())
        ctx = PipelineContext(scope=runner.scope, eventlog=el)
        pipeline = Pipeline(runner, stages, context=ctx)
        await pipeline.run(dag, host="example.com")
        # pipeline must not emit — the runner owns event emission
        assert el.count() == 0

    async def test_state_records_outcomes(self, tmp_path: Path):
        db = tmp_path / "state.db"
        with State(db) as st:
            run_id = st.start_run("example.com")
            dag = DAG()
            dag.add(Node(id="a"))
            dag.add(Node(id="b", depends_on=["a"]))
            stages = {
                "a": make_emitter_stage([OutputItem("x", "1")]),
                "b": make_emitter_stage([OutputItem("y", "2")]),
            }
            runner = Runner(_scope())
            ctx = PipelineContext(scope=runner.scope, state=st, run_id=run_id)
            pipeline = Pipeline(runner, stages, context=ctx)
            await pipeline.run(dag, host="example.com")

            assert st.is_done(run_id, "example.com", "a", "a")
            assert st.is_done(run_id, "example.com", "b", "b")
            stats = st.stats(run_id)
            assert stats["a"]["done"] == 1
            assert stats["b"]["done"] == 1

    async def test_state_records_failure(self, tmp_path: Path):
        db = tmp_path / "state.db"
        with State(db) as st:
            run_id = st.start_run("example.com")
            async def boom(runner, host, ctx):
                raise RuntimeError("nope")
            dag = DAG().add(Node(id="a"))
            stages = {"a": boom}
            runner = Runner(_scope())
            ctx = PipelineContext(scope=runner.scope, state=st, run_id=run_id)
            pipeline = Pipeline(runner, stages, context=ctx)
            await pipeline.run(dag, host="example.com")
            failed = st.hosts_failed_for(run_id, "a", "a")
            assert "example.com" in failed
            assert "nope" in failed["example.com"]

    async def test_state_records_skip(self, tmp_path: Path):
        db = tmp_path / "state.db"
        with State(db) as st:
            run_id = st.start_run("example.com")
            dag = DAG()
            dag.add(Node(id="a"))
            dag.add(Node(
                id="b", depends_on=["a"],
                should_run=lambda s: False,
            ))
            stages = {
                "a": make_emitter_stage([]),
                "b": make_emitter_stage([OutputItem("x", "ignored")]),
            }
            runner = Runner(_scope())
            ctx = PipelineContext(scope=runner.scope, state=st, run_id=run_id)
            pipeline = Pipeline(runner, stages, context=ctx)
            await pipeline.run(dag, host="example.com")
            assert st.is_done(run_id, "example.com", "a", "a")
            # b was skipped, not done
            assert not st.is_done(run_id, "example.com", "b", "b")
            row = st._conn.execute(
                "SELECT status FROM tool_runs WHERE run_id=? AND tool='b'", (run_id,)
            ).fetchone()
            assert row["status"] == "skipped"


# ============================================================
# Cross-stage state via ctx.extras
# ============================================================


class TestCrossStageState:
    async def test_stages_share_extras(self):
        async def producer(runner, host, ctx):
            ctx.extras["payload"] = {"key": "value", "n": 7}
            return [OutputItem("x", "p")]
        async def consumer(runner, host, ctx):
            payload = ctx.extras.get("payload", {})
            return [OutputItem("y", f"got:{payload.get('key')}:{payload.get('n')}")]
        dag = DAG()
        dag.add(Node(id="producer"))
        dag.add(Node(id="consumer", depends_on=["producer"]))
        stages = {"producer": producer, "consumer": consumer}
        runner = Runner(_scope())
        pipeline = Pipeline(runner, stages)
        outcomes = await pipeline.run(dag, host="example.com")
        c_out = next(o for o in outcomes if o.node_id == "consumer")
        assert c_out.items[0].value == "got:value:7"


# ============================================================
# Bundled subdomain pipeline (smoke test)
# ============================================================


class TestSubdomainPipeline:
    async def test_screenshot_skipped_when_no_live_hosts(self):
        # subenum → resolve → probe (no live_hosts) → screenshot (should skip)
        dag = add_subdomain_pipeline(DAG())
        async def subenum(runner, host, ctx):
            return [OutputItem("subdomain", f"a.{host}")]
        async def resolve(runner, host, ctx):
            return [OutputItem("host", f"a.{host}")]
        async def probe(runner, host, ctx):
            # returns no live_host items
            return []
        async def screenshot(runner, host, ctx):
            return [OutputItem("screenshot", "should-not-run")]

        stages = {
            "subenum": subenum,
            "resolve": resolve,
            "probe": probe,
            "screenshot": screenshot,
        }
        runner = Runner(_scope())
        pipeline = Pipeline(runner, stages)
        outcomes = await pipeline.run(dag, host="example.com")
        by_id = {o.node_id: o for o in outcomes}
        assert by_id["subenum"].status == "done"
        assert by_id["resolve"].status == "done"
        assert by_id["probe"].status == "done"
        assert by_id["screenshot"].status == "skipped"
        assert by_id["screenshot"].items == []

    async def test_screenshot_runs_when_live_hosts_exist(self):
        dag = add_subdomain_pipeline(DAG())
        async def subenum(runner, host, ctx):
            return [OutputItem("subdomain", f"a.{host}")]
        async def resolve(runner, host, ctx):
            return [OutputItem("host", f"a.{host}")]
        async def probe(runner, host, ctx):
            return [OutputItem("live_host", f"https://a.{host}/")]
        async def screenshot(runner, host, ctx):
            return [OutputItem("screenshot", f"shot-of-a.{host}")]

        stages = {"subenum": subenum, "resolve": resolve,
                  "probe": probe, "screenshot": screenshot}
        runner = Runner(_scope())
        pipeline = Pipeline(runner, stages)
        outcomes = await pipeline.run(dag, host="example.com")
        by_id = {o.node_id: o for o in outcomes}
        assert by_id["screenshot"].status == "done"
        assert by_id["screenshot"].items[0].value == "shot-of-a.example.com"
