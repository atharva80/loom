"""loom.fanout tests.

Two layers:
  1. Shape + concurrency — synthetic stages, no I/O. Verify that
     multiple hosts are processed, concurrency cap is respected,
     and per-host state isolation works (factory pattern).
  2. Resume integration — pre-mark some hosts done in the State DB,
     run the fanout, verify only unfinished hosts are processed.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

from loom.dag import DAG, Node
from loom.fanout import Fanout, FanoutResult
from loom.pipeline import Pipeline, PipelineContext, StageFn
from loom.runner import OutputItem, Runner
from loom.scope import from_dict as scope_from_dict
from loom.state import State


def _scope():
    return scope_from_dict({"name": "t", "target": "example.com",
                            "rate_limit_rps": 1000})


def make_recording_stage(name: str, sleep_s: float = 0.05) -> StageFn:
    """Stage that sleeps `sleep_s` and records (host, call_time) per call.

    Recordings are stored on the function object so tests can inspect
    after the fanout completes. Note: the recording is shared across
    all calls (even across hosts) — that's by design for these tests.
    """
    seen: list[tuple[str, float]] = []
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        seen.append((host, time.monotonic()))
        await asyncio.sleep(sleep_s)
        return [OutputItem("test", f"{name}-{host}")]
    _stage._seen = seen  # type: ignore[attr-defined]
    return _stage


def make_pipeline_factory(stages: dict[str, StageFn]):
    """Factory that returns a fresh Pipeline per host. Shares scope,
    runner, and context across hosts; only the in-memory RunState
    is per-host (because Pipeline.state is a fresh RunState())."""
    runner = Runner(_scope())
    def factory():
        ctx = PipelineContext(scope=runner.scope)
        return Pipeline(runner, stages, context=ctx)
    return factory


# ============================================================
# Basic shape
# ============================================================


class TestFanoutShape:
    async def test_empty_hosts(self):
        dag = DAG().add(Node(id="a"))
        factory = make_pipeline_factory({"a": make_recording_stage("a")})
        fanout = Fanout(factory, max_concurrency=4)
        results = await fanout.run(dag, hosts=[])
        assert results == []

    async def test_single_host(self):
        dag = DAG().add(Node(id="a"))
        factory = make_pipeline_factory({"a": make_recording_stage("a")})
        fanout = Fanout(factory, max_concurrency=4)
        results = await fanout.run(dag, hosts=["a.example.com"])
        assert len(results) == 1
        assert results[0].host == "a.example.com"
        assert len(results[0].outcomes) == 1
        assert results[0].outcomes[0].status == "done"

    async def test_multiple_hosts_all_processed(self):
        dag = DAG().add(Node(id="a"))
        stage = make_recording_stage("a", sleep_s=0.01)
        factory = make_pipeline_factory({"a": stage})
        fanout = Fanout(factory, max_concurrency=4)
        hosts = [f"h{i}.example.com" for i in range(8)]
        results = await fanout.run(dag, hosts=hosts)
        assert len(results) == 8
        assert {r.host for r in results} == set(hosts)
        # All hosts produced 1 outcome (one stage, done)
        assert all(len(r.outcomes) == 1 for r in results)
        assert all(r.outcomes[0].status == "done" for r in results)
        # Recording stage saw all 8 hosts
        assert len(stage._seen) == 8  # type: ignore[attr-defined]

    async def test_per_host_outcomes_returned(self):
        dag = DAG()
        dag.add(Node(id="a"))
        dag.add(Node(id="b", depends_on=["a"]))
        factory = make_pipeline_factory({
            "a": make_recording_stage("a", sleep_s=0.01),
            "b": make_recording_stage("b", sleep_s=0.01),
        })
        fanout = Fanout(factory, max_concurrency=4)
        results = await fanout.run(dag, hosts=["x.com", "y.com"])
        assert len(results) == 2
        for r in results:
            assert len(r.outcomes) == 2
            by_id = {o.node_id: o for o in r.outcomes}
            assert by_id["a"].status == "done"
            assert by_id["b"].status == "done"


# ============================================================
# Concurrency cap
# ============================================================


class TestFanoutConcurrency:
    async def test_concurrency_cap_respected(self):
        dag = DAG().add(Node(id="a"))
        # 8 hosts of 100ms each. With cap=2, expect ~400ms wall.
        stage = make_recording_stage("a", sleep_s=0.1)
        factory = make_pipeline_factory({"a": stage})
        fanout = Fanout(factory, max_concurrency=2)
        hosts = [f"h{i}.example.com" for i in range(8)]
        t0 = time.monotonic()
        results = await fanout.run(dag, hosts=hosts)
        wall = time.monotonic() - t0
        # 8 hosts / 2 concurrent / 0.1s = 0.4s
        # Allow 0.3s lower bound, 1.0s upper bound.
        assert 0.3 < wall < 1.0, f"wall {wall:.3f}s out of expected band"
        assert len(results) == 8

    async def test_no_cap_means_unbounded_concurrency(self):
        dag = DAG().add(Node(id="a"))
        stage = make_recording_stage("a", sleep_s=0.1)
        factory = make_pipeline_factory({"a": stage})
        # cap=100 effectively means unbounded for 8 hosts
        fanout = Fanout(factory, max_concurrency=100)
        hosts = [f"h{i}.example.com" for i in range(8)]
        t0 = time.monotonic()
        results = await fanout.run(dag, hosts=hosts)
        wall = time.monotonic() - t0
        assert wall < 0.4, f"expected near-0.1s wall, got {wall:.3f}s"
        assert len(results) == 8


# ============================================================
# State isolation per host (the bug we caught)
# ============================================================


class TestFanoutStateIsolation:
    async def test_per_host_state_does_not_leak(self):
        """Each host must see its own RunState — host A producing a
        `seed` artifact must NOT cause host B's gated stage to fire
        (B has no seed). This is the regression test for the race
        we caught: a single shared Pipeline.state across concurrent
        hosts was leaking host A's artifacts into host B's predicate
        evaluation.
        """
        dag = DAG()
        dag.add(Node(id="seed", outputs={"seed"}))
        dag.add(Node(
            id="gated", depends_on=["seed"],
            should_run=lambda s: s.from_node("seed", "seed") > 0,
        ))

        async def seed_stage(runner, host, ctx):
            if host == "produce.example.com":
                return [OutputItem("seed", "x")]
            return []
        async def gated_stage(runner, host, ctx):
            return [OutputItem("gated", f"g-{host}")]

        factory = make_pipeline_factory({"seed": seed_stage, "gated": gated_stage})
        fanout = Fanout(factory, max_concurrency=2)
        results = await fanout.run(dag, hosts=[
            "produce.example.com",
            "no-seed.example.com",
            "produce.example.com",  # second time — should still get gated
        ])
        for r in results:
            by_id = {o.node_id: o for o in r.outcomes}
            if r.host == "produce.example.com":
                assert by_id["gated"].status == "done"
            else:
                assert by_id["gated"].status == "skipped"


# ============================================================
# Resume integration
# ============================================================


class TestFanoutResume:
    async def test_fanout_via_resumable_pipeline_skips_done(self, tmp_path: Path):
        """End-to-end: use ResumablePipeline + Fanout. Pre-mark one
        host as done in the State DB. Verify the stage is NOT re-run
        for that host.
        """
        from loom.resume import ResumablePipeline
        db_path = tmp_path / "state.db"
        with State(db_path) as st:
            rid = st.start_run("example.com")
            runner = Runner(_scope())
            invocations: list[str] = []
            async def probe_stage(runner, host, ctx):
                invocations.append(host)
                return [OutputItem("probe", host)]

            # Factory creates a ResumablePipeline per host, sharing
            # the same State DB so all writes hit the same rows.
            def factory():
                ctx = PipelineContext(scope=runner.scope, state=st, run_id=rid)
                return ResumablePipeline(runner, {"probe": probe_stage},
                                          context=ctx)
            # Pre-mark hostA as done
            st.mark(rid, "hostA.example.com", "probe", "probe", "done")
            dag = DAG().add(Node(id="probe"))
            fanout = Fanout(factory, max_concurrency=2)
            results = await fanout.run(dag, hosts=[
                "hostA.example.com",  # should skip
                "hostB.example.com",  # should run
            ])
            # invocations: only hostB
            assert "hostA.example.com" not in invocations
            assert "hostB.example.com" in invocations
            # The state DB has hostA still as 'done' and hostB as 'done'
            assert st.is_done(rid, "hostA.example.com", "probe", "probe")
            assert st.is_done(rid, "hostB.example.com", "probe", "probe")
            # outcomes: hostA is skipped (synth), hostB is done
            by_host = {r.host: r for r in results}
            by_id_a = {o.node_id: o for o in by_host["hostA.example.com"].outcomes}
            by_id_b = {o.node_id: o for o in by_host["hostB.example.com"].outcomes}
            assert by_id_a["probe"].status == "skipped"
            assert by_id_b["probe"].status == "done"


# ============================================================
# Batches
# ============================================================


class TestFanoutBatches:
    async def test_batches_process_in_order(self):
        dag = DAG().add(Node(id="a"))
        stage = make_recording_stage("a", sleep_s=0.01)
        factory = make_pipeline_factory({"a": stage})
        fanout = Fanout(factory, max_concurrency=4)
        hosts = [f"h{i}" for i in range(7)]
        results = await fanout.run_batches(dag, hosts, batch_size=3)
        # 3 + 3 + 1 = 7 results
        assert len(results) == 7
        assert {r.host for r in results} == set(hosts)

    async def test_batches_with_delay(self):
        dag = DAG().add(Node(id="a"))
        stage = make_recording_stage("a", sleep_s=0.01)
        factory = make_pipeline_factory({"a": stage})
        fanout = Fanout(factory, max_concurrency=4)
        hosts = [f"h{i}" for i in range(4)]
        t0 = time.monotonic()
        results = await fanout.run_batches(dag, hosts, batch_size=2,
                                            inter_batch_delay_s=0.1)
        wall = time.monotonic() - t0
        # 2 batches → 1 inter-batch delay of 100ms
        assert wall >= 0.1, f"inter-batch delay not respected: {wall:.3f}s"
        assert len(results) == 4
