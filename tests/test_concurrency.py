"""Event-loop concurrency regression tests.

Live incident 2026-09-05: Runner used blocking subprocess calls inside
async stages, so one long stage (amass-brute, 15 min) held the event
loop thread and its level-mates never started (zero rows, zero
outputs, zero events after minutes). These tests pin concurrent
execution: two `sleep 2` stages behind max_concurrency=2 must finish
in ~2s, not ~4s.
"""

from __future__ import annotations

import time

import pytest

from loom.dag import DAG, Node
from loom.pipeline import Pipeline, PipelineContext
from loom.runner import Runner
from loom.scope import from_dict as scope_from_dict


def _scope():
    return scope_from_dict({"name": "t", "target": "example.com",
                            "rate_limit_rps": 1000})


def _two_sleepers():
    runner = Runner(_scope())

    async def sleeper(r, host, ctx):
        res = await r.run("sh", ["sh", "-c", "sleep 2"], stage="t",
                          host=host, parser="raw", timeout=30.0)
        assert res.exit_code == 0
        return res.items

    dag = DAG()
    dag.add(Node(id="a"))
    dag.add(Node(id="b"))
    stages = {"a": sleeper, "b": sleeper}
    ctx = PipelineContext(scope=runner.scope)
    pipe = Pipeline(runner, stages, context=ctx, max_concurrency=2)
    return pipe, dag


class TestLevelConcurrency:
    async def test_slow_stages_share_a_level(self):
        pipe, dag = _two_sleepers()
        t0 = time.monotonic()
        outcomes = await pipe.run(dag, host="example.com")
        dt = time.monotonic() - t0
        assert all(o.status == "done" for o in outcomes)
        assert dt < 3.5, f"stages ran serially: {dt:.1f}s for 2x sleep 2"

    async def test_streaming_stages_share_a_level(self):
        runner = Runner(_scope())

        async def sleeper(r, host, ctx):
            res = await r.run_streaming(
                "sh", ["sh", "-c", "sleep 2; echo hi"], stage="t",
                host=host, parser="raw", timeout=30.0)
            assert res.exit_code == 0
            return res.items

        dag = DAG()
        dag.add(Node(id="a"))
        dag.add(Node(id="b"))
        ctx = PipelineContext(scope=runner.scope)
        pipe = Pipeline(runner, {"a": sleeper, "b": sleeper},
                        context=ctx, max_concurrency=2)
        t0 = time.monotonic()
        outcomes = await pipe.run(dag, host="example.com")
        dt = time.monotonic() - t0
        assert all(o.status == "done" for o in outcomes)
        assert dt < 3.5, f"streaming stages ran serially: {dt:.1f}s"
