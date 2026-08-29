"""loom.bench — Microbenchmark for the orchestrator.

The point of loom is the scheduler. This module measures how the scheduler
performs vs a sequential baseline on a synthetic DAG that simulates the
shape of a real recon pipeline.

The synthetic DAG:
  - Stage "fast"  emits 1 artifact after 0.5s
  - Stage "slow"  emits 1 artifact after 2.0s
  - Stage "fuzzy" emits 10 artifacts after 1.0s

Sequential wall time: 0.5 + 2.0 + 1.0 = 3.5s
With concurrency (all three in the same level): ~2.0s (the longest)
Theoretical speedup: 1.75x

For a chain DAG (a → b → c) where each takes 1s, sequential is 3s and
parallel-within-level makes no difference (no two nodes are ready at once),
so we expect ~3s in both modes. This verifies the orchestrator doesn't
introduce spurious concurrency.

Run via: python -m loom.bench
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from .dag import DAG, Node, add_subdomain_pipeline
from .eventlog import EventLog
from .pipeline import Pipeline, PipelineContext, StageFn
from .runner import OutputItem, Runner
from .scope import Scope, from_dict as scope_from_dict


def _scope() -> Scope:
    return scope_from_dict({"name": "bench", "target": "example.com",
                            "rate_limit_rps": 1000})


def _delayed_stage(name: str, delay: float, n_items: int = 1) -> StageFn:
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        await asyncio.sleep(delay)
        return [OutputItem("bench", f"{name}-{i}") for i in range(n_items)]
    return _stage


@dataclass
class BenchResult:
    label: str
    wall_time_s: float
    outcomes: list


async def _run(dag: DAG, stages: dict[str, StageFn], max_concurrency=None) -> BenchResult:
    runner = Runner(_scope())
    pipeline = Pipeline(runner, stages, max_concurrency=max_concurrency)
    t0 = time.monotonic()
    outcomes = await pipeline.run(dag, host="example.com")
    wall = time.monotonic() - t0
    label = f"max_concurrency={max_concurrency}"
    return BenchResult(label=label, wall_time_s=wall, outcomes=outcomes)


async def bench_fanout() -> tuple[BenchResult, BenchResult]:
    """Three independent nodes: fast(0.5s), slow(2.0s), fuzzy(1.0s).
    Sequential = 3.5s. Parallel = ~2.0s.
    """
    dag = DAG()
    dag.add(Node(id="fast"))
    dag.add(Node(id="slow"))
    dag.add(Node(id="fuzzy"))
    stages = {
        "fast": _delayed_stage("fast", 0.5),
        "slow": _delayed_stage("slow", 2.0),
        "fuzzy": _delayed_stage("fuzzy", 1.0, n_items=10),
    }
    seq = await _run(dag, stages, max_concurrency=1)
    par = await _run(dag, stages, max_concurrency=None)
    return seq, par


async def bench_chain() -> tuple[BenchResult, BenchResult]:
    """a → b → c, each takes 1s. Sequential = parallel = 3s."""
    dag = DAG()
    dag.add(Node(id="a"))
    dag.add(Node(id="b", depends_on=["a"]))
    dag.add(Node(id="c", depends_on=["b"]))
    stages = {
        "a": _delayed_stage("a", 1.0),
        "b": _delayed_stage("b", 1.0),
        "c": _delayed_stage("c", 1.0),
    }
    seq = await _run(dag, stages, max_concurrency=1)
    par = await _run(dag, stages, max_concurrency=None)
    return seq, par


async def bench_diamond() -> tuple[BenchResult, BenchResult]:
    """a → {b, c} → d. a=0.5, b=1, c=1, d=0.5.
    Sequential: 0.5 + (1+1) + 0.5 = 3.0s
    Parallel: 0.5 + max(1,1) + 0.5 = 2.0s
    """
    dag = DAG()
    dag.add(Node(id="a"))
    dag.add(Node(id="b", depends_on=["a"]))
    dag.add(Node(id="c", depends_on=["a"]))
    dag.add(Node(id="d", depends_on=["b", "c"]))
    stages = {
        "a": _delayed_stage("a", 0.5),
        "b": _delayed_stage("b", 1.0),
        "c": _delayed_stage("c", 1.0),
        "d": _delayed_stage("d", 0.5),
    }
    seq = await _run(dag, stages, max_concurrency=1)
    par = await _run(dag, stages, max_concurrency=None)
    return seq, par


async def bench_subdomain_pipeline() -> tuple[BenchResult, BenchResult]:
    """Bundled 4-stage pipeline with the screenshot stage skipped.
    Stages: subenum=0.5, resolve=1.0, probe=0.8, screenshot=0.4.
    Sequential: 0.5+1.0+0.8+0.4 = 2.7s
    Parallel: max(0.5+1.0+0.8, 0.4) at probe's level; with
    subenum→resolve→probe all chained, parallel within-level makes
    no difference for the chain itself. So this should match sequential.
    """
    dag = add_subdomain_pipeline(DAG())
    stages = {
        "subenum": _delayed_stage("subenum", 0.5, n_items=3),
        "resolve": _delayed_stage("resolve", 1.0, n_items=3),
        "probe": _delayed_stage("probe", 0.8, n_items=1),  # 1 live_host
        "screenshot": _delayed_stage("screenshot", 0.4, n_items=1),
    }
    seq = await _run(dag, stages, max_concurrency=1)
    par = await _run(dag, stages, max_concurrency=None)
    return seq, par


def _print(label: str, seq: BenchResult, par: BenchResult) -> None:
    speedup = seq.wall_time_s / par.wall_time_s if par.wall_time_s > 0 else 0
    print(f"=== {label} ===")
    print(f"  sequential : {seq.wall_time_s:.3f}s  ({len(seq.outcomes)} outcomes)")
    print(f"  parallel   : {par.wall_time_s:.3f}s  ({len(par.outcomes)} outcomes)")
    print(f"  speedup    : {speedup:.2f}x")
    # Sanity: same number of outcomes in both
    assert len(seq.outcomes) == len(par.outcomes), (
        f"outcome count differs: {len(seq.outcomes)} vs {len(par.outcomes)}"
    )
    statuses_seq = sorted(o.status for o in seq.outcomes)
    statuses_par = sorted(o.status for o in par.outcomes)
    assert statuses_seq == statuses_par, (
        f"status sets differ: {statuses_seq} vs {statuses_par}"
    )
    print()


async def main() -> int:
    print("loom orchestrator benchmark")
    print("=" * 50)
    print()

    seq, par = await bench_fanout()
    _print("fanout (3 independent nodes, slow=2.0s)", seq, par)

    seq, par = await bench_chain()
    _print("chain (a→b→c, no parallelism possible)", seq, par)

    seq, par = await bench_diamond()
    _print("diamond (a→{b,c}→d, one parallel branch)", seq, par)

    seq, par = await bench_subdomain_pipeline()
    _print("bundled subdomain pipeline (4 stages, all chained)", seq, par)

    print("done. expect fanout speedup ~1.7x; chain ~1.0x; diamond ~1.5x; subdomain ~1.0x.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
