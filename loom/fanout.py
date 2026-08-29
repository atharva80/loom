"""loom.fanout — Per-host parallel execution of a per-host pipeline.

The orchestrator's `Pipeline.run(dag, host)` runs the DAG once for a
single host. The `Fanout` runs it N times — once per host — concurrently.

This is the multi-host primitive: take a list of 500 subdomains, run
the same probe pipeline on each, throttled by the shared RateLimiter,
with per-host state + resume.

Usage:
    def make_pipeline():
        return Pipeline(runner, stages, context=ctx)

    fanout = Fanout(make_pipeline, max_concurrency=20)
    results = await fanout.run(dag, hosts=[...])

Each host gets a fresh Pipeline (and thus a fresh in-memory RunState)
so concurrent hosts don't race on the same state object. The State
DB writes are serialized by SQLite WAL — that part is shared.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

from .dag import DAG
from .pipeline import NodeOutcome, Pipeline


PipelineFactory = Callable[[], Pipeline]


@dataclass
class FanoutResult:
    host: str
    outcomes: list[NodeOutcome]
    duration_s: float
    error: Optional[str] = None


class Fanout:
    """Drive a per-host Pipeline concurrently across many hosts.

    Takes a `PipelineFactory` rather than a single Pipeline so each
    host gets its own Pipeline (and thus its own RunState instance).
    The factory typically captures a shared scope, eventlog, state DB,
    and runner; the only thing that needs to be per-host is the
    Pipeline's in-memory RunState (because the predicates read from
    it and concurrent runs would race).
    """
    def __init__(self, pipeline_factory: PipelineFactory,
                 max_concurrency: int = 10):
        self.pipeline_factory = pipeline_factory
        self.sem = asyncio.Semaphore(max_concurrency)

    async def _run_host(self, dag: DAG, host: str) -> FanoutResult:
        async with self.sem:
            # Fresh pipeline per host → fresh in-memory RunState.
            # The factory's closure binds the shared State DB, EventLog,
            # RateLimiter, Runner, etc.
            pipeline = self.pipeline_factory()
            t0 = time.monotonic()
            try:
                outcomes = await pipeline.run(dag, host=host)
            except Exception as e:
                return FanoutResult(
                    host=host, outcomes=[], duration_s=time.monotonic() - t0,
                    error=f"{type(e).__name__}: {e}",
                )
            return FanoutResult(
                host=host, outcomes=outcomes,
                duration_s=time.monotonic() - t0,
            )

    async def run(self, dag: DAG, hosts: Iterable[str]) -> list[FanoutResult]:
        """Run the pipeline on each host, concurrently up to max_concurrency."""
        host_list = list(hosts)
        if not host_list:
            return []
        tasks = [self._run_host(dag, h) for h in host_list]
        return await asyncio.gather(*tasks, return_exceptions=False)

    async def run_batches(
        self, dag: DAG, hosts: Iterable[str], *, batch_size: int = 50,
        inter_batch_delay_s: float = 0.0,
    ) -> list[FanoutResult]:
        """Run in batches with an optional delay between batches.

        Useful for very large programs where you want to give the
        target a breather (or stay under an external rate limit
        that the per-program RateLimiter can't see).
        """
        host_list = list(hosts)
        all_results: list[FanoutResult] = []
        for i in range(0, len(host_list), batch_size):
            batch = host_list[i:i + batch_size]
            results = await self.run(dag, batch)
            all_results.extend(results)
            if i + batch_size < len(host_list) and inter_batch_delay_s > 0:
                await asyncio.sleep(inter_batch_delay_s)
        return all_results
