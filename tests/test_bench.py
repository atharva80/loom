"""loom.bench tests.

We don't time-assert (CI is too noisy); we just assert the bench module
imports, runs, and returns BenchResults with the right shape. Timing
results are captured in test_bench_speedups for diagnostic purposes
but with very loose bounds.
"""

from __future__ import annotations

import asyncio

import pytest

from loom.bench import (
    BenchResult,
    bench_chain,
    bench_diamond,
    bench_fanout,
    bench_subdomain_pipeline,
)


def _check(seq: BenchResult, par: BenchResult, expect_outcomes: int):
    assert isinstance(seq, BenchResult)
    assert isinstance(par, BenchResult)
    assert seq.wall_time_s > 0
    assert par.wall_time_s > 0
    assert len(seq.outcomes) == expect_outcomes
    assert len(par.outcomes) == expect_outcomes
    # Subdomain pipeline has a `screenshot` stage with a should_run
    # predicate that requires upstream live_host items; synthetic
    # stages emit `bench` artifacts, so screenshot is skipped there.
    # All other bench DAGs should have all-done outcomes.
    for o in seq.outcomes:
        assert o.status in ("done", "skipped")
    for o in par.outcomes:
        assert o.status in ("done", "skipped")


class TestBenchShape:
    async def test_fanout_shape(self):
        seq, par = await bench_fanout()
        _check(seq, par, expect_outcomes=3)
        # Parallel MUST be faster than sequential (1.75x expected).
        assert par.wall_time_s < seq.wall_time_s, (
            f"expected parallel < sequential; got {par.wall_time_s} vs {seq.wall_time_s}"
        )

    async def test_chain_shape(self):
        seq, par = await bench_chain()
        _check(seq, par, expect_outcomes=3)
        # Chain has no parallelism opportunity; parallel should ~= sequential.
        # Allow 50% slack.
        ratio = par.wall_time_s / seq.wall_time_s
        assert 0.5 < ratio < 1.5, f"chain ratio {ratio:.2f}x out of band"

    async def test_diamond_shape(self):
        seq, par = await bench_diamond()
        _check(seq, par, expect_outcomes=4)
        # Diamond has one parallel level; parallel should be faster.
        assert par.wall_time_s < seq.wall_time_s

    async def test_subdomain_pipeline_shape(self):
        seq, par = await bench_subdomain_pipeline()
        _check(seq, par, expect_outcomes=4)


class TestBenchRealisticSpeeds:
    """These tests have generous bounds — they verify the *direction* of
    speedup but allow 50% slack for CI noise."""

    async def test_fanout_speedup_direction(self):
        seq, par = await bench_fanout()
        # Expected: ~1.75x. Allow 1.2x as a loose lower bound.
        speedup = seq.wall_time_s / par.wall_time_s
        assert speedup > 1.2, f"fanout speedup only {speedup:.2f}x"

    async def test_chain_no_speedup(self):
        seq, par = await bench_chain()
        speedup = seq.wall_time_s / par.wall_time_s
        # Chain must NOT speed up (no parallelism opportunity).
        assert speedup < 1.5, f"chain unexpectedly sped up: {speedup:.2f}x"

    async def test_diamond_speedup_direction(self):
        seq, par = await bench_diamond()
        speedup = seq.wall_time_s / par.wall_time_s
        assert speedup > 1.2, f"diamond speedup only {speedup:.2f}x"
