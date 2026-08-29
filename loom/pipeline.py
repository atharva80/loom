"""loom.pipeline — Orchestrator that drives a DAG with the Runner.

The pipeline is the runtime that turns a DAG into a real run. It:

  1. Walks the DAG level by level (topological).
  2. At each level, runs all ready nodes concurrently (asyncio.gather).
  3. For each node, calls a `Stage` — a callable that takes (host, ctx)
     and returns a list of artifacts.
  4. Updates RunState with each node's results and artifacts.
  5. Skips nodes whose should_run predicate is False (marks them skipped).
  6. Persists per-tool state via the State module and emits per-artifact
     events via the EventLog.

The pipeline is what the CLI (F10) calls. It's also the integration test
target for F11 (benchmark vs /opt/tools/recon.sh).
"""

from __future__ import annotations

import asyncio
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable, Optional

from .dag import DAG, Node, RunState
from .eventlog import EventLog
from .runner import OutputItem, Runner, RunResult
from .scope import Scope
from .state import State


# A Stage is a coroutine that does the actual work for one node on one
# target (host or domain). Returns a list of artifacts it produced.
#
# The signature: async def stage(runner, host, ctx) -> list[OutputItem]
#  - runner: the Runner instance (for sub-tool invocations)
#  - host: the target host/domain for this invocation
#  - ctx: shared per-run context (e.g. event log, state, run_id, scope)
#
# Stages can be registered by name in the orchestrator or passed inline
# to Pipeline.run(dag, stages=...).
StageFn = Callable[[Runner, str, "PipelineContext"], Awaitable[list[OutputItem]]]


@dataclass
class PipelineContext:
    """Shared, read-mostly context passed to every Stage invocation."""
    scope: Scope
    eventlog: Optional[EventLog] = None
    state: Optional[State] = None
    run_id: Optional[int] = None
    # Per-stage working directory (where tools should write outputs).
    workdir: Optional[Path] = None
    # Free-form bag for cross-stage data (e.g. config, secrets paths).
    extras: dict = field(default_factory=dict)


@dataclass
class NodeOutcome:
    node_id: str
    status: str          # done | failed | skipped | timeout
    duration_s: float
    items: list[OutputItem] = field(default_factory=list)
    error: Optional[str] = None
    # When True, the orchestrator must NOT write this outcome to the
    # State DB — the outcome was synthesized because the work was
    # already done in a prior run, and we don't want to clobber the
    # existing row with a synthetic 'skipped' status. Set by
    # ResumablePipeline when it gates a stage via should_skip.
    from_resume: bool = False


class Pipeline:
    """Drives a DAG end-to-end.

    Usage:
        pipeline = Pipeline(runner=Runner(scope, ...), stages={...})
        outcomes = await pipeline.run(dag)
    """
    def __init__(
        self,
        runner: Runner,
        stages: dict[str, StageFn],
        context: Optional[PipelineContext] = None,
        # Max concurrent stages within a single level. None = no limit.
        max_concurrency: Optional[int] = None,
    ):
        self.runner = runner
        self.stages = stages
        self.context = context or PipelineContext(scope=runner.scope)
        # Ensure context's scope is the runner's scope (consistency).
        self.context.scope = runner.scope
        self.sem = asyncio.Semaphore(max_concurrency) if max_concurrency else None
        self.state = RunState()

    async def _invoke_stage(
        self, node: Node, host: str
    ) -> NodeOutcome:
        """Run a single stage invocation. Honors the concurrency semaphore."""
        t0 = time.monotonic()
        if node.id not in self.stages:
            err = f"no stage registered for node {node.id!r}"
            return NodeOutcome(node_id=node.id, status="failed",
                               duration_s=time.monotonic() - t0, error=err)
        stage_fn = self.stages[node.id]
        async def _do():
            return await stage_fn(self.runner, host, self.context)
        try:
            if self.sem:
                async with self.sem:
                    items = await _do()
            else:
                items = await _do()
            duration = time.monotonic() - t0
            return NodeOutcome(node_id=node.id, status="done",
                               duration_s=duration, items=items)
        except Exception as e:
            duration = time.monotonic() - t0
            tb = traceback.format_exc(limit=2)
            return NodeOutcome(node_id=node.id, status="failed",
                               duration_s=duration,
                               error=f"{type(e).__name__}: {e}\n{tb}")

    def _mark_state(self, outcome: NodeOutcome, host: str) -> None:
        """Update the persistent State for a per-host node outcome."""
        st = self.context.state
        rid = self.context.run_id
        if st is None or rid is None:
            return
        # tool = node_id (one row per (run, host, tool=node, stage=node))
        try:
            st.mark(
                run_id=rid, host=host, tool=outcome.node_id,
                stage=outcome.node_id, status=outcome.status,
                duration_s=outcome.duration_s, error=outcome.error,
            )
        except Exception:
            # don't let a state-write error break the run
            pass

    def _emit_events(self, outcome: NodeOutcome, host: str) -> None:
        """Write one event per item to the eventlog.

        NOTE: the Runner is the single event emitter (it appends per
        item with source=tool). This pipeline-level emitter was
        removed because it double-wrote every item when driven by the
        orchestrator (verified live: nuclei findings appeared twice).
        Kept as a no-op hook in case a future pipeline needs to add
        derived events.
        """
        return

    def _update_run_state(self, outcome: NodeOutcome) -> None:
        """Update the in-memory RunState used by should_run predicates."""
        self.state.results[outcome.node_id] = outcome.status
        # Count artifacts by (node_id, artifact_type)
        for it in outcome.items:
            key = (outcome.node_id, it.kind)
            self.state.artifacts[key] = self.state.artifacts.get(key, 0) + 1

    async def run_level(
        self, dag: DAG, level: list[str], host: str
    ) -> list[NodeOutcome]:
        """Run a single level's nodes. Skipped nodes are reported but not
        invoked. Failed nodes do not stop the level — other nodes still run
        (so e.g. nuclei on a single failing host doesn't block scanning
        other hosts)."""
        outcomes: list[NodeOutcome] = []

        # First: compute skipped nodes (predicates that returned False).
        skipped = dag.skipped(self.state)
        for nid in level:
            if nid in skipped:
                outcome = NodeOutcome(node_id=nid, status="skipped",
                                      duration_s=0.0)
                self.state.results[nid] = "skipped"
                outcomes.append(outcome)
                if not outcome.from_resume:
                    self._mark_state(outcome, host)
                self._emit_events(outcome, host)

        # Then: concurrently invoke the rest.
        to_invoke = [nid for nid in level if nid not in skipped]
        if not to_invoke:
            return outcomes

        # Build coroutines for each node in the level.
        coros = []
        for nid in to_invoke:
            node = dag.get(nid)
            coros.append(self._invoke_stage(node, host))

        # Run concurrently. Return exceptions as outcomes rather than raising.
        results = await asyncio.gather(*coros, return_exceptions=True)
        for nid, res in zip(to_invoke, results):
            outcome: NodeOutcome
            if isinstance(res, BaseException):
                outcome = NodeOutcome(node_id=nid, status="failed",
                                      duration_s=0.0,
                                      error=f"{type(res).__name__}: {res}")
            else:
                outcome = res  # type: ignore[assignment]
            self._update_run_state(outcome)
            outcomes.append(outcome)
            if not outcome.from_resume:
                self._mark_state(outcome, host)
            self._emit_events(outcome, host)

        return outcomes

    async def run(self, dag: DAG, host: str = "") -> list[NodeOutcome]:
        """Run the entire DAG against `host`. Returns all outcomes in the
        order they were processed (level by level, level-internal order
        is the dispatch order)."""
        dag.validate()
        all_outcomes: list[NodeOutcome] = []
        for level in dag.levels():
            level_outcomes = await self.run_level(dag, level, host)
            all_outcomes.extend(level_outcomes)
        return all_outcomes
