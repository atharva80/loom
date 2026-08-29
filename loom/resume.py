"""loom.resume — Crash-recovery layer over the orchestrator.

Long runs (multi-host, multi-hour) crash. Loom's resume layer:

  * Before a stage is invoked, consults `State.should_skip(run_id, host,
    tool, stage)`. If True, the stage is treated as already complete and
    NOT re-run.
  * Marks every stage `running` BEFORE invoking it, so a SIGKILL leaves
    a `running` row. On resume, `running` rows are treated as failed
    (the previous run didn't finish — redo).
  * Provides `Pipeline.run_resumable(dag, host, run_id)`: same as
    `Pipeline.run` but uses the should_skip gate per stage.
  * Provides `latest_inflight_run(state, domain) -> int | None`: find
    the most recent unfinished run for a domain so users can
    `loom resume <domain>` instead of starting over.

The "host" dimension: in v1 the orchestrator is per-host (one pipeline
per host). So `should_skip(run_id, host, tool_id, stage_id)` keys match
what `state.mark` writes when the runner records each stage.
"""

from __future__ import annotations

from typing import Optional

from .dag import DAG, Node
from .pipeline import NodeOutcome, Pipeline, PipelineContext, StageFn
from .state import State


def latest_inflight_run(state: State, domain: str) -> Optional[int]:
    """Return the most recent unfinished run_id for `domain`, or None.
    A run is 'inflight' if it has no `finished_at` timestamp.
    """
    for r in state.list_runs(domain=domain):
        if r.get("finished_at") is None:
            return r["id"]
    return None


def seed_run_state_from_db(state: State, run_id: int, dag: DAG) -> dict[str, str]:
    """Build a results dict (node_id -> status) for nodes whose state
    row is already `done` or `skipped`. Used to skip work in a resumed run.

    NOTE: this is a per-run helper. The Pipeline walks the DAG and calls
    `state.should_skip(...)` per stage, so the orchestrator stays the
    source of truth for ordering.
    """
    seed: dict[str, str] = {}
    for node in dag.nodes():
        # host="" is a sentinel for "any host" / pipeline-level skip
        if state.should_skip(run_id, "", node.id, node.id):
            seed[node.id] = "done"
    return seed


class ResumablePipeline(Pipeline):
    """A Pipeline that respects State.should_skip per stage.

    Behaves identically to `Pipeline` for fresh runs (no rows exist yet,
    nothing is skipped). For resumed runs, every stage whose state row is
    `done` or `skipped` is bypassed — its previous outcome is replayed
    as a `skipped`-equivalent (the items from the original run are not
    recovered; the user re-reads them from the eventlog).

    Race semantics: a row that is `running` from a crashed prior run is
    treated as NOT-skipped. The new run will mark it `done|failed|timeout`
    again, which is the desired behavior (re-run the half-finished work).
    """
    def __init__(
        self,
        runner,
        stages: dict[str, StageFn],
        context: Optional[PipelineContext] = None,
        max_concurrency: Optional[int] = None,
    ):
        super().__init__(runner, stages, context, max_concurrency)
        # Eager: pick up state + run_id from the context so the resume
        # gate is active even when callers use .run() directly (e.g. the
        # Fanout, which loops over hosts and calls .run() per host).
        self._state = context.state if context else None
        self._run_id = context.run_id if context else None

    async def _invoke_stage(self, node: Node, host: str) -> NodeOutcome:
        # NEW: gate on should_skip before invoking.
        if self._state is not None and self._run_id is not None:
            if self._state.should_skip(
                self._run_id, host, node.id, node.id
            ):
                return NodeOutcome(
                    node_id=node.id, status="skipped", duration_s=0.0,
                    from_resume=True,
                )
        return await super()._invoke_stage(node, host)

    async def run_resumable(
        self, dag: DAG, host: str = "", run_id: Optional[int] = None,
    ) -> list[NodeOutcome]:
        """Run the DAG, skipping stages already marked done/skipped in
        `State` for the given run_id. If `run_id` is None, falls back to
        `context.run_id` (same as `run()`)."""
        if self.context.state is not None:
            self._state = self.context.state
        self._run_id = run_id or self.context.run_id
        return await self.run(dag, host=host)


def make_resumable(pipeline: Pipeline) -> ResumablePipeline:
    """Promote a regular Pipeline to a ResumablePipeline, preserving its
    runner, stages, and context. The original pipeline is not mutated."""
    rp = ResumablePipeline(
        runner=pipeline.runner,
        stages=pipeline.stages,
        context=pipeline.context,
        max_concurrency=pipeline.sem._value if pipeline.sem else None,
    )
    return rp
