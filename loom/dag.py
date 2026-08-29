"""loom.dag — Pure DAG over pipeline stages.

The DAG is the central data structure of loom. Each node is a pipeline
stage (e.g. "subenum", "probe", "fuzz", "scan"). Edges represent
producer → consumer relationships on the stream of artifacts (subdomains,
URLs, hosts, findings, raw lines).

Properties:
  * Topological levels: nodes in the same level can run concurrently.
  * Cycle detection: any cycle is an error (construct-time).
  * Per-node `should_run` predicate: skip a node if its predicate is false
    given the upstream artifact counts (e.g. skip nuclei if no live hosts).
  * Per-node `inputs` / `outputs`: the artifact types it consumes/produces.
    Used for diagnostics, not scheduling.

This module is PURE — no subprocess, no I/O. The orchestrator (F8) drives
actual execution; the DAG just decides *what* and *in what order*.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional


@dataclass
class Node:
    """A single pipeline stage."""
    id: str
    # Names of artifact streams this node produces (e.g. {"subdomain", "url"}).
    outputs: set[str] = field(default_factory=set)
    # Names of artifact streams this node consumes. Used for diagnostic
    # edges only — runtime uses the explicit `depends_on` list.
    inputs: set[str] = field(default_factory=set)
    # IDs of nodes that must complete before this one runs.
    depends_on: list[str] = field(default_factory=list)
    # Optional predicate(run_state) -> bool. If False, the node is marked
    # "skipped" instead of "done" at scheduling time.
    should_run: Optional[Callable[["RunState"], bool]] = None
    # Human-readable description.
    description: str = ""

    def __post_init__(self):
        if not self.id:
            raise ValueError("node id must be non-empty")
        if " " in self.id:
            raise ValueError(f"node id must not contain spaces: {self.id!r}")


@dataclass
class RunState:
    """Mutable state passed to `should_run` predicates and updated as
    nodes complete. Keyed by node id → result string.

    Result strings: "done" | "skipped" | "failed" | "timeout" | absent
    """
    results: dict[str, str] = field(default_factory=dict)
    # Artifact counts from each completed node. Keyed by (node_id, artifact).
    artifacts: dict[tuple[str, str], int] = field(default_factory=dict)

    def is_done(self, node_id: str) -> bool:
        return self.results.get(node_id) == "done"

    def is_skipped(self, node_id: str) -> bool:
        return self.results.get(node_id) == "skipped"

    def is_completed(self, node_id: str) -> bool:
        """True if the node finished in any terminal state (done/skipped/
        failed/timeout). Pending = not completed."""
        return node_id in self.results

    def total(self, artifact: str) -> int:
        """Sum artifact counts across all nodes that produced it."""
        return sum(c for (nid, art), c in self.artifacts.items() if art == artifact)

    def from_node(self, node_id: str, artifact: str) -> int:
        return self.artifacts.get((node_id, artifact), 0)


class CycleError(ValueError):
    """Raised when the DAG contains a cycle."""


class DuplicateNodeError(ValueError):
    """Raised when two nodes share the same id."""


class UnknownNodeError(KeyError):
    """Raised when an edge references a node not in the DAG."""


class DAG:
    """Directed acyclic graph of pipeline stages.

    Nodes are stored in insertion order. Edges are derived from
    `Node.depends_on` and the artifact-type edges (a node with
    input "subdomain" and a producer of "subdomain" gets an implicit edge).
    """
    def __init__(self):
        self._nodes: dict[str, Node] = {}
        self._order: list[str] = []

    # ---- construction ----
    def add(self, node: Node) -> "DAG":
        if node.id in self._nodes:
            raise DuplicateNodeError(f"node {node.id!r} already in DAG")
        self._nodes[node.id] = node
        self._order.append(node.id)
        return self

    def add_many(self, nodes: Iterable[Node]) -> "DAG":
        for n in nodes:
            self.add(n)
        return self

    # ---- access ----
    def __contains__(self, node_id: str) -> bool:
        return node_id in self._nodes

    def __len__(self) -> int:
        return len(self._nodes)

    def __iter__(self):
        return iter(self._order)

    def get(self, node_id: str) -> Node:
        if node_id not in self._nodes:
            raise UnknownNodeError(node_id)
        return self._nodes[node_id]

    def nodes(self) -> list[Node]:
        return [self._nodes[nid] for nid in self._order]

    def ids(self) -> list[str]:
        return list(self._order)

    def dependencies(self, node_id: str) -> list[str]:
        """All nodes that must complete before `node_id` can run.
        Combines explicit `depends_on` and implicit artifact edges."""
        node = self.get(node_id)
        deps = set(node.depends_on)
        # Add implicit deps: any node whose output appears in this node's inputs.
        for other_id, other in self._nodes.items():
            if other_id == node_id:
                continue
            if other.outputs & node.inputs:
                deps.add(other_id)
        return [d for d in self._order if d in deps]

    def dependents(self, node_id: str) -> list[str]:
        """All nodes that depend on `node_id`."""
        return [nid for nid in self._order if node_id in self.dependencies(nid)]

    # ---- validation ----
    def validate(self) -> None:
        """Raise CycleError if the DAG has a cycle. Call before scheduling.
        Also raises UnknownNodeError for dangling dependencies."""
        for nid in self._order:
            for dep in self._nodes[nid].depends_on:
                if dep not in self._nodes:
                    raise UnknownNodeError(
                        f"node {nid!r} depends on unknown node {dep!r}"
                    )
        # Kahn's algorithm for cycle detection
        in_deg = {nid: 0 for nid in self._order}
        for nid in self._order:
            for d in self.dependencies(nid):
                in_deg[nid] += 1
        queue = [nid for nid, d in in_deg.items() if d == 0]
        visited = 0
        while queue:
            n = queue.pop(0)
            visited += 1
            for dep_id in self.dependents(n):
                in_deg[dep_id] -= 1
                if in_deg[dep_id] == 0:
                    queue.append(dep_id)
        if visited != len(self._order):
            raise CycleError("DAG contains a cycle")

    # ---- scheduling ----
    def levels(self) -> list[list[str]]:
        """Topological levels. Each level is a list of node IDs that can
        run concurrently. Level 0 = nodes with no dependencies.
        Raises CycleError if the DAG has a cycle."""
        self.validate()
        node_level: dict[str, int] = {}
        levels: list[list[str]] = []
        # Process nodes in dependency order via Kahn's algorithm
        remaining = set(self._order)
        placed: set[str] = set()
        while remaining:
            # All remaining nodes whose deps are all placed
            ready = [
                nid for nid in remaining
                if all(d in placed for d in self.dependencies(nid))
            ]
            if not ready:
                # Shouldn't happen after validate() but be defensive
                raise CycleError(
                    f"DAG scheduling stuck; remaining={remaining}, placed={placed}"
                )
            ready.sort()  # deterministic order
            levels.append(ready)
            for nid in ready:
                placed.add(nid)
            remaining -= set(ready)
        return levels

    def plan(self) -> list[list[str]]:
        """Synonym for `levels()` for callers that read better as
        "the execution plan"."""
        return self.levels()

    def ready(self, state: RunState) -> list[str]:
        """Nodes whose dependencies are complete AND whose should_run
        predicate (if any) returns True. These are the next to dispatch."""
        ready: list[str] = []
        for nid in self._order:
            if state.is_completed(nid):
                continue
            deps = self.dependencies(nid)
            if not all(state.is_completed(d) for d in deps):
                continue
            node = self._nodes[nid]
            if node.should_run is not None and not node.should_run(state):
                continue
            ready.append(nid)
        return ready

    def skipped(self, state: RunState) -> list[str]:
        """Nodes whose dependencies are complete but whose should_run
        predicate returned False. These are 'skipped', not 'done'."""
        skipped: list[str] = []
        for nid in self._order:
            if state.is_completed(nid):
                continue
            deps = self.dependencies(nid)
            if not all(state.is_completed(d) for d in deps):
                continue
            node = self._nodes[nid]
            if node.should_run is not None and not node.should_run(state):
                skipped.append(nid)
        return skipped


def add_subdomain_pipeline(dag: DAG) -> DAG:
    """Add a canonical 4-stage subdomain pipeline:
        subenum → resolve → probe → screenshot
    Demonstrates: artifact-type edges, depends_on, and a should_run
    predicate on screenshot (only for live hosts).
    """
    dag.add(Node(
        id="subenum",
        outputs={"subdomain"},
        description="enumerate subdomains (subfinder + assetfinder)",
    ))
    dag.add(Node(
        id="resolve",
        inputs={"subdomain"},
        outputs={"host"},
        depends_on=["subenum"],
        description="resolve subdomains to IPs (dnsx)",
    ))
    dag.add(Node(
        id="probe",
        inputs={"host"},
        outputs={"live_host"},
        depends_on=["resolve"],
        description="HTTP probe live hosts (httpx)",
    ))
    dag.add(Node(
        id="screenshot",
        inputs={"live_host"},
        outputs={"screenshot"},
        depends_on=["probe"],
        should_run=lambda s: s.total("live_host") > 0,
        description="screenshot live hosts (gowitness)",
    ))
    return dag
