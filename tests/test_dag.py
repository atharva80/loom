"""loom.dag tests.

Pure tests, no I/O. Cover:
  * Construction + validation (duplicates, dangling deps, cycles)
  * Topological levels (linear, diamond, fan-out, fan-in, deep chain)
  * should_run predicates (skip when no upstream, run when there is)
  * Implicit artifact edges
  * ready() and skipped() mid-execution
  * Bundled subdomain pipeline factory
"""

from __future__ import annotations

import pytest

from loom.dag import (
    DAG,
    CycleError,
    DuplicateNodeError,
    Node,
    RunState,
    UnknownNodeError,
    add_subdomain_pipeline,
)


# ============================================================
# Construction & validation
# ============================================================


class TestConstruction:
    def test_empty_dag(self):
        dag = DAG()
        assert len(dag) == 0
        assert list(dag) == []
        assert dag.levels() == []

    def test_add_node(self):
        dag = DAG()
        dag.add(Node(id="a"))
        assert len(dag) == 1
        assert "a" in dag
        assert dag.get("a").id == "a"

    def test_duplicate_node_raises(self):
        dag = DAG()
        dag.add(Node(id="a"))
        with pytest.raises(DuplicateNodeError):
            dag.add(Node(id="a"))

    def test_add_many(self):
        dag = DAG()
        dag.add_many([Node(id="a"), Node(id="b"), Node(id="c")])
        assert dag.ids() == ["a", "b", "c"]

    def test_unknown_node_raises(self):
        dag = DAG()
        with pytest.raises(UnknownNodeError):
            dag.get("nope")

    def test_contains(self):
        dag = DAG().add(Node(id="a"))
        assert "a" in dag
        assert "b" not in dag

    def test_empty_id_rejected(self):
        with pytest.raises(ValueError):
            Node(id="")
        with pytest.raises(ValueError):
            Node(id="a b")  # spaces not allowed


# ============================================================
# Dependency wiring
# ============================================================


class TestDependencies:
    def test_explicit_depends_on(self):
        dag = DAG()
        dag.add(Node(id="a"))
        dag.add(Node(id="b", depends_on=["a"]))
        assert dag.dependencies("b") == ["a"]
        assert dag.dependencies("a") == []

    def test_implicit_artifact_edge(self):
        # a produces "subdomain"; b consumes "subdomain" → b depends on a
        # even without explicit depends_on.
        dag = DAG()
        dag.add(Node(id="a", outputs={"subdomain"}))
        dag.add(Node(id="b", inputs={"subdomain"}))
        assert dag.dependencies("b") == ["a"]

    def test_explicit_beats_implicit(self):
        # If b explicitly depends on c, it should list c, not a (the
        # implicit producer). Both end up in deps.
        dag = DAG()
        dag.add(Node(id="a", outputs={"subdomain"}))
        dag.add(Node(id="c"))
        dag.add(Node(id="b", inputs={"subdomain"}, depends_on=["c"]))
        deps = dag.dependencies("b")
        assert "a" in deps
        assert "c" in deps

    def test_no_false_implicit_edge(self):
        # a produces "subdomain"; b consumes "host" → no edge
        dag = DAG()
        dag.add(Node(id="a", outputs={"subdomain"}))
        dag.add(Node(id="b", inputs={"host"}))
        assert dag.dependencies("b") == []

    def test_dependents(self):
        dag = DAG()
        dag.add(Node(id="a"))
        dag.add(Node(id="b", depends_on=["a"]))
        dag.add(Node(id="c", depends_on=["a"]))
        assert sorted(dag.dependents("a")) == ["b", "c"]
        assert dag.dependents("b") == []

    def test_dangling_dependency_raises(self):
        dag = DAG()
        dag.add(Node(id="a", depends_on=["ghost"]))
        with pytest.raises(UnknownNodeError):
            dag.validate()


# ============================================================
# Cycle detection
# ============================================================


class TestCycles:
    def test_self_loop_detected(self):
        dag = DAG()
        # Force a self-loop by mutating after add (bypasses input check).
        n = Node(id="a")
        dag.add(n)
        n.depends_on = ["a"]
        with pytest.raises(CycleError):
            dag.validate()

    def test_two_node_cycle_detected(self):
        dag = DAG()
        a = Node(id="a")
        b = Node(id="b", depends_on=["a"])
        dag.add_many([a, b])
        a.depends_on = ["b"]
        with pytest.raises(CycleError):
            dag.validate()

    def test_three_node_cycle_detected(self):
        dag = DAG()
        a = Node(id="a")
        b = Node(id="b", depends_on=["a"])
        c = Node(id="c", depends_on=["b"])
        dag.add_many([a, b, c])
        a.depends_on = ["c"]
        with pytest.raises(CycleError):
            dag.validate()

    def test_diamond_is_not_a_cycle(self):
        # a → b, a → c, b → d, c → d
        dag = DAG()
        dag.add(Node(id="a"))
        dag.add(Node(id="b", depends_on=["a"]))
        dag.add(Node(id="c", depends_on=["a"]))
        dag.add(Node(id="d", depends_on=["b", "c"]))
        dag.validate()  # should not raise
        levels = dag.levels()
        assert levels == [["a"], ["b", "c"], ["d"]]


# ============================================================
# Levels (parallel scheduling)
# ============================================================


class TestLevels:
    def test_single_node(self):
        dag = DAG().add(Node(id="a"))
        assert dag.levels() == [["a"]]

    def test_linear_chain(self):
        dag = DAG()
        for x in "abcd":
            dag.add(Node(id=x, depends_on=[prev] if (prev := x) and "abc".find(x) > 0 else []))
        # Cleaner equivalent:
        dag = DAG()
        for i, x in enumerate("abcd"):
            dag.add(Node(id=x, depends_on=["abcd"[i-1]] if i > 0 else []))
        levels = dag.levels()
        assert levels == [["a"], ["b"], ["c"], ["d"]]

    def test_diamond(self):
        dag = DAG()
        dag.add(Node(id="a"))
        dag.add(Node(id="b", depends_on=["a"]))
        dag.add(Node(id="c", depends_on=["a"]))
        dag.add(Node(id="d", depends_on=["b", "c"]))
        assert dag.levels() == [["a"], ["b", "c"], ["d"]]

    def test_fan_out(self):
        # a → {b, c, d, e} (all parallel)
        dag = DAG()
        dag.add(Node(id="a"))
        for x in "bcde":
            dag.add(Node(id=x, depends_on=["a"]))
        levels = dag.levels()
        assert levels[0] == ["a"]
        assert sorted(levels[1]) == ["b", "c", "d", "e"]
        assert len(levels) == 2

    def test_fan_in(self):
        # {a, b, c, d} → e
        dag = DAG()
        for x in "abcd":
            dag.add(Node(id=x))
        dag.add(Node(id="e", depends_on=list("abcd")))
        levels = dag.levels()
        assert sorted(levels[0]) == ["a", "b", "c", "d"]
        assert levels[1] == ["e"]

    def test_deep_chain(self):
        dag = DAG()
        ids = [f"n{i}" for i in range(10)]
        for i, x in enumerate(ids):
            dag.add(Node(id=x, depends_on=[ids[i-1]] if i > 0 else []))
        levels = dag.levels()
        assert len(levels) == 10
        for i, level in enumerate(levels):
            assert level == [ids[i]]

    def test_plan_is_alias_for_levels(self):
        dag = DAG().add(Node(id="a"))
        assert dag.plan() == dag.levels()


# ============================================================
# RunState
# ============================================================


class TestRunState:
    def test_empty(self):
        s = RunState()
        assert s.results == {}
        assert s.total("anything") == 0

    def test_is_done(self):
        s = RunState(results={"a": "done"})
        assert s.is_done("a")
        assert not s.is_done("b")

    def test_is_skipped(self):
        s = RunState(results={"a": "skipped"})
        assert s.is_skipped("a")
        assert not s.is_skipped("b")

    def test_is_completed(self):
        s = RunState(results={"a": "done", "b": "failed", "c": "timeout"})
        assert s.is_completed("a")
        assert s.is_completed("b")
        assert s.is_completed("c")
        assert not s.is_completed("d")
        assert not s.is_completed("e")  # not even started

    def test_total_across_nodes(self):
        s = RunState(artifacts={
            ("n1", "subdomain"): 100,
            ("n2", "subdomain"): 50,
            ("n2", "url"): 200,
        })
        assert s.total("subdomain") == 150
        assert s.total("url") == 200
        assert s.total("host") == 0

    def test_from_node(self):
        s = RunState(artifacts={("n1", "subdomain"): 42})
        assert s.from_node("n1", "subdomain") == 42
        assert s.from_node("n1", "url") == 0
        assert s.from_node("ghost", "subdomain") == 0


# ============================================================
# should_run predicates
# ============================================================


class TestShouldRun:
    def test_no_predicate_always_runs(self):
        dag = DAG()
        dag.add(Node(id="a"))
        dag.add(Node(id="b", depends_on=["a"]))
        state = RunState()
        assert dag.ready(state) == ["a"]
        state.results["a"] = "done"
        assert dag.ready(state) == ["b"]

    def test_predicate_false_skips(self):
        dag = DAG()
        dag.add(Node(id="a"))
        # b only runs if a produced > 0 of "subdomain"
        dag.add(Node(
            id="b", depends_on=["a"],
            should_run=lambda s: s.from_node("a", "subdomain") > 0,
        ))
        state = RunState()
        state.results["a"] = "done"
        state.artifacts[("a", "subdomain")] = 0
        # b is in skipped, not ready
        assert dag.ready(state) == []
        assert dag.skipped(state) == ["b"]

    def test_predicate_true_runs(self):
        dag = DAG()
        dag.add(Node(id="a"))
        dag.add(Node(
            id="b", depends_on=["a"],
            should_run=lambda s: s.from_node("a", "subdomain") > 0,
        ))
        state = RunState()
        state.results["a"] = "done"
        state.artifacts[("a", "subdomain")] = 5
        assert dag.ready(state) == ["b"]
        assert dag.skipped(state) == []

    def test_predicate_blocked_until_deps_done(self):
        # If b's predicate would be true but a hasn't completed,
        # b is not in ready() AND not in skipped().
        dag = DAG()
        dag.add(Node(id="a"))
        dag.add(Node(
            id="b", depends_on=["a"],
            should_run=lambda s: True,
        ))
        state = RunState()  # a not done
        assert dag.ready(state) == ["a"]
        assert "b" not in dag.ready(state)
        assert "b" not in dag.skipped(state)

    def test_predicate_total_artifact_check(self):
        # Common pattern: only screenshot if there are live hosts.
        dag = DAG()
        dag.add(Node(id="probe", outputs={"live_host"}))
        dag.add(Node(
            id="screenshot", inputs={"live_host"}, depends_on=["probe"],
            should_run=lambda s: s.total("live_host") > 0,
        ))
        state = RunState()
        # no probe results yet
        assert "screenshot" not in dag.ready(state)
        # probe done with 0 live hosts → skipped
        state.results["probe"] = "done"
        assert "screenshot" in dag.skipped(state)
        # probe done with 5 live hosts → ready
        state.artifacts[("probe", "live_host")] = 5
        assert "screenshot" in dag.ready(state)


# ============================================================
# Bundled subdomain pipeline
# ============================================================


class TestBundledSubdomainPipeline:
    def test_canonical_pipeline(self):
        dag = add_subdomain_pipeline(DAG())
        assert dag.ids() == ["subenum", "resolve", "probe", "screenshot"]
        levels = dag.levels()
        assert levels == [["subenum"], ["resolve"], ["probe"], ["screenshot"]]

    def test_screenshot_skipped_when_no_live_hosts(self):
        dag = add_subdomain_pipeline(DAG())
        state = RunState()
        # Run subenum, resolve, probe — none produce live_host
        for nid in ("subenum", "resolve", "probe"):
            state.results[nid] = "done"
        assert dag.ready(state) == []
        assert dag.skipped(state) == ["screenshot"]

    def test_screenshot_runs_when_live_hosts(self):
        dag = add_subdomain_pipeline(DAG())
        state = RunState()
        for nid in ("subenum", "resolve", "probe"):
            state.results[nid] = "done"
        state.artifacts[("probe", "live_host")] = 3
        assert dag.ready(state) == ["screenshot"]
        assert dag.skipped(state) == []

    def test_full_execution_walk(self):
        """Walk the DAG manually: process ready nodes level by level."""
        dag = add_subdomain_pipeline(DAG())
        state = RunState()
        # Mark each node done when we process it, with realistic artifacts.
        level_artifacts = {
            "subenum": {"subdomain": 12},
            "resolve": {"host": 10},
            "probe": {"live_host": 3},
        }
        order: list[str] = []
        for _ in range(len(dag)):
            ready = dag.ready(state)
            if not ready:
                # No predicate-skipped nodes
                for nid in dag.skipped(state):
                    state.results[nid] = "skipped"
                    order.append(nid)
                continue
            for nid in ready:
                state.results[nid] = "done"
                for art, count in level_artifacts.get(nid, {}).items():
                    state.artifacts[(nid, art)] = count
                order.append(nid)
        assert order == ["subenum", "resolve", "probe", "screenshot"]
        assert state.is_done("screenshot")

    def test_full_execution_walk_with_no_live_hosts(self):
        """If probe produces nothing, screenshot is skipped, not done."""
        dag = add_subdomain_pipeline(DAG())
        state = RunState()
        order: list[str] = []
        for _ in range(len(dag)):
            ready = dag.ready(state)
            for nid in dag.skipped(state):
                state.results[nid] = "skipped"
                order.append(nid)
            for nid in ready:
                state.results[nid] = "done"
                # probe produces 0 live hosts (intentionally)
                state.artifacts[(nid, "live_host")] = 0
                order.append(nid)
        # First three run normally; screenshot's predicate is False (0 live hosts)
        # so it's marked skipped, not done.
        assert order == ["subenum", "resolve", "probe", "screenshot"]
        assert state.is_skipped("screenshot")
        assert not state.is_done("screenshot")
