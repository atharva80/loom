"""Test suite for loom.state — SQLite-backed resume state."""
import pytest
from pathlib import Path

from loom.state import State


@pytest.fixture
def state(tmp_path) -> State:
    s = State(tmp_path / "state.db")
    yield s
    s.close()


def test_creates_db_file(tmp_path):
    p = tmp_path / "state.db"
    s = State(p)
    s.close()
    assert p.exists()


def test_start_run_returns_id(state):
    rid = state.start_run("example.com", "recon", "default")
    assert isinstance(rid, int)
    assert rid > 0
    run = state.get_run(rid)
    assert run is not None
    assert run["domain"] == "example.com"
    assert run["mode"] == "recon"
    assert run["scope_profile"] == "default"
    assert run["finished_at"] is None


def test_finish_run_sets_timestamp(state):
    rid = state.start_run("example.com")
    state.finish_run(rid)
    run = state.get_run(rid)
    assert run["finished_at"] is not None
    assert run["finished_at"] >= run["started_at"]


def test_list_runs_filters_by_domain(state):
    state.start_run("a.com")
    state.start_run("b.com")
    state.start_run("a.com")
    a = state.list_runs("a.com")
    b = state.list_runs("b.com")
    assert len(a) == 2
    assert len(b) == 1
    assert all(r["domain"] == "a.com" for r in a)


def test_mark_pending_then_done(state):
    rid = state.start_run("example.com")
    state.mark(rid, "a.com", "nuclei", "vuln", "pending")
    assert not state.is_done(rid, "a.com", "nuclei", "vuln")
    state.mark(rid, "a.com", "nuclei", "vuln", "running")
    assert not state.is_done(rid, "a.com", "nuclei", "vuln")
    state.mark(rid, "a.com", "nuclei", "vuln", "done", output_path="/tmp/out.json")
    assert state.is_done(rid, "a.com", "nuclei", "vuln")


def test_should_skip_done_or_skipped(state):
    rid = state.start_run("example.com")
    assert not state.should_skip(rid, "a.com", "nuclei", "vuln")
    state.mark(rid, "a.com", "nuclei", "vuln", "done")
    assert state.should_skip(rid, "a.com", "nuclei", "vuln")
    state.mark(rid, "b.com", "nuclei", "vuln", "skipped")
    assert state.should_skip(rid, "b.com", "nuclei", "vuln")
    state.mark(rid, "c.com", "nuclei", "vuln", "failed")
    assert not state.should_skip(rid, "c.com", "nuclei", "vuln")  # failed → retry


def test_hosts_done_for_returns_set(state):
    rid = state.start_run("example.com")
    for h in ["a.com", "b.com", "c.com"]:
        state.mark(rid, h, "nuclei", "vuln", "done")
    state.mark(rid, "d.com", "nuclei", "vuln", "failed")
    done = state.hosts_done_for(rid, "nuclei", "vuln")
    assert done == {"a.com", "b.com", "c.com"}


def test_hosts_failed_for_returns_dict_with_errors(state):
    rid = state.start_run("example.com")
    state.mark(rid, "a.com", "nuclei", "vuln", "failed", error="timeout")
    state.mark(rid, "b.com", "nuclei", "vuln", "failed", error="oom")
    failed = state.hosts_failed_for(rid, "nuclei", "vuln")
    assert failed == {"a.com": "timeout", "b.com": "oom"}


def test_stats_aggregates_by_stage_status(state):
    rid = state.start_run("example.com")
    state.mark(rid, "a.com", "nuclei", "vuln", "done")
    state.mark(rid, "b.com", "nuclei", "vuln", "done")
    state.mark(rid, "c.com", "nuclei", "vuln", "failed")
    state.mark(rid, "a.com", "ffuf", "fuzz", "done")
    stats = state.stats(rid)
    assert stats["vuln"]["done"] == 2
    assert stats["vuln"]["failed"] == 1
    assert stats["fuzz"]["done"] == 1


def test_resume_preserves_state_across_instances(tmp_path):
    p = tmp_path / "state.db"
    s1 = State(p)
    rid = s1.start_run("example.com")
    s1.mark(rid, "a.com", "nuclei", "vuln", "done")
    s1.close()

    s2 = State(p)
    assert s2.is_done(rid, "a.com", "nuclei", "vuln")
    assert s2.hosts_done_for(rid, "nuclei", "vuln") == {"a.com"}


def test_update_running_preserves_original_started_at(state):
    rid = state.start_run("example.com")
    state.mark(rid, "a.com", "nuclei", "vuln", "running")
    run = state.list_runs()[0]
    rid2 = rid  # for clarity
    # Get the started_at we just wrote
    conn = state._conn
    r1 = conn.execute(
        "SELECT started_at FROM tool_runs WHERE run_id=? AND host='a.com'",
        (rid2,),
    ).fetchone()
    t1 = r1["started_at"]
    # Re-mark running (e.g., heartbeat) — should not reset started_at
    state.mark(rid2, "a.com", "nuclei", "vuln", "running")
    r2 = conn.execute(
        "SELECT started_at FROM tool_runs WHERE run_id=? AND host='a.com'",
        (rid2,),
    ).fetchone()
    assert r2["started_at"] == t1


def test_mark_done_sets_finished_at(state):
    rid = state.start_run("example.com")
    state.mark(rid, "a.com", "nuclei", "vuln", "running")
    state.mark(rid, "a.com", "nuclei", "vuln", "done")
    conn = state._conn
    r = conn.execute(
        "SELECT started_at, finished_at FROM tool_runs WHERE run_id=? AND host='a.com'",
        (rid,),
    ).fetchone()
    assert r["finished_at"] is not None
    assert r["finished_at"] >= r["started_at"]
