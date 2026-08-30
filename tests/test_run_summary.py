"""Tests for loom.state.run_summary — the per-run one-line summary report.

F23: after a sweep, `loom status --run N --summary` prints a compact line:
  run 3 domain=twilio.com pipeline=subdomain 4402 subs 6962 resolved 826 probed 1 finding 0 failed 241s

This is the "how did it go?" one-liner that replaces manually grep-ing run.log.
"""

import json
import time
from pathlib import Path

import pytest

from loom.state import State


def _seed_run(tmp_path: Path, events: list[dict]) -> State:
    """Create a State + one finished run with tool_runs rows + events.jsonl."""
    st = State(tmp_path / "loom.sqlite")
    run_id = st.start_run("twilio.com", mode="recon",
                          scope_profile="ad-hoc", pipeline="subdomain")
    now = time.time()
    # subenum: 2 tools done, 1 host
    st.mark(run_id, "twilio.com", "assetfinder", "subenum_assetfinder", "done",
            duration_s=1.4)
    st.mark(run_id, "twilio.com", "subfinder", "subenum_subfinder", "done",
            duration_s=30.7)
    # resolve: done with a duration
    st.mark(run_id, "twilio.com", "dnsx", "resolve", "done", duration_s=4.9)
    # probe: done
    st.mark(run_id, "twilio.com", "httpx", "probe", "done", duration_s=180.1)
    # vulnscan: done
    st.mark(run_id, "twilio.com", "nuclei", "vulnscan", "done", duration_s=200.9)
    # finish the run
    st.finish_run(run_id)

    # events.jsonl in <workdir>/run-<id>/events.jsonl — write a couple
    evdir = tmp_path / f"run-{run_id}"
    evdir.mkdir(parents=True, exist_ok=True)
    with (evdir / "events.jsonl").open("w") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    return st


def test_run_summary_basic_shape(tmp_path):
    """A completed run produces a summary with hosts, subs, findings, failures."""
    st = _seed_run(tmp_path, events=[
        {"type": "subdomain", "value": "a.twilio.com", "stage": "subenum", "ts": 1.0},
        {"type": "subdomain", "value": "b.twilio.com", "stage": "subenum", "ts": 1.0},
        {"type": "finding", "value": "http://x.twilio.com",
         "evidence": {"severity": "medium", "name": "XSS"}, "stage": "vulnscan", "ts": 1.0},
    ])
    s = st.run_summary(1, workdir=tmp_path)
    assert s is not None
    assert s["run_id"] == 1
    assert s["domain"] == "twilio.com"
    assert s["pipeline"] == "subdomain"
    assert s["subdomains"] == 2
    assert s["findings"] == 1
    assert s["failed"] == 0
    assert s["duration_s"] is not None
    assert s["duration_s"] >= 0
    # total tool invocations
    assert s["tools"] == 5


def test_run_summary_counts_failures(tmp_path):
    """A run with a failed resolve reports it in the summary."""
    st = State(tmp_path / "loom.sqlite")
    run_id = st.start_run("x.com", mode="recon", pipeline="subdomain")
    st.mark(run_id, "x.com", "subfinder", "subenum_subfinder", "done", duration_s=10.0)
    st.mark(run_id, "x.com", "dnsx", "resolve", "failed",
            error="dnsx: flag provided but not defined: -H", duration_s=0.05)
    st.mark(run_id, "x.com", "httpx", "probe", "skipped", duration_s=0.0)
    st.finish_run(run_id)
    s = st.run_summary(run_id)
    assert s is not None
    assert s["failed"] == 1
    assert s["failed_stages"] == ["resolve"]
    assert s["tools"] == 3
    # resolve failed -> probe skipped counted as skipped
    assert s["skipped"] == 1


def test_run_summary_unknown_run(tmp_path):
    st = State(tmp_path / "loom.sqlite")
    assert st.run_summary(999) is None


def test_run_summary_running_run(tmp_path):
    """A run still in flight reports partial state without duration."""
    st = State(tmp_path / "loom.sqlite")
    run_id = st.start_run("y.com", mode="recon", pipeline="web")
    st.mark(run_id, "y.com", "catchall", "catchall", "done", duration_s=2.0)
    st.mark(run_id, "y.com", "katana", "crawl", "running")
    s = st.run_summary(run_id)
    assert s is not None
    assert s["status"] == "running"
    assert s["failed"] == 0
    assert s["duration_s"] is None  # not finished
    assert s["running"] == 1
