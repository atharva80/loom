"""Test suite for loom.eventlog — JSONL append-only event log."""
import json
import os
import tempfile
from pathlib import Path
import pytest

from loom.eventlog import EventLog


def test_creates_file_if_missing(tmp_path):
    p = tmp_path / "events.jsonl"
    assert not p.exists()
    el = EventLog(p)
    assert p.exists()
    assert el.size_bytes() == 0


def test_append_single_event(tmp_path):
    p = tmp_path / "events.jsonl"
    el = EventLog(p)
    el.append({"type": "subdomain", "value": "api.example.com", "source": "subfinder"})
    assert el.size_bytes() > 0
    content = p.read_text().strip()
    parsed = json.loads(content)
    assert parsed["type"] == "subdomain"
    assert parsed["value"] == "api.example.com"
    assert "ts" in parsed
    assert isinstance(parsed["ts"], float)


def test_append_multiple_preserves_order(tmp_path):
    p = tmp_path / "events.jsonl"
    el = EventLog(p)
    for i in range(10):
        el.append({"type": "subdomain", "value": f"sub{i}.example.com"})
    lines = [l for l in p.read_text().splitlines() if l]
    assert len(lines) == 10
    for i, line in enumerate(lines):
        assert json.loads(line)["value"] == f"sub{i}.example.com"


def test_extend_writes_all(tmp_path):
    p = tmp_path / "events.jsonl"
    el = EventLog(p)
    el.extend([
        {"type": "url", "value": "https://a"},
        {"type": "url", "value": "https://b"},
        {"type": "url", "value": "https://c"},
    ])
    events = list(el.read())
    assert len(events) == 3
    assert [e["value"] for e in events] == ["https://a", "https://b", "https://c"]


def test_read_skips_blank_lines(tmp_path):
    p = tmp_path / "events.jsonl"
    p.write_text('{"a":1}\n\n{"a":2}\n')
    el = EventLog(p)
    events = list(el.read())
    assert len(events) == 2
    assert [e["a"] for e in events] == [1, 2]


def test_count_by_type(tmp_path):
    p = tmp_path / "events.jsonl"
    el = EventLog(p)
    el.extend([
        {"type": "subdomain", "value": "a"},
        {"type": "subdomain", "value": "b"},
        {"type": "url", "value": "https://x"},
    ])
    assert el.count(type_="subdomain") == 2
    assert el.count(type_="url") == 1
    assert el.count(type_="port") == 0


def test_count_by_host(tmp_path):
    p = tmp_path / "events.jsonl"
    el = EventLog(p)
    el.extend([
        {"type": "subdomain", "host": "a.example.com"},
        {"type": "subdomain", "host": "b.example.com"},
        {"type": "subdomain", "host": "a.example.com"},
    ])
    assert el.count(host="a.example.com") == 2
    assert el.count(host="b.example.com") == 1
    assert el.count(host="missing.example.com") == 0


def test_count_combined_filters(tmp_path):
    p = tmp_path / "events.jsonl"
    el = EventLog(p)
    el.extend([
        {"type": "url", "host": "a.com", "stage": "crawl"},
        {"type": "url", "host": "a.com", "stage": "mine"},
        {"type": "url", "host": "b.com", "stage": "crawl"},
    ])
    assert el.count(type_="url", host="a.com", stage="crawl") == 1
    assert el.count(type_="url", host="a.com") == 2


def test_atomic_concurrent_appends_no_corruption(tmp_path):
    """Multiple processes appending simultaneously must not corrupt lines."""
    import threading
    p = tmp_path / "events.jsonl"
    el = EventLog(p)
    n_per_thread = 100
    n_threads = 8
    barrier = threading.Barrier(n_threads)

    def worker(tid):
        barrier.wait()
        for i in range(n_per_thread):
            el.append({"type": "x", "tid": tid, "i": i})

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    events = list(el.read())
    assert len(events) == n_per_thread * n_threads
    # Every line must be valid JSON (no torn writes)
    for e in events:
        assert "tid" in e
        assert "i" in e


def test_does_not_overwrite_existing_file(tmp_path):
    p = tmp_path / "events.jsonl"
    p.write_text('{"existing":true}\n')
    el = EventLog(p)
    el.append({"type": "new"})
    events = list(el.read())
    assert len(events) == 2
    assert events[0]["existing"] is True
    assert events[1]["type"] == "new"
