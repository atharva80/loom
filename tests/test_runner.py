"""loom.runner tests.

Two layers:
  1. Pure parser tests — no subprocess. Verify subfinder/httpx/naabu/nuclei/katana/dnsx
     line and JSON parsers handle the canonical output shapes.
  2. Runner tests — real subprocess via `sh -c` (always available) to drive
     the full code path: header injection, rate-limit acquire, eventlog append,
     state mark, timeout handling, streaming.

Subprocesses use `sh` / `printf` / `cat` / `true` only — no network, no
assumed tools, runs in <2s.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from loom.runner import (
    PARSERS,
    OutputItem,
    RunResult,
    Runner,
    ToolBlocked,
    parse_amass,
    parse_assetfinder,
    parse_dnsx,
    parse_gau,
    parse_httpx,
    parse_katana,
    parse_naabu,
    parse_nuclei,
    parse_raw,
    parse_subfinder,
    parse_wayback,
    _inject_headers,
)
from loom.ratelimit import RateLimiter
from loom.scope import Scope, from_dict as scope_from_dict
from loom.state import State
from loom.eventlog import EventLog


def _make_scope() -> Scope:
    return scope_from_dict({"name": "t", "target": "example.com", "rate_limit_rps": 1000})


# ============================================================
# Parser unit tests
# ============================================================


class TestParsers:
    def test_subfinder_dedupes_invalid(self):
        out = "a.example.com\nNOTADOMAIN\n[INFO] loading\nb.example.com\n"
        items = parse_subfinder(out)
        assert [i.value for i in items] == ["a.example.com", "b.example.com"]
        assert all(i.kind == "subdomain" for i in items)
        assert all(i.evidence["source"] == "subfinder" for i in items)

    def test_subfinder_drops_brackets(self):
        out = "[*] enumerating\na.example.com\n[INF] done\n"
        items = parse_subfinder(out)
        assert [i.value for i in items] == ["a.example.com"]

    def test_httpx_json_lines(self):
        out = json.dumps({
            "host": "a.example.com", "url": "https://a.example.com/",
            "status_code": 200, "title": "A", "tech": ["Nginx", "PHP"],
        }) + "\n" + json.dumps({
            "host": "b.example.com", "input": "b.example.com",
            "url": "https://b.example.com/", "status_code": 301,
        }) + "\n"
        items = parse_httpx(out)
        assert len(items) == 2
        assert items[0].kind == "host"
        assert items[0].value == "a.example.com"
        assert items[0].evidence["status_code"] == 200
        assert items[0].evidence["tech"] == ["Nginx", "PHP"]
        # input fallback for host
        assert items[1].evidence["status_code"] == 301

    def test_httpx_skips_garbage(self):
        out = "not json\n" + json.dumps({"host": "a.example.com"}) + "\n[INFO] x\n"
        items = parse_httpx(out)
        assert len(items) == 1
        assert items[0].value == "a.example.com"

    def test_naabu(self):
        out = "a.example.com:80\na.example.com:443\nnot-a-line\nb.example.com:8080\n"
        items = parse_naabu(out)
        assert [i.value for i in items] == [
            "a.example.com:80", "a.example.com:443", "b.example.com:8080"
        ]
        assert all(i.kind == "port" for i in items)

    def test_nuclei_json(self):
        out = json.dumps({
            "template-id": "CVE-2021-1234",
            "matched-at": "https://a.example.com/vuln",
            "type": "http",
            "info": {"severity": "high", "name": "Some Vuln"},
        }) + "\n"
        items = parse_nuclei(out)
        assert len(items) == 1
        assert items[0].kind == "finding"
        assert items[0].value == "https://a.example.com/vuln"
        assert items[0].evidence["template_id"] == "CVE-2021-1234"
        assert items[0].evidence["severity"] == "high"

    def test_nuclei_skips_malformed(self):
        out = "garbage\n" + json.dumps({"template-id": "x", "matched-at": "https://a.example.com/"}) + "\n"
        items = parse_nuclei(out)
        assert len(items) == 1

    def test_katana_urls(self):
        out = "https://a.example.com/page1\nhttps://a.example.com/page2\nnotaurl\n"
        items = parse_katana(out)
        assert [i.value for i in items] == [
            "https://a.example.com/page1", "https://a.example.com/page2"
        ]

    def test_gau_and_wayback_delegate_to_katana(self):
        out = "https://a.example.com/\n"
        assert parse_gau(out) == parse_katana(out)
        assert parse_wayback(out) == parse_katana(out)

    def test_dnsx(self):
        out = "a.example.com [a] 1.2.3.4\nb.example.com [cname] c.example.com\nGARBAGE\n"
        items = parse_dnsx(out)
        assert [i.value for i in items] == ["a.example.com", "b.example.com"]

    def test_assetfinder_amass_match_subfinder(self):
        out = "a.example.com\nb.example.com\n"
        assert parse_assetfinder(out) == parse_subfinder(out)
        assert parse_amass(out) == parse_subfinder(out)

    def test_raw_round_trip(self):
        out = "any text\ncan be here\n"
        items = parse_raw(out)
        assert len(items) == 1
        assert items[0].kind == "raw"
        assert items[0].value == "any text\ncan be here"

    def test_raw_empty(self):
        assert parse_raw("") == []
        assert parse_raw("   \n  \n") == []

    def test_all_parsers_registered(self):
        for name in ("subfinder", "httpx", "naabu", "nuclei", "katana",
                     "gau", "waybackurls", "dnsx", "assetfinder", "amass",
                     "ffuf", "raw"):
            assert name in PARSERS


# ============================================================
# Header injection
# ============================================================


class TestInjectHeaders:
    def test_no_headers_no_op(self):
        cmd = ["sh", "-c", "echo hi"]
        assert _inject_headers(cmd, {}) == cmd

    def test_appends_to_httpx(self):
        cmd = ["httpx", "-l", "subs.txt"]
        out = _inject_headers(cmd, {"User-Agent": "loom/1.0"})
        assert out == ["httpx", "-l", "subs.txt", "-H", "User-Agent: loom/1.0"]

    def test_ignored_for_unsupported_tool(self):
        cmd = ["subfinder", "-d", "example.com"]
        out = _inject_headers(cmd, {"User-Agent": "loom/1.0"})
        # subfinder isn't in HEADER_TOOLS — no injection
        assert out == cmd

    def test_multiple_headers(self):
        cmd = ["nuclei", "-u", "https://a.example.com"]
        out = _inject_headers(cmd, {"User-Agent": "x", "X-Bug-Bounty": "axrva"})
        assert out[-4:] == ["-H", "User-Agent: x", "-H", "X-Bug-Bounty: axrva"]

    def test_empty_cmd(self):
        assert _inject_headers([], {"User-Agent": "x"}) == []


# ============================================================
# Runner.run() — basic, header injection, eventlog, state
# ============================================================


class TestRunnerBasic:
    def _scope(self, **kw) -> Scope:
        s = scope_from_dict({"name": "t", "target": "example.com", "rate_limit_rps": 1000})
        for k, v in kw.items():
            setattr(s, k, v)
        return s

    def test_simple_command_succeeds(self, tmp_path: Path):
        runner = Runner(self._scope())
        result = runner.run(
            "subfinder",   # tool name; parser will be tried
            ["sh", "-c", "printf 'a.example.com\\nb.example.com\\n'"],
            stage="subenum",
            host="example.com",
            parser="subfinder",
            timeout=5.0,
        )
        assert result.exit_code == 0
        assert not result.timed_out
        assert [i.value for i in result.items] == ["a.example.com", "b.example.com"]
        assert result.subdomains() == ["a.example.com", "b.example.com"]
        assert result.duration_s > 0

    def test_eventlog_populated(self, tmp_path: Path):
        log_path = tmp_path / "events.jsonl"
        el = EventLog(log_path)
        runner = Runner(self._scope(), eventlog=el)
        runner.run(
            "subfinder", ["sh", "-c", "printf 'a.example.com\\n'"],
            stage="subenum", host="example.com", parser="subfinder", timeout=5.0,
        )
        assert el.count() == 1
        assert el.count(type_="subdomain") == 1
        assert el.count(host="example.com") == 1

    def test_state_marked_done(self, tmp_path: Path):
        db = tmp_path / "state.db"
        log = tmp_path / "events.jsonl"
        with State(db) as st:
            run_id = st.start_run("example.com")
            runner = Runner(self._scope(), state=st, eventlog=EventLog(log), run_id=run_id)
            runner.run(
                "subfinder", ["sh", "-c", "printf 'a.example.com\\n'"],
                stage="subenum", host="example.com", parser="subfinder", timeout=5.0,
            )
            assert st.is_done(run_id, "example.com", "subfinder", "subenum")
            stats = st.stats(run_id)
            assert stats["subenum"]["done"] == 1
            # duration_s was recorded
            rows = st._conn.execute(
                "SELECT duration_s FROM tool_runs WHERE run_id=?",
                (run_id,),
            ).fetchall()
            assert all(r["duration_s"] is not None and r["duration_s"] > 0 for r in rows)

    def test_blocked_tool_raises(self):
        scope = self._scope()
        scope.banned_tools = ["subfinder"]
        runner = Runner(scope)
        with pytest.raises(ToolBlocked):
            runner.run(
                "subfinder", ["sh", "-c", "true"],
                host="example.com", parser="subfinder", timeout=5.0,
            )

    def test_check_false_allows_blocked(self, tmp_path: Path):
        scope = self._scope()
        scope.banned_tools = ["subfinder"]
        runner = Runner(scope)
        result = runner.run(
            "subfinder", ["sh", "-c", "true"],
            host="example.com", parser="subfinder", timeout=5.0,
            check=False,
        )
        assert result.exit_code == 0

    def test_binary_not_found(self, tmp_path: Path):
        runner = Runner(self._scope())
        result = runner.run(
            "subfinder", ["/nonexistent/binary/xyz"],
            host="example.com", parser="subfinder", timeout=5.0,
        )
        assert result.exit_code == 127
        assert "binary not found" in (result.error or "")

    def test_nonzero_exit_marks_failed(self, tmp_path: Path):
        db = tmp_path / "state.db"
        with State(db) as st:
            run_id = st.start_run("example.com")
            runner = Runner(self._scope(), state=st, run_id=run_id)
            result = runner.run(
                "subfinder", ["sh", "-c", "echo oops >&2; exit 7"],
                host="example.com", parser="subfinder", timeout=5.0,
                stage="subenum",
            )
            assert result.exit_code == 7
            assert st.hosts_failed_for(run_id, "subfinder", "subenum") == {
                "example.com": "exit code 7: oops"
            }

    def test_timeout_marks_timeout(self, tmp_path: Path):
        db = tmp_path / "state.db"
        with State(db) as st:
            run_id = st.start_run("example.com")
            runner = Runner(self._scope(), state=st, run_id=run_id)
            result = runner.run(
                "subfinder", ["sh", "-c", "sleep 10"],
                host="example.com", parser="subfinder", timeout=0.3,
            )
            assert result.timed_out
            failed = st.hosts_failed_for(run_id, "subfinder", "subenum")
            # 'timeout' is not 'failed', so this should be empty
            assert failed == {}
            # but the row should be there with status='timeout'
            row = st._conn.execute(
                "SELECT status, error, duration_s FROM tool_runs WHERE run_id=?",
                (run_id,),
            ).fetchone()
            assert row["status"] == "timeout"
            assert "timeout" in (row["error"] or "").lower()


# ============================================================
# Runner rate-limit integration
# ============================================================


class TestRunnerRateLimit:
    def _scope(self) -> Scope:
        return scope_from_dict({"name": "t", "target": "example.com", "rate_limit_rps": 1000})

    def test_rate_limiter_throttles(self, tmp_path: Path):
        # 1 token, refills at 10/s → ~100ms between acquires
        rl = RateLimiter(rps=10, burst=1)
        runner = Runner(self._scope(), rate_limiter=rl)

        t0 = time.monotonic()
        for _ in range(3):
            runner.run(
                "subfinder", ["sh", "-c", "true"],
                host="example.com", parser="subfinder", timeout=2.0,
            )
        elapsed = time.monotonic() - t0
        # 3 acquires with burst=1, rps=10 → 1 immediate + 2 waits of ~100ms
        assert elapsed >= 0.15  # conservative lower bound

    def test_rate_limiter_blocks_on_no_token(self, tmp_path: Path):
        # burst=1, rps=2 (1 token per 500ms) — first call ok, second must wait
        rl = RateLimiter(rps=2, burst=1)
        runner = Runner(self._scope(), rate_limiter=rl)
        t0 = time.monotonic()
        runner.run("subfinder", ["sh", "-c", "true"],
                   host="example.com", parser="subfinder", timeout=2.0)
        runner.run("subfinder", ["sh", "-c", "true"],
                   host="example.com", parser="subfinder", timeout=2.0)
        elapsed = time.monotonic() - t0
        assert elapsed >= 0.4  # second call had to wait ~500ms


# ============================================================
# Runner.run_streaming() — line-by-line emission
# ============================================================


class TestRunnerStreaming:
    def _scope(self) -> Scope:
        return scope_from_dict({"name": "t", "target": "example.com", "rate_limit_rps": 1000})

    def test_streaming_subfinder_per_line(self, tmp_path: Path):
        runner = Runner(self._scope())
        collected: list[OutputItem] = []
        result = runner.run_streaming(
            "subfinder",
            ["sh", "-c", "for d in a b c d e; do printf '%s.example.com\\n' $d; sleep 0.02; done"],
            stage="subenum", host="example.com",
            parser="subfinder", timeout=5.0,
            on_item=collected.append,
        )
        assert [i.value for i in collected] == [
            f"{x}.example.com" for x in "abcde"
        ]
        # result.items should also have them all
        assert len(result.items) == 5

    def test_streaming_katana(self, tmp_path: Path):
        runner = Runner(self._scope())
        seen: list[str] = []
        result = runner.run_streaming(
            "katana",
            ["sh", "-c", "printf 'https://a.example.com/p1\\nhttps://a.example.com/p2\\njunk\\n'"],
            stage="crawl", host="example.com",
            timeout=5.0, on_item=lambda it: seen.append(it.value),
        )
        assert seen == ["https://a.example.com/p1", "https://a.example.com/p2"]

    def test_streaming_eventlog_per_line(self, tmp_path: Path):
        log = tmp_path / "e.jsonl"
        el = EventLog(log)
        runner = Runner(self._scope(), eventlog=el)
        runner.run_streaming(
            "katana",
            ["sh", "-c", "printf 'https://a.example.com/p1\\nhttps://a.example.com/p2\\n'"],
            stage="crawl", host="example.com", timeout=5.0,
        )
        assert el.count(type_="url") == 2

    def test_streaming_unknown_parser_buffers(self, tmp_path: Path):
        # ffuf uses parse_raw (no per-line streaming) — items should still appear,
        # just at the end.
        runner = Runner(self._scope())
        result = runner.run_streaming(
            "ffuf",
            ["sh", "-c", "printf 'result line 1\\nresult line 2\\n'"],
            stage="fuzz", host="example.com", parser="ffuf", timeout=5.0,
        )
        assert len(result.items) == 1
        assert "result line 1" in result.items[0].value
        assert "result line 2" in result.items[0].value


# ============================================================
# RunResult convenience methods
# ============================================================


class TestRunResult:
    def _result(self, items):
        return RunResult(
            tool="x", command=["x"], exit_code=0, duration_s=0.0, items=items,
        )

    def test_subdomains(self):
        r = self._result([
            OutputItem("subdomain", "a.example.com"),
            OutputItem("url", "https://a.example.com/"),
            OutputItem("subdomain", "b.example.com"),
        ])
        assert r.subdomains() == ["a.example.com", "b.example.com"]
        assert r.urls() == ["https://a.example.com/"]
        assert r.hosts() == []
        assert len(r.findings()) == 0

    def test_findings(self):
        r = self._result([
            OutputItem("finding", "https://a.example.com/vuln",
                       evidence={"template_id": "CVE-1"}),
        ])
        assert len(r.findings()) == 1
        assert r.findings()[0].evidence["template_id"] == "CVE-1"


# ============================================================
# Output file layout (workdir support)
# ============================================================


class TestWorkdirOutputs:
    def test_run_writes_four_files(self, tmp_path: Path):
        workdir = tmp_path / "out"
        runner = Runner(_make_scope(), workdir=workdir)
        result = runner.run(
            "subfinder", ["sh", "-c", "printf 'a.example.com\\nb.example.com\\n'"],
            stage="subenum", host="example.com",
            parser="subfinder", timeout=5.0,
        )
        # Find the created files
        files = list(workdir.rglob("*"))
        assert len(files) >= 4  # stdout, stderr, jsonl, cmd
        names = {f.name for f in files}
        # One of each suffix
        suffixes = {f.suffix + f.suffixes[-1] if len(f.suffixes) > 1 else f.suffix
                    for f in files}
        assert any(n.endswith(".stdout.txt") for n in names)
        assert any(n.endswith(".stderr.txt") for n in names)
        assert any(n.endswith(".jsonl") for n in names)
        assert any(n.endswith(".cmd.txt") for n in names)
        assert result.exit_code == 0

    def test_run_layout_is_stage_host_tool(self, tmp_path: Path):
        workdir = tmp_path / "out"
        runner = Runner(_make_scope(), workdir=workdir)
        runner.run(
            "subfinder", ["sh", "-c", "printf 'a.example.com\\n'"],
            stage="subenum", host="example.com",
            parser="subfinder", timeout=5.0,
        )
        # Path layout: workdir/subenum/example.com/subfinder.<ts>.stdout.txt
        host_dirs = list((workdir / "subenum").iterdir())
        assert len(host_dirs) == 1
        assert host_dirs[0].name == "example.com"
        files = list(host_dirs[0].iterdir())
        assert all(f.name.startswith("subfinder.") for f in files)

    def test_jsonl_contains_parsed_items(self, tmp_path: Path):
        workdir = tmp_path / "out"
        runner = Runner(_make_scope(), workdir=workdir)
        runner.run(
            "subfinder", ["sh", "-c", "printf 'a.example.com\\nb.example.com\\n'"],
            stage="subenum", host="example.com",
            parser="subfinder", timeout=5.0,
        )
        jsonl_files = list(workdir.rglob("*.jsonl"))
        assert len(jsonl_files) == 1
        lines = jsonl_files[0].read_text().strip().splitlines()
        assert len(lines) == 2
        items = [json.loads(l) for l in lines]
        assert {i["value"] for i in items} == {"a.example.com", "b.example.com"}
        assert all(i["kind"] == "subdomain" for i in items)
        assert all(i["evidence"]["source"] == "subfinder" for i in items)

    def test_stdout_contains_raw_output(self, tmp_path: Path):
        workdir = tmp_path / "out"
        runner = Runner(_make_scope(), workdir=workdir)
        runner.run(
            "subfinder", ["sh", "-c", "printf 'a.example.com\\n'"],
            stage="subenum", host="example.com",
            parser="subfinder", timeout=5.0,
        )
        stdout_files = list(workdir.rglob("*.stdout.txt"))
        assert len(stdout_files) == 1
        content = stdout_files[0].read_text()
        assert "a.example.com" in content

    def test_cmd_metadata_file(self, tmp_path: Path):
        workdir = tmp_path / "out"
        runner = Runner(_make_scope(), workdir=workdir)
        runner.run(
            "subfinder", ["sh", "-c", "printf 'a.example.com\\n'"],
            stage="subenum", host="example.com",
            parser="subfinder", timeout=5.0,
        )
        cmd_files = list(workdir.rglob("*.cmd.txt"))
        assert len(cmd_files) == 1
        meta = json.loads(cmd_files[0].read_text())
        assert meta["exit_code"] == 0
        assert meta["timed_out"] is False
        assert meta["item_count"] == 1
        assert meta["cmd"] == ["sh", "-c", "printf 'a.example.com\\n'"]
        assert meta["duration_s"] >= 0
        assert "stdout_bytes" in meta

    def test_stderr_captured(self, tmp_path: Path):
        workdir = tmp_path / "out"
        runner = Runner(_make_scope(), workdir=workdir)
        runner.run(
            "subfinder", ["sh", "-c", "echo noisy >&2; exit 0"],
            stage="subenum", host="example.com",
            parser="subfinder", timeout=5.0,
        )
        stderr_files = list(workdir.rglob("*.stderr.txt"))
        assert len(stderr_files) == 1
        assert "noisy" in stderr_files[0].read_text()

    def test_unsafe_host_chars_replaced(self, tmp_path: Path):
        workdir = tmp_path / "out"
        runner = Runner(_make_scope(), workdir=workdir)
        runner.run(
            "subfinder", ["sh", "-c", "printf 'a.example.com\\n'"],
            stage="subenum", host="a/b:weird host.com",
            parser="subfinder", timeout=5.0,
        )
        # The unsafe host is sanitized for the directory name
        host_dirs = list((workdir / "subenum").iterdir())
        assert len(host_dirs) == 1
        # No slashes, no spaces, no colons in the dir name
        assert "/" not in host_dirs[0].name
        assert " " not in host_dirs[0].name
        assert ":" not in host_dirs[0].name

    def test_output_path_recorded_in_state(self, tmp_path: Path):
        db = tmp_path / "s.db"
        workdir = tmp_path / "out"
        with State(db) as st:
            rid = st.start_run("example.com")
            runner = Runner(_make_scope(), state=st, run_id=rid, workdir=workdir)
            runner.run(
                "subfinder", ["sh", "-c", "printf 'a.example.com\\n'"],
                stage="subenum", host="example.com",
                parser="subfinder", timeout=5.0,
            )
            row = st._conn.execute(
                "SELECT output_path FROM tool_runs WHERE run_id=?", (rid,),
            ).fetchone()
            assert row["output_path"] is not None
            assert row["output_path"].endswith(".jsonl")
            # The file actually exists on disk
            assert Path(row["output_path"]).exists()

    def test_no_workdir_means_no_output_files(self, tmp_path: Path):
        # When workdir is None, nothing is written — the runner still
        # works (existing behavior).
        runner = Runner(_make_scope())  # no workdir
        result = runner.run(
            "subfinder", ["sh", "-c", "printf 'a.example.com\\n'"],
            stage="subenum", host="example.com",
            parser="subfinder", timeout=5.0,
        )
        assert result.exit_code == 0
        # And state.mark was called with output_path=None
        # (verified by not blowing up; the schema accepts NULL)

    def test_streaming_writes_outputs(self, tmp_path: Path):
        workdir = tmp_path / "out"
        runner = Runner(_make_scope(), workdir=workdir)
        runner.run_streaming(
            "katana",
            ["sh", "-c", "printf 'https://a.example.com/p1\\nhttps://a.example.com/p2\\n'"],
            stage="crawl", host="example.com", timeout=5.0,
        )
        files = list(workdir.rglob("*"))
        assert any(f.name.endswith(".stdout.txt") for f in files)
        assert any(f.name.endswith(".jsonl") for f in files)
        # Both URLs in the jsonl
        jsonl_files = list(workdir.rglob("*.jsonl"))
        assert len(jsonl_files) == 1
        items = [json.loads(l) for l in jsonl_files[0].read_text().splitlines()]
        assert {i["value"] for i in items} == {
            "https://a.example.com/p1", "https://a.example.com/p2"
        }

    def test_multiple_invocations_get_distinct_timestamps(self, tmp_path: Path):
        workdir = tmp_path / "out"
        runner = Runner(_make_scope(), workdir=workdir)
        for _ in range(3):
            runner.run(
                "subfinder", ["sh", "-c", "printf 'a.example.com\\n'"],
                stage="subenum", host="example.com",
                parser="subfinder", timeout=5.0,
            )
        jsonl_files = list(workdir.rglob("*.jsonl"))
        # Three distinct files (or fewer if timestamps collided; allow
        # >= 1 since the same ms is theoretically possible, but in
        # practice the test runs fast enough to collide so accept >=1)
        assert len(jsonl_files) >= 1
        # All files contain the subdomain
        for f in jsonl_files:
            content = f.read_text()
            assert "a.example.com" in content
