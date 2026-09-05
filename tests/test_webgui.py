"""Tests for the loom web console (loom gui).

Spins the real HTTP server on an ephemeral port (stdlib only, no
network beyond localhost): page serves, run/command validation
rejects bad input, file reads are jailed, kill works.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from loom import cli as _cli
from loom.webgui import GuiState, Handler, _parse_command


@pytest.fixture
def server(tmp_path):
    Handler.state = GuiState(tmp_path)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}", tmp_path
    httpd.shutdown()


def get(base, path):
    try:
        with urllib.request.urlopen(base + path, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def post(base, path, obj):
    data = json.dumps(obj).encode()
    req = urllib.request.Request(
        base + path, data=data,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


class TestGuiPage:
    def test_root_serves_console(self, server):
        base, _ = server
        status, body = get(base, "/")
        assert status == 200
        assert b"loom console" in body
        assert b"/api/state" in body

    def test_state_shape(self, server):
        base, _ = server
        status, body = get(base, "/api/state")
        assert status == 200
        doc = json.loads(body)
        assert {"snapshot", "executions", "overview"} <= set(doc)
        assert doc["snapshot"]["runs"] == []
        assert doc["overview"]["runs_total"] == 0


class TestGuiRunValidation:
    def test_run_needs_domain(self, server):
        base, _ = server
        status, doc = post(base, "/api/run", {"domain": ""})
        assert status == 400

    def test_run_denied_host_is_403(self, server):
        base, _ = server
        status, doc = post(base, "/api/run",
                           {"domain": "x.invalid", "scope": "nonexistent"})
        assert status in (400, 403)

    def test_run_launches_supervised_process(self, server):
        base, tmp = server
        status, doc = post(base, "/api/run",
                           {"domain": "example.invalid",
                            "pipeline": "catchall"})
        # scope gate passes (default allows), process spawns
        assert status == 200, doc
        assert doc["id"] >= 1
        time.sleep(1)
        status, body = get(base, "/api/exec?id=%d" % doc["id"])
        assert status == 200
        meta = json.loads(body)
        assert "log" in meta
        # let it finish or kill it — must not linger
        post(base, "/api/kill", {"id": doc["id"]})

    def test_kill_unknown_id_is_404(self, server):
        base, _ = server
        status, _ = post(base, "/api/kill", {"id": 424242})
        assert status == 404


class TestGuiCommandGate:
    def test_parse_allows_run_family(self):
        for cmd in ("run example.com",
                    "loom run example.com --pipeline web",
                    "sweeps --scopes-file s.csv",
                    "resume example.com",
                    "findings", "status example.com",
                    "list-runs", "diff", "validate"):
            tokens, name = _parse_command(cmd)
            assert name.startswith("cmd_"), cmd

    def test_parse_rejects_gui_and_server(self):
        for cmd in ("gui", "status-server --workdir x", "bogus-cmd",
                    "", "run --pipeline nope"):
            with pytest.raises(ValueError):
                _parse_command(cmd)

    def test_command_endpoint_rejects(self, server):
        base, _ = server
        status, _ = post(base, "/api/command", {"command": "gui"})
        assert status == 400


class TestGuiFiles:
    def test_traversal_blocked(self, server):
        base, tmp_path = server
        (tmp_path / "secret.txt").write_text("nope")
        status, _ = get(base, "/api/file?run=1&path=" + urllib.parse.quote(
            "../secret.txt"))
        assert status in (400, 404)

    def test_missing_run_file_is_404(self, server):
        base, _ = server
        status, _ = get(base, "/api/file?run=99&path=outputs/x.txt")
        assert status == 404

    def test_findings_empty_ok(self, server):
        base, _ = server
        status, body = get(base, "/api/findings")
        assert status == 200
        assert json.loads(body) == []

    def test_gui_in_cli_choices(self, capsys):
        with pytest.raises(SystemExit):
            _cli.main(["gui", "--help"])
        out = capsys.readouterr().out
        assert "--port" in out


class TestAutopilot:
    def test_empty_targets_is_400(self, server):
        base, _ = server
        status, doc = post(base, "/api/autopilot",
                           {"targets": "   \n,", "intensity": "quick"})
        assert status == 400

    def test_denied_scope_is_403(self, server):
        base, _ = server
        status, _ = post(base, "/api/autopilot",
                         {"targets": "example.com",
                          "intensity": "quick", "scope": "nonexistent"})
        assert status == 403

    def test_autopilot_spawns_sweep(self, server, monkeypatch):
        base, tmp_path = server
        seen = []
        from loom import webgui as _wg
        orig_spawn = _wg.GuiState.spawn

        def fake_spawn(self, argv, label, kind):
            seen.append((argv, label, kind))
            return {"id": 99, "kind": kind, "label": label,
                    "argv": argv, "pid": 1, "log": "x",
                    "started": 0.0, "finished": None, "rc": None,
                    "killed": False}

        monkeypatch.setattr(_wg.GuiState, "spawn", fake_spawn)
        status, doc = post(base, "/api/autopilot",
                           {"targets": "a.example.com\nb.example.com",
                            "intensity": "deep"})
        assert status == 200, doc
        argv, label, kind = seen[0]
        assert kind == "autopilot"
        assert "sweeps" in argv and "--timeout" in argv
        csv = tmp_path / "gui-logs" / "autopilot-scopes.csv"
        assert csv.exists()
        assert "a.example.com,deep,10" in csv.read_text()

    def test_dag_endpoint(self, server):
        import sqlite3
        base, tmp_path = server
        con = sqlite3.connect(str(tmp_path / "loom.sqlite"))
        con.execute("CREATE TABLE runs (id INTEGER PRIMARY KEY, domain TEXT,"
                    " pipeline TEXT, started_at REAL, finished_at REAL)")
        con.execute("CREATE TABLE tool_runs (run_id INTEGER, host TEXT, tool TEXT,"
                    " stage TEXT, status TEXT, started_at REAL, finished_at REAL,"
                    " output_path TEXT, error TEXT, duration_s REAL)")
        con.execute("INSERT INTO runs VALUES (1,'example.com','catchall',0,1)")
        con.commit()
        con.close()
        status, body = get(base, "/api/dag?run=1")
        assert status == 200
        doc = json.loads(body)
        assert doc["pipeline"] == "catchall"
        assert doc["levels"] == [["catchall"]]
        assert doc["nodes"][0]["status"] in ("done", "pending")

    def test_dag_unknown_run(self, server):
        base, _ = server
        status, body = get(base, "/api/dag?run=99")
        assert status == 200
        assert json.loads(body).get("error")

    def test_port_in_use_exits_2(self, tmp_path):
        import socket
        from loom import webgui as _wg
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        try:
            with pytest.raises(SystemExit) as exc:
                _wg.serve_forever(tmp_path, port)
            assert exc.value.code == 2
        finally:
            s.close()
