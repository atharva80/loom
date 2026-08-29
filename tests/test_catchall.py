"""Test suite for loom.catchall — catch-all / SPA-shell detector.

Uses a local HTTP server fixture to test catch-all detection in isolation
(no external network needed, no flake).
"""
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional
import socket
import pytest

from loom.catchall import detect, Probe, _entropy, _looks_like_html, _http_get


# ---------- Fixtures ----------

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class CatchAllHandler(BaseHTTPRequestHandler):
    """Returns the same HTML for every path (S3 static / SPA shell)."""
    BODY = b"<!DOCTYPE html><html><head><title>App</title></head><body><div id=root></div></body></html>"
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(self.BODY)))
        self.end_headers()
        self.wfile.write(self.BODY)
    def log_message(self, *a, **k): pass


class RealAppHandler(BaseHTTPRequestHandler):
    """Returns 200 for /, 404 for everything else."""
    def do_GET(self):
        if self.path == "/":
            body = b"<!DOCTYPE html><html><body>Welcome to real app</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = b"<!DOCTYPE html><html><body>404 Not Found</body></html>"
            self.send_response(404)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    def log_message(self, *a, **k): pass


class DeadHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"connection refused"
        self.send_response(503)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a, **k): pass


class _Server:
    def __init__(self, handler_cls):
        self.port = _free_port()
        self.httpd = HTTPServer(("127.0.0.1", self.port), handler_cls)
        self.t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.t.start()
    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def catchall_server():
    s = _Server(CatchAllHandler)
    yield f"127.0.0.1:{s.port}"
    s.stop()


@pytest.fixture
def real_app_server():
    s = _Server(RealAppHandler)
    yield f"127.0.0.1:{s.port}"
    s.stop()


@pytest.fixture
def dead_server():
    s = _Server(DeadHandler)
    yield f"127.0.0.1:{s.port}"
    s.stop()


# ---------- Helper unit tests ----------

def test_entropy_zero_for_empty():
    assert _entropy(b"") == 0.0


def test_entropy_high_for_random():
    import os
    e = _entropy(os.urandom(1000))
    assert e > 7.0


def test_looks_like_html():
    assert _looks_like_html(b"<!DOCTYPE html><html>")
    assert _looks_like_html(b"  <html>")
    assert not _looks_like_html(b'{"json": true}')


# ---------- Detection tests ----------

def test_detect_catchall(catchall_server):
    r = detect(catchall_server, https=False, timeout=3)
    assert r["classification"] == "catchall"
    assert r["confidence"] >= 0.8


def test_detect_clean_app(real_app_server):
    r = detect(real_app_server, https=False, timeout=3)
    assert r["classification"] == "clean"
    assert r["confidence"] >= 0.7


def test_detect_dead_host(dead_server):
    # 503 with small body — classified as clean (returns non-200 on root)
    r = detect(dead_server, https=False, timeout=3)
    assert r["classification"] in ("clean", "error")


def test_detect_unreachable_host():
    # Pick a port nothing is listening on
    r = detect(f"127.0.0.1:{_free_port()}", https=False, timeout=2)
    assert r["classification"] == "error"
    assert r["confidence"] >= 0.8


def test_detect_evidence_contains_all_three(catchall_server):
    r = detect(catchall_server, https=False, timeout=3)
    e = r["evidence"]
    assert "root_status" in e
    assert "root_size" in e
    assert "root_hash" in e
    assert "rand1_status" in e
    assert "rand1_size" in e
    assert "rand1_hash" in e
    assert "rand2_status" in e
    assert "rand2_size" in e
    assert "rand2_hash" in e


def test_catchall_root_and_random_have_same_hash(catchall_server):
    r = detect(catchall_server, https=False, timeout=3)
    e = r["evidence"]
    assert e["root_hash"] == e["rand1_hash"]


def test_clean_app_root_and_random_differ(real_app_server):
    r = detect(real_app_server, https=False, timeout=3)
    e = r["evidence"]
    # Real app: 200 vs 404, different hashes
    assert e["root_hash"] != e["rand1_hash"]
    assert e["rand1_status"] == 404
    assert e["root_status"] == 200
