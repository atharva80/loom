"""Shared fixtures: local HTTP servers for catchall/classifier tests.

No external network, no flake. Imported implicitly by every test module.
"""

from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest


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
