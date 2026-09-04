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
from conftest import _free_port

from loom.catchall import detect, Probe, _entropy, _looks_like_html, _http_get


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


def test_https_falls_back_to_http_clean(real_app_server):
    """HTTP-only host must not be 'error' when https=True.

    Live 2026-09-05: vulnweb.com has no TLS listener, so https-only
    probing classified it 'error' conf=1.0 although http serves fine.
    """
    r = detect(real_app_server, https=True, timeout=5)
    assert r["classification"] == "clean"
    assert r["evidence"]["scheme"] == "http"


def test_https_falls_back_to_http_catchall(catchall_server):
    r = detect(catchall_server, https=True, timeout=5)
    assert r["classification"] == "catchall"
    assert r["evidence"]["scheme"] == "http"


def test_error_only_when_both_schemes_fail():
    r = detect(f"127.0.0.1:{_free_port()}", https=True, timeout=2)
    assert r["classification"] == "error"


def test_scheme_recorded_for_plain_http(real_app_server):
    r = detect(real_app_server, https=False, timeout=3)
    assert r["evidence"]["scheme"] == "http"
