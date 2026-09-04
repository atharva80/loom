"""loom.catchall — Detect catch-all / SPA-shell / S3-static hosts.

Method: probe /, /random_unique_1, /random_unique_2.
If response bodies for random paths match the / body (or match each other),
the host is a catch-all — every URL returns the same content. Heavy stages
(ffuf, katana, arjun) should be skipped on these hosts.

We classify into:
  - clean:    random paths return 404, / returns 200 (real app)
  - catchall: random paths return same body as / (SPA shell, S3 static, S3 error)
  - error:    can't reach host / all paths fail (every tried scheme)
"""

import hashlib
import math
import re
import string
from collections import Counter
from dataclasses import dataclass
from typing import Optional
import urllib.request
import urllib.error


@dataclass
class Probe:
    url: str
    status: int
    body: bytes
    content_type: str = ""

    @property
    def body_hash(self) -> str:
        return hashlib.sha256(self.body).hexdigest()[:16]

    @property
    def body_size(self) -> int:
        return len(self.body)


def _http_get(url: str, timeout: float = 8.0, user_agent: str = "loom/0.1") -> Optional[Probe]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": user_agent})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return Probe(
                url=url,
                status=resp.status,
                body=resp.read(),
                content_type=resp.headers.get("Content-Type", ""),
            )
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = b""
        return Probe(url=url, status=e.code, body=body, content_type=e.headers.get("Content-Type", ""))
    except Exception:
        return None


def _random_path(rng: int = 0) -> str:
    # 16 hex chars from a counter; collision impossible across calls in one process
    n = rng if rng else 0
    return f"/{n:016x}"


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _looks_like_html(body: bytes) -> bool:
    head = body[:200].lower().lstrip()
    return head.startswith(b"<!doctype") or head.startswith(b"<html") or b"<html" in head[:300]


def _probe_set(base: str, timeout: float):
    """Fetch /, + two random paths. Returns (root, rand1, rand2)."""
    return (
        _http_get(base + "/", timeout=timeout),
        _http_get(base + _random_path(1), timeout=timeout),
        _http_get(base + _random_path(2), timeout=timeout),
    )


def _evidence_for(root, rand1, rand2, scheme: str) -> dict:
    return {
        "scheme": scheme,
        "root_status": root.status if root else None,
        "root_size": root.body_size if root else None,
        "root_hash": root.body_hash if root else None,
        "rand1_status": rand1.status if rand1 else None,
        "rand1_size": rand1.body_size if rand1 else None,
        "rand1_hash": rand1.body_hash if rand1 else None,
        "rand2_status": rand2.status if rand2 else None,
        "rand2_size": rand2.body_size if rand2 else None,
        "rand2_hash": rand2.body_hash if rand2 else None,
    }


def _classify(host: str, root, rand1, rand2, scheme: str) -> dict:
    """Classify from one scheme's probe set. Thresholds unchanged."""
    evidence = _evidence_for(root, rand1, rand2, scheme)

    if not root or root.status == 0:
        return {"host": host, "classification": "error", "confidence": 1.0, "evidence": evidence}

    # All probes failed → error
    if (not rand1 or rand1.status == 0) and (not rand2 or rand2.status == 0):
        return {"host": host, "classification": "error", "confidence": 0.9, "evidence": evidence}

    # Root returned non-200 → clean (probably points somewhere, or dead)
    if root.status >= 400:
        return {"host": host, "classification": "clean", "confidence": 0.7, "evidence": evidence}

    # Strong catch-all: random paths return SAME body as root
    rand_bodies = [p.body for p in (rand1, rand2) if p and p.status == 200]
    rand_sizes = {len(b) for b in rand_bodies}

    # Exact hash match
    if rand1 and rand1.status == 200 and rand1.body_hash == root.body_hash:
        return {"host": host, "classification": "catchall", "confidence": 0.99, "evidence": evidence}

    # Size match within 5% — strong signal
    if rand_bodies and root.body_size > 0:
        if all(abs(len(b) - root.body_size) / root.body_size < 0.05 for b in rand_bodies):
            return {"host": host, "classification": "catchall", "confidence": 0.95, "evidence": evidence}

    # All random paths return identical small body (e.g., "Not Found" template)
    if len(rand_sizes) == 1 and next(iter(rand_sizes)) < 2000 and len(rand_bodies) >= 2:
        # Small identical error pages from the SAME template → likely catch-all too
        if rand1.body_hash == rand2.body_hash and rand1.status == 200:
            return {"host": host, "classification": "catchall", "confidence": 0.85, "evidence": evidence}

    # Soft catch-all: random paths return 200 but small/generic body (SPA shell)
    if rand1 and rand1.status == 200 and root.status == 200:
        if root.body_size < 5000 and _looks_like_html(root.body):
            # Look for SPA indicators
            spa_markers = (b"<div id=\"root\"", b"<div id=\"app\"", b"<div id=\"__next\"",
                          b"<script>self.__next", b"<noscript>You need to enable",
                          b"<title>SPA</title>", b"single-page")
            if any(m in root.body for m in spa_markers):
                return {"host": host, "classification": "catchall", "confidence": 0.9, "evidence": evidence}

    # All random paths 404, root 200 → clean (real app)
    if (rand1 and rand1.status == 404) and (rand2 and rand2.status == 404):
        return {"host": host, "classification": "clean", "confidence": 0.95, "evidence": evidence}

    # Default: clean
    return {"host": host, "classification": "clean", "confidence": 0.6, "evidence": evidence}


def detect(host: str, https: bool = True, timeout: float = 8.0) -> dict:
    """Probe host for catch-all behavior.

    `https=True` prefers TLS but falls back to plaintext http when the
    TLS root probe fails (live 2026-09-05: vulnweb.com has no TLS
    listener; https-only probing misclassified it "error" conf=1.0
    although http serves fine). "error" is returned only when every
    tried scheme fails at /. The working scheme is recorded in
    `evidence["scheme"]`.

    Returns:
      {
        "host": str,
        "classification": "clean" | "catchall" | "error",
        "confidence": float (0.0-1.0),
        "evidence": dict,
      }
    """
    schemes = ("https", "http") if https else ("http",)
    pending = None
    for scheme in schemes:
        root, rand1, rand2 = _probe_set(f"{scheme}://{host}", timeout)
        if root is not None and root.status != 0:
            return _classify(host, root, rand1, rand2, scheme)
        pending = (root, rand1, rand2, scheme)
    # Every scheme failed at / → error; evidence from the last attempt.
    assert pending is not None
    root, rand1, rand2, scheme = pending
    return {"host": host, "classification": "error", "confidence": 1.0,
            "evidence": _evidence_for(root, rand1, rand2, scheme)}
