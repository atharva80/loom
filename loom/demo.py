"""loom.demo — Real end-to-end pipeline that runs against an authorized
live target. Used to exercise the orchestrator + LiveLogger in a real
network environment.

Stages (all pure-Python, no tool binaries required):
  1. catchall   — probe /, /rand1, /rand2 to classify the target
  2. probe      — fetch the root + a few common paths, parse titles/status
  3. tech       — extract Server + X-Powered-By + a few well-known cookies

The pipeline skips any stage whose should_run predicate says no. On
public-firing-range.appspot.com we expect:
  - catchall: clean (verified earlier)
  - probe: 200 OK on /, distinct status codes for random paths
  - tech: Server: Google Frontend

Usage:
    .venv/bin/python -m loom.demo <target>
    .venv/bin/python -m loom.demo public-firing-range.appspot.com
"""
from __future__ import annotations

import asyncio
import re
import time
from pathlib import Path
from typing import Optional

import httpx

from . import catchall
from .dag import DAG, Node
from .eventlog import EventLog
from .live import LiveLogger
from .pipeline import Pipeline, PipelineContext, StageFn
from .runner import OutputItem, Runner
from .scope import from_dict as scope_from_dict
from .state import State


# ============================================================
# Stage implementations
# ============================================================


def make_catchall_stage(log: LiveLogger) -> StageFn:
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        log.stage_start("catchall", host=host)
        t0 = time.monotonic()
        # Use HTTPS by default
        result = catchall.detect(host, https=True, timeout=15.0)
        duration = time.monotonic() - t0
        log.tool_done("catchall", host=host, items=1, duration_s=duration)
        classification = result.get("classification") or result.get("kind") or "unknown"
        conf = result.get("confidence", 0.0)
        if classification == "catchall":
            log.warn("catchall server — most scans will return 200 for any path",
                     host=host, classification=classification, confidence=conf)
        else:
            log.info(f"target classified: {classification} (conf={conf})",
                     host=host)
        return [OutputItem(
            kind="catchall_result", value=classification,
            evidence={"confidence": conf, **result.get("evidence", {})},
        )]
    return _stage


def make_probe_stage(log: LiveLogger) -> StageFn:
    paths = ["/", "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/admin",
             "/login", "/wp-admin", "/api", "/healthz", "/favicon.ico"]
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        log.stage_start("probe", host=host)
        t0 = time.monotonic()
        items: list[OutputItem] = []
        url = f"https://{host}"
        async with httpx.AsyncClient(
            timeout=10.0, follow_redirects=True,
            headers={"User-Agent": "loom/0.1 (axrva@hackerone)"},
        ) as client:
            for p in paths:
                t_p = time.monotonic()
                try:
                    r = await client.get(url + p)
                    dur = time.monotonic() - t_p
                    items.append(OutputItem(
                        kind="probe",
                        value=f"{url}{p}",
                        evidence={
                            "status_code": r.status_code,
                            "content_length": len(r.content),
                            "content_type": r.headers.get("content-type", ""),
                            "title": _extract_title(r.text),
                            "duration_s": round(dur, 3),
                        },
                    ))
                    log.tool_call("httpx.get", host=host, cmd=[url + p])
                    log.tool_done("httpx.get", host=host, items=1, duration_s=dur,
                                  status=r.status_code, size=len(r.content))
                except Exception as e:
                    log.warn(f"probe failed for {p}: {type(e).__name__}: {e}",
                             host=host, path=p)
        duration = time.monotonic() - t0
        log.stage_end("probe", host=host, status="done", items=len(items),
                      duration_s=duration)
        return items
    return _stage


_TITLE_RE = re.compile(r"<title[^>]*>([^<]*)</title>", re.IGNORECASE | re.DOTALL)


def _extract_title(html: str) -> Optional[str]:
    m = _TITLE_RE.search(html)
    return m.group(1).strip()[:200] if m else None


def make_tech_stage(log: LiveLogger) -> StageFn:
    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        log.stage_start("tech", host=host)
        t0 = time.monotonic()
        items: list[OutputItem] = []
        url = f"https://{host}"
        try:
            async with httpx.AsyncClient(
                timeout=10.0, follow_redirects=True,
                headers={"User-Agent": "loom/0.1 (axrva@hackerone)"},
            ) as client:
                r = await client.get(url + "/")
                headers = dict(r.headers)
                server = headers.get("server", "")
                powered = headers.get("x-powered-by", "")
                via = headers.get("via", "")
                cookies = [c.name for c in r.cookies.jar]
                # Build a tiny tech fingerprint
                techs: list[str] = []
                if server:
                    techs.append(server)
                if powered:
                    techs.append(powered)
                if "cloudflare" in (server + via).lower():
                    techs.append("cloudflare")
                if "gws" in server.lower() or "google" in (server + via).lower():
                    techs.append("google-frontend")
                if "php" in powered.lower():
                    techs.append("php")
                if "asp.net" in powered.lower():
                    techs.append("asp.net")
                for h, v in headers.items():
                    if h.lower() == "x-generator":
                        techs.append(v)
                # Dedupe but preserve order
                seen = set()
                techs = [t for t in techs if not (t in seen or seen.add(t))]

                items.append(OutputItem(
                    kind="tech",
                    value=",".join(techs) if techs else "unknown",
                    evidence={
                        "server": server,
                        "x_powered_by": powered,
                        "via": via,
                        "cookies": cookies,
                        "raw_headers_sample": {k: v for k, v in list(headers.items())[:10]},
                    },
                ))
                log.tool_call("httpx.get", host=host, cmd=[url + "/"],
                              purpose="fingerprint")
                log.tool_done("httpx.get", host=host, items=1,
                              techs=",".join(techs) or "unknown")
        except Exception as e:
            log.warn(f"tech detection failed: {type(e).__name__}: {e}",
                     host=host)
        duration = time.monotonic() - t0
        log.stage_end("tech", host=host, status="done", items=len(items),
                      duration_s=duration)
        return items
    return _stage


# ============================================================
# DAG definition
# ============================================================


def build_dag() -> DAG:
    """Three-stage live-test DAG:
        catchall → probe → tech
    Each stage has a should_run predicate that gates on the previous
    stage's output count.
    """
    dag = DAG()
    dag.add(Node(id="catchall", outputs={"catchall_result"}))
    dag.add(Node(
        id="probe",
        depends_on=["catchall"],
        # Skip probe if catchall produced no results.
        should_run=lambda s: s.from_node("catchall", "catchall_result") > 0,
    ))
    dag.add(Node(
        id="tech",
        depends_on=["probe"],
        # Skip tech if probe produced no results (network down).
        should_run=lambda s: s.from_node("probe", "probe") > 0,
    ))
    return dag


# ============================================================
# Entrypoint
# ============================================================


async def run_demo(target: str, workdir: Path) -> int:
    workdir.mkdir(parents=True, exist_ok=True)
    log = LiveLogger(workdir, run_id=1)
    log.info("demo run starting", target=target, workdir=str(workdir))

    scope = scope_from_dict({
        "name": "demo",
        "target": target,
        "rate_limit_rps": 20,
        "headers": {"X-Bug-Bounty": "axrva-drstrangexd"},
    })
    runner = Runner(scope, workdir=workdir / "outputs")
    el = EventLog(workdir / "events.jsonl")
    st = State(workdir / "state.db")
    rid = st.start_run(target, mode="demo", scope_profile=scope.name)
    log.info("run created", run_id=rid, scope=scope.name)

    stages = {
        "catchall": make_catchall_stage(log),
        "probe": make_probe_stage(log),
        "tech": make_tech_stage(log),
    }
    ctx = PipelineContext(
        scope=scope, eventlog=el, state=st, run_id=rid, workdir=workdir,
        extras={"log": log},
    )
    pipeline = Pipeline(runner, stages, context=ctx, max_concurrency=2)

    dag = build_dag()
    t0 = time.monotonic()
    outcomes = await pipeline.run(dag, host=target)
    wall = time.monotonic() - t0

    # Summary
    print()
    log.info("─" * 60)
    log.info("demo run complete", wall_s=round(wall, 2))
    for o in outcomes:
        log.stage_end(o.node_id, host=target, status=o.status,
                      items=len(o.items), duration_s=o.duration_s)
    log.info("─" * 60)
    log.info(f"log written to: {log.log_path}")
    log.info(f"events jsonl:   {workdir / 'events.jsonl'}")
    log.info(f"state db:       {workdir / 'state.db'}")
    log.info(f"outputs tree:   {workdir / 'outputs'}")

    st.finish_run(rid)
    log.close()
    st.close()
    return 0


def main() -> int:
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "public-firing-range.appspot.com"
    workdir = Path("/tmp/loom-demo") if len(sys.argv) <= 2 else Path(sys.argv[2])
    return asyncio.run(run_demo(target, workdir))


if __name__ == "__main__":
    raise SystemExit(main())
