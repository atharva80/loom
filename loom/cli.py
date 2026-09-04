"""loom CLI — command-line entrypoint.

Subcommands:
  * run <domain>     — start a new run against <domain>
  * resume <domain>  — resume the latest unfinished run for <domain>
  * status <domain>  — show per-stage status of the latest run
  * list-runs        — list all runs (optionally filtered by domain)
  * validate         — sanity-check the loom installation (which tools are
                       in PATH, which are missing)

All commands accept a --scope <name> flag to pick a scope profile
(default: "default"). Each run writes to ~/.local/share/loom/<run-id>/
by default; override with --workdir.

The CLI does NOT yet run real recon stages — that lands in F8 wiring
(real subfinder/httpx/nuclei stages). For now it provides the
operational surface: run creation, state inspection, resume.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

from . import __version__
from .dag import DAG
from .eventlog import EventLog
from .pipeline import Pipeline, PipelineContext
from .ratelimit import RateLimiter
from .resume import ResumablePipeline, latest_inflight_run, make_resumable
from .runner import Runner
from .scope import Scope, bundled, from_dict
from .state import State


# Default working directory for run state.
DEFAULT_WORKDIR = Path.home() / ".local" / "share" / "loom"


def _resolve_scope(name: str, target: Optional[str]) -> Scope:
    """Load a scope by bundled name. Errors out cleanly on unknown names."""
    try:
        return bundled(name, target=target)
    except KeyError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)


def _setup_run_dir(workdir: Path, run_id: int) -> dict[str, Path]:
    workdir.mkdir(parents=True, exist_ok=True)
    return {
        "run": workdir / f"run-{run_id}",
        "db": workdir / "loom.sqlite",
        "events": workdir / f"run-{run_id}" / "events.jsonl",
    }


def _print_stats(state: State, run_id: int, workdir: Optional[Path] = None) -> None:
    """Print a human-readable status block for a run."""
    run = state.get_run(run_id)
    if not run:
        print(f"run {run_id} not found")
        return
    print(f"run {run_id}  domain={run['domain']}  mode={run.get('mode')}  "
          f"scope={run.get('scope_profile')}")
    print(f"  started_at : {run['started_at']}")
    print(f"  finished_at: {run.get('finished_at')}")
    # F23: one-line summary (hosts/resolved/findings/failures/duration)
    summary = state.run_summary(run_id, workdir=workdir)
    if summary:
        parts = [
            f"{summary['tools']} tools",
            f"{summary['done']} done",
            f"{summary['failed']} failed",
            f"{summary['skipped']} skipped",
        ]
        if summary["subdomains"]:
            parts.append(f"{summary['subdomains']} subs")
        if summary["resolved"]:
            parts.append(f"{summary['resolved']} resolved")
        if summary["urls"]:
            parts.append(f"{summary['urls']} urls")
        if summary["findings"]:
            parts.append(f"{summary['findings']} findings")
        if summary["failed_stages"]:
            parts.append(f"failed_stages={','.join(summary['failed_stages'])}")
        if summary["duration_s"] is not None:
            parts.append(f"{summary['duration_s']}s")
        print("  summary   : " + " ".join(parts))
    stats = state.stats(run_id)
    if not stats:
        print("  (no stages recorded)")
        return
    print("  stages:")
    for stage, by_status in sorted(stats.items()):
        total = sum(by_status.values())
        done = by_status.get("done", 0)
        failed = by_status.get("failed", 0)
        skipped = by_status.get("skipped", 0)
        timeout = by_status.get("timeout", 0)
        running = by_status.get("running", 0)
        print(f"    {stage:<20} total={total:<4} done={done:<3} "
              f"failed={failed:<3} skipped={skipped:<3} "
              f"timeout={timeout:<3} running={running}")


def await_loop(coro_factory, *args, **kwargs):
    """Run an async coroutine to completion from a sync context.
    Centralizes the asyncio.run() pattern used in cmd_run / cmd_resume."""
    import asyncio
    return asyncio.run(coro_factory(*args, **kwargs))


# ============================================================
# Subcommand implementations
# ============================================================


def cmd_run(args: argparse.Namespace) -> int:
    """Create + execute a new run.

    With --scopes-file, iterate over the CSV's scopes in sequence,
    running each scope's pipeline (one run row per scope).
    """
    scopes_file = getattr(args, "scopes_file", None)
    if scopes_file:
        from .scopecsv import parse_scopes_csv
        entries = parse_scopes_csv(scopes_file)
        if not entries:
            print(f"no scopes found in {scopes_file}", file=sys.stderr)
            return 1
        print(f"loom: {len(entries)} scopes from {scopes_file}")
        rc = 0
        for i, entry in enumerate(entries, 1):
            print(f"  [{i}/{len(entries)}] {entry.domain} "
                  f"pipeline={entry.pipeline} concurrency={entry.max_concurrency}")
            child = argparse.Namespace(**vars(args))
            child.domain = entry.domain
            child.pipeline = entry.pipeline
            child.max_concurrency = entry.max_concurrency
            child.scopes_file = None
            child_rc = _run_one(child)
            if child_rc != 0:
                print(f"  scope {entry.domain} failed (rc={child_rc}); continuing",
                      file=sys.stderr)
                rc = child_rc
        return rc
    return _run_one(args)


def _run_one(args: argparse.Namespace) -> int:
    """Start a new run against a domain and execute the chosen pipeline.
    v0.2 supports: catchall, subdomain, web. v0.3 adds: multi (per-host
    fanout driven by --subdomains or --from-eventlog).
    """
    import asyncio
    from .dag import DAG, Node
    from .eventlog import EventLog
    from .fanout import Fanout
    from .live import LiveLogger
    from .pipeline import Pipeline, PipelineContext
    from .rambudget import RamBudget
    from .ratelimit import RateLimiter
    from .runner import Runner
    from .stages import (
        make_assetfinder_stage, make_dnsx_stage, make_httpx_stage,
        make_katana_stage, make_naabu_stage, make_nuclei_stage,
        make_subfinder_stage, make_waybackurls_stage, make_gau_stage,
    )
    from . import catchall

    # --h1-scope: build the Scope from a HackerOne program CSV (mixed
    # asset types, eligibility flags, OOS denials). The program's
    # denied_hosts then gate every runner invocation.
    h1_file = getattr(args, "h1_scope", None)
    if h1_file:
        from .h1scope import parse_h1_scope_csv, scope_to_profile
        h1 = parse_h1_scope_csv(h1_file)
        prof = scope_to_profile(
            h1,
            h1_username=getattr(args, "h1_username", "drstrangexd"),
            rate_limit_rps=getattr(args, "rate_limit", 30),
        )
        prof["target"] = args.domain
        scope = from_dict(prof)
        print(f"loom: {h1.program} program scope — "
              f"{len(h1.in_scope_hosts)} in-scope hosts, "
              f"{len(h1.denied_hosts)} denied, "
              f"{len(h1.mobile_apps)} mobile apps")
    else:
        scope = _resolve_scope(args.scope, target=args.domain)

    # Denied-host gate: refuse to start if the target itself is out of
    # scope (e.g. an H1 CSV listed it as not eligible). This catches
    # targets that bypass the runner's per-tool gate (catchall etc.).
    if not scope.is_host_allowed(args.domain):
        print(f"target {args.domain!r} is denied by scope "
              f"{scope.name!r}; refusing to run", file=sys.stderr)
        return 1

    workdir = Path(args.workdir).expanduser()
    workdir.mkdir(parents=True, exist_ok=True)

    db_path = workdir / "loom.sqlite"
    with State(db_path) as st:
        run_id = st.start_run(
            args.domain, mode=args.mode, scope_profile=scope.name,
            scope_spec=json.dumps(scope.to_dict()),
            pipeline=args.pipeline,
        )
        run_dir = workdir / f"run-{run_id}"
        run_dir.mkdir(parents=True, exist_ok=True)
        el = EventLog(run_dir / "events.jsonl")
        log = LiveLogger(run_dir, run_id=run_id)
        log.info("run starting", domain=args.domain, pipeline=args.pipeline,
                 scope=scope.name, mode=args.mode,
                 max_concurrency=args.max_concurrency,
                 max_ram_gb=args.max_ram_gb)

        # Build runner + context
        outputs_dir = run_dir / "outputs"
        outputs_dir.mkdir(parents=True, exist_ok=True)
        rl = RateLimiter(rps=scope.rate_limit_rps,
                          burst=max(1, scope.rate_limit_rps // 10))
        budget = RamBudget(max_bytes=args.max_ram_gb * 1024**3)
        runner = Runner(scope, eventlog=el, state=st, run_id=run_id,
                        rate_limiter=rl, workdir=outputs_dir,
                        ram_budget=budget)
        ctx = PipelineContext(scope=scope, eventlog=el, state=st, run_id=run_id,
                              workdir=run_dir,
                              extras={"log": log})

        # Build pipeline
        dag, stages = _build_pipeline(args.pipeline, log, catchall, Runner)

        # Multi-pipeline: per-host fanout. First resolve host list,
        # then run the per-host DAG concurrently across hosts.
        if args.pipeline in ("multi", "multiweb"):
            hosts = _resolve_hosts(args, workdir, st, log)
            if not hosts:
                log.error("multi pipeline: no hosts (--subdomains file is "
                          "empty or --from-eventlog run produced none)")
                st.finish_run(run_id)
                log.close()
                return 1
            # Persist the resolved host list so resume can rebuild
            # the fanout without needing the original --subdomains/
            # --from-eventlog args.
            st._conn.execute(
                "UPDATE runs SET hosts_json=? WHERE id=?",
                (json.dumps(hosts), run_id),
            )
            log.info("multi pipeline: fanout",
                     hosts=len(hosts), max_concurrency=args.max_concurrency)

            # Factory creates a fresh Pipeline per host (no state race).
            def factory():
                c = PipelineContext(scope=scope, eventlog=el, state=st,
                                    run_id=run_id, workdir=run_dir)
                return Pipeline(runner, stages, context=c,
                                max_concurrency=2)
            fanout = Fanout(factory, max_concurrency=args.max_concurrency)
            try:
                results = asyncio.run(fanout.run(dag, hosts=hosts))
            except Exception as e:
                log.error(f"fanout crashed: {type(e).__name__}: {e}")
                st.finish_run(run_id)
                log.close()
                return 2

            # Summary
            print()
            log.info("─" * 60)
            log.info("multi run complete", run_id=run_id, hosts=len(hosts))
            total_items = 0
            for r in results:
                for o in r.outcomes:
                    log.stage_end(o.node_id, host=r.host, status=o.status,
                                  items=len(o.items), duration_s=o.duration_s)
                    total_items += len(o.items)
            log.info("─" * 60)
            log.info(f"  hosts     : {len(results)}")
            log.info(f"  items     : {total_items}")
            log.info(f"  workdir   : {run_dir}")
            log.info(f"  state     : {db_path}")
            log.info(f"  log       : {log.log_path}")
            st.finish_run(run_id)
            log.close()
            return 0

        # Single-host pipelines (catchall, subdomain, web)
        pipeline = Pipeline(runner, stages, context=ctx, max_concurrency=2)

        # Run
        try:
            outcomes = asyncio.run(pipeline.run(dag, host=args.domain))
        except Exception as e:
            log.error(f"pipeline crashed: {type(e).__name__}: {e}")
            st.finish_run(run_id)
            log.close()
            return 2

        # Print summary
        print()
        log.info("─" * 60)
        log.info("run complete", run_id=run_id)
        for o in outcomes:
            log.stage_end(o.node_id, host=args.domain, status=o.status,
                          items=len(o.items), duration_s=o.duration_s)
        log.info("─" * 60)
        log.info(f"workdir: {run_dir}")
        log.info(f"  state : {db_path}")
        log.info(f"  events: {run_dir / 'events.jsonl'}")
        log.info(f"  log   : {log.log_path}")
        log.info(f"  outputs: {outputs_dir}/<stage>/<host>/<tool>.*")
        st.finish_run(run_id)
        log.close()
    return 0


def _resolve_hosts(args, workdir: Path, st, log) -> list[str]:
    """Resolve the list of hosts for the `multi` pipeline.

    Priority:
      1. --from-eventlog RUN_ID  — read subdomain artifacts from that
         run's eventlog (resolved via the shared State DB and the
         workdir layout <workdir>/run-<id>/events.jsonl)
      2. --subdomains PATH        — read one subdomain per line from file
      3. (fallback)               — return [] (caller will error)
    """
    if args.from_eventlog is not None:
        prior_run = st.get_run(args.from_eventlog)
        if not prior_run:
            log.error(f"--from-eventlog run {args.from_eventlog} not found")
            return []
        prior_el = workdir / f"run-{args.from_eventlog}" / "events.jsonl"
        if not prior_el.exists():
            log.error(f"prior run eventlog not found: {prior_el}")
            return []
        log.info("resolving hosts from eventlog",
                 run_id=args.from_eventlog, path=str(prior_el))
        # Use a fresh EventLog against the prior file (read-only).
        prior = EventLog(prior_el)
        subs = [e["value"] for e in prior.read() if e.get("type") == "subdomain"]
        # Dedup but preserve order
        seen = set()
        unique = []
        for s in subs:
            if s not in seen:
                seen.add(s)
                unique.append(s)
        log.info(f"loaded {len(unique)} subdomains from eventlog",
                 run_id=args.from_eventlog)
        return unique
    if args.subdomains is not None:
        p = Path(args.subdomains).expanduser()
        if not p.exists():
            log.error(f"subdomains file not found: {p}")
            return []
        lines = []
        with open(p, encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    lines.append(s)
        log.info(f"loaded {len(lines)} subdomains from file", path=str(p))
        return lines
    return []


def _build_pipeline(name: str, log, catchall_mod, runner_cls):
    """Build the DAG + stages dict for the named pipeline.

    v0.2 pipelines:
      - catchall : 1 stage (catchall detect). Cheapest; works anywhere.
      - subdomain: subenum (subfinder+assetfinder) → resolve (dnsx)
                   → probe (httpx) → vulnscan (nuclei)
                   v0.4: += urls (waybackurls + gau)
      - web      : catchall → katana (+ hakrawler) → nuclei
      - multi    : per-host probe. - multiweb: per-host catchall → probe → nuclei
    v0.4 pipelines:
      - full     : subenum → resolve → probe → urls → xss → scan
      - deep     : full + portscan + permute → resolve + tls + uncover
                   + takeover (subjack) + fuzz (ffuf)
    """
    from .dag import DAG, Node
    from .stages import (
        make_assetfinder_stage, make_dnsx_stage, make_httpx_stage,
        make_katana_stage, make_nuclei_stage, make_subfinder_stage,
        make_alterx_stage, make_crlfuzz_stage, make_dalfox_stage,
        make_ffuf_stage, make_gau_stage, make_gowitness_stage,
        make_hakrawler_stage, make_kxss_stage, make_naabu_stage,
        make_subjack_stage, make_tlsx_stage, make_uncover_stage,
        make_waybackurls_stage,
    )
    from .live import LiveLogger
    from .pipeline import StageFn

    # Required-tool gate: refuse runs whose pipeline has unresolvable
    # tools (live-verified exit 127s mid-DAG are worse than a clean
    # pre-flight refusal).
    REQUIRED_TOOLS: dict[str, set[str]] = {
        "catchall": set(),
        "multi": {"httpx"},
        "multiweb": {"httpx"},
        "subdomain": {"subfinder", "assetfinder", "dnsx", "httpx"},
        "web": {"httpx", "nuclei"},
        "full": {"subfinder", "assetfinder", "dnsx", "httpx",
                 "waybackurls", "gau"},
        "deep": {"subfinder", "assetfinder", "dnsx", "httpx",
                 "waybackurls", "gau", "naabu"},
    }
    _ = runner_cls  # historical signature; stages resolve their own binaries
    from .tools import resolve_tool
    missing = sorted(
        t for t in REQUIRED_TOOLS.get(name, set()) if resolve_tool(t) is None
    )
    if missing:
        print(f"error: pipeline {name!r} missing required tools: "
              f"{', '.join(missing)} — install them or run 'loom validate'",
              file=sys.stderr)
        sys.exit(2)

    if name == "catchall":
        dag = DAG()
        dag.add(Node(id="catchall", outputs={"catchall_result"}))
        stages = {"catchall": _make_catchall_stage(log, catchall_mod)}
        return dag, stages

    if name == "subdomain":
        dag = DAG()
        dag.add(Node(id="subenum_subfinder", outputs={"subdomain"}))
        dag.add(Node(id="subenum_assetfinder", outputs={"subdomain"}))
        dag.add(Node(
            id="resolve", inputs={"subdomain"},
            depends_on=["subenum_subfinder", "subenum_assetfinder"],
            should_run=lambda s: (s.from_node("subenum_subfinder", "subdomain")
                                  + s.from_node("subenum_assetfinder", "subdomain")) > 0,
        ))
        dag.add(Node(
            id="probe", inputs={"subdomain"}, outputs={"url"},
            depends_on=["resolve"],
            should_run=lambda s: s.from_node("resolve", "subdomain") > 0,
        ))
        # v0.4: historical URLs (waybackurls + gau) — cheap passive OSINT
        # on the target domain, in parallel with the probe stage.
        dag.add(Node(
            id="urls", depends_on=["resolve"],
            should_run=lambda s: s.from_node("resolve", "subdomain") > 0,
        ))
        dag.add(Node(
            id="urls_gau", depends_on=["resolve"],
            should_run=lambda s: s.from_node("resolve", "subdomain") > 0,
        ))
        dag.add(Node(
            id="vulnscan", inputs={"url"}, depends_on=["probe"],
            should_run=lambda s: s.from_node("probe", "url") > 0,
        ))
        stages = {
            "subenum_subfinder": make_subfinder_stage(),
            "subenum_assetfinder": make_assetfinder_stage(),
            "resolve": make_dnsx_stage(),
            "probe": make_httpx_stage(),
            "urls": make_waybackurls_stage(),
            "urls_gau": make_gau_stage(),
            "vulnscan": make_nuclei_stage(),
        }
        return dag, stages

    if name == "web":
        dag = DAG()
        dag.add(Node(id="catchall", outputs={"catchall_result"}))
        dag.add(Node(
            id="katana", inputs={"catchall_result"},
            depends_on=["catchall"],
            should_run=lambda s: s.from_node("catchall", "catchall_result") > 0,
        ))
        # v0.4: hakrawler as a second crawler in parallel with katana.
        dag.add(Node(
            id="hakrawler", inputs={"catchall_result"},
            depends_on=["catchall"],
            should_run=lambda s: s.from_node("catchall", "catchall_result") > 0,
        ))
        dag.add(Node(
            id="nuclei", inputs={"subdomain", "url"},
            depends_on=["katana", "hakrawler"],
            should_run=lambda s: (s.from_node("katana", "url")
                                  + s.from_node("hakrawler", "url")) > 0,
        ))
        # v0.5: screenshot crawled hosts as evidence.
        dag.add(Node(
            id="screenshot", depends_on=["katana", "hakrawler"],
            should_run=lambda s: (s.from_node("katana", "url")
                                  + s.from_node("hakrawler", "url")) > 0,
        ))
        stages = {
            "catchall": _make_catchall_stage(log, catchall_mod),
            "katana": make_katana_stage(),
            "hakrawler": make_hakrawler_stage(),
            "nuclei": make_nuclei_stage(),
            "screenshot": make_gowitness_stage(),
        }
        return dag, stages

    if name == "multi":
        # Per-host fanout DAG: just `probe` (httpx). Used in
        # combination with --subdomains or --from-eventlog. Each
        # host gets its own Pipeline instance via the factory in
        # cmd_run, so concurrent hosts don't race on state.
        dag = DAG()
        dag.add(Node(id="probe", outputs={"host"}))
        stages = {"probe": make_httpx_stage()}
        return dag, stages

    if name == "multiweb":
        # Per-host fanout DAG: catchall → probe (skipped if catchall)
        # → nuclei (skipped if probe got 0 hosts). Each host is
        # walked independently via the fanout factory in cmd_run.
        dag = DAG()
        dag.add(Node(id="catchall", outputs={"catchall_result"}))
        dag.add(Node(
            id="probe",
            depends_on=["catchall"],
            # Skip probe if catchall failed (kind != "clean")
            should_run=lambda s: s.from_node("catchall", "catchall_result") > 0,
        ))
        dag.add(Node(
            id="nuclei",
            depends_on=["probe"],
            # Skip nuclei if probe produced 0 hosts (catchall server
            # or all hosts down).
            should_run=lambda s: s.from_node("probe", "host") > 0,
        ))
        stages = {
            "catchall": _make_catchall_stage(log, catchall_mod),
            "probe": make_httpx_stage(),
            "nuclei": make_nuclei_stage(),
        }
        return dag, stages

    if name == "full":
        # v0.4: the complete passive+active recon chain on one domain.
        #   [1] subenum (subfinder ∥ assetfinder)
        #   [2] resolve (dnsx over the pooled subs)
        #   [3] probe (httpx) ∥ urls (waybackurls ∥ gau)
        #   [4] xss fan-out (dalfox ∥ kxss ∥ crlfuzz) ∥ scan (nuclei)
        dag = DAG()
        dag.add(Node(id="subenum_subfinder", outputs={"subdomain"}))
        dag.add(Node(id="subenum_assetfinder", outputs={"subdomain"}))
        dag.add(Node(
            id="resolve", inputs={"subdomain"},
            depends_on=["subenum_subfinder", "subenum_assetfinder"],
            should_run=lambda s: (s.from_node("subenum_subfinder", "subdomain")
                                  + s.from_node("subenum_assetfinder", "subdomain")) > 0,
        ))
        dag.add(Node(
            id="probe", inputs={"subdomain"}, outputs={"url"},
            depends_on=["resolve"],
            should_run=lambda s: s.from_node("resolve", "subdomain") > 0,
        ))
        dag.add(Node(
            id="urls", depends_on=["resolve"],
            should_run=lambda s: s.from_node("resolve", "subdomain") > 0,
        ))
        dag.add(Node(
            id="urls_gau", depends_on=["resolve"],
            should_run=lambda s: s.from_node("resolve", "subdomain") > 0,
        ))
        dag.add(Node(
            id="xss", depends_on=["probe", "urls", "urls_gau"],
            should_run=lambda s: (s.from_node("urls", "url")
                                  + s.from_node("urls_gau", "url")
                                  + s.from_node("probe", "url")) > 0,
        ))
        dag.add(Node(
            id="xss_kxss", depends_on=["probe", "urls", "urls_gau"],
            should_run=lambda s: (s.from_node("urls", "url")
                                  + s.from_node("urls_gau", "url")) > 0,
        ))
        dag.add(Node(
            id="xss_crlfuzz", depends_on=["probe", "urls", "urls_gau"],
            should_run=lambda s: (s.from_node("urls", "url")
                                  + s.from_node("urls_gau", "url")) > 0,
        ))
        dag.add(Node(
            id="scan", inputs={"url"}, depends_on=["probe", "urls", "urls_gau"],
            should_run=lambda s: s.from_node("probe", "url") > 0,
        ))
        dag.add(Node(
            id="screenshot", depends_on=["probe"],
            should_run=lambda s: s.from_node("probe", "url") > 0,
        ))
        stages = {
            "subenum_subfinder": make_subfinder_stage(),
            "subenum_assetfinder": make_assetfinder_stage(),
            "resolve": make_dnsx_stage(),
            "probe": make_httpx_stage(),
            "urls": make_waybackurls_stage(),
            "urls_gau": make_gau_stage(),
            "xss": make_dalfox_stage(),
            "xss_kxss": make_kxss_stage(),
            "xss_crlfuzz": make_crlfuzz_stage(),
            "scan": make_nuclei_stage(),
            "screenshot": make_gowitness_stage(),
        }
        return dag, stages

    if name == "deep":
        # v0.4: full + infrastructure. Adds port scanning (naabu),
        # TLS SAN harvesting, search-engine asset discovery (uncover),
        # subdomain permutations (alterx → dnsx re-resolve), takeover
        # checks (subjack) and directory fuzzing (ffuf).
        dag = DAG()
        dag.add(Node(id="subenum_subfinder", outputs={"subdomain"}))
        dag.add(Node(id="subenum_assetfinder", outputs={"subdomain"}))
        dag.add(Node(id="subenum_uncover", outputs={"subdomain"}))
        dag.add(Node(
            id="permute", inputs={"subdomain"},
            depends_on=["subenum_subfinder", "subenum_assetfinder",
                        "subenum_uncover"],
            should_run=lambda s: (s.from_node("subenum_subfinder", "subdomain")
                                  + s.from_node("subenum_assetfinder", "subdomain")
                                  + s.from_node("subenum_uncover", "subdomain")) > 0,
        ))
        dag.add(Node(
            id="resolve", inputs={"subdomain"},
            depends_on=["permute"],
            should_run=lambda s: s.from_node("permute", "subdomain") > 0
            or (s.from_node("subenum_subfinder", "subdomain")
                + s.from_node("subenum_assetfinder", "subdomain")
                + s.from_node("subenum_uncover", "subdomain")) > 0,
        ))
        dag.add(Node(
            id="tls", depends_on=["resolve"],
            should_run=lambda s: s.from_node("resolve", "subdomain") > 0,
        ))
        dag.add(Node(
            id="portscan", depends_on=["resolve"],
            should_run=lambda s: s.from_node("resolve", "subdomain") > 0,
        ))
        dag.add(Node(
            id="probe", inputs={"subdomain"}, outputs={"url"},
            depends_on=["resolve", "tls"],
            should_run=lambda s: s.from_node("resolve", "subdomain") > 0,
        ))
        dag.add(Node(
            id="urls", depends_on=["resolve"],
            should_run=lambda s: s.from_node("resolve", "subdomain") > 0,
        ))
        dag.add(Node(
            id="urls_gau", depends_on=["resolve"],
            should_run=lambda s: s.from_node("resolve", "subdomain") > 0,
        ))
        dag.add(Node(
            id="xss", depends_on=["probe", "urls", "urls_gau"],
            should_run=lambda s: (s.from_node("urls", "url")
                                  + s.from_node("urls_gau", "url")
                                  + s.from_node("probe", "url")) > 0,
        ))
        dag.add(Node(
            id="xss_kxss", depends_on=["probe", "urls", "urls_gau"],
            should_run=lambda s: (s.from_node("urls", "url")
                                  + s.from_node("urls_gau", "url")) > 0,
        ))
        dag.add(Node(
            id="xss_crlfuzz", depends_on=["probe", "urls", "urls_gau"],
            should_run=lambda s: (s.from_node("urls", "url")
                                  + s.from_node("urls_gau", "url")) > 0,
        ))
        dag.add(Node(
            id="takeover", depends_on=["resolve", "tls"],
            should_run=lambda s: s.from_node("resolve", "subdomain") > 0,
        ))
        dag.add(Node(
            id="fuzz", depends_on=["probe"],
            should_run=lambda s: s.from_node("probe", "url") > 0,
        ))
        dag.add(Node(
            id="scan", inputs={"url"}, depends_on=["probe", "urls", "urls_gau"],
            should_run=lambda s: s.from_node("probe", "url") > 0,
        ))
        dag.add(Node(
            id="screenshot", depends_on=["probe"],
            should_run=lambda s: s.from_node("probe", "url") > 0,
        ))
        stages = {
            "subenum_subfinder": make_subfinder_stage(),
            "subenum_assetfinder": make_assetfinder_stage(),
            "subenum_uncover": make_uncover_stage(),
            "permute": make_alterx_stage(),
            "resolve": make_dnsx_stage(),
            "tls": make_tlsx_stage(),
            "portscan": make_naabu_stage(),
            "probe": make_httpx_stage(),
            "urls": make_waybackurls_stage(),
            "urls_gau": make_gau_stage(),
            "xss": make_dalfox_stage(),
            "xss_kxss": make_kxss_stage(),
            "xss_crlfuzz": make_crlfuzz_stage(),
            "takeover": make_subjack_stage(),
            "fuzz": make_ffuf_stage(),
            "scan": make_nuclei_stage(),
            "screenshot": make_gowitness_stage(),
        }
        return dag, stages

    raise ValueError(f"unknown pipeline: {name!r}")


def _make_catchall_stage(log, catchall_mod):
    """Wrap loom.catchall.detect as a StageFn with live logging."""
    import time
    from .pipeline import PipelineContext
    from .runner import OutputItem, Runner

    async def _stage(runner: Runner, host: str, ctx: PipelineContext):
        log.stage_start("catchall", host=host)
        t0 = time.monotonic()
        result = catchall_mod.detect(host, https=True, timeout=15.0)
        duration = time.monotonic() - t0
        classification = (result.get("classification")
                          or result.get("kind") or "unknown")
        conf = result.get("confidence", 0.0)
        log.tool_done("catchall", host=host, items=1, duration_s=duration)
        if classification == "catchall":
            log.warn("catchall server — scans will be noisy",
                     host=host, classification=classification, confidence=conf)
        else:
            log.info(f"target classified: {classification} (conf={conf})",
                     host=host)
        return [OutputItem(
            kind="catchall_result", value=classification,
            evidence={"confidence": conf, **result.get("evidence", {})},
        )]
    return _stage


def cmd_resume(args: argparse.Namespace) -> int:
    """Resume the latest unfinished run for `args.domain`.

    Reconstruction: read the run row to recover mode + scope_profile,
    then rebuild the same pipeline (using _build_pipeline) and run it
    through a ResumablePipeline so already-done stages are skipped.
    """
    import asyncio
    from .eventlog import EventLog
    from .live import LiveLogger
    from .pipeline import Pipeline, PipelineContext
    from .rambudget import RamBudget
    from .ratelimit import RateLimiter
    from .resume import ResumablePipeline
    from .runner import Runner
    from . import catchall

    workdir = Path(args.workdir).expanduser()
    if not workdir.exists():
        print(f"workdir {workdir} does not exist; nothing to resume",
              file=sys.stderr)
        return 1

    db_path = workdir / "loom.sqlite"
    if not db_path.exists():
        print(f"no state db at {db_path}; nothing to resume", file=sys.stderr)
        return 1

    with State(db_path) as st:
        target_run = latest_inflight_run(st, args.domain)
        if target_run is None:
            print(f"no inflight run for domain {args.domain!r}", file=sys.stderr)
            return 1
        run = st.get_run(target_run)
        if run is None:
            # Race: run was finished/deleted between latest_inflight_run
            # and get_run. Treat as no inflight run.
            print(f"run {target_run} disappeared; cannot resume",
                  file=sys.stderr)
            return 1
        # Prefer the persisted scope_spec (v0.3+); fall back to
        # looking up the bundled scope by name (older runs, or runs
        # that predate the scope_spec migration).
        scope_spec = run.get("scope_spec")
        if scope_spec:
            try:
                scope = from_dict(json.loads(scope_spec))
            except Exception as e:
                print(f"could not parse scope_spec for run {target_run}: {e}",
                      file=sys.stderr)
                return 1
        else:
            scope = _resolve_scope(run["scope_profile"], target=args.domain)
        run_dir = workdir / f"run-{target_run}"
        el = EventLog(run_dir / "events.jsonl")
        log = LiveLogger(run_dir, run_id=target_run)

        # v0.3+: rebuild the original pipeline name + host list from
        # the persisted run row so resume works without the original
        # --pipeline/--subdomains/--from-eventlog CLI args.
        pipeline_name = run.get("pipeline") or "catchall"
        hosts_json = run.get("hosts_json")
        persisted_hosts = json.loads(hosts_json) if hosts_json else None

        log.info("resume starting", run_id=target_run,
                 domain=args.domain, mode=run["mode"],
                 scope=scope.name, pipeline=pipeline_name,
                 hosts=len(persisted_hosts) if persisted_hosts else 0)

        outputs_dir = run_dir / "outputs"
        rl = RateLimiter(rps=scope.rate_limit_rps,
                          burst=max(1, scope.rate_limit_rps // 10))
        budget = RamBudget(max_bytes=getattr(args, "max_ram_gb", 20) * 1024**3)
        runner = Runner(scope, eventlog=el, state=st, run_id=target_run,
                        rate_limiter=rl, workdir=outputs_dir,
                        ram_budget=budget)
        ctx = PipelineContext(scope=scope, eventlog=el, state=st,
                              run_id=target_run, workdir=run_dir,
                              extras={"log": log})

        dag, stages = _build_pipeline(pipeline_name, log, catchall, Runner)

        # Multi-host resume: drive the fanout across the persisted
        # host list, using a fresh Pipeline per host (the factory
        # pattern that prevents state races).
        if pipeline_name in ("multi", "multiweb") and persisted_hosts:
            from .fanout import Fanout

            def factory():
                c = PipelineContext(scope=scope, eventlog=el, state=st,
                                    run_id=target_run, workdir=run_dir)
                return ResumablePipeline(runner, stages, context=c)

            fanout = Fanout(factory, max_concurrency=args.max_concurrency)
            try:
                results = await_loop(fanout.run, dag, persisted_hosts)
            except Exception as e:
                log.error(f"fanout resume crashed: {type(e).__name__}: {e}")
                log.close()
                return 2
            # Summary
            print()
            log.info("─" * 60)
            log.info("multi resume complete", run_id=target_run,
                     hosts=len(persisted_hosts))
            for r in results:
                for o in r.outcomes:
                    log.stage_end(o.node_id, host=r.host, status=o.status,
                                  items=len(o.items), duration_s=o.duration_s)
            log.info("─" * 60)
            log.info(f"  workdir: {run_dir}")
            log.info(f"  log    : {log.log_path}")
            st.finish_run(target_run)
            log.close()
            return 0

        # Single-host resume (catchall / subdomain / web).
        rp = ResumablePipeline(runner, stages, context=ctx)

        try:
            outcomes = asyncio.run(rp.run_resumable(dag, host=args.domain))
        except Exception as e:
            log.error(f"resume crashed: {type(e).__name__}: {e}")
            log.close()
            return 2

        # Summary
        print()
        log.info("─" * 60)
        log.info("resume complete", run_id=target_run)
        for o in outcomes:
            log.stage_end(o.node_id, host=args.domain, status=o.status,
                          items=len(o.items), duration_s=o.duration_s)
        log.info("─" * 60)
        log.info(f"  workdir: {run_dir}")
        log.info(f"  log    : {log.log_path}")
        st.finish_run(target_run)
        log.close()
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    workdir = Path(args.workdir).expanduser()
    if not workdir.exists():
        print(f"workdir {workdir} does not exist", file=sys.stderr)
        return 1

    db_path = workdir / "loom.sqlite"
    if not db_path.exists():
        print(f"no runs found for domain {args.domain!r}", file=sys.stderr)
        return 1

    with State(db_path) as st:
        runs = st.list_runs(domain=args.domain)
        if not runs:
            print(f"no runs found for domain {args.domain!r}", file=sys.stderr)
            return 1
        # list_runs already returns newest-first. If --run is given,
        # pick that specific run; else the newest.
        if getattr(args, "run", None) is not None:
            run_id = args.run
            if not any(r["id"] == run_id for r in runs):
                print(f"run {run_id} not found for domain {args.domain!r}",
                      file=sys.stderr)
                return 1
        else:
            run_id = runs[0]["id"]
        _print_stats(st, run_id, workdir=workdir)
    return 0


def cmd_list_runs(args: argparse.Namespace) -> int:
    workdir = Path(args.workdir).expanduser()
    db_path = workdir / "loom.sqlite"
    if not db_path.exists():
        print("(no runs yet)")
        return 0
    any_found = False
    with State(db_path) as st:
        runs = st.list_runs(domain=args.domain)
        for r in runs:
            any_found = True
            finished = r.get("finished_at")
            status = "done" if finished else "inflight"
            pipeline = r.get("pipeline") or "-"
            hosts = r.get("hosts_json")
            hosts_n = f"{len(json.loads(hosts))} hosts" if hosts else ""
            print(f"run {r['id']:<4} {status:<10} domain={r['domain']:<20} "
                  f"pipeline={pipeline:<10} {hosts_n:<12} "
                  f"mode={r.get('mode')}  scope={r.get('scope_profile')}")
    if not any_found:
        print("(no runs yet)")
    return 0


# Tools loom expects (best-effort detection; missing tools are non-fatal).
EXPECTED_TOOLS = {
    "subfinder": "passive subdomain enumeration",
    "httpx": "HTTP probing",
    "naabu": "port scanning",
    "nuclei": "vulnerability scanning",
    "katana": "web crawling",
    "dnsx": "DNS toolkit",
    "ffuf": "web fuzzing",
    "gau": "wayback URL fetcher",
    "waybackurls": "wayback URL fetcher",
    "assetfinder": "subdomain enumeration",
    "amass": "attack surface mapping",
    "uncover": "exposed-asset discovery (search engines)",
    "tlsx": "TLS SAN/CN harvesting",
    "dalfox": "XSS scanning",
    "crlfuzz": "CRLF injection scanning",
    "kxss": "reflected-parameter detection",
    "hakrawler": "web crawling (JS-aware)",
    "subjack": "subdomain takeover checks",
    "alterx": "subdomain permutation generation",
    "gowitness": "screenshotting",
}


def cmd_validate(args: argparse.Namespace) -> int:
    from .tools import validate_report
    report = validate_report()
    missing: list[str] = []
    shadowed: int = 0
    print(f"loom {__version__} — tool check")
    print(f"  {'tool':<15} {'path'}")
    for tool, status, path, note in report:
        if status == "missing":
            missing.append(tool)
            print(f"  {tool:<15} (NOT FOUND)")
        else:
            print(f"  {tool:<15} {path}")
            if note:
                shadowed += 1
                print(f"  {'':<15}   {note}")
    print()
    ok = len(report) - len(missing)
    print(f"  {ok} present, {len(missing)} missing"
          + (f", {shadowed} shadowed" if shadowed else ""))
    return 0 if not missing else 1


# ============================================================
# Argument parsing
# ============================================================


def cmd_sweeps(args: argparse.Namespace) -> int:
    """Overnight multi-scope orchestrator.

    A friendlier wrapper over `loom run --scopes-file` for cron/overseer
    scripts. Iterates each scope in the CSV sequentially, prints a
    compact summary table, and exits with the count of failed scopes
    (capped at 1) so a non-zero exit surfaces problems.
    """
    from .scopecsv import parse_scopes_csv
    scopes_file = Path(args.scopes_file).expanduser()
    if not scopes_file.exists():
        print(f"scopes file not found: {scopes_file}", file=sys.stderr)
        return 1
    entries = parse_scopes_csv(scopes_file)
    if not entries:
        print(f"no scopes found in {scopes_file}", file=sys.stderr)
        return 1
    print(f"loom sweeps — {len(entries)} scope(s) from {scopes_file}")
    print(f"  {'#':<3} {'domain':<28} {'pipeline':<10} {'conc':<4} result")
    rc = 0
    for i, entry in enumerate(entries, 1):
        child = argparse.Namespace(**vars(args))
        child.domain = entry.domain
        child.pipeline = entry.pipeline
        child.max_concurrency = entry.max_concurrency
        child.scopes_file = None
        t0 = time.monotonic()
        try:
            child_rc = _run_one(child)
        except SystemExit as e:
            child_rc = int(e.code) if isinstance(e.code, int) else 2
        except Exception as e:  # defensive — never crash a sweep on one bad scope
            print(f"  [{i}/{len(entries)}] {entry.domain} crashed: "
                  f"{type(e).__name__}: {e}", file=sys.stderr)
            child_rc = 2
        dt = time.monotonic() - t0
        status = "ok" if child_rc == 0 else f"rc={child_rc}"
        print(f"  {i:<3} {entry.domain:<28} {entry.pipeline:<10} "
              f"{entry.max_concurrency:<4} {status}  ({dt:.1f}s)")
        if child_rc != 0:
            rc = 1
    return rc


def cmd_findings(args: argparse.Namespace) -> int:
    """Aggregate findings across all runs in a workdir.

    Reads every run-*/events.jsonl, keeps finding/takeover events,
    dedupes on (value, source), severity-sorts, prints a report or
    --json.
    """
    workdir = Path(args.workdir).expanduser()
    if not workdir.exists():
        print(f"workdir {workdir} does not exist", file=sys.stderr)
        return 1
    db_path = workdir / "loom.sqlite"
    if not db_path.exists():
        print("no runs found (no loom.sqlite)", file=sys.stderr)
        return 1

    run_domains: dict[int, str] = {}
    with State(db_path) as st:
        for r in st.list_runs():
            run_domains[r["id"]] = r.get("domain") or "?"

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    merged: dict[tuple[str, str], dict] = {}
    for ev_file in sorted(workdir.glob("run-*/events.jsonl")):
        try:
            run_id = int(ev_file.parent.name.split("-", 1)[1])
        except ValueError:
            continue
        try:
            lines = ev_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            etype = ev.get("type")
            if etype not in ("finding", "takeover"):
                continue
            src = ev.get("source") or "?"
            key = (str(ev.get("value")), src)
            runs = ev.setdefault("evidence", {}).setdefault("runs", [])
            if run_id not in runs:
                runs.append(run_id)
            prev = merged.get(key)
            if prev is None:
                sev = (ev.get("evidence", {}).get("severity") or "").lower()
                if etype == "takeover":
                    sev = sev or "high"
                ev["severity"] = sev or "info"
                ev["host"] = ev.get("host") or "?"
                merged[key] = ev
            else:
                # keep the richer severity across duplicates
                if ev.get("evidence", {}).get("severity", "") \
                        not in (None, "", "info"):
                    prev["severity"] = ev["evidence"]["severity"].lower()

    if not merged:
        print("no findings recorded yet", file=sys.stderr)
        return 1

    rows = sorted(merged.values(),
                  key=lambda e: (sev_order.get(e["severity"], 9),
                                 str(e.get("host", "")), str(e.get("value"))))
    if getattr(args, "json", False):
        print(json.dumps(rows, indent=2, default=str))
        return 0

    print(f"loom findings — {len(rows)} unique "
          f"(from runs {min(run_domains) if run_domains else '-'}.."
          f"{max(run_domains) if run_domains else '-'})")
    print(f"  {'sev':<8} {'source':<10} {'host':<28} value")
    for ev in rows:
        runs = ",".join(map(str, ev["evidence"].get("runs", [])))
        kind = (ev["evidence"].get("template_id")
                or ev["evidence"].get("vuln")
                or ev.get("type", "finding"))
        print(f"  {ev['severity']:<8} {str(ev.get('source'))[:10]:<10} "
              f"{str(ev.get('host'))[:28]:<28} {ev['value']}  "
              f"[{kind}] runs={runs}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="loom",
        description="loom — personal bug bounty orchestrator",
    )
    p.add_argument("--version", action="version", version=f"loom {__version__}")
    p.add_argument("--workdir", default=str(DEFAULT_WORKDIR),
                   help=f"workdir for runs (default: {DEFAULT_WORKDIR})")
    sub = p.add_subparsers(dest="cmd", required=True)

    # run
    pr = sub.add_parser("run", help="start a new run against a domain")
    pr.add_argument("domain", help="target domain (e.g. example.com)")
    pr.add_argument("--scope", default="default",
                    help="scope profile name (default: default)")
    pr.add_argument("--mode", default="recon",
                    help="run mode (recon, fast, deep)")
    pr.add_argument("--pipeline", default="catchall",
                    choices=["catchall", "subdomain", "web", "multi", "multiweb",
                             "full", "deep"],
                    help="pipeline to run (default: catchall). 'full' = enum+"
                         "resolve+probe+urls+xss+nuclei; 'deep' = full + ports, "
                         "TLS SAN, uncover, permute, takeover, fuzz")
    pr.add_argument("--subdomains", default=None,
                    help="path to a file with one subdomain per line; "
                         "used by 'multi' pipeline to drive per-host fanout")
    pr.add_argument("--from-eventlog", type=int, default=None, metavar="RUN_ID",
                    help="seed host list from a prior run's eventlog "
                         "(subdomain artifacts). Use with 'multi'.")
    pr.add_argument("--max-concurrency", type=int, default=10,
                    help="max concurrent hosts (default: 10)")
    pr.add_argument("--max-ram-gb", type=int, default=20,
                    help="per-run RAM budget cap in GB (default: 20)")
    pr.add_argument("--scopes-file", default=None,
                    help="path to a scope CSV (domain[,pipeline[,concurrency]] "
                         "per line, '#' comments); runs each scope in sequence "
                         "for overnight multi-scope operation")
    pr.add_argument("--h1-scope", default=None,
                    help="path to a HackerOne program scope CSV; builds the "
                         "Scope (headers, rate limit, denied hosts) from it")
    pr.add_argument("--h1-username", default="drstrangexd",
                    help="HackerOne username for X-Bug-Bounty/X-HackerOne-Research "
                         "headers (default: drstrangexd)")
    pr.add_argument("--rate-limit", type=int, default=30,
                    help="requests/sec cap for H1-program runs (default: 30)")
    pr.set_defaults(func=cmd_run)

    # resume
    prs = sub.add_parser("resume", help="resume the latest inflight run")
    prs.add_argument("domain", help="target domain")
    prs.add_argument("--scope", default="default",
                     help="scope profile name (default: default)")
    prs.add_argument("--max-concurrency", type=int, default=10,
                     help="max concurrent hosts for multi-pipeline resume (default: 10)")
    prs.set_defaults(func=cmd_resume)

    # status
    ps = sub.add_parser("status", help="show status of a run")
    ps.add_argument("domain", help="target domain")
    ps.add_argument("--run", type=int, default=None,
                    help="specific run id (default: newest)")
    ps.set_defaults(func=cmd_status)

    # list-runs
    pl = sub.add_parser("list-runs", help="list all runs")
    pl.add_argument("--domain", help="filter by domain")
    pl.set_defaults(func=cmd_list_runs)

    # validate
    pv = sub.add_parser("validate", help="check that recon tools are installed")
    pv.set_defaults(func=cmd_validate)

    # sweeps — overnight multi-scope wrapper
    psw = sub.add_parser("sweeps",
                         help="run a multi-scope overnight sweep "
                              "(wrapper over `run --scopes-file`)")
    psw.add_argument("--scopes-file", required=True,
                     help="CSV: domain[,pipeline[,concurrency]] per line")
    psw.add_argument("--workdir", default=str(DEFAULT_WORKDIR),
                     help=f"workdir (default: {DEFAULT_WORKDIR})")
    psw.add_argument("--h1-username", default="drstrangexd",
                     help="HackerOne username for headers (default: drstrangexd)")
    psw.add_argument("--rate-limit", type=int, default=30,
                     help="requests/sec cap for H1-program runs (default: 30)")
    psw.add_argument("--max-ram-gb", type=int, default=20,
                     help="per-run RAM budget cap in GB (default: 20)")
    psw.set_defaults(func=cmd_sweeps)

    # findings — cross-run aggregated findings report
    pf = sub.add_parser("findings",
                        help="aggregate findings across all runs (severity-sorted)")
    pf.add_argument("--json", action="store_true",
                    help="emit findings as a JSON array")
    pf.set_defaults(func=cmd_findings)

    # status-server — minimal live run-status web page
    pss = sub.add_parser("status-server",
                         help="serve a minimal live run-status web page")
    pss.add_argument("--workdir", required=True, help="loom workdir to watch")
    pss.add_argument("--port", type=int, default=8080)
    pss.set_defaults(func=_cmd_status_server)

    return p


def _cmd_status_server(args: argparse.Namespace) -> int:
    from .webstatus import serve
    serve(Path(args.workdir).expanduser(), args.port)
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
