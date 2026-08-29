# Loom Architecture — what reconftw does, what loom adds

## reconftw architecture (mapped)

### File structure
- `reconftw.sh` (1k LOC) — CLI parser, config loader, calls `start` → function chain → `end`
- `reconftw.cfg` (27k) — 600+ tunables
- `lib/validation.sh` (392) — input validators
- `lib/common.sh` (904) — common helpers (file count, dedup, sanitize)
- `lib/parallel.sh` (967) — `parallel_funcs` (background jobs + wait), `start_task`/`end_task`
- `lib/ui.sh` (464) — colored output
- `modules/modes.sh` (1.7k) — top-level entry points: `passive`, `osint`, `recon`, `vulns`, `all`, `multi_recon`, `monitor_mode`, `report_only_mode`
- `modules/core.sh` (2.4k) — logging, progress, incremental, monitor, cloud helpers
- `modules/subdomains.sh` (2.4k) — sub enum stages: `_subdomains_init`, `_subdomains_enumerate`, `_subdomains_finalize`
- `modules/web.sh` (3k) — probe, port scan, nuclei, fuzz, katana
- `modules/vulns.sh` (1.2k) — LFI, nuclei dast
- `modules/osint.sh` (787) — emails, dorks, leaks
- `modules/axiom.sh` (270) — distributed exec wrapper
- `modules/utils.sh` (1.5k) — lower-level functions

### Execution model
```
reconftw.sh → parse args → load cfg → load modules → call chosen mode function
mode function (e.g. `recon`) → fixed sequence of stage functions
each stage function → runs tools sequentially OR via `parallel_funcs`
parallel_funcs → backgrounded with `&` + `wait -n` loop, output to file
```

### Parallelism
- **`parallel_funcs N func1 func2 ...`** — runs N independent functions as bg jobs, waits for any one to finish, then starts next. This is the only parallelism primitive. Static fan-out per group.
- Per-tool threads are tuned in `reconftw.cfg` (`FFUF_THREADS=$((AVAILABLE_CORES * 10))` etc.).
- Axiom mode can offload stages to a fleet of cloud VMs.

### What reconftw already does well (DO NOT REBUILD)
1. ✅ Tool install (`install.sh`, 60k LOC)
2. ✅ Tool detection, missing-tool warnings (`tools_installed`, `mark_missing_tools_warn_once`)
3. ✅ Config system (600+ vars, `--custom-config`, `secrets.cfg.example`)
4. ✅ Output directory tree (`Recon/<domain>/`)
5. ✅ Resume via `incremental_save`/`incremental_diff`/`incremental_should_skip`
6. ✅ Hotlist (risk scoring)
7. ✅ Multiple modes (passive, osint, recon, vulns, all, multi_recon, monitor, report_only)
8. ✅ Axiom distributed execution
9. ✅ Cloud enum, OSINT, dorking, email harvesting
10. ✅ Notification (Slack/Telegram/Discord via `notify`)

### What reconftw DOES NOT do (what loom adds)

| Gap | reconftw reality | Loom addition |
|-----|------------------|---------------|
| **DAG-based streaming scheduler** | Linear function chain; `parallel_funcs` only runs within a group, can't depend on streaming output | Real DAG: each stage declares inputs/outputs, fires when minimum input ready |
| **Catch-all detection** | None — `ffuf` blindly sprays catch-alls | Pre-screen: same body for `/` and `/random_abc123` → mark catch-all, skip heavy stages |
| **Scope profiles** | Single global cfg, no per-program ROE encoding | `scope/<program>.yaml`: headers, banned tools, rate caps, allowed methods, allowed hosts |
| **Per-tool resource profiles** | Just `*_THREADS` config | `tools.yaml` profile: rps, memory MB, timeout, threads, requires, produces |
| **Normalized event log (JSONL)** | Per-tool files only, no canonical event stream | Every tool emits to `events.jsonl` with `{ts, stage, tool, type, host, value, evidence}` |
| **Rate budget sharing** | Per-tool rate limit, no global cap | Global RPS budget distributed across active tools |
| **Tech-aware template selection** | Nuclei runs all tags | Pick nuclei tags by `httpx` tech-detect output |
| **Resumability per host per tool** | Module-level: if nuclei crashes, restart whole nuclei | Per-host state in SQLite: nuclei on host X done at ts T |
| **Backpressure** | None — fire and forget | Slow downstream stage signals upstream to throttle |
| **Find finding store** | Files | SQLite DB queryable across runs |
| **Time/rate graphs in CLI** | None | Live TUI with current stage progress, RPS, ETA |
| **Hexstrike/MCP integration** | None | Each loom stage callable via MCP tool |
| **Auto-scope extraction from H1 program** | Manual | Parse `program_policy_url` and warn about banned techniques |

## Loom scope (v1)

### In
- DAG scheduler (Python 3.12, asyncio, no extra deps)
- Scope profile (YAML, 3 example profiles: default, verily-style, fast)
- Catch-all detector (the single biggest ROI piece)
- Tech-aware nuclei tag selection
- Tool resource profiles (in-process, no YAML)
- JSONL event log writer
- Resume via SQLite state
- Live progress + RPS display
- Wraps existing reconftw stages (calls them via `parallel_funcs` under the hood OR runs tool binaries directly with a thin Python wrapper)
- Single CLI: `loom recon -d target.com -s scope.yaml`
- One test target run end-to-end to verify

### Out (v2+)
- LLM decisioning
- Auth state injection (Caido/Burp cookies)
- Distributed/axiom mode (use reconftw's existing)
- Mobile/smart-contract (stay web-only)
- Auto-reporting

## Build order (test-driven, commit per feature)

1. **loom/eventlog.py** + `test_eventlog.py` — JSONL append + read + dedup
2. **loom/state.py** + `test_state.py` — SQLite state (per-host per-tool)
3. **loom/tools.py** + `test_tools.py` — tool resource profiles (rps, mem, threads, timeout)
4. **loom/catchall.py** + `test_catchall.py` — catch-all detector
5. **loom/scope.py** + `test_scope.py` — scope profile loader + enforcer
6. **loom/scheduler.py** + `test_scheduler.py` — DAG executor with streaming + backpressure
7. **loom/pipeline.py** + `test_pipeline.py` — actual 7-stage recon pipeline
8. **loom/cli.py** + `test_cli.py` — `loom recon -d X -s scope.yaml`
9. **loom/progress.py** + `test_progress.py` — live TUI
10. **End-to-end** run on `public-firing-range.appspot.com` and verify

## Critical decision: wrap reconftw vs replace

Two paths:
- **Path A: wrap reconftw bash functions from Python.** Use `subprocess` to call bash. Pro: get 18k lines of reconftw for free. Con: hard to test, two-language debugging.
- **Path B: replace reconftw's stage functions with Python equivalents, keep its install + config + output tree.** Pro: testable, single language. Con: more work.

**Path B chosen.** Why: the reconftw stages are simple bash pipelines around CLI tools — replicating them in Python is mostly `subprocess.run([...])` calls. The bash we keep is the install script and config schema.

## Test targets (authorized, per skill)
- `public-firing-range.appspot.com` (Google's authorized BB range, responsive)
- `testhtml5.vulnweb.com` (unreliable from here, skip)
- `testasp.vulnweb.com` (unreliable from here, skip)

We'll use `public-firing-range.appspot.com` for all live tests.

## Memory/rate ceilings (measured on this box)
- nuclei: 104MB resident, 13,619 templates
- nuclei safe concurrent: 4 (6GB used)
- ffuf safe concurrent: 6 (5GB)
- katana (headless) safe concurrent: 4 (2.4GB)
- amass active safe concurrent: 1 (2GB)
- RPS budget per program: vary 10-200, must be honored globally
- Total parallel heavy tools: 15-18 max
