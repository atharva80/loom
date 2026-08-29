# AGENTS.md — how to work on loom

## Project

**loom** is a personal bug-bounty orchestrator: a streaming DAG scheduler
that drives recon tools (subfinder, httpx, nuclei, katana, ffuf, …) through
a resumable, rate-limited, scope-aware pipeline.

The Python orchestrator lives in `loom/`; the upstream `reconftw.sh` shell
scripts are kept as a reference implementation.

## Build & run

```bash
# Install in editable mode
pip install -e ".[dev]"

# Run the full test suite (pytest-asyncio, asyncio_mode=auto)
.venv/bin/pytest

# Run a single test file
.venv/bin/pytest tests/test_runner.py -v

# Run a live test against a public target
.venv/bin/loom --workdir /tmp/loom-test run public-firing-range.appspot.com --pipeline catchall
```

## Test-driven development

**Every feature lands with tests first, then the implementation, then a
commit. No commit before the feature's test passes.**

- Tests use `pytest` + `pytest-asyncio` with `asyncio_mode = "auto"` (no
  `@pytest.mark.asyncio` decorators needed).
- Pyright noise is expected and ignored — pytest is the source of truth.
- Fake-binary integration tests: write shell scripts to a temp dir,
  prepend to `PATH`, run the real `Runner` against them. No mocks.
- Live tests use `public-firing-range.appspot.com` (the only authorized
  reachable target). Do not hit production bug-bounty targets from tests.

## Architecture

```
scope ──┐
        ├─► Runner ──► subprocess ──► OutputItem ─┐
eventlog┤                                          ├─► Pipeline ──► DAG
state ──┘                                          │
                                                   └─► Fanout (multi-host)
```

Key modules:

| Module | Responsibility |
|---|---|
| `loom/eventlog.py` | Append-only JSONL, offset pagination |
| `loom/state.py` | SQLite WAL — runs + tool_runs tables |
| `loom/runner.py` | Subprocess launch, parsing, RAM budget, header injection |
| `loom/dag.py` | Topological levels, should_run predicates, cycle detection |
| `loom/pipeline.py` | Async DAG walker, concurrency cap, cross-stage extras |
| `loom/resume.py` | ResumablePipeline — skips done stages |
| `loom/stages.py` | StageFn factories for each tool |
| `loom/fanout.py` | Per-host concurrent fanout (factory pattern) |
| `loom/rambudget.py` | 20GB RAM cap with per-tool RSS estimates |
| `loom/h1scope.py` | HackerOne scope CSV parser |
| `loom/scopecsv.py` | Simple CSV scope-list runner |
| `loom/tools.py` | Binary resolution, shadower detection |
| `loom/cli.py` | argparse entrypoint |
| `loom/webstatus.py` | Live status HTTP server |

## Conventions

- All timestamps are ISO-8601 with ms precision, UTC.
- Event format: `{type, source, host, value, ts, evidence}`.
- Per-tool output layout:
  `<workdir>/run-<id>/<stage>/<host>/<tool>.<unix-ms>.<stdout|stderr|cmd>.txt|.jsonl`
- State DB: single workdir-level `loom.sqlite` (WAL mode).
- CLI: `loom run <domain> [--pipeline P] [--scope S] [--h1-scope F] [--scopes-file F] [--workdir D]`.

## What NOT to do

- Don't edit `reconftw.sh`, `modules/`, `lib/`, `config/` — upstream content.
- Don't shadow `gh` with a token in commands — use `gh auth` or env vars.
- Don't hit production BB targets from automated tests.
- Don't bypass the scope gate — denied hosts are denied for a legal reason.
- Don't add emojis, widgets, or "AI-gen" chrome to the status page.

## Security

- Per-program scope profiles gate every request.
- Denied hosts are blocked at both the CLI gate and the runner's tool check.
- The live status server binds to `127.0.0.1` only.
- No credentials in the repo — `secrets.cfg.example` is the template.
