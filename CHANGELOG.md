# Changelog

## v0.4.2 — 2026-09-04

Eight new tool stages, two new pipelines, findings/sweeps subcommands,
and a preflight tool gate.

### New features

- **8 new tool stages** — uncover (search-engine asset discovery),
  tlsx (TLS SAN/CN harvesting), dalfox (XSS), crlfuzz (CRLF injection),
  kxss (reflected parameters), hakrawler (JS-aware crawler), subjack
  (takeover checks), alterx (subdomain permutations). Real flags
  verified against the installed binaries.
- **`full` pipeline** — subenum → resolve → probe ∥ urls → xss fan-out
  (dalfox ∥ kxss ∥ crlfuzz) ∥ nuclei scan.
- **`deep` pipeline** — full + naabu portscan + tlsx + uncover +
  alterx permute → re-resolve + subjack takeover + ffuf fuzz.
- **`loom findings [--json]`** — cross-run aggregated findings report:
  deduped on (value, source), severity-sorted, run provenance per row,
  takeover events default to high severity.
- **`loom sweeps --scopes-file F`** — overnight multi-scope wrapper
  with a per-scope summary table and a non-zero exit if any scope
  failed.
- **Preflight required-tool gate** — runs refuse cleanly (exit 2) when
  a pipeline's core binaries are unresolvable, instead of exit-127
  storms mid-DAG.
- **`urls`/`urls_gau` stages wired** — waybackurls + gau factories
  existed since v0.2 but ran in no pipeline; now in `subdomain`,
  `full`, and `deep`.
- **ffuf real-JSONL parser** — JSONL output becomes finding items
  (status, input, length, words).
- **Wordlist auto-resolution** — ffuf falls back to SecLists on
  boxes without `/usr/share/wordlists`, and finally to a built-in
  mini wordlist written into the run's inputs dir.

### Bugs fixed

- **Binary resolution fallback** — non-shadower tools installed in
  `~/go/bin` but absent from PATH resolved to None (1/12 → 11/12 on
  the dev box). PATH precedence for hits is preserved.
- **alterx permutation explosion** — uncapped alterx generated
  109,705 permutations from 190 subs on vulnweb.com and starved the
  dnsx resolve stage. Now `-limit 5000` by default (configurable).
- **ffuf flags** — `-silent -noninteractive` are not real ffuf flags
  (the binary just printed help). Now `-s -json`.
- **Version drift** — pyproject said 0.1.0 while CHANGELOG was at
  v0.3.0; a consistency test now locks them together.

## v0.3.0 — 2026-08-30

First public-ready release. Full orchestrator with multi-host fanout,
crash-resume, HackerOne scope support, and a live status page.

### New features

- **Vulnscan stage** — nuclei wired into the subdomain pipeline
  (`subenum → resolve → probe → vulnscan`), with tech-stack template
  selection (`-tags iis,aspnet,...` from httpx fingerprints).
- **HackerOne scope CSV parser** (`loom/h1scope.py`) — parses real H1
  program exports: mixed asset types (wildcard/URL/API/mobile/OTHER),
  eligibility flags → denied hosts, ccTLD wildcard handling, OOS
  path-precision.
- **`--h1-scope`, `--h1-username`, `--rate-limit` CLI flags** — load a
  program's scope CSV directly, build the Scope (headers, rate limit,
  denied hosts) from it.
- **Denied-target pre-run gate** — running an out-of-scope host fails
  fast before any stage runs.
- **Live status server** (`loom status-server`) — minimal terminal-style
  page, 2s polling, per-stage timers/status/duration, log tail, event
  counts. Stdlib only, binds to `127.0.0.1`.
- **RAM budget enforcement** — Runner acquires estimated RSS per tool
  before launch, releases on exit; `--max-ram-gb` (default 20) wired into
  CLI (was a dead flag before).
- **Overnight CSV mode** — `--scopes-file` runs each scope in sequence
  under one workdir; a failing scope never stops the sweep.
- **Binary resolution** (`loom/tools.py`) — `LOOM_TOOL_<NAME>` override →
  `~/go/bin` → PATH, with shadower validation (`-version` marker check).
- **Single event emitter** — Runner owns all events; pipeline-level
  `_emit_events` removed (was double-writing every item).

### Bugs fixed

- Per-line streaming parsers glued stdout (katana URLs concatenated in
  saved output) — regression test added.
- Nuclei `-json` flag removed in v3.11 → switched to `-j`.
- DAG cycle when adding vulnscan stage (probe declared subdomain output)
  → probe now outputs only `url`.
- ccTLD wildcard base collapse (`*.anduril.com.au` → `com.au`) → now
  keeps 3 labels for ccTLD second-level domains.
- Path-level OOS rows denying whole in-scope hosts → OOS hosts only
  denied if not already in-scope.
- Mobile app dedup across Play + App Store rows.
- `tool_runs` has no `id` column → queries use `ORDER BY rowid`.
- WAL mode SQLite read-only URI failed silently → plain connect.

### Tests

- 337/337 passing across 24 suites.
- New suites: `test_h1scope`, `test_cli_h1scope`, `test_webstatus`,
  `test_event_dedup`, `test_runner_ram`, `test_stdin`, `test_scopecsv`,
  `test_tools`, `test_cli_resume`, `test_cli_resume_multi`,
  `test_cli_multiweb`, `test_cli_status`, `test_state_scopespec`.

### Verified live

- `vulnweb.com`: 178 subs → 8 live → 3 real findings.
- `help.twilio.com` (Twilio in-scope, `drstrangexd` header): catchall →
  katana → nuclei, 341s, exit 0.
- Overnight CSV: 3-scope sweep in 8.5 minutes.

---

## v0.2.0 — 2026-08-29

Multi-host fanout, catch-all detection, per-tool output layout.

---

## v0.1.0 — 2026-08-29

Initial release. Core orchestrator (eventlog, state, catchall, scope,
ratelimit, runner, dag, pipeline, resume), CLI, benchmarks, live logger.
