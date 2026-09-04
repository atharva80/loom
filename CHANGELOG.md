# Changelog

## v0.6.0 — 2026-09-05

Tier-2 pass: hidden-parameter discovery, JS secret mining, ASN
harvest. Same rule as v0.5: raw pools append-only, stages only shape
tool inputs; discovered artifacts flow back into the pools so no
finding class is ever orphaned.

### New features

- **Arjun hidden-param discovery** (`params` node, `deep` only — it's
  request-heavy): normalized paramless reps → `arjun -u -oT -t 10`,
  discoveries join `urls_params` (which dalfox/kxss read first) AND
  `urls`. Runs a level before the xss/scan fanout so dalfox and
  nuclei consume its output same-run. `~/.local/bin` added to binary
  fallback dirs (pipx/pip-user tools live there).
- **JS secret mining** (`jssecrets` node, `deep`): downloads crawled
  `.js` (stdlib, 30-file/1MB caps) → gitleaks (`high` findings) +
  jsluice `urls` (endpoints resolved against their file's origin back
  into the pools — per-file invocations so relative URLs never
  orphan) + jsluice `secrets` (tool severity kept, default medium).
- **ASN harvest** (`asn` node, `deep`): `asnmap -d -silent -json`,
  RECORD-ONLY — CIDRs are never auto-fed to portscan (scanning
  unauthorized netblocks would exceed scope). Key-gated: clean skip
  with no PDCP key (no invocation, no failure).
- **`loom validate`** covers arjun/gitleaks/jsluice/asnmap.

### Decisions (stated, not silent)

- **rustscan skipped**: no cargo on the box, GitHub API unreachable
  for release binaries — and naabu `-top-ports full` already covers
  the full-range capability with zero new deps.
- **sqlmap not wired**: slow/noisy by default; XSS/CRLF fanout +
  nuclei cover the injection surface. Revisit as an opt-in node.

## v0.5.0 — 2026-09-05

Tier-1 optimization pass: same coverage in a fraction of the requests,
plus per-host fanout and screenshots. Guiding rule: raw pools are
append-only — normalization only shapes *tool inputs*, nothing is
ever dropped from storage, events, or attribution maps.

### New features

- **URL normalization** (`normalize_urls`, `scan_pool`) — collapse key
  `(host, path, param-names)`: param-value variants, pagination, and
  http/https dupes become one representative (https > has-query >
  shortest, deterministic). 15k gau URLs → hundreds of targets.
  `url_variants` map kept in extras for finding attribution.
- **Per-host fanout** — ffuf, naabu, and gowitness now iterate every
  known live host (root first, busiest next), each with its own
  invocation, output dir, and events. Previously only the pipeline
  root was fuzzed/scanned (live-verified hole on vulnweb).
- **gowitness screenshots** — new `screenshot` stage
  (`scan file -f`, Playwright-chromium auto-detected via
  `_chrome_path()`, `LOOM_CHROME_PATH` override), wired into
  `full`/`deep`/`web`. Shots persist under `screenshots/<host>/`.
- **Archive-URL mining moved earlier** — gau/waybackurls need only the
  domain, so they run alongside resolve/probe instead of after probe
  (~60s off the critical path). XSS nodes now also wait for probe so
  probe-discovered URLs are never missed.
- **stdin persisted** — every invocation's stdin lands in the
  `.cmd.txt` meta. Full reproducibility of inputs, not just outputs.
- **Real subjack parser** — `[+]` lines become `takeover` items in the
  eventlog/jsonl (stage return values alone never reach the eventlog,
  which had made takeovers invisible to `loom findings`).

### Bugs fixed

- **ffuf `-s -json` combo** — `-s` silently suppresses JSON output
  (plain matched words instead), which zeroed EVERY ffuf finding.
  Now `-json -noninteractive` (both verified live).
- **ffuf b64 inputs** — `input.FUZZ` values are base64-encoded;
  decoded for evidence.
- **Output filename collision** — `{tool}.{ts}` + `with_suffix()`
  replaced the timestamp, so re-runs overwrote prior outputs.
  Filenames are now explicit (`tool.<ts>.stdout.txt`, ...).
- **naabu/ffuf rooted at pipeline root only** — see per-host fanout.
- **Chrome Safe Browsing vs vuln targets** (environmental, documented):
  Chrome refuses flagged hosts (`ERR_BLOCKED_BY_CLIENT` on testasp);
  gowitness exposes no override — those hosts yield no shots on any
  Chrome-based tool.

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
- **naabu flags** — naabu has no `-ports` flag and `top-100` is not a
  valid `-p` value (live-verified exit 2). Now `-top-ports 100`.
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
