# Changelog

## v0.8.10 — 2026-09-05

status-server honors the global --workdir (same footgun as sweeps).

- **The gap**: `status-server --workdir` was required, so the global
  was silently ignored and the server either died (argparse) or
  watched the wrong dir. Never caught — zero tests touched it.
- **The fix**: SUPPRESS + global fallback, both orders tested.
- **Proof**: new `TestStatusServerWorkdir` (both orders); live serve
  + `/api/status` returns real runs/stages/log-tail for the requested
  workdir (page polls it every 2s).

## v0.8.9 — 2026-09-05

`run --scopes-file` no longer demands a positional domain.

- **The gap**: the multi-scope mode required `domain` positionally,
  so `run --scopes-file scopes.csv` died in argparse. Bare `run`
  still exits 2 with a clear error (exit-code contract unchanged).
- **Proof**: `TestRunScopesFile` (file-only invocation runs both
  scopes; bare run → 2); live 2-scope `run --scopes-file` verified,
  plus `status --json` read back mid-sweep.

## v0.8.8 — 2026-09-05

Sweeps --timeout: one hung scope no longer stalls the night.

- **The gap**: the sweeps docstring promised per-scope wall-clock
  timeouts; none existed — a hung scope (tarpit burning every tool
  budget) blocked all remaining scopes.
- **The fix**: `sweeps --timeout SECONDS` (default 0 = off) runs each
  scope in a daemon thread; on expiry the sweep advances with rc=124
  (GNU timeout convention) and the orphan may still finish its rows
  late on its own State connection. Non-zero scope count still drives
  the exit code for cron.
- **Proof**: `TestSweepsTimeout` — faked 30s hang + `--timeout 1`:
  both scopes attempted in ~1s, second completes, rc=1, "124" logged.

## v0.8.7 — 2026-09-05

Overnight path repaired: sweeps ran zero scopes + wrong workdir.

- **The incident** (first sweeps live-fire under v0.8): both scopes
  crashed instantly (`AttributeError: scope`, rc=2) — `cmd_sweeps`
  clones its argv for `_run_one` but the sweeps parser lacks
  run-only flags. Worse, the crash hid a second bug: the sweeps-level
  `--workdir` default clobbered the global, so the run silently
  landed in `~/.local/share/loom` (7 stray runs; removed, user's
  run-1 untouched).
- **The fixes**: child namespace filled with run-parser defaults
  (`scope/mode/subdomains/from_eventlog`); sweeps `--workdir` is now
  `argparse.SUPPRESS` with a fallback, so global order works and
  subcommand-level still overrides.
- **Proof**: strict child-namespace + workdir-precedence tests (the
  old table-output test passed on crashed rows — loose asserts kept);
  live 2-scope sweep verified landing in the requested workdir.

## v0.8.6 — 2026-09-05

Vulnscan gate widened (third and last probe-only gate).

- **The audit**: the `subdomain` pipeline's `vulnscan` node is
  `make_nuclei_stage` (consumes scan_pool) behind a probe-only gate
  — the same hole as scan (v0.8.4) and fuzz (v0.8.5). Gate is now
  the url pool; `depends_on` extended to `urls`/`urls_gau`.
- Gate map (all active nodes now match what their stage consumes):
  scan/fuzz/xss/vulnscan/params/jssecrets on the pool (fuzz also on
  resolve subs), takeover/asn/resolve on subs, screenshot on live
  probe, subenum stages unconditional.
- **Proof**: `TestVulnscanGate` in `tests/test_scan_pool_gate.py`.

## v0.8.5 — 2026-09-05

Fuzz gate widened to known hosts (same hole as scan).

- **The audit**: `fuzz` (ffuf) gated only on probe urls, but the
  stage fuzzes `_live_hosts(ctx)` ← passive urls + resolved subs +
  root. Probe-only gating would skip it on exactly the degraded
  runs where directory fuzzing still has targets.
- **The fix** (deep pipeline): gate is now the url pool OR resolved
  subdomains; `depends_on` extended to `urls`/`urls_gau` so the gate
  reads settled counts. `screenshot` remains the only probe-gated
  node, deliberately (chrome launches need live targets).
- **Proof** (`tests/test_fuzz_gate.py`): predicate units
  (passive-only / resolve-only / probe-only → run, empty → skip)
  plus end-to-end with the real predicate in a live Pipeline.

## v0.8.4 — 2026-09-05

Scan gate widened to the URL pool (nuclei no longer sits out).

- **The incident** (deep-sweep findings audit): all 85 findings were
  gitleaks-on-JS-mirror; nuclei ran zero times. `scan`/`screenshot`
  gated only on probe urls, but probe yielded 0 (tarpitted apex)
  while wayback/gau held 15,161 urls — the flagship scanner skipped
  the entire run although its stage consumes exactly that pool
  (`scan_pool ← extras["urls"]`, fed by probe+urls+urls_gau).
- **The fix**: `scan` predicate in `full` + `deep` is now the pool
  gate `(urls+urls_gau+probe) > 0`, identical to the xss nodes.
  `screenshot` stays probe-gated (needs live hosts; dead wayback
  urls would just burn chrome launches).
- **Proof** (`tests/test_scan_pool_gate.py`): predicate unit tests
  for both pipelines (passive-only → run, probe-only → run, empty →
  skip) plus an end-to-end mini-pipeline running the REAL deep scan
  predicate — passive urls flow, probe empty, scan executes done.

## v0.8.3 — 2026-09-05

Timeouts kill the whole process tree (group-kill).

- **The incident** (deep sweep triage): dalfox's 600s timeout escaped
  as a traceback-carrying stage failure — and measurement showed why
  timeouts hurt twice: grandchildren (dalfox→chrome, `sh`→`sleep`)
  inherit the stdout/stderr pipes, so post-kill `communicate()` /
  stderr-drain blocks until THEY exit. A 1s timeout took 47s; orphans
  then ate RAM through the rest of the sweep.
- **The fix** (`loom/runner.py`): both spawns use
  `start_new_session=True`; both timeout paths call the new
  `_kill_tree()` (killpg SIGKILL + fallback kill). uncover-without-keys
  triaged as correctly-handled (fast fail, structured error naming the
  missing keys — no change).
- **Proof** (`tests/test_proctree.py`): streaming timeouts return a
  timed-out `RunResult` (never raise); `run()` + `run_streaming()`
  with `sleep N & wait` grandchildren finish in ~1s with zero
  survivors (`pgrep` clean). Suite timeout tests: 105s → 2.6s.

## v0.8.2 — 2026-09-05

Contract-doc accuracy: LOOM_OUTPUTS.md now matches behavior, enforced by tests.

- **Removed phantom `soft` classification** from `catchall.py` docstrings —
  the code only emits `clean|catchall|error`; agents will never see `soft`.
- **`evidence: {}` guaranteed** (`EventLog.append` defaults it) so agents
  can index `evidence` unconditionally; doc says so explicitly.
- **New `tests/test_contract.py`**: pins the `--json` command set, the
  event-line key shape, and the catchall value/evidence vocabularies
  against LOOM_OUTPUTS.md — doc and code must change together.
- Shared catchall HTTP fixtures moved to `tests/conftest.py`.
- Doc now lists `diff` under `--json`, the exact `catchall_result`
  vocabulary + `scheme` key, and the manifest schema file.
- 494/494 green.

## v0.8.1 — 2026-09-05

Catchall accuracy: HTTPS→HTTP fallback + off-loop probing.

- **The bug** (found live via the v0.8.0 verification run):
  `detect(host, https=True)` probed TLS only and declared `"error"`
  conf=1.0 when there was no TLS listener — even for hosts serving
  HTTP perfectly well. Every HTTP-only target was misreported as dead
  in manifests, summaries, and agent-facing events.
- **The fix** (`loom/catchall.py`): `https=True` now means "prefer
  TLS, fall back to plaintext" — the full 3-probe set is retried over
  http when the TLS root probe fails. `"error"` requires every tried
  scheme to fail at `/`. Thresholds unchanged; the working scheme is
  recorded in `evidence["scheme"]`.
- **Off the event loop** (`loom/cli.py`): the stage wrapper now runs
  `detect()` in `asyncio.to_thread` — 3×15s of blocking urllib no
  longer holds the loop (the v0.8 async rule, applied to the one
  caller that bypasses the Runner).
- **Proof**: 4 new `test_catchall.py` tests (local HTTP-only servers
  classify clean/catchall via fallback, dead ports still `error`);
  live `testasp.vulnweb.com`: old `error`/1.0 → new `clean`/0.95 over
  `scheme=http`.

## v0.8.0 — 2026-09-05

True-async runner: `Runner.run()` / `run_streaming()` are now coroutines
backed by `asyncio` subprocesses. One long stage no longer starves its
entire DAG level.

- **The incident**: the deep-pipeline live run on vulnweb.com sat for
  minutes with zero state rows, zero outputs, zero events while
  amass-brute (15 min) ran — its level-mates (subfinder, assetfinder,
  uncover) never started. Blocking `subprocess.run`/`Popen` held the
  event-loop thread; `asyncio.gather` across a level only yields at
  `await` points, and there were none during a 15-minute wait.
- **The fix**: `asyncio.create_subprocess_exec` + `wait_for` timeouts +
  async readline loop in both methods. stdin is fed from a background
  task (the old write-everything-first order deadlocks past the 64K
  pipe buffers when input and output are both large).
- **Behavior changes** (both stricter-or-better, covered by tests):
  `run_streaming` timeouts now return a proper timed-out `RunResult`
  (state marked `timeout`, outputs written) instead of raising
  `TimeoutExpired` out of the stage; all ~30 `stages.py` call sites
  and every test now `await`s.
- **Regression proof** (`tests/test_concurrency.py`): two `sleep 2`
  stages behind `max_concurrency=2` finish in ~2s, not ~4s — for both
  `run()` and `run_streaming()`.
- **`loom diff <from> <to>`** (`--json`, `--types`): run-over-run delta
  for overnight triage — new/lost subdomains, urls, hosts, findings,
  takeovers, sourced from workdir artifacts + findings report.

## v0.7.1 — 2026-09-05

Contract enforcement: the manifest schema ships in-repo and the
exit-code contract is pinned by tests.

- **`loom/manifest.schema.json`** (Draft 2020-12, shipped as package
  data) + `validate_manifest()` — agents can validate before parsing.
- **Exit-code contract tests** (`tests/test_exit_codes.py`): every
  documented 0/1/2 path pinned.
- **amass brute verdict**: 20k-word brute emits real subs within the
  node budget (`rest/testasp/testaspnet/testphp/www` in the first 75
  output lines) — the top-20k slice ordering is confirmed productive.
- 478/478 passing.

## v0.7.0 — 2026-09-05

Agent-grade outputs: every read command speaks JSON, every run leaves
a manifest, and the output contract is written down.

### New features

- **run manifest** (`loom/manifest.py`): `run-<id>/manifest.json`
  with identity, timing, per-stage outcomes, event counts, the run
  summary, loom version, and resolved tool paths. Built purely from
  state DB + eventlog (no subprocesses, never raises). Written
  automatically by `run`, `resume` (both paths), and every `sweeps`
  scope.
- **`--json` everywhere**: `status`, `list-runs`, `validate` join
  `findings`. One JSON document on stdout, diagnostics on stderr.
- **`LOOM_OUTPUTS.md`**: the machine-readable contract — layout,
  crash-safety notes, all 12 artifact kinds with evidence fields,
  severity + status vocabularies (including the documented
  done/finished legacy split), manifest schema, exit codes, dedup key.

### Robustness notes

- EventLog's open-write-close per append is SIGKILL-safe by
  construction (verified by reading, not changed).
- Resume's skip gate keys on pipeline-level `(host, node, node)`
  marks — covered by a hermetic offline test (seed → resume →
  manifest, zero network, 0.78s).

## v0.6.1 — 2026-09-05

AssetNote wordlists: tech-gated fuzzing, arjun params, amass brute.

### New features

- **Wordlist layer** (`loom/wordlists.py`, outside the repo at
  `/opt/tools/wordlists/assetnote`, `LOOM_WORDLISTS` override):
  22 stable files (api-routes/params/php/aspx/js top-N slices +
  per-tech lists + best-dns), decoupled from AssetNote date stamps.
- **Tech-gated ffuf** — httpx fingerprints pick the wordlist
  (IIS/ASP.NET → aspx-top10k, php → php-top15k, ...), unknown tech →
  api-routes-top20k, no dir → SecLists common → built-in mini.
  Fallback chain never breaks; selection deterministic.
- **Arjun `-w`** params-top25k (matches arjun's default 25.9k cost,
  higher quality).
- **amass brute node** (`subenum_amass`, `deep`): `-brute -w
  best-dns-top20k` (frequency-ordered head of the 9.5M list) after
  passive searches, 900s budget, shares into the pool (amass
  previously never shared). Full 9.5M stays on disk for opt-in.
- **`loom validate`** reports wordlist status (advisory, never fails).

### Verification notes

- amass brute smoke-verified live (flags + wordlist accepted; full
  yield needs the node time budget — amass scaffolds recon before
  first brute hits, partial stdout still parses on timeout).
- ffuf tech gating verified against the real dir; api-routes entries
  carry leading slashes (servers normalize `//` — verified live).

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
