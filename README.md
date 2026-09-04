# loom

**Personal bug-bounty orchestrator** — a streaming DAG scheduler that drives
the recon tools you already have.

loom takes the scanner output from tools like `subfinder`, `httpx`, `nuclei`,
`katana`, `ffuf`, and turns it into a **resumable, rate-limited, scope-aware
pipeline** with structured output and a live status page.

It is a fork of [six2dez/reconftw](https://github.com/six2dez/reconftw) — the
upstream shell scripts are kept as a reference implementation; the Python
orchestrator is the product.

---

## Why loom exists

A recon run against a 500-subdomain program takes 45–90 minutes and crashes
three times. When it crashes, you restart from zero. When it finishes, you
have a directory tree full of raw text files and no idea which host was
scanned by which tool at what time.

loom fixes that:

| Problem | loom's answer |
|---|---|
| Crash = restart from zero | **Crash-resume** — every tool invocation is bookmarked in SQLite; resume picks up exactly where it left off |
| No idea what a long run is doing | **Live status server** — `loom status-server` serves a terminal-style page with per-stage timers, status, and a live log tail |
| Scanning out-of-scope hosts | **Per-program scope profiles** — allowed/denied hosts, banned tools, mandatory headers, RPS limits, all loaded from a HackerOne scope CSV |
| Wasting nuclei on catch-all servers | **Catch-all detection** — probe `/` + random paths; exact-hash / size-delta / SPA-marker heuristics gate the expensive scan stage |
| Raw text files everywhere | **Structured output** — every tool writes 4 files (`stdout.txt`, `stderr.txt`, `cmd.txt`, `jsonl`) to a clean per-stage/per-host tree |
| No record of what happened | **JSONL event log** — every artifact (subdomain, URL, finding) is appended to a queryable event log with type, source, host, stage, evidence |
| Tools stepping on each other | **Shared rate limiter** — one token-bucket per program, distributed across threads and async coroutines |
| RAM blowup on fan-out | **20GB RAM budget** — per-tool RSS estimates, acquired before launch, released on exit |

---

## Quick start

```bash
# Install
pip install -e .

# What recon tools do I have? (non-fatal if any are missing)
loom validate

# Single-host pipelines
loom run example.com --pipeline catchall              # classify (1 stage, ~2s)
loom run example.com --pipeline subdomain             # subenum → resolve → probe → vulnscan (+ urls)
loom run example.com --pipeline web                   # catchall → katana ∥ hakrawler → scan
loom run example.com --pipeline full                  # subenum → resolve → probe ∥ urls → xss fanout ∥ scan ∥ screenshots
loom run example.com --pipeline deep                  # full + portscan, tls-SAN, uncover, permute, takeover, fuzz, params, jssecrets, asn

# Multi-host fanout (drive hundreds of subs in parallel)
loom run example.com --pipeline multiweb \
    --subdomains subs.txt \
    --max-concurrency 20 \
    --max-ram-gb 20

# Seed the fanout from a prior run's eventlog
loom run example.com --pipeline multiweb --from-eventlog 1

# HackerOne program scope (mixed asset types, eligibility flags, OO denials)
loom run api.twilio.com --h1-scope project/twilio/scope.csv --pipeline web

# Overnight multi-scope sweep from a CSV (per-scope table, non-zero exit on failure)
loom run x --scopes-file scopes.csv --workdir ~/bbdata
loom sweeps --scopes-file scopes.csv --workdir ~/bbdata   # cron-friendly wrapper

# Aggregate findings across all runs in a workdir (severity-sorted)
loom findings --workdir ~/bbdata
loom findings --workdir ~/bbdata --json

# What changed between two runs (overnight triage)
loom diff --workdir ~/bbdata --json                    # newest two runs
loom diff --workdir ~/bbdata --from 1 --to 2 --types finding,subdomain

# Wordlists (AssetNote, tech-gated fuzz — see loom/wordlists.py)
# setup once: download from https://wordlists.assetnote.io/data/*.json
# manifests into /opt/tools/wordlists/assetnote, then create the stable
# top-N slices (lists are frequency-ordered, head keeps the best):
#   head -20000 httparchive_apiroutes_* > api-routes-top20k.txt
#   head -25000 httparchive_parameters_* > params-top25k.txt
#   ... (full mapping in loom/wordlists.py docstring)
loom validate --workdir ~/bbdata   # also reports wordlist status

# Watch it live (separate terminal)
loom status-server --workdir ~/bbdata --port 8080

# Resume the most recent unfinished run
loom resume example.com

# Show per-stage status
loom status example.com

# List all runs
loom list-runs
```

---

## Pipelines

| Name | Stages | Use for |
|---|---|---|
| `catchall` | catchall | Cheap classification. Always safe. |
| `subdomain` | subenum (subfinder + assetfinder) → resolve (dnsx) → probe (httpx) → vulnscan (nuclei) | New target: enumerate, resolve, probe, scan. |
| `web` | catchall → katana → nuclei | Single-host deep scan. |
| `multi` | per-host `probe` (httpx) | Fan out across many subs from a file. |
| `multiweb` | per-host `catchall` → `probe` → `nuclei` | Fan out deep scan across many subs. |

### DAG visualization

```
subdomain:   subenum_subfinder ─┐
subenum_assetfinder ─┤
                                └→ resolve → probe → vulnscan

web:         catchall → katana → nuclei

multiweb:    catchall → probe → nuclei   (per host, N hosts in parallel)
```

---

## HackerOne scope CSV

loom parses the **real** H1 scope export format — mixed asset types,
eligibility flags, wildcards, mobile apps, and out-of-scope denials:

```csv
identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission
api.twilio.com,API,,true,true
*.sip.*.twilio.com,WILDCARD,,true,true
status.twilio.com,URL,,false,false
https://play.google.com/store/apps/details?id=com.example.app,GOOGLE_PLAY_APP_ID,,true,true
```

- `WILDCARD` → base domain → drives subdomain enumeration
- `URL` / `API` → exact host → probed/scanned directly
- `GOOGLE_PLAY_APP_ID` / `APPLE_STORE_APP_ID` → mobile apps (kept separate, web scans skip them)
- `eligible_for_bounty=false` or `eligible_for_submission=false` → **denied hosts** (loom refuses to touch them)
- Headers (`X-Bug-Bounty`, `X-HackerOne-Research`) and rate limit are baked into every request

```bash
# Use a program's scope CSV directly
loom run api.twilio.com --h1-scope project/twilio/scope.csv --pipeline web

# Override the H1 username (default: drstrangexd)
loom run api.twilio.com --h1-scope project/twilio/scope.csv --h1-username myhandle --rate-limit 20
```

---

## scopes.csv (overnight mode)

For multi-program sweeps, a simple CSV drives sequential runs:

```csv
# domain,pipeline,concurrency
vulnweb.com,subdomain,4
testasp.vulnweb.com,catchall,2
testaspnet.vulnweb.com,web,2
```

```bash
loom run x --scopes-file scopes.csv --workdir ~/bbdata
loom status-server --workdir ~/bbdata --port 8080
```

Each scope runs in sequence under the same workdir (one run row per scope in
`loom.sqlite`). A failing scope is logged and skipped — one bad target never
stops the sweep.

---

## Output layout

```
~/.local/share/loom/
├── loom.sqlite              # all runs + tool_runs tables (one DB)
├── run-1/
│   ├── events.jsonl         # every artifact, append-only
│   ├── run.log              # human-readable log (also on stdout)
│   └── outputs/
│       ├── catchall/example.com/catchall.{stdout,stderr,cmd}.txt|.jsonl
│       ├── subenum/example.com/subfinder.{stdout,stderr,cmd}.txt|.jsonl
│       ├── resolve/example.com/dnsx.{stdout,stderr,cmd}.txt|.jsonl
│       ├── probe/example.com/httpx.{stdout,stderr,cmd}.txt|.jsonl
│       └── scan/example.com/nuclei.{stdout,stderr,cmd}.txt|.jsonl
├── run-2/
│   └── ...
```

---

## Live status server

`loom status-server --workdir <dir> --port 8080` serves a minimal terminal-style
page that polls every 2 seconds:

- Per-run timer and status (running / done)
- Per-stage table: tool, stage, status (color-coded), duration
- Event counts by type
- Live log tail (last 60 lines)

No framework, no dependencies — stdlib only.

---

## Binary resolution

loom resolves tool binaries with a preference order that prevents a common
shadowing hazard:

1. `LOOM_TOOL_<NAME>` env override (e.g. `LOOM_TOOL_HTTPX=/tmp/fake/httpx`)
2. Known Go bin dirs (`~/go/bin`, `$GOPATH/bin`, `/usr/local/go/bin`)
3. `PATH`

For known shadowers (like `httpx`, where a Python package of the same name
silently shadows ProjectDiscovery's binary), the resolved binary is validated
via `-version` output. `loom validate` reports any shadowing it finds.

---

## RAM budget

`--max-ram-gb` (default 20) enforces a per-run RAM cap: the Runner reserves
each tool's estimated RSS before launch and releases it on exit, so a 20-host
fan-out of nuclei can't blow past 20GB.

---

## Requirements

- Python ≥ 3.10
- Go 1.21+ (for the recon tools)
- External tools: `subfinder`, `httpx`, `nuclei`, `katana`, `dnsx`, `naabu`,
  `ffuf`, `gau`, `waybackurls`, `assetfinder`, `amass` (any missing tool is
  non-fatal — `loom validate` reports what's available)
- Optional (used by the `full`/`deep` pipelines): `uncover`, `tlsx`,
  `dalfox`, `crlfuzz`, `kxss`, `hakrawler`, `subjack`, `alterx`,
  `gowitness` (missing optional tools are skipped or gated by the
  preflight check; gowitness needs a Chrome binary — Playwright's
  bundled chromium is auto-detected, override with LOOM_CHROME_PATH)
- Tier-2 (`deep` only): `arjun` (hidden params; lives in
  `~/.local/bin`, resolved via fallback), `gitleaks` + `jsluice`
  (JS secret/endpoint mining), `asnmap` (ASN harvest — needs a free
  PDCP_API_KEY, cleanly skipped without one)

---

## Architecture

See [`LOOM_ARCHITECTURE.md`](LOOM_ARCHITECTURE.md) for the full gap analysis,
build order, and design decisions.

---

## Verified live

loom has been tested end-to-end against real targets:

- **vulnweb.com** (Acunetix's public scanner test domain): 178 subdomains → 8
  live → 3 real findings (exposed `db.sql` — high, MySQL dump — medium,
  ASP.NET debug mode — medium)
- **help.twilio.com** (Twilio in-scope host, with `drstrangexd` header):
  catchall → katana → nuclei, full pipeline completed in 341s
- **Overnight CSV mode**: 3-scope sweep (vulnweb + testasp + testaspnet)
  completed in 8.5 minutes, 3 run rows in loom.sqlite

---

## License

MIT — see [`LICENSE`](LICENSE).

Based on [six2dez/reconftw](https://github.com/six2dez/reconftw), used under
its original license.
