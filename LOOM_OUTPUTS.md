# LOOM_OUTPUTS — machine-readable output contract (v0.8)

This file is the contract for AGENTS and scripts consuming loom
output. Human tables may change; the JSON shapes below are stable.
Every read command (`status`, `list-runs`, `findings`, `validate`,
`diff`) accepts `--json` and prints exactly one JSON document to
stdout (exit codes below). Diagnostics go to stderr.

## Layout

```
<workdir>/loom.sqlite                  # state DB (WAL mode)
<workdir>/run-<id>/events.jsonl        # append-only event log
<workdir>/run-<id>/manifest.json       # self-describing run file
<workdir>/run-<id>/run.log             # human log tail
<workdir>/run-<id>/outputs/<stage>/<host>/<tool>.<ts_ms>.{stdout,stderr,cmd}.txt|<tool>.<ts_ms>.jsonl
<workdir>/run-<id>/inputs/<host>/      # generated inputs (targets, wordlists)
<workdir>/run-<id>/screenshots/<host>/ # gowitness shots
```

Crash-safety: `events.jsonl` is opened+closed per append (SIGKILL-safe);
`<tool>.<ts_ms>` filenames never collide across re-runs; every
invocation's argv AND stdin are persisted in `.cmd.txt` (`meta.stdin`
is null when no stdin was passed).

## events.jsonl

One object per line: `{type, source, host, value, ts, evidence, stage?}`.
`type` is the artifact kind (below). `evidence` is always present
(`{}` when the writer has nothing to add); `stage` only on
stage-backed writes. Malformed lines are skipped by
readers — never assume line count == event count.

### Artifact kinds

| kind | value | key evidence fields |
|---|---|---|
| `subdomain` | `a.example.com` | `source` (subfinder/assetfinder/...) |
| `host` | probed hostname | `url`, `status_code`, `title`, `tech[]` |
| `url` | full URL | `source`, `method`, `params` |
| `port` | `host:port` | `source: naabu` |
| `finding` | matched URL / `file:line` | `source`, `vuln`, `severity`, `rule`/`template_id` |
| `takeover` | subjack `[+]` line | `source: subjack`, `target` |
| `san` | cert SAN entry | `source: tlsx` |
| `asn` | `AS15169` | `input`, `as_name` |
| `cidr` | `8.8.8.0/24` | `input`, `asn` |
| `screenshot` | shot file path | `source: gowitness`, `host` |
| `catchall_result` | `clean`/`catchall`/`error` | `confidence`, `scheme` (`https`/`http`), probe `root_*`/`rand1_*`/`rand2_*` |
| `raw` | unparsed tool output | tool-dependent |

### Severity vocabulary (findings)

`critical > high > medium > low > info`. Sources without native
severity map explicitly: gitleaks → `high`, jsluice → tool value or
`medium`, ffuf content-discovery → none (no severity key), takeover →
`high`.

### Run status vocabulary

- `tool_runs.status`: `pending|running|done|failed|skipped|timeout`
- run-level: `list-runs`/manifest use `done|inflight`;
  `run_summary` (and `status --json`) use `finished|running`.
  (Historical inconsistency, kept for back-compat — treat
  done==finished, inflight==running.)

## manifest.json

`build_manifest(workdir, run_id)` — pure read of state DB + eventlog,
no subprocesses. Keys: `loom_version`, `run{id,domain,pipeline,mode,
scope_profile,status,started_at,finished_at,duration_s}`,
`stages[{host,tool,stage,status,duration_s,error,output_path}]`,
`events{type: count}`, `summary` (== `run_summary`), `resolved_tools`
(`{tool: path|null}`). Written automatically at the end of `run`,
`resume`, and every `sweeps` scope. `write_manifest` never raises.
`loom/manifest.schema.json` (Draft 2020-12, shipped as package data)
validates the shape — see `validate_manifest()`.

## Exit codes

- `0` success (validate: all expected tools present; wordlists are
  advisory and never fail the check).
- `1` usage/data errors (unknown domain run, no runs, no findings).
- `2` preflight refusal (denied/out-of-scope target, missing REQUIRED
  tools for the pipeline) or crashed pipeline.

## findings dedup key

`(value, source)`. The `runs: [ids]` list in each row's evidence shows
every run that observed it.
