# Security Policy

## Reporting a security issue

If you find a vulnerability in loom itself (not in a target you're testing),
please report it privately. Do **not** open a public issue.

## Scope rules are law

loom's scope profiles exist to keep you legal. A few non-negotiable rules:

- **Denied hosts are blocked at two layers** — the CLI gate (before any
  stage) and the runner's per-tool check. Bypassing either is a bug, not a
  feature.
- **Rate limits are per-program, not per-tool.** One budget, shared across
  all concurrent coroutines. Raising the limit to "go faster" risks a ban —
  don't.
- **The live status server binds to `127.0.0.1` only.** Don't expose it to a
  network.
- **No credentials in the repo.** `secrets.cfg.example` is the template.

## Testing targets

Use **only** explicitly-authorized targets for live testing:

- `public-firing-range.appspot.com` (Google's public test app)
- `vulnweb.com` and its subdomains (Acunetix's public scanner test targets)

Do not hit production bug-bounty targets from automated tests or CI.

## Responsible disclosure

If you find a vulnerability in a bug-bounty target while using loom, report it
through the program's official channel. loom is a tool — what you do with it
is your responsibility.
