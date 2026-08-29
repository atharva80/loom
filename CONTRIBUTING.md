# Contributing to loom

loom is a **personal** tool first — but contributions are welcome, especially
for: scope profiles for new programs, new stage drivers (new tools), parser
for new output formats, and catch-all detection improvements.

## Workflow

1. **Plan first.** Open an issue describing the gap and the approach.
2. **Test first.** Write the failing test before the implementation.
3. **Commit only after tests pass.** Every feature lands with: tests →
   implementation → commit.
4. **Keep the upstream alone.** Don't touch `reconftw.sh`, `modules/`,
   `lib/`, `config/` — they're six2dez's reference implementation.

## Running the suite

```bash
pip install -e ".[dev]"
.venv/bin/pytest                         # full suite
.venv/bin/pytest tests/test_runner.py -v # one file
```

All tests must pass before a commit lands. Pyright noise is ignored —
pytest is the source of truth.

## Code style

- Python 3.10+ syntax (walrus OK).
- pytest-asyncio with `asyncio_mode = "auto"` — no decorators.
- Fake-binary integration tests (shell scripts on a temp PATH) — no mocks.
- No emojis, widgets, or "AI-gen" chrome.

## Security

- **Never commit credentials.** Use `secrets.cfg.example` as a template.
- **Never hit production BB targets from automated tests.** Use
  `public-firing-range.appspot.com`.
- **Respect scope gates.** Denied hosts are denied for a legal reason.

## Commit messages

```
loom: <imperative summary>

<why + what, one paragraph if non-obvious>
```

## License

By contributing, you agree that your contributions will be licensed under
the MIT License.
