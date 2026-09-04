"""Contract tests: the machine-readable vocabularies LOOM_OUTPUTS.md promises.

Agents parse loom output sight-unseen. These tests pin the exact value
sets so a code change that adds/removes/renames a machine-read token
fails loudly instead of silently breaking downstream parsers.

Mirrors LOOM_OUTPUTS.md — update both together.
"""

from __future__ import annotations

import json

from loom.catchall import detect
from loom.cli import build_parser
from loom.eventlog import EventLog

# LOOM_OUTPUTS.md §Artifact kinds: catchall_result value vocabulary.
CATCHALL_VOCAB = {"clean", "catchall", "error"}

# LOOM_OUTPUTS.md §events.jsonl: every line carries exactly these keys.
EVENT_KEYS = {"type", "source", "host", "value", "ts", "evidence"}

# LOOM_OUTPUTS.md: every read command accepts --json.
JSON_COMMANDS = {"status", "list-runs", "validate", "findings", "diff"}

# LOOM_OUTPUTS.md §Artifact kinds: catchall evidence always carries these.
CATCHALL_EVIDENCE_KEYS = {
    "scheme",
    "root_status", "root_size", "root_hash",
    "rand1_status", "rand1_size", "rand1_hash",
    "rand2_status", "rand2_size", "rand2_hash",
}


def _json_commands() -> set[str]:
    parser = build_parser()
    found = set()
    for action in parser._subparsers._group_actions:
        for name, sub in action.choices.items():
            opt_names = {a.dest for a in sub._actions}
            if "json" in opt_names:
                found.add(name)
    return found


class TestContract:
    def test_json_command_set_matches_doc(self):
        assert _json_commands() == JSON_COMMANDS

    def test_event_line_shape(self, tmp_path):
        el = EventLog(tmp_path / "events.jsonl")
        el.append(type="subdomain", source="subfinder", host="example.com",
                  value="a.example.com")
        line = (tmp_path / "events.jsonl").read_text().strip().splitlines()[0]
        assert set(json.loads(line)) == EVENT_KEYS

    def test_catchall_vocab_clean(self, real_app_server):
        r = detect(real_app_server, https=False, timeout=3)
        assert r["classification"] in CATCHALL_VOCAB
        assert CATCHALL_EVIDENCE_KEYS <= set(r["evidence"])

    def test_catchall_vocab_catchall(self, catchall_server):
        r = detect(catchall_server, https=False, timeout=3)
        assert r["classification"] in CATCHALL_VOCAB
        assert CATCHALL_EVIDENCE_KEYS <= set(r["evidence"])

    def test_catchall_vocab_error(self):
        import socket

        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        r = detect(f"127.0.0.1:{port}", https=False, timeout=2)
        assert r["classification"] in CATCHALL_VOCAB
        assert CATCHALL_EVIDENCE_KEYS <= set(r["evidence"])
