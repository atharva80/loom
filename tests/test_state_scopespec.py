"""loom.state scope_spec tests (v0.3+)."""

from pathlib import Path

import pytest

from loom.state import State


class TestScopeSpec:
    def test_start_run_stores_scope_spec(self, tmp_path: Path):
        with State(tmp_path / "s.db") as st:
            spec = '{"target": "example.com", "rate_limit_rps": 50}'
            rid = st.start_run("example.com", mode="recon",
                                scope_profile="verily", scope_spec=spec)
            run = st.get_run(rid)
            assert run["scope_spec"] == spec

    def test_start_run_scope_spec_optional(self, tmp_path: Path):
        with State(tmp_path / "s.db") as st:
            rid = st.start_run("example.com")
            run = st.get_run(rid)
            # Defaults to None when not provided
            assert run["scope_spec"] is None

    def test_migration_adds_scope_spec_to_existing_db(self, tmp_path: Path):
        # Simulate a pre-v0.3 DB: create the table WITHOUT scope_spec
        import sqlite3
        db = tmp_path / "old.db"
        con = sqlite3.connect(str(db))
        con.executescript("""
            CREATE TABLE runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                started_at REAL NOT NULL,
                finished_at REAL,
                mode TEXT,
                scope_profile TEXT
            );
            CREATE TABLE tool_runs (
                run_id INTEGER NOT NULL, host TEXT NOT NULL, tool TEXT NOT NULL,
                stage TEXT NOT NULL, status TEXT NOT NULL,
                started_at REAL, finished_at REAL, output_path TEXT, error TEXT,
                duration_s REAL,
                PRIMARY KEY (run_id, host, tool, stage)
            );
        """)
        con.execute("INSERT INTO runs(domain, started_at, mode, scope_profile) "
                    "VALUES (?, ?, ?, ?)", ("old.com", 1.0, "recon", "default"))
        con.commit()
        con.close()
        # Now open with State — should migrate
        with State(db) as st:
            cols = {r["name"] for r in st._conn.execute(
                "PRAGMA table_info(runs)"
            ).fetchall()}
            assert "scope_spec" in cols
            # The old row is still there
            runs = st.list_runs(domain="old.com")
            assert len(runs) == 1
            assert runs[0]["scope_spec"] is None
            # New run can use scope_spec
            rid2 = st.start_run("new.com", scope_spec='{"target": "x.com"}')
            run2 = st.get_run(rid2)
            assert run2["scope_spec"] == '{"target": "x.com"}'
