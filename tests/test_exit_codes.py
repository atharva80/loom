"""Exit-code contract (LOOM_OUTPUTS.md): agents branch on exit codes,
so every documented code is pinned by a test.

  0 — success (validate: tools all present)
  1 — usage/data errors
  2 — preflight refusal / argparse misuse / crashed pipeline
"""

from __future__ import annotations

import pytest

from loom import cli


class TestExitCodes:
    def test_status_missing_workdir_is_1(self, tmp_path, capsys):
        code = cli.main(["--workdir", str(tmp_path / "nope"),
                         "status", "example.com"])
        assert code == 1

    def test_status_unknown_domain_is_1(self, tmp_path, capsys):
        from loom.state import State
        State(tmp_path / "loom.sqlite").close()
        code = cli.main(["--workdir", str(tmp_path),
                         "status", "missing.com"])
        assert code == 1

    def test_resume_missing_workdir_is_1(self, tmp_path, capsys):
        code = cli.main(["--workdir", str(tmp_path / "nope"),
                         "resume", "example.com"])
        assert code == 1

    def test_list_runs_no_db_is_0_with_marker(self, tmp_path, capsys):
        code = cli.main(["--workdir", str(tmp_path), "list-runs"])
        assert code == 0
        assert "no runs yet" in capsys.readouterr().out

    def test_unknown_pipeline_is_2(self, capsys):
        with pytest.raises(SystemExit) as exc:
            cli.main(["run", "example.com", "--pipeline", "nope"])
        assert exc.value.code == 2

    def test_findings_no_runs_is_1(self, tmp_path, capsys):
        wd = tmp_path / "empty"
        wd.mkdir()
        code = cli.main(["--workdir", str(wd), "findings"])
        assert code == 1
