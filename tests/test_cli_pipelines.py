"""Tests for the v0.4 pipeline extensions.

New pipelines:
  - full    : subenum → resolve → probe → [urls → xss] fan-out → scan
  - deep    : full + portscan + permute + tls + uncover + subjack + fuzz
New stages woven into existing pipelines:
  - subdomain: += urls (waybackurls + gau)
  - web     : nuclei also consumes urls (xss stage feeds nothing itself —
              xss results are findings)
All fake-binary, no network (targets are deliberately unresolvable .invalid
hosts; tool binaries are fakes that emit canned output).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from loom import cli


@pytest.fixture
def home_in_tmp(monkeypatch, tmp_path):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    return tmp_path


class TestFullPipelineCLI:
    def test_full_appears_in_choices(self, capsys):
        with pytest.raises(SystemExit) as exc:
            cli.main(["run", "--help"])
        out = capsys.readouterr().out
        for name in ("full", "deep"):
            assert name in out

    def test_full_pipeline_builds(self):
        """The full pipeline DAG is valid: topological order resolves,
        all nodes have stages registered."""
        from loom.dag import DAG
        from loom.live import LiveLogger

        dag, stages = cli._build_pipeline("full", LiveLogger(Path("/tmp")), None, None)
        dag.validate()
        assert set(stages) == set(dag.ids())
        # subenum → resolve → probe precede xss/scan
        order = [nid for lvl in dag.levels() for nid in lvl]
        idx = {n: i for i, n in enumerate(order)}
        for later in ("xss", "xss_kxss", "scan", "urls", "urls_gau"):
            if later in idx:
                assert idx[later] > idx["probe"]

    def test_deep_pipeline_builds(self):
        from loom.live import LiveLogger

        dag, stages = cli._build_pipeline("deep", LiveLogger(Path("/tmp")), None, None)
        dag.validate()
        assert set(stages) == set(dag.ids())
        # deep includes infra stages the full pipeline lacks
        for node in ("portscan", "permute", "tls", "subenum_uncover",
                     "takeover", "fuzz"):
            assert node in stages

    def test_missing_required_tool_exits_2(self, home_in_tmp, tmp_path, capsys,
                                           monkeypatch):
        """full pipeline needs subfinder/httpx/dnsx; with no resolvable
        binaries the run must refuse cleanly (pre-flight) instead of
        failing mid-DAG with exit-127s."""
        import shutil as _shutil
        from loom import tools as loom_tools
        monkeypatch.setattr(loom_tools, "GO_BIN_DIRS", ())
        monkeypatch.setattr(_shutil, "which", lambda name, path=None: None)
        loom_tools._validate_cache.clear()
        with pytest.raises(SystemExit) as exc:
            cli.main(["--workdir", str(tmp_path), "run", "example.com",
                      "--pipeline", "full"])
        assert exc.value.code == 2
        out = capsys.readouterr().err
        assert "missing required tools" in out
        loom_tools._validate_cache.clear()


class TestStageWeaving:
    def test_subdomain_pipeline_has_urls(self):
        from loom.live import LiveLogger

        dag, stages = cli._build_pipeline("subdomain", LiveLogger(Path("/tmp")), None, None)
        assert "urls" in stages
        assert "urls_gau" in stages

    def test_web_pipeline_scans_urls(self):
        from loom.live import LiveLogger

        dag, stages = cli._build_pipeline("web", LiveLogger(Path("/tmp")), None, None)
        # nuclei node consumes url stream from katana
        node = dag.get("nuclei")
        assert "url" in node.inputs


class TestUrlScheduling:
    """v0.5: archive-URL mining (gau/waybackurls) needs only the domain,
    so it runs alongside resolve/probe instead of after probe (~60s off
    the critical path on vulnweb). XSS nodes wait for probe too, so
    probe-discovered URLs are never missed."""

    def _levels(self, name):
        from loom.live import LiveLogger

        dag, stages = cli._build_pipeline(name, LiveLogger(Path("/tmp")), None, None)
        dag.validate()
        assert set(stages) == set(dag.ids())
        lvls = dag.levels()
        idx = {nid: i for i, lvl in enumerate(lvls) for nid in lvl}
        return dag, idx

    def test_urls_run_with_probe_not_after(self):
        for name in ("full", "deep", "subdomain"):
            _, idx = self._levels(name)
            assert idx["urls"] <= idx["probe"], name
            assert idx["urls_gau"] <= idx["probe"], name

    def test_xss_waits_for_probe(self):
        for name in ("full", "deep"):
            dag, idx = self._levels(name)
            for xss in ("xss", "xss_kxss", "xss_crlfuzz"):
                assert "probe" in dag.get(xss).depends_on, (name, xss)
                assert idx[xss] > idx["probe"], (name, xss)

    def test_screenshot_wired(self):
        from loom.live import LiveLogger

        for name in ("full", "deep", "web"):
            dag, stages = cli._build_pipeline(
                name, LiveLogger(Path("/tmp")), None, None)
            assert "screenshot" in stages, name
            assert "screenshot" in dag.ids(), name
