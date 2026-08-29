"""Tests for stdin support in Runner + the dnsx stage feeding subs via stdin."""

from __future__ import annotations

from pathlib import Path

import pytest

from loom.runner import Runner
from loom.scope import from_dict as scope_from_dict
from loom.pipeline import PipelineContext


def _scope():
    return scope_from_dict({"name": "t", "target": "example.com",
                            "rate_limit_rps": 1000})


def _make_fake(tmp_path: Path, name: str, script: str) -> Path:
    """Write an executable fake binary to tmp_path/bin/."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    p = bindir / name
    p.write_text(f"#!/bin/sh\n{script}\n")
    p.chmod(0o755)
    return p


class TestRunnerStdin:
    def test_run_passes_stdin(self, tmp_path, monkeypatch):
        """cat with stdin: `cat -` echoes the input back."""
        fake = _make_fake(
            tmp_path, "cat",
            "cat -",
        )
        monkeypatch.setenv("LOOM_TOOL_CAT", str(fake))
        runner = Runner(_scope())
        res = runner.run(
            "cat", ["cat", "-"], stage="manual", parser="raw",
            stdin="a.example.com\nb.example.com\n",
        )
        assert res.exit_code == 0
        assert "a.example.com" in res.stdout_tail
        assert "b.example.com" in res.stdout_tail

    def test_streaming_passes_stdin(self, tmp_path, monkeypatch):
        fake = _make_fake(
            tmp_path, "cat",
            "cat -",
        )
        monkeypatch.setenv("LOOM_TOOL_CAT", str(fake))
        runner = Runner(_scope())
        items = []
        res = runner.run_streaming(
            "cat", ["cat", "-"], stage="manual", parser="raw",
            on_item=items.append,
            stdin="x.example.com\n",
        )
        assert res.exit_code == 0
        assert any("x.example.com" in it.value for it in items)


class TestDnsxStageStdin:
    async def test_dnsx_stage_feeds_subs_via_stdin(self, tmp_path, monkeypatch):
        """dnsx stage must read ctx.extras['subdomains'] and pass them
        via stdin, not -d."""
        from loom.stages import make_dnsx_stage
        # fake dnsx: record the args + read stdin, echo resolved lines
        bindir = tmp_path / "bin"
        bindir.mkdir(exist_ok=True)
        fake = bindir / "dnsx"
        fake.write_text(
            "#!/bin/sh\n"
            "echo \"ARGS:$@\" >&2\n"
            "sed 's/.*/& [a] 1.2.3.4/'\n"
        )
        fake.chmod(0o755)
        monkeypatch.setenv("LOOM_TOOL_DNSX", str(fake))

        runner = Runner(_scope())
        ctx = PipelineContext(scope=runner.scope)
        ctx.extras["subdomains"] = ["a.example.com", "b.example.com"]
        stage = make_dnsx_stage()
        items = await stage(runner, "example.com", ctx)
        values = [i.value for i in items]
        assert "a.example.com" in values
        assert "b.example.com" in values
        # Resolved subs flow to downstream stages (probe)
        assert ctx.extras["resolved_subs"] == ["a.example.com", "b.example.com"]

    async def test_dnsx_stage_falls_back_to_host(self, tmp_path, monkeypatch):
        from loom.stages import make_dnsx_stage
        bindir = tmp_path / "bin"
        bindir.mkdir(exist_ok=True)
        fake = bindir / "dnsx"
        fake.write_text("#!/bin/sh\ncat -\n")
        fake.chmod(0o755)
        monkeypatch.setenv("LOOM_TOOL_DNSX", str(fake))

        runner = Runner(_scope())
        ctx = PipelineContext(scope=runner.scope)  # no extras
        stage = make_dnsx_stage()
        items = await stage(runner, "example.com", ctx)
        values = [i.value for i in items]
        assert "example.com" in values


class TestNucleiStageStdin:
    async def test_nuclei_stage_scans_extras_urls(self, tmp_path, monkeypatch):
        """nuclei stage reads ctx.extras['urls'] and feeds them via
        stdin (no -u)."""
        from loom.stages import make_nuclei_stage
        bindir = tmp_path / "bin"
        bindir.mkdir(exist_ok=True)
        fake = bindir / "nuclei"
        fake.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = \"-version\" ]; then echo 'projectdiscovery/nuclei v3.0'; exit 0; fi\n"
            "echo \"ARGS:$@\" >&2\n"
            "cat - >/dev/null\n"
            "echo '{\"template-id\": \"CVE-2024-1\", \"matched-at\": \"https://a.example.com/\", "
            "\"type\": \"http\", \"info\": {\"severity\": \"high\", \"name\": \"X\"}}'\n"
        )
        fake.chmod(0o755)
        monkeypatch.setenv("LOOM_TOOL_NUCLEI", str(fake))

        runner = Runner(_scope())
        ctx = PipelineContext(scope=runner.scope)
        ctx.extras["urls"] = ["https://a.example.com/", "https://b.example.com/"]
        stage = make_nuclei_stage()
        items = await stage(runner, "example.com", ctx)
        # The fake emits one nuclei JSON finding → parsed as a finding
        assert len(items) == 1
        assert items[0].kind == "finding"
        assert items[0].value == "https://a.example.com/"  # matched-at

    async def test_nuclei_stage_passes_tech_tags(self, tmp_path, monkeypatch):
        """When httpx fingerprinting detected tech (e.g. IIS/ASP.NET),
        the nuclei command gets -tags for the focused template set."""
        from loom.stages import make_nuclei_stage
        # Spy on the command via a fake that echoes ARGS to stderr,
        # then read the runner's captured stderr through the workdir
        # output file.
        bindir = tmp_path / "bin"
        bindir.mkdir(exist_ok=True)
        fake = bindir / "nuclei"
        fake.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = \"-version\" ]; then echo 'projectdiscovery/nuclei v3.0'; exit 0; fi\n"
            "echo \"ARGS:$@\"\n"
            "cat - >/dev/null\n"
        )
        fake.chmod(0o755)
        monkeypatch.setenv("LOOM_TOOL_NUCLEI", str(fake))

        runner = Runner(_scope(), workdir=tmp_path)
        ctx = PipelineContext(scope=runner.scope)
        ctx.extras["urls"] = ["https://a.example.com/"]
        ctx.extras["tech"] = {"microsoft asp.net", "iis:8.5"}
        stage = make_nuclei_stage()
        await stage(runner, "example.com", ctx)
        # The fake echoed its args to stdout; the nuclei parser drops
        # the non-JSON line, but the raw stdout is saved by the
        # workdir writer. Find the latest nuclei stdout file.
        import glob
        outs = sorted(glob.glob(str(tmp_path / "scan" / "*" / "nuclei*.stdout.txt")))
        assert outs, "no nuclei stdout captured"
        args = open(outs[-1]).read()
        assert "-tags" in args
        # aspnet from "microsoft asp.net" / "asp.net"; iis from "iis"
        assert "aspnet" in args
        assert "iis" in args
