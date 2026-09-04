"""Version consistency across pyproject.toml, __init__, CHANGELOG.

The repo drifted once (pyproject 0.1.0 vs CHANGELOG v0.3.0); this test
keeps them locked together.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def test_pyproject_version_matches_init():
    init = (REPO / "loom" / "__init__.py").read_text()
    m = re.search(r"__version__\s*=\s*\"([^\"]+)\"", init)
    assert m, "loom/__init__.py has no __version__"
    pyproject = (REPO / "pyproject.toml").read_text()
    m2 = re.search(r"^version\s*=\s*\"([^\"]+)\"", pyproject, re.M)
    assert m2, "pyproject.toml has no version"
    assert m.group(1) == m2.group(1), (
        f"pyproject {m2.group(1)} != __init__ {m.group(1)}"
    )


def test_changelog_documents_current_version():
    init = (REPO / "loom" / "__init__.py").read_text()
    version = re.search(r"__version__\s*=\s*\"([^\"]+)\"", init).group(1)
    changelog = (REPO / "CHANGELOG.md").read_text()
    assert f"v{version}" in changelog, (
        f"CHANGELOG.md missing a v{version} section"
    )
