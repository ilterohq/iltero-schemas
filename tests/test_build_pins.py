"""The package is built with one build backend, named the same way in both places that name it."""

from __future__ import annotations

import tomllib
from pathlib import Path

PYPROJECT = tomllib.loads((Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(encoding="utf-8"))


def test_the_locked_build_backend_is_the_one_the_build_system_names() -> None:
    """The release builds with --no-isolation from the lock, so a pin changed in one place only would be ignored."""
    (backend,) = PYPROJECT["build-system"]["requires"]
    assert backend.startswith("hatchling==")
    assert backend in PYPROJECT["dependency-groups"]["dev"]
