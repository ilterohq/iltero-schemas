"""The credential words and shapes load with the standard library only."""

from __future__ import annotations

import ast
from pathlib import Path

from tests.conftest import ROOT

PACKAGE = ROOT / "src" / "iltero_schemas"
CREDENTIALS = PACKAGE / "redaction" / "common" / "credentials.py"
# The packages Python loads before the credentials module.
HOLDING_PACKAGES = [PACKAGE / "__init__.py", PACKAGE / "redaction" / "__init__.py", CREDENTIALS.parent / "__init__.py"]


def _imported(path: Path) -> set[str]:
    module = ast.parse(path.read_text(encoding="utf-8"))
    return {
        *(node.module for node in ast.walk(module) if isinstance(node, ast.ImportFrom) and node.module),
        *(alias.name for node in ast.walk(module) if isinstance(node, ast.Import) for alias in node.names),
    }


def test_the_credentials_module_imports_the_standard_library_only() -> None:
    assert _imported(CREDENTIALS) == {"__future__", "re"}


def test_the_packages_that_hold_the_credentials_module_import_nothing() -> None:
    assert {str(path.relative_to(PACKAGE)): _imported(path) for path in HOLDING_PACKAGES} == {
        str(path.relative_to(PACKAGE)): set() for path in HOLDING_PACKAGES
    }
