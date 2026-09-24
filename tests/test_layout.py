"""Package layout rules: an ``__init__.py`` only re-exports; the code lives in named modules."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parent.parent / "src" / "iltero_schemas"
INIT_FILES = sorted(PACKAGE.rglob("__init__.py"))


@pytest.mark.parametrize("path", INIT_FILES, ids=lambda p: str(p.relative_to(PACKAGE)))
def test_init_files_carry_no_logic(path: Path) -> None:
    module = ast.parse(path.read_text(encoding="utf-8"))
    for index, node in enumerate(module.body):
        if index == 0 and isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            continue  # the docstring
        if isinstance(node, ast.ImportFrom):
            continue
        if isinstance(node, ast.Assign) and [t.id for t in node.targets if isinstance(t, ast.Name)] == ["__all__"]:
            continue
        pytest.fail(f"{path.relative_to(PACKAGE)}:{node.lineno}: only imports and __all__ belong in __init__.py")
