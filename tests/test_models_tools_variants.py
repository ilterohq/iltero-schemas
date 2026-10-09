from __future__ import annotations

import ast
from pathlib import Path

import iltero_schemas.models
from iltero_schemas.models.tools import variants

MODELS = Path(iltero_schemas.models.__file__).parent


def test_no_neutral_model_imports_one_tools_module() -> None:
    # A new tool joins its variants in models.tools.variants, so no neutral model changes.
    for path in MODELS.glob("*.py"):
        imported = {
            node.module
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
            if isinstance(node, ast.ImportFrom) and node.module
        }
        assert not {module for module in imported if module.startswith("iltero_schemas.models.tools.")} - {
            variants.__name__
        }, path.name
