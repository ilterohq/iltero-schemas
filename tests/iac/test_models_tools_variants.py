from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

import iltero_schemas.models
from iltero_schemas.models.iac.tools import variants

MODELS = Path(iltero_schemas.models.__file__).parent
# The package of every tool's own module, beside the variants that join them.
TOOLS = Path(variants.__file__).parent


def _imported(path: Path) -> set[str]:
    """Every module ``path`` imports; a name imported from the tools package counts as its module."""
    modules: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            modules |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
            if node.module == variants.__package__:
                modules |= {f"{node.module}.{alias.name}" for alias in node.names}
    return modules


def test_no_neutral_model_imports_one_tools_module() -> None:
    # A new tool joins its variants in models.iac.tools.variants, so no neutral model changes.
    neutral = [path for path in MODELS.rglob("*.py") if not path.is_relative_to(TOOLS)]
    assert neutral
    for path in neutral:
        tools = {module for module in _imported(path) if module.startswith(f"{variants.__package__}.")}
        assert not tools - {variants.__name__}, path.relative_to(MODELS)


def test_a_tool_keyed_part_of_another_tool_than_its_document_names_is_refused() -> None:
    # Only Terraform's variants exist, so the parts here stand in for another tool's.
    variants.check_tool_data("terraform", [SimpleNamespace(tool="terraform")], "tool_data")
    with pytest.raises(ValueError, match="resource.tool_data is keyed by the tool terraform"):
        variants.check_tool_data("terraform", [SimpleNamespace(tool="pulumi")], "resource.tool_data")
