"""Package layout rules: what an ``__init__.py`` holds, and where a change type's files live."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "src" / "iltero_schemas"
INIT_FILES = sorted(PACKAGE.rglob("__init__.py"))
# The folder names of the change types: a file of one change type sits in its type's folder.
CHANGE_TYPE_FOLDERS = {"iac", "image"}
# A package of one change type holds a docstring only: each name has one import path, the module that defines it,
# and importing the package starts no circular import.
CHANGE_TYPE_INIT_FILES = [path for path in INIT_FILES if path.parent.name in CHANGE_TYPE_FOLDERS]
# Vector folders of one kind of document, such as Sigstore attestations: a file name inside them, like
# image_signature, describes the document, not a change type.
ONE_DOCUMENT_VECTOR_FOLDERS = {PACKAGE / "vectors" / "attestations"}


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


def test_there_are_change_type_packages() -> None:
    assert CHANGE_TYPE_INIT_FILES


@pytest.mark.parametrize("path", CHANGE_TYPE_INIT_FILES, ids=lambda p: str(p.relative_to(PACKAGE)))
def test_a_change_type_package_holds_its_docstring_only(path: Path) -> None:
    body = ast.parse(path.read_text(encoding="utf-8")).body
    (statement,) = body
    assert isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant), path.relative_to(PACKAGE)
    assert isinstance(statement.value.value, str), path.relative_to(PACKAGE)


def test_the_iac_tool_list_imports_nothing_from_the_package() -> None:
    # ``canonical`` reads the tool list and ``models`` reads ``canonical``, so the list must stand alone.
    module = ast.parse((PACKAGE / "models" / "iac" / "tool_names.py").read_text(encoding="utf-8"))
    imported = [
        *(node.module for node in ast.walk(module) if isinstance(node, ast.ImportFrom) and node.module),
        *(alias.name for node in ast.walk(module) if isinstance(node, ast.Import) for alias in node.names),
    ]
    assert not [name for name in imported if name.startswith("iltero_schemas")]


def _names_a_change_type(path: Path) -> bool:
    """Whether a file or folder name holds a change type's folder name as a word, as ``local_run_image_build`` does."""
    return path.name not in CHANGE_TYPE_FOLDERS and bool(CHANGE_TYPE_FOLDERS & set(re.split(r"[_.-]", path.name)))


@pytest.mark.parametrize("root", [PACKAGE, ROOT / "tests"], ids=["package", "tests"])
def test_no_file_tells_change_types_apart_by_its_name(root: Path) -> None:
    named = [
        str(path.relative_to(root))
        for path in root.rglob("*")
        if "__pycache__" not in path.parts
        and not any(path.is_relative_to(folder) for folder in ONE_DOCUMENT_VECTOR_FOLDERS)
        and _names_a_change_type(path)
    ]
    assert named == []
