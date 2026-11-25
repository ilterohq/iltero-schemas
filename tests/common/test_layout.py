"""Package layout rules: what an ``__init__.py`` holds, and where a change type's files live."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from tests.conftest import ROOT

PACKAGE = ROOT / "src" / "iltero_schemas"
INIT_FILES = sorted(PACKAGE.rglob("__init__.py"))
# The folder names of the change types: a file of one change type sits in its type's folder.
CHANGE_TYPE_FOLDERS = {"iac", "image"}
# The folder of a layer that holds what every change type shares.
COMMON_FOLDER = "common"
# A package of one change type, or of what they share, holds a docstring only: each name has one import path, the
# module that defines it, and importing the package starts no circular import.
CHANGE_TYPE_INIT_FILES = [path for path in INIT_FILES if path.parent.name in CHANGE_TYPE_FOLDERS | {COMMON_FOLDER}]
# Each layer split by change type, and what it may hold beside its iac/, image/ and common/ folders: models also keeps
# one module per cloud provider in providers/, and tests its fixtures and shared helpers.
SPLIT_LAYERS = {
    PACKAGE / "canonical": set(),
    PACKAGE / "change_types": set(),
    PACKAGE / "kinds": set(),
    PACKAGE / "redaction": set(),
    PACKAGE / "models": {"providers"},
    PACKAGE / "scanner_check_mappings": set(),
    PACKAGE / "scanners": set(),
    ROOT / "tests": {"baseline", "conftest.py", "exceptions.py", "records.py", "server_runs.py", "statements.py"},
}
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


def test_every_layer_split_by_change_type_is_listed() -> None:
    split = {path.parent.parent for path in INIT_FILES if path.parent.name in CHANGE_TYPE_FOLDERS}
    assert split == set(SPLIT_LAYERS) - {ROOT / "tests"}


@pytest.mark.parametrize("layer", sorted(SPLIT_LAYERS), ids=lambda p: str(p.relative_to(ROOT)))
def test_a_layer_split_by_change_type_keeps_its_shared_code_in_its_common_folder(layer: Path) -> None:
    allowed = {"__init__.py", COMMON_FOLDER, *CHANGE_TYPE_FOLDERS, *SPLIT_LAYERS[layer]}
    held = {path.name for path in layer.iterdir() if path.name != "__pycache__"}
    assert sorted(held - allowed) == []


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


# The modules that reach the network or start a program, and the ``os`` functions that start one: the package does
# neither.
NETWORK_OR_PROCESS_MODULES = {
    "aiohttp", "asyncio", "ftplib", "http", "httpx", "multiprocessing", "requests", "smtplib", "socket", "ssl",
    "subprocess", "urllib", "urllib3", "xmlrpc",
}  # fmt: skip
PROCESS_FUNCTIONS = re.compile(r"(system|popen|exec\w*|\w*spawn\w*|fork\w*)")


@pytest.mark.parametrize("path", sorted(PACKAGE.rglob("*.py")), ids=lambda p: str(p.relative_to(PACKAGE)))
def test_no_module_of_the_package_reaches_the_network_or_starts_a_program(path: Path) -> None:
    module = ast.parse(path.read_text(encoding="utf-8"))
    imported = [
        *(node.module for node in ast.walk(module) if isinstance(node, ast.ImportFrom) and node.module),
        *(alias.name for node in ast.walk(module) if isinstance(node, ast.Import) for alias in node.names),
    ]
    assert not [name for name in imported if name.split(".")[0] in NETWORK_OR_PROCESS_MODULES]
    imported_from_os = [
        alias.name
        for node in ast.walk(module)
        if isinstance(node, ast.ImportFrom) and node.module == "os"
        for alias in node.names
    ]
    assert not [name for name in imported_from_os if PROCESS_FUNCTIONS.fullmatch(name)]
    called = [
        node.attr
        for node in ast.walk(module)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "os"
    ]
    assert not [name for name in called if PROCESS_FUNCTIONS.fullmatch(name)]
    dynamic = [
        node
        for node in ast.walk(module)
        if isinstance(node, ast.Call)
        and (
            (isinstance(node.func, ast.Name) and node.func.id == "__import__")
            or (isinstance(node.func, ast.Attribute) and node.func.attr == "import_module")
        )
    ]
    assert not dynamic


# The longest path, from the package folder, of a file the package ships. Windows refuses a path longer than 260
# characters unless long paths are turned on, and an installed package sits below Python's site-packages folder in the
# user's profile, often 60 to 90 characters deep: 160 leaves 100 for it.
MAX_SHIPPED_PATH = 160
# The repository's own folders, whose files a checkout writes below its folder, and the longest path of one of their
# files from the repository folder: the package's limit and ``src/``, leaving about 35 characters for a CI checkout
# folder such as ``D:/a/<repository>/<repository>/``.
CHECKED_OUT_FOLDERS = ("src", "tests", "scripts", "docs", ".github")
MAX_CHECKED_OUT_PATH = MAX_SHIPPED_PATH + len("src/")


def test_every_file_the_package_ships_has_a_path_short_enough_for_windows() -> None:
    too_long = [
        path.relative_to(PACKAGE.parent).as_posix()
        for path in PACKAGE.rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and len(path.relative_to(PACKAGE.parent).as_posix()) > MAX_SHIPPED_PATH
    ]
    assert too_long == []


def test_every_file_of_the_repository_has_a_path_short_enough_for_a_checkout_on_windows() -> None:
    too_long = [
        path.relative_to(ROOT).as_posix()
        for folder in CHECKED_OUT_FOLDERS
        for path in (ROOT / folder).rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and len(path.relative_to(ROOT).as_posix()) > MAX_CHECKED_OUT_PATH
    ]
    assert too_long == []
