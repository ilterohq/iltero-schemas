"""The files the conformance vectors' records and cases kept, by the path each record's register names them by.

A record that keeps files beside it, such as its evaluation inputs and the copy of the exceptions the server served, is
read with them. The vectors hold those files in one JSON file per record, ``kept_files/<change type>/<record>.json``,
and one per case that keeps files of its own, ``kept_files/<change type>/cases/<case name without its change type>
.json``. Each maps the path the record's register names a file by to its bytes: as text when they are UTF-8, as base64
otherwise. A consumer writes each file at its path beside the record before it reads the record. One file per record
keeps every shipped path short enough for every platform.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Any

from iltero_schemas.vectors.paths import VECTORS

KEPT_FILES = "kept_files"
# The folder of a change type's kept files that holds those of its cases.
CASE_FOLDER = "cases"


def _bytes(where: str, path: str, entry: Any) -> bytes:
    parts = PurePosixPath(path).parts
    if not path or "\\" in path or path.startswith("/") or ".." in parts:
        raise ValueError(f"{where}: {path!r} is not a relative path inside the record's folder")
    if not isinstance(entry, dict) or len(entry) != 1 or not isinstance(next(iter(entry.values())), str):
        raise ValueError(f"{where}: {path} holds exactly one of text or base64")
    if "text" in entry:
        return str(entry["text"]).encode("utf-8")
    if "base64" not in entry:
        raise ValueError(f"{where}: {path} holds exactly one of text or base64")
    try:
        return base64.b64decode(entry["base64"], validate=True)
    except binascii.Error as error:
        raise ValueError(f"{where}: {path} is not base64") from error


def _read(*parts: str) -> Mapping[str, bytes]:
    where = "/".join((KEPT_FILES, *parts))
    path = VECTORS.joinpath(KEPT_FILES, *parts)
    if not path.is_file():
        return MappingProxyType({})
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or set(document) != {"files"} or not isinstance(document["files"], dict):
        raise ValueError(f"{where} holds only its files")
    return MappingProxyType({name: _bytes(where, name, entry) for name, entry in document["files"].items()})


def kept_files_of(vector: str) -> Mapping[str, bytes]:
    """The files the record ``vector`` (``iac/local_run``, or ``iac/local_run.json``) kept, by the path its register
    names each by; empty for a record the vectors hold no kept files of. ``KeyError`` for a record the vectors do not
    hold."""
    change_type, name = vector.removesuffix(".json").split("/")
    if not VECTORS.joinpath("records", change_type, f"{name}.json").is_file():
        raise KeyError(f"the vectors hold no record {vector}")
    return _read(change_type, f"{name}.json")


def case_files_of(case: Mapping[str, Any]) -> Mapping[str, bytes]:
    """The files a case of the vectors (an entry of a ``cases.json``, with its ``name`` and ``vector``) kept of its own,
    by path; empty when it keeps none."""
    change_type = str(case["vector"]).split("/")[0]
    return _read(change_type, CASE_FOLDER, f"{str(case['name']).removeprefix(f'{change_type}_')}.json")


def kept_files_of_case(case: Mapping[str, Any]) -> Mapping[str, bytes]:
    """The files a case of the vectors kept: those of the record it is built on, each replaced by the case's own file at
    the same path."""
    return MappingProxyType({**kept_files_of(str(case["vector"])), **case_files_of(case)})
