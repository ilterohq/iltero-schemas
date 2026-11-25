"""The record cases of the conformance vectors: each names a record vector and the JSON Pointers to set and remove in
it (``records_valid/``, ``records_invalid/`` and the like)."""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from typing import Any

from iltero_schemas.vectors.paths import VECTORS
from iltero_schemas.vectors.plans import remove_pointer, set_pointer


def case_document(case: Mapping[str, Any]) -> dict[str, Any]:
    """The record ``case`` names: its vector, its values set, then removed."""
    document: dict[str, Any] = json.loads((VECTORS / "records" / case["vector"]).read_text(encoding="utf-8"))
    for pointer, value in case["set"].items():
        set_pointer(document, pointer, copy.deepcopy(value))
    for pointer in case["remove"]:
        remove_pointer(document, pointer)
    return document


def valid_case(change_type: str, name: str) -> dict[str, Any]:
    """The ``records_valid`` case ``name`` of ``change_type``."""
    cases = json.loads((VECTORS / "records_valid" / change_type / "cases.json").read_text(encoding="utf-8"))
    found: dict[str, Any] = next(case for case in cases if case["name"] == name)
    return found
