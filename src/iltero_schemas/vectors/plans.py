"""The plans a case of the conformance vectors names, as a consumer builds them, and the JSON Pointer edits cases
make.

A case names a plan as one written in the case (``{"plan": ...}``), or as a captured plan of ``raw_plans/iac`` edited
by JSON Pointer (RFC 6901): ``{"raw": <file>, "set": {pointer: value}, "remove": [pointer, ...]}``, the values set
first, in order, then the pointers removed. ``-`` as the last token of a list's pointer appends to it.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from typing import Any

from iltero_schemas.vectors.paths import VECTORS

# The last token of a JSON Pointer that names the place after a list's last item (RFC 6901): setting it appends.
APPEND = "-"


def _tokens(pointer: str) -> list[str]:
    return [token.replace("~1", "/").replace("~0", "~") for token in pointer.split("/")[1:]]


def _parent(document: Any, tokens: list[str]) -> Any:
    for token in tokens:
        document = document[int(token)] if isinstance(document, list) else document[token]
    return document


def set_pointer(document: Any, pointer: str, value: Any) -> None:
    """Set the value at a JSON Pointer (RFC 6901) whose parent exists; ``-`` as the last token of a list appends."""
    *parents, last = _tokens(pointer)
    holder = _parent(document, parents)
    if isinstance(holder, list) and last == APPEND:
        holder.append(value)
    else:
        holder[int(last) if isinstance(holder, list) else last] = value


def remove_pointer(document: Any, pointer: str) -> None:
    """Remove the value at the JSON Pointer ``pointer`` of ``document``."""
    *parents, last = _tokens(pointer)
    holder = _parent(document, parents)
    del holder[int(last) if isinstance(holder, list) else last]


def plan_of(named: Mapping[str, Any]) -> Any:
    """The plan ``named`` gives: the one it writes, or its captured plan with its values set and its pointers
    removed."""
    if "plan" in named:
        return copy.deepcopy(named["plan"])
    plan = json.loads(VECTORS.joinpath("raw_plans", "iac", named["raw"]).read_text(encoding="utf-8"))
    for pointer, value in named["set"].items():
        set_pointer(plan, pointer, copy.deepcopy(value))
    for pointer in named["remove"]:
        remove_pointer(plan, pointer)
    return plan
