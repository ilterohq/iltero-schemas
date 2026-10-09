"""Each IaC tool's table of kinds: which kind each of its resource types is, per provider.

The table is data, one JSON file per tool beside this module, so every
consumer names a resource's kind the same way and a reader can check the kind
an evaluation input claims. A type the table does not hold has no kind; the
input then carries the unknown marker in its place.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from importlib import resources
from types import MappingProxyType

from iltero_schemas.models.iac import IacTool

_TOOLS: tuple[IacTool, ...] = ("terraform",)


def _load(tool: IacTool) -> Mapping[str, Mapping[str, str]]:
    table = json.loads((resources.files(__package__) / f"{tool}.json").read_text(encoding="utf-8"))
    return MappingProxyType({provider: MappingProxyType(types) for provider, types in table.items()})


TOOL_KINDS: Mapping[IacTool, Mapping[str, Mapping[str, str]]] = MappingProxyType({tool: _load(tool) for tool in _TOOLS})


def kind_of(tool: IacTool, provider: str, resource_type: str) -> str | None:
    """The kind of ``resource_type`` of ``provider`` as ``tool`` declares it; None when the table has none."""
    return TOOL_KINDS[tool].get(provider, {}).get(resource_type)
