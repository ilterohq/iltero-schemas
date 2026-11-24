"""The resource changes a Terraform or OpenTofu plan (``terraform show -json``) would act on.

Each entry of ``resource_changes`` with ``mode: managed`` is listed unless its actions are only ``["no-op"]`` and it
neither imports (``change.importing`` set) nor moves (``previous_address`` set) the resource. Its key is its
``address`` and, for a deposed object, its ``deposed`` key, eight lowercase hexadecimal characters. A plan is read only
with its top-level ``timestamp``, the time the tool wrote it.
"""

from __future__ import annotations

from typing import Any

from iltero_schemas.models.common.redaction import is_redaction_marker, is_unknown_marker
from iltero_schemas.models.iac.planned_resources import (
    KeptPlannedResources,
    PlannedResource,
    PlannedResources,
    check_resources_listed,
)

# The shape ``variants.DEPOSED_KEY_PATTERNS`` gives for terraform, which imports this module.
from iltero_schemas.models.iac.tools.terraform import DEPOSED_KEY as _DEPOSED_KEY

NO_TIMESTAMP = "a plan names the time the tool wrote it in its timestamp"
NOT_A_LIST = "the resource changes of a plan are a list"
NOT_AN_OBJECT = "each resource change of a plan, and its change, is an object"
NOT_TEXT = "a resource change names its address, mode, previous address, deposed key and actions as text"
DEPOSED_KEY_SHAPE = "a deposed key is eight lowercase hexadecimal characters"


def _text_or_none(value: Any) -> bool:
    return value is None or isinstance(value, str)


def _acts(mode: str, actions: list[str], imports: bool, moves: bool) -> bool:
    """Whether a resource change counts as one the plan acts on: a managed resource that does more than nothing, or
    that the plan imports or moves."""
    return mode == "managed" and not (actions == ["no-op"] and not imports and not moves)


def _read(position: int, entry: Any) -> PlannedResource | None:
    if not isinstance(entry, dict):
        raise ValueError(NOT_AN_OBJECT)
    change = entry.get("change")
    if not isinstance(change, dict):
        raise ValueError(NOT_AN_OBJECT)
    address, mode, actions = entry.get("address"), entry.get("mode"), change.get("actions")
    if (
        not isinstance(address, str)
        or not isinstance(mode, str)
        or not isinstance(actions, list)
        or not all(isinstance(action, str) for action in actions)
        or not _text_or_none(entry.get("previous_address"))
        or not _text_or_none(entry.get("deposed"))
    ):
        raise ValueError(NOT_TEXT)
    deposed = entry.get("deposed")
    if deposed is not None and not _DEPOSED_KEY.fullmatch(deposed):
        raise ValueError(DEPOSED_KEY_SHAPE)
    imports = change.get("importing") is not None
    moves = entry.get("previous_address") is not None
    if not _acts(mode, actions, imports, moves):
        return None
    return PlannedResource(position, address, deposed, tuple(actions), imports, moves)


def planned_resources(plan: Any) -> PlannedResources:
    """Every resource change ``plan`` would act on, in its order, with the plan's ``timestamp``. Raises ``ValueError``
    for a plan with no timestamp, a resource change that is not an object or names its fields in another shape, a
    deposed key of another shape, one key twice, or more resources than one comparison reads."""
    if not isinstance(plan, dict) or not isinstance(plan.get("timestamp"), str):
        raise ValueError(NO_TIMESTAMP)
    # Terraform leaves resource_changes out of a plan that changes nothing.
    entries = plan.get("resource_changes", [])
    if not isinstance(entries, list):
        raise ValueError(NOT_A_LIST)
    resources = [read for position, entry in enumerate(entries) if (read := _read(position, entry)) is not None]
    check_resources_listed(resources)
    return PlannedResources(plan["timestamp"], tuple(resources))


def _marker(value: Any) -> bool:
    """Whether a field of a kept plan holds a marker that stands for its value, not the value the tool wrote."""
    return is_redaction_marker(value) or is_unknown_marker(value)


def kept_planned_resources(plan: Any) -> KeptPlannedResources:
    """What a plan as the record keeps it, redacted, shows of the resources it acts on: the time the tool wrote into it,
    the keys of the resource changes it surely acts on, and those of the changes whose mode, actions, import or move a
    marker stands for, which it may act on. A change whose address or deposed key a marker stands for is counted among
    those it may act on, by no key. Raises ``ValueError`` for a kept plan with no plain timestamp or resource list."""
    if not isinstance(plan, dict) or not isinstance(plan.get("timestamp"), str):
        raise ValueError(NO_TIMESTAMP)
    entries = plan.get("resource_changes", [])
    if not isinstance(entries, list):
        raise ValueError(NOT_A_LIST)
    surely: list[tuple[str, str | None]] = []
    maybe: list[tuple[str, str | None]] = []
    unnamed = 0
    for entry in entries:
        change = entry.get("change") if isinstance(entry, dict) else None
        if not isinstance(entry, dict) or not isinstance(change, dict):
            unnamed += 1
            continue
        address, deposed = entry.get("address"), entry.get("deposed")
        if not isinstance(address, str) or not (deposed is None or isinstance(deposed, str)):
            unnamed += 1
            continue
        mode, actions = entry.get("mode"), change.get("actions")
        importing, previous = change.get("importing"), entry.get("previous_address")
        if (
            not isinstance(mode, str)
            or not isinstance(actions, list)
            or not all(isinstance(a, str) for a in actions)
            or _marker(previous)
            or _marker(importing)
        ):
            maybe.append((address, deposed))
            continue
        if _acts(mode, actions, importing is not None, previous is not None):
            surely.append((address, deposed))
    return KeptPlannedResources(plan["timestamp"], frozenset(surely), frozenset(maybe), unnamed)
