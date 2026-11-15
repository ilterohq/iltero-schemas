"""What a stage's kept plan gives its scanner verdicts: each resource's unknown paths, the resources that configure
another, and the managed resources an assertion only scanners decide is about; and whether each resource the stage
left out of scope is one the plan shows it may leave out."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from iltero_schemas.models.coverage import IDENTITY_REASONS, Excluded
from iltero_schemas.models.iac.plan_exclusions import exclusion_reason
from iltero_schemas.models.iac.plan_relations import plan_configures
from iltero_schemas.models.iac.scanner_verdicts import plan_unknown_paths
from iltero_schemas.models.iac.tool_names import IacTool

# The plan actions that take a resource out of the plan's scope.
_LEAVES_SCOPE = (["delete"], ["forget"])


@dataclass(frozen=True)
class PlanScope:
    """What the stage's kept plan gives every scanner verdict: unknown paths, configuring resources, and the managed
    resources in scope by type."""

    unknown_paths: Mapping[str, list[str]]
    configures: Mapping[str, list[str]]
    in_scope: Mapping[str, list[str]]


def left_out_for_identity(excluded: Iterable[Excluded]) -> frozenset[int]:
    """The plan positions of the resources a stage left out of scope for their identity. Only these leave the scope of
    an assertion only scanners decide: a resource left out as not managed or as a deposed object is never in it."""
    return frozenset(entry.plan_index for entry in excluded if entry.reason in IDENTITY_REASONS)


def plan_scope(plan: dict[str, Any], left_out: frozenset[int]) -> PlanScope:
    """What ``plan`` gives the stage's scanner verdicts. A resource at a position in ``left_out`` (the stage excluded
    it for its identity, so its address may be redacted) gives nothing: it is in no assertion's scope. A deposed
    object, an old copy the plan sets aside while it replaces a resource, shares the live resource's address, so only
    the live resource gives its unknown paths."""
    unknown: dict[str, list[str]] = {}
    in_scope: dict[str, list[str]] = {}
    for index, change in enumerate(plan["resource_changes"]):
        if not isinstance(change, dict) or change.get("mode") != "managed" or index in left_out:
            continue
        body = change["change"]
        if change.get("deposed") is None:
            unknown[change["address"]] = plan_unknown_paths(body.get("after_unknown"))
        if body.get("actions") not in _LEAVES_SCOPE:
            in_scope.setdefault(change["type"], []).append(change["address"])
    return PlanScope(unknown, plan_configures(plan), in_scope)


def exclusion_holds(tool: IacTool, plan: dict[str, Any], excluded: Excluded) -> bool:
    """Whether the plan shows of the resource at ``excluded.plan_index`` what the exclusion says of it: the address
    the plan wrote, or none when that address is not text, and the reason ``exclusion_reason`` gives for it."""
    changes = plan.get("resource_changes")
    if not isinstance(changes, list) or excluded.plan_index >= len(changes):
        return False
    change = changes[excluded.plan_index]
    if not isinstance(change, dict):
        return False
    address = change.get("address")
    return excluded.id == (address if isinstance(address, str) else None) and excluded.reason == exclusion_reason(
        tool, change
    )
