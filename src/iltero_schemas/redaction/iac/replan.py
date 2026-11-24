"""Comparing a re-plan with the plan the plan stage evaluated, by the resources each would act on.

``replan_differences`` reads, from each plan as the tool wrote it, the resource changes the tool's reader lists
(``models.iac.planned_resources``): every managed resource change that does more than nothing, including resources the
plan stage left out of scope. Each is keyed by its address and deposed key and compared on the tool's ordered action
words, whether it imports the resource and whether it moves it. Nothing else is compared: no attribute value, plain or
hidden, no data source, no output. A key only the re-plan lists is ``added``, one only the evaluated plan lists is
``removed``, and one whose compared value differs is ``actions_changed``.

Each difference names its address as the record would keep it: the redaction marker when either side's plan, redacted
by the record's policy, hides the address, or when the address holds a string a tool declared sensitive in either plan.
No value, action list or plan copy is kept, and no redaction report is written for the re-plan.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from iltero_schemas.models.iac.planned_resources import PlannedResource, PlannedResources
from iltero_schemas.models.iac.replan_check import ReplanDifference, ReplanDifferenceKind, difference_sort_key
from iltero_schemas.models.iac.tool_names import IacTool
from iltero_schemas.models.iac.tools.variants import PLANNED_RESOURCE_READERS
from iltero_schemas.redaction.common.apply import REDACTED_KEY, redacted_marker, sensitive_strings
from iltero_schemas.redaction.common.policy import RedactionPolicy
from iltero_schemas.redaction.common.value_change import present_at
from iltero_schemas.redaction.iac.plan import PLAN_MARK_READERS, redact_plan

NO_READER = "no reader of the resource changes a plan would act on for this tool"


@dataclass(frozen=True)
class ReplanDifferences:
    """How many resources each plan would act on, how the two differ, and the time the tool wrote into each plan."""

    evaluated_plan_resources: int
    replan_resources: int
    differences: tuple[ReplanDifference, ...]
    evaluated_plan_timestamp: str
    replan_timestamp: str


class _Side:
    """One plan as the comparison reads it: its resources by key, its redacted plan, and its sensitive strings."""

    def __init__(self, tool: IacTool, plan: Any, policy: RedactionPolicy) -> None:
        self.read: PlannedResources = PLANNED_RESOURCE_READERS[tool](plan)
        self.redacted = redact_plan(tool, plan, policy).tree
        marks, anchors = PLAN_MARK_READERS[tool](plan)
        self.sensitive = sensitive_strings(plan, marks, anchors)
        self.by_key = {resource.key: resource for resource in self.read.resources}

    def marker_of(self, resource: PlannedResource) -> dict[str, Any] | None:
        """The marker that stands for ``resource``'s address in the redacted plan: the one at the address, or at a
        node above it that redaction hid whole (the list, the resource change); None when the address is kept."""
        node: Any = self.redacted
        for key in ("resource_changes", resource.position, "address"):
            if _is_marker(node):
                return node  # type: ignore[no-any-return]
            present, node = present_at(node, (key,))
            if not present:
                return None
        return node if _is_marker(node) else None


def _is_marker(node: Any) -> bool:
    """Whether ``node`` is an object redaction wrote in place of a value."""
    return isinstance(node, dict) and REDACTED_KEY in node


def _named(address: str, markers: list[dict[str, Any] | None], sensitive: set[str]) -> str | dict[str, Any]:
    """``address`` as the record keeps it: a side's marker, a marker when it holds a sensitive string, or the
    address."""
    for marker in markers:
        if marker is not None:
            return marker
    if any(value in address for value in sensitive):
        return redacted_marker("sensitive_value_reuse", address)
    return address


def replan_differences(tool: IacTool, evaluated_plan: Any, replan: Any, policy: RedactionPolicy) -> ReplanDifferences:
    """How ``replan`` differs from ``evaluated_plan``, both as ``tool`` wrote them, by the resources each would act on,
    each address named as ``policy`` leaves it. Raises ``ValueError`` for a tool with no reader, a plan the reader
    refuses (``models.iac.tools.terraform_planned_resources``), and a plan ``redact_plan`` refuses, such as one that
    already holds a redaction or unknown marker."""
    if tool not in PLANNED_RESOURCE_READERS:
        raise ValueError(NO_READER)
    evaluated, replanned = _Side(tool, evaluated_plan, policy), _Side(tool, replan, policy)
    sensitive = evaluated.sensitive | replanned.sensitive
    # Each difference beside where the plan that lists it lists it: the re-plan for added, the evaluated plan otherwise.
    found: list[tuple[ReplanDifference, int]] = []

    def add(address: str | dict[str, Any], resource: PlannedResource, difference: ReplanDifferenceKind) -> None:
        named = ReplanDifference.model_validate(
            {"address": address, "deposed_key": resource.deposed_key, "difference": difference}
        )
        found.append((named, resource.position))

    for key, resource in evaluated.by_key.items():
        other = replanned.by_key.get(key)
        if other is None:
            add(_named(resource.address, [evaluated.marker_of(resource)], sensitive), resource, "removed")
        elif other.compared != resource.compared:
            markers = [evaluated.marker_of(resource), replanned.marker_of(other)]
            add(_named(resource.address, markers, sensitive), resource, "actions_changed")
    for key, resource in replanned.by_key.items():
        if key not in evaluated.by_key:
            add(_named(resource.address, [replanned.marker_of(resource)], sensitive), resource, "added")
    # The record's order (``difference_sort_key``), and markers that tie on it by where their plan lists them.
    ordered = sorted(found, key=lambda pair: (difference_sort_key(pair[0]), pair[1]))
    return ReplanDifferences(
        evaluated_plan_resources=len(evaluated.read.resources),
        replan_resources=len(replanned.read.resources),
        differences=tuple(difference for difference, _ in ordered),
        evaluated_plan_timestamp=evaluated.read.timestamp,
        replan_timestamp=replanned.read.timestamp,
    )
