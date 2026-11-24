"""Why a resource of a plan is left out of the subjects a stage evaluates, decided from the plan alone.

A stage evaluates every resource of the plan it kept except those it leaves out, and it says why for each one
(``models.common.coverage.Excluded``). ``exclusion_reason`` gives that reason from the resource's own entry in the plan
and the plan's configuration, so the writer and every reader decide it the same way. The first of these that holds, in
this order, is the reason: a resource any of whose naming fields is not text was redacted (``identity_redacted``),
whatever its other naming fields hold; one whose naming fields are text too long, empty or holding control characters
cannot be named (``identity_unnameable``); one the configuration does not manage is ``not_managed``; an old copy a
replacement set aside is ``deposed``; one whose provider has no full source address or no short name an assertion can
target cannot be named (``identity_unnameable``); and one of a type that creates no object outside the tool, such as a
random value, is ``makes_no_outside_object``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from types import MappingProxyType
from typing import Any

from iltero_schemas.models.common.assertion import (
    CONTROL_CHARACTERS,
    PROVIDER_MAX_LENGTH,
    PROVIDER_PATTERN,
    Target,
    ToolSelector,
)
from iltero_schemas.models.common.coverage import ExclusionReason
from iltero_schemas.models.common.fields import ADDRESS_MAX_LENGTH, IDENTIFIER_MAX_LENGTH
from iltero_schemas.models.common.redaction import is_redaction_marker
from iltero_schemas.models.iac.tool_names import IacTool
from iltero_schemas.models.iac.tools.variants import PLAN_NAMING, PlanNaming

# The longest text each naming field holds.
NAMING_FIELD_MAX_LENGTHS: Mapping[str, int] = MappingProxyType(
    {
        "address": ADDRESS_MAX_LENGTH,
        "module": ADDRESS_MAX_LENGTH,
        "type": IDENTIFIER_MAX_LENGTH,
        "provider": IDENTIFIER_MAX_LENGTH,
    }
)
_PROVIDER_NAME = re.compile(PROVIDER_PATTERN)
# The plan actions that take a resource out of the plan's subjects: it is deleted, or the tool forgets it.
_LEAVES_SCOPE = (["delete"], ["forget"])


# The resource types a stage's assertions name, each with its provider's short name: (``random``, ``random_password``).
NamedTypes = frozenset[tuple[str, str]]


def named_resource_types_of_targets(tool: IacTool, targets: Iterable[Target]) -> NamedTypes:
    """Every resource type the ``targets`` of the rules a stage evaluates name for ``tool``, by its provider's short
    name: the types of each of their tool selectors. A resource of a type named here is never left out as one that
    creates nothing outside the tool, so a check that names it evaluates it. A target is an assertion's, or a
    hand-written rule's as its policy entry declares it."""
    return frozenset(
        (selector.provider, resource_type)
        for target in targets
        for selector in target.resources or []
        if isinstance(selector, ToolSelector) and selector.tool == tool
        for resource_type in selector.resource_types
    )


def leaves_scope(change: Mapping[str, Any]) -> bool:
    """Whether the plan deletes the resource of ``change``, or forgets it: it is no subject after the change."""
    body = change.get("change")
    return isinstance(body, dict) and body.get("actions") in _LEAVES_SCOPE


def _identity_problem(naming: PlanNaming, change: Mapping[str, Any]) -> ExclusionReason | None:
    """``identity_redacted`` when any naming field is redacted, whatever the others hold; else ``identity_unnameable``
    when any is text that cannot name the resource."""
    given = {name: change.get(field) for name, field in naming.fields.items() if change.get(field) is not None}
    for name, value in given.items():
        if not isinstance(value, str) and not is_redaction_marker(value):
            raise ValueError(f"the plan's {naming.fields[name]} is neither text nor a redaction marker")
    if any(not isinstance(value, str) for value in given.values()):
        return "identity_redacted"
    if any(
        not 0 < len(value) <= NAMING_FIELD_MAX_LENGTHS[name] or CONTROL_CHARACTERS.search(value)
        for name, value in given.items()
        if isinstance(value, str)
    ):
        return "identity_unnameable"
    return None


def exclusion_reason(
    tool: IacTool, change: Mapping[str, Any], provisioners: Mapping[str, bool], named_types: NamedTypes
) -> ExclusionReason | None:
    """Why the resource ``change`` (one entry of a ``tool`` plan's resource list) is left out of the subjects a stage
    evaluates, or None when it is evaluated; ``provisioners`` says whether each resource the plan's configuration
    declares has a provisioner (``PlanNaming.configured_provisioners``), and ``named_types`` which types the stage's
    rules name (``named_resource_types_of_targets``), which are never left out as creating nothing outside the tool.
    ``ValueError`` when a naming field is neither text nor a redaction marker: no stage keeps such a plan."""
    naming = PLAN_NAMING[tool]
    problem = _identity_problem(naming, change)
    if problem is not None:
        return problem
    if change.get("mode") != "managed":
        return "not_managed"
    if change.get("deposed") is not None:
        return "deposed"
    source = change.get(naming.fields["provider"])
    provider = naming.provider_short_name(source)
    if provider is None or len(provider) > PROVIDER_MAX_LENGTH or _PROVIDER_NAME.match(provider) is None:
        return "identity_unnameable"
    resource_type, address = change.get(naming.fields["type"]), change.get(naming.fields["address"])
    if (
        isinstance(source, str)
        and isinstance(resource_type, str)
        and isinstance(address, str)
        and (provider, resource_type) not in named_types
        and naming.makes_no_outside_object(
            source=source, resource_type=resource_type, address=address, provisioners=provisioners
        )
    ):
        return "makes_no_outside_object"
    return None
