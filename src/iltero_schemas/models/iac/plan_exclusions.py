"""Why a resource of a plan is left out of the subjects a stage evaluates, decided from the plan alone.

A stage evaluates every resource of the plan it kept except those it leaves out, and it says why for each one
(``models.coverage.Excluded``). ``exclusion_reason`` gives that reason from the resource's own entry in the plan, so
the writer and every reader decide it the same way: a resource any of whose naming fields is not text was redacted
(``identity_redacted``), whatever its other naming fields hold; one whose naming fields are text too long, empty or
holding control characters, or whose provider has no short name an assertion can target, cannot be named
(``identity_unnameable``); one the
configuration does not manage is ``not_managed``; an old copy a replacement set aside is ``deposed``. The first that
holds, in that order, is the reason.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from iltero_schemas.models.assertion import CONTROL_CHARACTERS, PROVIDER_MAX_LENGTH, PROVIDER_PATTERN
from iltero_schemas.models.coverage import ExclusionReason
from iltero_schemas.models.fields import ADDRESS_MAX_LENGTH, IDENTIFIER_MAX_LENGTH
from iltero_schemas.models.iac.tool_names import IacTool
from iltero_schemas.models.iac.tools.variants import PLAN_NAMING, PlanNaming
from iltero_schemas.models.redaction import is_redaction_marker

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


def exclusion_reason(tool: IacTool, change: Mapping[str, Any]) -> ExclusionReason | None:
    """Why the resource ``change`` (one entry of a ``tool`` plan's resource list) is left out of the subjects a stage
    evaluates, or None when it is evaluated. ``ValueError`` when a naming field is neither text nor a redaction
    marker: no stage keeps such a plan."""
    naming = PLAN_NAMING[tool]
    problem = _identity_problem(naming, change)
    if problem is not None:
        return problem
    if change.get("mode") != "managed":
        return "not_managed"
    if change.get("deposed") is not None:
        return "deposed"
    provider = naming.provider_short_name(change.get(naming.fields["provider"]))
    if provider is None or len(provider) > PROVIDER_MAX_LENGTH or _PROVIDER_NAME.match(provider) is None:
        return "identity_unnameable"
    return None
