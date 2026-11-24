"""The tool-keyed parts the neutral models carry, one name per part, and the checks that join two of them.

Each name is the union of every tool's variant of that part, chosen by its
``tool`` value. Only Terraform exists yet, so each is Terraform's model. A new
tool adds its module and joins its variant to each union here, as
``Annotated[TerraformX | OtherX, Field(discriminator="tool")]``, with a check
that the variant names the tool the enclosing document names. No neutral model
changes.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol

from iltero_schemas.models.iac.planned_resources import KeptPlannedResources, PlannedResources
from iltero_schemas.models.iac.tool_names import IacTool
from iltero_schemas.models.iac.tools import terraform, terraform_planned_resources
from iltero_schemas.models.iac.tools.terraform import (
    TerraformApplyData,
    TerraformIdentityData,
    TerraformRelatedData,
    TerraformResourceData,
    check_deposed,
)

# What only the tool that planned a resource says about it.
ResourceToolData = TerraformResourceData
# What only that tool says about a resource that refers to it.
RelatedToolData = TerraformRelatedData
# What only the tool that wrote the apply log says about the apply, and the checks against its changes.
ApplyToolData = TerraformApplyData
# What only the tool that wrote the state says in a resource identities document.
IdentityToolData = TerraformIdentityData


@dataclass(frozen=True)
class PlanNaming:
    """How one IaC tool's plan names a resource and what its plan says of the resource's scope: the field it writes
    each naming field under (``address``, ``module``, ``type``, ``provider``), the provider's short name an assertion
    targets it by, the sources each provider's kind table was reviewed against, whether each resource the plan's
    configuration declares has a provisioner, and whether a resource creates no object outside the tool."""

    fields: Mapping[str, str]
    provider_short_name: Callable[[object], str | None]
    reviewed_provider_sources: Mapping[str, frozenset[str]]
    configured_provisioners: Callable[[object], Mapping[str, bool]]
    makes_no_outside_object: Callable[..., bool]


# Each tool's way of naming a resource in its plan.
PLAN_NAMING: Mapping[IacTool, PlanNaming] = MappingProxyType(
    {
        "terraform": PlanNaming(
            terraform.PLAN_NAMING_FIELDS,
            terraform.provider_short_name,
            terraform.REVIEWED_PROVIDER_SOURCES,
            terraform.configured_provisioners,
            terraform.makes_no_outside_object,
        )
    }
)


# Each tool's reader of the resource changes its plan would act on, keyed for a re-plan comparison
# (``models.iac.planned_resources``).
PLANNED_RESOURCE_READERS: Mapping[IacTool, Callable[[object], PlannedResources]] = MappingProxyType(
    {"terraform": terraform_planned_resources.planned_resources}
)
# The shape of each tool's deposed key: the name of an old copy a replacement set aside.
DEPOSED_KEY_PATTERNS: Mapping[IacTool, re.Pattern[str]] = MappingProxyType({"terraform": terraform.DEPOSED_KEY})
# Each tool's reader of the same, from a plan as a record keeps it, redacted: what a reader recounts a re-plan check by.
KEPT_PLANNED_RESOURCE_READERS: Mapping[IacTool, Callable[[object], KeptPlannedResources]] = MappingProxyType(
    {"terraform": terraform_planned_resources.kept_planned_resources}
)


class ToolKeyed(Protocol):
    """A tool-keyed part: it names the tool whose variant it is."""

    @property
    def tool(self) -> str: ...


def check_tool_data(tool: IacTool, parts: Iterable[ToolKeyed], where: str) -> None:
    """Raise ``ValueError`` unless every part is the variant of ``tool``, the tool its enclosing document names."""
    if any(part.tool != tool for part in parts):
        raise ValueError(f"{where} is keyed by the tool {tool}")


def check_identity_against_apply(identity: IdentityToolData, apply: ApplyToolData) -> None:
    """Raise ``ValueError`` unless the resource identities document's tool part agrees with the apply's."""
    check_deposed(identity, apply)
