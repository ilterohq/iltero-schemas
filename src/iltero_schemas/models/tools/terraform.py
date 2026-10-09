"""Terraform, the first infrastructure-as-code (IaC) tool the contract supports.

A plan resource and the resources that refer to it carry a neutral core that
every tool can fill, plus ``tool_data``: what only this tool says about them,
keyed by ``tool``. Another tool adds its own module and its variant of each
part, and changes none here.
"""

from __future__ import annotations

from typing import Any, Literal

from iltero_schemas.models.base import StrictModel
from iltero_schemas.models.fields import Identifier
from iltero_schemas.models.redaction import MaybeHidden, MaybeHiddenAddress


class TerraformResourceData(StrictModel):
    """What Terraform's plan says about a resource beyond the neutral core, as the plan wrote it."""

    tool: Literal["terraform"]
    # The provider's full source address, such as ``registry.terraform.io/hashicorp/aws``.
    provider_source: Identifier | None
    # Why Terraform chose the action, such as ``replace_because_tainted``.
    action_reason: MaybeHidden | None
    # The address the resource had before a ``moved`` block renamed it.
    previous_address: MaybeHiddenAddress | None
    # The import block that brings an existing object under management, as the plan wrote it.
    importing: Any
    # The attribute paths whose change forces a replacement, as the plan wrote them.
    replace_paths: Any


class TerraformRelatedData(StrictModel):
    """How Terraform matched a related resource: to this instance of a ``count`` or ``for_each``, or to every one."""

    tool: Literal["terraform"]
    match: Literal["instance", "every_instance"]
