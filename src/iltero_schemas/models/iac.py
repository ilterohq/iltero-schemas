"""The infrastructure-as-code (IaC) tools a record may name, and the naming rules of each.

An IaC tool, such as Terraform, plans and applies changes to cloud
resources. The Iltero CLI never runs it. It reads the plan, the apply log and
the state the tool wrote. Every place in the contract that names an IaC tool
uses this one list. A new tool adds its name to the list and an entry to each
table below.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Literal, get_args

IacTool = Literal["terraform"]
# The same names as a tuple, in the order the type lists them.
IAC_TOOLS: tuple[IacTool, ...] = get_args(IacTool)
# How each tool spells a resource type, such as Terraform's ``aws_db_instance``.
RESOURCE_TYPE_PATTERNS: Mapping[IacTool, str] = MappingProxyType({"terraform": r"^[a-z][a-z0-9_]*$"})
# The scheme a subject's identity is written in when it is the resource's address in the tool's configuration.
ADDRESS_SCHEMES: Mapping[IacTool, str] = MappingProxyType({"terraform": "terraform_address"})
