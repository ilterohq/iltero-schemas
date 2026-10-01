"""The IaC tools a record may name: each has a rule for its resource types and a scheme for its addresses."""

from __future__ import annotations

import re
from typing import get_args

import pytest

from iltero_schemas.models.iac import ADDRESS_SCHEMES, IAC_TOOLS, RESOURCE_TYPE_PATTERNS, IacTool


def test_every_tool_has_a_type_rule_and_an_address_scheme() -> None:
    assert IAC_TOOLS == get_args(IacTool)
    assert set(RESOURCE_TYPE_PATTERNS) == set(ADDRESS_SCHEMES) == set(IAC_TOOLS)
    assert len(set(ADDRESS_SCHEMES.values())) == len(ADDRESS_SCHEMES)


@pytest.mark.parametrize("tool", IAC_TOOLS)
def test_each_type_rule_is_a_whole_match_pattern(tool: IacTool) -> None:
    pattern = RESOURCE_TYPE_PATTERNS[tool]
    assert pattern.startswith("^") and pattern.endswith("$")
    re.compile(pattern)


def test_terraform_names_its_addresses_in_the_scheme_both_consumers_use() -> None:
    assert ADDRESS_SCHEMES["terraform"] == "terraform_address"


def test_the_tables_cannot_be_changed() -> None:
    with pytest.raises(TypeError):
        ADDRESS_SCHEMES["terraform"] = "x"  # type: ignore[index]
    with pytest.raises(TypeError):
        RESOURCE_TYPE_PATTERNS["terraform"] = ".*"  # type: ignore[index]
