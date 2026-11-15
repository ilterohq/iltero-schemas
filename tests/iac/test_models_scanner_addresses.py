"""A scanner's address resolves to exactly one resource of the plan, or to none with the reason."""

from __future__ import annotations

import pytest

from iltero_schemas.models.iac.scanner_addresses import address_index, plan_resource_addresses, resolve, trivy_address
from iltero_schemas.models.scanners import SCANNER_TOOLS

# The addresses of a real plan, and how Trivy 0.72.0 wrote each of them.
PLAN = [
    "aws_db_instance.counted[0]",
    "aws_db_instance.counted[1]",
    'aws_db_instance.keyed["a"]',
    'aws_db_instance.keyed["b"]',
    "aws_db_instance.single",
    "module.outer[0].aws_db_instance.deep",
    "module.db.aws_db_instance.inner",
]


def test_trivy_writes_a_module_resource_with_the_md5_of_its_module_path() -> None:
    assert trivy_address("module.db.aws_db_instance.inner") == "aws_db_instance.inner_885c44cac781df4d73baeb3b2919c635"
    assert trivy_address("module.outer[0].aws_db_instance.deep") == (
        "aws_db_instance.deep_bbb110433ce5993116a928804fe86722"
    )


def test_trivy_writes_a_resource_without_its_instance_key() -> None:
    assert trivy_address("aws_db_instance.counted[1]") == "aws_db_instance.counted"
    assert trivy_address('aws_db_instance.keyed["a.b"]') == "aws_db_instance.keyed"


@pytest.mark.parametrize("address", ["", "aws_db_instance", "module.db", "a..b", "aws_db_instance.x[", "x.y z"])
def test_text_that_is_not_a_managed_resource_address_is_refused(address: str) -> None:
    with pytest.raises(ValueError):
        trivy_address(address)


def test_checkov_resolves_the_plans_own_address() -> None:
    index = address_index("checkov", PLAN)
    assert resolve(index, "aws_db_instance.counted[1]") == ("aws_db_instance.counted[1]", None)
    assert resolve(index, "module.db.aws_db_instance.inner") == ("module.db.aws_db_instance.inner", None)


def test_trivy_resolves_an_address_that_names_one_resource() -> None:
    index = address_index("trivy", PLAN)
    assert resolve(index, "aws_db_instance.single") == ("aws_db_instance.single", None)
    assert resolve(index, "aws_db_instance.inner_885c44cac781df4d73baeb3b2919c635") == (
        "module.db.aws_db_instance.inner",
        None,
    )


def test_a_trivy_address_shared_by_resources_made_by_count_or_for_each_is_ambiguous() -> None:
    index = address_index("trivy", PLAN)
    assert resolve(index, "aws_db_instance.counted") == (None, "ambiguous")
    assert resolve(index, "aws_db_instance.keyed") == (None, "ambiguous")


@pytest.mark.parametrize("tool", SCANNER_TOOLS)
def test_an_address_that_names_no_resource_of_the_plan_is_not_in_plan(tool: str) -> None:
    index = address_index(tool, PLAN)
    assert resolve(index, "aws_db_instance.other") == (None, "not_in_plan")
    assert resolve(index, None) == (None, "no_address")


def test_a_name_that_only_looks_alike_never_resolves() -> None:
    """No match by name: Checkov's address is exact, and a Trivy address without its module digest is another one."""
    assert resolve(address_index("checkov", PLAN), "aws_db_instance.inner") == (None, "not_in_plan")
    assert resolve(address_index("trivy", PLAN), "aws_db_instance.inner") == (None, "not_in_plan")


def test_the_addresses_resolved_against_are_every_managed_instance_whatever_its_action() -> None:
    """Leaving one instance out could let a Trivy address name the one that remained."""
    plan = {
        "resource_changes": [
            {"address": "aws_db_instance.counted[1]", "mode": "managed", "change": {"actions": ["no-op"]}},
            {"address": "aws_db_instance.counted[0]", "mode": "managed", "change": {"actions": ["delete"]}},
            {"address": "data.aws_iam_policy_document.p", "mode": "data", "change": {"actions": ["read"]}},
        ]
    }
    addresses = plan_resource_addresses(plan)
    assert addresses == ["aws_db_instance.counted[0]", "aws_db_instance.counted[1]"]
    assert resolve(address_index("trivy", addresses), "aws_db_instance.counted") == (None, "ambiguous")
    with pytest.raises(ValueError):
        plan_resource_addresses({"resource_changes": None})
