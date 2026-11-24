"""Why a resource of a plan is left out of the subjects a stage evaluates, decided from the plan alone."""

from __future__ import annotations

from typing import Any

import pytest

from iltero_schemas.models.common.assertion import TechnicalAssertion
from iltero_schemas.models.iac.plan_exclusions import exclusion_reason, named_resource_types_of_targets

REDACTED = {"__redacted": True, "reason": "value_shape", "present": True, "type": "string"}
RESOURCE = {
    "address": "aws_s3_bucket.logs",
    "mode": "managed",
    "type": "aws_s3_bucket",
    "provider_name": "registry.terraform.io/hashicorp/aws",
}


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({}, None),
        ({"address": REDACTED}, "identity_redacted"),
        ({"module_address": REDACTED}, "identity_redacted"),
        ({"provider_name": REDACTED, "mode": "data"}, "identity_redacted"),
        ({"address": ""}, "identity_unnameable"),
        ({"address": "a" * 2049, "type": REDACTED}, "identity_redacted"),
        ({"type": "a" * 257}, "identity_unnameable"),
        ({"address": b"aws_s3_bucket.logs\\u0007".decode("unicode_escape")}, "identity_unnameable"),
        ({"mode": "data"}, "not_managed"),
        ({"deposed": "0a1b2c3d"}, "deposed"),
        ({"deposed": None}, None),
        ({"provider_name": "registry.example/Odd.Provider"}, "identity_unnameable"),
        ({"provider_name": None}, "identity_unnameable"),
        ({"provider_name": None, "mode": "data"}, "not_managed"),
    ],
    ids=[
        "evaluated",
        "address_redacted",
        "module_redacted",
        "provider_redacted_before_mode",
        "empty_address",
        "redacted_outranks_unnameable",
        "type_too_long",
        "control_character",
        "data_source",
        "deposed_object",
        "deposed_written_as_null",
        "provider_with_no_short_name",
        "no_provider",
        "no_provider_on_a_data_source",
    ],
)
def test_a_resource_is_left_out_for_the_first_reason_that_holds(change: dict[str, Any], reason: str | None) -> None:
    assert exclusion_reason("terraform", {**RESOURCE, **change}, {}, frozenset()) == reason


@pytest.mark.parametrize(
    "value",
    [0, [], {}, {"__redacted": True}, {**REDACTED, "__redacted": 1}],
    ids=["number", "list", "object", "half_a_marker", "redacted_written_as_one"],
)
def test_a_naming_field_that_is_neither_text_nor_a_redaction_marker_is_a_plan_no_stage_keeps(value: Any) -> None:
    with pytest.raises(ValueError, match="neither text nor a redaction marker"):
        exclusion_reason("terraform", {**RESOURCE, "address": value}, {}, frozenset())


def assertion_naming(provider: str, *resource_types: str) -> TechnicalAssertion:
    """A state assertion whose tool selector names ``resource_types`` of ``provider``."""
    return TechnicalAssertion.model_validate(
        {
            "apiVersion": "iltero.com/v1",
            "kind": "TechnicalAssertion",
            "metadata": {
                "id": f"ACME.IAC.RESOURCE.{provider.upper()}.VALUE.LONG",
                "version": "1.0.0",
                "title": "The value is long",
            },
            "spec": {
                "change_type": "iac_change",
                "stage": "plan",
                "target": {
                    "kind": "resource",
                    "resources": [{"tool": "terraform", "provider": provider, "resource_types": list(resource_types)}],
                },
                "assert": {"path": "resource.after.length", "greater_or_equal": 24},
            },
        }
    )


def test_the_types_a_stage_s_assertions_name_are_taken_from_their_tool_selectors() -> None:
    assertions = [assertion_naming("random", "random_password", "random_id"), assertion_naming("aws", "aws_s3_bucket")]
    assert named_resource_types_of_targets("terraform", [a.spec.target for a in assertions]) == {
        ("random", "random_password"),
        ("random", "random_id"),
        ("aws", "aws_s3_bucket"),
    }


def test_a_resource_of_a_type_an_assertion_names_is_not_left_out_as_creating_nothing_outside_the_tool() -> None:
    change = {
        "address": "random_password.db",
        "mode": "managed",
        "type": "random_password",
        "name": "db",
        "provider_name": "registry.terraform.io/hashicorp/random",
        "change": {"actions": ["create"], "before": None, "after": {}},
    }
    declared = {"random_password.db": False}
    assert exclusion_reason("terraform", change, declared, frozenset()) == "makes_no_outside_object"
    named = named_resource_types_of_targets("terraform", [assertion_naming("random", "random_password").spec.target])
    assert exclusion_reason("terraform", change, declared, named) is None
