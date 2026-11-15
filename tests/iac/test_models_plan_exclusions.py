"""Why a resource of a plan is left out of the subjects a stage evaluates, decided from the plan alone."""

from __future__ import annotations

from typing import Any

import pytest

from iltero_schemas.models.iac.plan_exclusions import exclusion_reason

REDACTED = {"__redacted": True, "reason": "matched_pattern", "present": True, "type": "string"}
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
    assert exclusion_reason("terraform", {**RESOURCE, **change}) == reason


@pytest.mark.parametrize(
    "value",
    [0, [], {}, {"__redacted": True}, {**REDACTED, "__redacted": 1}],
    ids=["number", "list", "object", "half_a_marker", "redacted_written_as_one"],
)
def test_a_naming_field_that_is_neither_text_nor_a_redaction_marker_is_a_plan_no_stage_keeps(value: Any) -> None:
    with pytest.raises(ValueError, match="neither text nor a redaction marker"):
        exclusion_reason("terraform", {**RESOURCE, "address": value})
