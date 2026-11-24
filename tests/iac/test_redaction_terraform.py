"""Marks from the flag trees a Terraform or OpenTofu plan writes beside its values."""

from __future__ import annotations

import json
from typing import Any

import pytest

from iltero_schemas.models.common.redaction import RedactionPolicyDocument
from iltero_schemas.redaction.common.apply import RedactionError
from iltero_schemas.redaction.common.marks import Mark
from iltero_schemas.redaction.common.policy import policy_from_document
from iltero_schemas.redaction.common.problems import redaction_problems
from iltero_schemas.redaction.iac.terraform import marks_from_flags, plan_marks_and_anchors
from tests.conftest import VECTORS


def test_true_marks_its_path_and_false_or_absent_flags_mark_nothing() -> None:
    flags = {"password": True, "tags": {"owner": False, "team": True}, "rules": [False, {"key": True}], "n": 1}
    assert marks_from_flags(flags, ("after",), "declared_sensitive", declared_sensitive=True) == [
        Mark(("after", "password"), "declared_sensitive", declared_sensitive=True),
        Mark(("after", "tags", "team"), "declared_sensitive", declared_sensitive=True),
        Mark(("after", "rules", 1, "key"), "declared_sensitive", declared_sensitive=True),
    ]
    assert marks_from_flags(None, (), "known_after_deploy", declared_sensitive=False) == []


def test_a_flag_of_true_at_the_root_marks_the_whole_value() -> None:
    assert marks_from_flags(True, ("after",), "known_after_deploy", declared_sensitive=False) == [
        Mark(("after",), "known_after_deploy", declared_sensitive=False)
    ]


@pytest.mark.parametrize(
    "document",
    [None, [], {"resource_changes": {"a": 1}}, {"resource_changes": [1, {"address": 3}]}, {"configuration": []}],
    ids=["null", "a list", "changes not a list", "entries of the wrong shape", "configuration not an object"],
)
def test_a_plan_section_of_the_wrong_shape_gives_no_mark(document: Any) -> None:
    assert plan_marks_and_anchors(document)[0] == []


PLAN_CASES = json.loads((VECTORS / "redaction" / "iac" / "plan_cases.json").read_text(encoding="utf-8"))["cases"]
READ = [case for case in PLAN_CASES if "refused" not in case]


@pytest.mark.parametrize("case", READ, ids=lambda case: case["name"])
def test_a_redacted_plan_gives_the_marks_and_anchors_of_the_plan_it_was_redacted_from(case: dict[str, Any]) -> None:
    raw_marks, raw_anchors = plan_marks_and_anchors(case["plan"])
    redacted_marks, redacted_anchors = plan_marks_and_anchors(case["redacted"])
    assert redacted_anchors == raw_anchors
    # A mark under a value redaction hid whole names nothing in the redacted plan.
    assert set(redacted_marks) <= set(raw_marks)
    policy = policy_from_document(RedactionPolicyDocument.model_validate(case["policy"]))
    assert redaction_problems(policy, case["redacted"], marks=redacted_marks, anchors=redacted_anchors).count == 0


@pytest.mark.parametrize("holder", ["planned_values", "prior_state"])
def test_a_plan_resource_that_names_no_sensitive_values_is_refused(holder: str) -> None:
    module = {"root_module": {"resources": [{"address": "terraform_data.bare", "values": {"input": "v1"}}]}}
    plan = {holder: {"values": module} if holder == "prior_state" else module}
    with pytest.raises(RedactionError, match="every resource names its sensitive values, as the tool writes them"):
        plan_marks_and_anchors(plan)
    refused = next(case for case in PLAN_CASES if "refused" in case)
    assert refused["refused"].startswith("every resource names its sensitive values")


def test_every_string_inside_a_sensitive_object_output_of_a_plan_is_hidden_wherever_it_appears() -> None:
    case = next(
        case for case in PLAN_CASES if case["name"] == "terraform_plan_with_a_sensitive_object_output_copied_unmarked"
    )
    kept = case["kept_plan"]
    assert kept["planned_values"]["root_module"]["resources"][0]["values"]["input"]["reason"] == "sensitive_value_reuse"
    assert kept["resource_changes"][0]["change"]["after"]["input"]["reason"] == "sensitive_value_reuse"
    assert ["output_changes", "connection", "after"] in case["anchors"]
    assert ["planned_values", "outputs", "connection", "value"] in case["anchors"]


def test_a_plan_resource_whose_sensitive_values_hold_a_flag_that_is_not_a_boolean_is_refused() -> None:
    resource = {"address": "terraform_data.odd", "values": {"input": "v"}, "sensitive_values": {"input": "yes"}}
    with pytest.raises(RedactionError, match="hold only objects, lists and booleans"):
        plan_marks_and_anchors({"planned_values": {"root_module": {"resources": [resource]}}})


def test_every_string_inside_a_sensitive_object_variable_of_a_plan_is_hidden_wherever_it_appears() -> None:
    case = next(
        case for case in PLAN_CASES if case["name"] == "terraform_plan_with_a_sensitive_object_variable_copied_unmarked"
    )
    assert case["kept_plan"]["resource_changes"][0]["change"]["after"]["input"]["reason"] == "sensitive_value_reuse"
    assert case["kept_plan"]["variables"]["settings"]["value"]["reason"] == "declared_sensitive"
    assert ["variables", "settings", "value"] in case["anchors"]
