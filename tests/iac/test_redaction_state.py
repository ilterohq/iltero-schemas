"""Redacting an IaC tool's state the way a record's redaction policy leaves it, and the state digest of a run the tool
opened: the state's marks, its refusals and its conformance cases."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from iltero_schemas.canonical.common.encoding import CanonicalizationError
from iltero_schemas.canonical.iac.state import (
    STATE_EXCLUDED_TOP_LEVEL_KEYS,
    canonical_redacted_state_bytes,
    redacted_state_digest_of_kept,
)
from iltero_schemas.models.common.redaction import RedactionPolicyDocument
from iltero_schemas.models.iac.tool_names import IAC_TOOLS
from iltero_schemas.redaction.common.apply import RedactionError
from iltero_schemas.redaction.common.policy import BUILT_IN_REDACTION_POLICY, policy_from_document
from iltero_schemas.redaction.iac.state import (
    STATE_KEYS_NOT_READ,
    STATE_MARK_READERS,
    STATE_SUBJECT,
    redact_state,
    redacted_state_digest,
)
from iltero_schemas.redaction.iac.terraform import plan_marks_and_anchors, state_marks_and_anchors
from tests.conftest import VECTORS

RAW_STATES = VECTORS / "raw_states" / "iac"
CASES: list[dict[str, Any]] = json.loads(
    (VECTORS / "redaction" / "iac" / "state_cases.json").read_text(encoding="utf-8")
)["cases"]
KEPT = [case for case in CASES if "refused" not in case]
REFUSED = [case for case in CASES if "refused" in case]


def _case(name: str) -> dict[str, Any]:
    return next(case for case in CASES if case["name"] == name)


def _state(case: dict[str, Any]) -> Any:
    if "state" in case:
        return case["state"]
    named = case["raw_state"]
    document = json.loads((RAW_STATES / named["file"]).read_text(encoding="utf-8"))
    return document if named["under"] is None else document[named["under"]]


def _policy(case: dict[str, Any]) -> Any:
    return policy_from_document(RedactionPolicyDocument.model_validate(case["policy"]))


def test_every_iac_tool_has_a_state_mark_reader() -> None:
    assert set(STATE_MARK_READERS) == set(IAC_TOOLS)


@pytest.mark.parametrize("case", KEPT, ids=lambda case: case["name"])
def test_a_state_is_redacted_and_digested_as_each_case_gives(case: dict[str, Any]) -> None:
    state, policy = _state(case), _policy(case)
    marks, anchors = state_marks_and_anchors(state)
    assert [[list(mark.path), mark.reason, mark.declared_sensitive] for mark in marks] == [
        [mark["path"], mark["reason"], mark["declared_sensitive"]] for mark in case["marks"]
    ]
    assert [list(anchor) for anchor in anchors] == case["anchors"]
    kept = redact_state(case["tool"], state, policy).tree
    assert kept == case["kept_state"]
    assert canonical_redacted_state_bytes(case["tool"], kept).decode("utf-8") == case["canonical"]
    assert redacted_state_digest(case["tool"], state, policy) == case["redacted_state_digest"]
    assert redacted_state_digest_of_kept(case["tool"], kept) == case["redacted_state_digest"]


@pytest.mark.parametrize("case", REFUSED, ids=lambda case: case["name"])
def test_a_state_of_another_shape_than_the_tool_writes_is_refused(case: dict[str, Any]) -> None:
    with pytest.raises((RedactionError, CanonicalizationError)) as refused:
        redact_state(case["tool"], _state(case), _policy(case))
    assert str(refused.value) == case["refused"]


def test_the_cases_cover_each_refusal_of_a_state() -> None:
    assert {case["refused"].split(" at ")[0].split(";")[0] for case in REFUSED} == {
        "a state is a JSON object",
        "a state holds no top-level key other than format_version, terraform_version, values and checks",
        "the values of a state are an object",
        "the values of a state hold no key other than root_module and outputs",
        "the outputs of a state are an object of outputs, each an object",
        "every output of a state says whether it is sensitive, true or false",
        "the module",
        "the resources of the module",
        "the sensitive values of the resource",
        "the child modules of the module",
        "every resource names its sensitive values, as the tool writes them",
        "an integer is outside the range JSON numbers hold exactly",
        "the state holds an object",
    }


def test_an_unknown_key_is_named_in_its_refusal() -> None:
    assert _case("terraform_state_with_an_unknown_top_level_key")["refused"].endswith("; it holds resource_changes")
    assert _case("terraform_state_with_an_unknown_key_under_values")["refused"].endswith("; they hold checks")


@pytest.mark.parametrize(
    ("name", "message"),
    [
        (
            "terraform_state_with_an_unknown_top_level_key_shaped_like_a_credential",
            "a state holds no top-level key other than format_version, terraform_version, values and checks",
        ),
        (
            "terraform_state_with_an_unknown_key_under_values_that_is_not_a_plain_identifier",
            "the values of a state hold no key other than root_module and outputs",
        ),
    ],
    ids=["shaped like a credential", "not a plain identifier"],
)
def test_an_unknown_key_a_rule_could_take_for_a_value_is_not_named(name: str, message: str) -> None:
    assert _case(name)["refused"] == message


def test_a_long_unknown_key_is_not_named() -> None:
    state = {"format_version": "1.0", "values": {"x" * 65: {}}}
    with pytest.raises(RedactionError) as refused:
        state_marks_and_anchors(state)
    assert str(refused.value) == "the values of a state hold no key other than root_module and outputs"


def test_a_sensitive_values_flag_that_is_not_a_boolean_is_refused() -> None:
    assert (
        "hold only objects, lists and booleans"
        in _case("terraform_state_whose_sensitive_values_hold_a_flag_that_is_not_a_boolean")["refused"]
    )


def test_a_state_with_no_canonical_form_has_no_digest() -> None:
    case = _case("terraform_state_with_an_integer_beyond_the_canonical_range")
    with pytest.raises(CanonicalizationError):
        redacted_state_digest("terraform", _state(case), BUILT_IN_REDACTION_POLICY)


def test_a_state_nested_deeper_than_its_reader_reads_is_refused_and_its_module_walk_reads_any_depth() -> None:
    module: dict[str, Any] = {}
    for _ in range(5000):
        module = {"child_modules": [module]}
    with pytest.raises(RedactionError, match="the state nests deeper than its reader reads"):
        state_marks_and_anchors({"format_version": "1.0", "values": {"root_module": module}})


def test_every_string_inside_a_sensitive_object_or_list_output_is_hidden_wherever_it_appears() -> None:
    values = _case("terraform_state_with_sensitive_object_and_list_outputs_copied_unmarked")["kept_state"]["values"]
    copied = values["root_module"]["resources"][0]["values"]
    assert copied["input"]["reason"] == copied["output"]["reason"] == "sensitive_value_reuse"
    assert values["outputs"]["connection"]["value"]["type"] == "object"
    assert values["outputs"]["endpoints"]["value"]["type"] == "array"


def test_a_sensitive_string_output_held_by_a_resource_too_is_hidden_in_both() -> None:
    case = _case("terraform_state_with_a_sensitive_string_output")
    password = next(r for r in case["kept_state"]["values"]["root_module"]["resources"] if r["name"] == "db")
    assert password["values"]["result"]["reason"] == "declared_sensitive"
    # The output is named password, a key the policy denies, so it is hidden whole, flags and all.
    assert case["kept_state"]["values"]["outputs"]["password"]["reason"] == "deny_key"
    assert case["kept_state"]["values"]["outputs"]["manifest"]["value"] == "suffix=a85595\n"


def test_a_deposed_object_is_marked_by_its_own_sensitive_values() -> None:
    state = copy.deepcopy(_state(_case("terraform_state_with_a_deposed_object")))
    deposed = state["values"]["root_module"]["resources"][1]
    assert "deposed_key" in deposed
    deposed["sensitive_values"] = {"input": True}
    kept = redact_state("terraform", state, BUILT_IN_REDACTION_POLICY).tree
    assert kept["values"]["root_module"]["resources"][1]["values"]["input"]["reason"] == "declared_sensitive"
    assert kept["values"]["root_module"]["resources"][0]["values"]["input"] == "2"


def test_a_state_written_by_another_tool_version_has_the_same_digest() -> None:
    one = _case("terraform_state_written_by_one_terraform_version")["redacted_state_digest"]
    assert _case("terraform_state_written_by_another_terraform_version")["redacted_state_digest"] == one


def test_an_empty_state_is_read_as_holding_nothing() -> None:
    assert state_marks_and_anchors({"format_version": "1.0"}) == ([], [])
    assert _case("terraform_state_that_is_empty")["kept_state"] == {"format_version": "1.0"}


def test_a_state_and_a_plans_prior_state_are_marked_alike() -> None:
    state = _state(_case("terraform_state_with_a_sensitive_string_output"))
    marks, anchors = state_marks_and_anchors(state)
    plan_marks, plan_anchors = plan_marks_and_anchors({"prior_state": state})
    assert [("prior_state", *mark.path) for mark in marks] == [mark.path for mark in plan_marks]
    assert [("prior_state", *anchor) for anchor in anchors] == plan_anchors


def test_a_redacted_state_is_reported_as_a_state() -> None:
    redacted = redact_state("terraform", {"format_version": "1.0"}, BUILT_IN_REDACTION_POLICY)
    assert redacted.report.subject["kind"] == STATE_SUBJECT == "state"


def test_a_tool_with_no_state_reader_is_refused() -> None:
    with pytest.raises(ValueError, match="no state reader for this tool"):
        redact_state("pulumi", {}, BUILT_IN_REDACTION_POLICY)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("name", "without"),
    [
        ("terraform_state_with_check_results", "terraform_state_with_check_results_left_out"),
        ("terraform_state_with_a_failed_check_holding_a_secret", "terraform_state_with_a_failed_check_left_out"),
    ],
    ids=["captured", "a failed check holding a secret"],
)
def test_check_results_are_left_out_unread_and_digest_as_the_state_without_them(name: str, without: str) -> None:
    case = _case(name)
    assert "checks" in _state(case) and "checks" not in case["kept_state"]
    assert '"checks"' not in case["canonical"]
    assert case["redacted_state_digest"] == _case(without)["redacted_state_digest"]


def test_a_copy_of_a_sensitive_string_inside_check_results_hides_nothing_elsewhere() -> None:
    kept = _case("terraform_state_with_a_failed_check_holding_a_secret")["kept_state"]
    assert kept == _case("terraform_state_with_a_failed_check_left_out")["kept_state"]


def test_a_checks_key_deeper_in_the_state_is_content() -> None:
    state = {"format_version": "1.0", "values": {"outputs": {"checks": {"sensitive": False, "value": "kept"}}}}
    kept = redact_state("terraform", state, BUILT_IN_REDACTION_POLICY).tree
    assert kept["values"]["outputs"]["checks"]["value"] == "kept"
    assert b'"checks"' in canonical_redacted_state_bytes("terraform", kept)


def test_the_keys_a_state_reader_never_reads_are_left_out_of_the_digest_too() -> None:
    assert set(STATE_KEYS_NOT_READ) == set(STATE_MARK_READERS)
    assert all(STATE_KEYS_NOT_READ[tool] <= STATE_EXCLUDED_TOP_LEVEL_KEYS[tool] for tool in STATE_KEYS_NOT_READ)
