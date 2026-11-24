"""Applying a redaction policy again to a redacted document: what it would still hide."""

from __future__ import annotations

import json
from typing import Any

import pytest

from iltero_schemas.models.common.redaction import RedactionPolicyDocument, path_order
from iltero_schemas.redaction.common.apply import RedactionError
from iltero_schemas.redaction.common.marks import Mark
from iltero_schemas.redaction.common.paths import MAX_LISTED_KEY_LENGTH, parse_path
from iltero_schemas.redaction.common.policy import BUILT_IN_REDACTION_POLICY, RedactionPolicy, policy_from_document
from iltero_schemas.redaction.common.problems import (
    MAX_LISTED_PROBLEMS,
    NOT_RECHECKED_REASONS,
    RECHECKED_RULES,
    RedactionProblem,
    redaction_problems,
)
from tests.conftest import VECTORS

URL = "postgres://app:hidden-value@db.internal/app"
CASES = json.loads((VECTORS / "redaction" / "cases.json").read_text(encoding="utf-8"))["cases"]


def _problems(
    document: Any, policy: RedactionPolicy = BUILT_IN_REDACTION_POLICY, **kwargs: Any
) -> list[RedactionProblem]:
    return list(
        redaction_problems(policy, document, marks=kwargs.get("marks", []), anchors=kwargs.get("anchors", [])).problems
    )


@pytest.mark.parametrize("case", [case for case in CASES if "redacted" in case], ids=lambda case: case["name"])
def test_a_tree_redaction_left_holds_nothing_the_rules_would_hide_again(case: dict[str, Any]) -> None:
    policy = policy_from_document(RedactionPolicyDocument.model_validate(case["policy"]))
    marks = [Mark(tuple(mark["path"]), mark["reason"], mark["declared_sensitive"]) for mark in case["marks"]]
    anchors = [tuple(anchor) for anchor in case["anchors"]]
    assert redaction_problems(policy, case["redacted"], marks=marks, anchors=anchors).count == 0


@pytest.mark.parametrize(
    ("document", "problem"),
    [
        ({"password": "left"}, RedactionProblem(("password",), "value", "deny_key")),
        ({"env": [{"name": "API_TOKEN", "value": "left"}]}, RedactionProblem(("env", 0, "value"), "value", "deny_key")),
        ({"args": ["DB_PASS=left"]}, RedactionProblem(("args", 0), "value", "deny_key")),
        ({"url": URL}, RedactionProblem(("url",), "value", "value_shape")),
    ],
    ids=["a credential key", "a name beside the value", "an assignment", "a credential shape"],
)
def test_each_value_a_rule_would_hide_is_a_problem(document: Any, problem: RedactionProblem) -> None:
    assert _problems(document) == [problem]


def test_a_configured_path_is_applied_again_under_each_anchor_only() -> None:
    policy = RedactionPolicy((parse_path("tags.owner"),), ())
    document = {"after": {"tags": {"owner": "x"}}, "tags": {"owner": "y"}}
    assert _problems(document, policy, anchors=[("after",)]) == [
        RedactionProblem(("after", "tags", "owner"), "value", "configured_path")
    ]


def test_a_tool_s_mark_on_a_value_left_in_place_is_a_problem_and_on_a_marker_is_not() -> None:
    marker = {"__redacted": True, "reason": "declared_sensitive", "present": True, "type": "string"}
    marks = [Mark(("a",), "declared_sensitive", True), Mark(("b",), "provider_configuration", False)]
    assert _problems({"a": "left", "b": marker}, marks=marks) == [
        RedactionProblem(("a",), "value", "declared_sensitive")
    ]


def test_a_copy_of_a_marked_value_is_never_looked_for() -> None:
    marks = [Mark(("a",), "declared_sensitive", True)]
    assert _problems({"a": "the-marked-value", "copy": "the-marked-value"}, marks=marks) == [
        RedactionProblem(("a",), "value", "declared_sensitive")
    ]


def test_an_object_holding_a_key_shaped_like_a_credential_is_listed_once_and_its_value_is_not_read() -> None:
    document = {"by_name": {"DB_PASSWORD=hunter2": {"url": URL}, "team": {"url": URL}}}
    assert _problems(document) == [
        RedactionProblem(("by_name",), "key", "credential_shaped_key"),
        RedactionProblem(("by_name", "team", "url"), "value", "value_shape"),
    ]


@pytest.mark.parametrize(
    "resembling",
    [
        {"__redacted": True, "reason": "deny_key", "present": True, "type": "string", "note": URL},
        {"__redacted": True, "reason": URL, "present": True, "type": "string"},
        {"__unknown": True, "reason": "known_after_deploy", "present": True, "note": URL},
    ],
    ids=[
        "a marker with one more field",
        "a marker with a reason no rule gives",
        "an unknown marker with one more field",
    ],
)
def test_an_object_that_only_resembles_a_marker_is_read(resembling: dict[str, Any]) -> None:
    assert [problem.rule for problem in _problems({"x": resembling})] == ["value_shape"]


def test_problems_are_listed_in_path_order_and_capped_with_a_count_of_all() -> None:
    found = redaction_problems(
        BUILT_IN_REDACTION_POLICY, {"b": [URL] * (MAX_LISTED_PROBLEMS + 5), "a": URL}, marks=[], anchors=[]
    )
    assert found.count == MAX_LISTED_PROBLEMS + 6
    assert len(found.problems) == MAX_LISTED_PROBLEMS and found.problems[0].path == ("a",)
    assert [path_order(problem.path) for problem in found.problems] == sorted(
        path_order(problem.path) for problem in found.problems
    )


def test_a_long_key_on_a_listed_path_is_cut() -> None:
    key = "k" * (MAX_LISTED_KEY_LENGTH + 10)
    (problem,) = _problems({key: {"password": "left"}})
    assert problem.path == ("k" * MAX_LISTED_KEY_LENGTH, "password")


def test_paths_with_indexes_and_keys_at_one_depth_sort_without_comparing_a_number_with_text() -> None:
    assert sorted([("a", "b"), (0,), ("a", 1), (1, "x")], key=path_order) == [(0,), (1, "x"), ("a", 1), ("a", "b")]


def test_a_document_nested_deeper_than_a_check_reads_is_refused() -> None:
    document: Any = "x"
    for _ in range(70):
        document = [document]
    with pytest.raises(RedactionError, match="nests deeper than"):
        _problems(document)


def test_the_rules_applied_again_and_those_never_applied_again_are_named() -> None:
    assert set(RECHECKED_RULES) == {
        "declared_sensitive",
        "provider_configuration",
        "provisioner_configuration",
        "unplanned_configuration",
        "configured_path",
        "deny_key",
        "value_shape",
        "credential_shaped_key",
    }
    assert set(NOT_RECHECKED_REASONS) == {"sensitive_value_reuse", "field_not_read"}


def test_a_value_left_where_the_tool_flags_a_value_known_only_after_the_deployment_is_read() -> None:
    marks = [Mark(("after", "password"), "known_after_deploy", False), Mark(("whole",), "known_after_deploy", False)]
    document = {"after": {"password": URL}, "whole": {"token": "left"}}
    assert _problems(document, marks=marks) == [
        RedactionProblem(("after", "password"), "value", "deny_key"),
        RedactionProblem(("whole", "token"), "value", "deny_key"),
    ]


def test_a_marker_whose_type_is_not_a_json_type_name_is_read() -> None:
    resembling = {"__redacted": True, "reason": "deny_key", "present": True, "type": "secret", "note": URL}
    assert [problem.rule for problem in _problems({"x": resembling})] == ["value_shape"]
