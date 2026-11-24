"""Applying a redaction policy to a tree: hidden values become markers, and the report names every path touched."""

from __future__ import annotations

import copy
import json
import time
from typing import Any

import pytest

from iltero_schemas.canonical.common.encoding import digest_of
from iltero_schemas.models.common.redaction import MAX_REPORTED_PATH_DEPTH
from iltero_schemas.redaction.common import apply
from iltero_schemas.redaction.common.apply import RedactionError, redact
from iltero_schemas.redaction.common.marks import Mark
from iltero_schemas.redaction.common.paths import parse_path
from iltero_schemas.redaction.common.policy import RedactionPolicy

PLAIN = RedactionPolicy((), ())
UNKNOWN = {"__unknown": True, "reason": "known_after_deploy", "present": True}


def _policy(extra: tuple[str, ...] = (), allow: tuple[tuple[str, str], ...] = ()) -> RedactionPolicy:
    return RedactionPolicy(tuple(map(parse_path, extra)), tuple((parse_path(path), reason) for path, reason in allow))


def _redacted(reason: str, kind: str = "string", present: bool = True) -> dict[str, Any]:
    return {"__redacted": True, "reason": reason, "present": present, "type": kind}


def test_tool_marks_become_markers_and_absent_unknowns_are_added() -> None:
    tree = {"after": {"password": "p", "name": "n"}}
    marks = [
        Mark(("after", "password"), "declared_sensitive", declared_sensitive=True),
        Mark(("after", "arn"), "known_after_deploy", declared_sensitive=False),
    ]
    result = redact(tree, marks, PLAIN, subject="observation")
    assert result.tree == {"after": {"password": _redacted("declared_sensitive"), "name": "n", "arn": UNKNOWN}}
    assert result.report.redacted == [
        {"path": ["after", "password"], "reason": "declared_sensitive", "value_change": None}
    ]
    assert result.report.unknown == [["after", "arn"]]
    assert result.report.subject == {"kind": "observation", "digest": digest_of(result.tree)}


def test_a_present_value_marked_unknown_is_replaced() -> None:
    result = redact(
        {"a": {"id": "old"}}, [Mark(("a", "id"), "known_after_deploy", declared_sensitive=False)], PLAIN, subject="s"
    )
    assert result.tree == {"a": {"id": UNKNOWN}}


def test_denied_keys_hide_strings_and_containers_holding_one_but_never_numbers_or_booleans() -> None:
    tree = {
        "db_password": {"nested": "p"},
        "tokens": ["t"],
        "user_data": None,
        "password_length": 16,
        "secret": True,
        "master_user_secret": {"enabled": True},
    }
    result = redact(tree, [], PLAIN, subject="s")
    assert result.tree["db_password"] == _redacted("deny_key", "object")
    assert result.tree["tokens"] == _redacted("deny_key", "array")
    assert result.tree["user_data"] is None
    assert result.tree["password_length"] == 16 and result.tree["secret"] is True
    assert result.tree["master_user_secret"] == {"enabled": True}


def test_values_that_look_like_credentials_are_hidden_wherever_they_are() -> None:
    tree = {
        "script": "export AWS_ACCESS_KEY_ID=" + "AKIA" + "IOSFODNN7EXAMPLE",
        "items": ["-----BEGIN RSA " + "PRIVATE KEY-----"],
    }
    result = redact(tree, [], PLAIN, subject="s")
    assert result.tree["script"] == _redacted("value_shape")
    assert result.tree["items"] == [_redacted("value_shape")]
    assert [r["path"] for r in result.report.redacted] == [["items", 0], ["script"]]


def test_a_value_a_tool_marked_sensitive_is_hidden_wherever_it_is_copied() -> None:
    tree = {"r": {"after": {"tags": {"login": "copied-login-value"}, "tags_all": {"login": "copied-login-value"}}}}
    marks = [Mark(("r", "after", "tags", "login"), "declared_sensitive", declared_sensitive=True)]
    result = redact(tree, marks, PLAIN, subject="s")
    assert result.tree["r"]["after"]["tags"]["login"] == _redacted("declared_sensitive")
    assert result.tree["r"]["after"]["tags_all"]["login"] == _redacted("sensitive_value_reuse")


def test_a_marked_container_outside_resource_values_does_not_seed_reuse() -> None:
    tree = {
        "configuration": {"expression": {"references": ["aws_instance.web.value", "aws_instance.web"]}},
        "resources": [
            {"address": "aws_instance.web", "after": {"value": "the-real-value", "copy": "aws_instance.web"}}
        ],
    }
    marks = [
        Mark(("configuration", "expression"), "declared_sensitive", declared_sensitive=True),
        Mark(("resources", 0, "after", "value"), "declared_sensitive", declared_sensitive=True),
    ]
    result = redact(tree, marks, PLAIN, subject="s", anchors=[("resources", 0, "after")])
    assert result.tree["resources"][0]["address"] == "aws_instance.web"
    assert result.tree["resources"][0]["after"]["copy"] == "aws_instance.web"
    # Under an anchor, a marked container does seed: its strings are values.
    marks.append(Mark(("resources", 0, "after"), "declared_sensitive", declared_sensitive=True))
    result = redact(tree, marks, PLAIN, subject="s", anchors=[("resources", 0, "after")])
    assert result.tree["resources"][0]["address"] == _redacted("sensitive_value_reuse")


def test_only_a_value_the_tool_declared_sensitive_is_hidden_where_it_is_copied() -> None:
    tree = {"r": {"after": {"a": "first-long-value", "c": "other-long-value"}}}
    declared = Mark(("r", "after", "a"), "provider_configuration", declared_sensitive=True)
    undeclared = Mark(("r", "after", "c"), "provider_configuration", declared_sensitive=False)
    result = redact(
        {**tree, "copies": ["first-long-value", "other-long-value"]},
        [declared, undeclared],
        PLAIN,
        subject="s",
        anchors=[("r", "after")],
    )
    # The rule follows the mark's flag, whatever its reason says.
    assert result.tree["copies"] == [_redacted("sensitive_value_reuse"), "other-long-value"]
    assert result.tree["r"]["after"]["c"] == _redacted("provider_configuration")


def test_a_sensitive_string_is_hidden_inside_a_longer_string() -> None:
    tree = {"r": {"after": {"password": "hunter2-long-enough", "note": "conn --password hunter2-long-enough now"}}}
    result = redact(
        tree, [Mark(("r", "after", "password"), "declared_sensitive", declared_sensitive=True)], PLAIN, subject="s"
    )
    assert result.tree["r"]["after"]["note"] == _redacted("sensitive_value_reuse")


def test_strings_known_sensitive_elsewhere_are_hidden_too() -> None:
    result = redact(
        {"copy": "value-from-a-variable"}, [], PLAIN, subject="s", known_sensitive=["value-from-a-variable"]
    )
    assert result.tree["copy"] == _redacted("sensitive_value_reuse")


def test_short_marked_values_are_not_hidden_by_equality() -> None:
    tree = {"a": {"port": "5432"}, "b": {"port": "5432"}}
    result = redact(tree, [Mark(("a", "port"), "declared_sensitive", declared_sensitive=True)], PLAIN, subject="s")
    assert result.tree["b"]["port"] == "5432"


def test_configured_paths_apply_under_every_anchor_and_allow_paths_keep_one_value() -> None:
    policy = _policy(("tags.owner",), (("access_key", "needed to check the key id format"),))
    tree = {
        "resources": [
            {"after": {"tags": {"owner": "x"}, "access_key": "AK-visible", "secret_key": "s"}},
            {"before": {"tags": {"owner": "y"}}, "tags": {"owner": "not under an anchor"}},
        ]
    }
    anchors = [("resources", 0, "after"), ("resources", 1, "before")]
    result = redact(tree, [], policy, subject="s", anchors=anchors)
    assert result.tree["resources"][0]["after"]["tags"]["owner"] == _redacted("configured_path")
    assert result.tree["resources"][1]["before"]["tags"]["owner"] == _redacted("configured_path")
    assert result.tree["resources"][1]["tags"]["owner"] == "not under an anchor"
    assert result.tree["resources"][0]["after"]["access_key"] == "AK-visible"
    assert result.tree["resources"][0]["after"]["secret_key"] == _redacted("deny_key")
    assert result.report.exempted == [
        {"path": ["resources", 0, "after", "access_key"], "reason": "needed to check the key id format"}
    ]


def test_an_allow_path_never_overrides_a_tool_mark() -> None:
    policy = _policy((), (("password", "needed"),))
    tree = {"after": {"password": "p"}}
    result = redact(
        tree,
        [Mark(("after", "password"), "declared_sensitive", declared_sensitive=True)],
        policy,
        subject="s",
        anchors=[("after",)],
    )
    assert result.tree["after"]["password"] == _redacted("declared_sensitive") and result.report.exempted == []


def test_an_allow_path_covers_only_the_named_value() -> None:
    policy = _policy((), (("inner", "everything is needed"),))
    tree = {"after": {"inner": {"secret": "s", "plain": "v"}}}
    result = redact(tree, [], policy, subject="s", anchors=[("after",)])
    assert result.tree["after"]["inner"] == {"secret": _redacted("deny_key"), "plain": "v"}
    assert result.report.exempted == [{"path": ["after", "inner"], "reason": "everything is needed"}]


def test_a_value_both_sensitive_and_unknown_is_unknown_and_its_mark_is_reported() -> None:
    marks = [
        Mark(("after", "secret"), "declared_sensitive", declared_sensitive=True),
        Mark(("after", "secret"), "known_after_deploy", declared_sensitive=False),
    ]
    for ordering in (marks, marks[::-1]):
        result = redact({"after": {}}, ordering, PLAIN, subject="s")
        assert result.tree["after"]["secret"] == UNKNOWN
        assert result.report.unknown == [["after", "secret"]]
        assert result.report.redacted == [
            {"path": ["after", "secret"], "reason": "declared_sensitive", "value_change": None}
        ]


# How much longer four times the input may take. Linear work takes about four times as long, and
# quadratic work about sixteen. The ratio, not a wall-clock limit, keeps a slow runner from failing the test.
_GROWTH_LIMIT = 10


def _redaction_seconds(count: int) -> float:
    """The fastest of three redactions of ``count`` resources, each with a mark, an unknown and an anchor."""
    tree = {"resources": [{"after": {"a": {"b": "x" * 10}, "secret": f"hidden-value-{i}"}} for i in range(count)]}
    marks = [
        Mark(("resources", i, "after", "secret"), "declared_sensitive", declared_sensitive=True) for i in range(count)
    ]
    marks += [
        Mark(("resources", i, "after", "arn"), "known_after_deploy", declared_sensitive=False) for i in range(count)
    ]
    anchors = [("resources", i, "after") for i in range(count)]
    fastest = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        result = redact(tree, marks, PLAIN, subject="s", anchors=anchors)
        fastest = min(fastest, time.perf_counter() - started)
    assert len(result.report.redacted) == count and len(result.report.unknown) == count
    return fastest


def test_a_large_tree_with_many_marks_and_anchors_redacts_in_linear_time() -> None:
    small = _redaction_seconds(500)
    large = _redaction_seconds(2000)
    assert large < _GROWTH_LIMIT * small, (small, large)


def test_marks_under_a_hidden_parent_are_still_reported() -> None:
    tree = {"user_data": {"password": "p"}}
    result = redact(
        tree, [Mark(("user_data", "password"), "declared_sensitive", declared_sensitive=True)], PLAIN, subject="s"
    )
    assert result.tree["user_data"] == _redacted("deny_key", "object")
    assert result.report.redacted == [
        {"path": ["user_data"], "reason": "deny_key", "value_change": None},
        {"path": ["user_data", "password"], "reason": "declared_sensitive", "value_change": None},
    ]


def test_the_input_is_not_modified_and_the_report_carries_no_value() -> None:
    tree = {"after": {"password": "the-secret-value", "arn_holder": {}}}
    before = copy.deepcopy(tree)
    result = redact(
        tree, [Mark(("after", "arn_holder", "arn"), "known_after_deploy", declared_sensitive=False)], PLAIN, subject="s"
    )
    assert tree == before
    assert "the-secret-value" not in json.dumps(result.tree) + json.dumps(result.report.as_dict())
    assert result.report.as_dict()["policy"]["id"] == "iltero.redaction"


@pytest.mark.parametrize(
    "entry",
    [
        {"name": "API_TOKEN", "value": "plain-text-1"},
        {"name": "db.password", "value": "plain-text-1", "type": "string"},
        {"namespace": "aws:elasticbeanstalk:application:environment", "name": "SECRET_KEY", "value": "plain-text-1"},
        {"key": "db_password", "value": "plain-text-1", "propagate_at_launch": True},
        {"Key": "ApiToken", "Value": "plain-text-1"},
        {"ParameterKey": "DbPassword", "ParameterValue": "plain-text-1"},
    ],
    ids=[
        "a Kubernetes env entry",
        "a Helm set block",
        "a Beanstalk setting",
        "a tag",
        "a capitalised pair",
        "a CloudFormation parameter",
    ],
)
def test_a_value_is_judged_by_the_name_written_beside_it(entry: dict[str, Any]) -> None:
    result = redact({"settings": [entry]}, (), PLAIN, subject="observation")
    value_key = next(key for key in entry if key.lower() in {"value", "parametervalue"})
    assert result.tree["settings"][0][value_key] == _redacted("deny_key")
    assert result.report.redacted == [{"path": ["settings", 0, value_key], "reason": "deny_key", "value_change": None}]


def test_a_value_named_as_a_setting_is_kept_and_a_name_alone_is_never_hidden() -> None:
    tree = {"env": [{"name": "LOG_LEVEL", "value": "debug"}, {"name": "API_TOKEN"}, {"name": "x", "other": "y"}]}
    assert redact(tree, (), PLAIN, subject="observation").tree == tree


@pytest.mark.parametrize(
    "text",
    ["DB_PASS=plain", "CREDENTIALS=plain", "SESSION_KEY=plain", "PASSPHRASE=plain", "RUN |2 A=1 DB_PASS=plain make"],
)
def test_a_string_that_assigns_a_credential_is_hidden(text: str) -> None:
    result = redact({"env": [text]}, (), PLAIN, subject="observation")
    assert result.tree == {"env": [_redacted("deny_key")]}


@pytest.mark.parametrize("text", ["PATH=/usr/bin", "POSTGRES_PASSWORD_FILE=/run/secrets/db", "DB_PASSWORD=", "a == b"])
def test_a_string_that_assigns_a_setting_or_nothing_is_kept(text: str) -> None:
    assert redact({"env": [text]}, (), PLAIN, subject="observation").tree == {"env": [text]}


def test_a_container_named_as_a_credential_is_hidden_whole() -> None:
    result = redact({"env": [{"name": "DB_PASSWORD", "value": {"a": "x"}}]}, (), PLAIN, subject="observation")
    assert result.tree == {"env": [{"name": "DB_PASSWORD", "value": _redacted("deny_key", "object")}]}


def test_an_allow_path_keeps_a_value_named_or_assigned_as_a_credential() -> None:
    tree = {"after": {"env": [{"name": "API_TOKEN", "value": "kept-1"}], "args": ["DB_PASS=kept-2"]}}
    policy = _policy(allow=(("env[*].value", "a test value"), ("args[*]", "a test value")))
    assert redact(tree, (), policy, subject="observation", anchors=(("after",),)).tree == tree


def test_a_key_that_names_a_file_is_still_hidden_when_its_value_is_a_private_key() -> None:
    pem = "-----BEGIN RSA " + "PRIVATE KEY-----\nabc"
    assert redact({"private_key_file": pem}, (), PLAIN, subject="observation").tree == {
        "private_key_file": _redacted("value_shape")
    }


def _object_redaction_seconds(count: int) -> float:
    """The fastest of three redactions of one object with ``count`` keys and one named value."""
    tree = {"env": {f"KEY_{i}": "value" for i in range(count)} | {"name": "DB_PASSWORD", "value": "v"}}
    fastest = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        redact(tree, (), PLAIN, subject="s")
        fastest = min(fastest, time.perf_counter() - started)
    return fastest


def test_an_object_with_many_keys_is_redacted_in_linear_time() -> None:
    small, large = _object_redaction_seconds(5_000), _object_redaction_seconds(20_000)
    assert large < _GROWTH_LIMIT * small, (small, large)


def test_redact_refuses_a_key_shaped_like_a_credential_naming_only_the_path_before_it() -> None:
    with pytest.raises(RedactionError, match="an object key at tags is shaped like a credential") as raised:
        redact({"tags": {"DB_PASSWORD=hunter2": "x"}}, [], PLAIN, subject="s")
    assert "hunter2" not in str(raised.value)


def test_redact_refuses_a_mark_on_a_path_through_a_key_shaped_like_a_credential() -> None:
    marks = [Mark(("tags", "DB_PASSWORD=hunter2"), "known_after_deploy", False)]
    with pytest.raises(RedactionError, match="an object key at tags is shaped like a credential"):
        redact({"tags": {}}, marks, PLAIN, subject="s")


def test_redact_refuses_a_tree_whose_report_would_list_more_paths_than_a_report_holds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A report's real bound is a million paths; a smaller one shows the rule without a tree that large.
    monkeypatch.setattr(apply, "MAX_REPORTED_PATHS", 3)
    tree = {"items": [{"password": "p"} for _ in range(4)]}
    with pytest.raises(RedactionError, match="more than the 3 paths one report lists"):
        redact(tree, (), PLAIN, subject="s")


def test_redact_refuses_a_tree_whose_report_would_list_a_path_deeper_than_a_report_holds() -> None:
    tree: Any = {"password": "p"}
    for _ in range(MAX_REPORTED_PATH_DEPTH):
        tree = {"a": tree}
    with pytest.raises(RedactionError, match="a path deeper than"):
        redact(tree, (), PLAIN, subject="s")
