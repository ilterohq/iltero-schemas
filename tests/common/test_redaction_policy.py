"""The redaction policy: its recorded form and digest, its paths, and the policy a record writes out."""

from __future__ import annotations

import json

import pytest

from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.common.redaction import RedactionPolicyDocument
from iltero_schemas.redaction.common.credentials import ASSIGNMENT
from iltero_schemas.redaction.common.paths import parse_path
from iltero_schemas.redaction.common.policy import (
    BUILT_IN_REDACTION_POLICY,
    POLICY_ID,
    POLICY_VERSION,
    RedactionPolicy,
    policy_from_document,
)
from tests.conftest import VECTORS

NO_PATHS = BUILT_IN_REDACTION_POLICY


def _policy(extra: tuple[str, ...], allow: tuple[tuple[str, str], ...]) -> RedactionPolicy:
    return RedactionPolicy(tuple(map(parse_path, extra)), tuple((parse_path(path), reason) for path, reason in allow))


def test_a_policy_is_recorded_by_id_version_and_digest() -> None:
    policy = _policy(("a.b",), (("c[*].d", "needed by X"),))
    assert policy.digest.startswith("sha256:")
    recorded = policy.as_dict()
    assert {"credential_words", "key_qualifiers", "key_format_words", "identifier_words", "reuse_min_chars"} <= set(
        recorded
    )
    assert all(set(shape) == {"name", "pattern"} for shape in recorded["value_shapes"])
    assert policy.identity() == {"id": POLICY_ID, "version": POLICY_VERSION, "digest": policy.digest}
    assert policy.as_dict()["additional_paths"] == ["a.b"]
    assert policy.as_dict()["exempt_paths"] == [{"path": "c[*].d", "reason": "needed by X"}]
    assert policy.is_additional_path(("a", "b")) and not policy.is_additional_path(("a",))
    assert policy.exempt_reason(("c", 0, "d")) == "needed by X" and policy.exempt_reason(("c",)) is None
    assert _policy((), ()).digest == NO_PATHS.digest
    assert NO_PATHS.as_dict()["additional_paths"] == []


def test_a_policy_that_also_exempts_more_paths_keeps_its_own_and_leaves_the_project_s_unchanged() -> None:
    project = _policy(("a.b",), (("c[*].d", "needed by X"),))
    digest = project.digest
    widened = project.also_exempting(((parse_path("e.f"), "built in"),))
    assert widened.is_additional_path(("a", "b"))
    assert widened.exempt_reason(("c", 0, "d")) == "needed by X" and widened.exempt_reason(("e", "f")) == "built in"
    assert project.exempt_reason(("e", "f")) is None and project.digest == digest


def test_the_policy_digest_covers_the_named_value_pairs_and_the_assignment_rule() -> None:
    recorded = NO_PATHS.as_dict()
    assert ["name", "value"] in recorded["named_value_pairs"]
    assert recorded["assignment_pattern"] == ASSIGNMENT.pattern


def test_a_shipped_record_written_by_the_iltero_cli_names_the_policy_with_no_configured_paths() -> None:
    record = CAR.model_validate(json.loads((VECTORS / "records" / "iac" / "local_run_deployed.json").read_text()))
    named = {stage.redaction.policy for stage in record.stages.values()}
    assert {(policy.id, policy.version, policy.digest) for policy in named} == {
        (POLICY_ID, POLICY_VERSION, NO_PATHS.digest)
    }


def test_a_policy_lists_its_paths_in_order_so_its_digest_does_not_depend_on_the_configuration_s_order() -> None:
    written = _policy(("b.c", "a.b"), (("z", "last"), ("y", "first")))
    assert [pattern.text for pattern in written.additional_paths] == ["a.b", "b.c"]
    assert written.digest == _policy(("a.b", "b.c"), (("y", "first"), ("z", "last"))).digest


@pytest.mark.parametrize(
    ("extra", "allow"),
    [(("a.b", "a.b"), ()), ((), (("a", "one"), ("a", "two")))],
    ids=["an additional path twice", "an exempt path twice"],
)
def test_a_policy_names_each_path_once(extra: tuple[str, ...], allow: tuple[tuple[str, str], ...]) -> None:
    with pytest.raises(ValueError, match="names each additional and each exempt path once"):
        _policy(extra, allow)


@pytest.mark.parametrize(
    ("extra", "allow"),
    [(tuple(f"p{i}" for i in range(65)), ()), (("a" * 257,), ()), ((), tuple((f"p{i}", "r") for i in range(65)))],
    ids=["too many additional paths", "a path too long", "too many exempt paths"],
)
def test_a_policy_names_a_bounded_number_of_paths_each_of_bounded_length(
    extra: tuple[str, ...], allow: tuple[tuple[str, str], ...]
) -> None:
    with pytest.raises(ValueError, match="at most 64 additional and 64 exempt paths"):
        _policy(extra, allow)


def test_where_two_exempt_paths_match_one_value_the_first_in_code_point_order_gives_the_reason() -> None:
    policy = _policy((), (("rules[0]", "the first rule"), ("rules[*]", "every rule")))
    assert policy.exempt_reason(("rules", 0)) == "every rule"


def test_the_policy_a_record_writes_out_rebuilds_to_the_same_digest() -> None:
    policy = _policy(("tags.owner",), (("ingress[*].cidr_blocks", "public by design"),))
    assert policy_from_document(policy.document()).digest == policy.digest
    assert policy_from_document(BUILT_IN_REDACTION_POLICY.document()) == BUILT_IN_REDACTION_POLICY


def _document(**changes: object) -> RedactionPolicyDocument:
    return RedactionPolicyDocument.model_validate(
        {"id": POLICY_ID, "version": POLICY_VERSION, "additional_paths": [], "exempt_paths": [], **changes}
    )


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"id": "another.policy"}, "a redaction policy this contract does not define"),
        ({"version": "2"}, "a redaction policy this contract does not define"),
        ({"additional_paths": ["b", "a"]}, "lists each additional and each exempt path once, in order"),
        ({"additional_paths": ["a", "a"]}, "lists each additional and each exempt path once, in order"),
        (
            {"exempt_paths": [{"path": "b", "reason": "x"}, {"path": "a", "reason": "y"}]},
            "lists each additional and each exempt path once, in order",
        ),
    ],
    ids=["another id", "another version", "paths out of order", "a path twice", "exempt paths out of order"],
)
def test_a_record_s_policy_that_this_contract_cannot_rebuild_is_refused(
    changes: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        policy_from_document(_document(**changes))


@pytest.mark.parametrize("path", ["", "a..b", "a[x]", "a b", "a" * 257])
def test_a_record_s_policy_names_only_paths_in_the_grammar(path: str) -> None:
    with pytest.raises(ValueError, match="additional_paths"):
        _document(additional_paths=[path])
