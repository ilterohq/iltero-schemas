"""``PolicySourceManifest``: what a directory of hand-written policy may claim."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.assertion import TechnicalAssertion
from iltero_schemas.models.policy_source import (
    API_VERSION,
    KIND,
    MAX_POLICIES,
    PolicyEntry,
    PolicySourceManifest,
)

CHANGE: dict[str, Any] = {
    "title": "A production change happens inside an approved window",
    "assertion": {"id": "ACME.CHANGE.WINDOW_RESPECTED", "version": "1.0.0"},
    "stage": "pre_deploy",
    "target": {"kind": "change"},
    "file": "change_window.rego",
}
RESOURCE: dict[str, Any] = {
    "title": "A bucket's name carries the team that owns it",
    "assertion": {"id": "ACME.AWS.BUCKET_NAMING", "version": "1.0.0"},
    "stage": "plan",
    "target": {"kind": "resource", "provider": "aws", "resource_types": ["aws_s3_bucket"]},
    "file": "naming.rego",
}


def _manifest(*policies: dict[str, Any]) -> dict[str, Any]:
    return {
        "apiVersion": API_VERSION,
        "kind": KIND,
        "policies": [copy.deepcopy(policy) for policy in (policies or (CHANGE,))],
    }


def test_a_source_that_decides_a_process_and_a_state_assertion_validates() -> None:
    manifest = PolicySourceManifest.model_validate(_manifest(CHANGE, RESOURCE))
    assert [entry.assertion.id for entry in manifest.policies] == [
        "ACME.CHANGE.WINDOW_RESPECTED",
        "ACME.AWS.BUCKET_NAMING",
    ]
    assert manifest.policies[1].file == "naming.rego"


def test_it_says_which_document_it_is_the_way_every_authored_document_does() -> None:
    assert (API_VERSION, KIND) == ("iltero.io/v1", "PolicySourceManifest")


def test_a_policy_carries_what_an_assertion_carries_except_the_logic() -> None:
    """The manifest says what is decided; the Rego says how. The two never overlap."""
    entry = set(PolicyEntry.model_fields)
    spec = set(TechnicalAssertion.model_fields["spec"].annotation.model_fields)  # type: ignore[union-attr]
    assert {"stage", "target"} <= entry & spec
    assert "assert_" not in entry and "assert" not in entry
    assert "title" in entry  # what an assertion keeps in its metadata


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"stage": "plan", "target": {"kind": "change"}}, "not valid for target kind"),
        (
            {"stage": "pre_deploy", "target": {"kind": "resource", "provider": "aws", "resource_types": ["a"]}},
            "not valid for target kind",
        ),
        ({"file": "../escape.rego"}, "String should match"),
        ({"file": "nested/policy.rego"}, "String should match"),
        ({"file": "policy.txt"}, "String should match"),
        ({"file": ""}, "String should match"),
        ({"assertion": {"id": "not.an.id", "version": "1.0.0"}}, "String should match"),
        ({"package": "iltero.assertions.acme"}, "Extra inputs are not permitted"),
        ({"title": ""}, "must not be empty"),
        ({"title": "a title\u200bwith a zero-width space"}, "must not contain control characters"),
        ({"title": "x" * 201}, "at most 200"),
    ],
)
def test_a_policy_outside_the_shape_is_refused(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        PolicyEntry.model_validate({**copy.deepcopy(CHANGE), **changes})


def test_two_policies_may_not_decide_one_assertion_at_one_stage() -> None:
    other = {**copy.deepcopy(CHANGE), "file": "other.rego"}
    with pytest.raises(ValidationError, match="decide the same assertion"):
        PolicySourceManifest.model_validate(_manifest(CHANGE, other))


def test_the_same_assertion_may_be_decided_at_another_stage() -> None:
    later = {**copy.deepcopy(CHANGE), "stage": "post_deploy", "target": {"kind": "deployment"},
             "file": "later.rego"}  # fmt: skip
    assert len(PolicySourceManifest.model_validate(_manifest(CHANGE, later)).policies) == 2


def test_two_policies_may_not_be_written_in_one_file() -> None:
    other = {**copy.deepcopy(CHANGE), "assertion": {"id": "ACME.CHANGE.OTHER", "version": "1.0.0"}}
    with pytest.raises(ValidationError, match="written in the same file"):
        PolicySourceManifest.model_validate(_manifest(CHANGE, other))


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"apiVersion": "iltero.io/v2"}, "Input should be"),
        ({"kind": "PolicySource"}, "Input should be"),
        ({"policies": []}, "at least 1 item"),
        ({"policies": [CHANGE] * (MAX_POLICIES + 1)}, f"at most {MAX_POLICIES} items"),
        ({"notes": "hello"}, "Extra inputs are not permitted"),
    ],
)
def test_a_manifest_outside_the_shape_is_refused(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        PolicySourceManifest.model_validate({**_manifest(), **changes})
