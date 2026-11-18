"""``PolicySource``: what a directory of hand-written policy may claim."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.common.assertion import TechnicalAssertion
from iltero_schemas.models.common.policy_source import (
    API_VERSION,
    KIND,
    MAX_POLICIES,
    PolicyEntry,
    PolicySource,
)

CHANGE: dict[str, Any] = {
    "title": "A production change happens inside an approved window",
    "assertion": {"id": "ACME.COMMON.CHANGE.WINDOW.WINDOW_RESPECTED", "version": "1.0.0"},
    "stage": "pre_deploy",
    "target": {"kind": "change"},
    "file": "change_window.rego",
}
RESOURCE: dict[str, Any] = {
    "title": "A bucket's name carries the team that owns it",
    "assertion": {"id": "ACME.IAC.RESOURCE.AWS.S3.BUCKET_NAMING", "version": "1.0.0"},
    "stage": "plan",
    "target": {
        "kind": "resource",
        "resources": [{"tool": "terraform", "provider": "aws", "resource_types": ["aws_s3_bucket"]}],
    },
    "file": "naming.rego",
}


def _source(*policies: dict[str, Any]) -> dict[str, Any]:
    return {
        "apiVersion": API_VERSION,
        "kind": KIND,
        "metadata": {"name": "acme-policies"},
        "spec": {"policies": [copy.deepcopy(policy) for policy in (policies or (CHANGE,))]},
    }


def test_a_source_that_decides_a_process_and_a_state_assertion_validates() -> None:
    source = PolicySource.model_validate(_source(CHANGE, RESOURCE))
    assert [entry.assertion.id for entry in source.spec.policies] == [
        "ACME.COMMON.CHANGE.WINDOW.WINDOW_RESPECTED",
        "ACME.IAC.RESOURCE.AWS.S3.BUCKET_NAMING",
    ]
    assert source.spec.policies[1].file == "naming.rego"


def test_it_says_which_document_it_is_the_way_every_authored_document_does() -> None:
    assert (API_VERSION, KIND) == ("iltero.com/v1", "PolicySource")


def test_a_policy_carries_what_an_assertion_carries_except_the_logic() -> None:
    """The policy source says what is decided; the Rego says how. The two never overlap."""
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
            {
                "assertion": {"id": "ACME.IAC.RESOURCE.AWS.S3.CASE", "version": "1.0.0"},
                "stage": "pre_deploy",
                "target": {
                    "kind": "resource",
                    "resources": [{"tool": "terraform", "provider": "aws", "resource_types": ["a"]}],
                },
            },
            "not valid for target kind",
        ),
        (
            {
                "assertion": {"id": "ACME.IMAGE.RESOURCE.AWS.S3.CASE", "version": "1.0.0"},
                "stage": "plan",
                "target": RESOURCE["target"],
            },
            "not valid for target kind",
        ),
        ({"assertion": {"id": "ACME.HELM.CHANGE.WINDOW.CASE", "version": "1.0.0"}}, "names its change type"),
        ({"assertion": {"id": "ACME.COMMON.DEPLOYMENT.WINDOW.CASE", "version": "1.0.0"}}, "for target kind change"),
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
        PolicySource.model_validate(_source(CHANGE, other))


def test_the_same_assertion_may_be_decided_at_another_stage() -> None:
    later = {**copy.deepcopy(RESOURCE), "stage": "runtime", "file": "later.rego"}
    assert len(PolicySource.model_validate(_source(RESOURCE, later)).spec.policies) == 2


def test_two_policies_may_not_be_written_in_one_file() -> None:
    other = {**copy.deepcopy(CHANGE), "assertion": {"id": "ACME.COMMON.CHANGE.WINDOW.OTHER", "version": "1.0.0"}}
    with pytest.raises(ValidationError, match="written in the same file"):
        PolicySource.model_validate(_source(CHANGE, other))


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"apiVersion": "iltero.io/v1"}, "Input should be"),
        ({"kind": "PolicySourceManifest"}, "Input should be"),
        ({"spec": {"policies": []}}, "at least 1 item"),
        ({"spec": {"policies": [CHANGE] * (MAX_POLICIES + 1)}}, f"at most {MAX_POLICIES} items"),
        ({"notes": "hello"}, "Extra inputs are not permitted"),
        ({"metadata": {}}, "Field required"),
        ({"metadata": {"name": "a\nb"}}, "String should match pattern"),
        ({"metadata": {"name": "Acme-Policies"}}, "String should match pattern"),
        ({"metadata": {"name": " acme"}}, "String should match pattern"),
        ({"metadata": {"name": "acme-"}}, "String should match pattern"),
        ({"metadata": {"name": "аcme"}}, "String should match pattern"),
        ({"metadata": {"name": "a" * 64}}, "String should match pattern"),
    ],
)
def test_a_policy_source_outside_the_shape_is_refused(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        PolicySource.model_validate({**_source(), **changes})


def test_a_hand_written_policy_names_no_resources() -> None:
    scoped = {**CHANGE, "target": {"kind": "change", "resources": [{"provider": "aws", "kinds": ["kms_key"]}]}}
    with pytest.raises(ValidationError, match="names no resources: no compiler writes its scope guard"):
        PolicySource.model_validate(_source(scoped))
