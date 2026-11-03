"""The event contract: reasons closed per status, an identity exactly when there was a subject, a digest per verdict."""

from __future__ import annotations

import copy
import json
from typing import Any, get_args

import pytest
from pydantic import ValidationError

from iltero_schemas.assertions import APPLIED_PLAN_MATCHES_EVALUATED_PLAN_ID, BUILT_INS
from iltero_schemas.models.ci import CI_SYSTEMS
from iltero_schemas.models.event import (
    NO_EVALUATOR_REASONS,
    POLICY_STATUSES,
    STATUS_REASONS,
    STATUS_SEVERITY,
    AssuranceEvent,
    Bundle,
)
from iltero_schemas.models.fields import Identity, Status
from iltero_schemas.models.subjects import subject_key
from tests.conftest import ARNS, VECTORS

VECTOR: dict[str, Any] = json.loads((VECTORS / "events" / "plan_pass.json").read_text(encoding="utf-8"))


def _event(**changes: Any) -> dict[str, Any]:
    document = copy.deepcopy(VECTOR)
    for dotted, value in changes.items():
        node = document
        parts = dotted.split(".")
        for key in parts[:-1]:
            node = node[key]
        node[parts[-1]] = value
    return document


def test_the_vector_validates() -> None:
    event = AssuranceEvent.model_validate(VECTOR)
    assert event.evaluation.status == "pass" and event.subject.key is not None
    assert event.subject.identities[0].value == "aws_db_instance.payments"


def test_policy_statuses_are_the_four_the_output_contract_allows() -> None:
    assert POLICY_STATUSES == {"pass", "fail", "unknown", "not_applicable"}
    assert set(STATUS_REASONS) == {"pass", "fail", "unknown", "not_applicable", "not_evaluated", "error"}


@pytest.mark.parametrize(
    ("status", "reason"),
    [(status, reason) for status, reasons in STATUS_REASONS.items() for reason in sorted(reasons)],
)
def test_every_listed_reason_is_accepted_for_its_status(status: str, reason: str) -> None:
    changes: dict[str, Any] = {"evaluation.status": status, "evaluation.status_reason": reason}
    if reason == "no_subject_in_scope":
        changes.update({"subject.key": None, "subject.identities": [], "provenance.input_digest": None})
    if reason in NO_EVALUATOR_REASONS:
        changes.update({"provenance.evaluator": None, "provenance.bundle": None})
    AssuranceEvent.model_validate(_event(**changes))


@pytest.mark.parametrize(
    ("status", "reason", "message"),
    [
        ("pass", "redacted", "not a reason for status 'pass'"),
        ("fail", "redacted", "not a reason for status 'fail'"),
        ("unknown", "evaluator_crash", "not a reason for status 'unknown'"),
        ("error", "redacted", "not a reason for status 'error'"),
        ("unknown", None, "needs a status_reason"),
        ("error", None, "needs a status_reason"),
        ("done", None, "Input should be"),
    ],
)
def test_a_reason_outside_its_status_is_refused(status: str, reason: str | None, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        AssuranceEvent.model_validate(_event(**{"evaluation.status": status, "evaluation.status_reason": reason}))


def test_a_subject_has_no_key_and_no_identity_exactly_when_no_subject_was_in_scope() -> None:
    without: list[dict[str, Any]] = [{"subject.identities": []}, {"subject.key": None}]
    for changes in without:
        with pytest.raises(ValidationError, match="no key and no identity exactly when"):
            AssuranceEvent.model_validate(_event(**changes))
    with pytest.raises(ValidationError, match="no key and no identity exactly when"):
        AssuranceEvent.model_validate(
            _event(**{"evaluation.status": "not_applicable", "evaluation.status_reason": "no_subject_in_scope"})
        )


@pytest.mark.parametrize(
    ("kind", "identity"),
    [
        ("resource", {"scheme": "iltero_unit", "value": "root"}),
        ("change", {"scheme": "terraform_address", "value": "aws_db_instance.payments", "scope": {"unit": "root"}}),
    ],
    ids=["a resource named by a unit", "a change named by an address"],
)
def test_an_event_subject_is_named_by_its_local_identity(kind: str, identity: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match="exactly one identity in"):
        AssuranceEvent.model_validate(_event(**{"subject.kind": kind, "subject.identities": [identity]}))


def test_an_event_subjects_key_is_the_digest_of_its_identity_in_the_events_unit() -> None:
    with pytest.raises(ValidationError, match="the digest of its kind and its local identity"):
        AssuranceEvent.model_validate(_event(**{"subject.key": "sha256:" + "0" * 64}))
    with pytest.raises(ValidationError, match="its own unit"):
        AssuranceEvent.model_validate(_event(**{"provenance.run.unit": "network"}))


def test_a_policy_verdict_names_its_input() -> None:
    with pytest.raises(ValidationError, match="names the input"):
        AssuranceEvent.model_validate(_event(**{"provenance.input_digest": None}))
    AssuranceEvent.model_validate(
        _event(
            **{
                "evaluation.status": "not_evaluated",
                "evaluation.status_reason": "evaluator_unavailable",
                "provenance.input_digest": None,
                "provenance.evaluator": None,
                "provenance.bundle": None,
            }
        )
    )


def test_only_a_check_no_evaluator_ran_may_omit_the_evaluator() -> None:
    absent = {"provenance.evaluator": None, "provenance.bundle": None}
    for reason in sorted(NO_EVALUATOR_REASONS):
        status = "not_applicable" if reason == "no_subject_in_scope" else "not_evaluated"
        changes: dict[str, Any] = {**absent, "evaluation.status": status, "evaluation.status_reason": reason}
        if reason == "no_subject_in_scope":
            changes.update({"subject.key": None, "subject.identities": [], "provenance.input_digest": None})
        AssuranceEvent.model_validate(_event(**changes))
    with pytest.raises(ValidationError, match="names the evaluator that ran it"):
        AssuranceEvent.model_validate(_event(**absent))
    with pytest.raises(ValidationError, match="a bundle is named exactly when"):
        AssuranceEvent.model_validate(
            _event(
                **{
                    "evaluation.status": "not_evaluated",
                    "evaluation.status_reason": "evaluator_unavailable",
                    "provenance.evaluator": None,
                }
            )
        )
    with pytest.raises(ValidationError, match="a bundle is named exactly when"):
        AssuranceEvent.model_validate(_event(**{"provenance.bundle": None}))


def test_a_key_beyond_the_submission_is_refused() -> None:
    document = _event()
    document["anything_else"] = "x"
    with pytest.raises(ValidationError, match="anything_else"):
        AssuranceEvent.model_validate(document)


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        ("evaluation.observations", {"a": {"b": {"c": {"d": {"e": 1}}}}}, "nest deeper"),
        ("evaluation.observations", {"a": "b\x00"}, "control characters"),
        ("evaluation.observations", {"a": "x" * (512 * 1024)}, "at most 524288 bytes"),
        ("evaluation.policy_reason", "\u00e9" * 1500, "at most 2048 bytes"),
        ("evaluation.policy_reason", "a\u202eb", "control characters"),
        ("evaluation.status_detail", "x" * 2049, "at most 2048 characters"),
        ("evaluation.status_detail", "a\x1fb", "control characters"),
        ("provenance.compiler.contract_digest", None, "installed contract package has a digest"),
    ],
)
def test_what_the_policy_or_the_runner_said_is_bounded(path: str, value: Any, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        AssuranceEvent.model_validate(_event(**{path: value}))


def test_an_editable_contract_install_may_have_no_digest() -> None:
    AssuranceEvent.model_validate(
        _event(**{"provenance.compiler.contract_digest": None, "provenance.compiler.install": "editable"})
    )


# The subject kind an infrastructure change's check at each stage may be about: resources at the plan stage and at
# runtime, the change before deployment, the deployment after it.
_KIND_AT = {"plan": "resource", "runtime": "resource", "pre_deploy": "change"}


def _at(stage: str, **changes: Any) -> dict[str, Any]:
    """The vector's event moved to ``stage``, about a subject its assertions there can target."""
    kind = _KIND_AT.get(stage, "deployment")
    if kind == "resource":
        return _event(**{"evaluation.stage": stage}, **changes)
    unit = Identity(scheme="iltero_unit", value="root")
    subject = {
        "subject.kind": kind,
        "subject.identities": [{"scheme": "iltero_unit", "value": "root", "scope": None}],
        "subject.key": subject_key(kind, [unit]),
    }
    return _event(**{"evaluation.stage": stage}, **subject, **changes)


@pytest.mark.parametrize("stage", ["pre_deploy", "runtime"])
@pytest.mark.parametrize("source", ["server", "local_file", "none"])
def test_a_check_at_a_stage_that_reads_server_facts_says_where_they_came_from(stage: str, source: str) -> None:
    AssuranceEvent.model_validate(_at(stage, **{"provenance.facts_source": source}))
    with pytest.raises(ValidationError, match="facts_source is present exactly when"):
        AssuranceEvent.model_validate(_at(stage, **{"provenance.facts_source": None}))


@pytest.mark.parametrize("stage", ["plan", "post_deploy", "post_verify"])
def test_a_check_at_a_stage_that_reads_no_server_facts_names_no_facts_source(stage: str) -> None:
    AssuranceEvent.model_validate(_at(stage))
    with pytest.raises(ValidationError, match="facts_source is present exactly when"):
        AssuranceEvent.model_validate(_at(stage, **{"provenance.facts_source": "server"}))


def test_facts_source_is_always_stated() -> None:
    document = _event()
    del document["provenance"]["facts_source"]
    with pytest.raises(ValidationError, match="facts_source"):
        AssuranceEvent.model_validate(document)


def test_an_event_names_no_ci_context() -> None:
    document = _event()
    document["provenance"]["ci_context"] = {"integrity": "absent", "basis": "none"}
    with pytest.raises(ValidationError, match="ci_context"):
        AssuranceEvent.model_validate(document)


@pytest.mark.parametrize("provider", ["local", "ci", *CI_SYSTEMS])
def test_an_executor_ran_locally_or_in_a_ci_system(provider: str) -> None:
    AssuranceEvent.model_validate(_event(**{"provenance.executor.provider": provider}))


@pytest.mark.parametrize("provider", ["github-actions", "gitlab", ""])
def test_an_executor_in_an_unnamed_ci_system_is_refused(provider: str) -> None:
    with pytest.raises(ValidationError, match="Input should be"):
        AssuranceEvent.model_validate(_event(**{"provenance.executor.provider": provider}))


def test_the_status_order_ranks_every_status_once() -> None:
    assert sorted(STATUS_SEVERITY) == sorted(get_args(Status))


SERVED = {
    "kind": "server",
    "tarball_digest": "sha256:" + "5" * 64,
    "content_digest": "sha256:" + "6" * 64,
    "key_id": "iltero-bundle-2026-09",
}


@pytest.mark.parametrize("source", ["server_bundle", "local", "custom_rego", "contract_starter"])
def test_a_check_names_where_its_assertion_came_from(source: str) -> None:
    changes: dict[str, Any] = {"provenance.assertion_source": source}
    if source == "server_bundle":
        changes["provenance.bundle"] = SERVED
    AssuranceEvent.model_validate(_event(**changes))


def test_an_assertion_from_the_servers_bundle_is_not_evaluated_over_a_local_bundle() -> None:
    with pytest.raises(ValidationError, match="evaluated over the server's bundle"):
        AssuranceEvent.model_validate(_event(**{"provenance.assertion_source": "server_bundle"}))


def test_a_resource_only_the_cloud_knows_is_a_subject_only_at_runtime() -> None:
    identity = {"scheme": "aws_arn", "value": ARNS["rds_instance"]}
    with pytest.raises(ValidationError, match="read at runtime"):
        AssuranceEvent.model_validate(_event(**{"subject.identities": [identity]}))


@pytest.mark.parametrize(
    ("kind", "content_digest", "key_id"),
    [
        ("server", None, None),
        ("server", "sha256:" + "6" * 64, None),
        ("server", None, "iltero-bundle-2026-09"),
        ("local_bundle", "sha256:" + "6" * 64, None),
        ("local_bundle", None, "iltero-bundle-2026-09"),
    ],
    ids=[
        "server naming neither",
        "server without key",
        "server without content",
        "local with content",
        "local with key",
    ],
)
def test_a_bundle_names_its_content_digest_and_key_exactly_when_the_server_served_it(
    kind: str, content_digest: str | None, key_id: str | None
) -> None:
    document = {
        "kind": kind,
        "tarball_digest": "sha256:" + "5" * 64,
        "content_digest": content_digest,
        "key_id": key_id,
    }
    with pytest.raises(ValidationError, match="exactly when its kind is server"):
        Bundle.model_validate(document)


def test_a_served_bundle_with_its_content_digest_and_key_is_accepted() -> None:
    Bundle.model_validate(
        {
            "kind": "server",
            "tarball_digest": "sha256:" + "5" * 64,
            "content_digest": "sha256:" + "6" * 64,
            "key_id": "iltero-bundle-2026-09",
        }
    )


def test_a_build_check_at_the_plan_stage_says_where_its_server_facts_came_from() -> None:
    artifact = {
        "subject.kind": "artifact",
        "subject.identities": [{"scheme": "iltero_unit", "value": "root", "scope": None}],
        "evaluation.activity": "image_build",
        "provenance.checked_content": {
            "kind": "container_image",
            "repository": "ghcr.io/acme/api",
            "digest": "sha256:" + "a" * 64,
        },
    }
    key = subject_key("artifact", [Identity(scheme="iltero_unit", value="root")])
    AssuranceEvent.model_validate(_event(**artifact, **{"subject.key": key, "provenance.facts_source": "none"}))
    with pytest.raises(ValidationError, match="facts_source is present exactly when"):
        AssuranceEvent.model_validate(_event(**artifact, **{"subject.key": key, "provenance.facts_source": None}))


def test_an_event_names_a_known_activity() -> None:
    with pytest.raises(ValidationError, match="Input should be 'iac_change', 'image_build' or 'image_deploy'"):
        AssuranceEvent.model_validate(_event(**{"evaluation.activity": "database_migration"}))


def test_an_event_alone_is_checked_against_the_stages_and_targets_of_its_activity() -> None:
    with pytest.raises(ValidationError, match="not valid for target kind 'resource' in an image_build input"):
        AssuranceEvent.model_validate(_event(**{"evaluation.activity": "image_build"}))
    with pytest.raises(ValidationError, match="not valid for target kind 'resource' in an iac_change input"):
        AssuranceEvent.model_validate(_event(**{"evaluation.stage": "pre_deploy", "provenance.facts_source": "none"}))


def test_an_event_names_the_kind_of_content_its_activity_checks() -> None:
    image = {"kind": "container_image", "repository": "docker.io/library/nginx", "digest": "sha256:" + "a" * 64}
    with pytest.raises(ValidationError, match="an iac_change evaluation names the plan it checked"):
        AssuranceEvent.model_validate(_event(**{"provenance.checked_content": image}))


def test_a_builds_facts_never_come_from_a_local_file() -> None:
    key = subject_key("artifact", [Identity(scheme="iltero_unit", value="root")])
    artifact = {
        "subject.kind": "artifact",
        "subject.identities": [{"scheme": "iltero_unit", "value": "root", "scope": None}],
        "subject.key": key,
        "evaluation.activity": "image_build",
        "provenance.checked_content": {
            "kind": "container_image",
            "repository": "ghcr.io/acme/api",
            "digest": "sha256:" + "a" * 64,
        },
    }
    AssuranceEvent.model_validate(_event(**artifact, **{"provenance.facts_source": "server"}))
    with pytest.raises(ValidationError, match="a build's facts come only from the server"):
        AssuranceEvent.model_validate(_event(**artifact, **{"provenance.facts_source": "local_file"}))


def test_an_assertion_this_package_always_evaluates_is_named_only_by_its_shipped_document() -> None:
    shipped = BUILT_INS[APPLIED_PLAN_MATCHES_EVALUATED_PLAN_ID]
    built_in = {
        "assertion.id": APPLIED_PLAN_MATCHES_EVALUATED_PLAN_ID,
        "assertion.digest": shipped.digest,
        "provenance.compiled_digest": shipped.compiled_digest,
    }
    AssuranceEvent.model_validate(_at("post_deploy", **built_in))
    for field, value in (("assertion.digest", "sha256:" + "5" * 64), ("assertion.version", "9.9.9")):
        with pytest.raises(ValidationError, match="is a built-in assertion: it names the document this package ships"):
            AssuranceEvent.model_validate(_at("post_deploy", **{**built_in, field: value}))
    with pytest.raises(ValidationError, match="runs the module compiled from the document this package ships"):
        AssuranceEvent.model_validate(
            _at("post_deploy", **{**built_in, "provenance.compiled_digest": "sha256:" + "9" * 64})
        )
    for source in ("local", "custom_rego"):
        with pytest.raises(ValidationError, match="from this package or the server's bundle, never a scanner"):
            AssuranceEvent.model_validate(_at("post_deploy", **{**built_in, "provenance.assertion_source": source}))
