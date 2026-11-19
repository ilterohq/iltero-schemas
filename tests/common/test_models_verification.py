"""The verification report: thirteen properties, each with a result a verifier gives it, and no overall verdict."""

from __future__ import annotations

import copy
import json
from typing import Any, get_args

import pytest
from pydantic import ValidationError

from iltero_schemas.canonical import digest_of
from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.common.commit_review import CommitReviewOutcome
from iltero_schemas.models.common.facts import NotReadByTheStage, ServerFactsUnavailable
from iltero_schemas.models.common.verification import (
    API_VERSION,
    COMMIT_REVIEW_RESULTS,
    PROPERTY_RESULTS,
    Properties,
    VerificationReport,
    VerificationState,
)
from tests.conftest import VECTORS
from tests.records import valid_case_record

REPORT: dict[str, Any] = json.loads(
    (VECTORS / "reports" / "iac" / "verification_report.json").read_text(encoding="utf-8")
)

# The record of a run the server opened whose pre-deploy stage kept a commit review with a commit not reviewed.
NOT_REVIEWED_CASE = "iac_record_of_a_run_the_server_opened_keeping_its_commit_review_without_a_commit_review_check"
NOT_REVIEWED_REPORT: dict[str, Any] = json.loads(
    (VECTORS / "reports" / "iac" / "verification_report_commit_not_reviewed.json").read_text(encoding="utf-8")
)


def test_the_vector_validates_and_names_this_api_version() -> None:
    assert VerificationReport.model_validate(REPORT).api_version == API_VERSION


def test_a_report_names_the_thirteen_properties_and_no_overall_verdict() -> None:
    assert list(Properties.model_fields) == [
        "integrity",
        "source_identity",
        "approval_identity",
        "bundle_provenance",
        "stage_completeness",
        "plan_apply_match",
        "runtime_verification",
        "deployment_coverage",
        "exceptions",
        "commit_review",
        "reference_time",
        "evaluator_binary",
        "scanner_evidence",
    ]
    assert set(VerificationReport.model_fields) == {"api_version", "kind", "metadata", "record", "properties"}


def test_a_property_has_one_of_six_states() -> None:
    assert set(get_args(VerificationState)) == {
        "verified",
        "failed",
        "could_not_decide",
        "not_assessed",
        "not_performed",
        "claimed_by_record",
    }


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda d: d["properties"].pop("exceptions"), "Field required"),
        (
            lambda d: d["properties"].update(verified={"state": "verified", "reason": None, "detail": None}),
            "Extra inputs",
        ),
        (lambda d: d.update(verified=True), "Extra inputs"),
        (lambda d: d["properties"]["integrity"].update(state="passed"), "Input should be"),
        (lambda d: d["properties"]["integrity"].pop("reason"), "Field required"),
        (lambda d: d["record"].update(digest="sha256:abc"), "String should match pattern"),
        (lambda d: d["metadata"]["verifier"].update(name="server"), "Input should be 'iltero'"),
        (lambda d: d["metadata"].pop("verified_at"), "Field required"),
        (lambda d: d["metadata"].update(verified_at="2026-09-22 13:10"), "String should match pattern"),
        (
            lambda d: d["properties"]["integrity"].update(state="verified", reason="file_digests"),
            "no property of an unsigned record is verified",
        ),
        (
            lambda d: d["properties"]["integrity"].update(state="verified", reason=None),
            "no property of an unsigned record is verified",
        ),
        (
            lambda d: d["properties"]["source_identity"].update(state="verified", reason="ci_job_held_by_server"),
            "no property of an unsigned record is verified",
        ),
        (lambda d: d["properties"]["integrity"].update(state="failed"), "every other property is could_not_decide"),
    ],
    ids=[
        "a property missing",
        "an overall verdict among the properties",
        "an overall verdict on the report",
        "an unknown state",
        "no reason",
        "a record digest of the wrong shape",
        "another verifier",
        "no verification time",
        "a time not in RFC 3339",
        "integrity verified by digests",
        "integrity verified with no reason",
        "a source verified on an unsigned record",
        "claims beside a failed integrity",
    ],
)
def test_a_report_that_does_not_hold_together_is_refused(change: Any, message: str) -> None:
    document = copy.deepcopy(REPORT)
    change(document)
    with pytest.raises(ValidationError, match=message):
        VerificationReport.model_validate(document)


def test_a_failed_integrity_with_nothing_else_taken_is_accepted() -> None:
    document = copy.deepcopy(REPORT)
    for name in document["properties"]:
        document["properties"][name] = {"state": "could_not_decide", "reason": "integrity_failed", "detail": None}
    document["properties"]["integrity"] = {"state": "failed", "reason": "file_digests", "detail": None}
    VerificationReport.model_validate(document)


@pytest.mark.parametrize(
    ("state", "reason"),
    [
        ("claimed_by_record", "reported_by_pipeline"),
        ("not_assessed", "stage_pending"),
        ("not_performed", "stage_not_reported"),
        ("not_assessed", "project_config"),
        ("not_assessed", "environment_policy"),
        ("not_assessed", "not_supported"),
        ("not_assessed", "not_in_activity"),
    ],
)
def test_the_verification_after_deployment_is_one_of_seven_results(state: str, reason: str) -> None:
    document = copy.deepcopy(REPORT)
    document["properties"]["runtime_verification"] = {"state": state, "reason": reason, "detail": None}
    assert VerificationReport.model_validate(document).properties.runtime_verification.reason == reason


@pytest.mark.parametrize(
    ("state", "reason", "message"),
    [
        ("verified", "reported_by_pipeline", "no property of an unsigned record is verified"),
        ("failed", "refused", "runtime_verification is one of the results"),
        ("not_performed", "no_post_verify_stage", "runtime_verification is one of the results"),
        ("not_assessed", None, "runtime_verification is one of the results"),
        ("could_not_decide", "integrity_failed", "runtime_verification is one of the results"),
    ],
    ids=[
        "verified by the pipeline's word",
        "a refusal only the server knows",
        "an unlisted reason",
        "no reason",
        "undetermined with the record's integrity established",
    ],
)
def test_a_verification_after_deployment_outside_the_seven_results_is_refused(
    state: str, reason: str | None, message: str
) -> None:
    document = copy.deepcopy(REPORT)
    document["properties"]["runtime_verification"] = {"state": state, "reason": reason, "detail": None}
    with pytest.raises(ValidationError, match=message):
        VerificationReport.model_validate(document)


RESULTS = [
    (name, state, reason) for name, results in PROPERTY_RESULTS.items() for state, reason in sorted(results, key=str)
]


@pytest.mark.parametrize(("name", "state", "reason"), RESULTS, ids=[f"{n} {s} {r}" for n, s, r in RESULTS])
def test_each_property_takes_each_result_a_verifier_gives_it(name: str, state: str, reason: str | None) -> None:
    document = copy.deepcopy(REPORT)
    document["properties"][name] = {"state": state, "reason": reason, "detail": None}
    VerificationReport.model_validate(document)


@pytest.mark.parametrize("name", list(PROPERTY_RESULTS))
def test_a_property_with_a_reason_outside_its_results_is_refused(name: str) -> None:
    document = copy.deepcopy(REPORT)
    document["properties"][name] = {"state": "not_assessed", "reason": "checked_by_hand", "detail": None}
    with pytest.raises(ValidationError, match=f"{name} is one of the results a verifier gives that property"):
        VerificationReport.model_validate(document)


def test_a_run_still_in_progress_has_not_assessed_its_stages() -> None:
    document = copy.deepcopy(REPORT)
    document["properties"]["stage_completeness"] = {"state": "failed", "reason": "stages_pending", "detail": None}
    with pytest.raises(ValidationError, match="stage_completeness is one of the results"):
        VerificationReport.model_validate(document)


def test_a_finished_record_missing_a_stage_it_expects_failed_its_stage_completeness() -> None:
    document = copy.deepcopy(REPORT)
    document["properties"]["stage_completeness"] = {"state": "failed", "reason": "stage_not_reported", "detail": None}
    VerificationReport.model_validate(document)


def test_a_record_that_relied_on_a_served_exception_is_the_records_claim_rather_than_verified() -> None:
    document = copy.deepcopy(REPORT)
    document["properties"]["exceptions"] = {
        "state": "not_assessed",
        "reason": "served_exception_relied_on",
        "detail": None,
    }
    with pytest.raises(ValidationError, match="exceptions is one of the results"):
        VerificationReport.model_validate(document)


def test_the_commit_review_takes_one_result_per_outcome_named_by_that_outcome() -> None:
    assert set(COMMIT_REVIEW_RESULTS) == set(get_args(CommitReviewOutcome))
    assert all(reason == outcome for outcome, (_state, reason) in COMMIT_REVIEW_RESULTS.items())
    assert COMMIT_REVIEW_RESULTS["reviewed"] == ("claimed_by_record", "reviewed")
    assert {state for state, _reason in COMMIT_REVIEW_RESULTS.values()} == {
        "claimed_by_record",
        "failed",
        "could_not_decide",
        "not_performed",
    }


def test_the_results_a_verifier_gives_cannot_be_changed() -> None:
    with pytest.raises(TypeError):
        PROPERTY_RESULTS["integrity"] = frozenset()  # type: ignore[index]


def test_the_commit_review_report_names_its_record_and_gives_the_result_of_the_kept_outcome() -> None:
    document = valid_case_record("iac", NOT_REVIEWED_CASE)
    report = VerificationReport.model_validate(NOT_REVIEWED_REPORT)
    assert (report.record.uuid, report.record.digest) == (document["metadata"]["uuid"], digest_of(document))
    review = CAR.model_validate(document).stages[Stage.PRE_DEPLOY].commit_review
    assert review is not None and not isinstance(review, ServerFactsUnavailable | NotReadByTheStage)
    result = report.properties.commit_review
    assert (result.state, result.reason) == COMMIT_REVIEW_RESULTS[review.outcome] == ("failed", "not_reviewed")


@pytest.mark.parametrize(
    ("name", "result"),
    [
        ("approval_identity", ("not_performed", "run_opened_locally")),
        ("approval_identity", ("could_not_decide", "server_facts_unavailable")),
        ("approval_identity", ("not_assessed", "not_read_by_the_stage")),
        ("commit_review", ("not_performed", "run_opened_locally")),
        ("commit_review", ("could_not_decide", "server_facts_unavailable")),
        ("commit_review", ("not_assessed", "not_read_by_the_stage")),
        ("exceptions", ("claimed_by_record", "project_exception_relied_on")),
        ("exceptions", ("claimed_by_record", "project_exceptions_file_not_relied_on")),
        ("reference_time", ("not_performed", "runner_clock")),
        ("reference_time", ("claimed_by_record", "server")),
        ("evaluator_binary", ("claimed_by_record", "pinned_binary_named")),
        ("evaluator_binary", ("failed", "other_binary_named")),
        ("evaluator_binary", ("not_assessed", "no_opa_evaluation")),
    ],
)
def test_a_verifier_says_what_it_could_and_could_not_assess(name: str, result: tuple[str, str]) -> None:
    assert result in PROPERTY_RESULTS[name]


@pytest.mark.parametrize(
    ("name", "result"),
    [
        ("exceptions", ("not_assessed", "not_read_by_the_stage")),
        ("approval_identity", ("not_performed", "server_facts_unavailable")),
        ("reference_time", ("verified", "server")),
        ("reference_time", ("claimed_by_record", "timestamp_authority")),
        ("reference_time", ("claimed_by_record", "runner_clock")),
        ("exceptions", ("could_not_decide", "server_facts_unavailable")),
    ],
    ids=[
        "a stage keeps no exceptions",
        "a tool-opened run is not missing facts",
        "unsigned",
        "no such source",
        "a runner's clock is no trusted source",
        "no stage keeps the marker for exceptions",
    ],
)
def test_a_result_no_verifier_gives_is_not_among_a_propertys_results(name: str, result: tuple[str, str]) -> None:
    assert result not in PROPERTY_RESULTS[name]


def test_a_result_takes_a_plain_sentence_as_its_detail() -> None:
    document = copy.deepcopy(REPORT)
    document["properties"]["reference_time"] = {
        "state": "not_performed",
        "reason": "runner_clock",
        "detail": "the plan stage's time decided whether exception ex-1 was in force",
    }
    assert VerificationReport.model_validate(document).properties.reference_time.detail is not None


@pytest.mark.parametrize(
    ("detail", "message"),
    [("", "at least 1 character"), ("x" * 1025, "at most 1024 characters"), ("a\nb", "control character")],
    ids=["empty", "too long", "a line break"],
)
def test_a_detail_is_a_bounded_plain_sentence(detail: str, message: str) -> None:
    document = copy.deepcopy(REPORT)
    document["properties"]["reference_time"]["detail"] = detail
    with pytest.raises(ValidationError, match=message):
        VerificationReport.model_validate(document)
