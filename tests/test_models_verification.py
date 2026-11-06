"""The verification report: nine properties, each with a result a verifier gives it, and no overall verdict."""

from __future__ import annotations

import copy
import json
from typing import Any, get_args

import pytest
from pydantic import ValidationError

from iltero_schemas.models.verification import (
    API_VERSION,
    PROPERTY_RESULTS,
    Properties,
    VerificationReport,
    VerificationState,
)
from tests.conftest import VECTORS

REPORT: dict[str, Any] = json.loads(
    (VECTORS / "reports" / "iac" / "verification_report.json").read_text(encoding="utf-8")
)


def test_the_vector_validates_and_names_this_api_version() -> None:
    assert VerificationReport.model_validate(REPORT).api_version == API_VERSION


def test_a_report_names_the_nine_properties_and_no_overall_verdict() -> None:
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
    ]
    assert set(VerificationReport.model_fields) == {"api_version", "record", "verifier", "properties"}


def test_a_property_has_one_of_six_states() -> None:
    assert set(get_args(VerificationState)) == {
        "verified",
        "failed",
        "not_determined",
        "not_assessed",
        "not_performed",
        "client_asserted",
    }


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda d: d["properties"].pop("exceptions"), "Field required"),
        (lambda d: d["properties"].update(verified={"state": "verified", "reason": None}), "Extra inputs"),
        (lambda d: d.update(verified=True), "Extra inputs"),
        (lambda d: d["properties"]["integrity"].update(state="passed"), "Input should be"),
        (lambda d: d["properties"]["integrity"].pop("reason"), "Field required"),
        (lambda d: d["record"].update(digest="sha256:abc"), "String should match pattern"),
        (lambda d: d["verifier"].update(name="server"), "Input should be 'iltero'"),
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
        (lambda d: d["properties"]["integrity"].update(state="failed"), "every other property is not_determined"),
    ],
    ids=[
        "a property missing",
        "an overall verdict among the properties",
        "an overall verdict on the report",
        "an unknown state",
        "no reason",
        "a record digest of the wrong shape",
        "another verifier",
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
        document["properties"][name] = {"state": "not_determined", "reason": "integrity_failed"}
    document["properties"]["integrity"] = {"state": "failed", "reason": "file_digests"}
    VerificationReport.model_validate(document)


@pytest.mark.parametrize(
    ("state", "reason"),
    [
        ("client_asserted", "reported_by_pipeline"),
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
    document["properties"]["runtime_verification"] = {"state": state, "reason": reason}
    assert VerificationReport.model_validate(document).properties.runtime_verification.reason == reason


@pytest.mark.parametrize(
    ("state", "reason", "message"),
    [
        ("verified", "reported_by_pipeline", "no property of an unsigned record is verified"),
        ("failed", "refused", "runtime_verification is one of the results"),
        ("not_performed", "no_post_verify_stage", "runtime_verification is one of the results"),
        ("not_assessed", None, "runtime_verification is one of the results"),
        ("not_determined", "integrity_failed", "runtime_verification is one of the results"),
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
    document["properties"]["runtime_verification"] = {"state": state, "reason": reason}
    with pytest.raises(ValidationError, match=message):
        VerificationReport.model_validate(document)


RESULTS = [
    (name, state, reason) for name, results in PROPERTY_RESULTS.items() for state, reason in sorted(results, key=str)
]


@pytest.mark.parametrize(("name", "state", "reason"), RESULTS, ids=[f"{n} {s} {r}" for n, s, r in RESULTS])
def test_each_property_takes_each_result_a_verifier_gives_it(name: str, state: str, reason: str | None) -> None:
    document = copy.deepcopy(REPORT)
    document["properties"][name] = {"state": state, "reason": reason}
    VerificationReport.model_validate(document)


@pytest.mark.parametrize("name", list(PROPERTY_RESULTS))
def test_a_property_with_a_reason_outside_its_results_is_refused(name: str) -> None:
    document = copy.deepcopy(REPORT)
    document["properties"][name] = {"state": "not_assessed", "reason": "checked_by_hand"}
    with pytest.raises(ValidationError, match=f"{name} is one of the results a verifier gives that property"):
        VerificationReport.model_validate(document)


def test_a_run_still_in_progress_has_not_assessed_its_stages() -> None:
    document = copy.deepcopy(REPORT)
    document["properties"]["stage_completeness"] = {"state": "failed", "reason": "stages_pending"}
    with pytest.raises(ValidationError, match="stage_completeness is one of the results"):
        VerificationReport.model_validate(document)


def test_a_finished_record_missing_a_stage_it_expects_failed_its_stage_completeness() -> None:
    document = copy.deepcopy(REPORT)
    document["properties"]["stage_completeness"] = {"state": "failed", "reason": "stage_not_reported"}
    VerificationReport.model_validate(document)


def test_a_record_that_lists_no_exception_has_its_exceptions_not_assessed() -> None:
    document = copy.deepcopy(REPORT)
    document["properties"]["exceptions"] = {"state": "not_performed", "reason": "exceptions_not_listed"}
    with pytest.raises(ValidationError, match="exceptions is one of the results"):
        VerificationReport.model_validate(document)


def test_the_results_a_verifier_gives_cannot_be_changed() -> None:
    with pytest.raises(TypeError):
        PROPERTY_RESULTS["integrity"] = frozenset()  # type: ignore[index]
