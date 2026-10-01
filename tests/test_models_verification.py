"""The verification report: nine properties, each with one of six states, and no overall verdict."""

from __future__ import annotations

import copy
import json
from typing import Any, get_args

import pytest
from pydantic import ValidationError

from iltero_schemas.models.verification import API_VERSION, Properties, VerificationReport, VerificationState
from tests.conftest import VECTORS

REPORT: dict[str, Any] = json.loads((VECTORS / "reports" / "verification_report.json").read_text(encoding="utf-8"))


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
        (lambda d: d["properties"].update(verified={"state": "verified", "basis": None}), "Extra inputs"),
        (lambda d: d.update(verified=True), "Extra inputs"),
        (lambda d: d["properties"]["integrity"].update(state="passed"), "Input should be"),
        (lambda d: d["properties"]["integrity"].pop("basis"), "Field required"),
        (lambda d: d["record"].update(digest="sha256:abc"), "String should match pattern"),
        (lambda d: d["verifier"].update(name="server"), "Input should be 'iltero'"),
        (
            lambda d: d["properties"]["integrity"].update(state="verified", basis="digest_linkage"),
            "verified only by a signature",
        ),
        (lambda d: d["properties"]["integrity"].update(state="verified", basis=None), "verified only by a signature"),
        (lambda d: d["properties"]["integrity"].update(state="failed"), "every other property is not_determined"),
    ],
    ids=[
        "a property missing",
        "an overall verdict among the properties",
        "an overall verdict on the report",
        "an unknown state",
        "no basis",
        "a record digest of the wrong shape",
        "another verifier",
        "integrity verified by digests",
        "integrity verified on no basis",
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
        document["properties"][name] = {"state": "not_determined", "basis": "integrity_failed"}
    document["properties"]["integrity"] = {"state": "failed", "basis": "digest_linkage"}
    VerificationReport.model_validate(document)
