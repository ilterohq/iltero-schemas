"""The trust level a report assigns its record, the run statement's signer and findings, and the rules that keep them
in agreement with the properties."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.common.report_trust import (
    STATEMENT_PROBLEMS,
    TRUST_LEVEL_RESULTS,
    AssignedTrustLevel,
    StatementTrustRoot,
)
from iltero_schemas.models.common.verification import VerificationReport
from iltero_schemas.statement.reasons import RECORD_DIFFERENCES, RUN_STATEMENT_DOES_NOT_HOLD
from tests.conftest import VECTORS

REPORTS = VECTORS / "reports" / "iac"
ROOT = {
    "key_id": "dev-run-statements",
    "listed_in": "iltero",
    "operator": None,
    "trust_data_digest": "sha256:" + "a" * 64,
}


def _report(name: str) -> dict[str, Any]:
    document: dict[str, Any] = json.loads((REPORTS / name).read_text(encoding="utf-8"))
    return document


def test_a_report_assigns_one_of_two_trust_levels_each_with_its_reasons() -> None:
    assert {level for level, _reason in TRUST_LEVEL_RESULTS} == {"policy_enforced", "self_attested"}
    assert [reason for level, reason in TRUST_LEVEL_RESULTS if level == "policy_enforced"] == ["run_statement"]


def test_a_trust_level_with_a_reason_of_another_level_is_refused() -> None:
    with pytest.raises(ValidationError, match="a trust level is one a verifier assigns"):
        AssignedTrustLevel(level="policy_enforced", reason="no_statement_given")


@pytest.mark.parametrize(("listed_in", "operator"), [("operator", None), ("iltero", "Example Operator")])
def test_a_trust_root_names_an_operator_exactly_for_a_key_of_an_operators_file(
    listed_in: str, operator: str | None
) -> None:
    with pytest.raises(ValidationError, match="names an operator exactly when"):
        StatementTrustRoot.model_validate({**ROOT, "listed_in": listed_in, "operator": operator})


def test_a_problem_is_a_reason_a_statement_does_not_hold_or_a_difference_but_a_refusal() -> None:
    assert STATEMENT_PROBLEMS == RUN_STATEMENT_DOES_NOT_HOLD | (RECORD_DIFFERENCES - {"record_refused_by_the_server"})


@pytest.mark.parametrize(
    ("name", "pointer", "value", "message"),
    [
        (
            "verification_report_tracked_run_with_its_run_statement.json",
            "run",
            None,
            "a run statement that verified names its digest, how it lists the record",
        ),
        (
            "verification_report_tracked_run_with_its_run_statement.json",
            "notes",
            [{"reason": "another_unit", "sentence": "the record's unit is not a unit of the run statement"}],
            "a run statement's notes are notes of a record comparison",
        ),
        (
            "verification_report_tracked_run_with_its_run_statement.json",
            "problems",
            [{"reason": "key_revoked", "sentence": "the run statement's key is revoked"}],
            "the problems of a run statement that verified are differences from the record",
        ),
        (
            "verification_report_run_statement_signed_with_a_revoked_key.json",
            "problems",
            [],
            "a run statement that did not verify has exactly one problem",
        ),
        (
            "verification_report_run_statement_signed_with_a_revoked_key.json",
            "not_compared",
            [{"stage": "pre_deploy", "part": "approvals"}],
            "a run statement that did not verify names no part it could not compare",
        ),
        (
            "verification_report_tracked_run_with_its_run_statement.json",
            "not_compared",
            [{"stage": "pre_deploy", "part": "commit_review"}, {"stage": "pre_deploy", "part": "approvals"}],
            "named each once, by stage in the order of the lifecycle, then part",
        ),
        (
            "verification_report_tracked_run_with_its_run_statement.json",
            "not_compared",
            [{"stage": "plan", "part": "approvals"}, {"stage": "plan", "part": "approvals"}],
            "named each once, by stage in the order of the lifecycle, then part",
        ),
    ],
    ids=[
        "no run end",
        "a difference as a note",
        "a refusal of a statement that verified",
        "no problem",
        "a part not compared beside a statement that did not verify",
        "parts not compared out of order",
        "a part not compared twice",
    ],
)
def test_a_run_statements_findings_that_disagree_are_refused(name: str, pointer: str, value: Any, message: str) -> None:
    document = _report(name)
    document["run_statement"][pointer] = value
    with pytest.raises(ValidationError, match=message):
        VerificationReport.model_validate(document)


@pytest.mark.parametrize(
    ("name", "change", "message"),
    [
        (
            "verification_report_tracked_run_without_its_run_statement.json",
            lambda d: d.update(trust_root=ROOT),
            "a report names a trust root exactly when a run statement verified",
        ),
        (
            "verification_report_tracked_run_with_its_run_statement.json",
            lambda d: d.update(trust_level={"level": "self_attested", "reason": "run_opened_locally"}),
            "was given no run statement",
        ),
        (
            "verification_report_tracked_run_with_its_run_statement.json",
            lambda d: d["run_statement"]["problems"].append({"reason": "another_unit", "sentence": "another unit"}),
            "a run statement with a problem gives a trust level whose reason says so",
        ),
        (
            "verification_report_run_statement_signing_other_approvals.json",
            lambda d: d["run_statement"].update(problems=[]),
            "a run statement that does not hold has a problem the report lists",
        ),
        (
            "verification_report_record_the_server_refused.json",
            lambda d: d["run_statement"].update(listed_as="subject"),
            "is one the run statement lists as refused",
        ),
        (
            "verification_report_tracked_run_without_its_run_statement.json",
            lambda d: d.update(trust_level={"level": "self_attested", "reason": "integrity_failed"}),
            "a record's integrity failed on its files exactly when its trust level reason is integrity_failed",
        ),
        (
            "verification_report_tracked_run_without_its_run_statement.json",
            lambda d: d["properties"].update(
                {
                    name: {"state": "failed", "reason": "file_digests", "detail": None}
                    if name == "integrity"
                    else {"state": "could_not_decide", "reason": "integrity_failed", "detail": None}
                    for name in d["properties"]
                }
            ),
            "a record's integrity failed on its files exactly when its trust level reason is integrity_failed",
        ),
        (
            "verification_report_run_statement_signing_other_approvals.json",
            lambda d: d["properties"].update(
                integrity={"state": "failed", "reason": "refused_by_server", "detail": None}
            ),
            "a record's integrity failed as refused_by_server exactly when its trust level reason is refused_by_server",
        ),
        (
            "verification_report_tracked_run_with_its_run_statement.json",
            lambda d: d["run_statement"].update(listed_as="conflicting_upload"),
            "a policy_enforced record is one a run statement that verified lists as accepted",
        ),
        (
            "verification_report_tracked_run_with_its_run_statement.json",
            lambda d: d["properties"].update(
                integrity={"state": "claimed_by_record", "reason": "file_digests", "detail": None}
            ),
            "verified by a run statement exactly when its trust level is policy_enforced",
        ),
        (
            "verification_report_run_statement_signing_other_approvals.json",
            lambda d: d["properties"].update(
                pinned_plan={"state": "verified", "reason": "pinned_and_named_by_accepted_record", "detail": None}
            ),
            "a property is verified by a run statement only for a policy_enforced record",
        ),
    ],
    ids=[
        "a trust root with no statement",
        "opened locally beside a statement",
        "a problem beside policy_enforced",
        "does not hold with no problem",
        "refused but listed as the subject",
        "integrity_failed with its files holding",
        "files failing with another trust level reason",
        "refused integrity with another trust level reason",
        "policy_enforced for a conflicting upload",
        "policy_enforced with its integrity claimed",
        "verified beside a statement that does not hold",
    ],
)
def test_a_trust_level_that_disagrees_with_the_findings_or_the_properties_is_refused(
    name: str, change: Any, message: str
) -> None:
    document = copy.deepcopy(_report(name))
    change(document)
    with pytest.raises(ValidationError, match=message):
        VerificationReport.model_validate(document)


def test_the_bundle_signature_is_verified_with_no_run_statement() -> None:
    report = VerificationReport.model_validate(
        _report("verification_report_tracked_run_without_its_run_statement.json")
    )
    assert report.trust_level.level == "self_attested"
    assert (report.properties.bundle_signature.state, report.properties.bundle_signature.reason) == (
        "verified",
        "bundle_signature_checked",
    )
