"""The verification report the verifier writes: the trust level and its reason, the trust root, what reading the run
statement found, the stages' trust data, and how a run statement upgrades or fails each property."""

from __future__ import annotations

import json
from typing import Any

import pytest

from iltero_schemas.canonical import digest
from iltero_schemas.models.common.base import API_VERSION
from iltero_schemas.models.common.run_statement import RunClosePredicate, StatementSubject
from iltero_schemas.models.common.verification import PRE_DEPLOY_RESULT_ORDER, RUN_STATEMENT, VerificationReport
from iltero_schemas.statement import RunStatementError, run_statement_payload
from iltero_schemas.trust import OPERATOR_TRUST_FILE_KIND, parse_operator_signing_keys, read_trust_file
from iltero_schemas.vectors.vector_reports import (
    REPORT_VERIFIED_AT,
    REPORT_VERIFIER_VERSION,
    ReportSource,
    report_source,
    vector_report,
)
from iltero_schemas.vectors.vector_signing_keys import (
    VECTOR_SIGNING_KEYS_FILE,
    active_key_entry,
)
from iltero_schemas.verifier import verification_report
from iltero_schemas.verifier.record_results import SERVED_EXCEPTION_RELIED_ON
from tests.server_runs import verify_es256
from tests.statements import Signer, statement_parts

DEPLOYED = {"record": {"vector": "iac/tracked_run_deployed.json"}}
WITH_ITS_STATEMENT = {**DEPLOYED, "run_statement": {"vector": "iac/tracked_run_deployed.json"}}
OPERATOR = "Test Operator"
OPERATOR_SERVER = "operator.test.example"
OPERATOR_KEY_ID = "operator-run-statements"


def _report(given: ReportSource, **changes: Any) -> VerificationReport:
    arguments: dict[str, Any] = {
        "reader_checks_hold": True,
        "unpackaged_paths": given.unpackaged_paths,
        "statement": given.statement,
        "iltero": given.iltero,
        "operator": given.operator,
        "signature_check": verify_es256,
        "verifier_version": REPORT_VERIFIER_VERSION,
        "verified_at": REPORT_VERIFIED_AT,
    }
    return verification_report(given.record, given.files, **{**arguments, **changes})


def test_a_record_its_run_statement_holds_for_is_policy_enforced_and_names_its_signer() -> None:
    report = vector_report("iac", WITH_ITS_STATEMENT, verify_es256)
    assert (report.trust_level.level, report.trust_level.reason) == ("policy_enforced", "run_statement")
    assert report.trust_root is not None and report.run_statement is not None
    assert (report.trust_root.key_id, report.trust_root.listed_in, report.trust_root.operator) == (
        "dev-run-statements",
        "iltero",
        None,
    )
    assert report.trust_root.trust_data_digest == digest(VECTOR_SIGNING_KEYS_FILE.read_bytes())
    assert report.run_statement.digest is not None and report.run_statement.listed_as == "subject"


def test_a_tracked_run_read_with_no_statement_is_self_attested_and_names_no_trust_root() -> None:
    report = vector_report("iac", DEPLOYED, verify_es256)
    assert (report.trust_level.level, report.trust_level.reason) == ("self_attested", "no_statement_given")
    assert report.trust_root is None and report.run_statement is None


def test_a_local_run_is_self_attested_as_opened_locally() -> None:
    report = vector_report("iac", {"record": {"vector": "iac/local_run.json"}}, verify_es256)
    assert (report.trust_level.level, report.trust_level.reason) == ("self_attested", "run_opened_locally")


def test_a_statement_that_does_not_verify_is_a_problem_and_never_a_lower_level_alone() -> None:
    case = {"record": {"run_statement_case": "iac/statement_signed_with_a_revoked_key"}}
    report = vector_report("iac", case, verify_es256)
    assert report.trust_level.reason == "run_statement_does_not_hold" and report.trust_root is None
    assert report.run_statement is not None and report.run_statement.digest is None
    assert [problem.reason for problem in report.run_statement.problems] == ["key_revoked"]


def test_a_statement_that_does_not_hold_for_the_record_lists_each_difference_as_a_problem() -> None:
    case = {"record": {"run_statement_case": "iac/statement_of_another_unit"}}
    report = vector_report("iac", case, verify_es256)
    assert report.trust_level.reason == "run_statement_does_not_hold" and report.trust_root is not None
    assert report.run_statement is not None
    assert [problem.reason for problem in report.run_statement.problems] == ["another_unit", "record_not_listed"]


def test_a_record_the_server_refused_fails_its_integrity_and_lists_no_refusal_as_a_problem() -> None:
    case = {"record": {"run_statement_case": "iac/statement_listing_the_record_as_refused"}}
    report = vector_report("iac", case, verify_es256)
    assert report.trust_level.reason == "refused_by_server"
    assert (report.properties.integrity.state, report.properties.integrity.reason) == ("failed", "refused_by_server")
    assert report.run_statement is not None and report.run_statement.problems == []


def test_bytes_that_are_not_a_run_statement_are_refused_and_give_no_report() -> None:
    with pytest.raises(RunStatementError) as refused:
        _report(report_source("iac", DEPLOYED), statement=b"not a run statement")
    assert refused.value.reason == "not_json"


def test_a_record_whose_reader_checks_failed_decides_nothing_whatever_its_statement_says() -> None:
    report = _report(report_source("iac", WITH_ITS_STATEMENT), reader_checks_hold=False)
    assert report.trust_level.reason == "integrity_failed" and report.trust_root is not None
    assert (report.properties.integrity.state, report.properties.integrity.reason) == ("failed", "file_digests")
    assert {(result.state, result.reason) for name, result in report.properties if name != "integrity"} == {
        ("could_not_decide", "integrity_failed")
    }


def test_the_report_names_how_the_run_ended_from_its_statement() -> None:
    report = vector_report("iac", WITH_ITS_STATEMENT, verify_es256)
    assert report.run_statement is not None and report.run_statement.run is not None
    ended = report.run_statement.run
    assert (ended.ending, ended.unanswered_results, ended.stages_never_accepted) == ("abandoned", 0, 1)


def test_the_report_shows_the_trust_data_each_stage_names() -> None:
    given = report_source("iac", DEPLOYED)
    report = _report(given)
    named = {stage: kept.execution.bundle for stage, kept in given.record.stages.items()}
    assert report.stage_trust_data_digests == {
        stage: None if bundle is None else bundle.trust_data_digest for stage, bundle in named.items()
    }


def test_an_earlier_copy_is_policy_enforced_with_its_note_and_leaves_its_later_stages_to_the_later_record() -> None:
    case = {"record": {"run_statement_case": "iac/statement_listing_the_record_as_an_earlier_accepted_copy"}}
    report = vector_report("iac", case, verify_es256)
    assert report.trust_level.level == "policy_enforced" and report.run_statement is not None
    assert [note.reason for note in report.run_statement.notes] == ["record_not_the_one_that_counts"]
    for found in (report.properties.stage_completeness, report.properties.check_after_deployment):
        assert (found.state, found.reason) == ("not_assessed", "later_record_holds_the_later_stages")
        assert found.detail is not None and report.run_statement.listed_as == "earlier_copy"


def test_a_final_record_missing_a_stage_is_never_verified_complete() -> None:
    report = vector_report("iac", WITH_ITS_STATEMENT, verify_es256)
    found = report.properties.stage_completeness
    assert (found.state, found.reason) == ("failed", "stage_not_reported")


def test_the_statement_of_another_run_names_no_run_end() -> None:
    report = vector_report("iac", {"record": {"run_statement_case": "iac/statement_of_another_run"}}, verify_es256)
    assert report.run_statement is not None and report.run_statement.digest is not None
    assert report.run_statement.run is None


def test_a_refused_record_names_the_list_the_stage_and_the_reason_the_server_signed() -> None:
    case = {"record": {"run_statement_case": "iac/statement_listing_the_record_as_refused"}}
    detail = vector_report("iac", case, verify_es256).properties.integrity.detail
    assert detail == (
        "the run statement lists this record among the records the server read and refused, at the post_deploy "
        "stage, for record_not_accepted"
    )


def test_a_failure_names_the_first_difference_and_how_many_more() -> None:
    case = {"record": {"run_statement_case": "iac/statement_whose_ci_job_ran_in_another_repository"}}
    detail = vector_report("iac", case, verify_es256).properties.source_identity.detail
    assert detail is not None and detail.endswith("(and 2 more differences)")


def test_an_exception_of_the_projects_own_comes_before_a_served_one_a_statement_covers() -> None:
    order = PRE_DEPLOY_RESULT_ORDER
    assert order.index(SERVED_EXCEPTION_RELIED_ON) < order.index(("claimed_by_record", "project_exception_relied_on"))
    assert order.index(("claimed_by_record", "project_exception_relied_on")) < order.index(RUN_STATEMENT)
    assert order.index(("claimed_by_record", "served_exception_approved_by_run_starter")) < order.index(RUN_STATEMENT)


def _operator_file(signer: Signer) -> bytes:
    entry = active_key_entry(
        signer.public_der,
        key_id=OPERATOR_KEY_ID,
        purpose="run_statement",
        server=OPERATOR_SERVER,
        valid_from="2026-01-01T00:00:00Z",
    )
    document = {
        "apiVersion": API_VERSION,
        "kind": OPERATOR_TRUST_FILE_KIND,
        "operator": OPERATOR,
        "server": OPERATOR_SERVER,
        "keys": [entry],
    }
    return json.dumps(document).encode("utf-8")


def test_a_statement_an_operators_key_signed_names_the_operator_and_its_file() -> None:
    signer = Signer()
    operator = parse_operator_signing_keys(_operator_file(signer))
    subjects, predicate = statement_parts()
    predicate["run"]["server"] = OPERATOR_SERVER
    payload = run_statement_payload(
        [StatementSubject.model_validate(subject) for subject in subjects], RunClosePredicate.model_validate(predicate)
    ).payload
    given = report_source("iac", DEPLOYED)
    report = _report(
        given,
        statement=signer.envelope(payload, key_id=OPERATOR_KEY_ID),
        iltero=read_trust_file(VECTOR_SIGNING_KEYS_FILE.read_bytes(), development=True),
        operator=operator,
    )
    assert report.trust_root is not None
    assert (report.trust_root.key_id, report.trust_root.listed_in, report.trust_root.operator) == (
        OPERATOR_KEY_ID,
        "operator",
        OPERATOR,
    )
    # The stages loaded the development server's bundle, so the operator's statement does not hold for the record.
    assert report.run_statement is not None and {p.reason for p in report.run_statement.problems} == {
        "bundle_of_another_server"
    }
    signature = report.properties.bundle_signature
    assert (signature.state, signature.reason) == ("failed", "bundle_of_another_server")


def test_the_report_names_each_part_the_statement_signs_that_the_record_keeps_no_copy_of() -> None:
    case = {"record": {"run_statement_case": "iac/statement_signing_parts_the_record_keeps_no_copy_of"}}
    report = vector_report("iac", case, verify_es256)
    assert report.run_statement is not None
    assert [(part.stage, part.part) for part in report.run_statement.not_compared] == [("pre_deploy", "approvals")]


def test_a_statement_that_did_not_verify_names_no_part_not_compared() -> None:
    case = {"record": {"run_statement_case": "iac/statement_signed_with_a_revoked_key"}}
    report = vector_report("iac", case, verify_es256)
    assert report.run_statement is not None and report.run_statement.not_compared == []
