"""The event contract for an evaluation from a scanner's results: about a resource, one of the scanner outcomes, no
facts from the server, and only what its report decided."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.assertions.paths import NOT_DECIDED_BY_SCANNERS
from iltero_schemas.models.common.event import AssuranceEvent
from iltero_schemas.models.common.fields import Identity
from iltero_schemas.models.common.scanner_evaluator import (
    NO_RESULT_IN_THE_REPORT,
    NO_RESULT_OF_THE_MAPPED_CHECKS,
    SCANNER_NOT_RUN,
    SCANNER_OUTCOMES,
    SCANNER_VERSION_NOT_ALLOWED,
)
from iltero_schemas.models.common.subjects import subject_key
from tests.common.test_models_event import FROM_SCANNER, _event, _from_scanner


def test_a_scanners_result_stands_for_an_assertion_it_can_see() -> None:
    AssuranceEvent.model_validate(FROM_SCANNER)


@pytest.mark.parametrize(("status", "reason"), sorted(SCANNER_OUTCOMES, key=str))
def test_every_outcome_of_a_scanners_results_makes_a_valid_event(status: str, reason: str | None) -> None:
    AssuranceEvent.model_validate(_from_scanner(**{"evaluation.status": status, "evaluation.status_reason": reason}))


@pytest.mark.parametrize(
    ("status", "reason"),
    [("unknown", "redacted"), ("not_applicable", "when_guard_excluded"), ("not_evaluated", "timeout")],
)
def test_a_scanners_result_gives_no_other_status(status: str, reason: str) -> None:
    changes = {"evaluation.status": status, "evaluation.status_reason": reason}
    with pytest.raises(ValidationError, match="an evaluation from a scanner's results is one of"):
        AssuranceEvent.model_validate(_from_scanner(**changes))


def test_a_scanner_whose_report_holds_no_result_at_all_leaves_no_subject_unknown() -> None:
    changes = {"evaluation.status": "unknown", "evaluation.status_reason": NO_RESULT_IN_THE_REPORT}
    with pytest.raises(ValidationError, match="status_reason must be a reason for status unknown"):
        AssuranceEvent.model_validate(_from_scanner(**changes))


def test_only_an_evaluation_from_a_scanners_result_is_not_evaluated_for_the_scanners_version() -> None:
    changes = {"evaluation.status": "not_evaluated", "evaluation.status_reason": SCANNER_VERSION_NOT_ALLOWED}
    with pytest.raises(
        ValidationError, match=f"only an evaluation from a scanner's results is {SCANNER_VERSION_NOT_ALLOWED}"
    ):
        AssuranceEvent.model_validate(_event(**changes))


def test_a_member_of_a_scanner_requirement_that_gave_no_report_names_its_bound_checks_and_nothing_it_read() -> None:
    AssuranceEvent.model_validate(
        _from_scanner(**{"evaluation.status": "not_evaluated", "evaluation.status_reason": SCANNER_NOT_RUN})
    )


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"provenance.evaluator.version": "3.3.8"}, "names no version and no input exactly when"),
        ({"provenance.input_digest": "sha256:" + "a" * 64}, "names no version and no input exactly when"),
        ({"provenance.evaluator.result_addresses": ["aws_db_instance.payments"]}, "decided none of its mapped checks"),
        ({"provenance.evaluator.undecided_rule_ids": []}, "decided none of its mapped checks"),
    ],
    ids=["a version", "an input", "a resource read", "a check decided"],
)
def test_a_member_of_a_scanner_requirement_that_gave_no_report_names_nothing_it_did_not_do(
    changes: dict[str, Any], message: str
) -> None:
    not_run = {"evaluation.status": "not_evaluated", "evaluation.status_reason": SCANNER_NOT_RUN}
    with pytest.raises(ValidationError, match=message):
        AssuranceEvent.model_validate(_from_scanner(**not_run, **changes))


def test_a_scanner_that_gave_a_report_names_its_version_and_the_report() -> None:
    with pytest.raises(ValidationError, match="names no version and no input exactly when"):
        AssuranceEvent.model_validate(_from_scanner(**{"provenance.evaluator.version": None}))


def test_a_scanners_result_is_about_a_resource() -> None:
    unit = {"scheme": "iltero_unit", "value": "root", "scope": None}
    key = subject_key("change", [Identity(scheme="iltero_unit", value="root")])
    changes = {"subject.kind": "change", "subject.identities": [unit], "subject.key": key}
    with pytest.raises(ValidationError, match="an evaluation from a scanner's result is about a resource"):
        AssuranceEvent.model_validate(_from_scanner(**changes))


def test_a_scanners_result_reads_no_facts_from_the_server() -> None:
    with pytest.raises(ValidationError, match="an evaluation from a scanner's result reads no facts from the server"):
        AssuranceEvent.model_validate(_from_scanner(**{"provenance.facts_source": "server"}))


@pytest.mark.parametrize(
    ("field", "value"), [("digest", "sha256:" + "a" * 64), ("platform", "linux-x86_64"), ("python_version", "cp312")]
)
def test_a_scanners_evaluation_leaves_what_ran_to_its_report(field: str, value: str) -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        AssuranceEvent.model_validate(_from_scanner(**{f"provenance.evaluator.{field}": value}))


@pytest.mark.parametrize("assertion_id", sorted(NOT_DECIDED_BY_SCANNERS))
def test_an_assertion_no_scanner_decides_is_never_decided_by_a_scanners_result(assertion_id: str) -> None:
    event = copy.deepcopy(FROM_SCANNER)
    event["assertion"]["id"] = assertion_id
    with pytest.raises(ValidationError, match=f"{assertion_id} is never decided by a scanner's result"):
        AssuranceEvent.model_validate(event)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("rule_ids", ["CKV_AWS_17", "CKV_AWS_16"], "rule_ids is sorted, each once"),
        ("result_addresses", ["b", "a"], "result_addresses is sorted, each once"),
        ("unknown_paths", ["x", "x"], "unknown_paths is sorted, each once"),
        ("failed_rule_ids", ["CKV_AWS_99"], "name mapped checks"),
        ("undecided_rule_ids", ["CKV_AWS_99"], "name mapped checks"),
    ],
)
def test_a_scanner_evaluator_names_its_checks_resources_and_paths_once_in_order(
    field: str, value: list[str], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        AssuranceEvent.model_validate(_from_scanner(**{f"provenance.evaluator.{field}": value}))


def test_a_check_is_failed_or_undecided_never_both() -> None:
    changes = {
        "provenance.evaluator.failed_rule_ids": ["CKV_AWS_16"],
        "provenance.evaluator.undecided_rule_ids": ["CKV_AWS_16"],
    }
    with pytest.raises(ValidationError, match="each in one of them"):
        AssuranceEvent.model_validate(_from_scanner(**changes))


_RULES: list[str] = FROM_SCANNER["provenance"]["evaluator"]["rule_ids"]


@pytest.mark.parametrize(
    "changes",
    [
        {"provenance.evaluator.result_addresses": ["aws_db_instance.main"]},
        {"provenance.evaluator.unknown_paths": ["publicly_accessible"]},
        {"provenance.evaluator.failed_rule_ids": _RULES[:1], "provenance.evaluator.undecided_rule_ids": _RULES[1:]},
        {"provenance.evaluator.undecided_rule_ids": []},
    ],
    ids=["a resource read", "an unknown path", "a failed check", "a check decided"],
)
def test_a_scanner_whose_report_holds_no_result_of_its_checks_decided_none_of_them_and_read_no_resource(
    changes: dict[str, Any],
) -> None:
    reason = {"evaluation.status": "not_evaluated", "evaluation.status_reason": NO_RESULT_OF_THE_MAPPED_CHECKS}
    with pytest.raises(ValidationError, match="holds no result of its mapped checks decided none of them"):
        AssuranceEvent.model_validate(_from_scanner(**reason, **changes))


def test_a_scanner_whose_report_holds_no_result_at_all_decided_none_of_its_checks_and_read_no_resource() -> None:
    reason = {"evaluation.status": "not_evaluated", "evaluation.status_reason": NO_RESULT_IN_THE_REPORT}
    AssuranceEvent.model_validate(_from_scanner(**reason))
    with pytest.raises(ValidationError, match="holds no result at all decided none of its checks"):
        AssuranceEvent.model_validate(_from_scanner(**reason, **{"provenance.evaluator.undecided_rule_ids": []}))
