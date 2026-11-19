"""One call makes every check a reader makes of a record of a change made with an IaC tool."""

from __future__ import annotations

import json
from typing import Any

from iltero_schemas.canonical.common.encoding import canonical_bytes, digest
from iltero_schemas.models.common.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.iac.exception_evidence import SERVED_NOT_GIVEN
from iltero_schemas.models.iac.kept_file_problems import kept_file_problems
from iltero_schemas.models.iac.kept_files import KeptFiles
from iltero_schemas.vectors.kept_files import kept_files_of_case
from tests.conftest import VECTORS, documents
from tests.records import every_kept_copy, valid_case_record

EVERY_FAILURE = (
    "iac_record_of_a_run_the_server_opened_whose_every_plan_failure_a_served_exception_covers_and_one_check_undecided"
)


NOTHING_ELSE_OPEN = "iac_record_of_a_run_the_server_opened_whose_every_plan_failure_a_served_exception_covers"


def _files(case: str | None = None) -> KeptFiles:
    """The served exceptions every case's plan stage may have kept, and the evaluation inputs ``case``'s record kept:
    each in the case's own folder, or else in the folder of the record it is built on."""
    kept = [canonical_bytes(json.loads(path.read_text(encoding="utf-8"))) for path in documents("served_exceptions")]
    kept += every_kept_copy("served-exceptions.json")
    inputs: dict[str, bytes] = {}
    if case is not None:
        cases = json.loads((VECTORS / "records_valid" / "iac" / "cases.json").read_text(encoding="utf-8"))
        by_path = kept_files_of_case(next(c for c in cases if c["name"] == case))
        for ref in valid_case_record("iac", case)["evidence_refs"]:
            if ref["path"] in by_path and "/contexts/" in ref["path"]:
                inputs[digest(by_path[ref["path"]])] = by_path[ref["path"]]
    return KeptFiles(
        scanner_check_mappings={},
        observations={},
        reports={},
        plans={},
        assertions={},
        local_exceptions={},
        served_exceptions={digest(data): data for data in kept},
        inputs=inputs,
    )


def _problems(record: dict[str, Any], case: str | None = None) -> list[tuple[str, str]]:
    return kept_file_problems(CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True}), _files(case))


def test_a_record_whose_every_claim_a_reader_works_out_again_has_no_problem() -> None:
    assert _problems(valid_case_record("iac", NOTHING_ELSE_OPEN), NOTHING_ELSE_OPEN) == []


def test_a_record_whose_every_failure_is_excepted_and_one_check_undecided_has_no_problem() -> None:
    assert _problems(valid_case_record("iac", EVERY_FAILURE), EVERY_FAILURE) == []


def test_an_exception_the_kept_copy_does_not_hold_is_listed() -> None:
    record = valid_case_record("iac", EVERY_FAILURE)
    record["stages"]["plan"]["served_exceptions"]["excepted_failures"][0]["exception_id"] = "exc_9999"
    assert ("stages.plan.served_exceptions.excepted_failures", SERVED_NOT_GIVEN) in _problems(record)


def test_a_verdict_the_counts_do_not_give_is_listed_even_when_the_model_skipped_the_integrity_checks() -> None:
    record = valid_case_record("iac", EVERY_FAILURE)
    record["stages"]["plan"]["verdict"]["value"] = "not_met"
    record["stages"]["plan"]["verdict"]["reason"] = "every_failure_excepted"
    assert ("stages.plan.verdict", "is not the verdict the stage's counts give") in _problems(record)


def test_a_cases_kept_inputs_are_exactly_the_inputs_its_evaluations_name() -> None:
    car = CAR.model_validate(valid_case_record("iac", NOTHING_ELSE_OPEN), context={SKIP_INTEGRITY_CHECKS: True})
    named = {event.provenance.input_digest for event in car.events if event.provenance.scanner_checks is None}
    assert set(_files(NOTHING_ELSE_OPEN).inputs) == named - {None}
