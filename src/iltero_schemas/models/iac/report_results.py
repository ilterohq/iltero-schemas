"""The results a verifier gives a record's exceptions and its ``scanner_reports`` property, from the record and its kept
files.

Every verifier that reads the same record and files gives the same results: ``exception_results`` gives the
exception results that hold, which a verifier passes with the pre-deploy results that hold to
``verification.first_that_holds``; ``scanner_reports_result`` gives the ``scanner_reports`` property's one result, the
first of ``verification.SCANNER_REPORTS_RESULT_ORDER`` that holds. A detail names the first problem a check lists and
how many more there are, never a value from a kept file. A verifier calls ``scanner_reports_result`` for every record,
an image change's too, whose activity reads no scanner report. Call both on a record whose integrity holds: a verifier
that could not establish it gives every other property ``could_not_decide``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from iltero_schemas.change_types import ACTIVITIES
from iltero_schemas.models.common.scanner_evaluator import ScannerEvaluator
from iltero_schemas.models.common.scanners import PIPELINE
from iltero_schemas.models.common.verdicts import stage_scanner_requirements, unmet_scanner_requirement
from iltero_schemas.models.common.verification import PropertyResult, VerificationState
from iltero_schemas.models.iac.exception_evidence import (
    kept_served_exceptions,
    local_exception_problems,
    served_exception_problems,
)
from iltero_schemas.models.iac.scanner_results import scanner_evidence_problems

if TYPE_CHECKING:
    from iltero_schemas.models.common.car import CAR
    from iltero_schemas.models.iac.kept_files import KeptFiles

# What a reader of the record and its kept files cannot confirm about an exception the server served.
SERVED_EXCEPTION_RELIED_ON = (
    "the kept copy gives each failure the record names as excepted; only the server that opened the run confirms that "
    "it served that copy, who approved each exception and whether one was revoked, and whether an exception was in "
    "force rests on the stage's reference time"
)
# The same, when the person who approved one of those exceptions started the run.
APPROVED_BY_RUN_STARTER = (
    "the kept copy says the person who approved an exception the record relies on started the run; "
    + SERVED_EXCEPTION_RELIED_ON
)
# An exception result: its state and its reason.
ExceptionResult = tuple[VerificationState, str]


def _detail(problems: list[tuple[str, str]]) -> str:
    """The first problem, where and what, and how many more there are."""
    where, what = problems[0]
    count = len(problems) - 1
    more = "" if count == 0 else f" (and {count} more problem{'s' if count > 1 else ''})"
    return f"{where} {what}{more}"


def exception_results(car: CAR, files: KeptFiles) -> dict[ExceptionResult, str | None]:
    """Every exception result that holds for ``car``, with its detail: whether the exceptions files its stages kept
    give what it names, whether it relied on an exception the server served or one of the project's own, whether one
    of those served exceptions was approved by the person who started the run, and whether its activity applies no
    exception at any stage."""
    holding: dict[ExceptionResult, str | None] = {}
    problems = local_exception_problems(car, files) + served_exception_problems(car, files)
    if problems:
        holding[("failed", "kept_exceptions_do_not_hold")] = _detail(problems)
    for record in car.stages.values():
        used = record.served_exceptions
        if used is None:
            continue
        if not used.excepted_failures:
            holding[("claimed_by_record", "served_exceptions_not_relied_on")] = None
            continue
        # The fixed sentences say what the kept copy gives, so they stand only beside a copy that holds.
        holding[("claimed_by_record", "served_exception_relied_on")] = None if problems else SERVED_EXCEPTION_RELIED_ON
        served = kept_served_exceptions(record, files)
        relied_on = {failure.exception_id for failure in used.excepted_failures}
        if served is not None and any(
            exception.id in relied_on and exception.approver_and_run_starter == "same_user"
            for exception in served.spec.exceptions
        ):
            holding[("claimed_by_record", "served_exception_approved_by_run_starter")] = (
                None if problems else APPROVED_BY_RUN_STARTER
            )
    if any(
        isinstance(event.provenance.evaluator, ScannerEvaluator) and event.provenance.evaluator.local_exception
        for event in car.events
    ):
        holding[("claimed_by_record", "project_exception_relied_on")] = None
    elif any(record.scanners is not None and record.scanners.local_exceptions for record in car.stages.values()):
        holding[("claimed_by_record", "project_exceptions_file_not_relied_on")] = None
    activity = ACTIVITIES[car.change.activity]
    # An activity whose stages apply no exception, the server's or the project's own, such as an image deploy.
    if activity.stage_that_applies_served_exceptions is None and not activity.stages_that_read_scanner_reports:
        holding[("not_assessed", "not_in_activity")] = None
    return holding


def scanner_reports_result(car: CAR, files: KeptFiles) -> PropertyResult:
    """The ``scanner_reports`` property's result for ``car``: whether its scanner verdicts follow from the files its
    stages kept, whether a required group of scanners gave only gaps, and who ran the reports its stages read."""
    problems = scanner_evidence_problems(car, files)
    if problems:
        return PropertyResult(state="failed", reason="kept_files_do_not_give_the_verdicts", detail=_detail(problems))
    for stage, record in car.stages.items():
        events = [event for event in car.events if event.evaluation.stage == stage]
        unmet = unmet_scanner_requirement(events, scanner_requirements=stage_scanner_requirements(record))
        if unmet is not None:
            scanners = ", ".join(sorted(unmet))
            detail = f"in the {stage.value} stage, the required group of {scanners} gave only gaps for a check"
            return PropertyResult(state="not_performed", reason="scanner_requirement_not_met", detail=detail)
    reports = [
        report for record in car.stages.values() if record.scanners is not None for report in record.scanners.reports
    ]
    if any(report.ran_by == PIPELINE for report in reports):
        return PropertyResult(state="claimed_by_record", reason="ran_by_pipeline", detail=None)
    if reports:
        return PropertyResult(state="claimed_by_record", reason="ran_by_iltero_cli", detail=None)
    if not ACTIVITIES[car.change.activity].stages_that_read_scanner_reports:
        return PropertyResult(state="not_assessed", reason="not_in_activity", detail=None)
    return PropertyResult(state="not_assessed", reason="no_scanner_report", detail=None)
