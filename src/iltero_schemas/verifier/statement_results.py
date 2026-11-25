"""What a run statement changes in a record's results.

A run statement that verified and holds for the record (it lists the record as one the server accepted, and the record
differs from it in nothing) covers the facts it signs, so each result that rests on them becomes ``verified``, naming
that basis (``UPGRADED_BY_RUN_STATEMENT``): the record's integrity, the CI jobs of its stages, the approvals, commit
review and exceptions the server served, the reference times, the bundle the run was held to, and the apply job's facts
(only the server's own times, limit and pinned plan). What the statement does not sign stays the record's claim: the
received plan file and rendered plan the apply job reported, the re-plan, the evaluator, the scanners and the check
after deployment.

``stage_completeness`` is decided only for the stages the record holds: for the unit's subject that reports every
stage it expects, by the gaps the statement names of the unit; for the subject that lacks one, as the record alone
gives it (the run ended, so the stage will never be reported); for a record a later one replaced, which holds none of
the later stages, ``later_record_holds_the_later_stages``, which the check after deployment of such a record names
too in place of a stage still pending.

A statement that verified and differs from the record fails each property a difference is about
(``FAILED_BY_DIFFERENCE``, ``FAILED_BY_SERVED_PART``), the first difference in the comparison's order giving the
detail; every other result stays as the record alone gives it. The differences that fail no property, another run,
unit, activity, environment, enforcement mode or build, a run the server did not open, and a record the statement
does not list as accepted, show only in the trust level and the run statement's problems.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import TYPE_CHECKING

from iltero_schemas.models.common.kept_files import KeptFiles
from iltero_schemas.models.common.run_statement import RunStatement
from iltero_schemas.models.common.verification import PropertyResult
from iltero_schemas.models.common.verification_states import (
    LATER_RECORD_HOLDS_THE_LATER_STAGES,
    RUN_STATEMENT,
    SERVED_PART_DIFFERS,
    Result,
)
from iltero_schemas.models.iac.apply_job_results import CHECK_OF_PROPERTY
from iltero_schemas.statement.differences import RecordComparison, ServedPartDiffers, StatementDifference
from iltero_schemas.statement.reasons import (
    BUNDLE_DIFFERS,
    BUNDLE_OF_ANOTHER_SERVER,
    CI_JOB_DIFFERS,
    EXPECTED_STAGES_DIFFER,
    REFERENCE_TIME_DIFFERS,
    REQUIRED_ASSERTIONS_DIFFER,
    SCANNER_CHECK_MAPPING_DIFFERS,
    STAGE_NOT_LISTED,
)
from iltero_schemas.verifier.record_results import exceptions_result, result

if TYPE_CHECKING:
    from iltero_schemas.models.common.car import CAR

# The result of the check after deployment a later record's result replaces for a record that lacks the stage.
STAGE_PENDING: Result = ("not_assessed", "stage_pending")
# Each result a run statement that holds for the record upgrades, by property, and what it becomes.
UPGRADED_BY_RUN_STATEMENT: Mapping[tuple[str, Result], Result] = MappingProxyType(
    {
        ("integrity", ("claimed_by_record", "file_digests")): RUN_STATEMENT,
        ("source_identity", ("not_assessed", "ci_job_held_by_server")): RUN_STATEMENT,
        ("approval_identity", ("claimed_by_record", "approvals_listed")): RUN_STATEMENT,
        ("commit_review", ("claimed_by_record", "reviewed")): RUN_STATEMENT,
        ("reference_time", ("claimed_by_record", "server")): RUN_STATEMENT,
        ("bundle_used", ("claimed_by_record", "server_bundle_named")): (
            "verified",
            "served_and_named_by_every_accepted_result",
        ),
        ("plan_age", ("claimed_by_record", "plan_age_within_limit")): RUN_STATEMENT,
        ("apply_job_approval_order", ("claimed_by_record", "approved_after_plan_stage_record_accepted")): RUN_STATEMENT,
        ("pinned_plan", ("claimed_by_record", "evaluated_plan_is_pinned_plan")): (
            "verified",
            "pinned_and_named_by_accepted_record",
        ),
    }
)
# The properties each difference of a record from its statement fails, with the difference's code as the reason.
FAILED_BY_DIFFERENCE: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        CI_JOB_DIFFERS: ("source_identity",),
        REFERENCE_TIME_DIFFERS: ("reference_time",),
        BUNDLE_DIFFERS: ("bundle_used",),
        BUNDLE_OF_ANOTHER_SERVER: ("bundle_signature",),
        EXPECTED_STAGES_DIFFER: ("stage_completeness",),
        STAGE_NOT_LISTED: ("stage_completeness",),
        REQUIRED_ASSERTIONS_DIFFER: ("stage_completeness",),
        SCANNER_CHECK_MAPPING_DIFFERS: ("scanner_reports",),
    }
)
# The properties a served part whose kept copy differs from the signed one fails, by the part's name in
# ``ServedPartDigests``: every property about the apply job reads its facts, and the approval order its approvals too.
FAILED_BY_SERVED_PART: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "approvals": ("approval_identity", "apply_job_approval_order"),
        "commit_review": ("commit_review",),
        "served_exceptions": ("exceptions",),
        "apply_job_facts": tuple(CHECK_OF_PROPERTY),
    }
)


def _with_count(difference: StatementDifference, count: int) -> str:
    """The sentence of ``difference``, and how many more differences fail the same property."""
    more = "" if count == 0 else f" (and {count} more difference{'s' if count > 1 else ''})"
    return f"{difference.problem}{more}"


def failed_by_differences(comparison: RecordComparison) -> dict[str, PropertyResult]:
    """The result of each property a difference of ``comparison`` fails, by property name."""
    found: dict[str, list[tuple[Result, StatementDifference]]] = {}
    for difference in comparison.differences:
        if isinstance(difference, ServedPartDiffers):
            names, failed = FAILED_BY_SERVED_PART[difference.part], SERVED_PART_DIFFERS
        else:
            names, failed = FAILED_BY_DIFFERENCE.get(difference.reason, ()), ("failed", difference.reason)
        for name in names:
            found.setdefault(name, []).append((failed, difference))
    return {name: result(*listed[0][0], _with_count(listed[0][1], len(listed) - 1)) for name, listed in found.items()}


def _counted(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"


def _stage_completeness(car: CAR, statement: RunStatement) -> PropertyResult:
    """``stage_completeness`` of the unit's subject that reports every stage it expects: verified when the run left no
    result it required of the record's unit unanswered; otherwise failed, as abandoned when the run was, with the
    count. Every expected stage of the unit accepted a record, since its subject holds them all."""
    unanswered = sum(gap.unit == car.unit for gap in statement.predicate.gaps.unanswered_results)
    if not unanswered:
        return result(*RUN_STATEMENT)
    run = statement.predicate.run
    count = f"{_counted(unanswered, 'required result', 'required results')} never answered"
    if run.ending == "abandoned":
        return result("failed", "run_abandoned", f"the run was abandoned at {run.ended_at}: {count}")
    return result("failed", "required_results_unanswered", f"the run closed at {run.ended_at}: {count}")


def held_by_run_statement(
    car: CAR,
    files: KeptFiles,
    found: Mapping[str, PropertyResult],
    statement: RunStatement,
    comparison: RecordComparison,
) -> dict[str, PropertyResult]:
    """The results ``found`` of ``car``, which ``comparison`` shows its run statement holds for, as that statement
    leaves them."""
    held = dict(found)
    held["exceptions"] = exceptions_result(car, files, served_copy_signed=True)
    if comparison.listed_as == "subject":
        if car.all_expected_stages_reported:
            held["stage_completeness"] = _stage_completeness(car, statement)
    else:
        detail = f"the run statement names a later record, {comparison.replaced_by}, that holds the later stages"
        held["stage_completeness"] = result(*LATER_RECORD_HOLDS_THE_LATER_STAGES, detail)
        if (held["check_after_deployment"].state, held["check_after_deployment"].reason) == STAGE_PENDING:
            held["check_after_deployment"] = result(*LATER_RECORD_HOLDS_THE_LATER_STAGES, detail)
    held = {name: upgraded(name, kept) for name, kept in held.items()}
    if car.subject.source.repository is None and held["source_identity"].state == "verified":
        held["source_identity"] = result(
            *RUN_STATEMENT, "the record names no repository, so only its commit is verified"
        )
    return held


def refusal_detail(statement: RunStatement, record_digest: str) -> str:
    """Where the run statement lists the record ``record_digest`` as refused: the list, the stage and the reason the
    server signed."""
    gaps = statement.predicate.gaps
    listed = [
        ("records the server read and refused", gaps.refused_records),
        ("uploads refused before reading", gaps.refused_uploads),
    ]
    where, refused = next(
        (name, entry) for name, entries in listed for entry in entries if entry.digest == record_digest
    )
    return f"the run statement lists this record among the {where}, at the {refused.stage} stage, for {refused.reason}"


def upgraded(name: str, found: PropertyResult) -> PropertyResult:
    """``found``, the result of the property ``name``, as a run statement that holds for the record leaves it."""
    after = UPGRADED_BY_RUN_STATEMENT.get((name, (found.state, found.reason)))
    return found if after is None else result(*after, found.detail)
