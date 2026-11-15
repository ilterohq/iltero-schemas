"""Every scanner result a stage's source suppressed names exactly the project's exception its kept file gives it.

A stage that applied the project's own exceptions file keeps a byte copy of it
(``models.local_exceptions.LocalExceptionsUsed``). A reader reads that copy and
works out again, for each result the scanned source suppressed, which exception
covers it: the same assertion, the resource's address in the plan, the run's
environment and the stage's reference time (``exception_in_force``). The record
must name that exception, or none when none covers it: naming another claims an
approval the file does not give, and leaving one out hides one it does. Whether
an exception is in force is judged at the stage's reference time, which is only as
trustworthy as its source.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from iltero_schemas.canonical.encoding import digest
from iltero_schemas.models.checked_content import CheckedPlan
from iltero_schemas.models.iac.tool_names import ADDRESS_SCHEMES
from iltero_schemas.models.local_exceptions import exception_in_force, read_local_exceptions
from iltero_schemas.models.scanner_evaluator import SUPPRESSED_IN_SOURCE, ScannerEvaluator
from iltero_schemas.models.server_facts import ExceptionGrant

if TYPE_CHECKING:
    from iltero_schemas.models.car import CAR
    from iltero_schemas.models.event import AssuranceEvent
    from iltero_schemas.models.kept_files import KeptFiles

NOT_KEPT = "the record does not keep an exceptions file with the digest the stage names"
NOT_READABLE = "is not a project's exceptions file the contract can read"
NOT_GIVEN = "names an exception the kept exceptions file does not give this result"
LEFT_OUT = "names no exception, but the kept exceptions file gives this result one"


def _given(car: CAR, event: AssuranceEvent, grants: list[ExceptionGrant]) -> ExceptionGrant | None:
    """The exception the kept file gives the event's result, worked out as the stage worked it out."""
    content = event.provenance.checked_content
    scheme = ADDRESS_SCHEMES.get(content.tool) if isinstance(content, CheckedPlan) else None
    identity = next((each for each in event.subject.identities if each.scheme == scheme), None)
    if identity is None:
        return None
    at = car.stages[event.evaluation.stage].reference_time.value
    return exception_in_force(grants, event.assertion.id, identity, car.subject.environment, at)


def exception_problems(car: CAR, files: KeptFiles) -> list[tuple[str, str]]:
    """Every stage's exceptions file that cannot be read from its kept copy, and every suppressed scanner result whose
    named exception, or lack of one, is not what that file gives it, as (where, what) pairs.

    Call only on a record whose structure holds (``check_structure``): each named exception is then from its stage's
    file. A stage that applied no file names no exception, so it has nothing to check.
    """
    problems: list[tuple[str, str]] = []
    for stage, record in car.stages.items():
        used = record.scanners.local_exceptions if record.scanners is not None else None
        if used is None:
            continue
        where = f"stages.{stage.value}.scanners.local_exceptions"
        data = files.exceptions.get(used.digest)
        if data is None or digest(data) != used.digest:
            problems.append((where, NOT_KEPT))
            continue
        try:
            grants = read_local_exceptions(data, used.file_path).spec.exceptions
        except ValueError:
            problems.append((where, NOT_READABLE))
            continue
        for index, event in enumerate(car.events):
            evaluator = event.provenance.evaluator
            if (
                event.evaluation.stage is not stage
                or not isinstance(evaluator, ScannerEvaluator)
                or event.evaluation.status_reason != SUPPRESSED_IN_SOURCE
            ):
                continue
            named, given = evaluator.local_exception, _given(car, event, grants)
            at = f"events.{index}.provenance.evaluator.local_exception"
            if named is None and given is not None:
                problems.append((at, LEFT_OUT))
            elif named is not None and (given is None or given.id != named.id):
                problems.append((at, NOT_GIVEN))
    return problems
