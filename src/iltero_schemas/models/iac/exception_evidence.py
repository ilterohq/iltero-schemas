"""Every exception a record names is exactly the one the copy its stage kept gives the result.

A project writes its own exceptions in a file. A stage that applied the project's own exceptions file keeps a byte copy
of it (``models.common.local_exceptions.LocalExceptionsUsed``). A reader reads that copy and works out again, for each
result the scanned source suppressed, which exception covers it: the same assertion, the resource's address in the
plan, the run's environment and the stage's reference time (``exception_in_force``). The record must name that
exception, or none when none covers it: naming another claims an approval the file does not give, and leaving one out
hides one it does. Whether an exception is in force is judged at the stage's reference time, which is only as
trustworthy as its source.

The server serves its own exceptions to a run it opened. The stage that applies them keeps a canonical copy of the
``ServedExceptions`` document it was served (``models.common.served_exceptions.ServedExceptionsUsed``) and names each
failed result an exception covers. A reader reads that copy, checks it was served to the record's run and stage for the
record's environment, and works out again, for each failed result of the stage about a resource, which exception covers
it (``served_exception_for``): the record must name exactly those. That shows the record agrees with the copy it kept;
only the server can show the copy is what it served.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from iltero_schemas.canonical.common.encoding import canonical_bytes, digest
from iltero_schemas.models.common.checked_content import CheckedPlan
from iltero_schemas.models.common.exception_terms import exception_in_force, resource_key
from iltero_schemas.models.common.fields import Identity
from iltero_schemas.models.common.local_exceptions import LocalException, read_local_exceptions
from iltero_schemas.models.common.scanner_evaluator import SUPPRESSED_IN_SOURCE, ScannerEvaluator
from iltero_schemas.models.common.served_exceptions import (
    MAX_SERVED_EXCEPTIONS_BYTES,
    ServedException,
    ServedExceptions,
    served_exception_for,
)
from iltero_schemas.models.common.strict_json import strict_json
from iltero_schemas.models.iac.tool_names import ADDRESS_SCHEMES

if TYPE_CHECKING:
    from iltero_schemas.models.common.car import CAR
    from iltero_schemas.models.common.event import AssuranceEvent
    from iltero_schemas.models.iac.kept_files import KeptFiles

NOT_KEPT = "the record does not keep an exceptions file with the digest the stage names"
NOT_READABLE = "is not a project's exceptions file the contract can read"
NOT_GIVEN = "names an exception the kept exceptions file does not give this result"
LEFT_OUT = "names no exception, but the kept exceptions file gives this result one"
SERVED_NOT_KEPT = "the record does not keep, as canonical JSON, the served exceptions with the digest the stage names"
SERVED_NOT_READABLE = "is not a served exceptions document the contract can read"
SERVED_ELSEWHERE = "holds exceptions served to another run or stage, or for another environment"
SERVED_NOT_GIVEN = "names a failed result the kept served exceptions do not cover, or not with that exception"
SERVED_LEFT_OUT = "leaves out a failed result the kept served exceptions cover"


def _address(event: AssuranceEvent) -> Identity | None:
    """The identity the event's subject has in the plan, by its address; None for a subject the plan names no address
    for."""
    content = event.provenance.checked_content
    scheme = ADDRESS_SCHEMES.get(content.tool) if isinstance(content, CheckedPlan) else None
    return next((each for each in event.subject.identities if each.scheme == scheme), None)


def _given(car: CAR, event: AssuranceEvent, exceptions: list[LocalException]) -> LocalException | None:
    """The exception the kept file gives the event's result, worked out as the stage worked it out."""
    identity = _address(event)
    if identity is None:
        return None
    at = car.stages[event.evaluation.stage].reference_time.value
    return exception_in_force(exceptions, event.assertion.id, identity, car.subject.environment, at)


def local_exception_problems(car: CAR, files: KeptFiles) -> list[tuple[str, str]]:
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
        data = files.local_exceptions.get(used.digest)
        if data is None or digest(data) != used.digest:
            problems.append((where, NOT_KEPT))
            continue
        try:
            exceptions = read_local_exceptions(data, used.file_path).spec.exceptions
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
            named, given = evaluator.local_exception, _given(car, event, exceptions)
            at = f"events.{index}.provenance.evaluator.local_exception"
            if named is None and given is not None:
                problems.append((at, LEFT_OUT))
            elif named is not None and (given is None or given.id != named.id):
                problems.append((at, NOT_GIVEN))
    return problems


def _read_served(data: bytes | None, named: str) -> ServedExceptions | str:
    """The served exceptions document the stage kept, or the problem with its copy."""
    if data is None or digest(data) != named:
        return SERVED_NOT_KEPT
    if len(data) > MAX_SERVED_EXCEPTIONS_BYTES:
        return SERVED_NOT_READABLE
    try:
        document = strict_json(data, "a served exceptions document")
        canonical = canonical_bytes(document)
    except ValueError:
        return SERVED_NOT_READABLE
    if canonical != data:
        return SERVED_NOT_KEPT
    try:
        return ServedExceptions.model_validate(document)
    except ValueError:
        return SERVED_NOT_READABLE


def _by_assertion_and_resource(exceptions: list[ServedException]) -> dict[tuple[object, ...], list[ServedException]]:
    """The exceptions about each assertion id and resource, so each failed result is matched against those alone."""
    index: dict[tuple[object, ...], list[ServedException]] = {}
    for exception in exceptions:
        for resource in exception.scope.resources:
            index.setdefault((exception.scope.assertion.id, resource_key(resource)), []).append(exception)
    return index


def served_exception_problems(car: CAR, files: KeptFiles) -> list[tuple[str, str]]:
    """Every stage's copy of the exceptions the server served it that cannot be read or was served elsewhere, and every
    failed result the stage names as covered, or leaves out, against what that copy gives, as (where, what) pairs.

    Call on every record a stage of which applied served exceptions, once its structure holds (``check_structure``).
    """
    problems: list[tuple[str, str]] = []
    for stage, record in car.stages.items():
        used = record.served_exceptions
        if used is None:
            continue
        where = f"stages.{stage.value}.served_exceptions"
        served = _read_served(files.served_exceptions.get(used.digest), used.digest)
        if isinstance(served, str):
            problems.append((where, served))
            continue
        exceptions: list[ServedException] = served.spec.exceptions
        if (
            served.metadata.run_id != car.run.id
            or served.metadata.stage is not stage
            or any(exception.scope.environment != car.subject.environment for exception in exceptions)
        ):
            problems.append((where, SERVED_ELSEWHERE))
            continue
        at = record.reference_time.value
        about = _by_assertion_and_resource(exceptions)
        given: dict[tuple[object, ...], str] = {}
        for event in car.events:
            identity = _address(event)
            if event.evaluation.stage is not stage or event.evaluation.status != "fail" or identity is None:
                continue
            candidates = about.get((event.assertion.id, resource_key(identity)), [])
            found = served_exception_for(candidates, event.assertion, identity, car.subject.environment, at)
            if isinstance(found, ServedException):
                given[(event.assertion, resource_key(identity), event.engine)] = found.id
        named = {
            (failure.assertion, resource_key(failure.resource), failure.engine): failure.exception_id
            for failure in used.excepted_failures
        }
        failures = f"{where}.excepted_failures"
        if any(given.get(key) != exception_id for key, exception_id in named.items()):
            problems.append((failures, SERVED_NOT_GIVEN))
        if set(given) - set(named):
            problems.append((failures, SERVED_LEFT_OUT))
    return problems
