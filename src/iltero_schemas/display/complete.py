"""Whether a display words file has exactly one entry for each code the contract defines, and none extra.

Every set is taken from the contract's own constants: the result statuses and their reasons (``event.STATUS_REASONS``),
the verdicts and their reasons (``coverage.VERDICT_RANKING``), the reasons a served exception does not cover a result
an exception was about (``served_exceptions.NoServedExceptionReason``), the trust levels and their reasons
(``report_trust.TRUST_LEVEL_RESULTS``), the trust files a signing key is listed in (``trust.operator.ListedIn``), the
verification states, and each property's results (``verification.PROPERTY_RESULTS``, with the result of a record whose
integrity failed).
"""

from __future__ import annotations

from collections.abc import Collection, Iterable
from typing import Any, Literal, get_args, get_origin

from iltero_schemas.display.model import DisplayWords, ProcessOutcome
from iltero_schemas.models.common.coverage import VERDICT_RANKING, VerdictValue
from iltero_schemas.models.common.event import STATUS_REASONS
from iltero_schemas.models.common.exception_terms import NO_EXCEPTION_FOR_THE_ASSERTION_AND_RESOURCE
from iltero_schemas.models.common.fields import Status
from iltero_schemas.models.common.report_trust import TRUST_LEVEL_RESULTS, TrustLevel
from iltero_schemas.models.common.served_exceptions import NoServedExceptionReason
from iltero_schemas.models.common.verification import COULD_NOT_DECIDE, INTEGRITY_FAILED, PROPERTY_RESULTS
from iltero_schemas.models.common.verification_states import Result, VerificationState
from iltero_schemas.trust.operator import ListedIn


def literal_values(annotation: Any) -> frozenset[str]:
    """Every value of a ``Literal``, or of a union of them."""
    if get_origin(annotation) is Literal:
        return frozenset(get_args(annotation))
    return frozenset(value for member in get_args(annotation) for value in literal_values(member))


def reported_results(name: str) -> frozenset[Result]:
    """Every result a verification report may give property ``name``: those of ``PROPERTY_RESULTS``, and the result a
    record whose integrity failed gives it."""
    return PROPERTY_RESULTS[name] | {INTEGRITY_FAILED if name == "integrity" else COULD_NOT_DECIDE}


def near_miss_reasons() -> frozenset[str]:
    """Why a served exception about a failed result's assertion and resource did not cover it."""
    return literal_values(NoServedExceptionReason) - {NO_EXCEPTION_FOR_THE_ASSERTION_AND_RESOURCE}


def named(key: str | Result) -> str:
    """A code, or a verification result in words: "state verified with reason run_statement", or "… with no reason"."""
    if isinstance(key, str):
        return key
    state, reason = key
    return f"state {state} with {'no reason' if reason is None else f'reason {reason}'}"


def _difference(where: str, given: Iterable[Any], expected: Collection[Any]) -> list[str]:
    given = set(given)
    missing = sorted(map(named, set(expected) - given))
    extra = sorted(map(named, given - set(expected)))
    return [f"{where} has no entry for {key}" for key in missing] + [
        f"{where} has an entry for {key}, which the contract does not define" for key in extra
    ]


def _status_reason_problems(words: DisplayWords) -> list[str]:
    problems = _difference("status_reasons", words.status_reasons, STATUS_REASONS)
    groups: dict[str, set[str]] = {}
    for status, reasons in words.status_reasons.items():
        problems += _difference(f"status_reasons.{status}", reasons, STATUS_REASONS.get(status, ()))
        for reason in reasons.values():
            if reason.group is not None:
                groups.setdefault(reason.group, set()).add(status)
    problems += [
        f"status_reason_groups has no group {group}" for group in sorted(set(groups) - set(words.status_reason_groups))
    ]
    problems += [
        f"no status reason reads in group {group}" for group in sorted(set(words.status_reason_groups) - set(groups))
    ]
    return problems + [
        f"group {group} holds reasons of more than one status" for group in sorted(groups) if len(groups[group]) > 1
    ]


def _reason_problems(words: DisplayWords) -> list[str]:
    """The verdicts' and the trust levels' reasons."""
    problems: list[str] = []
    for value, verdict in words.verdicts.items():
        verdict_reasons = {reason for given, reason in VERDICT_RANKING if given == value and reason is not None}
        problems += _difference(f"verdicts.{value}.reasons", verdict.reasons, verdict_reasons)
    for level, entry in words.trust_levels.items():
        level_reasons = {reason for given, reason in TRUST_LEVEL_RESULTS if given == level}
        problems += _difference(f"trust_levels.{level}.reasons", entry.reasons, level_reasons)
    return problems


def _property_problems(words: DisplayWords) -> list[str]:
    """The verification properties and each one's results."""
    problems = _difference("verification_properties", words.verification_properties, PROPERTY_RESULTS)
    for name, entry in words.verification_properties.items():
        given = [(result.state, result.reason) for result in entry.results]
        expected = reported_results(name) if name in PROPERTY_RESULTS else frozenset()
        problems += _difference(f"verification_properties.{name}", given, expected)
    return problems


def completeness_problems(words: DisplayWords) -> list[str]:
    """Every entry ``words`` lacks or holds beyond the contract's codes, and every reason group it names wrongly; none
    for a complete file."""
    return [
        *_difference("result_statuses", words.result_statuses, literal_values(Status)),
        *_status_reason_problems(words),
        *_difference("verdicts", words.verdicts, literal_values(VerdictValue)),
        *_difference("notes.no_exception_in_force", words.notes.no_exception_in_force, near_miss_reasons()),
        *_difference("trust_levels", words.trust_levels, literal_values(TrustLevel)),
        *_reason_problems(words),
        *_difference("signed_by", words.signed_by, literal_values(ListedIn)),
        *_difference("verification_states", words.verification_states, literal_values(VerificationState)),
        *_property_problems(words),
        *_difference("process_outcomes", words.process_outcomes, literal_values(ProcessOutcome)),
    ]
