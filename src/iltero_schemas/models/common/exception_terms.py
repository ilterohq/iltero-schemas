"""What a project's own exception and an exception the server serves share: what one covers, when it holds, and the
rules both follow.

An exception says that an assertion does not have to hold for an environment and the resources it names, between two
times. A project writes its own in a ``LocalExceptions`` file (``models.common.local_exceptions``); the server serves
its own in a ``ServedExceptions`` document (``models.common.served_exceptions``). Both name each resource by its
address in the IaC tool's configuration, scoped by its unit, the identity the plan stage keys the subject by: a
resource being created has no cloud identity yet, and one that is replaced gets a new one.

The functions here read either shape through ``ExceptionTerms``, so one rule decides which exception covers a result,
whichever wrote it.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import timedelta
from typing import Literal, Protocol, TypeVar

from iltero_schemas.assertions.paths import BUILT_IN_IDS
from iltero_schemas.models.common.fields import Identity, parse_timestamp
from iltero_schemas.models.common.subjects import ADDRESS_IDENTITY_SCHEMES

# The most resources one exception covers.
MAX_EXCEPTION_RESOURCES = 256
# The longest an exception may hold, from when it starts, so each is reviewed at least once a year.
MAX_EXCEPTION_DAYS = 365
MAX_EXCEPTION_DURATION = timedelta(days=MAX_EXCEPTION_DAYS)

# Why no exception covers a result: none is about its assertion and resource; those that are name another environment,
# or the run names none; or every one has expired, or one holds only later.
NoExceptionReason = Literal[
    "no_exception_for_the_assertion_and_resource",
    "for_another_environment",
    "run_names_no_environment",
    "not_yet_in_force",
    "expired",
]


class AssertionTerms(Protocol):
    """The assertion an exception is about, by its id."""

    @property
    def id(self) -> str: ...


class ScopeTerms(Protocol):
    """What an exception covers: an assertion, in one environment, for the resources it names."""

    @property
    def assertion(self) -> AssertionTerms: ...

    @property
    def environment(self) -> str: ...

    @property
    def resources(self) -> Sequence[Identity]: ...


class ExceptionTerms(Protocol):
    """An exception of either shape: its id, what it covers and the times it holds between."""

    @property
    def id(self) -> str: ...

    @property
    def scope(self) -> ScopeTerms: ...

    @property
    def valid_from(self) -> str: ...

    @property
    def expires_at(self) -> str: ...


AnyException = TypeVar("AnyException", bound=ExceptionTerms)


def check_exception(exception: ExceptionTerms) -> None:
    """Raise ``ValueError`` unless ``exception`` follows the rules every exception follows: it never covers a built-in
    assertion, it names each resource by its address scoped by its unit, and it ends after it starts and at most
    ``MAX_EXCEPTION_DAYS`` later."""
    if exception.scope.assertion.id in BUILT_IN_IDS:
        raise ValueError("an exception never covers a built-in assertion: what it records is never waived")
    if any(
        r.scheme not in ADDRESS_IDENTITY_SCHEMES or r.scope is None or set(r.scope) != {"unit"}
        for r in exception.scope.resources
    ):
        raise ValueError("an exception names each resource by its address, scoped by its unit and nothing else")
    ends, starts = parse_timestamp(exception.expires_at), parse_timestamp(exception.valid_from)
    if ends <= starts:
        raise ValueError("an exception expires after it starts")
    if (ends[0] - starts[0], ends[1]) > (MAX_EXCEPTION_DURATION, starts[1]):
        raise ValueError(f"an exception lasts at most {MAX_EXCEPTION_DAYS} days from when it starts")


def check_exception_list(exceptions: Sequence[ExceptionTerms]) -> None:
    """Raise ``ValueError`` unless each exception has an id of its own and at most one covers an assertion,
    environment and resource at any time, so the one that covers a result is never a choice."""
    ids = [exception.id for exception in exceptions]
    if len(set(ids)) != len(ids):
        raise ValueError("each exception has an id of its own")
    for index, exception in enumerate(exceptions):
        if any(_overlap(exception, other) for other in exceptions[index + 1 :]):
            raise ValueError("no two exceptions cover the same assertion, environment and resource at the same time")


def _resource_key(identity: Identity) -> tuple[str, str, tuple[tuple[str, str], ...] | None]:
    scope = None if identity.scope is None else tuple(sorted(identity.scope.items()))
    return (identity.scheme, identity.value, scope)


def _overlap(first: ExceptionTerms, second: ExceptionTerms) -> bool:
    """Whether two exceptions cover one assertion, environment and resource at some same time."""
    if (first.scope.assertion.id, first.scope.environment) != (second.scope.assertion.id, second.scope.environment):
        return False
    if not {_resource_key(r) for r in first.scope.resources} & {_resource_key(r) for r in second.scope.resources}:
        return False
    return parse_timestamp(first.valid_from) <= parse_timestamp(second.expires_at) and parse_timestamp(
        second.valid_from
    ) <= parse_timestamp(first.expires_at)


def in_force(exception: ExceptionTerms, at: str) -> bool:
    """Whether ``exception`` holds at the time ``at``: from ``valid_from`` up to and including ``expires_at``."""
    return parse_timestamp(exception.valid_from) <= parse_timestamp(at) <= parse_timestamp(exception.expires_at)


def covers(exception: ExceptionTerms, assertion_id: str, identity: Identity) -> bool:
    """Whether ``exception`` is about ``assertion_id`` and names the resource ``identity`` names: the same scheme, value
    and scope."""
    return exception.scope.assertion.id == assertion_id and any(
        _resource_key(resource) == _resource_key(identity) for resource in exception.scope.resources
    )


def exception_in_force(
    exceptions: Iterable[AnyException], assertion_id: str, identity: Identity, environment: str | None, at: str
) -> AnyException | None:
    """The exception that covers ``assertion_id`` for the resource ``identity`` names, in ``environment``, at the
    time ``at``: at most one does (``check_exception_list``). None when none does, and for a run that names no
    environment."""
    for exception in exceptions:
        if (
            covers(exception, assertion_id, identity)
            and exception.scope.environment == environment
            and in_force(exception, at)
        ):
            return exception
    return None


def why_no_exception(
    exceptions: Iterable[ExceptionTerms], assertion_id: str, identity: Identity, environment: str | None, at: str
) -> NoExceptionReason | None:
    """Why no exception covers the result ``exception_in_force`` is asked about; None when one does."""
    covering = [exception for exception in exceptions if covers(exception, assertion_id, identity)]
    if not covering:
        return "no_exception_for_the_assertion_and_resource"
    if environment is None:
        return "run_names_no_environment"
    here = [exception for exception in covering if exception.scope.environment == environment]
    if not here:
        return "for_another_environment"
    if any(in_force(exception, at) for exception in here):
        return None
    # Between two exceptions, the next one is not yet in force.
    if all(parse_timestamp(exception.expires_at) < parse_timestamp(at) for exception in here):
        return "expired"
    return "not_yet_in_force"
