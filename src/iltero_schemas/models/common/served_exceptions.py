"""``ServedExceptions``: the exceptions the server serves one stage of a run it opened.

A served exception (``ServedException``) says that an assertion does not have to hold for an environment and the
resources it names, between two times, why, who asked for it and who approved it in Iltero, and when. It names the
assertion's document it was approved for by its digest.

The server serves the exceptions in force for one stage of one run as this document, with the stage's run token. The
stage keeps a copy of it and names each failed result an exception covers (``ServedExceptionsUsed``). The result stays
failed: an exception records an approved deviation beside it, never in its place. A reader works out again which
exception covers each failed result (``served_exception_for``) from the copy the record keeps. That shows the record
agrees with the copy it kept, not that the server served it: only the server can check that. The rules every exception
follows are in ``models.common.exception_terms``.

The contract checks that the requester and the approver are different accounts of one identity provider. That is the
least it can check: the server compares them as Iltero users, and records whether the requester's Iltero user is
whoever started the run or triggered the attempt the exception is served to (``requester_is_run_actor``).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Annotated, Literal

from pydantic import Field, model_validator

from iltero_schemas.models.common.base import API_VERSION as API_VERSION
from iltero_schemas.models.common.base import StageValue, StrictModel
from iltero_schemas.models.common.exception_terms import (
    MAX_EXCEPTION_RESOURCES,
    NoExceptionReason,
    check_exception,
    check_exception_list,
    exception_in_force,
    named_by_its_address,
    resource_key,
    why_no_exception,
)
from iltero_schemas.models.common.fields import (
    AssertionRef,
    Digest,
    Identifier,
    Identity,
    MemberPath,
    Timestamp,
    Uuid,
    parse_timestamp,
)
from iltero_schemas.models.common.server_facts import MAX_FACT_ITEMS, Actor, Engine, Text

KIND = "ServedExceptions"
# The largest served exceptions document, in canonical JSON bytes: far more than the exceptions in force for one stage
# need, and bounded because a reader reads the stage's copy whole. The server serves none larger.
MAX_SERVED_EXCEPTIONS_BYTES = 16 * 1024 * 1024

# Why no served exception covers a failed result: a reason any exception gives, or one only a served exception gives.
# The one that covers the assertion and resource was approved for another document of the assertion (another digest or
# version), or was approved after the stage's reference time.
NoServedExceptionReason = (
    NoExceptionReason | Literal["approved_for_another_document_of_the_assertion", "approved_after_the_reference_time"]
)


class ResourcesScope(StrictModel):
    """What a served exception covers: one assertion's document, in one environment, for the resources it names.

    ``kind`` names the shape: an exception about resources. Another kind of scope is a shape of its own.
    """

    kind: Literal["resources"]
    assertion: AssertionRef
    environment: Identifier
    resources: Annotated[list[Identity], Field(min_length=1, max_length=MAX_EXCEPTION_RESOURCES)]


class ServedException(StrictModel):
    """One exception approved in Iltero: an assertion waived for an environment and resources, between two times,
    why, who asked for it, who approved it and when."""

    id: Identifier
    status: Literal["approved"]
    scope: ResourcesScope
    valid_from: Timestamp
    expires_at: Timestamp
    requested_by: Actor
    approved_by: Actor
    approved_at: Timestamp
    # Whether the requester's Iltero user started the run or triggered the attempt it is served to, as the server found.
    requester_is_run_actor: bool
    reason: Text

    @model_validator(mode="after")
    def _follows_the_rules_of_a_served_exception(self) -> ServedException:
        check_exception(self)
        if parse_timestamp(self.approved_at) > parse_timestamp(self.expires_at):
            raise ValueError("an exception is approved no later than it expires")
        if self.requested_by.provider != self.approved_by.provider:
            raise ValueError("an exception names who asked for it and who approved it by one identity provider")
        if self.requested_by.id == self.approved_by.id:
            raise ValueError("an exception is approved by someone other than who asked for it")
        return self


class ServedExceptionsMetadata(StrictModel):
    """The run and the stage the exceptions were served to."""

    run_id: Uuid
    stage: StageValue


class ServedExceptionsSpec(StrictModel):
    """The exceptions in force for the stage, each id once, and at most one for an assertion, environment and resource
    at any time, so the one that covers a result is never a choice. Empty when none is."""

    exceptions: Annotated[list[ServedException], Field(max_length=MAX_FACT_ITEMS)]

    @model_validator(mode="after")
    def _one_exception_at_a_time(self) -> ServedExceptionsSpec:
        check_exception_list(self.exceptions)
        return self


class ServedExceptions(StrictModel):
    """The exceptions the server served one stage of a run."""

    api_version: Literal["iltero.com/v1"] = Field(alias="apiVersion")
    kind: Literal["ServedExceptions"]
    metadata: ServedExceptionsMetadata
    spec: ServedExceptionsSpec


def served_exception_for(
    exceptions: Iterable[ServedException], assertion: AssertionRef, identity: Identity, environment: str | None, at: str
) -> ServedException | NoServedExceptionReason:
    """The served exception that covers a failed result of ``assertion`` for the resource ``identity`` names, in
    ``environment``, at the stage's reference time ``at``: one in force then, approved for that assertion's document
    (its id, version and digest) and approved no later than ``at``. Otherwise why none does, the reasons any exception
    gives first."""
    exceptions = list(exceptions)
    reason = why_no_exception(exceptions, assertion.id, identity, environment, at)
    if reason is not None:
        return reason
    found = exception_in_force(exceptions, assertion.id, identity, environment, at)
    if found is None:
        raise AssertionError("why_no_exception found an exception in force, so exception_in_force finds it too")
    if found.scope.assertion != assertion:
        return "approved_for_another_document_of_the_assertion"
    if parse_timestamp(found.approved_at) > parse_timestamp(at):
        return "approved_after_the_reference_time"
    return found


class ExceptedFailure(StrictModel):
    """A failed result of the stage that a served exception covers: the assertion, the resource, the evaluator that
    gave it (together, the one event they name) and the exception."""

    assertion: AssertionRef
    resource: Identity
    engine: Engine
    exception_id: Identifier

    @model_validator(mode="after")
    def _named_by_its_address(self) -> ExceptedFailure:
        if not named_by_its_address(self.resource):
            raise ValueError("an excepted failed result names its resource by its address, scoped by its unit")
        return self


class ServedExceptionsUsed(StrictModel):
    """The served exceptions a stage applied: the digest of the ``ServedExceptions`` document's canonical JSON, where
    the stage keeps those canonical bytes, and each failed result an exception covers.

    ``excepted_failures`` is sorted by assertion id, resource and engine, each once; empty when no exception covers a
    failed result.
    """

    digest: Digest
    copy_path: MemberPath
    excepted_failures: Annotated[list[ExceptedFailure], Field(max_length=MAX_FACT_ITEMS)]

    @model_validator(mode="after")
    def _sorted_each_once(self) -> ServedExceptionsUsed:
        keys = [_failure_key(failure) for failure in self.excepted_failures]
        if keys != sorted(set(keys)):
            raise ValueError("excepted_failures is sorted by assertion id, resource and engine, each once")
        return self


def _failure_key(failure: ExceptedFailure) -> tuple[str, tuple[str, str, tuple[tuple[str, str], ...]], str]:
    scheme, value, scope = resource_key(failure.resource)
    return (failure.assertion.id, (scheme, value, scope or ()), failure.engine)
