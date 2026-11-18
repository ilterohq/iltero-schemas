"""``ServedExceptions``: the exceptions the server serves one stage of a run it opened.

A served exception (``ServedException``) says that an assertion does not have to hold for an environment and the
resources it names, between two times, why, who asked for it and who approved it in Iltero, and when. It names the
assertion's document it was approved for by its digest.

The server serves the exceptions in force for one stage of one run as this document. The stage keeps it, so a reader
can work out again which exception covers each result. The rules every exception follows, and how one is matched to a
result, are in ``models.common.exception_terms``.

The contract checks that the requester and the approver are different accounts of one identity provider. That is the
least it can check: the server compares them as Iltero users, and records whether the requester's Iltero user is
whoever started the run or triggered the attempt the exception is served to (``requester_is_run_actor``).
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_validator

from iltero_schemas.models.common.base import API_VERSION as API_VERSION
from iltero_schemas.models.common.base import StageValue, StrictModel
from iltero_schemas.models.common.exception_terms import (
    MAX_EXCEPTION_RESOURCES,
    check_exception,
    check_exception_list,
)
from iltero_schemas.models.common.fields import AssertionRef, Identifier, Identity, Timestamp, Uuid, parse_timestamp
from iltero_schemas.models.common.server_facts import MAX_FACT_ITEMS, Actor, Text

KIND = "ServedExceptions"


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
