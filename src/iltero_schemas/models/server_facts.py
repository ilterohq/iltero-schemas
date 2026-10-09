"""The facts only the server holds, as an evaluation input carries them: approvals, exceptions, earlier evaluations.

Each is normalised whatever produced it, so an assertion compares neutral
fields only.

- An **approval** names what it approves (``subject``): a change, by its
  digest, or a run, by Iltero's run id. ``method`` says how it was obtained;
  an approval obtained by a CI system's deployment review names no role,
  since none is verified. ``independence`` says whether the approver is someone
  other than whoever started the run or triggered the attempt; a
  self-approval the policy permitted names that policy's version. ``actor.id``
  is the provider's stable account id, never a login, a name or an address.
- An **exception** waives one assertion for an environment and the resources
  it names, between two times.
- An **earlier evaluation** is the result of one check of an earlier stage.

All three are the server's claims, as served.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AfterValidator, Field, model_validator

from iltero_schemas.models.base import StageValue, StrictModel, TargetKindValue
from iltero_schemas.models.fields import (
    Address,
    AssertionId,
    AssertionKey,
    Digest,
    Identifier,
    Identity,
    Status,
    Timestamp,
    Uuid,
    instant,
    plain_text,
)

# The most items of each kind one facts document carries: more than one stage needs.
MAX_FACT_ITEMS = 256
# The most resources one exception covers.
MAX_EXCEPTION_RESOURCES = 256
MAX_ROLES = 32
# Free text a person wrote, such as why an exception was granted.
TEXT_MAX_LENGTH = 1024
Text = Annotated[str, Field(min_length=1, max_length=TEXT_MAX_LENGTH), AfterValidator(plain_text)]
Independence = Literal["independent", "self_permitted_by_policy"]
# How an approval was obtained: a CI system's deployment review, or a review in Iltero itself.
ApprovalMethod = Literal["ci_deployment_review", "iltero_review"]


class Actor(StrictModel):
    """A person or workload, named by the system that knows them."""

    provider: Identifier
    id: Identifier


class ChangeSubject(StrictModel):
    """An approval of one change: its digest binds it to that plan and no other."""

    kind: Literal["change"]
    digest: Digest


class RunSubject(StrictModel):
    """An approval of one run, by Iltero's run id: it approves the run, not a plan's content."""

    kind: Literal["run"]
    id: Uuid


ApprovalSubject = Annotated[ChangeSubject | RunSubject, Field(discriminator="kind")]


class Approval(StrictModel):
    """One approval, normalised whatever produced it."""

    id: Identifier
    actor: Actor
    roles: Annotated[list[Identifier], Field(max_length=MAX_ROLES)]
    status: Literal["approved"]
    subject: ApprovalSubject
    method: ApprovalMethod
    independence: Independence
    policy_version: Identifier | None
    timestamp: Timestamp

    @model_validator(mode="after")
    def _consistent(self) -> Approval:
        if (self.policy_version is None) != (self.independence == "independent"):
            raise ValueError("an approval names the policy version exactly when the policy permitted a self-approval")
        if self.method == "ci_deployment_review" and self.roles:
            raise ValueError("an approval a CI deployment review gave names no role: none is verified")
        return self


class AssertionName(StrictModel):
    """An assertion by its id: an exception covers every version of it."""

    id: AssertionId


class ExceptionScope(StrictModel):
    """What an exception covers: one assertion, in one environment, for the resources it names."""

    assertion: AssertionName
    environment: Identifier
    resources: Annotated[list[Identity], Field(min_length=1, max_length=MAX_EXCEPTION_RESOURCES)]


class ExceptionGrant(StrictModel):
    """One exception: an assertion waived for an environment and resources, between two times."""

    id: Identifier
    status: Literal["approved"]
    scope: ExceptionScope
    valid_from: Timestamp
    expires_at: Timestamp
    approved_by: Actor
    reason: Text

    @model_validator(mode="after")
    def _ends_after_it_starts(self) -> ExceptionGrant:
        if instant(self.expires_at) <= instant(self.valid_from):
            raise ValueError("an exception expires after it starts")
        return self


class EvaluatedSubject(StrictModel):
    """What an earlier check was about: its kind and local id."""

    kind: TargetKindValue
    id: Address


class Result(StrictModel):
    """What an earlier check found."""

    status: Status


class EarlierEvaluation(StrictModel):
    """The result of one check of an earlier stage, as the server recorded it."""

    id: Identifier
    assertion: AssertionKey
    stage: StageValue
    subject: EvaluatedSubject
    result: Result
    plan_digest: Digest | None
    observed_at: Timestamp


Approvals = Annotated[list[Approval], Field(max_length=MAX_FACT_ITEMS)]
Exceptions = Annotated[list[ExceptionGrant], Field(max_length=MAX_FACT_ITEMS)]
Evaluations = Annotated[list[EarlierEvaluation], Field(max_length=MAX_FACT_ITEMS)]
