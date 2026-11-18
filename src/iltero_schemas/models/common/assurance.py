"""``assurance``: what an assertion's results were about one subject over time, the input of an assertion about the
assurance history (``spec.target.kind: assurance``).

It names the assertion and the subject, the current result and the one before it,
and what happened in between: the deployments recorded and the exceptions approved.
An input about a subject with no earlier result has no ``previous`` and nothing
``since_previous``.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field, model_validator

from iltero_schemas.models.common.base import StageValue, StrictModel
from iltero_schemas.models.common.fields import AssertionKey, Digest, Status, Timestamp, Uuid, parse_timestamp
from iltero_schemas.models.common.server_facts import MAX_FACT_ITEMS, EvaluatedSubject, ExceptionGrant


class AssuranceResult(StrictModel):
    """One result of the assertion about the subject: its status, the stage that reached it, and when."""

    status: Status
    stage: StageValue
    observed_at: Timestamp


class RecordedDeployment(StrictModel):
    """A deployment recorded for the subject's unit: the record that describes it, its change, and when."""

    record: Uuid
    change_digest: Digest
    deployed_at: Timestamp


class SincePrevious(StrictModel):
    """What happened between the previous result and the current one."""

    deployments: Annotated[list[RecordedDeployment], Field(max_length=MAX_FACT_ITEMS)]
    exceptions: Annotated[list[ExceptionGrant], Field(max_length=MAX_FACT_ITEMS)]


class Assurance(StrictModel):
    """An assertion's results about one subject: now, the time before, and what happened in between."""

    assertion: AssertionKey
    subject: EvaluatedSubject
    current: AssuranceResult
    previous: AssuranceResult | None
    since_previous: SincePrevious | None

    @model_validator(mode="after")
    def _between_two_results(self) -> Assurance:
        if (self.previous is None) != (self.since_previous is None):
            raise ValueError("what happened since the previous result is given exactly when there is one")
        if self.previous is not None and self.since_previous is not None:
            start, end = parse_timestamp(self.previous.observed_at), parse_timestamp(self.current.observed_at)
            if start > end:
                raise ValueError("the previous result comes before the current one")
            if any(not start <= parse_timestamp(d.deployed_at) <= end for d in self.since_previous.deployments):
                raise ValueError("a deployment since the previous result comes between it and the current one")
        return self
