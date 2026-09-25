"""``AssuranceFacts`` v1: what Iltero Compass knows about a run that the pipeline cannot say for itself.

Some checks need facts only Iltero Compass holds: who approved the change,
which exceptions are in force, earlier evaluations. The facts document carries
them for one run and one stage, scoped to the stack, environment and change
they were issued for. A tool places each part into the part of the evaluation
input with the same name.

Until Iltero Compass can supply a part, it sends an unknown marker in its place
rather than an empty list. The difference decides the verdict: an assertion
that looks for an approval in an empty list fails, as if the change had been
refused; the same assertion over a marker yields ``unknown`` with the
marker's reason, which says what is true — the answer was not available.
"""

from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict, Field

from iltero_schemas.models.base import StrictModel
from iltero_schemas.models.fields import Digest, EnvironmentKey, RunStage, Timestamp, Uuid

API_VERSION = "iltero.io/assurance-facts/v1"
# Why a part of the facts is missing; the evaluator's runtime copies it into the result.
UnknownReason = Literal["server_facts_unavailable"]


class UnknownMarker(StrictModel):
    """What stands where a fact could not be supplied: the evaluator reads it as ``unknown``, with this reason.

    It is always written under its marker name, ``__unknown``, which is the name the evaluator looks for.
    """

    model_config = ConfigDict(serialize_by_alias=True)

    unknown: Literal[True] = Field(alias="__unknown")
    reason: UnknownReason


class FactsScope(StrictModel):
    """What the facts were issued for: the change, by its digest over every unit's plan; null before a plan."""

    stack_id: Uuid
    environment: EnvironmentKey
    change_digest: Digest | None


class AssuranceFacts(StrictModel):
    """The facts for one run and one stage. Every part is a marker until Iltero Compass can fill it."""

    api_version: Literal["iltero.io/assurance-facts/v1"] = Field(alias="apiVersion")
    run_id: Uuid
    stage: RunStage
    scope: FactsScope
    issued_at: Timestamp
    approvals: UnknownMarker
    exceptions: UnknownMarker
    evaluations: UnknownMarker
