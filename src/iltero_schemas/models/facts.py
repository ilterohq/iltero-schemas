"""The unknown marker: what stands where a fact could not be supplied.

Some checks need facts only the server holds: who approved the change,
which exceptions are in force, earlier evaluations. Until the server can
supply such a part, the evaluation input holds an unknown marker in its place
rather than an empty list. The difference decides the verdict: an assertion
that looks for an approval in an empty list fails, as if the change had been
refused; the same assertion over a marker yields ``unknown`` with the
marker's reason, which says what is true — the answer was not available.

A fact the IaC tool did not report, such as whether an older tool's plan is
complete, holds a marker of its own (``NotReported``): a null there would read
as a known value.
"""

from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict, Field

from iltero_schemas.models.base import StrictModel

# Why a fact is missing; the evaluator's runtime copies it into the result.
UnknownReason = Literal["server_facts_unavailable"]


class ServerFactsUnavailable(StrictModel):
    """What stands where a fact could not be supplied: the evaluator reads it as ``unknown``, with this reason.

    It is always written under its marker name, ``__unknown``, which is the name the evaluator looks for.
    """

    model_config = ConfigDict(serialize_by_alias=True)

    unknown: Literal[True] = Field(alias="__unknown")
    reason: UnknownReason


class NotReported(StrictModel):
    """What stands where the IaC tool did not report a fact: the evaluator reads it as ``unknown``, with this reason."""

    model_config = ConfigDict(serialize_by_alias=True)

    unknown: Literal[True] = Field(alias="__unknown")
    reason: Literal["not_reported_by_tool"]
