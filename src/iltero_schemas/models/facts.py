"""The unknown marker: what stands where a fact only the server holds could not be supplied.

Some checks need facts only the server holds: who approved the change,
which exceptions are in force, earlier evaluations. Until the server can
supply such a part, the evaluation input holds an unknown marker in its place
rather than an empty list. The difference decides the verdict: an assertion
that looks for an approval in an empty list fails, as if the change had been
refused; the same assertion over a marker yields ``unknown`` with the
marker's reason, which says what is true — the answer was not available.
"""

from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict, Field

from iltero_schemas.models.base import StrictModel

# Why a part of the facts is missing; the evaluator's runtime copies it into the result.
UnknownReason = Literal["server_facts_unavailable"]


class UnknownMarker(StrictModel):
    """What stands where a fact could not be supplied: the evaluator reads it as ``unknown``, with this reason.

    It is always written under its marker name, ``__unknown``, which is the name the evaluator looks for.
    """

    model_config = ConfigDict(serialize_by_alias=True)

    unknown: Literal[True] = Field(alias="__unknown")
    reason: UnknownReason
