"""What a stage read of the facts only the server holds: the unknown marker, and the facts' envelope.

Some checks need facts only the server holds: who approved the change,
which exceptions are in force, earlier evaluations. Until the server can
supply such a part, the evaluation input holds an unknown marker in its place
rather than an empty list. The difference decides the verdict: an assertion
that looks for an approval in an empty list fails, as if the change had been
refused; the same assertion over a marker yields ``unknown`` with the
marker's reason, which says what is true — the answer was not available.

A stage that read facts from the server keeps the envelope of the document it
received (``FactsReceived``): what it was issued for and when, and the digest
of the document as received, so a record can be reconciled with what the
server issued. It is the writer's copy of that envelope.
"""

from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict, Field

from iltero_schemas.models.base import StageValue, StrictModel
from iltero_schemas.models.fields import Digest, EnvironmentKey, Identifier, Timestamp, Uuid

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
    """What the facts were issued for: the stack, the environment, and the unit's change; null names no change."""

    stack_id: Uuid
    environment: EnvironmentKey
    change_digest: Digest | None


class FactsReceived(StrictModel):
    """The envelope of the facts document a stage received: its kind, the run and stage it was issued for, when,
    what for, and its digest. It holds none of the facts themselves, so it proves nothing about an approval."""

    # The facts document is the server's own message; the contract records only the kind it named.
    api_version: Identifier
    run_id: Uuid
    stage: StageValue
    issued_at: Timestamp
    scope: FactsScope
    # ``canonical.digest_of`` of the whole facts document as parsed from the response body, every member as received.
    digest: Digest
