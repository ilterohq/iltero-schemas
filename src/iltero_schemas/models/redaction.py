"""The redaction marker: what stands in an evaluation input where a value was hidden.

A runner may hide a value it must not pass on, such as a secret in a planned
attribute. It writes a marker in its place that says a value was there, why
it was hidden and its type, so a check can still tell a hidden value from a
missing one. The fields where a hidden value may legitimately sit accept one.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from iltero_schemas.models.base import StrictModel
from iltero_schemas.models.fields import Address, Identifier

# The marker's reason: a short token, as the evaluator's runtime accepts it.
REASON_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"


class RedactedMarker(StrictModel):
    """What stands where a value was hidden: that one was there, why it was hidden, and its type."""

    redacted: Literal[True] = Field(alias="__redacted")
    reason: Annotated[str, Field(pattern=REASON_PATTERN)]
    present: bool
    type: Annotated[str, Field(pattern=REASON_PATTERN)]


# A name that may have been hidden: a hidden name is still a fact about the resource.
MaybeHidden = Identifier | RedactedMarker
MaybeHiddenAddress = Address | RedactedMarker
