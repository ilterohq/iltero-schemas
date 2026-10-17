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
from iltero_schemas.models.fields import Address, Digest, Identifier

# The marker's reason: a short token, as the evaluator's runtime accepts it.
REASON_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"


class RedactedMarker(StrictModel):
    """What stands where a value was hidden: that one was there, why it was hidden, and its type."""

    redacted: Literal[True] = Field(alias="__redacted")
    reason: Annotated[str, Field(pattern=REASON_PATTERN)]
    present: bool
    type: Annotated[str, Field(pattern=REASON_PATTERN)]


# The most paths one redaction report lists in each of its lists: every attribute of the most resources a plan holds.
MAX_REPORTED_PATHS = 1_000_000


class RedactionPolicyRef(StrictModel):
    """The redaction policy that ran, by id, version and digest."""

    id: Identifier
    version: Identifier
    digest: Digest


class RedactedInput(StrictModel):
    """What was redacted, and the digest of the redacted tree."""

    kind: Literal["observation", "facts", "deployment"]
    digest: Digest


# A path in the redacted tree. Map keys are part of a path, so it is plain text with no length limit.
TreePath = str


class HiddenPath(StrictModel):
    """One path the policy hid, and the reason, as a token."""

    path: TreePath
    reason: Annotated[str, Field(pattern=REASON_PATTERN)]


class AllowedPath(StrictModel):
    """One path the project allowed through, with the reason its configuration gives in its own words."""

    path: TreePath
    reason: str


class RedactionReport(StrictModel):
    """What a stage's redaction hid, left unknown or allowed, by path and reason. No value ever appears here."""

    policy: RedactionPolicyRef
    subject: RedactedInput
    redacted: Annotated[list[HiddenPath], Field(max_length=MAX_REPORTED_PATHS)]
    unknown: Annotated[list[TreePath], Field(max_length=MAX_REPORTED_PATHS)]
    allowed: Annotated[list[AllowedPath], Field(max_length=MAX_REPORTED_PATHS)]


# A name that may have been hidden: a hidden name is still a fact about the resource.
MaybeHidden = Identifier | RedactedMarker
MaybeHiddenAddress = Address | RedactedMarker
