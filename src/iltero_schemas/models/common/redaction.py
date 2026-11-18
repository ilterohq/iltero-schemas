"""The redaction marker: what stands in an evaluation input where a value was redacted.

A runner may redact a value it must not pass on, such as a secret in a planned
attribute. It writes a marker in its place that says a value was there, why
it was redacted and its type, so an assertion can still tell a redacted value from a
missing one. The fields where a redacted value may legitimately sit accept one.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AfterValidator, BeforeValidator, Field, ValidationError

from iltero_schemas.canonical.common.encoding import INT_MAX
from iltero_schemas.models.common.base import StrictModel
from iltero_schemas.models.common.fields import MAX_RESOURCES, Address, Digest, Identifier, RawText, plain_text

# The marker's reason: a short token, as the evaluator's runtime accepts it.
REASON_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"
# Why a redaction policy hid a value: one of the policy's own fixed tokens, never taken from a value.
RedactionReason = Annotated[str, Field(pattern=REASON_PATTERN)]


def _true_itself(value: object) -> object:
    # Only JSON ``true`` marks a value redacted, as in the evaluator's runtime: never 1 or 1.0.
    if value is not True:
        raise ValueError("a redaction marker's __redacted is true")
    return value


class RedactedMarker(StrictModel):
    """What stands where a value was redacted: that one was there, why it was redacted, and its type."""

    redacted: Annotated[Literal[True], BeforeValidator(_true_itself)] = Field(alias="__redacted")
    reason: RedactionReason
    present: bool
    type: Annotated[str, Field(pattern=REASON_PATTERN)]


def is_redaction_marker(value: object) -> bool:
    """Whether ``value`` is a whole redaction marker: what a redaction policy writes where it hid a value."""
    try:
        RedactedMarker.model_validate(value)
    except ValidationError:
        return False
    return True


# The most reasons one count of redacted values lists: a bound on its size, as on every list a record holds.
MAX_REDACTION_REASONS = 64
# How many values redaction hid for one reason; never zero, as a reason that hid none is not named.
RedactedValueCount = Annotated[int, Field(ge=1, le=INT_MAX)]
RedactedValueCounts = Annotated[dict[RedactionReason, RedactedValueCount], Field(max_length=MAX_REDACTION_REASONS)]


def redacted_value_counts(document: object) -> dict[str, int]:
    """For each reason, how many redaction markers in ``document`` say a value was there (``present``): the markers the
    document holds, not proof of what a policy did. A marker is an object ``is_redaction_marker`` accepts; the walk
    visits object values and list items, never keys, and never looks inside a marker."""
    counts: dict[str, int] = {}
    stack: list[object] = [document]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            # Only an object whose __redacted is true can be a marker; checking that first keeps the walk cheap.
            if node.get("__redacted") is True and is_redaction_marker(node):
                if node["present"]:
                    counts[node["reason"]] = counts.get(node["reason"], 0) + 1
                continue
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return dict(sorted(counts.items()))


# The most paths one redaction report lists in each of its lists: ten for each of the most resources a plan holds.
MAX_REPORTED_PATHS = 10 * MAX_RESOURCES
# The longest reason a project's configuration gives for allowing a path through.
ALLOWED_REASON_MAX_LENGTH = 1024


class RedactionPolicyRef(StrictModel):
    """The redaction policy that ran, by id, version and digest."""

    id: Identifier
    version: Identifier
    digest: Digest


# What a stage redacted: what the plan stage observed, the facts the pre-deploy stage was given, the deployment the
# post-deploy stage read, or the drift check the post-verify stage read.
RedactedKind = Literal["observation", "facts", "deployment", "drift_check", "post_apply_resources"]


class RedactedInput(StrictModel):
    """What was redacted, and the digest of the redacted tree."""

    kind: RedactedKind
    digest: Digest


# A path in the redacted tree. Map keys are part of a path, so it is kept as written.
TreePath = RawText


class RedactedPath(StrictModel):
    """One path the policy hid, and the reason, as a token."""

    path: TreePath
    reason: RedactionReason


class AllowedPath(StrictModel):
    """One path the project allowed through, with the reason its configuration gives in its own words."""

    path: TreePath
    reason: Annotated[str, Field(min_length=1, max_length=ALLOWED_REASON_MAX_LENGTH), AfterValidator(plain_text)]


class RedactionReport(StrictModel):
    """What a stage's redaction hid, left unknown or allowed, by path and reason. No value ever appears here."""

    policy: RedactionPolicyRef
    input: RedactedInput
    redacted: Annotated[list[RedactedPath], Field(max_length=MAX_REPORTED_PATHS)]
    unknown: Annotated[list[TreePath], Field(max_length=MAX_REPORTED_PATHS)]
    allowed: Annotated[list[AllowedPath], Field(max_length=MAX_REPORTED_PATHS)]


# A name that may have been redacted: a redacted name is still a fact about the resource.
MaybeRedacted = Identifier | RedactedMarker
MaybeRedactedAddress = Address | RedactedMarker
