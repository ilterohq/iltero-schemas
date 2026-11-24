"""Redaction in a record: the markers that stand where a value was hidden, the policy that hid it, and the report.

A tool redacts a value it must not pass on, such as a secret in a planned attribute. It writes a marker in its place
that says a value was there, why it was hidden and its type, so an assertion can still tell a hidden value from a
missing one. The fields where a hidden value may legitimately sit accept one. A record writes out the redaction policy
every stage ran, and each stage's report lists, by path and reason, every value it hid, left unknown or exempted.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Annotated, Literal

from pydantic import AfterValidator, BeforeValidator, Field, ValidationError, model_validator

from iltero_schemas.canonical.common.encoding import INT_MAX
from iltero_schemas.models.common.base import StrictModel
from iltero_schemas.models.common.fields import (
    MAX_RESOURCES,
    Address,
    Digest,
    Identifier,
    RawKey,
    plain_text,
)
from iltero_schemas.models.common.sent_documents import MAX_JSON_DEPTH
from iltero_schemas.redaction.common.paths import REDACTION_PATH_PATTERN
from iltero_schemas.redaction.common.value_change import (
    OBSERVATION_SUBJECT,
    ValueChange,
    is_hidden_at_or_above,
    paired_before,
)
from iltero_schemas.redaction.common.words import key_is_shaped_like_a_credential

# What a tool says about a value it hides whatever the policy says: the tool declared it sensitive, or it sits in a
# provider's, a provisioner's or an unplanned resource's configuration, or in a field the reading of a workload does not
# use, which can hold a container's environment values, its arguments, or text another tool or the container wrote.
SensitiveMarkReason = Literal[
    "declared_sensitive",
    "provider_configuration",
    "provisioner_configuration",
    "unplanned_configuration",
    "field_not_read",
]
# Why a policy's own rules hid a value: it equals or holds a value a tool declared sensitive, it sits at a path the
# project configured, its key or the name beside it looks like a credential's, or the value looks like a credential.
PolicyRuleReason = Literal["sensitive_value_reuse", "configured_path", "deny_key", "value_shape"]
# Why a value was hidden: one of a fixed set, never taken from a value.
RedactionReason = SensitiveMarkReason | PolicyRuleReason
# The JSON type of the value a marker stands for.
JsonTypeName = Literal["object", "array", "string", "number", "boolean", "null"]
# Why a value is not in the tree: the tool knows it only after the deployment.
KNOWN_AFTER_DEPLOY = "known_after_deploy"


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
    type: JsonTypeName


class UnknownMarker(StrictModel):
    """What redaction writes where the tool knows a value only after the deployment: the evaluator reads it as
    ``unknown``."""

    unknown: Annotated[Literal[True], BeforeValidator(_true_itself)] = Field(alias="__unknown")
    reason: Literal["known_after_deploy"]
    present: Literal[True]


def is_redaction_marker(value: object) -> bool:
    """Whether ``value`` is a whole redaction marker: what a redaction policy writes where it hid a value."""
    try:
        RedactedMarker.model_validate(value)
    except ValidationError:
        return False
    return True


def is_unknown_marker(value: object) -> bool:
    """Whether ``value`` is exactly the unknown marker redaction writes where a tool knows a value only after the
    deployment."""
    try:
        UnknownMarker.model_validate(value)
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
# The longest reason a project's configuration gives for exempting a path.
EXEMPT_REASON_MAX_LENGTH = 1024
# The most additional and the most exempt paths one policy names, and the longest path it names.
MAX_POLICY_PATHS = 64
MAX_POLICY_PATH_LENGTH = 256
# The grammar of a configured path, the one ``redaction.common.paths`` parses, matched whole.
CONFIGURED_PATH_PATTERN = f"^{REDACTION_PATH_PATTERN.pattern}$"

ConfiguredPath = Annotated[str, Field(max_length=MAX_POLICY_PATH_LENGTH, pattern=CONFIGURED_PATH_PATTERN)]
ExemptReason = Annotated[str, Field(min_length=1, max_length=EXEMPT_REASON_MAX_LENGTH), AfterValidator(plain_text)]


class RedactionPolicyRef(StrictModel):
    """The redaction policy that ran, by id, version and digest."""

    id: Identifier
    version: Identifier
    digest: Digest


class ExemptPathRule(StrictModel):
    """A path a project exempts from its redaction policy, with the reason its configuration gives in its own words."""

    path: ConfiguredPath
    reason: ExemptReason


class RedactionPolicyDocument(StrictModel):
    """The redaction policy a record's stages ran, written out so a reader rebuilds it and its digest.

    It is the built-in policy of ``id`` and ``version`` with the project's additional paths, hidden wherever a
    resource's values appear, and its exempt paths, kept with a reason. A run the server opened exempts none.
    """

    id: Identifier
    version: Identifier
    additional_paths: Annotated[list[ConfiguredPath], Field(max_length=MAX_POLICY_PATHS)]
    exempt_paths: Annotated[list[ExemptPathRule], Field(max_length=MAX_POLICY_PATHS)]


# What a stage redacted: what the plan stage observed, the facts the pre-deploy stage was given, the deployment the
# post-deploy stage read, or the drift check the post-verify stage read.
RedactedKind = Literal["observation", "facts", "deployment", "drift_check", "post_apply_resources"]


class RedactedInput(StrictModel):
    """What was redacted, and the digest of the redacted tree."""

    kind: RedactedKind
    digest: Digest


# A path in a redacted tree: the object keys and list indexes from its root, as the tree writes them. A key is any
# text, even empty, as JSON allows; an index counts from zero.
PathSegment = RawKey | Annotated[int, Field(ge=0, le=INT_MAX)]
# A redacted tree nests no deeper than the documents a stage sends.
MAX_REPORTED_PATH_DEPTH = MAX_JSON_DEPTH
ReportedPath = Annotated[list[PathSegment], Field(max_length=MAX_REPORTED_PATH_DEPTH)]


def path_order(path: Sequence[str | int]) -> tuple[tuple[int, int, str], ...]:
    """The order paths are listed in: segment by segment, a list index before an object key, indexes by number and
    keys by code point."""
    return tuple((0, segment, "") if isinstance(segment, int) else (1, 0, segment) for segment in path)


class RedactedPath(StrictModel):
    """One path the policy hid, the reason, as a token, and, in the report of what the plan stage observed, whether the
    value there changed (``redaction.common.value_change``)."""

    path: ReportedPath
    reason: RedactionReason
    # Null except on a path under a resource change's after in the report of what the plan stage observed.
    value_change: ValueChange | None


class ExemptedPath(StrictModel):
    """One path the project exempted, with the reason its configuration gives in its own words."""

    path: ReportedPath
    reason: ExemptReason


def _listed_in_order(keys: Sequence[tuple[object, ...]]) -> bool:
    return all(earlier < later for earlier, later in zip(keys, keys[1:], strict=False))


class RedactionReport(StrictModel):
    """What a stage's redaction hid, left unknown or exempted, by path and reason. No value ever appears here.

    Each list is in path order (``path_order``), then by reason, with no entry twice. No key on a listed path is
    shaped like a credential: a tool refuses to redact a tree with such a key, as no marker can stand for a key.
    """

    policy: RedactionPolicyRef
    input: RedactedInput
    redacted: Annotated[list[RedactedPath], Field(max_length=MAX_REPORTED_PATHS)]
    unknown: Annotated[list[ReportedPath], Field(max_length=MAX_REPORTED_PATHS)]
    exempted: Annotated[list[ExemptedPath], Field(max_length=MAX_REPORTED_PATHS)]

    @model_validator(mode="after")
    def _paths_in_order_with_no_key_shaped_like_a_credential(self) -> RedactionReport:
        if not (
            _listed_in_order([(path_order(entry.path), entry.reason) for entry in self.redacted])
            and _listed_in_order([(path_order(path),) for path in self.unknown])
            and _listed_in_order([(path_order(entry.path), entry.reason) for entry in self.exempted])
        ):
            raise ValueError("a redaction report lists each path in path order, then by reason, once")
        paths = [entry.path for entry in self.redacted] + self.unknown + [entry.path for entry in self.exempted]
        if any(isinstance(key, str) and key_is_shaped_like_a_credential(key) for path in paths for key in path):
            raise ValueError("a redaction report lists no path through a key shaped like a credential")
        return self


def check_value_changes(report: RedactionReport) -> None:
    """Raise ``ValueError`` unless the entries of ``report`` name value changes as redaction writes them: only in the
    report of what the plan stage observed, exactly on the paths under a resource change's ``after``, the same on every
    entry of one path, and ``changed`` or ``unchanged`` only where the paired path under ``before`` is hidden too and
    the value is not one the report lists as known only after the deployment."""
    if report.input.kind != OBSERVATION_SUBJECT:
        if any(entry.value_change is not None for entry in report.redacted):
            raise ValueError("only the redaction report of what the plan stage observed names a value change")
        return
    hidden = {tuple(entry.path) for entry in report.redacted}
    unknown = {tuple(path) for path in report.unknown}
    named: dict[tuple[str | int, ...], str | None] = {}
    for entry in report.redacted:
        path = tuple(entry.path)
        before = paired_before(path)
        if (before is None) != (entry.value_change is None):
            raise ValueError(
                "the redaction report of what the plan stage observed names a value change exactly on the paths under "
                "a resource change's after"
            )
        if named.setdefault(path, entry.value_change) != entry.value_change:
            raise ValueError("every entry of one path of a redaction report names the same value change")
        if entry.value_change not in ("changed", "unchanged"):
            continue
        if before is not None and not is_hidden_at_or_above(before, hidden):
            raise ValueError(
                "a redaction report says whether a value changed only where the paired value under before is hidden too"
            )
        if path in unknown:
            raise ValueError(
                "a redaction report says whether a value changed only for a value known before the deployment"
            )


# A name that may have been redacted: a redacted name is still a fact about the resource.
MaybeRedacted = Identifier | RedactedMarker
MaybeRedactedAddress = Address | RedactedMarker
