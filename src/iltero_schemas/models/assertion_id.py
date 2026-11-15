"""The parts of an assertion id, each in a fixed place, so an id says what kind of check it is.

An assertion id reads, segment by segment, joined by dots::

    <NAMESPACE>.<CHANGE_TYPE>.<TARGET>.<SCOPE...>.<CHECK>

- the namespace: ``ILT`` for Iltero's own assertions, a project's own name for its own;
- the change type the assertion is about (``CHANGE_TYPE_SEGMENT``), or ``COMMON`` for every change type;
- the target kind, which tells a check of a resource's state (``RESOURCE``) from a check of a process
  (``CHANGE``, ``DEPLOYMENT``, ``ARTIFACT``, ``ASSURANCE``);
- the scope: for a resource, its provider and service (``AWS.RDS``); for a process, one area. Iltero's own
  process assertions take an area from ``ASSERTION_AREAS``; a project names its own;
- the check, in plain words.

So ``ILT.IAC.RESOURCE.AWS.RDS.STORAGE_ENCRYPTED`` is Iltero's check of an RDS resource's state in an IaC change,
and ``ILT.COMMON.CHANGE.APPROVAL.PRODUCTION_APPROVED`` Iltero's check of an approval, for every change type. Each
list grows by a value: a new change type, provider, target kind or area moves no existing id. Once released, an id
is never renamed: a renamed check is a new assertion.

The change-type segment says what an assertion is about, not which change it was evaluated in: a ``COMMON``
assertion is evaluated in records of every change type. Evidence is grouped by change with an event's
``evaluation.activity``. An area compares only within one namespace, and a resource's service is the author's word.

``ILT`` is Iltero's alone: a project's own id has a namespace of its own that does not start with ``ILT``.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Literal

from iltero_schemas.models.change_type import CHANGE_TYPE_SEGMENT, COMMON_SEGMENT, ChangeTypeName

# Iltero's own namespace, and the start of every one of its ids.
ILTERO_NAMESPACE = "ILT"
ILTERO_ID_PREFIX = f"{ILTERO_NAMESPACE}."
# A name Windows reserves for a device; an id becomes a file name and the part before its first dot would be taken
# for the device.
WINDOWS_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
)
# The most characters an assertion id, and each of its segments, has: long enough for plain words, short enough to
# read at a glance.
ASSERTION_ID_MAX_LENGTH = 96
SEGMENT_MAX_LENGTH = 48
# The areas of Iltero's own process assertions. A new area adds a value.
ASSERTION_AREAS = frozenset({"APPROVAL", "SOURCE", "CONTENT", "DRIFT", "BUILD", "CHECKS", "PROVENANCE", "HISTORY"})
# Every target kind, as ``models.assertion.TargetKind`` lists them (a test holds the two together).
TargetKindName = Literal["resource", "change", "deployment", "artifact", "assurance"]
# How many segments the scope has, by target kind: a resource's provider and service; a process's one area.
SCOPE_SEGMENTS: Mapping[TargetKindName, int] = MappingProxyType(
    {"resource": 2, "change": 1, "deployment": 1, "artifact": 1, "assurance": 1}
)
_CHANGE_TYPE_OF_SEGMENT: Mapping[str, ChangeTypeName] = MappingProxyType(
    {segment: change_type for change_type, segment in CHANGE_TYPE_SEGMENT.items()}
)


def check_project_id(identifier: str) -> None:
    """Raise ``ValueError`` unless ``identifier``, an id a project gives its own assertion or binding set, has a
    namespace of its own: not Iltero's, and not one that reads like it."""
    if identifier.split(".")[0].startswith(ILTERO_NAMESPACE):
        raise ValueError(f"a project's own id has a namespace of its own, not {ILTERO_NAMESPACE} or one starting so")


def provider_segment(provider: str) -> str:
    """A provider's name as an id segment: upper case, a hyphen written as an underscore (``google-beta`` gives
    ``GOOGLE_BETA``)."""
    return provider.upper().replace("-", "_")


def change_type_segment(change_type: ChangeTypeName | None) -> str:
    """The id segment of ``change_type``, or ``COMMON`` for an assertion about every change type."""
    return COMMON_SEGMENT if change_type is None else CHANGE_TYPE_SEGMENT[change_type]


def change_type_of_id(assertion_id: str) -> ChangeTypeName | None:
    """The change type an id's second segment names, or None for ``COMMON``; raises ``ValueError`` for another."""
    parts = assertion_id.split(".")
    if len(parts) < 5:
        raise ValueError("an assertion id must be NAMESPACE.CHANGE_TYPE.TARGET.SCOPE.CHECK")
    segment = parts[1]
    if segment == COMMON_SEGMENT:
        return None
    if segment not in _CHANGE_TYPE_OF_SEGMENT:
        named = ", ".join([*sorted(_CHANGE_TYPE_OF_SEGMENT), COMMON_SEGMENT])
        raise ValueError(f"an assertion id's second segment names its change type: one of {named}")
    return _CHANGE_TYPE_OF_SEGMENT[segment]


def check_assertion_id(
    assertion_id: str, change_type: ChangeTypeName | None, target_kind: TargetKindName, provider: str | None
) -> None:
    """Raise ``ValueError`` unless ``assertion_id`` names, in their places, the change type, target kind and, for a
    resource, the ``provider`` the assertion declares."""
    if len(assertion_id) > ASSERTION_ID_MAX_LENGTH:
        raise ValueError(f"an assertion id must be at most {ASSERTION_ID_MAX_LENGTH} characters")
    parts = assertion_id.split(".")
    if any(len(part) > SEGMENT_MAX_LENGTH for part in parts):
        raise ValueError(f"each segment of an assertion id must be at most {SEGMENT_MAX_LENGTH} characters")
    if parts[0] in WINDOWS_DEVICE_NAMES:
        raise ValueError("an assertion id must not start with a name Windows reserves for a device")
    if parts[0] != ILTERO_NAMESPACE and parts[0].startswith(ILTERO_NAMESPACE):
        raise ValueError(
            f"an assertion id's namespace must be {ILTERO_NAMESPACE} or one not starting {ILTERO_NAMESPACE}"
        )
    scope = SCOPE_SEGMENTS[target_kind]
    if len(parts) != 4 + scope:
        shape = "PROVIDER.SERVICE" if target_kind == "resource" else "AREA"
        article = "an" if target_kind[0] in "aeiou" else "a"
        raise ValueError(
            f"{article} {target_kind} assertion's id must be NAMESPACE.CHANGE_TYPE.{target_kind.upper()}.{shape}.CHECK"
        )
    expected = change_type_segment(change_type)
    if parts[1] != expected:
        about = "change_type: null" if change_type is None else f"change_type: {change_type}"
        raise ValueError(f"the id's second segment must be {expected}, for {about}")
    if parts[2] != target_kind.upper():
        raise ValueError(f"the id's third segment must be {target_kind.upper()}, for target kind {target_kind}")
    if target_kind == "resource":
        if provider is None:
            raise ValueError("a resource assertion's id is checked against its provider")
        if parts[3] != provider_segment(provider):
            raise ValueError(f"the id's fourth segment must be {provider_segment(provider)}, for provider {provider}")
    elif parts[0] == ILTERO_NAMESPACE and parts[3] not in ASSERTION_AREAS:
        raise ValueError(f"an Iltero process assertion's area must be one of {', '.join(sorted(ASSERTION_AREAS))}")
