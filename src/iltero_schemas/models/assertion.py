"""``TechnicalAssertion`` v1: the envelope of a rule an author writes.

A technical assertion names what is checked (``metadata``), at which point of
the change lifecycle (``spec.stage``), about which kind of thing
(``spec.target``), and the check itself (``spec.assert``) with an optional
applicability guard (``spec.when``). The check is written in the assertion
language, whose grammar is parsed and validated by ``iltero_schemas.ast``;
this module validates everything around it.

Every model refuses unknown keys. ``spec.type`` is derived from
``spec.target.kind`` (``resource`` is a *state* assertion, everything else a
*process* assertion); an author may write it, but only the derived value is
accepted.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# ``ILT.<...>`` names an Iltero-maintained assertion, ``<ORG>.<...>`` a
# customer one: upper-case segments joined by dots, at least two of them.
ID_PATTERN = r"^[A-Z][A-Z0-9_]*(\.[A-Z][A-Z0-9_]*)+$"
ID_MAX_LENGTH = 128
# A name Windows reserves for a device; an id becomes a file name and the
# part before its first dot would be taken for the device.
_WINDOWS_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
)
# The human version string: semantic version core, advisory only; evidence
# cites the digest. Bounded because it becomes part of a file name.
VERSION_PATTERN = r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
VERSION_MAX_LENGTH = 32
TITLE_MAX_LENGTH = 200
NAME_PATTERN = r"^[a-z][a-z0-9_]*$"
PROVIDER_MAX_LENGTH = 32
RESOURCE_TYPE_MAX_LENGTH = 128
RESOURCE_TYPES_MAX = 64
# Characters no human-readable field or literal may contain: C0 and C1
# controls, DEL, zero-width and bidirectional formatting characters.
CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")


class Stage(StrEnum):
    """Where in the change lifecycle an assertion is evaluated."""

    PLAN = "plan"
    PRE_DEPLOY = "pre_deploy"
    POST_DEPLOY = "post_deploy"
    POST_VERIFY = "post_verify"
    RUNTIME = "runtime"


class TargetKind(StrEnum):
    """What kind of thing an assertion is about."""

    RESOURCE = "resource"
    CHANGE = "change"
    DEPLOYMENT = "deployment"
    ASSURANCE = "assurance"


class AssertionType(StrEnum):
    """A state assertion checks properties; a process assertion checks relationships."""

    STATE = "state"
    PROCESS = "process"


DERIVED_TYPE: dict[TargetKind, AssertionType] = {
    TargetKind.RESOURCE: AssertionType.STATE,
    TargetKind.CHANGE: AssertionType.PROCESS,
    TargetKind.DEPLOYMENT: AssertionType.PROCESS,
    TargetKind.ASSURANCE: AssertionType.PROCESS,
}

# The only combinations an assertion may declare; anything else is rejected.
VALID_COMBINATIONS: frozenset[tuple[AssertionType, Stage, TargetKind]] = frozenset(
    {
        (AssertionType.STATE, Stage.PLAN, TargetKind.RESOURCE),
        (AssertionType.STATE, Stage.POST_VERIFY, TargetKind.RESOURCE),
        (AssertionType.STATE, Stage.RUNTIME, TargetKind.RESOURCE),
        (AssertionType.PROCESS, Stage.PRE_DEPLOY, TargetKind.CHANGE),
        (AssertionType.PROCESS, Stage.POST_DEPLOY, TargetKind.DEPLOYMENT),
        (AssertionType.PROCESS, Stage.POST_VERIFY, TargetKind.DEPLOYMENT),
        (AssertionType.PROCESS, Stage.POST_VERIFY, TargetKind.ASSURANCE),
        (AssertionType.PROCESS, Stage.RUNTIME, TargetKind.DEPLOYMENT),
        (AssertionType.PROCESS, Stage.RUNTIME, TargetKind.ASSURANCE),
    }
)


_ID = re.compile(ID_PATTERN)


def assert_assertion_id(value: str) -> str:
    """Return ``value`` when it has the shape of an assertion id; raise ``ValueError`` otherwise."""
    if not _ID.fullmatch(value) or len(value) > ID_MAX_LENGTH:
        raise ValueError(f"not an assertion id: {value!r}")
    return value


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _title(value: str) -> str:
    if not value.strip():
        raise ValueError("must not be empty")
    if CONTROL_CHARACTERS.search(value):
        raise ValueError("must not contain control characters")
    return value


class Metadata(_Strict):
    """Identity of the assertion as an author names it."""

    id: Annotated[str, Field(pattern=ID_PATTERN, max_length=ID_MAX_LENGTH)]
    version: Annotated[str, Field(pattern=VERSION_PATTERN, max_length=VERSION_MAX_LENGTH)]
    title: Annotated[str, Field(max_length=TITLE_MAX_LENGTH)]

    @model_validator(mode="after")
    def _check(self) -> Metadata:
        if self.id.split(".")[0] in _WINDOWS_DEVICE_NAMES:
            raise ValueError(f"id must not start with {self.id.split('.')[0]!r}, a name Windows reserves for a device")
        _title(self.title)
        return self


class ResourceTarget(_Strict):
    """A state assertion's target: resources of the named types from one provider."""

    kind: Literal["resource"]
    provider: Annotated[str, Field(pattern=NAME_PATTERN, max_length=PROVIDER_MAX_LENGTH)]
    resource_types: Annotated[
        list[Annotated[str, Field(pattern=NAME_PATTERN, max_length=RESOURCE_TYPE_MAX_LENGTH)]],
        Field(min_length=1, max_length=RESOURCE_TYPES_MAX),
    ]

    @model_validator(mode="after")
    def _unique(self) -> ResourceTarget:
        if len(set(self.resource_types)) != len(self.resource_types):
            raise ValueError("resource_types must not repeat a type")
        return self


class ProcessTarget(_Strict):
    """A process assertion's target: the change, the deployment or the assurance history."""

    kind: Literal["change", "deployment", "assurance"]


Target = Annotated[ResourceTarget | ProcessTarget, Field(discriminator="kind")]


class Spec(_Strict):
    """What is checked, when, and about what."""

    type: AssertionType | None = None
    stage: Stage
    target: Target
    when: dict[str, Any] | None = None
    assert_: dict[str, Any] = Field(alias="assert")

    @property
    def derived_type(self) -> AssertionType:
        return DERIVED_TYPE[TargetKind(self.target.kind)]

    @model_validator(mode="after")
    def _combination(self) -> Spec:
        derived = self.derived_type
        if self.type is not None and self.type != derived:
            raise ValueError(
                f"type {self.type.value!r} does not match target kind {self.target.kind!r} ({derived.value})"
            )
        if (derived, self.stage, TargetKind(self.target.kind)) not in VALID_COMBINATIONS:
            raise ValueError(f"stage {self.stage.value!r} is not valid for target kind {self.target.kind!r}")
        return self


class TechnicalAssertion(_Strict):
    """The document an author writes; ``registry`` fields are never accepted from an author."""

    api_version: Literal["iltero.io/v1"] = Field(alias="apiVersion")
    kind: Literal["TechnicalAssertion"]
    metadata: Metadata
    spec: Spec
