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

from iltero_schemas.kinds.vocabulary import RESOURCE_KINDS
from iltero_schemas.models.iac import RESOURCE_TYPE_PATTERNS, IacTool

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
# The most kinds one selector names, and the longest kind.
KINDS_MAX = 64
KIND_MAX_LENGTH = 64
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


# A provider's short name, as an assertion and an evaluation input name it (``aws``).
ProviderName = Annotated[str, Field(pattern=NAME_PATTERN, max_length=PROVIDER_MAX_LENGTH)]


class KindSelector(_Strict):
    """Resources of one provider, by the neutral kinds that provider's list names (``kinds.vocabulary``)."""

    provider: ProviderName
    kinds: Annotated[
        list[Annotated[str, Field(pattern=NAME_PATTERN, max_length=KIND_MAX_LENGTH)]],
        Field(min_length=1, max_length=KINDS_MAX),
    ]

    @model_validator(mode="after")
    def _kinds(self) -> KindSelector:
        known = RESOURCE_KINDS.get(self.provider)
        if known is None:
            raise ValueError(f"provider {self.provider!r} has no resource kinds a selector can name")
        if not set(self.kinds) <= known:
            raise ValueError(f"kinds must be {self.provider} resource kinds: {', '.join(sorted(known))}")
        if len(set(self.kinds)) != len(self.kinds):
            raise ValueError("kinds must not repeat a kind")
        return self


class ToolSelector(_Strict):
    """Resources of the named types, from one provider, as one IaC tool names them.

    The one place a target names a tool's own types: for a check that reads that
    tool's attributes. Each tool spells types its own way, so a type is checked
    against the rule of the tool named.
    """

    tool: IacTool
    provider: ProviderName
    resource_types: Annotated[
        list[Annotated[str, Field(min_length=1, max_length=RESOURCE_TYPE_MAX_LENGTH)]],
        Field(min_length=1, max_length=RESOURCE_TYPES_MAX),
    ]

    @model_validator(mode="after")
    def _types(self) -> ToolSelector:
        rule = re.compile(RESOURCE_TYPE_PATTERNS[self.tool])
        if not all(rule.fullmatch(name) for name in self.resource_types):
            raise ValueError(f"resource_types must be {self.tool} resource types")
        if len(set(self.resource_types)) != len(self.resource_types):
            raise ValueError("resource_types must not repeat a type")
        return self


# The most selectors one target names.
SELECTORS_MAX = 16


class ResourceTarget(_Strict):
    """A state assertion's target: the resources its one tool selector picks, whose values are that tool's own."""

    kind: Literal["resource"]
    resources: Annotated[list[ToolSelector], Field(min_length=1, max_length=1)]


class ProcessTarget(_Strict):
    """A process assertion's target: the change, the deployment or the assurance history.

    A change or deployment target may name ``resources``, by kinds so it holds for every tool: it is then in scope
    only when the change touches a resource one of its selectors picks.
    """

    kind: Literal["change", "deployment", "assurance"]
    resources: Annotated[list[KindSelector], Field(min_length=1, max_length=SELECTORS_MAX)] | None = None

    @model_validator(mode="after")
    def _resources(self) -> ProcessTarget:
        if self.resources is not None and self.kind == "assurance":
            raise ValueError("an assurance target names no resources: it has no change to scope")
        return self


Target = Annotated[ResourceTarget | ProcessTarget, Field(discriminator="kind")]


# The stages whose input has a change a target's selectors can scope.
SCOPED_STAGES = frozenset({Stage.PRE_DEPLOY, Stage.POST_DEPLOY})


def check_target(stage: Stage, target: ResourceTarget | ProcessTarget) -> None:
    """Raise ``ValueError`` unless ``target`` is valid at ``stage`` and its selectors have a change to scope."""
    kind = TargetKind(target.kind)
    if (DERIVED_TYPE[kind], stage, kind) not in VALID_COMBINATIONS:
        raise ValueError(f"stage {stage.value!r} is not valid for target kind {target.kind!r}")
    if isinstance(target, ProcessTarget) and target.resources is not None and stage not in SCOPED_STAGES:
        raise ValueError(f"a {target.kind} target at {stage.value} has no change to scope")


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
        check_target(self.stage, self.target)
        return self


class TechnicalAssertion(_Strict):
    """The document an author writes; ``registry`` fields are never accepted from an author."""

    api_version: Literal["iltero.io/v1"] = Field(alias="apiVersion")
    kind: Literal["TechnicalAssertion"]
    metadata: Metadata
    spec: Spec
