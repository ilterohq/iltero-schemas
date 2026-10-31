"""``TechnicalAssertion`` v1: the envelope of a rule an author writes.

A technical assertion names what is checked (``metadata``), at which point of
the change lifecycle (``spec.stage``), about which kind of thing
(``spec.target``), and the condition itself (``spec.assert``) with an optional
applicability guard (``spec.when``). The condition is written in the assertion
language, whose grammar is parsed and validated by ``iltero_schemas.ast``;
this module validates everything around it.

Every model refuses unknown keys. ``spec.type`` is derived from
``spec.target.kind`` (``resource`` is a *state* assertion, everything else a
*process* assertion); an author may write it, but only the derived value is
accepted.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from iltero_schemas.kinds.vocabulary import RESOURCE_KINDS
from iltero_schemas.models.change_type import IAC_CHANGE_TYPE, ChangeTypeName
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
# The longest suggested action: one instruction sentence, a little longer than a title.
REMEDIATION_MAX_LENGTH = 300
NAME_PATTERN = r"^[a-z][a-z0-9_]*$"
PROVIDER_MAX_LENGTH = 32
RESOURCE_TYPE_MAX_LENGTH = 128
RESOURCE_TYPES_MAX = 64
# The most kinds one selector names, and the longest kind.
KINDS_MAX = 64
KIND_MAX_LENGTH = 64
# Characters no human-readable field or literal may contain: C0 and C1
# controls, DEL, zero-width and bidirectional formatting characters, and the
# characters that show as nothing (soft hyphen, grapheme joiner, Hangul fillers).
CONTROL_CHARACTERS = re.compile(
    r"[\x00-\x1f\x7f-\x9f\xad\u034f\u061c\u115f\u1160\u180e\u200b-\u200f\u2028-\u202e\u2060-\u2064\u2066-\u2069"
    r"\u3164\ufeff\uffa0]"
)


class Stage(StrEnum):
    """Where in the change lifecycle an assertion is evaluated."""

    PLAN = "plan"
    PRE_DEPLOY = "pre_deploy"
    POST_DEPLOY = "post_deploy"
    POST_VERIFY = "post_verify"
    RUNTIME = "runtime"


def stage_name(stage: Stage) -> str:
    """The stage as a reader says it in a sentence, such as "post-verify"."""
    return stage.value.replace("_", "-")


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


ASSERTION_TYPE_FOR_TARGET: dict[TargetKind, AssertionType] = {
    TargetKind.RESOURCE: AssertionType.STATE,
    TargetKind.CHANGE: AssertionType.PROCESS,
    TargetKind.DEPLOYMENT: AssertionType.PROCESS,
    TargetKind.ASSURANCE: AssertionType.PROCESS,
}

Combination = tuple[AssertionType, Stage, TargetKind]
# The combinations an assertion about each change type may declare.
COMBINATIONS: Mapping[ChangeTypeName, frozenset[Combination]] = MappingProxyType(
    {
        IAC_CHANGE_TYPE: frozenset(
            {
                (AssertionType.STATE, Stage.PLAN, TargetKind.RESOURCE),
                (AssertionType.STATE, Stage.RUNTIME, TargetKind.RESOURCE),
                (AssertionType.PROCESS, Stage.PRE_DEPLOY, TargetKind.CHANGE),
                (AssertionType.PROCESS, Stage.POST_DEPLOY, TargetKind.DEPLOYMENT),
                (AssertionType.PROCESS, Stage.POST_VERIFY, TargetKind.DEPLOYMENT),
                (AssertionType.PROCESS, Stage.RUNTIME, TargetKind.DEPLOYMENT),
                (AssertionType.PROCESS, Stage.RUNTIME, TargetKind.ASSURANCE),
            }
        ),
    }
)
# The combinations every change type allows, which an assertion about any change may declare.
SHARED_COMBINATIONS: frozenset[Combination] = frozenset.intersection(*COMBINATIONS.values())
# Every combination some change type allows; anything else is rejected.
VALID_COMBINATIONS: frozenset[Combination] = frozenset().union(*COMBINATIONS.values())


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
    """The assertion's identity, and the text a person reads about it."""

    id: Annotated[str, Field(pattern=ID_PATTERN, max_length=ID_MAX_LENGTH)]
    version: Annotated[str, Field(pattern=VERSION_PATTERN, max_length=VERSION_MAX_LENGTH)]
    title: Annotated[str, Field(max_length=TITLE_MAX_LENGTH)]
    # What a person does to make a failing subject meet the assertion. Shown to people only: the compiler
    # ignores it, so it is in neither the AST nor the source digest.
    remediation: Annotated[str, Field(max_length=REMEDIATION_MAX_LENGTH)] | None = None

    @model_validator(mode="after")
    def _check(self) -> Metadata:
        if self.id.split(".")[0] in _WINDOWS_DEVICE_NAMES:
            raise ValueError(f"id must not start with {self.id.split('.')[0]!r}, a name Windows reserves for a device")
        _title(self.title)
        if self.remediation is not None:
            _title(self.remediation)
        elif "remediation" in self.model_fields_set:
            # The assertion's digest is taken over the document as written: one meaning, one digest.
            raise ValueError("remediation is left out, never null")
        return self


# A provider's short name, as an assertion and an evaluation input name it (``aws``, ``google-beta``).
PROVIDER_PATTERN = r"^[a-z][a-z0-9_-]*$"
ProviderName = Annotated[str, Field(pattern=PROVIDER_PATTERN, max_length=PROVIDER_MAX_LENGTH)]


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

    The one place a target names a tool's own types: for an assertion that reads that
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


def check_target(stage: Stage, target: ResourceTarget | ProcessTarget, change_type: ChangeTypeName | None) -> None:
    """Raise ``ValueError`` unless ``target`` is valid at ``stage`` for ``change_type``, or for every change type when
    it is None, and its selectors have a change to scope."""
    kind = TargetKind(target.kind)
    valid = SHARED_COMBINATIONS if change_type is None else COMBINATIONS[change_type]
    if (ASSERTION_TYPE_FOR_TARGET[kind], stage, kind) not in valid:
        about = "any change" if change_type is None else f"a change of type {change_type!r}"
        raise ValueError(
            f"stage {stage.value!r} is not valid for target kind {target.kind!r} in an assertion about {about}"
        )
    if isinstance(target, ProcessTarget) and target.resources is not None and stage not in SCOPED_STAGES:
        raise ValueError(f"a {target.kind} target at {stage.value} has no change to scope")


# What an author is told when an assertion does not say which change type it is about.
CHANGE_TYPE_MISSING = "change_type is missing: give iac_change, or null for an assertion about any change"


class Spec(_Strict):
    """What is checked, when, and about what."""

    type: AssertionType | None = None
    # The change type the assertion is about, or null for an assertion about any change, which may declare only the
    # stages and targets every change type allows.
    change_type: ChangeTypeName | None
    stage: Stage
    target: Target
    when: dict[str, Any] | None = None
    assert_: dict[str, Any] = Field(alias="assert")

    @property
    def derived_type(self) -> AssertionType:
        return ASSERTION_TYPE_FOR_TARGET[TargetKind(self.target.kind)]

    @model_validator(mode="before")
    @classmethod
    def _names_its_change_type(cls, data: Any) -> Any:
        if isinstance(data, dict) and "change_type" not in data:
            raise ValueError(CHANGE_TYPE_MISSING)
        return data

    @model_validator(mode="after")
    def _combination(self) -> Spec:
        derived = self.derived_type
        if self.type is not None and self.type != derived:
            raise ValueError(
                f"type {self.type.value!r} does not match target kind {self.target.kind!r} ({derived.value})"
            )
        check_target(self.stage, self.target, self.change_type)
        return self


class TechnicalAssertion(_Strict):
    """The document an author writes; ``registry`` fields are never accepted from an author."""

    api_version: Literal["iltero.io/v1"] = Field(alias="apiVersion")
    kind: Literal["TechnicalAssertion"]
    metadata: Metadata
    spec: Spec
