"""``TechnicalAssertion`` v1: the envelope of a rule an author writes.

A technical assertion names what is checked (``metadata``), at which point of
the change lifecycle (``spec.stage``), about which kind of thing
(``spec.target``), and the condition itself (``spec.assert``) with an optional
applicability guard (``spec.when``). The condition is written in the assertion
language, whose grammar is parsed and validated by ``iltero_schemas.ast``;
this module validates everything around it.

An assertion observed by scanners has no condition of its own (``assert: null``).
Its description says exactly what is true of a resource that meets it, and an
scanner checks entry names the scanner checks that decide it. It names the stages
whose scanner results may observe it (``spec.evidence.stages``) instead of one
``spec.stage``, and its ``when`` guard, if any, still decides where it applies.

Every model refuses unknown keys. An assertion's type is derived from
``spec.target.kind`` (``resource`` is a *state* assertion, everything else a
*process* assertion), never written.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from iltero_schemas.kinds.common.vocabulary import RESOURCE_KINDS
from iltero_schemas.models.common.assertion_id import ASSERTION_ID_MAX_LENGTH, WINDOWS_DEVICE_NAMES, check_assertion_id
from iltero_schemas.models.common.change_type import IAC_CHANGE_TYPE, IMAGE_RELEASE_TYPE, ChangeTypeName
from iltero_schemas.models.iac.tool_names import RESOURCE_TYPE_PATTERNS, IacTool

# The document's kind. Its apiVersion is ``models.common.base.API_VERSION``, which this module cannot import: the base
# model reads this module's stages and target kinds.
KIND = "TechnicalAssertion"
# Upper-case segments joined by dots, at least two: the shape every id of the contract has (assertions, scanner check
# mappings) and every reference to one is read by. An assertion's own id also puts its parts in fixed places
# (``models.common.assertion_id``).
ID_PATTERN = r"^[A-Z][A-Z0-9_]*(\.[A-Z][A-Z0-9_]*)+$"
ID_MAX_LENGTH = ASSERTION_ID_MAX_LENGTH
# The human version string: semantic version core, advisory only; evidence
# cites the digest. Bounded because it becomes part of a file name.
VERSION_PATTERN = r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
VERSION_MAX_LENGTH = 32
TITLE_MAX_LENGTH = 200
# The longest description: one line (no line breaks; YAML ``>-`` folds a long one) saying exactly what a resource that
# meets the assertion is like.
DESCRIPTION_MAX_LENGTH = 1000
# The longest suggested action: one instruction sentence, a little longer than a title.
REMEDIATION_MAX_LENGTH = 300
NAME_PATTERN = r"^[a-z][a-z0-9_]*$"
PROVIDER_MAX_LENGTH = 32
RESOURCE_TYPE_MAX_LENGTH = 128
RESOURCE_TYPES_MAX = 64
# The most kinds one selector names, and the longest kind.
KINDS_MAX = 64
KIND_MAX_LENGTH = 64
# Characters no human-readable field or literal may contain: C0 and C1 controls, DEL, zero-width and bidirectional
# formatting characters, the characters that show as nothing (soft hyphen, grapheme joiner, Hangul fillers), every
# other control and format character, and the tag characters, which spell hidden text. Written as code points, not
# Unicode categories, so every reader refuses the same characters whatever its Unicode version. Variation selectors,
# which follow ordinary emoji, are allowed.
CONTROL_CHARACTERS = re.compile(
    r"[\x00-\x1f\x7f-\x9f\xad\u034f\u0600-\u0605\u061c\u06dd\u070f\u0890\u0891\u08e2\u115f\u1160\u180e"
    r"\u200b-\u200f\u2028-\u202e\u2060-\u2064\u2066-\u206f\u3164\ufeff\uffa0\ufff9-\ufffb\U000110bd\U000110cd"
    r"\U00013430-\U0001343f\U0001bca0-\U0001bca3\U0001d173-\U0001d17a\U000e0000-\U000e007f]"
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
    ARTIFACT = "artifact"


class AssertionType(StrEnum):
    """A state assertion checks properties; a process assertion checks relationships."""

    STATE = "state"
    PROCESS = "process"


ASSERTION_TYPE_FOR_TARGET: dict[TargetKind, AssertionType] = {
    TargetKind.RESOURCE: AssertionType.STATE,
    TargetKind.CHANGE: AssertionType.PROCESS,
    TargetKind.DEPLOYMENT: AssertionType.PROCESS,
    TargetKind.ASSURANCE: AssertionType.PROCESS,
    TargetKind.ARTIFACT: AssertionType.PROCESS,
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
        IMAGE_RELEASE_TYPE: frozenset(
            {
                (AssertionType.PROCESS, Stage.PLAN, TargetKind.ARTIFACT),
                (AssertionType.PROCESS, Stage.PRE_DEPLOY, TargetKind.CHANGE),
                (AssertionType.PROCESS, Stage.POST_DEPLOY, TargetKind.DEPLOYMENT),
                (AssertionType.PROCESS, Stage.POST_VERIFY, TargetKind.DEPLOYMENT),
            }
        ),
    }
)

# Every combination some change type allows; anything else is rejected. An assertion about any change may declare any
# of them, and reads only the parts every change type evaluated at its stage and target provides (``profiles``).
VALID_COMBINATIONS: frozenset[Combination] = frozenset().union(*COMBINATIONS.values())


_ID = re.compile(ID_PATTERN)


def assert_assertion_id(value: str) -> str:
    """Return ``value`` when it has the shape of an assertion id; raise ``ValueError`` otherwise."""
    if not _ID.fullmatch(value) or len(value) > ID_MAX_LENGTH:
        raise ValueError(
            f"an assertion id is upper-case segments joined by dots, at least two, at most {ID_MAX_LENGTH} characters"
        )
    return value


class _Strict(BaseModel):
    # A refusal names the field and the rule, never the value it refused.
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


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
    # What is true of a subject that meets the assertion, in full. Required when the assertion has no condition of its
    # own, since the description is then the only statement of what its scanner checks decide. Like the remediation,
    # it is in neither the AST nor the source digest.
    description: Annotated[str, Field(max_length=DESCRIPTION_MAX_LENGTH)] | None = None

    @model_validator(mode="after")
    def _check(self) -> Metadata:
        if self.id.split(".")[0] in WINDOWS_DEVICE_NAMES:
            raise ValueError("id must not start with a name Windows reserves for a device")
        _title(self.title)
        for name in ("remediation", "description"):
            value = getattr(self, name)
            if value is not None:
                _title(value)
            elif name in self.model_fields_set:
                # The assertion's digest is taken over the document as written: one meaning, one digest.
                raise ValueError(f"{name} is left out, never null")
        return self


# A provider's short name, as an assertion and an evaluation input name it (``aws``, ``google-beta``).
PROVIDER_PATTERN = r"^[a-z][a-z0-9_-]*$"
ProviderName = Annotated[str, Field(pattern=PROVIDER_PATTERN, max_length=PROVIDER_MAX_LENGTH)]


class KindSelector(_Strict):
    """Resources of one provider, by the neutral kinds that provider's list names (``kinds.common.vocabulary``)."""

    provider: ProviderName
    kinds: Annotated[
        list[Annotated[str, Field(pattern=NAME_PATTERN, max_length=KIND_MAX_LENGTH)]],
        Field(min_length=1, max_length=KINDS_MAX),
    ]

    @model_validator(mode="after")
    def _kinds(self) -> KindSelector:
        known = RESOURCE_KINDS.get(self.provider)
        if known is None:
            named = ", ".join(sorted(RESOURCE_KINDS))
            raise ValueError(f"provider must be one whose resource kinds a selector can name: {named}")
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
    """A process assertion's target: the change, the deployment, the assurance history or the built artifact.

    A change or deployment target may name ``resources``, by kinds so it holds for every tool: it is then in scope
    only when the change touches a resource one of its selectors picks.
    """

    kind: Literal["change", "deployment", "assurance", "artifact"]
    resources: Annotated[list[KindSelector], Field(min_length=1, max_length=SELECTORS_MAX)] | None = None

    @model_validator(mode="after")
    def _resources(self) -> ProcessTarget:
        if self.resources is not None and self.kind in ("assurance", "artifact"):
            raise ValueError(f"an {self.kind} target names no resources: it has no change to scope")
        return self


Target = Annotated[ResourceTarget | ProcessTarget, Field(discriminator="kind")]


# The stages whose input has a change a target's selectors can scope.
SCOPED_STAGES = frozenset({Stage.PRE_DEPLOY, Stage.POST_DEPLOY})


def check_target(stage: Stage, target: ResourceTarget | ProcessTarget, change_type: ChangeTypeName | None) -> None:
    """Raise ``ValueError`` unless ``target`` is valid at ``stage`` for ``change_type``, or for every change type when
    it is None, and its selectors have a change to scope."""
    kind = TargetKind(target.kind)
    valid = VALID_COMBINATIONS if change_type is None else COMBINATIONS[change_type]
    if (ASSERTION_TYPE_FOR_TARGET[kind], stage, kind) not in valid:
        about = "any change" if change_type is None else f"a change of type {change_type!r}"
        raise ValueError(
            f"stage {stage.value!r} is not valid for target kind {target.kind!r} in an assertion about {about}"
        )
    if isinstance(target, ProcessTarget) and target.resources is not None and stage not in SCOPED_STAGES:
        raise ValueError(f"a {target.kind} target at {stage.value} has no change to scope")
    if isinstance(target, ProcessTarget) and target.resources is not None and change_type != IAC_CHANGE_TYPE:
        raise ValueError(f"a {target.kind} target names resources only in an assertion about an iac_change")


# What an author is told when an assertion does not say which change type it is about.
CHANGE_TYPE_MISSING = (
    "change_type is missing: give iac_change or image_release, or null for an assertion about any change"
)


_STAGE_ORDER = list(Stage)

# The stages whose scanner results Iltero reads: the only ones whose results may decide an assertion with no condition
# of its own. Every stage some activity reads scanner reports at (``Activity.stages_that_read_scanner_reports``).
STAGES_WITH_SCANNER_RESULTS = frozenset({Stage.PLAN})


def check_evidence_stages(stages: Iterable[Stage]) -> None:
    """Raise ``ValueError`` unless every stage is one whose scanner results Iltero reads."""
    if not set(stages) <= STAGES_WITH_SCANNER_RESULTS:
        allowed = ", ".join(stage.value for stage in _STAGE_ORDER if stage in STAGES_WITH_SCANNER_RESULTS)
        raise ValueError(f"evidence.stages may name only {allowed}: Iltero reads scanner results at no other stage")


class Evidence(_Strict):
    """The stages whose scanner results may observe an assertion that has no condition of its own."""

    stages: Annotated[list[Stage], Field(min_length=1, max_length=len(Stage))]

    @model_validator(mode="after")
    def _in_order(self) -> Evidence:
        check_evidence_stages(self.stages)
        if self.stages != sorted(set(self.stages), key=_STAGE_ORDER.index):
            raise ValueError("stages are in lifecycle order, each stage once")
        return self


class Spec(_Strict):
    """What is checked, when, and about what.

    An assertion with a condition (``assert``) names the one stage it is evaluated at. One with ``assert: null`` is
    observed by scanners: it names, in ``evidence``, the stages whose scanner results may observe it, and no
    ``stage``. Only a resource can be observed that way.
    """

    # The change type the assertion is about, or null for an assertion about any change, which may declare any stage
    # and target some change type allows (``VALID_COMBINATIONS``).
    change_type: ChangeTypeName | None
    # Left out exactly when ``assert`` is null.
    stage: Stage | None = None
    # Present exactly when ``assert`` is null.
    evidence: Evidence | None = None
    target: Target
    when: dict[str, Any] | None = None
    # Always written: the condition, or null for an assertion observed by scanners.
    assert_: dict[str, Any] | None = Field(alias="assert")

    @property
    def derived_type(self) -> AssertionType:
        return ASSERTION_TYPE_FOR_TARGET[TargetKind(self.target.kind)]

    @property
    def observed_by_scanners(self) -> bool:
        """Whether the assertion has no condition of its own, so only scanner results observe it."""
        return self.assert_ is None

    @property
    def stages(self) -> tuple[Stage, ...]:
        """Every stage the assertion is evaluated or observed at, in lifecycle order."""
        if self.stage is not None:
            return (self.stage,)
        if self.evidence is None:
            raise ValueError("an assertion names its stage or its evidence stages")
        return tuple(self.evidence.stages)

    @model_validator(mode="before")
    @classmethod
    def _names_its_change_type(cls, data: Any) -> Any:
        if isinstance(data, dict) and "change_type" not in data:
            raise ValueError(CHANGE_TYPE_MISSING)
        return data

    @model_validator(mode="after")
    def _combination(self) -> Spec:
        if self.observed_by_scanners:
            if self.stage is not None or "stage" in self.model_fields_set or self.evidence is None:
                raise ValueError("an assertion with assert: null names evidence.stages and no stage")
            if self.target.kind != TargetKind.RESOURCE.value:
                raise ValueError("an assertion with assert: null is about a resource: only a resource is scanned")
        elif self.stage is None or self.evidence is not None or "evidence" in self.model_fields_set:
            raise ValueError("an assertion with a condition names its stage and no evidence")
        for stage in self.stages:
            check_target(stage, self.target, self.change_type)
        return self


class TechnicalAssertion(_Strict):
    """The document an author writes; ``registry`` fields are never accepted from an author."""

    api_version: Literal["iltero.com/v1"] = Field(alias="apiVersion")
    kind: Literal["TechnicalAssertion"]
    metadata: Metadata
    spec: Spec

    @model_validator(mode="after")
    def _id_names_what_it_checks(self) -> TechnicalAssertion:
        target = self.spec.target
        provider = target.resources[0].provider if isinstance(target, ResourceTarget) else None
        check_assertion_id(self.metadata.id, self.spec.change_type, target.kind, provider)
        return self

    @model_validator(mode="after")
    def _described_when_observed_by_scanners(self) -> TechnicalAssertion:
        if self.spec.observed_by_scanners and self.metadata.description is None:
            raise ValueError("an assertion with assert: null has a metadata.description saying exactly what it checks")
        return self
