"""``EvaluatorBindingSet``: which scanner checks decide which assertion.

A scanner such as Checkov or Trivy runs its own checks and says which passed.
A binding names one assertion and lists its scanner evaluators. Each evaluator
says: *these checks of this tool, at a version the constraint admits, read from
this kind of input, together decide the assertion at this stage*. Nothing is
executed for a bound check: the tool already ran, and its results become one
evaluation of the assertion, beside the assertion's own condition if it has one.

The checks of one evaluator decide together (all of them): any check that fails
fails the assertion, all of them passing passes it, and a check with no result
leaves it undecided. A tool has one evaluator per assertion and stage.

An event decided this way names the digest of its evaluator together with the
assertion it cites (by id, version and document digest), so a later change to
either is visible in what a past record meant.

Rules enforced when a set is read rather than when a run uses it:

* each assertion is bound once, and its evaluators are one per tool and stage;
* a tool's check is used once per stage across the whole set;
* an evaluator reads input its stage stands for (``STAGE_INPUT_KINDS``): a result about the configuration never
  decides anything the plan settles, and only deployed resources decide a running state;
* no binding decides an assertion in ``NOT_DECIDED_BY_SCANNERS``: a built-in, or one decided from facts no scanner
  reports.

That an evaluator's stage is one of the assertion's stages needs the assertion's
document, so a reader checks it with the document (``models.scanner_results``).
A set read from a project's own file decides only the project's own assertions,
never one in Iltero's namespace or one that reads like it (``check_project_set``):
those ids are bound only by the sets Iltero ships.
A check bound nowhere is not an error: its result is kept as evidence and
counted, never turned into a verdict no binding gave it.
"""

from __future__ import annotations

from collections.abc import Mapping
from functools import cached_property
from types import MappingProxyType
from typing import Annotated, Literal

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from pydantic import AfterValidator, Field, model_validator

from iltero_schemas.assertions.paths import NOT_DECIDED_BY_SCANNERS
from iltero_schemas.canonical.encoding import digest_of
from iltero_schemas.models.assertion import ID_MAX_LENGTH, ID_PATTERN, VERSION_MAX_LENGTH, VERSION_PATTERN, Stage
from iltero_schemas.models.assertion_id import ILTERO_NAMESPACE, check_project_id
from iltero_schemas.models.base import API_VERSION as API_VERSION
from iltero_schemas.models.base import StageValue, StrictModel, sorted_unique
from iltero_schemas.models.fields import Digest
from iltero_schemas.models.scanners import ScannerTool

KIND = "EvaluatorBindingSet"
# A tool names its checks in its own way: Checkov's ``CKV_AWS_16``, Trivy's ``AWS-0080``.
RULE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]*$"
RULE_ID_MAX_LENGTH = 128
# Far more assertions than any binding set binds; the bound stops a file from being read without limit.
MAX_BINDINGS = 10_000
# One evaluator per tool and stage, with room for every tool at every stage.
MAX_EVALUATORS = 32
# More checks than one tool needs to decide one assertion: an S3 public access block, for one, has four settings,
# each its own check.
MAX_RULES_PER_EVALUATOR = 16

# What a scanner's result may decide. Only a decision counts: the tool found the
# thing true or found it false. A check the tool skipped, or could not settle,
# leaves the assertion undecided.
AcceptedStatus = Literal["pass", "fail"]
# Each scanner's own words for a decision, and the decision each names. No other word of a tool is read as one.
TOOL_DECISIONS: Mapping[str, Mapping[str, AcceptedStatus]] = MappingProxyType(
    {
        "checkov": MappingProxyType({"PASSED": "pass", "FAILED": "fail"}),
        "trivy": MappingProxyType({"PASS": "pass", "FAIL": "fail"}),
    }
)

# What a scanner read, in the contract's words, whatever the tool calls it: the plan (the values the plan settled on),
# or the resources as deployed. A tool's results about the configuration as written, where a value may still be a
# variable, decide nothing (``models.iac.scanner_observations``).
InputKind = Literal["plan", "deployed_resources"]
# The input whose results may decide an assertion at each stage.
STAGE_INPUT_KINDS: Mapping[Stage, frozenset[InputKind]] = MappingProxyType(
    {
        Stage.PLAN: frozenset({"plan"}),
        Stage.RUNTIME: frozenset({"deployed_resources"}),
    }
)
# How a result of a bound check finds the subject it decides: the result's resource address is the subject's own, or
# the result is about a resource the plan says configures the subject (an S3 bucket's public access block).
SubjectMatch = Literal["exact_address", "plan_configures"]
# The operators that bound a range from above: a constraint without one would admit a future major version, whose
# checks may decide something else.
_UPPER_BOUNDS = frozenset({"<", "<=", "==", "~=", "==="})


def _specifier(value: str) -> str:
    """A PEP 440 version specifier with an upper bound, as ``packaging`` reads it, kept as written."""
    try:
        specifiers = SpecifierSet(value)
    except InvalidSpecifier:
        raise ValueError("is not a version specifier") from None
    if not any(spec.operator in _UPPER_BOUNDS for spec in specifiers):
        raise ValueError("bounds the version from above, such as <4")
    return value


VersionConstraint = Annotated[str, Field(min_length=1, max_length=128), AfterValidator(_specifier)]
# More attribute paths than the checks of one evaluator read.
MAX_PATHS_READ = 32
ATTRIBUTE_PATH_PATTERN = r"^[A-Za-z0-9_-]+(/([A-Za-z0-9_-]+|\*))*$"
AttributePath = Annotated[str, Field(pattern=ATTRIBUTE_PATH_PATTERN, max_length=256)]
RuleId = Annotated[str, Field(pattern=RULE_ID_PATTERN, max_length=RULE_ID_MAX_LENGTH)]


def constraint_met(constraint: str, version: str) -> bool:
    """Whether ``version``, the tool's version string, satisfies ``constraint``.

    A pre-release satisfies nothing: ``4.0.0b1`` sits inside ``<4`` by version
    order, and a binding written against the released 3.x does not admit a 4.0
    beta. A local build (``3.2.1+patched``) satisfies nothing: its checks may not be
    the released ones. A version string that is not written as the tool releases
    it (``v3.2.1``, surrounding spaces), or not a version at all, satisfies nothing
    either. Each leaves the tool's results undecided rather than decided on a guess.
    """
    try:
        parsed = Version(version)
    except InvalidVersion:
        return False
    if parsed.is_prerelease or parsed.local is not None or str(parsed) != version:
        return False
    return parsed in SpecifierSet(constraint)


def _unique(values: list[object], message: str) -> None:
    seen: set[object] = set()
    for value in values:
        if value in seen:
            raise ValueError(message)
        seen.add(value)


class AssertionCite(StrictModel):
    """The assertion a binding decides: its id, its version and the digest of its document."""

    id: Annotated[str, Field(pattern=ID_PATTERN, max_length=ID_MAX_LENGTH)]
    version: Annotated[str, Field(pattern=VERSION_PATTERN, max_length=VERSION_MAX_LENGTH)]
    digest: Digest


class SetMetadata(StrictModel):
    """Which binding set this is, and which revision of it."""

    id: Annotated[str, Field(pattern=ID_PATTERN, max_length=ID_MAX_LENGTH)]
    version: Annotated[str, Field(pattern=VERSION_PATTERN, max_length=VERSION_MAX_LENGTH)]


# Lifecycle order is the order ``Stage`` lists its stages in (a test pins it).
_STAGE_ORDER = list(Stage)


class ScannerBinding(StrictModel):
    """One scanner evaluator of an assertion (an item of its ``evaluators``): these checks of this tool, at a version
    the constraint admits, read from this input, together decide the assertion at this stage."""

    tool: ScannerTool
    stage: StageValue
    # Sorted, each check once, compared exactly as the tool writes them; all of them together decide the assertion.
    rule_ids: Annotated[list[RuleId], Field(min_length=1, max_length=MAX_RULES_PER_EVALUATOR)]
    # A result from a version outside this range decides nothing for this binding.
    tool_version_constraint: VersionConstraint
    input_kind: InputKind
    subject_match: SubjectMatch
    # The attribute paths the checks read on the resources their results are about, with ``/`` between names and
    # ``*`` for any list element (``ingress/*/cidr_blocks``), sorted, each once. A result that passes while one of
    # these values is known only after the deployment does not pass, whatever keys the tool says it read.
    paths_read: Annotated[list[AttributePath], Field(min_length=1, max_length=MAX_PATHS_READ)]

    @model_validator(mode="after")
    def _checks_and_input(self) -> ScannerBinding:
        if not sorted_unique(self.rule_ids):
            raise ValueError("rule_ids is sorted, each check once")
        if not sorted_unique(self.paths_read):
            raise ValueError("paths_read is sorted, each path once")
        allowed = STAGE_INPUT_KINDS.get(self.stage, frozenset())
        if self.input_kind not in allowed:
            reads = " or ".join(sorted(allowed)) + " input" if allowed else "no scanner input"
            raise ValueError(f"a scanner binding at {self.stage.value} reads {reads}")
        return self

    @property
    def key(self) -> tuple[int, str]:
        """Where the binding sits among its assertion's evaluators: by stage in lifecycle order, then by tool."""
        return _STAGE_ORDER.index(self.stage), self.tool


class AssertionBinding(StrictModel):
    """One assertion and the scanner checks that decide it, one evaluator per tool and stage."""

    assertion: AssertionCite
    evaluators: Annotated[list[ScannerBinding], Field(min_length=1, max_length=MAX_EVALUATORS)]

    @model_validator(mode="after")
    def _one_per_tool_and_stage(self) -> AssertionBinding:
        if self.assertion.id in NOT_DECIDED_BY_SCANNERS:
            raise ValueError(f"no binding decides {self.assertion.id}: a scanner's result never decides it")
        keys = [evaluator.key for evaluator in self.evaluators]
        if keys != sorted(set(keys)):
            raise ValueError("evaluators are in lifecycle order of their stage, then by tool, one per tool and stage")
        return self

    def evaluator_digest(self, evaluator: ScannerBinding) -> str:
        """The digest an event names for ``evaluator`` deciding this assertion: over the assertion it cites and the
        evaluator, so an edit to either is visible."""
        return digest_of(
            {"assertion": self.assertion.model_dump(mode="json"), "evaluator": evaluator.model_dump(mode="json")}
        )


class BindingSetSpec(StrictModel):
    """The set's bindings, sorted by assertion id, each assertion once and each check of a tool at a stage once."""

    bindings: Annotated[list[AssertionBinding], Field(min_length=1, max_length=MAX_BINDINGS)]

    @model_validator(mode="after")
    def _unambiguous(self) -> BindingSetSpec:
        if not sorted_unique([binding.assertion.id for binding in self.bindings]):
            raise ValueError("bindings are sorted by assertion id, each assertion once")
        _unique(
            [
                (evaluator.stage.value, evaluator.tool, rule)
                for binding in self.bindings
                for evaluator in binding.evaluators
                for rule in evaluator.rule_ids
            ],
            "two bindings use the same check of the same tool at the same stage",
        )
        return self


class EvaluatorBindingSet(StrictModel):
    """A set of assertion bindings, read as a whole so its rules hold before any is used."""

    api_version: Literal["iltero.com/v1"] = Field(alias="apiVersion")
    kind: Literal["EvaluatorBindingSet"]
    metadata: SetMetadata
    spec: BindingSetSpec

    @cached_property
    def by_digest(self) -> Mapping[str, tuple[AssertionBinding, ScannerBinding]]:
        """Each evaluator of the set and the binding it belongs to, by the digest an event names it by."""
        return MappingProxyType(
            {
                binding.evaluator_digest(evaluator): (binding, evaluator)
                for binding in self.spec.bindings
                for evaluator in binding.evaluators
            }
        )


def check_project_set(binding_set: EvaluatorBindingSet) -> None:
    """Raise ``ValueError`` unless ``binding_set``, read from a project's own file, decides only the project's own
    assertions, none in Iltero's namespace or one that reads like it, and is not named as one of Iltero's sets."""
    check_project_id(binding_set.metadata.id)
    for binding in binding_set.spec.bindings:
        if binding.assertion.id.split(".")[0].startswith(ILTERO_NAMESPACE):
            raise ValueError(
                f"a project's binding set decides only the project's own assertions, not {binding.assertion.id}"
            )
