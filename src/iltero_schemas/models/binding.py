"""``EvaluatorBindingSet``: which scanner check establishes which assertion.

A scanner such as Checkov or Trivy runs its own checks and says which
passed. An **evaluator binding** licenses one claim: *this check of this
tool, at this version, establishes this assertion*. Nothing is executed
for a bound check — the tool already ran, and its result is credited to
the assertion the binding names.

That is a strong claim, so the record must be able to show which licence
it rested on: an event credited this way names the binding entry's id,
its version and the digest of the entry itself, so a later change to the
catalogue cannot silently alter what a past record meant.

Two rules keep a record unambiguous, and both are checked when a set is
read rather than when a run uses it:

* a tool's check is bound once — one entry per ``(stage, tool, check_id)``;
* an assertion is established by one check per tool — one entry per
  ``(stage, tool, assertion id)``.

A check with no entry anywhere is not an error: it is retained as evidence
and counted, never turned into a verdict it was not licensed to give.
"""

from __future__ import annotations

from typing import Annotated, Literal

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from pydantic import AfterValidator, Field, model_validator

from iltero_schemas.canonical.encoding import digest_of
from iltero_schemas.models.assertion import ID_MAX_LENGTH, ID_PATTERN, VERSION_MAX_LENGTH, VERSION_PATTERN
from iltero_schemas.models.base import StageValue, StrictModel

API_VERSION = "iltero.io/v1"
KIND = "EvaluatorBindingSet"
# The scanners a binding may cite. The CLI never runs them; it reads what they wrote.
TOOLS = ("checkov", "trivy", "prowler")
# A tool names its checks in its own way: Checkov's ``CKV_AWS_16``, Trivy's ``AVD-AWS-0080``.
CHECK_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]*$"
CHECK_ID_MAX_LENGTH = 128
# A tool's own word for the outcome of a check (``PASSED``, ``FAILED``, Trivy's ``STATUS_FAILURE``).
TOOL_STATUS_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]*$"
TOOL_STATUS_MAX_LENGTH = 64
# Far more entries than any catalogue needs; the bound stops a file from being read without limit.
MAX_BINDINGS = 10_000
# How many of the tool's words one entry may translate.
MAX_STATUS_MAP = 32

Tool = Literal["checkov", "trivy", "prowler"]
# What a scanner's result may be credited as. Only a decision counts: the tool
# either found the thing true or found it false. A check the tool skipped, or
# could not settle, is not a decision, so it leaves the assertion exactly where
# it was — unanswered — rather than being read as "does not apply here". That
# matters most where the skip was written by the party being audited: a comment
# in their own source must not close a gap in their own record.
CreditedStatus = Literal["pass", "fail"]


def _specifier(value: str) -> str:
    """A PEP 440 version specifier, as ``packaging`` reads it, kept as written."""
    try:
        SpecifierSet(value)
    except InvalidSpecifier as exc:
        raise ValueError(f"is not a version specifier: {exc}") from None
    return value


VersionConstraint = Annotated[str, Field(min_length=1, max_length=128), AfterValidator(_specifier)]


def constraint_met(constraint: str, version: str) -> bool:
    """Whether ``version`` — the tool's own version string — satisfies ``constraint``.

    A pre-release satisfies nothing: ``4.0.0b1`` sits inside ``<4`` by
    version order, and a binding written against the released 3.x is not a
    licence for a 4.0 beta. A version string that is not a version at all
    satisfies nothing either. Both leave the check uncredited rather than
    credited on a guess.
    """
    try:
        parsed = Version(version)
    except InvalidVersion:
        return False
    if parsed.is_prerelease:
        return False
    return parsed in SpecifierSet(constraint)


def _unique(values: list[object], message: str) -> None:
    seen: set[object] = set()
    for value in values:
        if value in seen:
            raise ValueError(f"{message}: {value!r}")
        seen.add(value)


class AssertionCite(StrictModel):
    """The assertion an entry establishes."""

    id: Annotated[str, Field(pattern=ID_PATTERN, max_length=ID_MAX_LENGTH)]
    version: Annotated[str, Field(pattern=VERSION_PATTERN, max_length=VERSION_MAX_LENGTH)]


class SetMetadata(StrictModel):
    """Which catalogue this is, and which revision of it."""

    id: Annotated[str, Field(pattern=ID_PATTERN, max_length=ID_MAX_LENGTH)]
    version: Annotated[str, Field(pattern=VERSION_PATTERN, max_length=VERSION_MAX_LENGTH)]


class EvaluatorBinding(StrictModel):
    """One licence: this tool's check, at a version that satisfies the constraint, establishes this assertion."""

    id: Annotated[str, Field(pattern=ID_PATTERN, max_length=ID_MAX_LENGTH)]
    version: Annotated[str, Field(pattern=VERSION_PATTERN, max_length=VERSION_MAX_LENGTH)]
    tool: Tool
    # The tool's version is read from its own output; a version outside this
    # range is not evidence for this entry, and the check is not evaluated.
    tool_version_constraint: VersionConstraint
    check_id: Annotated[str, Field(pattern=CHECK_ID_PATTERN, max_length=CHECK_ID_MAX_LENGTH)]
    # What the tool must have been looking at for its result to be evidence for
    # this entry, in the tool's own words. It matters: Checkov's ``terraform``
    # reads the configuration, where a value may still be a variable, while
    # ``terraform_plan`` reads the values the plan settled on. A result from
    # anything else is not credited. ``null`` for a tool with one thing to read.
    framework: Annotated[str, Field(pattern=CHECK_ID_PATTERN, max_length=CHECK_ID_MAX_LENGTH)] | None
    assertion: AssertionCite
    stage: StageValue
    # The tool's vocabulary translated into the contract's: a word the tool
    # may print and is not listed here leaves the observation uncredited.
    status_map: Annotated[
        dict[Annotated[str, Field(pattern=TOOL_STATUS_PATTERN, max_length=TOOL_STATUS_MAX_LENGTH)], CreditedStatus],
        Field(min_length=1, max_length=MAX_STATUS_MAP),
    ]

    @property
    def digest(self) -> str:
        """The digest of this entry's canonical form: what an event names, so a later edit is visible."""
        return digest_of(self.model_dump(mode="json"))


class EvaluatorBindingSet(StrictModel):
    """A catalogue of licences, read as a whole so its rules hold before any of it is used."""

    api_version: Literal["iltero.io/v1"] = Field(alias="apiVersion")
    kind: Literal["EvaluatorBindingSet"]
    metadata: SetMetadata
    bindings: Annotated[list[EvaluatorBinding], Field(min_length=1, max_length=MAX_BINDINGS)]

    @model_validator(mode="after")
    def _entries_are_unambiguous(self) -> EvaluatorBindingSet:
        _unique([entry.id for entry in self.bindings], "two entries share the id")
        _unique(
            [(entry.stage.value, entry.tool, entry.check_id) for entry in self.bindings],
            "two entries bind the same check of the same tool at the same stage",
        )
        _unique(
            [(entry.stage.value, entry.tool, entry.assertion.id) for entry in self.bindings],
            "two checks of the same tool establish the same assertion at the same stage",
        )
        return self
