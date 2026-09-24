"""``PolicySourceManifest``: what a directory of hand-written policy claims to decide.

The assertion language covers what most rules need, and nothing more. A rule
that needs logic beyond it is written as a **custom policy source**: a
directory of ``.rego`` files with a manifest saying, for each of them, which
assertion it decides, at which stage, and about what.

The assertion document stays out of it. A ``TechnicalAssertion`` describes a
rule in a language this project owns and can compile; a custom policy source
is code somebody else wrote. Mixing the two would put an engine's name inside
the one document that is meant to outlive any engine. So a manifest entry
carries everything an assertion carries *except* the logic — the id, the
version, the stage and the target — and the ``.rego`` files carry the logic.

The difference matters at replay. A compiled rule is re-derived from the
assertion and refused if it differs; hand-written policy cannot be, so it
runs as the retained code and every record that holds one says so.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AfterValidator, Field, model_validator

from iltero_schemas.models.assertion import (
    CONTROL_CHARACTERS,
    DERIVED_TYPE,
    ID_MAX_LENGTH,
    ID_PATTERN,
    TITLE_MAX_LENGTH,
    VALID_COMBINATIONS,
    VERSION_MAX_LENGTH,
    VERSION_PATTERN,
    Target,
    TargetKind,
)
from iltero_schemas.models.base import StageValue, StrictModel

API_VERSION = "iltero.io/v1"
KIND = "PolicySourceManifest"
# A file name inside the source directory: a plain name, no directory part, no escape.
FILE_PATTERN = r"^[A-Za-z0-9._-]+\.rego$"
FILE_MAX_LENGTH = 255
# More policies than a source has any reason to hold.
MAX_POLICIES = 512

PolicyFile = Annotated[str, Field(pattern=FILE_PATTERN, max_length=FILE_MAX_LENGTH)]


def _plain_title(value: str) -> str:
    """A title a person reads: not empty, and no character that could rewrite what they see."""
    if not value.strip():
        raise ValueError("must not be empty")
    if CONTROL_CHARACTERS.search(value):
        raise ValueError("must not contain control characters")
    return value


class PolicyAssertion(StrictModel):
    """Which assertion the policy decides, and which version of it this code is."""

    id: Annotated[str, Field(pattern=ID_PATTERN, max_length=ID_MAX_LENGTH)]
    version: Annotated[str, Field(pattern=VERSION_PATTERN, max_length=VERSION_MAX_LENGTH)]


class PolicyEntry(StrictModel):
    """One policy: what it claims, what it decides, when, about what, and which files it is written in."""

    # What this policy claims, in words, the way an assertion's title does.
    title: Annotated[str, Field(max_length=TITLE_MAX_LENGTH), AfterValidator(_plain_title)]
    assertion: PolicyAssertion
    stage: StageValue
    target: Target
    # The one file this policy is written in. A policy's code is scoped to the
    # assertion it decides and cannot be used by another, so splitting it across
    # files would buy nothing but a second way to write the same thing.
    file: PolicyFile

    @model_validator(mode="after")
    def _the_combination_is_one_that_exists(self) -> PolicyEntry:
        kind = TargetKind(self.target.kind)
        if (DERIVED_TYPE[kind], self.stage, kind) not in VALID_COMBINATIONS:
            raise ValueError(f"stage {self.stage.value!r} is not valid for target kind {self.target.kind!r}")
        return self


class PolicySourceManifest(StrictModel):
    """A directory of hand-written policy, read as a whole so its rules hold before any of it is loaded."""

    api_version: Literal["iltero.io/v1"] = Field(alias="apiVersion")
    kind: Literal["PolicySourceManifest"]
    policies: Annotated[list[PolicyEntry], Field(min_length=1, max_length=MAX_POLICIES)]

    @model_validator(mode="after")
    def _each_assertion_is_decided_once(self) -> PolicySourceManifest:
        decided = [(entry.stage.value, entry.assertion.id) for entry in self.policies]
        if len(set(decided)) != len(decided):
            raise ValueError("two policies decide the same assertion at the same stage")
        written = [entry.file for entry in self.policies]
        if len(set(written)) != len(written):
            raise ValueError("two policies are written in the same file")
        return self
