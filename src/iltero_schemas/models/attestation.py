"""``Attestation`` v1: a person's claim, written down so it can be audited.

Most of what a framework asks about cannot be decided from a plan. That a
policy exists, that someone is responsible for it, that a review happened —
no technical assertion establishes any of it. An **attestation** is how a
person says it instead: the claim verbatim, what it is about, who is saying
it, how they arrived at it, what they looked at, and when it stops counting.

Three rules make it evidence rather than a note.

* **``valid_until`` is required.** A claim with no expiry is a stale
  screenshot, and it is the finding auditors raise most often against
  automated compliance tooling.
* **It is an artifact, never a verdict.** Nothing derives an assertion's
  status from an attestation. It sits in the record's evidence register and
  is read by a person.
* **It says how sure it is of who wrote it.** Without a signature the
  attester is ``asserted`` — the tool wrote down a name it was given and
  verified nothing — and a reader is told so in those words.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AfterValidator, Field, model_validator

from iltero_schemas.models.assertion import ID_MAX_LENGTH, ID_PATTERN, VERSION_MAX_LENGTH, VERSION_PATTERN
from iltero_schemas.models.base import StrictModel
from iltero_schemas.models.context import ReferenceTimeTrust
from iltero_schemas.models.fields import Digest, Identifier, Timestamp, plain_text

# A document a person authors the content of, so it sits in the same namespace as
# the others and says which it is in ``kind``. The files this tool writes for itself
# name their type in the version instead, and carry no ``kind``.
API_VERSION = "iltero.io/v1"
KIND = "Attestation"
# How a claim is recognised in a record's evidence register. A bundle rewrites
# every path, so this is what a reader has left to tell a claim from any other
# document the record cites: it is part of the record format, not of any one writer.
MEDIA_TYPE = "application/vnd.iltero.attestation+json"
UUID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
# Long enough for the claim itself; a claim that needs more than this is a document, and the
# attestation should point at it through ``supporting_evidence`` instead.
STATEMENT_MAX_LENGTH = 4096
# How the attester arrived at the claim: by looking at something, or by asking someone.
AssessmentMethod = Literal["EXAMINE", "INTERVIEW"]
# How sure the record is of who wrote it. ``ci_oidc`` needs a token this tool can verify,
# which it cannot do offline, so an offline attestation is always ``asserted``.
IdentitySource = Literal["ci_oidc", "asserted"]
# More supporting evidence than any one claim cites.
MAX_SUPPORTING_EVIDENCE = 256

Statement = Annotated[str, Field(min_length=1, max_length=STATEMENT_MAX_LENGTH), AfterValidator(plain_text)]
Uuid = Annotated[str, Field(pattern=UUID_PATTERN)]


class Scope(StrictModel):
    """What the claim is about: a system and an environment, and the rule or control it speaks to."""

    # The assertion this claim stands in for, when it stands in for one.
    assertion_id: Annotated[str, Field(pattern=ID_PATTERN, max_length=ID_MAX_LENGTH)] | None
    # The control in whatever framework the reader is auditing against, as they write it.
    control_ref: Identifier | None
    system_id: Identifier
    environment: Identifier

    @model_validator(mode="after")
    def _says_what_it_is_about(self) -> Scope:
        if self.assertion_id is None and self.control_ref is None:
            raise ValueError("a claim names the assertion or the control it is about")
        return self


class Attester(StrictModel):
    """Who is making the claim, and how much of that this record could establish."""

    identity: Identifier
    # Where the identity came from, when anything issued it.
    idp: Identifier | None
    auth_method: Identifier | None
    role: Identifier | None
    # Where the role is written down, so a reader can check the person holds it.
    role_source_ref: Identifier | None
    identity_source: IdentitySource


class AttestedAt(StrictModel):
    """When the claim was made, and how far the clock that said so can be trusted.

    The same two questions a ``ReferenceTime`` answers, and the same words for
    the answer; a claim has no transparency-log source, so its own list of
    clocks is shorter.
    """

    value: Timestamp
    source: Literal["compass_server", "timestamp_authority", "runner_clock"]
    trust: ReferenceTimeTrust


class SupportingEvidence(StrictModel):
    """One file the attester looked at, named the way the record's register names it."""

    ref_id: Identifier
    digest: Digest


class Attestation(StrictModel):
    """One claim a person made, as this tool writes it down."""

    api_version: Literal["iltero.io/v1"] = Field(alias="apiVersion")
    kind: Literal["Attestation"]
    uuid: Uuid
    statement: Statement
    scope: Scope
    attester: Attester
    assessment_method: AssessmentMethod
    supporting_evidence: Annotated[list[SupportingEvidence], Field(max_length=MAX_SUPPORTING_EVIDENCE)]
    attested_at: AttestedAt
    # Required: a claim that never stops counting is not evidence of anything current.
    valid_until: Timestamp
    next_review_at: Timestamp | None
    # The attestation this one replaces, by uuid.
    supersedes: Uuid | None
    # Nothing signs an attestation yet; the field is here so a reader never has to ask.
    signature: None
    # The version of this tool that wrote it, so a reader knows what rules were in force.
    written_by: Annotated[str, Field(pattern=VERSION_PATTERN, max_length=VERSION_MAX_LENGTH)] | None

    @model_validator(mode="after")
    def _expires_after_it_was_made(self) -> Attestation:
        if self.valid_until <= self.attested_at.value:
            raise ValueError("valid_until is after the claim was made")
        if self.next_review_at is not None and self.next_review_at > self.valid_until:
            raise ValueError("a review due after the claim expires is not a review")
        return self
