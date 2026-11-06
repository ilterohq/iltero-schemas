"""The facts only the server holds, as an evaluation input carries them: approvals, exceptions, earlier evaluations,
the verified source and the verified attestation.

Each is normalised whatever produced it, so an assertion compares neutral
fields only.

- An **approval** names what it approves (``subject``): a change, by its
  digest, or a run, by Iltero's run id. ``method`` says how it was obtained;
  an approval obtained by a CI system's deployment review names no role,
  since none is verified. ``independence`` says whether the approver is someone
  other than whoever started the run or triggered the attempt; a
  self-approval the policy permitted names that policy's version. ``actor.id``
  is the provider's stable account id, never a login, a name or an address.
- An **exception** waives one assertion for an environment and the resources
  it names, between two times.
- An **earlier evaluation** is the result of one evaluation of an earlier stage.
- The **verified source** is the commit the server verified from the identity
  the continuous integration (CI) system gave the job that opened the run, not
  the commit the tool reads from its checkout, with the CI run and repository
  that identity named.
- The **verified attestation** is what the server found when it checked the
  signature of the build's attestation: the repository, commit, run and signer
  the signing certificate names, or why it refused the attestation, or that
  none was sent.

All five are the server's claims, as served.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AfterValidator, Field, model_validator

from iltero_schemas.canonical.encoding import INT_MAX
from iltero_schemas.models.assertion import Stage
from iltero_schemas.models.base import StageValue, StrictModel, TargetKindValue
from iltero_schemas.models.checked_content import CheckedContent
from iltero_schemas.models.ci import CiSystem
from iltero_schemas.models.fields import (
    AssertionId,
    AssertionKey,
    Commit,
    Digest,
    Identifier,
    Identity,
    Status,
    Timestamp,
    Uuid,
    parse_timestamp,
    plain_text,
)
from iltero_schemas.models.image.attestation import ProvenancePredicateType
from iltero_schemas.profiles import reads_checked_content

# The most items of each kind one facts document carries: more than one stage needs.
MAX_FACT_ITEMS = 256
# The most resources one exception covers.
MAX_EXCEPTION_RESOURCES = 256
MAX_ROLES = 32
# Free text a person wrote, such as why an exception was granted.
TEXT_MAX_LENGTH = 1024
Text = Annotated[str, Field(min_length=1, max_length=TEXT_MAX_LENGTH), AfterValidator(plain_text)]
Independence = Literal["independent", "self_permitted_by_policy"]
# How an approval was obtained: a CI system's deployment review, or a review in Iltero itself.
ApprovalMethod = Literal["ci_deployment_review", "iltero_review"]


class Actor(StrictModel):
    """A person or workload, named by the system that knows them."""

    provider: Identifier
    id: Identifier


class ChangeSubject(StrictModel):
    """An approval of one change: its digest (``canonical.change_digest``) binds it to that change type, unit,
    environment and checked content."""

    kind: Literal["change"]
    digest: Digest


class RunSubject(StrictModel):
    """An approval of one run, by Iltero's run id: it approves the run, not a plan's content."""

    kind: Literal["run"]
    id: Uuid


ApprovalSubject = Annotated[ChangeSubject | RunSubject, Field(discriminator="kind")]


class Approval(StrictModel):
    """One approval, normalised whatever produced it."""

    id: Identifier
    actor: Actor
    roles: Annotated[list[Identifier], Field(max_length=MAX_ROLES)]
    status: Literal["approved"]
    subject: ApprovalSubject
    method: ApprovalMethod
    independence: Independence
    policy_version: Identifier | None
    timestamp: Timestamp

    @model_validator(mode="after")
    def _consistent(self) -> Approval:
        if (self.policy_version is None) != (self.independence == "independent"):
            raise ValueError("an approval names the policy version exactly when the policy permitted a self-approval")
        if self.method == "ci_deployment_review" and self.roles:
            raise ValueError("an approval a CI deployment review gave names no role: none is verified")
        return self


class AssertionName(StrictModel):
    """An assertion by its id: an exception covers every version of it."""

    id: AssertionId


class ExceptionScope(StrictModel):
    """What an exception covers: one assertion, in one environment, for the resources it names."""

    assertion: AssertionName
    environment: Identifier
    resources: Annotated[list[Identity], Field(min_length=1, max_length=MAX_EXCEPTION_RESOURCES)]


class ExceptionGrant(StrictModel):
    """One exception: an assertion waived for an environment and resources, between two times."""

    id: Identifier
    status: Literal["approved"]
    scope: ExceptionScope
    valid_from: Timestamp
    expires_at: Timestamp
    approved_by: Actor
    reason: Text

    @model_validator(mode="after")
    def _ends_after_it_starts(self) -> ExceptionGrant:
        if parse_timestamp(self.expires_at) <= parse_timestamp(self.valid_from):
            raise ValueError("an exception expires after it starts")
        return self


class EvaluatedSubject(StrictModel):
    """What an earlier evaluation was about: its kind and its key (``models.subjects``)."""

    kind: TargetKindValue
    key: Digest


class Result(StrictModel):
    """What an earlier evaluation found."""

    status: Status


class EarlierEvaluation(StrictModel):
    """The result of one evaluation of an earlier stage, as the server recorded it."""

    id: Identifier
    assertion: AssertionKey
    stage: StageValue
    subject: EvaluatedSubject
    result: Result
    # The content the evaluation read; null for an evaluation whose input carried none, such as at runtime.
    checked_content: CheckedContent | None
    observed_at: Timestamp

    @model_validator(mode="after")
    def _checked_content_where_it_was_read(self) -> EarlierEvaluation:
        kind = self.checked_content.kind if self.checked_content is not None else None
        if kind not in reads_checked_content(Stage(self.stage)):
            raise ValueError(
                "an earlier evaluation names the content it checked exactly when its stage reads that content"
            )
        return self


class CiRunSource(StrictModel):
    """A commit and the CI run a CI system's identity named it for: the CI system and the instance of it, the
    repository and the run.

    A CI system's ids are unique only within one instance of it, so each id is read with the system and instance.
    """

    commit: Commit
    ci_provider: CiSystem
    # The instance of the CI system, by its host name, such as github.com.
    ci_instance: Identifier
    # The repository's id at the CI system, which does not change when the repository is renamed.
    repository_id: Identifier
    ci_run_id: Identifier
    ci_run_attempt: Annotated[int, Field(ge=1, le=INT_MAX)]


class VerifiedSource(CiRunSource):
    """The commit the server verified from the CI system's identity for the job that opened the run, and what that
    identity named, with the repository's name."""

    repository: Identifier


# Why the server refused a build's attestation: it is no attestation of one signed statement, its signature does not
# hold, its certificate names another CI identity than the run's, it names another image, or it is not the build's
# provenance.
AttestationRefusal = Literal[
    "not_an_attestation", "signature_invalid", "identity_mismatch", "subject_mismatch", "predicate_not_provenance"
]
# Where the job that signed ran: on the CI system's own runners, or on runners the CI system's user runs.
RunnerEnvironment = Literal["ci_hosted", "self_hosted"]
# A value a signing certificate names, such as a workflow's address, which may be longer than an identifier.
CertificateValue = Annotated[str, Field(min_length=1, max_length=TEXT_MAX_LENGTH), AfterValidator(plain_text)]


class TransparencyLogEntry(StrictModel):
    """The entry of a transparency log that recorded the signature, so it can be found again."""

    log_id: Identifier
    log_index: Annotated[int, Field(ge=0, le=INT_MAX)]


class AttestationVerifier(StrictModel):
    """The program that verified the attestation, and its version."""

    name: Identifier
    version: Identifier


class TrustRoot(StrictModel):
    """The trust root the server checked the signature against: its name and the digest of its contents."""

    name: Identifier
    digest: Digest


class AttestationCheck(StrictModel):
    """The server's check of a build's attestation: the file it checked, what it checked it against, and when, so the
    check can be repeated."""

    # The digest of the attestation file the server checked; the server's word that it is the record's attestation.
    attestation_digest: Digest
    trust_root: TrustRoot
    verifier: AttestationVerifier
    verified_at: Timestamp


class VerifiedAttestation(CiRunSource, AttestationCheck):
    """A build's attestation whose signature the server verified: what its signing certificate names, the image it
    is about, and what is needed to check the verification again.

    The commit, repository and run come from the certificate the CI system's identity was issued, never from the
    statement the job wrote.
    """

    outcome: Literal["verified"]
    # The subject the server matched: the image's own digest.
    image_digest: Digest
    predicate_type: ProvenancePredicateType
    # Who issued the CI system's identity token, such as https://token.actions.githubusercontent.com.
    issuer: CertificateValue
    # The Git reference the run was for, such as refs/heads/main.
    source_ref: CertificateValue
    # The workflow that signed, by its path and reference, and the commit that workflow file was at.
    signer_identity: CertificateValue
    signer_commit: Commit
    # The workflow the run started from.
    build_config: CertificateValue
    # True when the job's own workflow signed, rather than a workflow separate from the job.
    signed_by_same_job: bool
    runner_environment: RunnerEnvironment
    signed_at: Timestamp
    # Where the signing time comes from: a transparency log's entry, or a timestamp authority, which logs nothing.
    timestamp_source: Literal["transparency_log", "timestamp_authority"]
    log_entry: TransparencyLogEntry | None

    @model_validator(mode="after")
    def _logged_and_signed_before_it_was_verified(self) -> VerifiedAttestation:
        if (self.log_entry is not None) != (self.timestamp_source == "transparency_log"):
            raise ValueError("an attestation names its transparency log entry exactly when the log timed its signature")
        if parse_timestamp(self.signed_at) > parse_timestamp(self.verified_at):
            raise ValueError("an attestation was signed no later than the server verified it")
        return self


class RefusedAttestation(AttestationCheck):
    """A build's attestation the server refused, why, and what it checked it against."""

    outcome: Literal["refused"]
    reason: AttestationRefusal


class AttestationNotSent(StrictModel):
    """No attestation was sent with the build."""

    outcome: Literal["not_sent"]


AttestationOutcome = Annotated[
    VerifiedAttestation | RefusedAttestation | AttestationNotSent, Field(discriminator="outcome")
]


Approvals = Annotated[list[Approval], Field(max_length=MAX_FACT_ITEMS)]
Exceptions = Annotated[list[ExceptionGrant], Field(max_length=MAX_FACT_ITEMS)]
Evaluations = Annotated[list[EarlierEvaluation], Field(max_length=MAX_FACT_ITEMS)]
