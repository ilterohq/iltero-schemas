"""``VerificationReport`` v1: what a verifier found about one record, one property at a time.

A verifier, such as ``iltero car verify``, reads a Change Assurance Record
and the files it cites. It reports on nine properties, one at a time. Each
property gets a state and, where it helps, the reason for it.
There is no overall "verified". A reader looks at each property it needs.

The report is a document of its own, not a part of the record. The tool that
wrote a record cannot vouch for that record, so a record carries no
verification results. The report names the record it is about by the digest
of the record's bytes.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from iltero_schemas.models.base import StrictModel
from iltero_schemas.models.fields import Digest, Identifier, Uuid

API_VERSION = "iltero.io/verification-report/v1"
# verified: the verifier checked the property and it holds. failed: it checked it and it does not hold.
# not_determined: it looked and could not decide. not_assessed: it did not assess the property for this
# record, for example because the step it reads is pending or out of scope. not_performed: the record shows
# that the step the property is about did not happen. client_asserted: the only evidence is the record's own
# claim.
VerificationState = Literal[
    "verified",
    "failed",
    "not_determined",
    "not_assessed",
    "not_performed",
    "client_asserted",
]


# The results a verifier gives the verification after deployment, each a state and its reason.
# reported_by_pipeline: the pipeline reported its post-verify stage, which only the pipeline's word supports.
# stage_pending: the record expects the stage, and the run that would report it is still in progress.
# stage_not_reported: the record expects the stage, and it was never reported. project_config, environment_policy
# and not_supported: the record leaves the stage out of scope for that reason. When the record's integrity is not
# established, the property is not_determined, as every other one is.
RUNTIME_VERIFICATION_RESULTS: frozenset[tuple[VerificationState, str]] = frozenset(
    {
        ("client_asserted", "reported_by_pipeline"),
        ("not_assessed", "stage_pending"),
        ("not_performed", "stage_not_reported"),
        ("not_assessed", "project_config"),
        ("not_assessed", "environment_policy"),
        ("not_assessed", "not_supported"),
    }
)


class PropertyResult(StrictModel):
    """One property's state, and a short name for why it is that state (null when there is nothing to name)."""

    state: VerificationState
    reason: Identifier | None


class Properties(StrictModel):
    """The nine properties a verifier reports on. Each says what ``verified`` would mean."""

    # The record's structure is valid, and the evidence it cites has not changed.
    integrity: PropertyResult
    # The repository, the commit and the pipeline came from an authenticated source.
    source_identity: PropertyResult
    # Every approval came from an authenticated identity.
    approval_identity: PropertyResult
    # The evaluations ran from a bundle signed by an authorised key that was not revoked.
    bundle_provenance: PropertyResult
    # Every required stage is present, and every assertion owed has a result or is listed as not evaluated.
    stage_completeness: PropertyResult
    # The plan that was approved is the plan that was applied.
    plan_apply_match: PropertyResult
    # A verification after deployment ran.
    runtime_verification: PropertyResult
    # No deployment known to the connected systems is missing a record.
    deployment_coverage: PropertyResult
    # Every exception used was approved and valid at the time of deployment.
    exceptions: PropertyResult


class Verifier(StrictModel):
    """The program that wrote the report, and its version as the program reports it."""

    name: Literal["iltero"]
    version: Identifier


class VerifiedRecord(StrictModel):
    """The record the report is about: its id, and the digest of its bytes as the verifier read them."""

    uuid: Uuid
    digest: Digest


class VerificationReport(StrictModel):
    """What one verifier found about one record."""

    api_version: Literal["iltero.io/verification-report/v1"] = Field(alias="apiVersion")
    record: VerifiedRecord
    verifier: Verifier
    properties: Properties

    @model_validator(mode="after")
    def _integrity_needs_a_signature(self) -> VerificationReport:
        # Anyone who can edit a record can recompute its digests. Only a signature could verify its integrity,
        # and no record carries one in this version.
        integrity = self.properties.integrity.state
        if integrity == "verified":
            raise ValueError("a record's integrity is verified only by a signature, and no record carries one")
        # A record that does not hold together says nothing a verifier can take about itself.
        others = {result.state for name, result in self.properties if name != "integrity"}
        if integrity in ("failed", "not_determined") and others != {"not_determined"}:
            raise ValueError("when a record's integrity is not established, every other property is not_determined")
        runtime = self.properties.runtime_verification
        established = integrity not in ("failed", "not_determined")
        if established and (runtime.state, runtime.reason) not in RUNTIME_VERIFICATION_RESULTS:
            raise ValueError("runtime_verification is one of the results a verifier gives the stage after deployment")
        return self
