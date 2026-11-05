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

from types import MappingProxyType
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
# and not_supported: the record leaves the stage out of scope for that reason. not_in_activity: the record's activity
# has no stage after deployment, as a build has none.
RUNTIME_VERIFICATION_RESULTS: frozenset[tuple[VerificationState, str | None]] = frozenset(
    {
        ("client_asserted", "reported_by_pipeline"),
        ("not_assessed", "stage_pending"),
        ("not_performed", "stage_not_reported"),
        ("not_assessed", "project_config"),
        ("not_assessed", "environment_policy"),
        ("not_assessed", "not_supported"),
        ("not_assessed", "not_in_activity"),
    }
)
# The results a verifier gives an approval or an exception that the pre-deploy stage reads. not_in_activity: the
# record's activity has no pre-deploy stage. server_facts_unavailable: the stage ran with no facts from the server.
# pre_deploy_pending: the run that would report the stage is still in progress. pre_deploy_out_of_scope: the record
# leaves the stage out of scope.
_PRE_DEPLOY_RESULTS: frozenset[tuple[VerificationState, str | None]] = frozenset(
    {
        ("not_assessed", "not_in_activity"),
        ("not_performed", "server_facts_unavailable"),
        ("not_assessed", "pre_deploy_pending"),
        ("not_assessed", "pre_deploy_out_of_scope"),
    }
)
# The results a verifier gives each property of a record whose integrity is established, each a state and its reason.
# file_digests: the files the record cites hold the digests it names, which anyone who can edit them can recompute.
# ci_job_held_by_server: only the server that opened the run verified its CI jobs. run_opened_locally: the tool opened
# the run, so no CI job was verified. approvals_listed: the record lists approvals, its writer's claim.
# no_approval_served: the server opened the run and the stage lists no approval. exceptions_not_listed: a record lists
# no exception, so a verifier cannot assess the exceptions the server may have served. server_bundle_named: a stage
# names the server's bundle. local_assertions: the checks were the project's own. expected_stages: every stage the
# record expects reported. stages_pending: the run is still in progress. stage_not_reported: the record is finished
# and a stage it expects was never reported. no_post_deploy_stage: no stage compared the applied plan.
# plan_files_supplied: the plan files given to the verifier were compared. binding_undecided: they could not be.
# deployment_coverage has no reason: no reader of one record knows of a deployment that left no record.
PROPERTY_RESULTS: MappingProxyType[str, frozenset[tuple[VerificationState, str | None]]] = MappingProxyType(
    {
        "integrity": frozenset({("client_asserted", "file_digests")}),
        "source_identity": frozenset(
            {("not_assessed", "ci_job_held_by_server"), ("not_performed", "run_opened_locally")}
        ),
        "approval_identity": _PRE_DEPLOY_RESULTS
        | {("client_asserted", "approvals_listed"), ("not_performed", "no_approval_served")},
        "bundle_provenance": frozenset(
            {("client_asserted", "server_bundle_named"), ("not_performed", "local_assertions")}
        ),
        "stage_completeness": frozenset(
            {
                ("client_asserted", "expected_stages"),
                ("not_assessed", "stages_pending"),
                ("failed", "stage_not_reported"),
            }
        ),
        "plan_apply_match": frozenset(
            {
                ("not_assessed", "not_in_activity"),
                ("not_performed", "no_post_deploy_stage"),
                ("client_asserted", "plan_files_supplied"),
                ("failed", "plan_files_supplied"),
                ("not_determined", "binding_undecided"),
            }
        ),
        "runtime_verification": RUNTIME_VERIFICATION_RESULTS,
        "deployment_coverage": frozenset({("not_assessed", None)}),
        "exceptions": _PRE_DEPLOY_RESULTS | {("not_assessed", "exceptions_not_listed")},
    }
)
# A record whose integrity is not established: its integrity failed on the files it cites, and every other property is
# not determined, since a record that does not hold together says nothing a verifier can take about itself.
INTEGRITY_FAILED: tuple[VerificationState, str | None] = ("failed", "file_digests")
NOT_DETERMINED: tuple[VerificationState, str | None] = ("not_determined", "integrity_failed")


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


class ReportedRecord(StrictModel):
    """The record the report is about: its id, and the digest of its bytes as the verifier read them."""

    uuid: Uuid
    digest: Digest


class VerificationReport(StrictModel):
    """What one verifier found about one record."""

    api_version: Literal["iltero.io/verification-report/v1"] = Field(alias="apiVersion")
    record: ReportedRecord
    verifier: Verifier
    properties: Properties

    @model_validator(mode="after")
    def _results(self) -> VerificationReport:
        # Anyone who can edit a record can recompute its digests. Only a signature could verify a record's integrity,
        # or any property that rests on it, and no record carries one.
        if any(result.state == "verified" for _, result in self.properties):
            raise ValueError("no property of an unsigned record is verified")
        results = {name: (result.state, result.reason) for name, result in self.properties}
        if results["integrity"] == INTEGRITY_FAILED:
            if any(result != NOT_DETERMINED for name, result in results.items() if name != "integrity"):
                raise ValueError(
                    "when a record's integrity is not established, every other property is not_determined with the "
                    "reason integrity_failed"
                )
            return self
        for name, result in results.items():
            if result not in PROPERTY_RESULTS[name]:
                raise ValueError(f"{name} is one of the results a verifier gives that property")
        return self
