"""``VerificationReport`` v1: what a verifier found about one record, one property at a time.

A verifier, such as ``iltero record verify``, reads a Change Assurance Record
and the files it cites. It reports on twelve properties, one at a time. Each
property gets a state and, where it helps, the reason for it and a detail.
There is no overall "verified". A reader looks at each property it needs.

The report is a document of its own, not a part of the record. The tool that
wrote a record cannot vouch for that record, so a record carries no
verification results. The report names the record it is about by its id and the
digest of its canonical JSON.
"""

from __future__ import annotations

from collections.abc import Collection
from types import MappingProxyType
from typing import Annotated, Literal

from pydantic import AfterValidator, Field, model_validator

from iltero_schemas.models.common.base import API_VERSION as API_VERSION
from iltero_schemas.models.common.base import StrictModel
from iltero_schemas.models.common.fields import Digest, Identifier, Timestamp, Uuid, plain_text

KIND = "VerificationReport"
# verified: the verifier checked the property and it holds. failed: it checked it and it does not hold.
# could_not_decide: it looked and could not decide. not_assessed: it did not assess the property for this
# record, for example because the step it reads is pending or out of scope. not_performed: the record shows
# that the step the property is about did not happen. claimed_by_record: the only evidence is the record's own
# claim.
VerificationState = Literal[
    "verified",
    "failed",
    "could_not_decide",
    "not_assessed",
    "not_performed",
    "claimed_by_record",
]
# Long enough for a stage name and a sentence about what the verifier found.
RESULT_DETAIL_MAX_LENGTH = 1024


# The results a verifier gives the verification after deployment, each a state and its reason.
# reported_by_pipeline: the pipeline reported its post-verify stage, which only the pipeline's word supports.
# stage_pending: the record expects the stage, and the run that would report it is still in progress.
# stage_not_reported: the record expects the stage, and it was never reported. project_config, environment_policy
# and not_supported: the record leaves the stage out of scope for that reason. not_in_activity: the record's activity
# has no stage after deployment, as a build has none.
RUNTIME_VERIFICATION_RESULTS: frozenset[tuple[VerificationState, str | None]] = frozenset(
    {
        ("claimed_by_record", "reported_by_pipeline"),
        ("not_assessed", "stage_pending"),
        ("not_performed", "stage_not_reported"),
        ("not_assessed", "project_config"),
        ("not_assessed", "environment_policy"),
        ("not_assessed", "not_supported"),
        ("not_assessed", "not_in_activity"),
    }
)
# The results a verifier gives an approval, an exception or the commit review that the pre-deploy stage reads.
# not_in_activity: the record's activity has no pre-deploy stage. run_opened_locally: the tool opened the run, so no
# server served the fact and no check of it happened. server_facts_unavailable: the server opened the run, a check
# needed the fact, and the stage kept the unknown marker in its place. pre_deploy_pending: the run that would report the
# stage is still in progress. pre_deploy_out_of_scope: the record leaves the stage out of scope.
_PRE_DEPLOY_RESULTS: frozenset[tuple[VerificationState, str | None]] = frozenset(
    {
        ("not_assessed", "not_in_activity"),
        ("not_performed", "run_opened_locally"),
        ("could_not_decide", "server_facts_unavailable"),
        ("not_assessed", "pre_deploy_pending"),
        ("not_assessed", "pre_deploy_out_of_scope"),
    }
)
# not_read_by_the_stage: the stage's results read no such fact, so it kept the marker that says so (an approval or the
# commit review; a stage keeps no exceptions, so this result is never an exception's).
_NOT_READ_BY_THE_STAGE: tuple[VerificationState, str | None] = ("not_assessed", "not_read_by_the_stage")
# The results a verifier gives the exceptions a record relied on. project_exception_relied_on: an event names an
# exception from the project's own exceptions file, the project's own word. project_exceptions_file_not_relied_on: a
# stage applied a project exceptions file and no event relied on an exception from it. exceptions_not_listed: the
# record lists no exception, so a verifier cannot assess the exceptions a server may have served (a run the server
# opened). Their order with the pre-deploy results is ``PRE_DEPLOY_RESULT_ORDER``.
_EXCEPTION_RESULTS: frozenset[tuple[VerificationState, str | None]] = frozenset(
    {
        ("claimed_by_record", "project_exception_relied_on"),
        ("claimed_by_record", "project_exceptions_file_not_relied_on"),
        ("not_assessed", "exceptions_not_listed"),
    }
)
# The order a verifier takes the results of an approval, an exception or the commit review in: the first that holds for
# the record is its result, and the stage's own result (such as approvals_listed or a commit review outcome) comes only
# when none of these holds. So one record gives one report. The project's own exceptions come first: a stage other than
# pre-deploy may rely on one, so a pre-deploy stage that is not in the activity or out of scope does not hide it.
PRE_DEPLOY_RESULT_ORDER: tuple[tuple[VerificationState, str], ...] = (
    ("claimed_by_record", "project_exception_relied_on"),
    ("claimed_by_record", "project_exceptions_file_not_relied_on"),
    ("not_assessed", "not_in_activity"),
    ("not_assessed", "pre_deploy_out_of_scope"),
    ("not_performed", "run_opened_locally"),
    ("not_assessed", "pre_deploy_pending"),
)


def first_that_holds(holding: Collection[tuple[VerificationState, str]]) -> tuple[VerificationState, str] | None:
    """The result of ``PRE_DEPLOY_RESULT_ORDER`` that comes first among ``holding``, the results that hold for one
    property of a record, or None when none of them holds and the stage's own result applies. Pass only results that
    property can take (``PROPERTY_RESULTS``): an exception result given for an approval is refused when the report is
    read."""
    return next((result for result in PRE_DEPLOY_RESULT_ORDER if result in holding), None)


# The results a verifier gives the reference time, by the weakest source any stage of the record took its time from:
# runner_clock when any stage used the runner's own clock, so no trusted time source was used; server when every stage
# took the time the server gave, the record's own claim until a signature binds it.
REFERENCE_TIME_RESULTS: frozenset[tuple[VerificationState, str | None]] = frozenset(
    {("not_performed", "runner_clock"), ("claimed_by_record", "server")}
)
# The results a verifier gives the evaluator binary (``models.common.pinned_evaluator``): every OPA evaluation names the
# binary of the release this contract pins for its platform, the record's own claim; an evaluation names another
# version, platform or binary, its first problem in the detail; or the record has no OPA evaluation.
EVALUATOR_BINARY_RESULTS: frozenset[tuple[VerificationState, str | None]] = frozenset(
    {
        ("claimed_by_record", "pinned_binary_named"),
        ("failed", "other_binary_named"),
        ("not_assessed", "no_opa_evaluation"),
    }
)
# The result a verifier gives the commit review for the outcome the pre-deploy stage kept, by that outcome; the reason
# is the outcome. reviewed is the record's claim. The outcomes that show a commit the change ships was not reviewed
# fail. too_many_commits was not decided, and no_review_starting_point checked no commit.
COMMIT_REVIEW_RESULTS: MappingProxyType[str, tuple[VerificationState, str]] = MappingProxyType(
    {
        "reviewed": ("claimed_by_record", "reviewed"),
        "not_reviewed": ("failed", "not_reviewed"),
        "review_starting_point_not_in_history": ("failed", "review_starting_point_not_in_history"),
        "head_commit_before_review_starting_point": ("failed", "head_commit_before_review_starting_point"),
        "source_commit_not_verified_commit": ("failed", "source_commit_not_verified_commit"),
        "build_commit_not_verified_commit": ("failed", "build_commit_not_verified_commit"),
        "too_many_commits": ("could_not_decide", "too_many_commits"),
        "no_review_starting_point": ("not_performed", "no_review_starting_point"),
    }
)
# The results a verifier gives each property of a record whose integrity is established, each a state and its reason.
# file_digests: the files the record cites hold the digests it names, which anyone who can edit them can recompute.
# ci_job_held_by_server: only the server that opened the run verified its CI jobs. run_opened_locally: the tool opened
# the run, so no CI job was verified. approvals_listed: the record lists approvals, its writer's claim.
# no_approval_served: the server opened the run and the stage keeps an empty list of approvals. exceptions_not_listed: a
# record lists no exception, so a verifier cannot assess the exceptions the server may have served. server_bundle_named:
# a stage names the server's bundle. local_assertions: the checks were the project's own. expected_stages: every stage
# the record expects reported. stages_pending: the run is still in progress. stage_not_reported: the record is finished
# and a stage it expects was never reported. no_post_deploy_stage: no stage compared the applied plan.
# plan_files_supplied: the plan files given to the verifier were compared. binding_undecided: they could not be.
# deployment_coverage has no reason: no reader of one record knows of a deployment that left no record.
PROPERTY_RESULTS: MappingProxyType[str, frozenset[tuple[VerificationState, str | None]]] = MappingProxyType(
    {
        "integrity": frozenset({("claimed_by_record", "file_digests")}),
        "source_identity": frozenset(
            {("not_assessed", "ci_job_held_by_server"), ("not_performed", "run_opened_locally")}
        ),
        "approval_identity": _PRE_DEPLOY_RESULTS
        | {_NOT_READ_BY_THE_STAGE, ("claimed_by_record", "approvals_listed"), ("not_performed", "no_approval_served")},
        "bundle_provenance": frozenset(
            {("claimed_by_record", "server_bundle_named"), ("not_performed", "local_assertions")}
        ),
        "stage_completeness": frozenset(
            {
                ("claimed_by_record", "expected_stages"),
                ("not_assessed", "stages_pending"),
                ("failed", "stage_not_reported"),
            }
        ),
        "plan_apply_match": frozenset(
            {
                ("not_assessed", "not_in_activity"),
                ("not_performed", "no_post_deploy_stage"),
                ("claimed_by_record", "plan_files_supplied"),
                ("failed", "plan_files_supplied"),
                ("could_not_decide", "binding_undecided"),
            }
        ),
        "runtime_verification": RUNTIME_VERIFICATION_RESULTS,
        "deployment_coverage": frozenset({("not_assessed", None)}),
        # A stage keeps no exceptions, so no stage keeps the unknown marker in their place.
        "exceptions": (_PRE_DEPLOY_RESULTS - {("could_not_decide", "server_facts_unavailable")}) | _EXCEPTION_RESULTS,
        "commit_review": _PRE_DEPLOY_RESULTS | {_NOT_READ_BY_THE_STAGE} | frozenset(COMMIT_REVIEW_RESULTS.values()),
        "reference_time": REFERENCE_TIME_RESULTS,
        "evaluator_binary": EVALUATOR_BINARY_RESULTS,
    }
)
# A record whose integrity is not established: its integrity failed on the files it cites, and the verifier could not
# decide any other property, since a record that does not hold together says nothing a verifier can take about itself.
INTEGRITY_FAILED: tuple[VerificationState, str | None] = ("failed", "file_digests")
COULD_NOT_DECIDE: tuple[VerificationState, str | None] = ("could_not_decide", "integrity_failed")


class PropertyResult(StrictModel):
    """One property's state, a short name for why it is that state (null when there is nothing to name), and a plain
    sentence about what the verifier found (null when there is nothing to add)."""

    state: VerificationState
    reason: Identifier | None
    detail: Annotated[str, Field(min_length=1, max_length=RESULT_DETAIL_MAX_LENGTH), AfterValidator(plain_text)] | None


class Properties(StrictModel):
    """The twelve properties a verifier reports on. Each says what ``verified`` would mean."""

    # The record's structure is valid, and the evidence it cites has not changed.
    integrity: PropertyResult
    # The repository, the commit and the pipeline came from an authenticated source.
    source_identity: PropertyResult
    # Every approval came from an authenticated identity.
    approval_identity: PropertyResult
    # The evaluations ran from a bundle signed by an authorised key that was not revoked.
    bundle_provenance: PropertyResult
    # Every required stage is present, and every required assertion has a result or is listed as not evaluated.
    stage_completeness: PropertyResult
    # The plan that was approved is the plan that was applied.
    plan_apply_match: PropertyResult
    # A verification after deployment ran.
    runtime_verification: PropertyResult
    # No deployment known to the connected systems is missing a record.
    deployment_coverage: PropertyResult
    # Every exception relied on was approved and in force at the reference time of the stage that relied on it.
    exceptions: PropertyResult
    # Every commit the change ships was reviewed.
    commit_review: PropertyResult
    # Every stage took its reference time, which every expiry and ordering comparison uses, from a source a verifier
    # can trust.
    reference_time: PropertyResult
    # Every evaluation ran on the binary of the Open Policy Agent (OPA) release this contract pins, for its platform.
    evaluator_binary: PropertyResult


class Verifier(StrictModel):
    """The program that wrote the report, and its version as the program reports it."""

    name: Literal["iltero"]
    version: Identifier


class ReportedRecord(StrictModel):
    """The record the report is about: its id, and the digest of its canonical JSON as the verifier read it."""

    uuid: Uuid
    digest: Digest


class ReportMetadata(StrictModel):
    """The report's fixed facts: the program that wrote it, and when, by its own clock. A result such as a stage
    still pending holds at that time."""

    verifier: Verifier
    verified_at: Timestamp


class VerificationReport(StrictModel):
    """What one verifier found about one record."""

    api_version: Literal["iltero.com/v1"] = Field(alias="apiVersion")
    kind: Literal["VerificationReport"]
    metadata: ReportMetadata
    record: ReportedRecord
    properties: Properties

    @model_validator(mode="after")
    def _results(self) -> VerificationReport:
        # Anyone who can edit a record can recompute its digests. Only a signature could verify a record's integrity,
        # or any property that rests on it, and no record carries one.
        if any(result.state == "verified" for _, result in self.properties):
            raise ValueError("no property of an unsigned record is verified")
        results = {name: (result.state, result.reason) for name, result in self.properties}
        if results["integrity"] == INTEGRITY_FAILED:
            if any(result != COULD_NOT_DECIDE for name, result in results.items() if name != "integrity"):
                raise ValueError(
                    "when a record's integrity is not established, every other property is could_not_decide with the "
                    "reason integrity_failed"
                )
            return self
        for name, result in results.items():
            if result not in PROPERTY_RESULTS[name]:
                raise ValueError(f"{name} is one of the results a verifier gives that property")
        return self
