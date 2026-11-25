"""``VerificationReport`` v1: what a verifier found about one record, one property at a time.

A verifier, such as ``iltero record verify``, reads a Change Assurance Record, the files it cites and, when it is
given one, the run statement the server that opened the run signed when the run ended. It assigns the record a trust
level (``report_trust``) and reports on twenty properties, one at a time. Each property gets a state and, where it
helps, the reason for it and a detail. There is no overall "verified". A reader looks at each property it needs.

A property is ``verified`` only when a signature the verifier checked covers the facts it rests on, and those facts
show it holds. Every ``verified`` result but the bundle signature's rests on the run statement, and its reason is
``run_statement`` or names what the statement signs (``served_and_named_by_every_accepted_result``,
``pinned_and_named_by_accepted_record``). The bundle signature's, ``bundle_signature_checked``, rests on the signature
of the served bundle each stage kept.

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

from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.base import API_VERSION as API_VERSION
from iltero_schemas.models.common.base import StageValue, StrictModel
from iltero_schemas.models.common.fields import Digest, Identifier, Timestamp, Uuid, plain_text
from iltero_schemas.models.common.report_trust import (
    AssignedTrustLevel,
    RunStatementFindings,
    StatementTrustRoot,
    trust_level_problem,
)
from iltero_schemas.models.common.verification_states import BUNDLE_SIGNATURE_CHECKED as BUNDLE_SIGNATURE_CHECKED
from iltero_schemas.models.common.verification_states import COULD_NOT_DECIDE as COULD_NOT_DECIDE
from iltero_schemas.models.common.verification_states import INTEGRITY_FAILED as INTEGRITY_FAILED
from iltero_schemas.models.common.verification_states import (
    LATER_RECORD_HOLDS_THE_LATER_STAGES as LATER_RECORD_HOLDS_THE_LATER_STAGES,
)
from iltero_schemas.models.common.verification_states import REFUSED_BY_SERVER as REFUSED_BY_SERVER
from iltero_schemas.models.common.verification_states import RUN_STATEMENT as RUN_STATEMENT
from iltero_schemas.models.common.verification_states import SERVED_PART_DIFFERS as SERVED_PART_DIFFERS
from iltero_schemas.models.common.verification_states import VerificationState as VerificationState

KIND = "VerificationReport"
# Long enough for a stage name and a sentence about what the verifier found.
RESULT_DETAIL_MAX_LENGTH = 1024


# The results a verifier gives the check after deployment, each a state and its reason. reported_by_pipeline: the
# pipeline reported its post-verify stage, which only the pipeline's word supports. stage_pending: the record expects
# the stage, and the run that would report it is still in progress. stage_not_reported: the record expects the stage,
# and it was never reported. later_record_holds_the_later_stages: the run statement names a later record as the one that
# holds the stages after this record's. project_config, environment_policy and not_supported: the record leaves the
# stage out of scope for that reason. not_in_activity: the record's activity has no stage after deployment, as a build
# has none.
CHECK_AFTER_DEPLOYMENT_RESULTS: frozenset[tuple[VerificationState, str | None]] = frozenset(
    {
        ("claimed_by_record", "reported_by_pipeline"),
        ("not_assessed", "stage_pending"),
        ("not_performed", "stage_not_reported"),
        ("not_assessed", "project_config"),
        ("not_assessed", "environment_policy"),
        ("not_assessed", "not_supported"),
        ("not_assessed", "not_in_activity"),
        LATER_RECORD_HOLDS_THE_LATER_STAGES,
    }
)
# The results a verifier gives the approvals and the commit review the pre-deploy stage reads, and the exceptions a
# record relied on.
# not_in_activity: the record's activity has no pre-deploy stage, or, for the exceptions, applies no exception at any
# stage, as an image build or deploy does. run_opened_locally: the tool opened the run, so no server served the fact
# and no check of it happened. server_facts_unavailable: the server opened the run, a check needed the fact, and the
# stage kept the unknown marker in its place. pre_deploy_pending: the run that would report the stage is still in
# progress. pre_deploy_out_of_scope: the record leaves the stage out of scope for a reason other than needs_the_server;
# a run the tool opened that leaves it out as needing the server gets run_opened_locally.
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
# commit review; this result is never an exception's).
_NOT_READ_BY_THE_STAGE: tuple[VerificationState, str | None] = ("not_assessed", "not_read_by_the_stage")
# The results a verifier gives the exceptions a record relied on (``models.iac.report_results.exception_results``).
# kept_exceptions_do_not_hold: an exceptions file a stage kept, the project's own or the one the server served, does not
# give the exceptions the record names, or was served to another run, stage or environment. served_exception_relied_on:
# the plan stage names a failed result an exception the server served covers, and the kept copy gives it; only the
# server that opened the run confirms that it served that copy, who approved each exception and whether one was revoked
# later, and whether an exception was in force rests on the stage's reference time. served_exception_approved_by_run_
# starter: the same, and the copy says the person who approved one of those exceptions started the run.
# served_exceptions_not_relied_on: the plan stage applied the exceptions the server served and names no failed result
# they cover. project_exception_relied_on: an event names an exception from the project's own exceptions file, the
# project's own word. project_exceptions_file_not_relied_on: a stage applied a project exceptions file and no event
# relied on an exception from it. ``exception_results`` also gives the pre-deploy result not_in_activity for an activity
# that applies no exception at any stage. With a run statement that holds for the record, served_exception_relied_on
# becomes (verified, run_statement): the statement signs the copy, and the kept-file checks match each exception to the
# results it covers at the stage's reference time, which the statement signs too. Their order with the pre-deploy
# results is ``PRE_DEPLOY_RESULT_ORDER``.
_EXCEPTION_RESULTS: frozenset[tuple[VerificationState, str | None]] = frozenset(
    {
        ("failed", "kept_exceptions_do_not_hold"),
        RUN_STATEMENT,
        ("claimed_by_record", "served_exception_approved_by_run_starter"),
        ("claimed_by_record", "served_exception_relied_on"),
        ("claimed_by_record", "served_exceptions_not_relied_on"),
        ("claimed_by_record", "project_exception_relied_on"),
        ("claimed_by_record", "project_exceptions_file_not_relied_on"),
    }
)
# The order a verifier takes the results of an approval, an exception or the commit review in: the first that holds for
# the record is its result, and the stage's own result (such as approvals_listed or a commit review outcome) comes only
# when none of these holds. So one record gives one report. The exception results come first, and a kept file that does
# not hold before any: the plan stage applies exceptions, so a pre-deploy stage that is not in the activity, out of
# scope or still pending does not hide one the record relied on. An exception the server served that a run statement
# covers comes after one of the project's own, which nothing signs, so a record that relies on both is not verified.
PRE_DEPLOY_RESULT_ORDER: tuple[tuple[VerificationState, str], ...] = (
    ("failed", "kept_exceptions_do_not_hold"),
    ("claimed_by_record", "served_exception_approved_by_run_starter"),
    ("claimed_by_record", "served_exception_relied_on"),
    ("claimed_by_record", "project_exception_relied_on"),
    RUN_STATEMENT,
    ("claimed_by_record", "served_exceptions_not_relied_on"),
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


# The results a verifier gives the six properties about the job that applies an infrastructure change, beyond the
# pre-deploy results, in the order a verifier takes them (``models.iac.apply_job_results``): the first that holds is
# the property's result. plan_and_apply_in_one_job: the run plans and applies in one job, so the step the property is
# about does not happen. approval_not_required: the environment's policy requires no approval of the apply job.
# rendered_plan_not_sent and replan_not_compared: the apply job reported no rendered plan, or compared no re-plan. The
# order results keep the name of the field plan_stage_record_accepted_at, the time the server received the plan-stage
# record that counts. The failed and
# claimed_by_record results name what the facts the pre-deploy stage kept, or change.replan_check, say. Of the facts,
# only the server's own times, limit, approval requirement and pinned plan are the server's word: the received plan
# file's digest and the rendered plan are what the apply job reported, and the re-plan is the pipeline's. So a run
# statement that signs the kept facts (and, for the approval order, the approvals) upgrades only plan_age,
# apply_job_approval_order and pinned_plan (``UPGRADED_BY_RUN_STATEMENT``). A rendered plan that differs decides
# replan_resource_actions before the comparison does.
_ONE_JOB_FLOW: tuple[VerificationState, str] = ("not_performed", "plan_and_apply_in_one_job")
APPLY_JOB_RESULT_ORDER: MappingProxyType[str, tuple[tuple[VerificationState, str], ...]] = MappingProxyType(
    {
        "plan_age": (("failed", "plan_older_than_limit"), ("claimed_by_record", "plan_age_within_limit")),
        "apply_job_approval_order": (
            _ONE_JOB_FLOW,
            ("not_performed", "approval_not_required"),
            ("failed", "approved_before_plan_stage_record_accepted"),
            ("failed", "no_approval_after_plan_stage_record_accepted"),
            ("claimed_by_record", "approved_after_plan_stage_record_accepted"),
        ),
        "received_plan_file": (
            _ONE_JOB_FLOW,
            ("failed", "plan_file_not_sent"),
            ("failed", "received_plan_file_differs"),
            ("claimed_by_record", "received_plan_file_matches"),
        ),
        "rendered_plan": (
            _ONE_JOB_FLOW,
            ("failed", "rendered_plan_differs"),
            ("could_not_decide", "rendered_plan_not_sent"),
            ("claimed_by_record", "rendered_plan_matches"),
        ),
        "pinned_plan": (
            ("failed", "plan_differs_from_pinned_plan"),
            ("claimed_by_record", "evaluated_plan_is_pinned_plan"),
        ),
        "replan_resource_actions": (
            _ONE_JOB_FLOW,
            ("failed", "rendered_plan_differs"),
            ("failed", "resource_actions_differ"),
            ("could_not_decide", "replan_not_compared"),
            ("claimed_by_record", "same_resource_actions"),
        ),
    }
)


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
# The results a verifier gives the ``scanner_reports`` property (``models.iac.report_results.scanner_reports_result``),
# the first that holds in this order. kept_files_do_not_give_the_verdicts: a scanner evaluation does not follow from the
# files its stage kept. other_scanner_named: a report of a scanner the Iltero CLI ran names a release, platform
# or digest the scanner pin does not give (``models.common.pinned_scanner``). scanner_requirement_not_met: a group of
# scanners the stage requires gave only gaps for a check and subject. ran_by_pipeline: a kept report the pipeline ran,
# the pipeline's word. ran_by_iltero_cli: every kept report the Iltero CLI ran, the record's word, each naming the
# pinned release. not_in_activity: the record's activity reads no scanner report.
# no_scanner_report: no stage read a scanner report and none requires one; in a run the server opened, only that server
# confirms its stages required none.
SCANNER_REPORTS_RESULT_ORDER: tuple[tuple[VerificationState, str], ...] = (
    ("failed", "kept_files_do_not_give_the_verdicts"),
    ("failed", "other_scanner_named"),
    ("not_performed", "scanner_requirement_not_met"),
    ("claimed_by_record", "ran_by_pipeline"),
    ("claimed_by_record", "ran_by_iltero_cli"),
    ("not_assessed", "not_in_activity"),
    ("not_assessed", "no_scanner_report"),
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
# refused_by_server: the run statement lists the record as one the server refused. ci_job_held_by_server: only the
# server that opened the run verified its CI jobs, and no run statement was given that signs them. run_opened_locally:
# the tool opened the run, so no CI job was verified. ci_job_differs: the record's commit, or its repository, is not
# that of the CI job the run statement signs for a stage. approvals_listed: the record lists approvals, its writer's
# claim. no_approval_served: the server opened the run and the stage keeps an empty list of approvals.
# served_part_differs: a stage's copy of a part the server served, or of the apply job's facts, is not the one the run
# statement signs. The ``exceptions`` and ``scanner_reports`` results are described where they are listed.
# bundle_signature_checked: every stage that names the server's bundle kept its tarball, and it read back under a key of
# the reader's trust set, its signature verified. local_assertions: the checks were the project's own.
# trust_data_differs: a stage names other trust data than the reader holds, so it checked its bundle against other keys.
# bundle_of_another_server: a stage's bundle is signed by a key that is not one of the server the run statement names.
# server_bundle_named: a stage names the server's bundle, and no run statement says the run was held to it.
# served_and_named_by_every_accepted_result: the run statement says the server held the run to the bundle every stage
# names; that the evaluator ran from it stays the record's word. bundle_differs: a stage names another bundle than the
# run statement's settings. expected_stages: every stage the record expects reported. stages_pending: the run is still
# in progress. stage_not_reported: the record is finished and a stage it expects was never reported. With a run
# statement, for the unit's subject that reports every stage it expects: run_statement when the run left no result it
# required of the unit unanswered; run_abandoned when the run was abandoned and left one; required_results_unanswered
# when the run closed and left one. later_record_holds_the_later_stages for a record a later record replaced, which
# holds none of the later stages. expected_stages_differ, stage_not_listed and required_assertions_differ when the
# record's expected stages, a stage it holds, or a stage's required assertions are not those the statement signs.
# scanner_check_mapping_differs (scanner_reports): a stage applied another served scanner check mapping than the run
# statement's settings. reference_time_differs: a stage took its time from the server, and it is not when the run
# statement says the server issued the stage its facts or its token. no_post_deploy_stage: no stage compared the applied
# plan. plan_digests_compared: the record compared the digests it names of the evaluated plan and the applied plan.
# redacted_plan_only: in a run the tool opened that names no saved plan file, the record compared only the digests of
# the redacted plans, so hidden values were not compared; of a comparison that held, a verifier gives it exactly when
# the tool opened the run and change.plan.artifact_digest_source is not_provided, and plan_digests_compared otherwise. A
# comparison that failed gives plan_digests_compared: redacted plans that differ already show the plans differ.
# binding_undecided: the record could not compare them. pinned_and_named_by_accepted_record: the run statement signs the
# facts that say the plan the accepted record names as evaluated is the plan the server pinned; that the runner
# evaluated that plan stays its word. deployment_coverage has no reason: no reader of one record knows of a deployment
# that left no record.
_FACTS_DIFFER: frozenset[tuple[VerificationState, str | None]] = frozenset({SERVED_PART_DIFFERS})
_APPLY_JOB_UPGRADES: MappingProxyType[str, frozenset[tuple[VerificationState, str | None]]] = MappingProxyType(
    {
        "plan_age": frozenset({RUN_STATEMENT}),
        "apply_job_approval_order": frozenset({RUN_STATEMENT}),
        "pinned_plan": frozenset({("verified", "pinned_and_named_by_accepted_record")}),
    }
)
PROPERTY_RESULTS: MappingProxyType[str, frozenset[tuple[VerificationState, str | None]]] = MappingProxyType(
    {
        "integrity": frozenset({("claimed_by_record", "file_digests"), RUN_STATEMENT, REFUSED_BY_SERVER}),
        "source_identity": frozenset(
            {
                ("not_assessed", "ci_job_held_by_server"),
                ("not_performed", "run_opened_locally"),
                RUN_STATEMENT,
                ("failed", "ci_job_differs"),
            }
        ),
        "approval_identity": _PRE_DEPLOY_RESULTS
        | {
            _NOT_READ_BY_THE_STAGE,
            ("claimed_by_record", "approvals_listed"),
            ("not_performed", "no_approval_served"),
            RUN_STATEMENT,
            SERVED_PART_DIFFERS,
        },
        "bundle_signature": frozenset(
            {
                BUNDLE_SIGNATURE_CHECKED,
                ("not_performed", "local_assertions"),
                ("failed", "trust_data_differs"),
                ("failed", "bundle_of_another_server"),
            }
        ),
        "bundle_used": frozenset(
            {
                ("verified", "served_and_named_by_every_accepted_result"),
                ("claimed_by_record", "server_bundle_named"),
                ("not_performed", "local_assertions"),
                ("failed", "bundle_differs"),
            }
        ),
        "stage_completeness": frozenset(
            {
                ("claimed_by_record", "expected_stages"),
                ("not_assessed", "stages_pending"),
                ("failed", "stage_not_reported"),
                RUN_STATEMENT,
                ("failed", "run_abandoned"),
                ("failed", "required_results_unanswered"),
                ("failed", "expected_stages_differ"),
                ("failed", "stage_not_listed"),
                ("failed", "required_assertions_differ"),
                LATER_RECORD_HOLDS_THE_LATER_STAGES,
            }
        ),
        "plan_apply_match": frozenset(
            {
                ("not_assessed", "not_in_activity"),
                ("not_performed", "no_post_deploy_stage"),
                ("claimed_by_record", "plan_digests_compared"),
                ("claimed_by_record", "redacted_plan_only"),
                ("failed", "plan_digests_compared"),
                ("could_not_decide", "binding_undecided"),
            }
        ),
        "check_after_deployment": CHECK_AFTER_DEPLOYMENT_RESULTS,
        "deployment_coverage": frozenset({("not_assessed", None)}),
        # No stage keeps an unknown marker for exceptions: a stage of a run the server opened is always served them.
        "exceptions": (_PRE_DEPLOY_RESULTS - {("could_not_decide", "server_facts_unavailable")})
        | _EXCEPTION_RESULTS
        | {SERVED_PART_DIFFERS},
        "commit_review": _PRE_DEPLOY_RESULTS
        | {_NOT_READ_BY_THE_STAGE, RUN_STATEMENT, SERVED_PART_DIFFERS}
        | frozenset(COMMIT_REVIEW_RESULTS.values()),
        "reference_time": REFERENCE_TIME_RESULTS | {RUN_STATEMENT, ("failed", "reference_time_differs")},
        "evaluator_binary": EVALUATOR_BINARY_RESULTS,
        "scanner_reports": frozenset(SCANNER_REPORTS_RESULT_ORDER) | {("failed", "scanner_check_mapping_differs")},
        **{
            name: _PRE_DEPLOY_RESULTS | frozenset(order) | _FACTS_DIFFER | _APPLY_JOB_UPGRADES.get(name, frozenset())
            for name, order in APPLY_JOB_RESULT_ORDER.items()
        },
    }
)


class PropertyResult(StrictModel):
    """One property's state, a short name for why it is that state (null when there is nothing to name), and a plain
    sentence about what the verifier found (null when there is nothing to add)."""

    state: VerificationState
    reason: Identifier | None
    detail: Annotated[str, Field(min_length=1, max_length=RESULT_DETAIL_MAX_LENGTH), AfterValidator(plain_text)] | None


class Properties(StrictModel):
    """The twenty properties a verifier reports on. Each says what ``verified`` would mean; for the properties about
    the job that applies an infrastructure change that no verifier can verify, what its best result claims."""

    # The record's structure is valid, the evidence it cites has not changed, and it is a record the server accepted.
    integrity: PropertyResult
    # The repository and the commit are those of the CI jobs the server verified held the stages' tokens.
    source_identity: PropertyResult
    # Every approval is one the server served the stage.
    approval_identity: PropertyResult
    # The served bundle each stage names, as it kept it, is signed by an authorized key that was not revoked; that the
    # stage ran it stays the record's word.
    bundle_signature: PropertyResult
    # The server held the run to the bundle every stage names.
    bundle_used: PropertyResult
    # Every required stage is present, and every required assertion has a result or is listed as not evaluated.
    stage_completeness: PropertyResult
    # The plan the record says was evaluated is the plan it says was applied.
    plan_apply_match: PropertyResult
    # A check after deployment ran.
    check_after_deployment: PropertyResult
    # No deployment of the project and environment is missing a record.
    deployment_coverage: PropertyResult
    # Every exception relied on was served by the server and in force at the reference time of the stage that relied
    # on it.
    exceptions: PropertyResult
    # Every commit the change ships was reviewed.
    commit_review: PropertyResult
    # Every stage took its reference time, which every expiry and ordering comparison uses, from the server, at the time
    # it issued the stage its facts or its token.
    reference_time: PropertyResult
    # Every evaluation ran on the binary of the Open Policy Agent (OPA) release this contract pins, for its platform.
    evaluator_binary: PropertyResult
    # Every scanner verdict comes from a report of the pinned scanner the server that opened the run required, run on
    # the plan the record evaluated.
    scanner_reports: PropertyResult
    # No more than the limit passed between the server receiving the plan-stage record that counts and issuing the apply
    # job's facts: all the server's own times and its limit.
    plan_age: PropertyResult
    # The server received every approval of the apply job at or after plan_stage_record_accepted_at, when it received
    # the plan-stage record that counts, and none before. An approval's time is when the server received it, not when
    # the reviewer gave it.
    apply_job_approval_order: PropertyResult
    # The apply job reported, by its digest, the saved plan file the plan stage evaluated.
    received_plan_file: PropertyResult
    # The plan the apply job reports it rendered from its saved plan file is the evaluated plan.
    rendered_plan: PropertyResult
    # The plan the record names as evaluated is the plan the server pinned.
    pinned_plan: PropertyResult
    # The re-plan the pipeline reports from the apply job acts on the same resources, with the same actions, as the
    # evaluated plan.
    replan_resource_actions: PropertyResult


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
    """What one verifier found about one record: the trust level it assigns the record, the key that signed the run
    statement that level rests on (null when no statement verified), what reading that statement found (null when none
    was given), the digest of the trust data each stage names (null for a stage that loaded its project's own
    assertions), and the properties."""

    api_version: Literal["iltero.com/v1"] = Field(alias="apiVersion")
    kind: Literal["VerificationReport"]
    metadata: ReportMetadata
    record: ReportedRecord
    trust_level: AssignedTrustLevel
    trust_root: StatementTrustRoot | None
    run_statement: RunStatementFindings | None
    stage_trust_data_digests: Annotated[dict[StageValue, Digest | None], Field(max_length=len(Stage))]
    properties: Properties

    @model_validator(mode="after")
    def _results(self) -> VerificationReport:
        results = {name: (result.state, result.reason) for name, result in self.properties}
        if results["integrity"] == INTEGRITY_FAILED:
            if any(result != COULD_NOT_DECIDE for name, result in results.items() if name != "integrity"):
                raise ValueError(
                    "when a record's integrity is not established, every other property is could_not_decide with the "
                    "reason integrity_failed"
                )
        else:
            for name, result in results.items():
                if result not in PROPERTY_RESULTS[name]:
                    raise ValueError(f"{name} is one of the results a verifier gives that property")
        problem = trust_level_problem(self.trust_level, self.trust_root, self.run_statement, results)
        if problem is not None:
            raise ValueError(problem)
        return self
