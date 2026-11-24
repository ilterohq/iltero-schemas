"""How a record's stages hold together, and which of its values a reader can recompute."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.change_types import IAC_CHANGE, IMAGE_BUILD
from iltero_schemas.models.common.assertion import Stage, TargetKind
from iltero_schemas.models.common.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.common.coverage import Coverage, stage_outcome
from iltero_schemas.models.common.fields import Identity
from iltero_schemas.models.common.stages import integrity_problems, scope_counted_from
from iltero_schemas.models.common.subjects import subject_key
from tests.records import (
    DEPLOYED,
    NOT_READ_BY_THE_STAGE,
    PROJECT_CONFIG,
    RECORD,
    THROUGH_PRE_DEPLOY,
    UNKNOWN,
    VERIFIED,
    add_built_in,
    stage_record,
)
from tests.records import set_path as _set
from tests.records import stage as _stage
from tests.server_runs import (
    served,
    served_stage_record,
)

_READER = {SKIP_INTEGRITY_CHECKS: True}


def _moved_event(index: int, stage: str) -> dict[str, Any]:
    event: dict[str, Any] = copy.deepcopy(RECORD["events"][index])
    event["evaluation"]["stage"] = stage
    event["provenance"]["facts_source"] = "none" if stage == "pre_deploy" else None
    if stage == "pre_deploy":
        event["subject"].update(
            kind="change",
            key=subject_key("change", [Identity(scheme="iltero_unit", value="root")]),
            identities=[{"scheme": "iltero_unit", "value": "root"}],
        )
    return event


# A pre-deploy stage that ran no check keeps the marker that it read none of the server's facts.
PRE_DEPLOY = {
    "pre_deploy": _stage("pre_deploy", **{"approvals": NOT_READ_BY_THE_STAGE, "commit_review": NOT_READ_BY_THE_STAGE})
}
# A pre-deploy stage whose checks read an input that carries the server's facts keeps the marker that input held.
CHECKED_PRE_DEPLOY = {"pre_deploy": _stage("pre_deploy")}
POST_VERIFY = {"post_verify": _stage("post_verify")}


@pytest.mark.parametrize(
    ("document", "message"),
    [
        (stage_record(expected_stages=["plan", "plan"]), "named once each, in the order they run"),
        (stage_record(expected_stages=["pre_deploy", "plan"]), "named once each, in the order they run"),
        (stage_record(expected_stages=[]), "starts at its plan stage"),
        (stage_record(expected_stages=["post_deploy"]), "starts at its plan stage"),
        (stage_record(expected_stages=["plan", "runtime"]), "runtime observations belong to no deployment"),
        (
            stage_record(
                out_of_scope=[{"stage": "post_verify", "reason": "project_config", "declared_in": PROJECT_CONFIG}] * 2
            ),
            "a stage is named not in scope once",
        ),
        (
            stage_record(
                out_of_scope=[
                    {"stage": "post_verify", "reason": "project_config", "declared_in": PROJECT_CONFIG},
                    {"stage": "post_deploy", "reason": "not_supported", "declared_in": None},
                ]
            ),
            "a stage is expected or not in scope, never both",
        ),
        (
            stage_record(expected_stages=["plan", "pre_deploy", "post_deploy"], out_of_scope=[]),
            "accounts for every stage of the lifecycle",
        ),
        (
            stage_record(POST_VERIFY, expected_stages=["plan", "post_deploy", "post_verify"]),
            "verifies a deployment only after its post-deploy stage",
        ),
        (
            stage_record(**{"stages.plan.coverage.subjects_in_scope.source_digest": "sha256:" + "c" * 64}),
            "counts the resources of the plan the record names",
        ),
        (
            stage_record(PRE_DEPLOY, expected_stages=["plan", "post_deploy"]),
            "stage 'pre_deploy' is not one this record expects",
        ),
        (
            served_stage_record({"pre_deploy": {**_stage("pre_deploy"), "stage": "plan"}}),
            "the pre_deploy stage record names itself plan",
        ),
        (
            served_stage_record(
                {
                    "pre_deploy": _stage(
                        "pre_deploy", **{"coverage.subjects_in_scope.counted_from": "plan_resource_enumeration"}
                    )
                }
            ),
            "the pre_deploy stage counts its scope as change_unit",
        ),
        (
            stage_record(events=[*RECORD["events"][:-1], _moved_event(-1, "pre_deploy")]),
            "every event belongs to a stage",
        ),
        (
            served_stage_record(CHECKED_PRE_DEPLOY, events=[_moved_event(0, "pre_deploy"), *RECORD["events"][1:]]),
            "grouped by stage, in the order the stages run",
        ),
        (
            served_stage_record(CHECKED_PRE_DEPLOY, events=[*RECORD["events"], _moved_event(-1, "pre_deploy")]),
            "an assertion is evaluated by one stage only",
        ),
        (
            stage_record(
                **{
                    "stages.plan.coverage.subjects_per_assertion": {
                        **RECORD["stages"]["plan"]["coverage"]["subjects_per_assertion"],
                        "ILT.IAC.RESOURCE.AWS.S3.NEVER_RUN@1.0.0": 1,
                    }
                }
            ),
            "counts subjects only for the assertions it was required to evaluate",
        ),
    ],
    ids=[
        "an expected stage twice",
        "expected stages out of order",
        "no expected stage",
        "no plan stage expected",
        "runtime expected",
        "a stage named not in scope twice",
        "a stage both expected and not in scope",
        "a lifecycle stage not accounted for",
        "verified before deployed",
        "another plan's resources",
        "a stage not expected",
        "a stage under another's name",
        "a later stage counting the plan's resources",
        "an event of a stage the record lacks",
        "events out of stage order",
        "one assertion in two stages",
        "subjects of an assertion with no event",
    ],
)
def test_a_record_whose_stages_do_not_hold_together_is_refused(document: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        CAR.model_validate(document)
    with pytest.raises(ValidationError, match=message):
        CAR.model_validate(document, context=_READER)  # the structure holds for every reader


def _with_an_edited_event_reason() -> dict[str, Any]:
    """The record with one event's reason reworded after its stage wrote its events file."""
    document = stage_record()
    document["events"][1]["evaluation"]["policy_reason"] = "assert: true; reworded"
    return document


def _flipped_event() -> dict[str, Any]:
    event: dict[str, Any] = copy.deepcopy(RECORD["events"][1])
    event["evaluation"].update(status="fail", policy_reason="assert: false")
    return event


PASSED = {"value": "met", "reason": None, "computed_from": "status_counts", "stage": None}
WITH_GAPS = {
    "value": "has_gaps",
    "reasons": [{"reason": "required_policy_evaluation_failed", "stage": None, "detail": "1 of 5"}],
}


@pytest.mark.parametrize(
    ("document", "problems"),
    [
        (stage_record(**{"stages.plan.events.count": 4}), ["stages.plan.events"]),
        (
            stage_record(events=[RECORD["events"][0], _flipped_event(), *RECORD["events"][2:]]),
            ["stages.plan.coverage", "stages.plan.coverage"],
        ),
        (stage_record(**{"stages.plan.verdict": PASSED}), ["stages.plan.verdict"]),
        (stage_record(**{"stages.plan.evidence_status": WITH_GAPS}), ["stages.plan.evidence_status"]),
        ({**stage_record(), "coverage": {**RECORD["coverage"], "sampled": True}}, ["coverage"]),
        ({**stage_record(), "verdict": {**RECORD["verdict"], "value": "met", "reason": None}}, ["verdict"]),
        ({**stage_record(), "evidence_status": WITH_GAPS}, ["evidence_status"]),
        (_with_an_edited_event_reason(), ["stages.plan.events.digest"]),
    ],
    ids=[
        "a stage's events counted wrong",
        "an event's status edited",
        "a stage verdict its counts do not give",
        "a stage status its counts do not give",
        "a top-level coverage no stage reported",
        "a top-level verdict no stage reached",
        "a top-level status no stage reported",
        "an event edited after its stage wrote its events file",
    ],
)
def test_an_edited_value_a_reader_can_recompute_is_listed(document: dict[str, Any], problems: list[str]) -> None:
    with pytest.raises(ValidationError, match=problems[0].replace(".", r"\.")):
        CAR.model_validate(document)
    car = CAR.model_validate(document, context=_READER)
    assert [where for where, _ in integrity_problems(car)] == problems


def test_a_record_as_written_has_nothing_to_recompute() -> None:
    assert integrity_problems(CAR.model_validate(RECORD)) == []


NOT_REPORTED = {"__unknown": True, "reason": "not_reported_by_tool"}


def _plan_flags(
    flags: dict[str, Any], gaps: list[dict[str, Any]], stages: dict[str, dict[str, Any]] | None = None, **changes: Any
) -> CAR:
    """The record with the plan's ``flags`` and the plan stage's ``gaps``, its status as they give it, read without
    its derived checks."""
    plan = {f"change.plan.{flag}": value for flag, value in flags.items()}
    coverage = Coverage.model_validate({**RECORD["stages"]["plan"]["coverage"], "gaps": gaps})
    status = stage_outcome(coverage).evidence_status.model_dump(mode="json")
    stage = {"stages.plan.coverage.gaps": gaps, "stages.plan.evidence_status": status}
    document = stage_record(stages, **plan, **changes, **stage)
    return CAR.model_validate(document, context=_READER)


@pytest.mark.parametrize(
    ("flags", "gaps"),
    [
        ({"complete": False}, [{"kind": "plan_incomplete", "value": False}]),
        (
            {"complete": NOT_REPORTED, "applyable": False},
            [{"kind": "plan_incomplete", "value": NOT_REPORTED}, {"kind": "plan_not_applyable", "value": False}],
        ),
        ({"tool_version": NOT_REPORTED}, []),
    ],
    ids=["incomplete", "not reported and not applyable", "tool version not reported"],
)
def test_the_plan_stage_lists_a_gap_for_each_plan_flag_that_is_not_true(
    flags: dict[str, Any], gaps: list[dict[str, Any]]
) -> None:
    assert integrity_problems(_plan_flags(flags, gaps)) == []


@pytest.mark.parametrize(
    ("flags", "gaps"),
    [
        ({"complete": False}, []),
        ({}, [{"kind": "plan_incomplete", "value": False}]),
        ({"applyable": NOT_REPORTED}, [{"kind": "plan_not_applyable", "value": False}]),
        ({"complete": False}, [{"kind": "plan_incomplete", "value": False}] * 2),
        (
            {"complete": False, "applyable": False},
            [{"kind": "plan_not_applyable", "value": False}, {"kind": "plan_incomplete", "value": False}],
        ),
    ],
    ids=["a flag without its gap", "a gap for a true flag", "a gap of another value", "a gap twice", "out of order"],
)
def test_plan_flag_gaps_that_do_not_match_the_plan_flags_are_a_problem(
    flags: dict[str, Any], gaps: list[dict[str, Any]]
) -> None:
    car = _plan_flags(flags, gaps)
    assert integrity_problems(car) == [
        (
            "stages.plan.coverage.gaps",
            "does not match change.plan.complete and change.plan.applyable: one gap, in kind order, for each that is "
            "not true, with its value",
        )
    ]
    with pytest.raises(ValidationError, match="does not match change.plan.complete and change.plan.applyable"):
        CAR.model_validate(car.model_dump(mode="json", by_alias=True))


def test_only_the_plan_stage_lists_a_plan_flag_gap() -> None:
    gap = [{"kind": "plan_incomplete", "value": False}]
    later = {
        "pre_deploy": _stage(
            "pre_deploy",
            **{"coverage.gaps": gap, "approvals": NOT_READ_BY_THE_STAGE, "commit_review": NOT_READ_BY_THE_STAGE},
        )
    }
    expected = ["plan", "pre_deploy", "post_deploy"]
    changes = {"change.plan.complete": False, "stages.plan.coverage.gaps": gap}
    document = served(stage_record(later, expected_stages=expected, all_expected_stages_reported=False, **changes))
    with pytest.raises(ValidationError, match="the pre_deploy stage lists a plan-flag gap"):
        CAR.model_validate(document, context=_READER)


@pytest.mark.parametrize(
    ("field", "value"),
    [("id", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), ("unit", "network")],
    ids=["another run", "another unit"],
)
def test_every_event_names_the_records_run(field: str, value: str) -> None:
    document = stage_record()
    _set(document, f"events.0.provenance.run.{field}", value)
    if field == "unit":
        # The event moves to the other unit whole, so only the record can tell it is not its own.
        subject = document["events"][0]["subject"]
        subject["identities"][0]["scope"] = {"unit": value}
        subject["key"] = subject_key(subject["kind"], [Identity.model_validate(subject["identities"][0])])
    with pytest.raises(ValidationError, match="every event names the record's run"):
        CAR.model_validate(document, context=_READER)


def test_a_pre_deploy_stage_counts_the_change_the_record_names() -> None:
    with_stage = served(
        stage_record(
            PRE_DEPLOY, expected_stages=["plan", "pre_deploy", "post_deploy"], all_expected_stages_reported=False
        )
    )
    CAR.model_validate(with_stage)
    with_stage["stages"]["pre_deploy"]["coverage"]["subjects_in_scope"]["source_digest"] = "sha256:" + "e" * 64
    with pytest.raises(ValidationError, match="source_digest is not change.digest"):
        CAR.model_validate(with_stage)
    where = "stages.pre_deploy.coverage.subjects_in_scope.source_digest"
    assert integrity_problems(CAR.model_validate(with_stage, context=_READER)) == [(where, "is not change.digest")]


def test_a_stage_after_the_deployment_is_always_enforcing() -> None:
    document = add_built_in(
        stage_record({"post_deploy": _stage("post_deploy", enforcement_mode="advisory")}), "post_deploy"
    )
    with pytest.raises(ValidationError, match="comes after the deployment, so its gate is enforcing"):
        CAR.model_validate(document, context=_READER)


@pytest.mark.parametrize(
    ("stage", "kinds", "basis"),
    [
        (Stage.PLAN, set(), "plan_resource_enumeration"),
        (Stage.PLAN, {TargetKind.RESOURCE}, "plan_resource_enumeration"),
        (Stage.PRE_DEPLOY, set(), "change_unit"),
        (Stage.POST_DEPLOY, {TargetKind.DEPLOYMENT}, "deployment_unit"),
        (Stage.POST_VERIFY, {TargetKind.DEPLOYMENT}, "deployment_unit"),
        (Stage.POST_VERIFY, set(), "deployment_unit"),
    ],
)
def test_a_stage_counts_by_the_kind_of_subject_its_checks_are_about(
    stage: Stage, kinds: set[TargetKind], basis: str | None
) -> None:
    assert scope_counted_from(IAC_CHANGE, stage, kinds) == basis


@pytest.mark.parametrize("kinds", [set(), {TargetKind.ARTIFACT}])
def test_a_builds_plan_stage_counts_the_artifact_it_built(kinds: set[TargetKind]) -> None:
    assert scope_counted_from(IMAGE_BUILD, Stage.PLAN, kinds) == "artifact_unit"


def test_a_builds_plan_stage_counts_no_resources() -> None:
    with pytest.raises(ValueError, match="subjects its assertions can target"):
        scope_counted_from(IMAGE_BUILD, Stage.PLAN, {TargetKind.RESOURCE})


def test_post_verify_counts_its_deployment_beside_the_resources_of_the_checks_it_settles() -> None:
    """A check the plan stage postponed is about a resource; post-verify still counts its one deployment."""
    assert scope_counted_from(IAC_CHANGE, Stage.POST_VERIFY, {TargetKind.DEPLOYMENT, TargetKind.RESOURCE}) == (
        "deployment_unit"
    )


@pytest.mark.parametrize(
    ("stage", "kinds", "message"),
    [
        (Stage.PRE_DEPLOY, {TargetKind.CHANGE, TargetKind.RESOURCE}, "about one kind of subject"),
        (Stage.PRE_DEPLOY, {TargetKind.RESOURCE}, "subjects its assertions can target"),
        (Stage.POST_VERIFY, {TargetKind.ASSURANCE}, "subjects its assertions can target"),
    ],
)
def test_a_stages_checks_are_about_one_kind_of_subject_it_can_target(
    stage: Stage, kinds: set[TargetKind], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        scope_counted_from(IAC_CHANGE, stage, kinds)


def _approval(subject: dict[str, str], approval_id: str = "apr_0001") -> dict[str, Any]:
    return {
        "id": approval_id,
        "actor": {"provider": "iltero", "id": "reviewer_1"},
        "roles": ["security"],
        "status": "approved",
        "subject": subject,
        "method": "iltero_review",
        "independence": "independent",
        "policy_version": None,
        "timestamp": "2026-09-22T13:05:30.000Z",
        "bound_to": None,
    }


def _pre_deploy_reading(*approvals: dict[str, Any]) -> dict[str, Any]:
    """The record of a run the server opened, with a pre-deploy stage whose checks read ``approvals`` from it."""
    document = served(THROUGH_PRE_DEPLOY)
    document["stages"]["pre_deploy"]["approvals"] = list(approvals)
    return document


def test_a_stage_lists_the_approvals_its_checks_read_of_its_change_or_run() -> None:
    of_change = _approval({"kind": "change", "digest": THROUGH_PRE_DEPLOY["change"]["digest"]})
    of_run = _approval({"kind": "run", "id": THROUGH_PRE_DEPLOY["run"]["id"]}, "apr_0002")
    CAR.model_validate(_pre_deploy_reading(of_change, of_run), context=_READER)


@pytest.mark.parametrize("listed", [False, True], ids=["no_approval", "one_approval"])
def test_a_stage_whose_results_read_no_facts_from_the_server_keeps_the_unknown_marker_for_its_approvals(
    listed: bool,
) -> None:
    of_change = _approval({"kind": "change", "digest": THROUGH_PRE_DEPLOY["change"]["digest"]})
    document = served(THROUGH_PRE_DEPLOY)
    for event in document["events"]:
        if event["evaluation"]["stage"] == "pre_deploy":
            event["provenance"]["facts_source"] = "none"
    document["stages"]["pre_deploy"]["approvals"] = [of_change] if listed else []
    with pytest.raises(ValidationError, match="the pre_deploy stage keeps the unknown marker for its approvals when"):
        CAR.model_validate(document, context=_READER)


def test_a_stage_whose_results_read_facts_from_the_server_may_keep_the_unknown_marker_for_its_approvals() -> None:
    document = served(THROUGH_PRE_DEPLOY)
    assert document["stages"]["pre_deploy"]["approvals"] == UNKNOWN
    car = CAR.model_validate(document, context=_READER)
    assert car.stages[Stage.PRE_DEPLOY].listed_approvals == []
    assert integrity_problems(car) == []


@pytest.mark.parametrize(
    ("approvals", "message"),
    [
        (
            [_approval({"kind": "run", "id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"})],
            "only approvals of a change or of",
        ),
        ([_approval({"kind": "run", "id": THROUGH_PRE_DEPLOY["run"]["id"]})] * 2, "lists each approval once"),
    ],
    ids=["another run", "listed twice"],
)
def test_a_stage_lists_no_approval_of_another_run_and_each_once(approvals: list[dict[str, Any]], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        CAR.model_validate(_pre_deploy_reading(*approvals), context=_READER)


def test_an_approval_of_another_change_is_an_integrity_problem() -> None:
    document = _pre_deploy_reading(_approval({"kind": "change", "digest": "sha256:" + "e" * 64}))
    what = "lists approval apr_0001 of another change: another change type, unit, environment or checked content"
    with pytest.raises(ValidationError, match=f"stages.pre_deploy.approvals {what}"):
        CAR.model_validate(document)
    car = CAR.model_validate(document, context=_READER)
    assert integrity_problems(car) == [("stages.pre_deploy.approvals", what)]


def test_a_forged_change_digest_is_reported_with_every_digest_bound_to_the_change() -> None:
    document = _pre_deploy_reading(_approval({"kind": "change", "digest": THROUGH_PRE_DEPLOY["change"]["digest"]}))
    document["change"]["digest"] = "sha256:" + "e" * 64
    with pytest.raises(
        ValidationError, match="change.digest is not the digest of the change type, unit, environment and plan"
    ):
        CAR.model_validate(document)
    assert [where for where, _ in integrity_problems(CAR.model_validate(document, context=_READER))] == [
        "change.digest",
        "stages.pre_deploy.coverage.subjects_in_scope.source_digest",
        "stages.pre_deploy.approvals",
    ]


def test_only_a_stage_whose_input_carries_approvals_keeps_them_or_the_unknown_marker() -> None:
    with pytest.raises(ValidationError, match="the plan stage keeps approvals, or the unknown marker, exactly where"):
        CAR.model_validate(stage_record(**{"stages.plan.approvals": []}), context=_READER)
    document = _pre_deploy_reading()
    document["stages"]["pre_deploy"]["approvals"] = None
    with pytest.raises(
        ValidationError, match="the pre_deploy stage keeps approvals, or the unknown marker, exactly where"
    ):
        CAR.model_validate(document, context=_READER)


ONE_POLICY = (
    "every stage and every redacted evidence file name the redaction policy the record writes out, by its digest"
)
OTHER_POLICY_DIGEST = "sha256:" + "f" * 64


def test_a_record_redacts_under_one_policy_in_every_stage() -> None:
    document = served(
        stage_record(
            PRE_DEPLOY, expected_stages=["plan", "pre_deploy", "post_deploy"], all_expected_stages_reported=False
        )
    )
    CAR.model_validate(document)
    document["stages"]["pre_deploy"]["redaction"]["policy"]["digest"] = OTHER_POLICY_DIGEST
    with pytest.raises(ValidationError, match=ONE_POLICY):
        CAR.model_validate(document)
    with pytest.raises(ValidationError, match=ONE_POLICY):
        CAR.model_validate(document, context=_READER)


def test_a_redacted_evidence_file_names_the_records_policy() -> None:
    document = stage_record()
    redacted = next(ref for ref in document["evidence_refs"] if ref["redaction_policy"] is not None)
    redacted["redaction_policy"]["digest"] = OTHER_POLICY_DIGEST
    with pytest.raises(ValidationError, match=ONE_POLICY):
        CAR.model_validate(document)


def test_a_file_no_redaction_touched_names_no_policy() -> None:
    document = stage_record()
    redacted = document["stages"]["plan"]["redaction"]["input"]["digest"]
    for ref in document["evidence_refs"]:
        if ref["digest"] != redacted:
            ref["redaction_policy"] = None
            # A file kept with nothing redacted is kept as the pipeline gave it, so named by its own digest.
            if ref["source"] is not None:
                ref["source"]["digest"] = ref["digest"]
    CAR.model_validate(document)


@pytest.mark.parametrize("name", ["post_deploy", "post_verify"])
def test_an_infrastructure_stage_after_the_deployment_evaluates_its_always_evaluated_check(name: str) -> None:
    stages = {"post_deploy": _stage("post_deploy"), "post_verify": _stage("post_verify")}
    document = stage_record(stages)
    if name == "post_verify":
        add_built_in(document, "post_deploy")
    with pytest.raises(ValidationError, match="is evaluated once, at the .* stage, once it has reported"):
        CAR.model_validate(document, context=_READER)


@pytest.mark.parametrize(
    ("source", "name", "kind"),
    [
        (RECORD, "plan", "facts"),
        (THROUGH_PRE_DEPLOY, "pre_deploy", "observation"),
        (DEPLOYED, "post_deploy", "facts"),
        (VERIFIED, "post_verify", "observation"),
    ],
    ids=["plan", "pre_deploy", "post_deploy", "post_verify"],
)
def test_a_stage_redacts_what_it_reads(source: dict[str, Any], name: str, kind: str) -> None:
    document = copy.deepcopy(source)
    document["stages"][name]["redaction"]["input"]["kind"] = kind
    with pytest.raises(ValidationError, match=f"the {name} stage's redaction report is of the"):
        CAR.model_validate(document, context=_READER)
