"""How a record's stages hold together, and which of its values a reader can recompute."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.change_types import IAC_CHANGE
from iltero_schemas.models.assertion import Stage, TargetKind
from iltero_schemas.models.car import CAR, SKIP_INTEGRITY_CHECKS, OutOfScope
from iltero_schemas.models.coverage import Coverage, StageOutcome, combine_in_order, stage_outcome
from iltero_schemas.models.fields import Identity
from iltero_schemas.models.stages import integrity_problems, scope_counted_from
from iltero_schemas.models.subjects import subject_key
from tests.records import RECORD
from tests.records import set_path as _set
from tests.records import stage as _stage

_READER = {SKIP_INTEGRITY_CHECKS: True}
CONFIG = {"path": ".iltero/config.yml", "digest": "sha256:" + "d" * 64}


def _with_top_level(document: dict[str, Any]) -> dict[str, Any]:
    """The record's top level set to its stages combined, where they combine, so only the rule under test fails."""
    outcomes = {
        name: StageOutcome.model_validate({key: stage[key] for key in ("coverage", "verdict", "assurance_status")})
        for name, stage in document["stages"].items()
    }
    try:
        combined = combine_in_order(document["expected_stages"], outcomes)
    except ValueError:
        return document  # stages that cannot be combined: the structure is what is under test
    return {**document, **combined.model_dump(mode="json")}


def _record(stages: dict[str, dict[str, Any]] | None = None, /, **changes: Any) -> dict[str, Any]:
    """The run's record with ``changes``; a change of expected stages leaves the rest of the lifecycle out of scope."""
    document = copy.deepcopy(RECORD)
    document["stages"].update(copy.deepcopy(stages or {}))
    for dotted, value in changes.items():
        _set(document, dotted, value)
    if "expected_stages" in changes and "out_of_scope" not in changes:
        expected = set(changes["expected_stages"])
        document["out_of_scope"] = [
            {"stage": stage.value, "reason": "project_config", "declared_in": CONFIG}
            for stage in IAC_CHANGE.stages
            if stage.value not in expected
        ]
    return _with_top_level(document)


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


PRE_DEPLOY = {"pre_deploy": _stage("pre_deploy")}
POST_VERIFY = {"post_verify": _stage("post_verify")}


@pytest.mark.parametrize(
    ("document", "message"),
    [
        (_record(expected_stages=["plan", "plan"]), "named once each, in the order they run"),
        (_record(expected_stages=["pre_deploy", "plan"]), "named once each, in the order they run"),
        (_record(expected_stages=[]), "starts at its plan stage"),
        (_record(expected_stages=["post_deploy"]), "starts at its plan stage"),
        (_record(expected_stages=["plan", "runtime"]), "runtime observations belong to no deployment"),
        (
            _record(out_of_scope=[{"stage": "post_verify", "reason": "project_config", "declared_in": CONFIG}] * 2),
            "a stage is named not in scope once",
        ),
        (
            _record(
                out_of_scope=[
                    {"stage": "post_verify", "reason": "project_config", "declared_in": CONFIG},
                    {"stage": "post_deploy", "reason": "not_supported", "declared_in": None},
                ]
            ),
            "a stage is expected or not in scope, never both",
        ),
        (
            _record(expected_stages=["plan", "pre_deploy", "post_deploy"], out_of_scope=[]),
            "accounts for every stage of the lifecycle",
        ),
        (
            _record(POST_VERIFY, expected_stages=["plan", "post_deploy", "post_verify"]),
            "verifies a deployment only after its post-deploy stage",
        ),
        (
            _record(**{"stages.plan.coverage.subjects_in_scope.source_digest": "sha256:" + "c" * 64}),
            "counts the resources of the plan the record names",
        ),
        (
            _record(PRE_DEPLOY, expected_stages=["plan", "post_deploy"]),
            "stage 'pre_deploy' is not one this record expects",
        ),
        (
            _record({"pre_deploy": {**_stage("pre_deploy"), "stage": "plan"}}),
            "the pre_deploy stage record names itself plan",
        ),
        (
            _record(
                {
                    "pre_deploy": _stage(
                        "pre_deploy", **{"coverage.subjects_in_scope.counted_from": "plan_resource_enumeration"}
                    )
                }
            ),
            "the pre_deploy stage counts its scope as change_unit",
        ),
        (_record(events=[*RECORD["events"][:-1], _moved_event(-1, "pre_deploy")]), "every event belongs to a stage"),
        (
            _record(PRE_DEPLOY, events=[_moved_event(0, "pre_deploy"), *RECORD["events"][1:]]),
            "grouped by stage, in the order the stages run",
        ),
        (
            _record(PRE_DEPLOY, events=[*RECORD["events"], _moved_event(-1, "pre_deploy")]),
            "an assertion is evaluated by one stage only",
        ),
        (
            _record(
                **{
                    "stages.plan.coverage.subjects_per_assertion": {
                        **RECORD["stages"]["plan"]["coverage"]["subjects_per_assertion"],
                        "ILT.AWS.S3.NEVER_RUN@1.0.0": 1,
                    }
                }
            ),
            "counts subjects only for assertions it has events for",
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


def _flipped_event() -> dict[str, Any]:
    event: dict[str, Any] = copy.deepcopy(RECORD["events"][1])
    event["evaluation"].update(status="fail", policy_reason="assert: false")
    return event


PASSED = {"value": "pass", "exit_code": 0, "computed_from": "status_counts", "stage": None}
INCOMPLETE = {"value": "incomplete", "reason": "evaluator_error", "detail": "1 of 5"}


@pytest.mark.parametrize(
    ("document", "problems"),
    [
        (_record(**{"stages.plan.events.count": 4}), ["stages.plan.coverage"]),
        (_record(events=[RECORD["events"][0], _flipped_event(), *RECORD["events"][2:]]), ["stages.plan.coverage"]),
        (_record(**{"stages.plan.verdict": PASSED}), ["stages.plan.verdict"]),
        (_record(**{"stages.plan.assurance_status": INCOMPLETE}), ["stages.plan.assurance_status"]),
        ({**_record(), "coverage": {**RECORD["coverage"], "sampled": True}}, ["coverage"]),
        ({**_record(), "verdict": {**RECORD["verdict"], "value": "fail", "exit_code": 1}}, ["verdict"]),
        ({**_record(), "assurance_status": INCOMPLETE}, ["assurance_status"]),
    ],
    ids=[
        "a stage's events counted wrong",
        "an event's status edited",
        "a stage verdict its counts do not give",
        "a stage status its counts do not give",
        "a top-level coverage no stage reported",
        "a top-level verdict no stage reached",
        "a top-level status no stage reported",
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
    status = stage_outcome(coverage).assurance_status.model_dump(mode="json")
    stage = {"stages.plan.coverage.gaps": gaps, "stages.plan.assurance_status": status}
    document = _record(stages, **plan, **changes, **stage)
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
    later = {"pre_deploy": _stage("pre_deploy", **{"coverage.gaps": gap})}
    expected = ["plan", "pre_deploy", "post_deploy"]
    changes = {"change.plan.complete": False, "stages.plan.coverage.gaps": gap}
    document = _record(later, expected_stages=expected, complete=False, **changes)
    with pytest.raises(ValidationError, match="the pre_deploy stage lists a plan-flag gap"):
        CAR.model_validate(document, context=_READER)


def _coverage(
    counts: dict[str, int], *, expected: int = 5, evaluated: int = 5, subjects: int = 2, truncated: bool = False
) -> Coverage:
    document = copy.deepcopy(RECORD["stages"]["plan"]["coverage"])
    full = dict.fromkeys(document["status_counts"], 0) | counts
    document.update(status_counts=full, evaluations=sum(full.values()), assertions_evaluated=evaluated)
    document["assertions_expected"]["value"] = expected
    document["subjects_evaluated"] = subjects
    document["truncated"] = {"value": truncated, "limit": 1 if truncated else None, "reason": None}
    return Coverage.model_validate(document)


@pytest.mark.parametrize(
    ("coverage", "code", "value"),
    [
        (_coverage({"pass": 5}), 0, "pass"),
        (_coverage({"pass": 4, "not_applicable": 1}), 0, "pass"),
        (_coverage({"pass": 4, "fail": 1}), 1, "fail"),
        (_coverage({"pass": 3, "fail": 1, "unknown": 1}), 3, "indeterminate"),
        (_coverage({"pass": 3, "unknown": 1, "error": 1}), 4, "fail"),
        (_coverage({"pass": 4, "not_evaluated": 1}), 6, "fail"),
        (_coverage({"pass": 5}, evaluated=4), 6, "fail"),
        (_coverage({}, expected=0, evaluated=0, subjects=0), 6, "fail"),
        (_coverage({"not_applicable": 5}, evaluated=0, subjects=0), 6, "fail"),
        (_coverage({"pass": 5}, truncated=True), 6, "fail"),
        (_coverage({"fail": 1, "unknown": 1, "error": 1, "not_evaluated": 1}), 6, "fail"),
    ],
    ids=[
        "all pass",
        "pass and not applicable",
        "a failure",
        "an undecided check outranks a failure",
        "an error outranks an undecided check",
        "a check not evaluated",
        "an assertion not evaluated",
        "nothing expected",
        "no subject evaluated",
        "truncated",
        "a gap outranks everything",
    ],
)
def test_a_stage_verdict_is_the_code_its_counts_give(coverage: Coverage, code: int, value: str) -> None:
    verdict = stage_outcome(coverage).verdict
    assert (verdict.value, verdict.exit_code, verdict.computed_from, verdict.stage) == (
        value,
        code,
        "status_counts",
        None,
    )


def test_an_error_marks_a_stage_incomplete_and_a_clean_run_complete() -> None:
    status = stage_outcome(_coverage({"pass": 3, "error": 2})).assurance_status
    assert (status.value, status.reason, status.detail) == (
        "incomplete",
        "required_policy_evaluation_failed",
        "2 of 5 evaluations ended in an evaluator error",
    )
    assert stage_outcome(_coverage({"fail": 5})).assurance_status.value == "complete"


@pytest.mark.parametrize("path", ["C:/outside/config.yml", "D:config.yml", "../config.yml"])
def test_the_file_that_leaves_a_stage_out_is_inside_the_project(path: str) -> None:
    config = {"path": path, "digest": "sha256:" + "d" * 64}
    scoped = _record(
        expected_stages=["plan", "post_deploy"],
        out_of_scope=[
            {"stage": "pre_deploy", "reason": "project_config", "declared_in": config},
            {"stage": "post_verify", "reason": "project_config", "declared_in": CONFIG},
        ],
    )
    with pytest.raises(ValidationError, match="relative path inside the project"):
        CAR.model_validate(scoped, context=_READER)


def test_a_record_that_leaves_the_approval_gate_out_names_the_file_that_says_so() -> None:
    """A project that has no approval step says so in its configuration, and the record names that file."""
    config = {"path": ".iltero/config.yml", "digest": "sha256:" + "d" * 64}
    scoped = _record(
        expected_stages=["plan", "post_deploy"],
        out_of_scope=[
            {"stage": "pre_deploy", "reason": "project_config", "declared_in": config},
            {"stage": "post_verify", "reason": "project_config", "declared_in": CONFIG},
        ],
    )
    car = CAR.model_validate(scoped, context=_READER)
    (left_out, _) = car.out_of_scope
    assert left_out.declared_in is not None and left_out.declared_in.path == ".iltero/config.yml"


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        ({"stage": "pre_deploy", "reason": "project_config", "declared_in": None}, "names the file that says so"),
        ({"stage": "pre_deploy", "reason": "not_supported", "declared_in": CONFIG}, "names the file that says so"),
        (
            {"stage": "post_verify", "reason": "environment_policy", "declared_in": CONFIG},
            "names the file that says so",
        ),
    ],
    ids=["a project choice naming no file", "a file named for no choice", "a file named for a policy"],
)
def test_a_stage_left_out_says_why_in_a_way_that_holds(entry: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        OutOfScope.model_validate(entry)


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        (
            {"stage": "post_deploy", "reason": "project_config", "declared_in": CONFIG},
            "a project can leave out only the pre-deploy and post-verify stages",
        ),
        (
            {"stage": "pre_deploy", "reason": "environment_policy", "declared_in": None},
            "an environment's policy can leave out only the post-verify stage",
        ),
        (
            {"stage": "pre_deploy", "reason": "not_supported", "declared_in": None},
            "the pre-deploy stage is supported for terraform",
        ),
    ],
    ids=["a project leaving out post-deploy", "a policy leaving out pre-deploy", "a tool that runs pre-deploy"],
)
def test_a_stage_is_left_out_only_for_a_reason_its_activity_allows(entry: dict[str, Any], message: str) -> None:
    expected = [stage.value for stage in IAC_CHANGE.stages if stage.value != entry["stage"]]
    scoped = _record(
        expected_stages=expected,
        out_of_scope=[entry],
    )
    with pytest.raises(ValidationError, match=message):
        CAR.model_validate(scoped, context=_READER)


POLICY_LEAVES_OUT_POST_VERIFY = {
    "expected_stages": ["plan", "pre_deploy", "post_deploy"],
    "out_of_scope": [{"stage": "post_verify", "reason": "environment_policy", "declared_in": None}],
}


def test_the_environment_policy_of_a_run_the_server_opened_can_leave_out_post_verify() -> None:
    scoped = _record(
        **POLICY_LEAVES_OUT_POST_VERIFY, **{"governance.run_opened_by": "server", "run.origin": "server_issued"}
    )
    for event in scoped["events"]:
        event["provenance"]["run"]["origin"] = "server_issued"
    for coverage in (scoped["coverage"], scoped["stages"]["plan"]["coverage"]):
        coverage["assertions_expected"]["origin"] = "server_pinned"
    (left_out,) = CAR.model_validate(scoped, context=_READER).out_of_scope
    assert left_out.reason == "environment_policy"


def test_a_local_run_has_no_environment_policy_to_leave_a_stage_out() -> None:
    with pytest.raises(ValidationError, match="only a run the server opened has an environment policy"):
        CAR.model_validate(_record(**POLICY_LEAVES_OUT_POST_VERIFY), context=_READER)


def test_a_terraform_record_cannot_call_its_post_verify_stage_unsupported() -> None:
    unsupported = [{"stage": "post_verify", "reason": "not_supported", "declared_in": None}]
    scoped = _record(expected_stages=["plan", "pre_deploy", "post_deploy"], out_of_scope=unsupported)
    with pytest.raises(ValidationError, match="the post-verify stage is supported for terraform"):
        CAR.model_validate(scoped, context=_READER)


def test_a_project_can_leave_out_the_post_verify_stage() -> None:
    left_out = [{"stage": "post_verify", "reason": "project_config", "declared_in": CONFIG}]
    scoped = _record(expected_stages=["plan", "pre_deploy", "post_deploy"], out_of_scope=left_out)
    (entry,) = CAR.model_validate(scoped, context=_READER).out_of_scope
    assert entry.reason == "project_config"


def test_a_record_always_expects_its_post_deploy_stage() -> None:
    with pytest.raises(ValidationError, match="a project can leave out only the pre-deploy and post-verify stages"):
        CAR.model_validate(_record(expected_stages=["plan"]), context=_READER)


@pytest.mark.parametrize(
    ("reason", "declared_in", "message"),
    [
        ("project_config", CONFIG, "a project can leave out only the pre-deploy and post-verify stages"),
        ("environment_policy", None, "an environment's policy can leave out only the post-verify stage"),
        ("not_supported", None, "the post-deploy stage is supported for terraform"),
    ],
    ids=["by the project", "by an environment's policy", "as not supported"],
)
def test_no_reason_leaves_out_the_post_deploy_stage(reason: str, declared_in: Any, message: str) -> None:
    left_out = [{"stage": "post_deploy", "reason": reason, "declared_in": declared_in}]
    scoped = _record(expected_stages=["plan", "pre_deploy", "post_verify"], out_of_scope=left_out)
    with pytest.raises(ValidationError, match=message):
        CAR.model_validate(scoped, context=_READER)


@pytest.mark.parametrize(
    ("field", "value"),
    [("id", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), ("origin", "server_issued"), ("unit", "network")],
    ids=["another run", "another way of opening it", "another unit"],
)
def test_every_event_names_the_records_run(field: str, value: str) -> None:
    document = _record()
    _set(document, f"events.0.provenance.run.{field}", value)
    if field == "unit":
        # The event moves to the other unit whole, so only the record can tell it is not its own.
        subject = document["events"][0]["subject"]
        subject["identities"][0]["scope"] = {"unit": value}
        subject["key"] = subject_key(subject["kind"], [Identity.model_validate(subject["identities"][0])])
    with pytest.raises(ValidationError, match="every event names the record's run"):
        CAR.model_validate(document, context=_READER)


def test_an_offline_record_has_no_facts_from_the_server() -> None:
    pre_deploy = _stage("pre_deploy")
    event = _moved_event(-1, "pre_deploy")
    moved = f"{event['assertion']['id']}@{event['assertion']['version']}"
    plan = copy.deepcopy(RECORD["stages"]["plan"])
    del plan["coverage"]["subjects_per_assertion"][moved]
    document = _record(
        {"plan": plan, "pre_deploy": pre_deploy},
        expected_stages=["plan", "pre_deploy", "post_deploy"],
        complete=False,
        events=[*RECORD["events"][:-1], event],
    )
    CAR.model_validate(document, context=_READER)
    document["events"][-1]["provenance"]["facts_source"] = "server"
    with pytest.raises(ValidationError, match="has no facts from the server"):
        CAR.model_validate(document, context=_READER)


def test_a_pre_deploy_stage_counts_the_change_the_record_names() -> None:
    with_stage = _record(PRE_DEPLOY, expected_stages=["plan", "pre_deploy", "post_deploy"], complete=False)
    CAR.model_validate(with_stage)
    with_stage["stages"]["pre_deploy"]["coverage"]["subjects_in_scope"]["source_digest"] = "sha256:" + "e" * 64
    with pytest.raises(ValidationError, match="source_digest is not change.digest"):
        CAR.model_validate(with_stage)
    where = "stages.pre_deploy.coverage.subjects_in_scope.source_digest"
    assert integrity_problems(CAR.model_validate(with_stage, context=_READER)) == [(where, "is not change.digest")]


def test_a_stage_after_the_deployment_is_always_enforcing() -> None:
    document = _record({"post_deploy": _stage("post_deploy", enforcement_mode="advisory")})
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
        (Stage.POST_VERIFY, {TargetKind.RESOURCE}, None),
        (Stage.POST_VERIFY, set(), None),
    ],
)
def test_a_stage_counts_by_the_kind_of_subject_its_checks_are_about(
    stage: Stage, kinds: set[TargetKind], basis: str | None
) -> None:
    assert scope_counted_from(stage, kinds) == basis


@pytest.mark.parametrize(
    ("stage", "kinds", "message"),
    [
        (Stage.POST_VERIFY, {TargetKind.DEPLOYMENT, TargetKind.RESOURCE}, "about one kind of subject"),
        (Stage.PRE_DEPLOY, {TargetKind.RESOURCE}, "subjects its assertions can target"),
    ],
)
def test_a_stages_checks_are_about_one_kind_of_subject_it_can_target(
    stage: Stage, kinds: set[TargetKind], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        scope_counted_from(stage, kinds)


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
    }


def _pre_deploy_reading(*approvals: dict[str, Any]) -> dict[str, Any]:
    """The record with a pre-deploy stage whose checks read ``approvals``."""
    document = _record(PRE_DEPLOY, expected_stages=["plan", "pre_deploy", "post_deploy"], complete=False)
    document["stages"]["pre_deploy"]["approvals"] = list(approvals)
    return document


def test_a_stage_lists_the_approvals_its_checks_read_of_its_change_or_run() -> None:
    of_change = _approval({"kind": "change", "digest": RECORD["change"]["digest"]})
    of_run = _approval({"kind": "run", "id": RECORD["run"]["id"]}, "apr_0002")
    CAR.model_validate(_pre_deploy_reading(of_change, of_run), context=_READER)


@pytest.mark.parametrize(
    ("approvals", "message"),
    [
        (
            [_approval({"kind": "run", "id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"})],
            "only approvals of a change or of",
        ),
        ([_approval({"kind": "run", "id": RECORD["run"]["id"]})] * 2, "lists each approval once"),
    ],
    ids=["another run", "listed twice"],
)
def test_a_stage_lists_no_approval_of_another_run_and_each_once(approvals: list[dict[str, Any]], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        CAR.model_validate(_pre_deploy_reading(*approvals), context=_READER)


def test_an_approval_of_another_change_is_an_integrity_problem() -> None:
    document = _pre_deploy_reading(_approval({"kind": "change", "digest": "sha256:" + "e" * 64}))
    what = "lists approval apr_0001 of another change: another change type, unit, environment or plan"
    with pytest.raises(ValidationError, match=f"stages.pre_deploy.approvals {what}"):
        CAR.model_validate(document)
    car = CAR.model_validate(document, context=_READER)
    assert integrity_problems(car) == [("stages.pre_deploy.approvals", what)]


def test_a_forged_change_digest_is_reported_with_every_digest_bound_to_the_change() -> None:
    document = _pre_deploy_reading(_approval({"kind": "change", "digest": RECORD["change"]["digest"]}))
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


def test_only_a_stage_whose_input_carries_approvals_lists_them() -> None:
    with pytest.raises(ValidationError, match="the plan stage lists approvals exactly when"):
        CAR.model_validate(_record(**{"stages.plan.approvals": []}), context=_READER)
    document = _pre_deploy_reading()
    document["stages"]["pre_deploy"]["approvals"] = None
    with pytest.raises(ValidationError, match="the pre_deploy stage lists approvals exactly when"):
        CAR.model_validate(document, context=_READER)


ONE_POLICY = "every stage and every redacted evidence file name the same redaction policy"
OTHER_POLICY_DIGEST = "sha256:" + "f" * 64


def test_a_record_redacts_under_one_policy_in_every_stage() -> None:
    document = _record(PRE_DEPLOY, expected_stages=["plan", "pre_deploy", "post_deploy"], complete=False)
    CAR.model_validate(document)
    document["stages"]["pre_deploy"]["redaction"]["policy"]["digest"] = OTHER_POLICY_DIGEST
    with pytest.raises(ValidationError, match=ONE_POLICY):
        CAR.model_validate(document)
    with pytest.raises(ValidationError, match=ONE_POLICY):
        CAR.model_validate(document, context=_READER)


def test_a_redacted_evidence_file_names_the_records_policy() -> None:
    document = _record()
    redacted = next(ref for ref in document["evidence_refs"] if ref["redaction_policy"] is not None)
    redacted["redaction_policy"]["digest"] = OTHER_POLICY_DIGEST
    with pytest.raises(ValidationError, match=ONE_POLICY):
        CAR.model_validate(document)


def test_a_file_no_redaction_touched_names_no_policy() -> None:
    document = _record()
    for ref in document["evidence_refs"]:
        ref["redaction_policy"] = None
    CAR.model_validate(document)
