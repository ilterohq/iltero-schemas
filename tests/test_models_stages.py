"""How a record's stages hold together, and which of its values a reader can recompute."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.canonical import change_digest
from iltero_schemas.models.car import CAR, DERIVED_CHECKED_BY_READER, OutOfScope
from iltero_schemas.models.coverage import Coverage, StageOutcome, combine_in_order, stage_outcome
from iltero_schemas.models.stages import LIFECYCLE, derived_problems
from tests.records import RECORD
from tests.records import set_path as _set
from tests.records import stage as _stage

_READER = {DERIVED_CHECKED_BY_READER: True}
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
    document["stages"].update(stages or {})
    for dotted, value in changes.items():
        _set(document, dotted, value)
    if "expected_stages" in changes and "not_in_scope" not in changes:
        expected = set(changes["expected_stages"])
        document["not_in_scope"] = [
            {"stage": stage.value, "basis": "not_supported", "declared_in": None}
            for stage in LIFECYCLE
            if stage.value not in expected
        ]
    return _with_top_level(document)


def _moved_event(index: int, stage: str) -> dict[str, Any]:
    event: dict[str, Any] = copy.deepcopy(RECORD["events"][index])
    event["evaluation"]["stage"] = stage
    event["provenance"]["facts_source"] = "none" if stage == "pre_deploy" else None
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
            _record(not_in_scope=[{"stage": "post_verify", "basis": "not_supported", "declared_in": None}] * 2),
            "a stage is named not in scope once",
        ),
        (
            _record(
                not_in_scope=[
                    {"stage": "post_verify", "basis": "not_supported", "declared_in": None},
                    {"stage": "post_deploy", "basis": "not_supported", "declared_in": None},
                ]
            ),
            "a stage is expected or not in scope, never both",
        ),
        (_record(not_in_scope=[]), "accounts for every stage of the lifecycle"),
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
                        "pre_deploy", **{"coverage.subjects_in_scope.basis": "plan_resource_enumeration"}
                    )
                }
            ),
            "the pre_deploy stage counts its scope as its own",
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
    event["evaluation"].update(status="fail", reason="assert: false")
    return event


PASSED = {"value": "pass", "exit_code": 0, "basis": "status_counts", "stage": None}
INCOMPLETE = {"value": "incomplete", "reason": "evaluator_error", "detail": "1 of 5"}


@pytest.mark.parametrize(
    ("document", "problems"),
    [
        (_record(**{"stages.plan.events.count": 4}), ["stages.plan.coverage"]),
        (_record(events=[RECORD["events"][0], _flipped_event(), *RECORD["events"][2:]]), ["stages.plan.coverage"]),
        (_record(**{"stages.plan.verdict": PASSED}), ["stages.plan.verdict"]),
        (_record(**{"stages.plan.assurance_status": INCOMPLETE}), ["stages.plan.assurance_status"]),
        ({**_record(), "coverage": {**RECORD["coverage"], "sampled": True}}, ["coverage"]),
        ({**_record(), "verdict": {**RECORD["verdict"], "exit_code": 6}}, ["verdict"]),
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
    assert [where for where, _ in derived_problems(car)] == problems


def test_a_record_as_written_has_nothing_to_recompute() -> None:
    assert derived_problems(CAR.model_validate(RECORD)) == []


def _coverage(
    counts: dict[str, int], *, expected: int = 5, evaluated: int = 5, subjects: int = 2, truncated: bool = False
) -> Coverage:
    document = copy.deepcopy(RECORD["stages"]["plan"]["coverage"])
    full = dict.fromkeys(document["status_counts"], 0) | counts
    document.update(status_counts=full, checks=sum(full.values()), assertions_evaluated=evaluated)
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
    assert (verdict.value, verdict.exit_code, verdict.basis, verdict.stage) == (value, code, "status_counts", None)


def test_an_error_marks_a_stage_incomplete_and_a_clean_run_complete() -> None:
    status = stage_outcome(_coverage({"pass": 3, "error": 2})).assurance_status
    assert (status.value, status.reason, status.detail) == (
        "incomplete",
        "required_policy_evaluation_failed",
        "2 of 5 checks ended in an evaluator error",
    )
    assert stage_outcome(_coverage({"fail": 5})).assurance_status.value == "complete"


def test_a_record_that_leaves_the_approval_gate_out_names_the_file_that_says_so() -> None:
    """A project that has no approval step says so in its configuration, and the record names that file."""
    config = {"path": ".iltero/config.yml", "digest": "sha256:" + "d" * 64}
    scoped = _record(
        expected_stages=["plan", "post_deploy"],
        not_in_scope=[
            {"stage": "pre_deploy", "basis": "project_config", "declared_in": config},
            {"stage": "post_verify", "basis": "not_supported", "declared_in": None},
        ],
    )
    car = CAR.model_validate(scoped, context=_READER)
    (left_out, _) = car.not_in_scope
    assert left_out.declared_in is not None and left_out.declared_in.path == ".iltero/config.yml"


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        (
            {"stage": "post_deploy", "basis": "project_config", "declared_in": CONFIG},
            "only the pre-deploy approval gate",
        ),
        ({"stage": "pre_deploy", "basis": "project_config", "declared_in": None}, "names the file that says so"),
        ({"stage": "pre_deploy", "basis": "not_supported", "declared_in": CONFIG}, "names the file that says so"),
    ],
    ids=["a project leaving out post-deploy", "a project choice naming no file", "a file named for no choice"],
)
def test_a_stage_left_out_says_why_in_a_way_that_holds(entry: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        OutOfScope.model_validate(entry)


def test_a_record_always_expects_its_post_deploy_stage() -> None:
    with pytest.raises(ValidationError, match="always expects its post-deploy stage"):
        CAR.model_validate(_record(expected_stages=["plan"]), context=_READER)


def test_a_pre_deploy_stage_needs_the_change_digest() -> None:
    units = RECORD["change"]["units"]
    change_digest_value = change_digest({unit["unit"]: unit["plan"]["digest"] for unit in units})
    with_stage = _record(PRE_DEPLOY, expected_stages=["plan", "pre_deploy", "post_deploy"], complete=False)
    with pytest.raises(ValidationError, match="names the change digest"):
        CAR.model_validate(with_stage, context=_READER)
    with_stage["change"]["digest"] = change_digest_value
    CAR.model_validate(with_stage, context=_READER)


@pytest.mark.parametrize(
    ("field", "value"),
    [("id", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), ("basis", "server_issued"), ("unit", "network")],
    ids=["another run", "another way of opening it", "another unit"],
)
def test_every_event_names_the_records_run(field: str, value: str) -> None:
    document = _record()
    _set(document, f"events.0.provenance.run.{field}", value)
    with pytest.raises(ValidationError, match="every event names the record's run"):
        CAR.model_validate(document, context=_READER)


def test_an_offline_record_has_no_facts_from_compass() -> None:
    units = RECORD["change"]["units"]
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
        **{"change.digest": change_digest({unit["unit"]: unit["plan"]["digest"] for unit in units})},
    )
    CAR.model_validate(document, context=_READER)
    document["events"][-1]["provenance"]["facts_source"] = "server"
    with pytest.raises(ValidationError, match="has no facts from Iltero Compass"):
        CAR.model_validate(document, context=_READER)
