"""A record of an apply whose state after it was not read: no identities, no post-verify, a coverage gap at post-deploy,
and the apply log kept in its register."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.canonical import digest_of
from iltero_schemas.models.car import CAR, SKIP_INTEGRITY_CHECKS, StageRecord
from iltero_schemas.models.context import AssuranceContext
from iltero_schemas.models.coverage import STATE_REASON, Coverage, combine_in_order, stage_outcome
from iltero_schemas.models.stages import integrity_problems
from tests.conftest import VECTORS
from tests.records import DEPLOYED, VERIFIED, iac_change

NOT_READ = {"__unknown": True, "reason": "state_not_read"}
STATE_GAP = {"kind": "state_not_read"}


def _restaged(document: dict[str, Any], stage: str) -> None:
    """``stage``'s verdict and status recomputed from its coverage, and the record's top level from its stages."""
    record = document["stages"][stage]
    outcome = stage_outcome(Coverage.model_validate(record["coverage"])).model_dump(mode="json")
    record.update(verdict=outcome["verdict"], assurance_status=outcome["assurance_status"])
    outcomes = {name: StageRecord.model_validate(value).outcome for name, value in document["stages"].items()}
    document.update(combine_in_order(document["expected_stages"], outcomes).model_dump(mode="json"))


def _not_read(source: dict[str, Any] = DEPLOYED) -> dict[str, Any]:
    """``source`` with the state after its apply not read: the log's word alone, no identities, and the gap."""
    document = copy.deepcopy(source)
    apply = document["change"]["deployment"]["apply"]
    apply.update(state=NOT_READ, outcomes_from="apply_log_alone")
    for entry in apply["changes"]:
        entry["outcome_from"] = "apply_log_alone"
    document["change"]["identity"] = None
    stage = document["stages"]["post_deploy"]
    stage["coverage"]["gaps"] = [STATE_GAP]
    stage["coverage"]["subjects_in_scope"]["source_digest"] = digest_of(document["change"]["deployment"])
    _restaged(document, "post_deploy")
    return document


def test_a_record_of_an_apply_whose_state_was_not_read_has_no_identities_and_a_gap() -> None:
    car = CAR.model_validate(_not_read())
    assert iac_change(car).identity is None
    assert (car.verdict.exit_code, car.assurance_status.value) == (6, "incomplete")
    post_deploy = car.stages[next(stage for stage in car.stages if stage.value == "post_deploy")]
    assert (post_deploy.verdict.exit_code, post_deploy.assurance_status.reason) == (6, STATE_REASON)


def test_a_record_names_no_identities_when_the_state_was_not_read() -> None:
    document = _not_read()
    document["change"]["identity"] = copy.deepcopy(DEPLOYED["change"]["identity"])
    with pytest.raises(ValidationError, match="names no identities when the state after the apply was not read"):
        CAR.model_validate(document)


def test_a_record_with_the_state_read_still_names_its_identities() -> None:
    document = copy.deepcopy(DEPLOYED)
    document["change"]["identity"] = None
    with pytest.raises(ValidationError, match="its identities exactly when its post-deploy stage has reported"):
        CAR.model_validate(document)


def test_post_verify_needs_the_state_after_the_apply() -> None:
    with pytest.raises(ValidationError, match="post-verify needs the identities the state after the apply gives"):
        CAR.model_validate(_not_read(VERIFIED))


def test_a_post_verify_input_needs_the_state_after_the_apply() -> None:
    context = AssuranceContext.model_validate_json(
        (VECTORS / "contexts" / "iac" / "post_verify.json").read_text(encoding="utf-8")
    ).model_dump(mode="json", by_alias=True)
    apply = context["deployment"]["apply"]
    apply.update(state=NOT_READ, outcomes_from="apply_log_alone")
    for entry in apply["changes"]:
        entry["outcome_from"] = "apply_log_alone"
    with pytest.raises(ValidationError, match="post-verify needs the identities the state after the apply gives"):
        AssuranceContext.model_validate(context)


def test_only_the_post_deploy_stage_lists_the_state_not_read() -> None:
    document = _not_read()
    document["stages"]["plan"]["coverage"]["gaps"].append(STATE_GAP)
    _restaged(document, "plan")
    with pytest.raises(ValidationError, match="the plan stage lists the state not read"):
        CAR.model_validate(document)


@pytest.mark.parametrize("read", [True, False], ids=["a gap with the state read", "no gap with the state not read"])
def test_the_post_deploy_stage_lists_the_state_not_read_exactly_when_it_was_not(read: bool) -> None:
    document = copy.deepcopy(DEPLOYED) if read else _not_read()
    document["stages"]["post_deploy"]["coverage"]["gaps"] = [STATE_GAP] if read else []
    _restaged(document, "post_deploy")
    with pytest.raises(ValidationError, match="does not match change.deployment.apply.state"):
        CAR.model_validate(document)


def test_only_an_evaluation_of_a_record_whose_state_was_not_read_is_unknown_for_it() -> None:
    document = copy.deepcopy(DEPLOYED)
    event = next(e for e in document["events"] if e["evaluation"]["stage"] == "post_deploy")
    event["evaluation"].update(status="unknown", status_reason=STATE_REASON)
    car = CAR.model_validate(document, context={SKIP_INTEGRITY_CHECKS: True})
    assert ("events.3.evaluation.status_reason", "names a state not read the record does not") in [
        tuple(problem) for problem in integrity_problems(car)
    ]


def test_the_apply_log_is_an_entry_of_the_evidence_register() -> None:
    log = DEPLOYED["change"]["deployment"]["apply"]["source"]["digest"]
    document = copy.deepcopy(DEPLOYED)
    document["evidence_refs"] = [
        ref for ref in document["evidence_refs"] if ref["source"] is None or ref["source"]["digest"] != log
    ]
    with pytest.raises(ValidationError, match="the apply log the deployment was read from is an entry"):
        CAR.model_validate(document)


def test_a_record_whose_state_was_not_read_gives_the_reason_only_at_post_deploy() -> None:
    document = _not_read()
    event = next(e for e in document["events"] if e["evaluation"]["stage"] == "pre_deploy")
    event["evaluation"].update(status="unknown", status_reason=STATE_REASON)
    car = CAR.model_validate(document, context={SKIP_INTEGRITY_CHECKS: True})
    index = document["events"].index(event)
    assert (f"events.{index}.evaluation.status_reason", "names a state not read the record does not") in [
        tuple(problem) for problem in integrity_problems(car)
    ]


IMAGE_DEPLOY: dict[str, Any] = json.loads(
    (VECTORS / "records" / "image" / "local_run_deploy.json").read_text(encoding="utf-8")
)


@pytest.mark.parametrize("stage", ["pre_deploy", "post_deploy", "post_verify"])
def test_a_record_with_no_state_after_an_apply_lists_no_state_not_read(stage: str) -> None:
    document = copy.deepcopy(IMAGE_DEPLOY)
    document["stages"][stage]["coverage"]["gaps"].append(STATE_GAP)
    _restaged(document, stage)
    with pytest.raises(
        ValidationError, match=f"the {stage} stage lists the state not read, which a record of image_deploy never has"
    ):
        CAR.model_validate(document)


def test_a_record_with_no_state_after_an_apply_gives_no_state_not_read_reason() -> None:
    document = copy.deepcopy(IMAGE_DEPLOY)
    event = document["events"][-1]
    event["evaluation"].update(status="unknown", status_reason=STATE_REASON)
    car = CAR.model_validate(document, context={SKIP_INTEGRITY_CHECKS: True})
    assert (
        f"events.{len(document['events']) - 1}.evaluation.status_reason",
        "names a state not read the record does not",
    ) in [tuple(problem) for problem in integrity_problems(car)]


def test_an_evaluation_of_the_post_deploy_stage_may_be_unknown_for_a_state_not_read() -> None:
    document = _not_read()
    event = next(e for e in document["events"] if e["evaluation"]["stage"] == "post_deploy")
    event["evaluation"].update(status="unknown", status_reason=STATE_REASON)
    car = CAR.model_validate(document, context={SKIP_INTEGRITY_CHECKS: True})
    assert not [problem for problem in integrity_problems(car) if problem[0].endswith("status_reason")]
