"""The record contract: every path it names stays inside it, and its own counts must agree."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import TypeAdapter, ValidationError

from iltero_schemas.canonical import digest_of
from iltero_schemas.models.assertion import Stage
from iltero_schemas.models.car import CAR, MAX_PATH_COMPONENTS, MemberPath, StageRecord
from iltero_schemas.models.coverage import Coverage, combine_in_order, stage_outcome
from tests.conftest import POST_DEPLOY, binding, change, identity_record, removed

RECORD: dict[str, Any] = json.loads((Path(__file__).parent / "data" / "plan_record.json").read_text(encoding="utf-8"))


def _record(**changes: Any) -> dict[str, Any]:
    document: dict[str, Any] = copy.deepcopy(RECORD)
    for dotted, value in changes.items():
        node = document
        parts = dotted.split(".")
        for key in parts[:-1]:
            node = node[key]
        node[parts[-1]] = value
    return document


def test_a_record_a_run_wrote_validates() -> None:
    car = CAR.model_validate(RECORD)
    assert car.assurance_level == "self_attested" and car.complete is False
    assert len(car.events) == car.coverage.checks == 5
    assert car.evidence_refs and all(not ref.path.startswith("/") for ref in car.evidence_refs)


@pytest.mark.parametrize(
    "path",
    [
        "/etc/hosts",
        "../../etc/hosts",
        "units/../../etc/hosts",
        "./units/root/car.json",
        "C:/windows/system32",
        "//server/share",
        "units/" * (MAX_PATH_COMPONENTS + 1) + "file",
        "units/root/\\evil",
        "units/root/a b",
        "",
    ],
    ids=["absolute", "up", "inner up", "dot", "drive", "unc", "deep", "backslash", "space", "empty"],
)
def test_a_path_that_leaves_the_record_is_refused(path: str) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(MemberPath).validate_python(path)


def test_a_cited_path_that_leaves_the_record_is_refused_in_the_record() -> None:
    document = _record()
    document["evidence_refs"][0]["path"] = "../../../etc/hosts"
    with pytest.raises(ValidationError, match="relative path of plain names"):
        CAR.model_validate(document)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"coverage.checks": 4}, "add up to the number of checks"),
        ({"assurance_level": "governed"}, "Input should be 'self_attested'"),
        ({"run_id.basis": "guessed"}, "Input should be"),
        ({"uuid": "not-a-uuid"}, "String should match pattern"),
        ({"integrity.signature": "MEUCIQ"}, "Input should be None"),
        ({"retention_class": "soc2_730d"}, "Input should be None"),
        ({"complete": True}, "complete exactly when every expected stage has reported"),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_a_record_that_does_not_hold_together_is_refused(change: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        CAR.model_validate(_record(**change))


def test_the_status_counts_name_every_status() -> None:
    document = _record()
    del document["coverage"]["status_counts"]["error"]
    with pytest.raises(ValidationError, match="names every status"):
        CAR.model_validate(document)


def test_an_unknown_key_anywhere_is_refused() -> None:
    document = _record()
    document["stages"]["plan"]["extra"] = 1
    with pytest.raises(ValidationError, match="extra"):
        CAR.model_validate(document)


def test_a_stage_the_record_does_not_expect_is_refused() -> None:
    document = _record()
    document["stages"]["runtime"] = copy.deepcopy(document["stages"]["plan"])
    document["stages"]["runtime"]["stage"] = "runtime"
    with pytest.raises(ValidationError, match="not one this record expects"):
        CAR.model_validate(document)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"stages.plan.ran.bundle": None}, "absent together"),
        ({"stages.plan.ran.reason": "why"}, "gives no reason"),
        ({"stages.plan.compiler.install": "source"}, "Input should be"),
        ({"stages.plan.ran.evaluator.environment": {}}, "Extra inputs"),
    ],
    ids=["half a runner", "a reason although it ran", "an install this build never writes", "limits on the stage"],
)
def test_a_stage_that_does_not_describe_a_real_run_is_refused(change: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        CAR.model_validate(_record(**change))


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        ("timeout_s", 0, "greater than 0"),
        ("timeout_s", 3601, "less than or equal to 3600"),
        ("timeout_s", "30", "valid number"),
        ("memory_cap", {"bytes": "lots", "enforced": True, "kind": "rlimit_as"}, "valid integer"),
        ("capabilities_digest", "sha256:nope", "String should match"),
    ],
    ids=["no time", "too long", "not a number", "not a size", "not a digest"],
)
def test_limits_a_record_names_must_be_limits(path: str, value: Any, message: str) -> None:
    """A record says what its checks ran under; a replay applies those limits, so they are bounded here."""
    document = _record()
    document["events"][0]["provenance"]["evaluator"]["environment"][path] = value
    with pytest.raises(ValidationError, match=message):
        CAR.model_validate(document)


def test_the_evidence_register_names_each_file_once() -> None:
    document = _record()
    document["evidence_refs"].append(copy.deepcopy(document["evidence_refs"][0]))
    with pytest.raises(ValidationError, match="name the same file"):
        CAR.model_validate(document)
    document["evidence_refs"][-1]["path"] = "units/root/elsewhere.json"
    with pytest.raises(ValidationError, match="share a name"):
        CAR.model_validate(document)


SCANNERS: dict[str, Any] = {
    "catalogue": {
        "id": "ILT.BINDINGS.STARTER",
        "version": "1.0.0",
        "origin": "shipped",
        "file_name": None,
        "digest": "sha256:" + "b" * 64,
        "retained": "units/root/plan/bindings.json",
        "entries": 2,
    },
    "reports": [
        {
            "tool": "checkov",
            "tool_version": "3.3.8",
            "frameworks": ["terraform_plan"],
            "report_digest": "sha256:" + "a" * 64,
            "observations": "units/root/artifacts/sha256-" + "c" * 64,
            "checks_read": 73,
            "unbound_checks": 71,
            "parsing_errors": 0,
        }
    ],
    "credited": 2,
    "binding_unverified": 0,
    "unbound_checks": 71,
}


def test_a_stage_given_no_scanner_report_says_so() -> None:
    assert CAR.model_validate(RECORD).stages[Stage.PLAN].scanners is None


def test_a_stage_records_what_each_report_said_and_what_became_of_it() -> None:
    car = CAR.model_validate(_record(**{"stages.plan.scanners": copy.deepcopy(SCANNERS)}))
    scanners = car.stages[Stage.PLAN].scanners
    assert scanners is not None
    (report,) = scanners.reports
    assert report.tool == "checkov" and report.checks_read == 73
    assert scanners.credited == 2 and scanners.catalogue.id == "ILT.BINDINGS.STARTER"


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"unbound_checks": 70}, "the unbound count is the sum"),
        ({"credited": 3}, "every result a tool reported"),
        ({"binding_unverified": 1}, "every result a tool reported"),
    ],
)
def test_a_scanner_block_whose_counts_do_not_add_up_is_refused(change: dict[str, Any], message: str) -> None:
    scanners = {**copy.deepcopy(SCANNERS), **change}
    with pytest.raises(ValidationError, match=message):
        CAR.model_validate(_record(**{"stages.plan.scanners": scanners}))


def test_one_report_per_tool_per_stage() -> None:
    scanners = copy.deepcopy(SCANNERS)
    scanners["reports"] = [scanners["reports"][0], copy.deepcopy(scanners["reports"][0])]
    scanners["unbound_checks"] = 142
    scanners["credited"] = 4
    with pytest.raises(ValidationError, match="one report per tool"):
        CAR.model_validate(_record(**{"stages.plan.scanners": scanners}))


@pytest.mark.parametrize(
    ("catalogue", "message"),
    [
        ({"origin": "file"}, "a catalogue read from a file names it"),
        ({"file_name": "bindings.yaml"}, "a catalogue read from a file names it"),
    ],
)
def test_a_catalogue_must_say_where_it_came_from(catalogue: dict[str, Any], message: str) -> None:
    """A file cannot claim to be the set the contract package ships."""
    scanners = copy.deepcopy(SCANNERS)
    scanners["catalogue"] = {**scanners["catalogue"], **catalogue}
    with pytest.raises(ValidationError, match=message):
        CAR.model_validate(_record(**{"stages.plan.scanners": scanners}))


def test_a_catalogue_read_from_a_file_names_it() -> None:
    scanners = copy.deepcopy(SCANNERS)
    scanners["catalogue"] = {**scanners["catalogue"], "origin": "file", "file_name": "bindings.yaml"}
    car = CAR.model_validate(_record(**{"stages.plan.scanners": scanners}))
    assert car.stages[Stage.PLAN].scanners is not None


def test_a_results_file_outside_the_record_is_refused() -> None:
    scanners = copy.deepcopy(SCANNERS)
    scanners["reports"][0]["observations"] = "../checkov.observations.json"
    with pytest.raises(ValidationError, match="String should match|relative|component"):
        CAR.model_validate(_record(**{"stages.plan.scanners": scanners}))


def _deployed(**changes: Any) -> dict[str, Any]:
    """The plan record after a post-deploy stage reported, with ``changes`` applied."""
    document = _record(deployment=copy.deepcopy(POST_DEPLOY["deployment"]), identity=identity_record())
    document["deployment"]["plan"]["digest"] = document["plan"]["digest"]
    # The apply ran after the plan the record evaluated.
    document["deployment"]["apply"]["timing"].update(started_at="2026-09-22T14:00:00Z", ended_at="2026-09-22T14:01:00Z")
    document["identity"]["sources"]["plan"]["digest"] = document["plan"]["digest"]
    document["identity"]["sources"]["state"] = dict(document["deployment"]["apply"]["state"])
    document["stages"]["post_deploy"] = _post_deploy_stage(document["stages"]["plan"])
    document.update(changes)
    return _combined(document)


def _post_deploy_stage(plan_stage: dict[str, Any]) -> dict[str, Any]:
    """A post-deploy stage record that ran no check: one deployment in scope, nothing evaluated."""
    stage = copy.deepcopy(plan_stage)
    stage["stage"] = "post_deploy"
    stage["observed_at"] = "2026-09-22T14:02:00Z"
    stage["events"] = {**plan_stage["events"], "count": 0, "path": "units/root/post_deploy/events.json"}
    stage["coverage"] = {
        **plan_stage["coverage"],
        "subjects_in_scope": {**plan_stage["coverage"]["subjects_in_scope"], "value": 1, "basis": "deployment_unit"},
        "subjects_evaluated": 1,
        "assertions_expected": {**plan_stage["coverage"]["assertions_expected"], "value": 0},
        "assertions_evaluated": 0,
        "subjects_per_assertion": {},
        "status_counts": dict.fromkeys(plan_stage["coverage"]["status_counts"], 0),
        "checks": 0,
    }
    outcome = stage_outcome(Coverage.model_validate(stage["coverage"])).model_dump(mode="json")
    return {**stage, "verdict": outcome["verdict"], "assurance_status": outcome["assurance_status"]}


def _combined(document: dict[str, Any]) -> dict[str, Any]:
    """The record with its post-deploy scope naming its deployment, and its top level set from its stages."""
    if "post_deploy" in document["stages"] and document["deployment"] is not None:
        scope = document["stages"]["post_deploy"]["coverage"]["subjects_in_scope"]
        scope["source_digest"] = digest_of(document["deployment"])
    outcomes = {name: StageRecord.model_validate(stage).outcome for name, stage in document["stages"].items()}
    return {**document, **combine_in_order(document["expected_stages"], outcomes).model_dump(mode="json")}


def test_a_record_describes_the_deployment_and_its_identities_exactly_when_post_deploy_reported() -> None:
    assert CAR.model_validate(_deployed()).deployment is not None
    document = _deployed()
    del document["stages"]["post_deploy"]
    with pytest.raises(ValidationError, match="the deployment exactly when its post-deploy stage has reported"):
        CAR.model_validate(document)
    document = _deployed(identity=None)
    with pytest.raises(ValidationError, match="its identities exactly when its post-deploy stage has reported"):
        CAR.model_validate(document)
    with pytest.raises(ValidationError, match="its identities exactly when"):
        CAR.model_validate(_record(identity=identity_record()))


def test_a_record_carries_the_identities_of_its_own_unit() -> None:
    bindings = [binding("aws_db_instance.payments"), binding("aws_s3_bucket.logs", "s3_bucket")]
    unresolved = [{"address": "aws_lambda_function.worker", "reason": "identifier_invalid"}]
    document = _deployed()
    document["identity"].update(bindings=bindings, unresolved=unresolved)
    car = CAR.model_validate(document)
    assert car.identity is not None and len(car.identity.bindings) == 2
    document["identity"].update(bindings=[binding("a.x", unit="network")], unresolved=[])
    with pytest.raises(ValidationError, match="belongs to the unit"):
        CAR.model_validate(document)


def test_the_identities_are_read_from_the_applied_plan_the_deployment_names() -> None:
    document = _deployed()
    document["identity"]["sources"]["plan"]["digest"] = "sha256:" + "c" * 64
    with pytest.raises(ValidationError, match="read from the applied plan the deployment names"):
        CAR.model_validate(document)
    document["identity"]["sources"]["plan"] = {"digest": document["plan"]["digest"], "digest_version": "2"}
    with pytest.raises(ValidationError, match="read from the applied plan the deployment names"):
        CAR.model_validate(document)
    document["identity"]["sources"]["plan"] = None
    document["identity"].update(removed=None, removed_unresolved=None, deposed_destroyed=None)
    with pytest.raises(ValidationError, match="read from the applied plan the deployment names"):
        CAR.model_validate(document)


def _with_changes(*changes: dict[str, Any], **identity: Any) -> dict[str, Any]:
    document = _deployed()
    apply = document["deployment"]["apply"]
    apply["changes"], apply["summary"] = list(changes), None
    document["identity"].update(identity)
    return _combined(document)


def test_what_the_identities_list_as_removed_is_exactly_what_left_the_state() -> None:
    deleted = change("aws_db_instance.old", "delete", ["delete"], "applied")
    forgotten = change("aws_s3_bucket.kept", "forget", [], "no_operation")
    good = _with_changes(
        deleted,
        forgotten,
        removed=[removed("aws_db_instance.old")],
        removed_unresolved=[{"address": "aws_s3_bucket.kept", "reason": "no_resolver", "fate": "forgotten"}],
    )
    assert CAR.model_validate(good).identity is not None


@pytest.mark.parametrize(
    ("changes", "listed", "fate"),
    [
        ([change("aws_db_instance.old", "delete", ["delete"], "applied")], [], "deleted"),
        ([change("aws_db_instance.old", "delete", ["delete"], "errored")], ["aws_db_instance.old"], "deleted"),
        ([change("aws_db_instance.old", "update", ["update"], "applied")], ["aws_db_instance.old"], "deleted"),
        ([change("aws_db_instance.old", "replace", ["create"], "applied")], ["aws_db_instance.old"], "deleted"),
        ([change("aws_db_instance.old", "delete", ["delete"], "applied")], ["aws_db_instance.old"], "forgotten"),
    ],
    ids=[
        "a deletion left out",
        "a delete that failed listed as removed",
        "an update listed as removed",
        "a forgotten old object listed as deleted",
        "a deletion listed as forgotten",
    ],
)
def test_a_record_that_misstates_what_left_the_state_is_refused(
    changes: list[dict[str, Any]], listed: list[str], fate: str
) -> None:
    document = _with_changes(*changes, removed=[removed(address, fate=fate) for address in listed])
    with pytest.raises(ValidationError, match="exactly what left the state, and how"):
        CAR.model_validate(document)


def test_a_record_refuses_a_replan_that_is_the_evaluated_plan() -> None:
    document = _deployed()
    document["deployment"]["superseded_by"] = {"basis": "dependency_replan"}
    document = _combined(document)
    with pytest.raises(ValidationError, match="a re-plan is a plan other than the evaluated one"):
        CAR.model_validate(document)


def test_a_record_refuses_an_artifact_digest_without_its_basis() -> None:
    with pytest.raises(ValidationError, match="present exactly when artifact_digest_basis is plan_binary"):
        CAR.model_validate(_record(**{"plan.artifact_digest_basis": "plan_binary"}))


def test_a_plan_stage_observed_after_the_apply_started_is_refused() -> None:
    document = _deployed()
    document["deployment"]["apply"]["timing"]["started_at"] = "2026-09-22T13:00:13Z"
    with pytest.raises(ValidationError, match="the plan stage was observed no later than the apply started"):
        CAR.model_validate(document)


def test_the_post_deploy_stage_counts_the_deployment_the_record_describes() -> None:
    document = _deployed()
    assert CAR.model_validate(document).deployment is not None
    document["stages"]["post_deploy"]["coverage"]["subjects_in_scope"]["source_digest"] = document["plan"]["digest"]
    with pytest.raises(ValidationError, match="must count the one deployment the record describes"):
        CAR.model_validate(document)


def test_the_identities_are_read_from_the_state_the_deployment_was_held_to() -> None:
    document = _deployed()
    document["identity"]["sources"]["state"]["digest"] = "sha256:" + "9" * 64
    with pytest.raises(ValidationError, match="read from the state the deployment was held to"):
        CAR.model_validate(document)


def test_every_event_names_the_plan_the_record_evaluated() -> None:
    document = _record()
    document["events"][0]["provenance"]["plan_digest"]["value"] = "sha256:" + "a" * 64
    with pytest.raises(ValidationError, match="every event names the plan the record evaluated"):
        CAR.model_validate(document)
