"""The record contract: every path it names stays inside it, and its own counts must agree."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from pydantic import TypeAdapter, ValidationError

from iltero_schemas.canonical import change_digest, digest_of
from iltero_schemas.models.assertion import Stage
from iltero_schemas.models.car import CAR, SKIP_INTEGRITY_CHECKS, PlanRecord, StageRecord
from iltero_schemas.models.coverage import Coverage, combine_in_order, stage_outcome
from iltero_schemas.models.fields import MAX_PATH_COMPONENTS, RAW_TEXT_MAX_BYTES, MemberPath
from iltero_schemas.models.redaction import MAX_REPORTED_PATHS
from iltero_schemas.models.stages import integrity_problems
from tests.conftest import POST_DEPLOY, binding, change, identity_record, removed
from tests.records import RECORD
from tests.records import record as _record


def test_a_record_a_run_wrote_validates() -> None:
    car = CAR.model_validate(RECORD)
    assert car.trust_level == "self_attested" and car.complete is False
    assert car.compliance_determination is None and car.plan.tool == "terraform"
    assert len(car.events) == car.coverage.evaluations == 5
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
        ({"coverage.evaluations": 4}, "add up to the number of evaluations"),
        ({"trust_level": "server_governed"}, "Input should be 'self_attested'"),
        ({"trust_level": "governed"}, "a record without a signature is self_attested"),
        ({"trust_level": "source_authenticated"}, "a record without a signature is self_attested"),
        ({"trust_level": "authority_accepted"}, "Input should be 'self_attested'"),
        ({"trust_level": "assessor_reviewed"}, "Input should be 'self_attested'"),
        ({"compliance_determination": "compliant"}, "Input should be None"),
        ({"governance.run_opened_by": "governed"}, "Input should be 'server' or 'local'"),
        ({"plan.tool": "pulumi"}, "Input should be 'terraform'"),
        ({"run.origin": "guessed"}, "Input should be"),
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
        ({"stages.plan.execution.bundle": None}, "absent together"),
        ({"stages.plan.execution.reason": "why"}, "gives no reason"),
        ({"stages.plan.compiler.install": "source"}, "Input should be"),
        ({"stages.plan.execution.evaluator.limits": {}}, "Extra inputs"),
    ],
    ids=["half a runner", "a reason although it ran", "an install this build never writes", "limits on the stage"],
)
def test_a_stage_that_does_not_describe_a_real_run_is_refused(change: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        CAR.model_validate(_record(**change))


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        ("timeout_seconds", 0, "greater than 0"),
        ("timeout_seconds", 3601, "less than or equal to 3600"),
        ("timeout_seconds", "30", "valid number"),
        ("memory_limit", {"bytes": "lots", "enforced": True, "kind": "rlimit_as"}, "valid integer"),
        ("capabilities_digest", "sha256:nope", "String should match"),
    ],
    ids=["no time", "too long", "not a number", "not a size", "not a digest"],
)
def test_limits_a_record_names_must_be_limits(path: str, value: Any, message: str) -> None:
    """A record says what its evaluations ran under; a replay applies those limits, so they are bounded here."""
    document = _record()
    document["events"][0]["provenance"]["evaluator"]["limits"][path] = value
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
    "binding_set": {
        "id": "ILT.BINDINGS.STARTER",
        "version": "1.0.0",
        "origin": "shipped",
        "file_name": None,
        "digest": "sha256:" + "b" * 64,
        "copy_path": "units/root/plan/bindings.json",
        "binding_count": 2,
    },
    "reports": [
        {
            "tool": "checkov",
            "tool_version": "3.3.8",
            "input_kinds": ["terraform_plan"],
            "report_digest": "sha256:" + "a" * 64,
            "observations": "units/root/artifacts/sha256-" + "c" * 64,
            "results_read": 73,
            "results_without_binding": 71,
            "parsing_errors": 0,
        }
    ],
    "results_accepted": 2,
    "results_binding_unverified": 0,
    "results_without_binding": 71,
}


def test_a_stage_given_no_scanner_report_says_so() -> None:
    assert CAR.model_validate(RECORD).stages[Stage.PLAN].scanners is None


def test_a_stage_records_what_each_report_said_and_what_became_of_it() -> None:
    car = CAR.model_validate(_record(**{"stages.plan.scanners": copy.deepcopy(SCANNERS)}))
    scanners = car.stages[Stage.PLAN].scanners
    assert scanners is not None
    (report,) = scanners.reports
    assert report.tool == "checkov" and report.results_read == 73
    assert scanners.results_accepted == 2 and scanners.binding_set.id == "ILT.BINDINGS.STARTER"


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"results_without_binding": 70}, "results_without_binding is the sum"),
        ({"results_accepted": 3}, "every result a tool reported"),
        ({"results_binding_unverified": 1}, "every result a tool reported"),
    ],
)
def test_a_scanner_block_whose_counts_do_not_add_up_is_refused(change: dict[str, Any], message: str) -> None:
    scanners = {**copy.deepcopy(SCANNERS), **change}
    with pytest.raises(ValidationError, match=message):
        CAR.model_validate(_record(**{"stages.plan.scanners": scanners}))


def test_a_report_of_a_scanner_outside_the_list_is_refused() -> None:
    scanners = copy.deepcopy(SCANNERS)
    scanners["reports"][0]["tool"] = "tfsec"
    with pytest.raises(ValidationError, match="Input should be"):
        CAR.model_validate(_record(**{"stages.plan.scanners": scanners}))


def test_one_report_per_tool_per_stage() -> None:
    scanners = copy.deepcopy(SCANNERS)
    scanners["reports"] = [scanners["reports"][0], copy.deepcopy(scanners["reports"][0])]
    scanners["results_without_binding"] = 142
    scanners["results_accepted"] = 4
    with pytest.raises(ValidationError, match="one report per tool"):
        CAR.model_validate(_record(**{"stages.plan.scanners": scanners}))


@pytest.mark.parametrize(
    ("binding_set", "message"),
    [
        ({"origin": "file"}, "a binding set read from a file names it"),
        ({"file_name": "bindings.yaml"}, "a binding set read from a file names it"),
    ],
)
def test_a_binding_set_must_say_where_it_came_from(binding_set: dict[str, Any], message: str) -> None:
    """A file cannot claim to be the set the contract package ships."""
    scanners = copy.deepcopy(SCANNERS)
    scanners["binding_set"] = {**scanners["binding_set"], **binding_set}
    with pytest.raises(ValidationError, match=message):
        CAR.model_validate(_record(**{"stages.plan.scanners": scanners}))


def test_a_binding_set_read_from_a_file_names_it() -> None:
    scanners = copy.deepcopy(SCANNERS)
    scanners["binding_set"] = {**scanners["binding_set"], "origin": "file", "file_name": "bindings.yaml"}
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
    stage["reference_time"] = {**plan_stage["reference_time"], "value": stage["observed_at"]}
    stage["events"] = {**plan_stage["events"], "count": 0, "path": "units/root/post_deploy/events.json"}
    stage["coverage"] = {
        **plan_stage["coverage"],
        "subjects_in_scope": {
            **plan_stage["coverage"]["subjects_in_scope"],
            "value": 1,
            "counted_from": "deployment_unit",
        },
        "subjects_evaluated": 1,
        "assertions_expected": {**plan_stage["coverage"]["assertions_expected"], "value": 0},
        "assertions_evaluated": 0,
        "subjects_per_assertion": {},
        "status_counts": dict.fromkeys(plan_stage["coverage"]["status_counts"], 0),
        "evaluations": 0,
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
    # Another version is refused before the two plans are compared: no rule but the tool's has a digest.
    document["identity"]["sources"]["plan"] = {"digest": document["plan"]["digest"], "digest_version": "2"}
    with pytest.raises(ValidationError, match="is not the version of the terraform plan digest rule"):
        CAR.model_validate(document)
    document["identity"]["sources"]["plan"] = None
    document["identity"].update(removed=None, removed_unresolved=None)
    document["identity"]["tool_data"]["deposed_deleted"] = None
    with pytest.raises(ValidationError, match="read from the applied plan the deployment names"):
        CAR.model_validate(document)


def _with_changes(*changes: dict[str, Any], **identity: Any) -> dict[str, Any]:
    document = _deployed()
    apply = document["deployment"]["apply"]
    apply["changes"], apply["tool_data"]["summary"] = list(changes), None
    document["identity"].update(identity)
    return _combined(document)


def test_what_the_identities_list_as_removed_is_exactly_what_left_the_state() -> None:
    deleted = change("aws_db_instance.old", "delete", ["delete"], "applied")
    forgotten = change("aws_s3_bucket.kept", "forget", [], "no_operation")
    good = _with_changes(
        deleted,
        forgotten,
        removed=[removed("aws_db_instance.old")],
        removed_unresolved=[{"address": "aws_s3_bucket.kept", "reason": "no_resolver", "removal": "forgotten"}],
    )
    assert CAR.model_validate(good).identity is not None


@pytest.mark.parametrize(
    ("changes", "listed", "removal"),
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
    changes: list[dict[str, Any]], listed: list[str], removal: str
) -> None:
    document = _with_changes(*changes, removed=[removed(address, removal=removal) for address in listed])
    with pytest.raises(ValidationError, match="exactly what left the state, and how"):
        CAR.model_validate(document)


def test_a_record_refuses_a_replan_that_is_the_evaluated_plan() -> None:
    document = _deployed()
    document["deployment"]["superseded_by"] = {"reason": "dependency_replanned"}
    document = _combined(document)
    with pytest.raises(ValidationError, match="a re-plan is a plan other than the evaluated one"):
        CAR.model_validate(document)


def test_a_record_refuses_a_saved_plan_without_its_artifact_digest() -> None:
    with pytest.raises(ValidationError, match="present exactly when artifact_digest_source is saved_plan"):
        CAR.model_validate(_record(**{"plan.artifact_digest_source": "saved_plan"}))


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


@pytest.mark.parametrize(
    ("flag", "message"),
    [("complete", "valid boolean"), ("applyable", "valid boolean"), ("tool_version", "valid string")],
)
def test_a_plan_flag_the_tool_did_not_report_is_its_marker_never_null(flag: str, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        PlanRecord.model_validate({**RECORD["plan"], flag: None})
    PlanRecord.model_validate({**RECORD["plan"], flag: {"__unknown": True, "reason": "not_reported_by_tool"}})


OTHER_PLAN = "sha256:" + "e" * 64


def test_a_change_digest_is_the_digest_of_its_unit() -> None:
    document = _record(**{"change.digest": change_digest({"root": OTHER_PLAN})})
    with pytest.raises(ValidationError, match="change.digest is not the digest of the change's units"):
        CAR.model_validate(document)
    car = CAR.model_validate(document, context={SKIP_INTEGRITY_CHECKS: True})
    assert integrity_problems(car) == [("change.digest", "is not the digest of the change's units")]


@pytest.mark.parametrize("value", [1, "true", "no", [True]])
def test_only_true_skips_the_integrity_checks(value: object) -> None:
    document = _record(**{"stages.plan.verdict.value": "pass", "stages.plan.verdict.exit_code": 0})
    CAR.model_validate(document, context={SKIP_INTEGRITY_CHECKS: True})
    with pytest.raises(ValidationError, match="is not the verdict the stage's counts give"):
        CAR.model_validate(document, context={SKIP_INTEGRITY_CHECKS: value})


def test_a_stage_compiled_from_a_wheel_names_the_wheel() -> None:
    stage = copy.deepcopy(RECORD["stages"]["plan"])
    stage["compiler"] = {**stage["compiler"], "install": "wheel", "contract_digest": None}
    with pytest.raises(ValidationError, match="an installed contract package has a digest"):
        StageRecord.model_validate(stage)


def test_the_identities_count_exactly_the_deposed_objects_the_apply_destroyed() -> None:
    deposed = [
        {"address": "aws_db_instance.db", "key": "bb9fd791", "outcome": "applied"},
        {"address": "aws_db_instance.db", "key": "cc0a1b2d", "outcome": "errored"},
    ]
    for counted, valid in ((1, True), (0, False), (2, False)):
        document = _deployed()
        document["deployment"]["apply"]["tool_data"].update(summary=None, deposed=deposed)
        document["identity"]["tool_data"]["deposed_deleted"] = counted
        document = _combined(document)
        if valid:
            assert CAR.model_validate(document).identity is not None
            continue
        with pytest.raises(ValidationError, match="count exactly the deposed objects the apply destroyed"):
            CAR.model_validate(document)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("stages.plan.reference_time", {"value": "2026-09-22T13:00:13.568Z", "trust": "attested"}),
        ("stages.plan.reference_time.anything", [1, 2]),
        ("stages.plan.redaction", {}),
        ("stages.plan.redaction.input.kind", "artifact"),
        ("stages.plan.redaction.redacted", [{"path": "resources[0].after.password", "reason": "Not A Token"}]),
        ("subject.source", {"x": 1}),
        ("subject.source.vcs", "svn"),
    ],
    ids=["time-no-source", "time-extra", "redaction-empty", "redaction-kind", "redaction-reason", "source", "vcs"],
)
def test_the_reference_time_redaction_report_and_source_have_their_shape(path: str, value: Any) -> None:
    with pytest.raises(ValidationError):
        CAR.model_validate(_record(**{path: value}))


def test_a_redaction_report_keeps_paths_and_allowed_reasons_as_written() -> None:
    odd = 'resources[0].after.tags["a key\nwith a line"]' + "x" * 3000
    document = _record(
        **{
            "stages.plan.redaction.unknown": [odd],
            "stages.plan.redaction.allowed": [{"path": odd, "reason": "Public by design"}],
        }
    )
    assert CAR.model_validate(document).stages[Stage.PLAN].redaction.unknown == [odd]


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("stages.plan.redaction.unknown", ["x" * (RAW_TEXT_MAX_BYTES + 1)]),
        ("stages.plan.redaction.unknown", [""]),
        ("stages.plan.redaction.unknown", ["p"] * (MAX_REPORTED_PATHS + 1)),
        ("stages.plan.redaction.allowed", [{"path": "p", "reason": "line\nbreak"}]),
        ("stages.plan.redaction.allowed", [{"path": "p", "reason": ""}]),
    ],
    ids=["path-too-long", "path-empty", "too-many-paths", "reason-control", "reason-empty"],
)
def test_a_redaction_report_is_bounded_and_its_allowed_reasons_are_plain_text(path: str, value: Any) -> None:
    with pytest.raises(ValidationError):
        CAR.model_validate(_record(**{path: value}))


def test_raw_text_is_bounded_in_utf8_bytes() -> None:
    at_limit = "\u00e9" * (RAW_TEXT_MAX_BYTES // 2)
    accepted = CAR.model_validate(_record(**{"stages.plan.redaction.unknown": [at_limit]}))
    assert accepted.stages[Stage.PLAN].redaction.unknown == [at_limit]
    with pytest.raises(ValidationError, match=f"at most {RAW_TEXT_MAX_BYTES} bytes"):
        CAR.model_validate(_record(**{"stages.plan.redaction.unknown": [at_limit + "\u00e9"]}))


@pytest.mark.parametrize(
    ("time", "message"),
    [
        ({"trust": "attested"}, "only ever asserted"),
        ({"value": "2026-09-22T13:00:14Z"}, "uses the time it observed"),
        ({"source": "server", "trust": "attested"}, "no time from the server"),
        (
            {
                "time_window": {
                    "not_before": "2026-09-22T13:00:00Z",
                    "not_after": "2026-09-22T13:01:00Z",
                    "nonce_digest": "sha256:" + "a" * 64,
                }
            },
            "exactly when a timestamp authority",
        ),
        ({"source": "timestamp_authority", "trust": "attested"}, "exactly when a timestamp authority"),
    ],
    ids=["clock-attested", "clock-not-observed", "local-server-time", "clock-time-window", "authority-no-time-window"],
)
def test_a_stage_reference_time_claims_no_more_than_its_source(time: dict[str, Any], message: str) -> None:
    reference_time = {**RECORD["stages"]["plan"]["reference_time"], **time}
    with pytest.raises(ValidationError, match=message):
        CAR.model_validate(_record(**{"stages.plan.reference_time": reference_time}))


def test_a_clock_time_written_another_way_is_the_same_instant() -> None:
    observed = RECORD["stages"]["plan"]["observed_at"]
    written = observed.replace("Z", "000Z") if "." in observed else observed.replace("Z", ".000Z")
    reference_time = {**RECORD["stages"]["plan"]["reference_time"], "value": written}
    CAR.model_validate(_record(**{"stages.plan.reference_time": reference_time}))


def test_a_stage_names_a_local_bundles_content_digest_and_key_as_null() -> None:
    document = _record()
    document["stages"]["plan"]["execution"]["bundle"]["key_id"] = "iltero-bundle-2026-09"
    with pytest.raises(ValidationError, match="exactly when its kind is server"):
        CAR.model_validate(document)
