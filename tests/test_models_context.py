"""The context contract: the envelope, the parts, and that the parts present match the profile exactly."""

from __future__ import annotations

import copy
import json
import re
from typing import Any, get_args

import pytest
from pydantic import ValidationError

from iltero_schemas.canonical import change_digest
from iltero_schemas.compiler.limits import OBSERVATIONS_MAX_BYTES
from iltero_schemas.models.context import API_VERSION, PARTS, AssuranceContext, KindNotMapped
from iltero_schemas.models.event import STATUS_REASONS
from iltero_schemas.models.facts import NotReported, UnknownReason
from iltero_schemas.models.fields import Identity
from iltero_schemas.models.iac.deployment import Deployment
from iltero_schemas.models.iac.markers import ApplyLogIncomplete, StateNotRead
from iltero_schemas.models.subjects import subject_key
from iltero_schemas.profiles import PROFILES
from tests.conftest import POST_DEPLOY, VECTORS

VECTOR: dict[str, Any] = json.loads((VECTORS / "contexts" / "iac" / "plan_resource.json").read_text(encoding="utf-8"))


def _without(*names: str) -> dict[str, Any]:
    document = copy.deepcopy(VECTOR)
    for name in names:
        del document[name]
    return document


def test_the_vector_validates_and_names_exactly_the_profile_parts() -> None:
    context = AssuranceContext.model_validate(VECTOR)
    assert context.subject is not None and context.resource is not None
    assert context.subject.key.startswith("sha256:")
    assert context.subject.identities[0].value == context.resource.id == "aws_db_instance.payments"
    named = {name for name, part in VECTOR.items() if part is not None}
    assert named - {"apiVersion", "evaluation", "organization_scope", "reference_time"} == {
        "source",
        "change",
        "plan",
        "subject",
        "resource",
    }


def test_every_profile_root_is_a_field_of_the_contract() -> None:
    roots = set().union(*(profile.roots for profile in PROFILES.values()))
    assert roots - {"evaluation", "organization_scope", "reference_time"} == set(PARTS)
    assert set(PARTS) <= set(AssuranceContext.model_fields)


def test_the_api_version_constant_is_the_one_the_model_accepts() -> None:
    assert VECTOR["apiVersion"] == API_VERSION


@pytest.mark.parametrize("name", ["source", "change", "plan", "resource"])
def test_a_required_part_missing_is_refused_by_name(name: str) -> None:
    with pytest.raises(ValidationError, match=f"plan_resource: missing {name}"):
        AssuranceContext.model_validate(_without(name))


def test_a_part_outside_the_profile_is_refused_by_name() -> None:
    document = copy.deepcopy(VECTOR)
    document["approvals"] = []
    with pytest.raises(ValidationError, match="plan_resource: not part of this profile: approvals"):
        AssuranceContext.model_validate(document)


def test_the_subject_is_always_required() -> None:
    with pytest.raises(ValidationError, match="subject is required"):
        AssuranceContext.model_validate(_without("subject"))


def test_an_unknown_key_anywhere_is_refused() -> None:
    document = copy.deepcopy(VECTOR)
    document["plan"]["id"] = "plan_001"
    with pytest.raises(ValidationError, match="plan.id"):
        AssuranceContext.model_validate(document)


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("plan", "digest"), "sha256:abc", "String should match pattern"),
        (("source", "commit", "sha"), "c84e7a1", "String should match pattern"),
        (("evaluation", "timestamp"), "2026-09-16 18:05:00", "String should match pattern"),
        (("subject", "identities"), [], "at least 1 item"),
        (("subject", "identities", 0, "value"), "a\x00b", "control characters"),
        (("subject", "identities", 0, "value"), "a\u202eb", "control characters"),
        (("subject", "identities", 0, "value"), "a\u00adb", "control characters"),
        (("subject", "identities", 0, "value"), "a\u034fb", "control characters"),
        (("subject", "identities", 0, "value"), "a\u061cb", "control characters"),
        (("subject", "identities", 0, "value"), "a\u115fb", "control characters"),
        (("subject", "identities", 0, "value"), "a\u1160b", "control characters"),
        (("subject", "identities", 0, "value"), "a\u180eb", "control characters"),
        (("subject", "identities", 0, "value"), "a\u3164b", "control characters"),
        (("subject", "identities", 0, "value"), "a\uffa0b", "control characters"),
        (("subject", "identities", 0, "value"), "x" * 2049, "at most 2048"),
        (("subject", "key"), "aws_db_instance.payments", "String should match pattern"),
        (("resource", "action"), "read", "Input should be"),
        (("reference_time", "source"), "wall_clock", "Input should be"),
        (("evaluation", "timestamp"), "2026-13-45T25:61:61Z", "real date and time"),
        (("plan", "complete"), "yes", "Input should be a valid boolean"),
        (("plan", "complete"), 1, "Input should be a valid boolean"),
        (("plan", "source_commit"), "d" * 40, "must be the source commit"),
    ],
)
def test_a_malformed_value_is_refused(path: tuple[str, ...], value: Any, message: str) -> None:
    document = copy.deepcopy(VECTOR)
    node = document
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    with pytest.raises(ValidationError, match=message):
        AssuranceContext.model_validate(document)


def test_the_context_and_source_are_sparse() -> None:
    document = copy.deepcopy(VECTOR)
    document["organization_scope"] = {}
    # A change made outside any environment is named by a digest whose environment key is null.
    plan = VECTOR["plan"]
    checked = {"kind": "plan", "digest": plan["digest"], "digest_version": plan["digest_version"], "tool": plan["tool"]}
    document["change"]["digest"] = change_digest("iac_change", "root", None, checked)
    document["source"] = {"vcs": "git", "commit": {"sha": VECTOR["source"]["commit"]["sha"]}}
    context = AssuranceContext.model_validate(document)
    assert context.organization_scope.environment is None
    assert context.source is not None and context.source.repository is None


def test_a_redacted_name_is_accepted_where_a_name_may_have_been_redacted() -> None:
    marker = {"__redacted": True, "reason": "sensitive_value_reuse", "present": True, "type": "string"}
    document = copy.deepcopy(VECTOR)
    document["resource"]["name"] = marker
    document["resource"]["related"] = [
        {
            "address": marker,
            "type": marker,
            "relation": "configures",
            "via": [marker],
            "resource": None,
            "tool_data": {"tool": "terraform", "match": "instance"},
        }
    ]
    document["resource"]["tool_data"]["action_reason"] = marker
    AssuranceContext.model_validate(document)
    document["resource"]["id"] = marker
    with pytest.raises(ValidationError, match="resource.id"):
        AssuranceContext.model_validate(document)


def test_a_long_terraform_address_is_accepted_where_an_id_would_not_be() -> None:
    document = copy.deepcopy(VECTOR)
    address = "module." + ("x" * 300) + '["k"].aws_db_instance.payments'
    document["subject"]["identities"][0]["value"] = address
    identities = [Identity.model_validate(document["subject"]["identities"][0])]
    document["subject"]["key"] = subject_key("resource", identities)
    document["resource"]["id"] = address
    AssuranceContext.model_validate(document)
    document["organization_scope"]["environment"]["name"] = "x" * 257
    with pytest.raises(ValidationError, match="at most 256"):
        AssuranceContext.model_validate(document)


def test_the_deployment_is_refused_outside_its_profile() -> None:
    document = copy.deepcopy(VECTOR)
    document["deployment"] = POST_DEPLOY["deployment"]
    with pytest.raises(ValidationError, match="not part of this profile: deployment"):
        AssuranceContext.model_validate(document)


def test_a_replan_is_a_plan_other_than_the_evaluated_one() -> None:
    document = copy.deepcopy(POST_DEPLOY)
    document["deployment"]["superseded_by"] = {"reason": "dependency_replanned"}
    with pytest.raises(ValidationError, match="a re-plan is a plan other than the evaluated one"):
        AssuranceContext.model_validate(document)
    document["deployment"]["plan"]["digest"] = "sha256:" + "b" * 64
    context = AssuranceContext.model_validate(document)
    assert isinstance(context.deployment, Deployment) and context.deployment.superseded_by is not None


@pytest.mark.parametrize("part", ["plan", "deployment"])
@pytest.mark.parametrize(
    ("digest", "basis"),
    [(None, "saved_plan"), ("sha256:" + "d" * 64, "not_provided")],
    ids=["saved plan without digest", "digest without saved plan"],
)
def test_an_artifact_digest_is_present_exactly_when_a_saved_plan_was_given(part: str, digest: Any, basis: str) -> None:
    document = copy.deepcopy(POST_DEPLOY)
    target = document["plan"] if part == "plan" else document["deployment"]["plan"]
    target.update(artifact_digest=digest, artifact_digest_source=basis)
    with pytest.raises(ValidationError, match="present exactly when artifact_digest_source is saved_plan"):
        AssuranceContext.model_validate(document)


def test_a_plan_digest_version_other_than_its_tools_is_refused() -> None:
    document = copy.deepcopy(POST_DEPLOY)
    document["plan"]["digest_version"] = "2"
    with pytest.raises(ValidationError, match="is not the version of the terraform plan digest rule"):
        AssuranceContext.model_validate(document)


PRE_DEPLOY: dict[str, Any] = json.loads(
    (VECTORS / "contexts" / "iac" / "pre_deploy_change.json").read_text(encoding="utf-8")
)
MARKER = {"__unknown": True, "reason": "server_facts_unavailable"}


@pytest.mark.parametrize("part", ["evaluations", "approvals", "exceptions"])
def test_a_server_fact_is_a_list_or_the_unknown_marker(part: str) -> None:
    assert PRE_DEPLOY[part] == MARKER
    AssuranceContext.model_validate(PRE_DEPLOY)
    AssuranceContext.model_validate({**PRE_DEPLOY, part: []})
    with pytest.raises(ValidationError):
        AssuranceContext.model_validate({**PRE_DEPLOY, part: {**MARKER, "reason": "redacted"}})
    with pytest.raises(ValidationError):
        AssuranceContext.model_validate({**PRE_DEPLOY, part: {"__redacted": True}})


@pytest.mark.parametrize("production", [True, False, {"__unknown": True, "reason": "server_facts_unavailable"}])
def test_the_environment_says_whether_it_is_production_or_that_nobody_knows(production: object) -> None:
    environment = {"name": "production", "production": production}
    AssuranceContext.model_validate(
        {**VECTOR, "organization_scope": {**VECTOR["organization_scope"], "environment": environment}}
    )


@pytest.mark.parametrize("production", [None, "yes"], ids=["null", "text"])
def test_an_environment_without_a_production_answer_is_refused(production: object) -> None:
    environment = {"name": "production", "production": production}
    with pytest.raises(ValidationError, match="production"):
        AssuranceContext.model_validate(
            {**VECTOR, "organization_scope": {**VECTOR["organization_scope"], "environment": environment}}
        )


def test_only_a_pre_deploy_input_names_the_run_it_belongs_to() -> None:
    assert PRE_DEPLOY["run"]["id"]
    without = {key: value for key, value in PRE_DEPLOY.items() if key != "run"}
    with pytest.raises(ValidationError, match="pre_deploy_change: missing run"):
        AssuranceContext.model_validate(without)
    with pytest.raises(ValidationError, match="plan_resource: not part of this profile: run"):
        AssuranceContext.model_validate({**VECTOR, "run": PRE_DEPLOY["run"]})


UNMAPPED = {"__unknown": True, "reason": "kind_unmapped"}


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        ({"provider": "aws", "type": "aws_kms_key", "kind": None}, "other than the one the terraform table gives"),
        (
            {"provider": "aws", "type": "aws_kms_key", "kind": "iam_role"},
            "other than the one the terraform table gives",
        ),
        ({"provider": "aws", "type": "aws_kms_key", "kind": UNMAPPED}, "other than the one the terraform table gives"),
        ({"provider": "aws", "type": "aws_new_thing", "kind": "kms_key"}, "other than the one the terraform table"),
        ({"provider": "google", "type": "google_kms_key", "kind": "kms_key"}, "other than the one the terraform table"),
        ({"provider": "hashicorp/aws", "type": "aws_kms_key", "kind": "kms_key"}, "String should match pattern"),
    ],
    ids=[
        "no kind for a type the table holds",
        "another kind than the table's",
        "the marker for a type the table holds",
        "a kind for a type the table lacks",
        "a kind for a provider with no kinds",
        "a long provider",
    ],
)
def test_a_resource_names_the_kind_its_tools_table_gives_its_type(entry: dict[str, Any], message: str) -> None:
    resources = [{"id": "r.x", "action": "update", "module": None, **entry}]
    with pytest.raises(ValidationError, match=message):
        AssuranceContext.model_validate({**VECTOR, "change": {**VECTOR["change"], "resources": resources}})


@pytest.mark.parametrize(
    "entry",
    [
        {"provider": "aws", "type": "aws_kms_key", "kind": "kms_key"},
        {"provider": "aws", "type": "aws_new_thing", "kind": UNMAPPED},
        {"provider": "google", "type": "google_kms_key", "kind": None},
        {"provider": "google-beta", "type": "google_kms_key", "kind": None},
    ],
    ids=["the table's kind", "a type the table lacks", "a provider with no kinds", "a provider named with a hyphen"],
)
def test_a_resource_kind_is_the_tables_unknown_or_absent_for_a_provider_with_none(entry: dict[str, Any]) -> None:
    resources = [{"id": "r.x", "action": "update", "module": None, **entry}]
    AssuranceContext.model_validate({**VECTOR, "change": {**VECTOR["change"], "resources": resources}})


@pytest.mark.parametrize(
    "field", ["provider_source", "action_reason", "previous_address", "importing", "replace_paths"]
)
def test_what_only_the_tool_says_about_a_resource_is_under_tool_data(field: str) -> None:
    document = copy.deepcopy(VECTOR)
    document["resource"][field] = None
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        AssuranceContext.model_validate(document)


def test_a_related_resource_says_how_it_matched_under_tool_data() -> None:
    related: dict[str, Any] = {"address": "a.b", "type": "t", "relation": "configures", "via": [], "resource": None}
    document = copy.deepcopy(VECTOR)
    document["resource"]["related"] = [{**related, "match": "instance"}]
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        AssuranceContext.model_validate(document)


def test_a_plan_resource_names_the_kind_its_tools_table_gives_its_type() -> None:
    document = copy.deepcopy(VECTOR)
    document["resource"]["kind"] = "kms_key"
    with pytest.raises(ValidationError, match="other than the one the terraform table gives"):
        AssuranceContext.model_validate(document)


@pytest.mark.parametrize("provider", [None, "registry.terraform.io/hashicorp/aws"], ids=["none", "a source address"])
def test_a_plan_resource_names_its_providers_short_name(provider: str | None) -> None:
    document = copy.deepcopy(VECTOR)
    document["resource"]["provider"] = provider
    with pytest.raises(ValidationError, match="resource.provider"):
        AssuranceContext.model_validate(document)


@pytest.mark.parametrize(
    ("provider", "type_", "kind"),
    [("aws", "aws_new_thing", UNMAPPED), ("google", "google_kms_key", None)],
    ids=["a type the table lacks", "a provider with no kinds"],
)
def test_a_plan_resource_kind_is_unknown_or_absent_where_the_table_gives_none(
    provider: str, type_: str, kind: dict[str, Any] | None
) -> None:
    document = copy.deepcopy(VECTOR)
    document["resource"].update(provider=provider, type=type_, kind=kind)
    AssuranceContext.model_validate(document)


@pytest.mark.parametrize(
    ("time", "message"),
    [
        ({"trust": "attested"}, "only ever asserted"),
        ({"source": "timestamp_authority", "trust": "attested"}, "exactly when a timestamp authority"),
        (
            {
                "time_window": {
                    "not_before": "2026-09-16T18:04:00Z",
                    "not_after": "2026-09-16T18:06:00Z",
                    "nonce_digest": "sha256:" + "a" * 64,
                }
            },
            "exactly when a timestamp authority",
        ),
    ],
    ids=["clock-attested", "authority-no-time-window", "clock-time-window"],
)
def test_a_reference_time_claims_no_more_than_its_source(time: dict[str, Any], message: str) -> None:
    document = {**VECTOR, "reference_time": {**VECTOR["reference_time"], **time}}
    with pytest.raises(ValidationError, match=message):
        AssuranceContext.model_validate(document)


def test_a_timestamp_authority_time_carries_its_time_window() -> None:
    time_window = {
        "not_before": "2026-09-16T18:04:00Z",
        "not_after": "2026-09-16T18:06:00Z",
        "nonce_digest": "sha256:" + "a" * 64,
    }
    time = {
        "value": "2026-09-16T18:05:00Z",
        "source": "timestamp_authority",
        "trust": "attested",
        "time_window": time_window,
    }
    AssuranceContext.model_validate({**VECTOR, "reference_time": time})


@pytest.mark.parametrize(
    ("not_before", "not_after"),
    [("2026-09-16T18:06:00Z", "2026-09-16T18:04:00Z"), ("2026-09-16T18:05:30Z", "2026-09-16T18:06:00Z")],
    ids=["reversed", "time-before-window"],
)
def test_a_timestamp_authority_time_lies_inside_its_time_window(not_before: str, not_after: str) -> None:
    time_window = {"not_before": not_before, "not_after": not_after, "nonce_digest": "sha256:" + "a" * 64}
    time = {
        "value": "2026-09-16T18:05:00Z",
        "source": "timestamp_authority",
        "trust": "attested",
        "time_window": time_window,
    }
    with pytest.raises(ValidationError, match="inside its time window"):
        AssuranceContext.model_validate({**VECTOR, "reference_time": time})


def _set(document: dict[str, Any], path: tuple[str | int, ...], value: Any) -> dict[str, Any]:
    node: Any = document
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return document


RELATED: dict[str, Any] = {
    "address": "aws_db_parameter_group.payments",
    "type": "aws_db_parameter_group",
    "relation": "configures",
    "via": [],
    "resource": None,
    "tool_data": {"tool": "terraform", "match": "instance"},
}


@pytest.mark.parametrize("name", ["plan_resource.json", "pre_deploy_change.json"], ids=["resource", "change"])
def test_the_change_digest_is_the_digest_of_its_units_plan(name: str) -> None:
    document = json.loads((VECTORS / "contexts" / "iac" / name).read_text(encoding="utf-8"))
    with pytest.raises(
        ValidationError, match="change.digest is the digest of the change type, unit, environment and plan"
    ):
        AssuranceContext.model_validate(_set(document, ("change", "digest"), "sha256:" + "a" * 64))


@pytest.mark.parametrize(
    "path",
    [
        ("change", "digest"),
        ("change", "resources", 0, "type"),
        ("resource", "type"),
        ("resource", "name"),
        ("resource", "tool_data", "provider_source"),
        ("resource", "related", 0, "type"),
    ],
    ids=lambda path: ".".join(map(str, path)),
)
def test_a_fact_the_stage_always_knows_is_never_null(path: tuple[str | int, ...]) -> None:
    document = copy.deepcopy(VECTOR)
    document["resource"]["related"] = [copy.deepcopy(RELATED)]
    AssuranceContext.model_validate(document)
    with pytest.raises(ValidationError, match=re.escape(".".join(map(str, path)))):
        AssuranceContext.model_validate(_set(document, path, None))


NOT_REPORTED = {"__unknown": True, "reason": "not_reported_by_tool"}


@pytest.mark.parametrize("flag", ["complete", "applyable", "tool_version"])
def test_a_plan_fact_the_tool_did_not_report_is_the_unknown_marker_never_null(flag: str) -> None:
    AssuranceContext.model_validate(_set(copy.deepcopy(VECTOR), ("plan", flag), NOT_REPORTED))
    with pytest.raises(ValidationError, match=f"plan.{flag}"):
        AssuranceContext.model_validate(_set(copy.deepcopy(VECTOR), ("plan", flag), None))


@pytest.mark.parametrize(
    ("path", "reason"),
    [
        (("plan", "complete"), "server_facts_unavailable"),
        (("approvals",), "not_reported_by_tool"),
        (("organization_scope", "environment", "production"), "not_reported_by_tool"),
    ],
    ids=["a plan flag", "a server fact", "production"],
)
def test_an_unknown_marker_carries_only_the_reason_its_field_can_have(path: tuple[str, ...], reason: str) -> None:
    document = json.loads((VECTORS / "contexts" / "iac" / "pre_deploy_change.json").read_text(encoding="utf-8"))
    with pytest.raises(ValidationError, match=re.escape(".".join(path))):
        AssuranceContext.model_validate(_set(document, path, {"__unknown": True, "reason": reason}))


def test_every_marker_reason_is_a_reason_an_unknown_status_can_give() -> None:
    markers = (NotReported, KindNotMapped, ApplyLogIncomplete, StateNotRead)
    reasons = {get_args(model.model_fields["reason"].annotation)[0] for model in markers}
    assert reasons | set(get_args(UnknownReason)) <= STATUS_REASONS["unknown"]


POST_VERIFY: dict[str, Any] = json.loads(
    (VECTORS / "contexts" / "iac" / "post_verify.json").read_text(encoding="utf-8")
)


def test_a_post_verify_input_carries_its_drift_check() -> None:
    document = copy.deepcopy(POST_VERIFY)
    assert AssuranceContext.model_validate(document).drift_check is not None
    document["drift_check"] = None
    with pytest.raises(ValidationError, match="post_verify: missing drift_check"):
        AssuranceContext.model_validate(document)


def test_a_post_verify_input_takes_a_drift_check_read_in_the_second_the_apply_ended() -> None:
    document = copy.deepcopy(POST_VERIFY)
    document["deployment"]["apply"]["timing"]["ended_at"] = "2026-09-16T18:40:30.285Z"
    assert AssuranceContext.model_validate(document).drift_check is not None


def test_a_post_verify_input_refuses_a_drift_check_read_before_the_apply_ended() -> None:
    document = copy.deepcopy(POST_VERIFY)
    document["drift_check"].update(first_reading_at="2026-09-16T18:38:30Z", second_reading_at="2026-09-16T18:39:30Z")
    with pytest.raises(ValidationError, match="first reading was taken no earlier than the second the apply ended in"):
        AssuranceContext.model_validate(document)


BUILD: dict[str, Any] = json.loads((VECTORS / "contexts" / "image" / "plan_artifact.json").read_text(encoding="utf-8"))


def test_a_build_input_carries_its_image_its_reports_and_the_verified_commit() -> None:
    context = AssuranceContext.model_validate(BUILD)
    assert context.evaluation.activity == "image_build" and context.subject is not None
    assert context.subject.kind == "artifact" and context.artifact is not None
    named = {name for name, part in BUILD.items() if part is not None}
    assert named - {"apiVersion", "evaluation", "organization_scope", "reference_time"} == {
        "source",
        "subject",
        "artifact",
        "tests",
        "scans",
        "verified_source",
        "attestation_outcome",
    }


@pytest.mark.parametrize("name", ["artifact", "tests", "scans", "verified_source", "attestation_outcome"])
def test_a_build_input_missing_a_part_is_refused_by_name(name: str) -> None:
    with pytest.raises(ValidationError, match=f"plan_artifact: missing {name}"):
        AssuranceContext.model_validate({**BUILD, name: None})


def test_a_build_input_may_have_no_reports_but_says_so() -> None:
    assert AssuranceContext.model_validate({**BUILD, "tests": [], "scans": []}).tests == []


def test_a_build_input_holds_the_marker_where_no_server_verified_the_commit() -> None:
    marker = {"__unknown": True, "reason": "server_facts_unavailable"}
    assert AssuranceContext.model_validate({**BUILD, "verified_source": marker}).verified_source is not None
    assert AssuranceContext.model_validate({**BUILD, "attestation_outcome": marker}).attestation_outcome is not None


def test_a_build_input_says_whether_an_attestation_was_verified_refused_or_not_sent() -> None:
    checked = BUILD["attestation_outcome"]
    refused = {
        "outcome": "refused",
        "attestation_digest": checked["attestation_digest"],
        "trust_root": checked["trust_root"],
        "verifier": checked["verifier"],
        "verified_at": checked["verified_at"],
        "reason": "signature_invalid",
    }
    assert AssuranceContext.model_validate({**BUILD, "attestation_outcome": refused}).attestation_outcome is not None
    not_sent = {"outcome": "not_sent"}
    assert AssuranceContext.model_validate({**BUILD, "attestation_outcome": not_sent}).attestation_outcome is not None
    with pytest.raises(ValidationError):
        AssuranceContext.model_validate({**BUILD, "attestation_outcome": {**refused, "reason": "expired"}})


def test_a_build_inputs_commit_is_the_builds_own_and_may_differ_from_the_checkout() -> None:
    artifact = {**BUILD["artifact"], "build_commit": "d" * 40}
    assert AssuranceContext.model_validate({**BUILD, "artifact": artifact}).artifact is not None
    unknown = {**BUILD["artifact"], "build_commit": {"__unknown": True, "reason": "not_reported_by_tool"}}
    AssuranceContext.model_validate({**BUILD, "artifact": unknown})


def test_an_input_is_checked_against_the_profile_of_its_own_activity() -> None:
    evaluation = {**BUILD["evaluation"], "activity": "iac_change"}
    with pytest.raises(ValidationError, match="not valid for target kind 'artifact' in an iac_change input"):
        AssuranceContext.model_validate({**BUILD, "evaluation": evaluation})
    evaluation = {**VECTOR["evaluation"], "activity": "image_build"}
    with pytest.raises(ValidationError, match="not valid for target kind 'resource' in an image_build input"):
        AssuranceContext.model_validate({**VECTOR, "evaluation": evaluation})


def test_a_build_input_names_no_environment() -> None:
    scope = {**BUILD["organization_scope"], "environment": {"name": "production", "production": True}}
    with pytest.raises(ValidationError, match="a build's input names no environment"):
        AssuranceContext.model_validate({**BUILD, "organization_scope": scope})


DEPLOY: dict[str, Any] = json.loads((VECTORS / "contexts" / "image" / "post_verify.json").read_text(encoding="utf-8"))


def test_a_deploy_input_reads_its_parts_in_the_deploys_shapes() -> None:
    context = AssuranceContext.model_validate(DEPLOY)
    assert context.evaluation.activity == "image_deploy"
    assert type(context.change).__name__ == "ImageChange" and type(context.drift_check).__name__ == "ImageDriftCheck"
    evaluation = {**DEPLOY["evaluation"], "activity": "iac_change"}
    with pytest.raises(ValidationError, match="change.resources"):
        AssuranceContext.model_validate({**DEPLOY, "evaluation": evaluation})


def test_a_deploy_inputs_change_digest_is_of_its_image_in_its_unit_and_environment() -> None:
    scope = {**DEPLOY["organization_scope"], "environment": {"name": "staging", "production": False}}
    with pytest.raises(
        ValidationError, match="change.digest is the digest of the change type, unit, environment and image"
    ):
        AssuranceContext.model_validate({**DEPLOY, "organization_scope": scope})


def test_a_deploy_inputs_reading_names_its_change() -> None:
    check = {**DEPLOY["drift_check"], "change_digest": "sha256:" + "7" * 64}
    with pytest.raises(ValidationError, match="drift_check.change_digest is change.digest"):
        AssuranceContext.model_validate({**DEPLOY, "drift_check": check})


def test_an_input_that_reads_its_runners_clock_uses_the_time_of_its_evaluation() -> None:
    later = {**VECTOR["reference_time"], "value": "2026-09-16T18:05:01Z"}
    with pytest.raises(ValidationError, match="an input that reads its runner's clock uses the time of its evaluation"):
        AssuranceContext.model_validate({**VECTOR, "reference_time": later})
    same_instant = {**VECTOR["reference_time"], "value": "2026-09-16T18:05:00.000Z"}
    AssuranceContext.model_validate({**VECTOR, "reference_time": same_instant})


POST_VERIFY_CONTEXT: dict[str, Any] = json.loads(
    (VECTORS / "contexts" / "iac" / "post_verify.json").read_text(encoding="utf-8")
)


def test_the_assurance_part_is_any_object_held_to_the_bounds_of_a_policys_observations() -> None:
    AssuranceContext.model_validate({**POST_VERIFY_CONTEXT, "assurance": {"checked": ["drift"]}})
    with pytest.raises(ValidationError, match="must be at most"):
        AssuranceContext.model_validate({**POST_VERIFY_CONTEXT, "assurance": {"text": "a" * OBSERVATIONS_MAX_BYTES}})
    with pytest.raises(ValidationError, match="must not contain control characters"):
        AssuranceContext.model_validate({**POST_VERIFY_CONTEXT, "assurance": {"text": "a\u0000"}})
