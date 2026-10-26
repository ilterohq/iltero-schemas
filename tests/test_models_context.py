"""The context contract: the envelope, the parts, and that the parts present match the profile exactly."""

from __future__ import annotations

import copy
import json
import re
from typing import Any, get_args

import pytest
from pydantic import ValidationError

from iltero_schemas.models.context import API_VERSION, PARTS, AssuranceContext, KindNotMapped
from iltero_schemas.models.event import STATUS_REASONS
from iltero_schemas.models.facts import NotReported, UnknownReason
from iltero_schemas.models.fields import Identity
from iltero_schemas.models.subjects import subject_key
from iltero_schemas.profiles import PROFILES
from tests.conftest import POST_DEPLOY, VECTORS

VECTOR: dict[str, Any] = json.loads((VECTORS / "contexts" / "plan_resource.json").read_text(encoding="utf-8"))


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
    assert context.deployment is not None and context.deployment.superseded_by is not None


@pytest.mark.parametrize("part", ["plan", "deployment"])
@pytest.mark.parametrize(
    ("digest", "basis"),
    [(None, "saved_plan"), ("sha256:" + "d" * 64, "not_provided")],
    ids=["binary without digest", "digest without binary"],
)
def test_an_artifact_digest_is_present_exactly_when_a_binary_was_given(part: str, digest: Any, basis: str) -> None:
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


PRE_DEPLOY: dict[str, Any] = json.loads((VECTORS / "contexts" / "pre_deploy_change.json").read_text(encoding="utf-8"))
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
    document = json.loads((VECTORS / "contexts" / name).read_text(encoding="utf-8"))
    with pytest.raises(ValidationError, match="change.digest is the digest of its unit's plan"):
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
    document = json.loads((VECTORS / "contexts" / "pre_deploy_change.json").read_text(encoding="utf-8"))
    with pytest.raises(ValidationError, match=re.escape(".".join(path))):
        AssuranceContext.model_validate(_set(document, path, {"__unknown": True, "reason": reason}))


def test_every_marker_reason_is_a_reason_an_unknown_status_can_give() -> None:
    reasons = {get_args(model.model_fields["reason"].annotation)[0] for model in (NotReported, KindNotMapped)}
    assert reasons | set(get_args(UnknownReason)) <= STATUS_REASONS["unknown"]
