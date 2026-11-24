"""Which resources of a plan a stage leaves out, and which in scope no check reaches as reviewed."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.kinds.common.vocabulary import RESOURCE_KINDS
from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.common.coverage import Coverage, stage_outcome
from iltero_schemas.models.common.coverage_gaps import ProviderSourceGap
from iltero_schemas.models.iac.plan_coverage import (
    check_provider_source_gaps,
    plan_coverage_problems,
    plan_exclusions,
    provider_source_gap_kind,
    provider_source_gaps,
)
from iltero_schemas.models.iac.plan_exclusions import named_resource_types_of_targets
from iltero_schemas.models.iac.tools import terraform
from iltero_schemas.models.iac.tools.terraform import configured_address
from tests.conftest import VECTORS
from tests.iac.test_models_plan_exclusions import assertion_naming

TF, TOFU = "registry.terraform.io", "registry.opentofu.org"
# No assertion of the stage names a resource type.
NO_NAMED_TYPES: frozenset[tuple[str, str]] = frozenset()


def _change(address: str, source: str, mode: str = "managed", actions: tuple[str, ...] = ("create",)) -> dict[str, Any]:
    resource_type = address.split(".")[-2]
    return {
        "address": address,
        "mode": mode,
        "type": resource_type,
        "name": address.split(".")[-1],
        "provider_name": source,
        "change": {"actions": list(actions), "before": None, "after": {}},
    }


def _plan(*changes: dict[str, Any], provisioned: tuple[str, ...] = ()) -> dict[str, Any]:
    """A plan of ``changes``, whose root module declares each of them, those at ``provisioned`` with a provisioner."""
    declared = {configured_address(change["address"]) for change in changes if "module." not in change["address"]}
    resources = [
        {"address": address, **({"provisioners": [{"type": "local-exec"}]} if address in provisioned else {})}
        for address in sorted(declared)
    ]
    return {"resource_changes": list(changes), "configuration": {"root_module": {"resources": resources}}}


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (_change("random_id.suffix", f"{TF}/hashicorp/random"), "makes_no_outside_object"),
        (_change("random_password.db", f"{TOFU}/hashicorp/random"), "makes_no_outside_object"),
        (_change("time_rotating.key", f"{TF}/hashicorp/time"), "makes_no_outside_object"),
        (_change("null_resource.plain", f"{TF}/hashicorp/null"), "makes_no_outside_object"),
        (_change("terraform_data.plain", "terraform.io/builtin/terraform"), "makes_no_outside_object"),
        (_change("random_id.custom", "example.com/acme/random"), None),
        (_change("tls_private_key.k", f"{TF}/hashicorp/tls"), None),
        (_change("local_file.f", f"{TF}/hashicorp/local"), None),
        (_change("aws_s3_bucket.b", "aws"), "identity_unnameable"),
        (_change("aws_s3_bucket.b", "hashicorp/aws"), "identity_unnameable"),
    ],
    ids=[
        "random on Terraform's registry",
        "random on OpenTofu's registry",
        "time",
        "null_resource without a provisioner",
        "terraform_data without a provisioner",
        "random from another host",
        "tls",
        "local",
        "a provider with no host",
        "a provider with no host but a namespace",
    ],
)
def test_a_resource_that_creates_no_outside_object_is_left_out_and_any_other_is_not(
    change: dict[str, Any], reason: str | None
) -> None:
    excluded = plan_exclusions("terraform", _plan(change), NO_NAMED_TYPES)
    assert [entry.reason for entry in excluded] == ([reason] if reason else [])


def test_a_null_resource_or_terraform_data_the_configuration_gives_a_provisioner_stays_in_scope() -> None:
    plan = _plan(
        _change("null_resource.ran[0]", f"{TF}/hashicorp/null"),
        _change('module.m["a"].terraform_data.ran', "terraform.io/builtin/terraform"),
        provisioned=("null_resource.ran",),
    )
    plan["configuration"]["root_module"]["module_calls"] = {
        "m": {"module": {"resources": [{"address": "terraform_data.ran", "provisioners": [{"type": "local-exec"}]}]}}
    }
    assert plan_exclusions("terraform", plan, NO_NAMED_TYPES) == []


@pytest.mark.parametrize(
    "change",
    [_change("random_id.ran", f"{TF}/hashicorp/random"), _change("time_sleep.ran", f"{TF}/hashicorp/time")],
    ids=["random", "time"],
)
def test_any_resource_the_configuration_gives_a_provisioner_or_does_not_declare_stays_in_scope(
    change: dict[str, Any],
) -> None:
    assert plan_exclusions("terraform", _plan(change, provisioned=(change["address"],)), NO_NAMED_TYPES) == []
    undeclared = _plan(change)
    undeclared["configuration"]["root_module"]["resources"] = []
    assert plan_exclusions("terraform", undeclared, NO_NAMED_TYPES) == []


def test_the_types_that_create_no_outside_object_belong_to_no_provider_with_resource_kinds() -> None:
    sources = [
        *terraform.TYPE_PREFIXES_THAT_MAKE_NO_OUTSIDE_OBJECT,
        *terraform.TYPES_THAT_MAKE_NO_OUTSIDE_OBJECT_WITHOUT_A_PROVISIONER,
    ]
    assert sources and not {terraform.provider_short_name(source) for source in sources} & RESOURCE_KINDS.keys()


def test_every_provider_with_resource_kinds_names_the_sources_its_table_was_reviewed_against() -> None:
    assert terraform.REVIEWED_PROVIDER_SOURCES.keys() == RESOURCE_KINDS.keys()


@pytest.mark.parametrize(
    ("source", "kind"),
    [
        (f"{TF}/hashicorp/aws", None),
        (f"{TOFU}/hashicorp/aws", None),
        ("example.com/acme/aws", "provider_source_not_reviewed"),
        (f"{TF}/hashicorp/awscc", "provider_has_no_resource_kinds"),
        ("aws", "provider_has_no_resource_kinds"),
    ],
)
def test_a_provider_source_is_reviewed_has_unreviewed_kinds_or_has_none(source: str, kind: str | None) -> None:
    assert provider_source_gap_kind("terraform", source) == kind


def test_the_resources_in_scope_no_check_reaches_as_reviewed_are_counted_by_kind_and_source() -> None:
    plan = _plan(
        _change("aws_s3_bucket.a", f"{TF}/hashicorp/aws"),
        _change("awscc_s3_bucket.b", f"{TF}/hashicorp/awscc"),
        _change("awscc_s3_bucket.c", f"{TF}/hashicorp/awscc"),
        _change("aws_s3_bucket.d", "example.com/acme/aws"),
        _change("random_id.e", f"{TF}/hashicorp/random"),
        _change("data.awscc_s3_bucket.f", f"{TF}/hashicorp/awscc", mode="data"),
    )
    gaps = provider_source_gaps("terraform", plan, plan_exclusions("terraform", plan, NO_NAMED_TYPES), NO_NAMED_TYPES)
    assert [(gap.kind, gap.provider_source, gap.count) for gap in gaps] == [
        ("provider_has_no_resource_kinds", f"{TF}/hashicorp/awscc", 2),
        ("provider_source_not_reviewed", "example.com/acme/aws", 1),
    ]


def test_a_resource_the_plan_deletes_or_forgets_is_no_subject_so_it_is_no_provider_source_gap() -> None:
    plan = _plan(
        _change("awscc_s3_bucket.deleted", f"{TF}/hashicorp/awscc", actions=("delete",)),
        _change("terraform_data.forgotten", "terraform.io/builtin/terraform", actions=("forget",)),
        _change("awscc_s3_bucket.replaced", f"{TF}/hashicorp/awscc", actions=("delete", "create")),
    )
    plan["configuration"]["root_module"]["resources"][-1]["provisioners"] = [{"type": "local-exec"}]
    gaps = provider_source_gaps("terraform", plan, plan_exclusions("terraform", plan, NO_NAMED_TYPES), NO_NAMED_TYPES)
    assert [(gap.kind, gap.provider_source, gap.count) for gap in gaps] == [
        ("provider_has_no_resource_kinds", f"{TF}/hashicorp/awscc", 1),
    ]


RECORD = json.loads((VECTORS / "records" / "iac" / "local_run.json").read_text(encoding="utf-8"))


def _gap(kind: str, source: str, count: int = 1) -> dict[str, Any]:
    return {"kind": kind, "provider_source": source, "count": count, "stage": None}


def _coverage(*gaps: dict[str, Any], **scope: Any) -> dict[str, Any]:
    coverage: dict[str, Any] = copy.deepcopy(RECORD["stages"]["plan"]["coverage"])
    coverage["gaps"] = [*coverage["gaps"], *gaps]
    coverage["subjects_in_scope"].update(scope)
    return coverage


@pytest.mark.parametrize(
    ("gaps", "scope", "message"),
    [
        (
            (_gap("provider_has_no_resource_kinds", "b"), _gap("provider_has_no_resource_kinds", "a")),
            {},
            "sorted by kind and source",
        ),
        (
            (_gap("provider_has_no_resource_kinds", "a"), _gap("provider_has_no_resource_kinds", "a")),
            {},
            "once for each kind of gap",
        ),
        ((_gap("provider_has_no_resource_kinds", "a", 10_000),), {}, "count no more resources than it has in scope"),
        ((_gap("provider_has_no_resource_kinds", "a", 0),), {}, "greater than or equal to 1"),
    ],
    ids=["out of order", "a source twice", "more than the subjects in scope", "a count of none"],
)
def test_a_stage_lists_its_provider_source_gaps_once_sorted_and_within_its_scope(
    gaps: tuple[dict[str, Any], ...], scope: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        Coverage.model_validate(_coverage(*gaps, **scope))


def test_a_provider_source_gap_and_its_reason_hold_for_a_stage_that_counted_the_plan_s_resources() -> None:
    coverage = Coverage.model_validate(
        _coverage(
            _gap("provider_has_no_resource_kinds", f"{TF}/hashicorp/awscc", 2),
            _gap("provider_source_not_reviewed", "example.com/acme/aws"),
        )
    )
    reasons = {reason.reason: reason.detail for reason in stage_outcome(coverage).evidence_status.reasons}
    assert reasons["provider_has_no_resource_kinds"] == (
        "2 plan resources in scope from 1 provider source with no resource kinds a check can name"
    )
    assert reasons["provider_source_not_reviewed"] == (
        "1 plan resource in scope from 1 provider source no reviewed kind table describes"
    )


def test_a_record_s_provider_source_gap_names_the_kind_its_source_gives() -> None:
    record = CAR.model_validate(RECORD)
    stage = record.stages[Stage.PLAN]
    wrong = ProviderSourceGap(kind="provider_has_no_resource_kinds", provider_source=f"{TF}/hashicorp/aws", count=1)
    coverage = stage.coverage.model_copy(update={"gaps": [*stage.coverage.gaps, wrong]})
    changed = record.model_copy(
        update={"stages": {**record.stages, Stage.PLAN: stage.model_copy(update={"coverage": coverage})}}
    )
    with pytest.raises(
        ValueError, match="lists registry.terraform.io/hashicorp/aws as a provider with no resource kinds"
    ):
        check_provider_source_gaps(changed, "terraform")


def test_a_stage_whose_exclusions_or_provider_gaps_differ_from_its_plan_s_is_listed() -> None:
    record = CAR.model_validate(RECORD)
    stage = record.stages[Stage.PLAN]
    plan = _plan(
        *[_change("aws_s3_bucket.a", f"{TF}/hashicorp/aws")] * stage.coverage.subjects_in_scope.value,
        _change("awscc_s3_bucket.b", f"{TF}/hashicorp/awscc"),
        _change("random_id.c", f"{TF}/hashicorp/random"),
    )
    assert plan_coverage_problems(record, Stage.PLAN, "terraform", plan, NO_NAMED_TYPES) == [
        ("stages.plan.coverage.subjects_in_scope.excluded", "is not what the plan it counted leaves out"),
        ("stages.plan.coverage.gaps", "does not list the provider source gaps the plan it counted gives"),
    ]


def test_a_provisioner_two_modules_down_keeps_its_resource_in_scope() -> None:
    plan = _plan(_change("module.a.module.b.null_resource.ran", f"{TF}/hashicorp/null"))
    inner = {"resources": [{"address": "null_resource.ran", "provisioners": [{"type": "local-exec"}]}]}
    plan["configuration"]["root_module"]["module_calls"] = {"a": {"module": {"module_calls": {"b": {"module": inner}}}}}
    assert plan_exclusions("terraform", plan, NO_NAMED_TYPES) == []


def test_a_null_resource_the_configuration_does_not_declare_stays_in_scope() -> None:
    plan = _plan(_change("module.gone.null_resource.x", f"{TF}/hashicorp/null"))
    assert plan_exclusions("terraform", plan, NO_NAMED_TYPES) == []


@pytest.mark.parametrize(
    "configuration",
    [
        [],
        {"root_module": []},
        {"root_module": {"module_calls": []}},
        {"root_module": {"module_calls": {"m": {"module": "text"}}}},
        {"root_module": {"resources": {"address": "null_resource.x"}}},
        {"root_module": {"resources": [{"address": 3, "provisioners": []}]}},
        {"root_module": {"resources": [{"address": "null_resource.x", "provisioners": "local-exec"}]}},
    ],
    ids=[
        "a list",
        "a root module that is a list",
        "module calls that are a list",
        "a call whose module is text",
        "resources that are an object",
        "an address that is a number",
        "provisioners that are text",
    ],
)
def test_a_configuration_of_the_wrong_shape_never_leaves_a_resource_that_may_run_a_command_out(
    configuration: Any,
) -> None:
    plan = {"resource_changes": [_change("null_resource.x", f"{TF}/hashicorp/null")], "configuration": configuration}
    assert plan_exclusions("terraform", plan, NO_NAMED_TYPES) == []


def test_a_resource_whose_type_an_assertion_names_stays_in_scope_and_is_no_provider_source_gap() -> None:
    plan = _plan(
        _change("random_password.db", f"{TF}/hashicorp/random"),
        _change("random_id.suffix", f"{TF}/hashicorp/random"),
    )
    named = named_resource_types_of_targets("terraform", [assertion_naming("random", "random_password").spec.target])
    excluded = plan_exclusions("terraform", plan, named)
    assert [(entry.id, entry.reason) for entry in excluded] == [("random_id.suffix", "makes_no_outside_object")]
    assert plan_exclusions("terraform", plan, NO_NAMED_TYPES) != excluded
    assert provider_source_gaps("terraform", plan, excluded, named) == []


def test_a_resource_from_an_unreviewed_source_stays_a_gap_although_an_assertion_names_its_type() -> None:
    plan = _plan(_change("aws_s3_bucket.fork", "example.com/acme/aws"))
    named = named_resource_types_of_targets("terraform", [assertion_naming("aws", "aws_s3_bucket").spec.target])
    gaps = provider_source_gaps("terraform", plan, plan_exclusions("terraform", plan, named), named)
    assert [(gap.kind, gap.provider_source) for gap in gaps] == [
        ("provider_source_not_reviewed", "example.com/acme/aws")
    ]
