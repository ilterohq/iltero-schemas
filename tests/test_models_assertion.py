from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.assertion import (
    DERIVED_TYPE,
    VALID_COMBINATIONS,
    AssertionType,
    Stage,
    TargetKind,
    TechnicalAssertion,
)


def _document(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "apiVersion": "iltero.io/v1",
        "kind": "TechnicalAssertion",
        "metadata": {"id": "ACME.AWS.RDS.ENCRYPTED", "version": "1.0.0", "title": "RDS encrypted"},
        "spec": {
            "stage": "plan",
            "target": {
                "kind": "resource",
                "resources": [{"tool": "terraform", "provider": "aws", "resource_types": ["aws_db_instance"]}],
            },
            "assert": {"path": "resource.after.storage_encrypted", "equal": True},
        },
    }
    for key, value in overrides.items():
        section, _, field = key.partition("__")
        if field:
            document[section][field] = value
        else:
            document[section] = value
    return document


def _error_locations(document: dict[str, Any]) -> list[str]:
    with pytest.raises(ValidationError) as raised:
        TechnicalAssertion.model_validate(document)
    return [".".join(str(p) for p in e["loc"]) for e in raised.value.errors()]


def test_a_minimal_document_validates_and_type_is_derived() -> None:
    model = TechnicalAssertion.model_validate(_document())
    assert model.spec.type is None
    assert model.spec.derived_type is AssertionType.STATE


def test_every_target_kind_has_a_derived_type() -> None:
    assert set(DERIVED_TYPE) == set(TargetKind)


def test_explicit_type_must_match_the_derived_one() -> None:
    document = _document()
    document["spec"]["type"] = "state"
    TechnicalAssertion.model_validate(document)
    document["spec"]["type"] = "process"
    assert _error_locations(document) == ["spec"]


@pytest.mark.parametrize("stage", list(Stage))
@pytest.mark.parametrize("kind", list(TargetKind))
def test_only_listed_stage_and_target_combinations_are_accepted(stage: Stage, kind: TargetKind) -> None:
    target: dict[str, Any] = {"kind": kind.value}
    if kind is TargetKind.RESOURCE:
        target["resources"] = [{"tool": "terraform", "provider": "aws", "resource_types": ["aws_db_instance"]}]
    document = _document(spec__stage=stage.value, spec__target=target)
    allowed = (DERIVED_TYPE[kind], stage, kind) in VALID_COMBINATIONS
    if allowed:
        TechnicalAssertion.model_validate(document)
    else:
        assert _error_locations(document) == ["spec"]


def test_unknown_keys_are_refused_at_every_level() -> None:
    assert _error_locations({**_document(), "registry": {}}) == ["registry"]
    assert _error_locations(_document(metadata__owner="x")) == ["metadata.owner"]
    assert _error_locations(_document(spec__severity="high")) == ["spec.severity"]
    assert _error_locations(_document(spec__target={"kind": "change", "provider": "aws"})) == [
        "spec.target.change.provider"
    ]


def test_provider_and_resource_type_lengths_are_bounded() -> None:
    long_provider = {
        "kind": "resource",
        "resources": [{"tool": "terraform", "provider": "a" * 33, "resource_types": ["a"]}],
    }
    assert _error_locations(_document(spec__target=long_provider)) == ["spec.target.resource.resources.0.provider"]
    long_type = {
        "kind": "resource",
        "resources": [{"tool": "terraform", "provider": "aws", "resource_types": ["a" * 129]}],
    }
    assert _error_locations(_document(spec__target=long_type)) == ["spec.target.resource.resources.0.resource_types.0"]
    many = {
        "kind": "resource",
        "resources": [{"tool": "terraform", "provider": "aws", "resource_types": [f"t{i}" for i in range(65)]}],
    }
    assert _error_locations(_document(spec__target=many)) == ["spec.target.resource.resources.0.resource_types"]


@pytest.mark.parametrize("value", ["iltero.io/v2", "v1", ""])
def test_api_version_and_kind_are_fixed(value: str) -> None:
    assert _error_locations({**_document(), "apiVersion": value}) == ["apiVersion"]
    assert _error_locations({**_document(), "kind": value}) == ["kind"]


@pytest.mark.parametrize(
    ("assertion_id", "location"),
    [
        ("ILT", "metadata.id"),
        ("ilt.aws.x", "metadata.id"),
        ("ILT..X", "metadata.id"),
        ("1ILT.X", "metadata.id"),
        ("ILT.X-Y", "metadata.id"),
        ("A" * 129 + ".B", "metadata.id"),
        ("CON.AWS.X", "metadata"),
        ("COM1.X", "metadata"),
        ("NUL.X.Y", "metadata"),
    ],
)
def test_id_grammar_and_device_names(assertion_id: str, location: str) -> None:
    assert _error_locations(_document(metadata__id=assertion_id)) == [location]


@pytest.mark.parametrize("version", ["1", "1.0", "v1.0.0", "01.0.0", "1.0.0-rc1", "", "1.0." + "9" * 30])
def test_version_is_a_semantic_version_core(version: str) -> None:
    assert _error_locations(_document(metadata__version=version)) == ["metadata.version"]


@pytest.mark.parametrize("title", ["", "   ", "line\nbreak", "x" * 201])
def test_title_is_a_bounded_single_line(title: str) -> None:
    assert _error_locations(_document(metadata__title=title))[0].startswith("metadata")


def test_resource_target_needs_provider_and_unique_types() -> None:
    assert _error_locations(_document(spec__target={"kind": "resource", "resource_types": ["a"]}))
    assert _error_locations(
        _document(
            spec__target={
                "kind": "resource",
                "resources": [{"tool": "terraform", "provider": "aws", "resource_types": []}],
            }
        )
    )
    assert _error_locations(
        _document(
            spec__target={
                "kind": "resource",
                "resources": [{"tool": "terraform", "provider": "aws", "resource_types": ["a", "a"]}],
            }
        )
    )
    assert _error_locations(
        _document(
            spec__target={
                "kind": "resource",
                "resources": [{"tool": "terraform", "provider": "AWS", "resource_types": ["a"]}],
            }
        )
    )
    assert _error_locations(
        _document(
            spec__target={
                "kind": "resource",
                "resources": [{"tool": "terraform", "provider": "aws", "resource_types": ["Aws-x"]}],
            }
        )
    )


def test_a_resource_target_names_a_known_iac_tool() -> None:
    selector = {"provider": "aws", "resource_types": ["aws_db_instance"]}
    without = {"kind": "resource", "resources": [selector]}
    assert _error_locations(_document(spec__target=without)) == ["spec.target.resource.resources.0.tool"]
    unknown = {"kind": "resource", "resources": [{**selector, "tool": "pulumi"}]}
    assert _error_locations(_document(spec__target=unknown)) == ["spec.target.resource.resources.0.tool"]


@pytest.mark.parametrize("resource_type", ["AWS::S3::Bucket", "aws_db_instance\n"], ids=["another tool's", "newline"])
def test_resource_types_follow_the_rule_of_the_tool_the_target_names(resource_type: str) -> None:
    target = {
        "kind": "resource",
        "resources": [{"tool": "terraform", "provider": "aws", "resource_types": [resource_type]}],
    }
    assert _error_locations(_document(spec__target=target)) == ["spec.target.resource.resources.0"]


def test_target_kind_is_closed() -> None:
    assert _error_locations(_document(spec__target={"kind": "policy"})) == ["spec.target"]


def test_models_are_immutable() -> None:
    model = TechnicalAssertion.model_validate(_document())
    with pytest.raises(ValidationError):
        model.metadata.id = "X.Y"


def test_a_kind_selector_names_kinds_its_provider_lists() -> None:
    target = {"kind": "change", "resources": [{"provider": "aws", "kinds": ["kms_key", "iam_policy"]}]}
    TechnicalAssertion.model_validate(_document(spec__stage="pre_deploy", spec__target=target))
    for selector, location in (
        ({"provider": "aws", "kinds": ["warp_drive"]}, "spec.target.change.resources.0"),
        ({"provider": "acme", "kinds": ["thing"]}, "spec.target.change.resources.0"),
        ({"provider": "aws", "kinds": ["kms_key", "kms_key"]}, "spec.target.change.resources.0"),
    ):
        document = _document(spec__stage="pre_deploy", spec__target={"kind": "change", "resources": [selector]})
        assert _error_locations(document) == [location]


def test_a_resource_target_names_exactly_one_selector() -> None:
    selector = {"tool": "terraform", "provider": "aws", "resource_types": ["aws_db_instance"]}
    for resources in ([], [selector, selector]):
        target = {"kind": "resource", "resources": resources}
        assert _error_locations(_document(spec__target=target)) == ["spec.target.resource.resources"]


def test_an_assurance_target_names_no_resources() -> None:
    target = {"kind": "assurance", "resources": [{"provider": "aws", "kinds": ["rds_instance"]}]}
    assert _error_locations(_document(spec__stage="post_verify", spec__target=target)) == ["spec.target.assurance"]


def test_a_resource_target_names_its_tools_types_and_a_change_target_names_kinds() -> None:
    kinds = {"kind": "resource", "resources": [{"provider": "aws", "kinds": ["rds_instance"]}]}
    assert "spec.target.resource.resources.0.kinds" in _error_locations(_document(spec__target=kinds))
    tool = {
        "kind": "change",
        "resources": [{"tool": "terraform", "provider": "aws", "resource_types": ["aws_kms_key"]}],
    }
    document = _document(spec__stage="pre_deploy", spec__target=tool)
    assert "spec.target.change.resources.0.tool" in _error_locations(document)


def test_a_scoped_target_has_a_change_to_scope() -> None:
    target = {"kind": "deployment", "resources": [{"provider": "aws", "kinds": ["rds_instance"]}]}
    TechnicalAssertion.model_validate(_document(spec__stage="post_deploy", spec__target=target))
    assert _error_locations(_document(spec__stage="post_verify", spec__target=target)) == ["spec"]


def test_a_provider_short_name_may_hold_a_hyphen() -> None:
    selector = {"tool": "terraform", "provider": "google-beta", "resource_types": ["google_compute_instance"]}
    TechnicalAssertion.model_validate(_document(spec__target={"kind": "resource", "resources": [selector]}))
    for provider in ("-aws", "Aws", "hashicorp/aws"):
        target = {"kind": "resource", "resources": [{**selector, "provider": provider}]}
        assert _error_locations(_document(spec__target=target)) == ["spec.target.resource.resources.0.provider"]
