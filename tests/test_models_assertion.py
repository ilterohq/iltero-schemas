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
            "target": {"kind": "resource", "provider": "aws", "resource_types": ["aws_db_instance"]},
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
        target.update(provider="aws", resource_types=["aws_db_instance"])
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
    long_provider = {"kind": "resource", "provider": "a" * 33, "resource_types": ["a"]}
    assert _error_locations(_document(spec__target=long_provider)) == ["spec.target.resource.provider"]
    long_type = {"kind": "resource", "provider": "aws", "resource_types": ["a" * 129]}
    assert _error_locations(_document(spec__target=long_type)) == ["spec.target.resource.resource_types.0"]
    many = {"kind": "resource", "provider": "aws", "resource_types": [f"t{i}" for i in range(65)]}
    assert _error_locations(_document(spec__target=many)) == ["spec.target.resource.resource_types"]


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
    assert _error_locations(_document(spec__target={"kind": "resource", "provider": "aws", "resource_types": []}))
    assert _error_locations(
        _document(spec__target={"kind": "resource", "provider": "aws", "resource_types": ["a", "a"]})
    )
    assert _error_locations(_document(spec__target={"kind": "resource", "provider": "AWS", "resource_types": ["a"]}))
    assert _error_locations(
        _document(spec__target={"kind": "resource", "provider": "aws", "resource_types": ["Aws-x"]})
    )


def test_target_kind_is_closed() -> None:
    assert _error_locations(_document(spec__target={"kind": "policy"})) == ["spec.target"]


def test_models_are_immutable() -> None:
    model = TechnicalAssertion.model_validate(_document())
    with pytest.raises(ValidationError):
        model.metadata.id = "X.Y"
