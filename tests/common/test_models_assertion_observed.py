"""An assertion observed by scanners: no condition of its own, the stages whose scanner results observe it, and its
description."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.ast import AssertionSyntaxError, parse_document, source_digest
from iltero_schemas.ast.nodes import to_json
from iltero_schemas.change_types.common.registry import ACTIVITIES
from iltero_schemas.models.common import assertion
from iltero_schemas.models.common.assertion import (
    DESCRIPTION_MAX_LENGTH,
    STAGES_WITH_SCANNER_RESULTS,
    Stage,
    TechnicalAssertion,
)
from tests.common.test_models_assertion import _document, _error_locations


def _observed(**spec: Any) -> dict[str, Any]:
    """An assertion with no condition of its own, observed by scanners at plan."""
    document = _document(spec__evidence={"stages": ["plan"]}, spec__assert=None)
    del document["spec"]["stage"]
    document["metadata"]["description"] = "An RDS instance whose storage the plan sets to encrypted."
    document["spec"].update(spec)
    return document


def test_an_assertion_observed_by_scanners_names_its_evidence_stages_and_no_condition() -> None:
    spec = TechnicalAssertion.model_validate(_observed()).spec
    assert spec.observed_by_scanners and spec.stage is None and spec.stages == (Stage.PLAN,)


def test_an_assertion_with_a_condition_is_not_observed_by_scanners_and_has_one_stage() -> None:
    spec = TechnicalAssertion.model_validate(_document()).spec
    assert not spec.observed_by_scanners and spec.evidence is None and spec.stages == (Stage.PLAN,)


def test_assert_is_always_written() -> None:
    document = _document()
    del document["spec"]["assert"]
    assert _error_locations(document) == ["spec.assert"]


def test_an_assertion_observed_by_scanners_names_no_stage() -> None:
    with pytest.raises(ValidationError, match="names evidence.stages and no stage"):
        TechnicalAssertion.model_validate(_observed(stage="plan"))


def test_an_assertion_observed_by_scanners_names_its_evidence() -> None:
    document = _observed()
    del document["spec"]["evidence"]
    with pytest.raises(ValidationError, match="names evidence.stages and no stage"):
        TechnicalAssertion.model_validate(document)


def test_an_assertion_with_a_condition_names_no_evidence() -> None:
    with pytest.raises(ValidationError, match="names its stage and no evidence"):
        TechnicalAssertion.model_validate(_document(spec__evidence={"stages": ["plan"]}))


def test_an_assertion_observed_by_scanners_is_about_a_resource() -> None:
    document = _observed(target={"kind": "change"})
    with pytest.raises(ValidationError, match="only a resource is scanned"):
        TechnicalAssertion.model_validate(document)


def test_evidence_stages_are_in_lifecycle_order_each_once() -> None:
    with pytest.raises(ValidationError, match="stages are in lifecycle order, each stage once"):
        TechnicalAssertion.model_validate(_observed(evidence={"stages": ["plan", "plan"]}))


def test_evidence_names_at_least_one_stage() -> None:
    assert _error_locations(_observed(evidence={"stages": []})) == ["spec.evidence.stages"]


def test_a_stage_written_as_null_is_refused_on_an_assertion_observed_by_scanners() -> None:
    with pytest.raises(ValidationError, match="names evidence.stages and no stage"):
        TechnicalAssertion.model_validate(_observed(stage=None))


def test_evidence_written_as_null_is_refused_on_an_assertion_with_a_condition() -> None:
    with pytest.raises(ValidationError, match="names its stage and no evidence"):
        TechnicalAssertion.model_validate(_document(spec__evidence=None))


def test_an_ast_with_a_condition_has_exactly_one_stage() -> None:
    ast = parse_document(_document())
    with pytest.raises(ValueError, match="has one stage"):
        replace(ast, stages=(Stage.PLAN, Stage.RUNTIME))
    with pytest.raises(ValueError, match="has one stage"):
        replace(ast, stages=())


def test_every_evidence_stage_is_valid_for_the_target(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(assertion, "STAGES_WITH_SCANNER_RESULTS", frozenset({Stage.PLAN, Stage.PRE_DEPLOY}))
    with pytest.raises(ValidationError, match="stage 'pre_deploy' is not valid for target kind 'resource'"):
        TechnicalAssertion.model_validate(_observed(evidence={"stages": ["plan", "pre_deploy"]}))


@pytest.mark.parametrize("stages", [["runtime"], ["plan", "runtime"]])
def test_an_assertion_is_observed_only_at_a_stage_whose_scanner_results_iltero_reads(stages: list[str]) -> None:
    message = "evidence.stages may name only plan: Iltero reads scanner results at no other stage"
    with pytest.raises(ValidationError, match=message):
        TechnicalAssertion.model_validate(_observed(evidence={"stages": stages}))


def test_the_stages_with_scanner_results_are_those_some_activity_reads_scanner_reports_at() -> None:
    read = frozenset().union(*(activity.stages_that_read_scanner_reports for activity in ACTIVITIES.values()))
    assert read == STAGES_WITH_SCANNER_RESULTS


def test_an_ast_observed_by_scanners_names_only_stages_whose_scanner_results_iltero_reads() -> None:
    ast = parse_document(_observed())
    with pytest.raises(ValueError, match="Iltero reads scanner results at no other stage"):
        replace(ast, stages=(Stage.PLAN, Stage.RUNTIME))


def test_an_assertion_observed_by_scanners_is_described() -> None:
    document = _observed()
    del document["metadata"]["description"]
    with pytest.raises(ValidationError, match="has a metadata.description saying exactly what it checks"):
        TechnicalAssertion.model_validate(document)


def test_a_description_is_left_out_rather_than_null() -> None:
    with pytest.raises(ValidationError, match="description is left out, never null"):
        TechnicalAssertion.model_validate(_document(metadata={**_document()["metadata"], "description": None}))


def test_a_description_is_bounded_and_has_no_control_characters() -> None:
    metadata = _document()["metadata"]
    for description in ("x" * (DESCRIPTION_MAX_LENGTH + 1), "a​b", " "):
        with pytest.raises(ValidationError):
            TechnicalAssertion.model_validate(_document(metadata={**metadata, "description": description}))


def test_a_description_is_not_part_of_the_ast() -> None:
    plain = _observed()
    described = _observed()
    described["metadata"]["description"] = "Another wording of the same check."
    assert source_digest(parse_document(plain)) == source_digest(parse_document(described))


def test_the_ast_of_an_assertion_observed_by_scanners_names_its_evidence_and_no_condition() -> None:
    ast = to_json(parse_document(_observed()))
    assert ast["evidence"] == {"stages": ["plan"]} and "stage" not in ast and ast["assert"] is None


def test_the_ast_of_an_assertion_with_a_condition_names_its_stage_and_no_evidence() -> None:
    ast = to_json(parse_document(_document()))
    assert ast["stage"] == "plan" and "evidence" not in ast


def test_a_guard_resolves_at_every_stage_an_assertion_is_observed_at(monkeypatch: pytest.MonkeyPatch) -> None:
    """``plan`` is a root at plan only, so a guard that reads it cannot apply at runtime too, with runtime widened
    into the stages with scanner results."""
    monkeypatch.setattr(assertion, "STAGES_WITH_SCANNER_RESULTS", frozenset({Stage.PLAN, Stage.RUNTIME}))
    document = _observed(evidence={"stages": ["plan", "runtime"]}, when={"path": "plan.digest", "not_equal": None})
    with pytest.raises(AssertionSyntaxError, match="not available at this stage"):
        parse_document(document)
    parse_document(_observed(when={"path": "plan.digest", "not_equal": None}))


def test_a_spec_with_neither_stage_nor_evidence_names_no_stages() -> None:
    spec = TechnicalAssertion.model_validate(_document()).spec.model_copy(update={"stage": None})
    with pytest.raises(ValueError, match="names its stage or its evidence stages"):
        _ = spec.stages
