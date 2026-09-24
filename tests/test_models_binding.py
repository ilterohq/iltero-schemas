"""``EvaluatorBindingSet``: the rules that keep a credited verdict unambiguous."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from iltero_schemas.ast import parse_document
from iltero_schemas.ast.document import DocumentError, load_document
from iltero_schemas.bindings import STARTER_SET, load_binding_set, starter_set
from iltero_schemas.models.binding import (
    MAX_BINDINGS,
    MAX_STATUS_MAP,
    TOOLS,
    EvaluatorBinding,
    EvaluatorBindingSet,
    constraint_met,
)
from iltero_schemas.models.event import POLICY_STATUSES, Evaluation

ASSERTIONS = Path(__file__).resolve().parent.parent / "src" / "iltero_schemas" / "assertions"

ENTRY: dict[str, Any] = {
    "id": "ILT.BINDING.CHECKOV.CKV_AWS_16",
    "version": "1.0.0",
    "tool": "checkov",
    "tool_version_constraint": ">=3,<4",
    "check_id": "CKV_AWS_16",
    "framework": "terraform_plan",
    "assertion": {"id": "ILT.AWS.RDS.STORAGE_ENCRYPTED", "version": "1.0.0"},
    "stage": "plan",
    "status_map": {"PASSED": "pass", "FAILED": "fail"},
}


def _set(*entries: dict[str, Any]) -> dict[str, Any]:
    return {
        "apiVersion": "iltero.io/v1",
        "kind": "EvaluatorBindingSet",
        "metadata": {"id": "ILT.BINDINGS.TEST", "version": "1.0.0"},
        "bindings": [copy.deepcopy(entry) for entry in (entries or (ENTRY,))],
    }


def _other(**changes: Any) -> dict[str, Any]:
    return {**copy.deepcopy(ENTRY), "id": "ILT.BINDING.CHECKOV.OTHER", **changes}


def test_the_starter_set_loads() -> None:
    shipped = starter_set()
    assert shipped.metadata.id == "ILT.BINDINGS.STARTER"
    assert [entry.check_id for entry in shipped.bindings] == ["CKV_AWS_16", "CKV_AWS_17"]


def test_an_entry_says_what_the_tool_must_have_been_reading() -> None:
    """A configuration scan and a plan scan answer different questions about one resource."""
    assert {entry.framework for entry in starter_set().bindings} == {"terraform_plan"}


def test_every_starter_entry_cites_an_assertion_this_package_ships() -> None:
    """A binding that names an assertion nobody can read licenses nothing."""
    for entry in starter_set().bindings:
        document = load_document((ASSERTIONS / f"{entry.assertion.id}.yaml").read_text(encoding="utf-8"))
        parsed = parse_document(document)
        assert parsed.id == entry.assertion.id
        assert parsed.version == entry.assertion.version
        assert parsed.stage is entry.stage


def test_only_a_decision_may_be_credited() -> None:
    """A skipped or unsettled check is not a decision, and an event could not carry it anyway.

    ``not_applicable`` and ``unknown`` need a ``status_reason`` the runner sets
    from what it observed; a scanner's result gives none, so crediting one
    could only produce an event the contract refuses.
    """
    accepted = set()
    for status in sorted(POLICY_STATUSES | {"error", "not_evaluated"}):
        try:
            EvaluatorBinding.model_validate({**ENTRY, "status_map": {"X": status}})
        except ValidationError:
            continue
        accepted.add(status)
    assert accepted == {"pass", "fail"}
    assert accepted < POLICY_STATUSES


def test_every_status_the_starter_set_credits_makes_a_valid_event() -> None:
    """The end-to-end guarantee: nothing an entry may say can produce an event the contract refuses."""
    credited = {value for entry in starter_set().bindings for value in entry.status_map.values()}
    assert credited == {"pass", "fail"}
    for status in sorted(credited):
        evaluation = {
            "stage": "plan",
            "status": status,
            "status_reason": None,
            "status_detail": None,
            "reason": None,
            "observations": None,
        }
        Evaluation.model_validate(evaluation)


def test_an_entry_digest_changes_with_the_entry() -> None:
    first = EvaluatorBinding.model_validate(ENTRY)
    second = EvaluatorBinding.model_validate({**ENTRY, "status_map": {"PASSED": "pass"}})
    assert first.digest != second.digest
    assert EvaluatorBinding.model_validate(copy.deepcopy(ENTRY)).digest == first.digest


def test_two_entries_may_not_share_an_id() -> None:
    with pytest.raises(ValidationError, match="two entries share the id"):
        EvaluatorBindingSet.model_validate(_set(ENTRY, {**ENTRY, "check_id": "CKV_AWS_17"}))


def test_one_tool_may_bind_a_check_once_per_stage() -> None:
    other = _other(assertion={"id": "ILT.AWS.RDS.NOT_PUBLIC", "version": "1.0.0"})
    with pytest.raises(ValidationError, match="bind the same check"):
        EvaluatorBindingSet.model_validate(_set(ENTRY, other))


def test_one_tool_may_establish_an_assertion_with_one_check_per_stage() -> None:
    other = _other(check_id="CKV_AWS_999")
    with pytest.raises(ValidationError, match="establish the same assertion"):
        EvaluatorBindingSet.model_validate(_set(ENTRY, other))


def test_two_tools_may_establish_the_same_assertion() -> None:
    """The run chooses which tools it was given; the catalogue may describe both."""
    other = _other(tool="trivy", check_id="AWS-0080")
    assert len(EvaluatorBindingSet.model_validate(_set(ENTRY, other)).bindings) == 2


@pytest.mark.parametrize("value", ["not a specifier", ">=", "3.2", "=>3"])
def test_a_constraint_that_is_not_a_version_specifier_is_refused(value: str) -> None:
    with pytest.raises(ValidationError, match="is not a version specifier"):
        EvaluatorBinding.model_validate({**ENTRY, "tool_version_constraint": value})


@pytest.mark.parametrize(
    ("constraint", "version", "met"),
    [
        (">=3,<4", "3.3.8", True),
        (">=3,<4", "2.5.0", False),
        (">=3,<4", "4.0.0", False),
        (">=3,<4", "3.0.0rc1", False),
        (">=3,<4", "4.0.0b1", False),
        (">=3,<4", "nightly", False),
        ("==0.72.0", "0.72.0", True),
    ],
)
def test_a_tool_version_is_read_against_the_constraint(constraint: str, version: str, met: bool) -> None:
    assert constraint_met(constraint, version) is met


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"tool": "tfsec"}, "Input should be"),
        ({"check_id": "-leading-hyphen"}, "String should match"),
        ({"check_id": "x" * 129}, "at most 128"),
        ({"stage": "runtime"}, None),
        ({"status_map": {}}, "at least 1 item"),
        ({"status_map": {f"S{n}": "pass" for n in range(MAX_STATUS_MAP + 1)}}, "at most 32 items"),
        ({"status_map": {"BAD STATUS": "pass"}}, "String should match"),
        ({"id": "not.an.id"}, "String should match"),
        ({"version": "1.0"}, "String should match"),
        ({"framework": None}, None),
        ({"framework": "not a framework"}, "String should match"),
        ({"severity": "high"}, "Extra inputs are not permitted"),
    ],
)
def test_an_entry_outside_the_shape_is_refused(changes: dict[str, Any], message: str | None) -> None:
    if message is None:
        EvaluatorBinding.model_validate({**ENTRY, **changes})
        return
    with pytest.raises(ValidationError, match=message):
        EvaluatorBinding.model_validate({**ENTRY, **changes})


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"apiVersion": "iltero.io/v2"}, "Input should be"),
        ({"kind": "BindingSet"}, "Input should be"),
        ({"bindings": []}, "at least 1 item"),
        ({"bindings": [ENTRY] * (MAX_BINDINGS + 1)}, f"at most {MAX_BINDINGS} items"),
        ({"notes": "hello"}, "Extra inputs are not permitted"),
    ],
)
def test_a_set_outside_the_shape_is_refused(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        EvaluatorBindingSet.model_validate({**_set(), **changes})


def test_the_tools_a_binding_may_cite_are_the_documented_three() -> None:
    for tool in TOOLS:
        assert EvaluatorBinding.model_validate({**ENTRY, "tool": tool}).tool == tool


def test_a_set_is_read_under_the_document_guards() -> None:
    text = STARTER_SET.read_text(encoding="utf-8")
    assert load_binding_set(text).metadata.id == "ILT.BINDINGS.STARTER"
    with pytest.raises(DocumentError):
        load_binding_set(text + "\n---\napiVersion: iltero.io/v1\n")
    with pytest.raises(DocumentError):
        load_binding_set("bindings: &a []\nmore: *a\n")


def test_the_starter_set_is_the_file_on_disk() -> None:
    """The shipped bytes are what the model accepted, not a copy built in code."""
    document = yaml.safe_load(STARTER_SET.read_text(encoding="utf-8"))
    assert EvaluatorBindingSet.model_validate(document) == starter_set()
