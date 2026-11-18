"""``ScannerCheckMapping``: one scanner checks entry per assertion, its scanner evaluators, and the rules that bind
them."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from iltero_schemas.assertions.paths import ASSERTIONS, NOT_DECIDED_BY_SCANNERS
from iltero_schemas.ast.document import DocumentError, load_document
from iltero_schemas.canonical.common.encoding import digest_of
from iltero_schemas.models.common.assertion import Stage, TechnicalAssertion
from iltero_schemas.models.common.event import POLICY_STATUSES, Evaluation
from iltero_schemas.models.common.scanners import SCANNER_TOOLS
from iltero_schemas.models.iac.scanner_check_mapping import (
    MAX_ASSERTION_MAPPINGS,
    MAX_RULE_IDS,
    MAX_SCANNER_CHECKS,
    STAGE_INPUT_KINDS,
    TOOL_DECISIONS,
    AssertionMapping,
    ScannerCheckMapping,
    ScannerChecks,
    check_project_mapping,
    constraint_met,
)
from iltero_schemas.scanner_check_mappings import STARTER_MAPPING, load_scanner_check_mapping, starter_mapping
from tests.conftest import VECTORS, documents

DIGEST = "sha256:" + "a" * 64
CHECKS: dict[str, Any] = {
    "tool": "checkov",
    "stage": "plan",
    "rule_ids": ["CKV_AWS_16"],
    "tool_version_constraint": ">=3,<4",
    "input_kind": "plan",
    "subject_match": "exact_address",
    "paths_read": ["storage_encrypted"],
}
CITE: dict[str, Any] = {"id": "ILT.IAC.RESOURCE.AWS.RDS.STORAGE_ENCRYPTED", "version": "1.0.0", "digest": DIGEST}


def _assertion_mapping(
    assertion_id: str = "ILT.IAC.RESOURCE.AWS.RDS.STORAGE_ENCRYPTED", *scanner_checks: dict[str, Any]
) -> dict[str, Any]:
    return {
        "assertion": {**CITE, "id": assertion_id},
        "scanner_checks": [copy.deepcopy(e) for e in scanner_checks or (CHECKS,)],
    }


def _mapping(*entries: dict[str, Any], mapping_id: str = "ILT.SCANNER_CHECKS.TEST") -> dict[str, Any]:
    return {
        "apiVersion": "iltero.com/v1",
        "kind": "ScannerCheckMapping",
        "metadata": {"id": mapping_id, "version": "1.0.0"},
        "spec": {"assertion_mappings": [copy.deepcopy(entry) for entry in entries or (_assertion_mapping(),)]},
    }


def test_the_starter_mapping_maps_each_check_verified_against_the_pinned_scanners() -> None:
    """The checks and tools each starter is bound to, as verified over real plans (Checkov 3.3.8, Trivy 0.72.0)."""
    shipped = starter_mapping()
    assert shipped.metadata.id == "ILT.SCANNER_CHECKS.STARTER"
    assert {
        b.assertion.id: {e.tool: e.rule_ids for e in b.scanner_checks} for b in shipped.spec.assertion_mappings
    } == {
        "ILT.IAC.RESOURCE.AWS.CLOUDTRAIL.RECORDS_ALL_REGIONS": {"checkov": ["CKV_AWS_67"], "trivy": ["AWS-0014"]},
        "ILT.IAC.RESOURCE.AWS.CLOUDTRAIL.VALIDATES_LOG_FILES": {"checkov": ["CKV_AWS_36"], "trivy": ["AWS-0016"]},
        "ILT.IAC.RESOURCE.AWS.CONFIG.RECORDER_ENABLED": {"checkov": ["CKV2_AWS_45"]},
        "ILT.IAC.RESOURCE.AWS.CONFIG.RECORDER_RECORDS_GLOBAL_RESOURCES": {"checkov": ["CKV2_AWS_48"]},
        "ILT.IAC.RESOURCE.AWS.EC2.NO_SSH_OR_RDP_OPEN_TO_THE_INTERNET": {"trivy": ["AWS-0107"]},
        "ILT.IAC.RESOURCE.AWS.IAM.NO_POLICY_ALLOWS_ALL_ACTIONS_ON_ALL_RESOURCES": {"checkov": ["CKV_AWS_62"]},
        "ILT.IAC.RESOURCE.AWS.RDS.NOT_PUBLIC": {"checkov": ["CKV_AWS_17"], "trivy": ["AWS-0180"]},
        "ILT.IAC.RESOURCE.AWS.RDS.STORAGE_ENCRYPTED": {"checkov": ["CKV_AWS_16"], "trivy": ["AWS-0080"]},
        "ILT.IAC.RESOURCE.AWS.S3.PUBLIC_ACCESS_BLOCKED": {
            "checkov": ["CKV_AWS_53", "CKV_AWS_54", "CKV_AWS_55", "CKV_AWS_56"]
        },
    }


def _shipped_documents() -> dict[str, TechnicalAssertion]:
    return {
        path.name.removesuffix(".yaml"): TechnicalAssertion.model_validate(
            load_document(path.read_text(encoding="utf-8"))
        )
        for path in ASSERTIONS.iterdir()
        if path.name.endswith(".yaml")
    }


def test_every_starter_only_scanners_observe_is_mapped_in_the_shipped_mapping() -> None:
    """A starter with no condition of its own is decided by nothing but its scanner checks entries."""
    bound = {entry.assertion.id for entry in starter_mapping().spec.assertion_mappings}
    observed = {i for i, document in _shipped_documents().items() if document.spec.observed_by_scanners}
    assert observed and observed <= bound


def test_no_starter_only_scanners_observe_rests_on_trivy_alone() -> None:
    """Trivy reports no pass for one resource, so a starter only Trivy decided could fail but never pass."""
    documents = _shipped_documents()
    for entry in starter_mapping().spec.assertion_mappings:
        if documents[entry.assertion.id].spec.observed_by_scanners:
            assert any(evaluator.tool != "trivy" for evaluator in entry.scanner_checks), entry.assertion.id


def test_every_shipped_scanner_checks_entry_cites_the_document_this_package_ships_at_one_of_its_stages() -> None:
    """A scanner checks entry cites the assertion by the digest of its document as written, which covers its
    description."""
    for entry in starter_mapping().spec.assertion_mappings:
        document = load_document((ASSERTIONS / f"{entry.assertion.id}.yaml").read_text(encoding="utf-8"))
        assertion = TechnicalAssertion.model_validate(document)
        assert (entry.assertion.version, entry.assertion.digest) == (
            assertion.metadata.version,
            digest_of(document),
        )
        assert all(evaluator.stage in assertion.spec.stages for evaluator in entry.scanner_checks)


@pytest.mark.parametrize(
    "path",
    documents("scanner_check_mappings"),
    ids=lambda p: p.name,
)
def test_every_scanner_check_mapping_vector_cites_the_document_of_each_assertion_it_decides(path: Path) -> None:
    for entry in ScannerCheckMapping.model_validate(
        json.loads(path.read_text(encoding="utf-8"))
    ).spec.assertion_mappings:
        folder = ASSERTIONS if entry.assertion.id.startswith("ILT.") else VECTORS / "assertions"
        document = load_document((folder / f"{entry.assertion.id}.yaml").read_text(encoding="utf-8"))
        assert (entry.assertion.version, entry.assertion.digest) == (
            document["metadata"]["version"],
            digest_of(document),
        )
        stages = TechnicalAssertion.model_validate(document).spec.stages
        assert all(evaluator.stage in stages for evaluator in entry.scanner_checks)


def test_a_decision_is_only_the_tools_own_words_for_pass_and_fail() -> None:
    """A skipped or undecided result is not a decision; ``unknown`` and ``not_applicable`` need a runner's reason."""
    for tool in SCANNER_TOOLS:
        assert set(TOOL_DECISIONS[tool].values()) == {"pass", "fail"}
    assert {"pass", "fail"} < POLICY_STATUSES
    for status in ("pass", "fail"):
        evaluation = {
            "activity": "iac_change",
            "stage": "plan",
            "status": status,
            "status_reason": None,
            "status_detail": None,
            "policy_reason": None,
            "observations": None,
        }
        Evaluation.model_validate(evaluation)


def test_a_scanner_checks_digest_changes_with_the_entry_and_with_the_assertion_it_cites() -> None:
    entry = AssertionMapping.model_validate(_assertion_mapping())
    first = entry.scanner_checks_digest(entry.scanner_checks[0])
    widened = ScannerChecks.model_validate({**CHECKS, "rule_ids": ["CKV_AWS_16", "CKV_AWS_17"]})
    assert entry.scanner_checks_digest(widened) != first
    edited = AssertionMapping.model_validate(
        {**_assertion_mapping(), "assertion": {**CITE, "digest": "sha256:" + "b" * 64}}
    )
    assert edited.scanner_checks_digest(edited.scanner_checks[0]) != first
    assert AssertionMapping.model_validate(_assertion_mapping()).scanner_checks_digest(entry.scanner_checks[0]) == first


def test_a_mapping_finds_a_scanner_checks_entry_by_its_digest() -> None:
    shipped = starter_mapping()
    entry = shipped.spec.assertion_mappings[1]
    assert shipped.by_digest[entry.scanner_checks_digest(entry.scanner_checks[0])] == (entry, entry.scanner_checks[0])
    assert DIGEST not in shipped.by_digest


def test_an_assertion_is_mapped_once_in_a_mapping() -> None:
    with pytest.raises(ValidationError, match="assertion_mappings are sorted by assertion id, each assertion once"):
        ScannerCheckMapping.model_validate(_mapping(_assertion_mapping(), _assertion_mapping()))


def test_assertion_mappings_are_sorted_by_assertion_id() -> None:
    other = _assertion_mapping("ILT.IAC.RESOURCE.AWS.RDS.NOT_PUBLIC", {**CHECKS, "rule_ids": ["CKV_AWS_17"]})
    ScannerCheckMapping.model_validate(_mapping(other, _assertion_mapping()))
    with pytest.raises(ValidationError, match="assertion_mappings are sorted by assertion id"):
        ScannerCheckMapping.model_validate(_mapping(_assertion_mapping(), other))


def test_one_tool_uses_a_check_once_per_stage_across_the_mapping() -> None:
    other = _assertion_mapping(
        "ILT.IAC.RESOURCE.AWS.RDS.NOT_PUBLIC", {**CHECKS, "rule_ids": ["CKV_AWS_16", "CKV_AWS_99"]}
    )
    with pytest.raises(ValidationError, match="two assertion mappings use the same check"):
        ScannerCheckMapping.model_validate(_mapping(other, _assertion_mapping()))


def test_an_assertion_has_one_scanner_checks_entry_per_tool_and_stage() -> None:
    with pytest.raises(ValidationError, match="one per tool and stage"):
        AssertionMapping.model_validate(
            _assertion_mapping("ILT.IAC.RESOURCE.AWS.RDS.STORAGE_ENCRYPTED", CHECKS, CHECKS)
        )


def test_scanner_checks_are_in_lifecycle_order_then_by_tool() -> None:
    trivy = {**CHECKS, "tool": "trivy", "rule_ids": ["AWS-0080"]}
    runtime = {**CHECKS, "stage": "runtime", "input_kind": "deployed_resources", "rule_ids": ["CKV_AWS_99"]}
    AssertionMapping.model_validate(
        _assertion_mapping("ILT.IAC.RESOURCE.AWS.RDS.STORAGE_ENCRYPTED", CHECKS, trivy, runtime)
    )
    for order in ((trivy, CHECKS), (runtime, CHECKS)):
        with pytest.raises(ValidationError, match="in lifecycle order of their stage, then by tool"):
            AssertionMapping.model_validate(_assertion_mapping("ILT.IAC.RESOURCE.AWS.RDS.STORAGE_ENCRYPTED", *order))


def test_two_tools_may_decide_the_same_assertion() -> None:
    """Several evaluators observe one assertion: each tool gives its own evaluation."""
    trivy = {**CHECKS, "tool": "trivy", "rule_ids": ["AWS-0080"]}
    entry = AssertionMapping.model_validate(
        _assertion_mapping("ILT.IAC.RESOURCE.AWS.RDS.STORAGE_ENCRYPTED", CHECKS, trivy)
    )
    assert [e.tool for e in entry.scanner_checks] == ["checkov", "trivy"]


@pytest.mark.parametrize("assertion_id", sorted(NOT_DECIDED_BY_SCANNERS))
def test_no_scanner_checks_entry_decides_an_assertion_no_scanner_decides(assertion_id: str) -> None:
    with pytest.raises(
        ValidationError, match=f"no scanner checks decide {assertion_id}: a scanner's result never decides it"
    ):
        AssertionMapping.model_validate(_assertion_mapping(assertion_id))


@pytest.mark.parametrize("rule_ids", [["CKV_AWS_17", "CKV_AWS_16"], ["CKV_AWS_16", "CKV_AWS_16"]])
def test_rule_ids_are_sorted_each_check_once(rule_ids: list[str]) -> None:
    with pytest.raises(ValidationError, match="rule_ids is sorted, each check once"):
        ScannerChecks.model_validate({**CHECKS, "rule_ids": rule_ids})


@pytest.mark.parametrize(
    ("stage", "input_kind", "message"),
    [
        ("plan", "deployed_resources", "a scanner checks entry at plan reads plan input"),
        ("plan", "deployed_resources", "a scanner checks entry at plan reads plan input"),
        ("runtime", "plan", "a scanner checks entry at runtime reads deployed_resources input"),
        ("pre_deploy", "plan", "a scanner checks entry at pre_deploy reads no scanner input"),
    ],
)
def test_a_scanner_checks_entry_reads_the_input_its_stage_stands_for(stage: str, input_kind: str, message: str) -> None:
    """A configuration result never decides what the plan settles; only deployed resources decide a running state."""
    with pytest.raises(ValidationError, match=message):
        ScannerChecks.model_validate({**CHECKS, "stage": stage, "input_kind": input_kind})
    assert ScannerChecks.model_validate({**CHECKS, "stage": "runtime", "input_kind": "deployed_resources"})


def test_only_the_plan_and_runtime_stages_read_scanner_input() -> None:
    assert set(STAGE_INPUT_KINDS) == {Stage.PLAN, Stage.RUNTIME}


@pytest.mark.parametrize("value", [">=3", ">=0", "!=3.1", ">3,!=4.0"])
def test_a_constraint_bounds_the_version_from_above(value: str) -> None:
    """An open range would admit a future major version, whose checks may decide something else."""
    with pytest.raises(ValidationError, match="bounds the version from above"):
        ScannerChecks.model_validate({**CHECKS, "tool_version_constraint": value})


@pytest.mark.parametrize("subject_match", ["exact_address", "plan_configures"])
def test_a_scanner_checks_entry_says_how_a_result_finds_its_subject(subject_match: str) -> None:
    assert ScannerChecks.model_validate({**CHECKS, "subject_match": subject_match}).subject_match == subject_match
    with pytest.raises(ValidationError, match="Input should be"):
        ScannerChecks.model_validate({**CHECKS, "subject_match": "same_name"})


def test_a_project_mapping_decides_only_the_projects_own_assertions() -> None:
    project = ScannerCheckMapping.model_validate(
        _mapping(_assertion_mapping("ACME.IAC.RESOURCE.AWS.RDS.ENCRYPTED"), mapping_id="ACME.SCANNER_CHECKS.A")
    )
    check_project_mapping(project)
    with pytest.raises(
        ValueError, match="decides only the project's own assertions, not ILT.IAC.RESOURCE.AWS.RDS.STORAGE_ENCRYPTED"
    ):
        check_project_mapping(ScannerCheckMapping.model_validate(_mapping(mapping_id="ACME.SCANNER_CHECKS.A")))
    with pytest.raises(ValueError, match="a namespace of its own, not ILT or one starting so"):
        check_project_mapping(starter_mapping())


def test_an_assertion_id_a_later_release_may_ship_is_refused_in_a_project_mapping() -> None:
    """Any ``ILT.`` id is reserved, shipped today or not."""
    project = _mapping(
        _assertion_mapping("ILT.IAC.RESOURCE.AWS.S3.NOT_YET_SHIPPED"), mapping_id="ACME.SCANNER_CHECKS.A"
    )
    with pytest.raises(ValueError, match="not ILT.IAC.RESOURCE.AWS.S3.NOT_YET_SHIPPED"):
        check_project_mapping(ScannerCheckMapping.model_validate(project))


@pytest.mark.parametrize("value", ["not a specifier", ">=", "3.2", "=>3"])
def test_a_constraint_that_is_not_a_version_specifier_is_refused(value: str) -> None:
    with pytest.raises(ValidationError, match="is not a version specifier"):
        ScannerChecks.model_validate({**CHECKS, "tool_version_constraint": value})


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
        (">=3,<4", "3.2.1+patched", False),
        (">=3,<4", "v3.2.1", False),
        (">=3,<4", " 3.2.1", False),
        (">=3,<4", "3.2.1.post1", True),
    ],
)
def test_a_tool_version_is_read_against_the_constraint(constraint: str, version: str, met: bool) -> None:
    assert constraint_met(constraint, version) is met


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"tool": "tfsec"}, "Input should be"),
        ({"rule_ids": ["-leading-hyphen"]}, "String should match"),
        ({"rule_ids": ["x" * 129]}, "at most 128"),
        ({"rule_ids": []}, "at least 1 item"),
        (
            {"rule_ids": [f"R{n:02}" for n in range(MAX_RULE_IDS + 1)]},
            f"at most {MAX_RULE_IDS} items",
        ),
        ({"id": "ILT.BINDING.CHECKOV.CKV_AWS_16"}, "Extra inputs are not permitted"),
        ({"status_map": {"PASSED": "pass"}}, "Extra inputs are not permitted"),
        ({"input_kind": None}, "Input should be"),
        ({"input_kind": "terraform_plan"}, "Input should be"),
        ({"severity": "high"}, "Extra inputs are not permitted"),
    ],
)
def test_a_scanner_checks_entry_outside_the_shape_is_refused(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        ScannerChecks.model_validate({**CHECKS, **changes})


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"scanner_checks": []}, "at least 1 item"),
        ({"scanner_checks": [CHECKS] * (MAX_SCANNER_CHECKS + 1)}, f"at most {MAX_SCANNER_CHECKS} items"),
        ({"assertion": {"id": "ILT.IAC.RESOURCE.AWS.RDS.STORAGE_ENCRYPTED", "version": "1.0.0"}}, "Field required"),
        ({"notes": "hello"}, "Extra inputs are not permitted"),
    ],
)
def test_an_assertion_mapping_outside_the_shape_is_refused(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        AssertionMapping.model_validate({**_assertion_mapping(), **changes})


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"apiVersion": "iltero.io/v2"}, "Input should be"),
        ({"kind": "BindingSet"}, "Input should be"),
        ({"spec": {"assertion_mappings": []}}, "at least 1 item"),
        (
            {"spec": {"assertion_mappings": [_assertion_mapping()] * (MAX_ASSERTION_MAPPINGS + 1)}},
            f"at most {MAX_ASSERTION_MAPPINGS} items",
        ),
        ({"notes": "hello"}, "Extra inputs are not permitted"),
    ],
)
def test_a_mapping_outside_the_shape_is_refused(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        ScannerCheckMapping.model_validate({**_mapping(), **changes})


def test_every_tool_a_mapping_may_name_has_its_words_for_a_decision() -> None:
    for tool in SCANNER_TOOLS:
        assert ScannerChecks.model_validate({**CHECKS, "tool": tool}).tool == tool
        assert tool in TOOL_DECISIONS


def test_a_mapping_is_read_under_the_document_guards() -> None:
    text = STARTER_MAPPING.read_text(encoding="utf-8")
    assert load_scanner_check_mapping(text).metadata.id == "ILT.SCANNER_CHECKS.STARTER"
    with pytest.raises(DocumentError):
        load_scanner_check_mapping(text + "\n---\napiVersion: iltero.com/v1\n")
    with pytest.raises(DocumentError):
        load_scanner_check_mapping("assertion_mappings: &a []\nmore: *a\n")


def test_a_mapping_writes_no_value_only_as_null() -> None:
    text = STARTER_MAPPING.read_text(encoding="utf-8").replace("input_kind: plan", "input_kind: ~", 1)
    with pytest.raises(DocumentError, match="no value is written as null"):
        load_scanner_check_mapping(text)


def test_the_starter_mapping_is_the_file_on_disk() -> None:
    """The shipped bytes are what the model accepted, not a copy built in code."""
    document = yaml.safe_load(STARTER_MAPPING.read_text(encoding="utf-8"))
    assert ScannerCheckMapping.model_validate(document) == starter_mapping()


def test_lifecycle_order_is_the_order_the_stages_are_listed_in() -> None:
    """Scanner checks entries are ordered by stage; reordering ``Stage`` would make every shipped mapping invalid."""
    assert [stage.value for stage in Stage] == ["plan", "pre_deploy", "post_deploy", "post_verify", "runtime"]
