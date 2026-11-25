"""Checking the documents a scanning stage sends with its record against the record's redaction policy."""

from __future__ import annotations

import dataclasses
import json
from typing import Any

import pytest

from iltero_schemas.canonical.common.encoding import canonical_bytes, digest
from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.common.kept_files import KeptFiles
from iltero_schemas.models.common.sent_documents import SentDocumentError
from iltero_schemas.models.iac.stage_files import sent_documents
from iltero_schemas.redaction.common.apply import RedactionError
from iltero_schemas.redaction.iac.sent_documents import (
    MARKS_NOT_READ,
    NESTS_TOO_DEEP,
    document_marks_and_anchors,
    kept_document_redaction_problems,
    sent_document_problems,
)
from iltero_schemas.vectors.kept_files import kept_files_of
from tests.conftest import VECTORS

NAME = "iac/local_run_scanned_project_required"
CAR_OF_NAME = CAR.model_validate(json.loads((VECTORS / "records" / f"{NAME}.json").read_text(encoding="utf-8")))
KEPT = kept_files_of(NAME)
URL = "postgres://app:hidden-value@db.internal/app"


def test_each_document_a_scanning_stage_sends_holds_nothing_its_policy_would_hide() -> None:
    sent = sent_documents(CAR_OF_NAME, Stage.PLAN)
    assert {name for name, _entry in sent} == {"redacted_plan", "scanner_report", "scanner_observations"}
    for _name, entry in sent:
        assert sent_document_problems(CAR_OF_NAME, Stage.PLAN, entry, KEPT[entry.path]).count == 0


def test_a_document_the_stage_does_not_send_or_whose_bytes_are_not_its_entry_is_refused() -> None:
    _name, entry = sent_documents(CAR_OF_NAME, Stage.PLAN)[0]
    other = next(
        ref for ref in CAR_OF_NAME.evidence_refs if ref not in [e for _n, e in sent_documents(CAR_OF_NAME, Stage.PLAN)]
    )
    with pytest.raises(SentDocumentError, match="not one the stage sends with its record"):
        sent_document_problems(CAR_OF_NAME, Stage.PLAN, other, KEPT[entry.path])
    with pytest.raises(SentDocumentError, match="not the file its register entry names"):
        sent_document_problems(CAR_OF_NAME, Stage.PLAN, entry, KEPT[entry.path] + b" ")


def _with_report(document: Any) -> tuple[CAR, Any]:
    """The record with its first scanner report's entry naming ``document``'s canonical bytes, and that entry."""
    data = canonical_bytes(document)
    name, entry = next(
        (name, entry) for name, entry in sent_documents(CAR_OF_NAME, Stage.PLAN) if name == "scanner_report"
    )
    changed = entry.model_copy(update={"digest": digest(data), "size_bytes": len(data)})
    refs = [changed if ref is entry else ref for ref in CAR_OF_NAME.evidence_refs]
    record = CAR_OF_NAME.model_copy(update={"evidence_refs": refs})
    scanners = record.stages[Stage.PLAN].scanners
    assert scanners is not None and name == "scanner_report"
    reports = [
        report.model_copy(update={"report_digest": changed.digest}) if report.report_digest == entry.digest else report
        for report in scanners.reports
    ]
    stage = record.stages[Stage.PLAN].model_copy(update={"scanners": scanners.model_copy(update={"reports": reports})})
    return record.model_copy(update={"stages": {**record.stages, Stage.PLAN: stage}}), changed


def test_a_sent_report_holding_a_credential_is_a_problem() -> None:
    document = json.loads(
        KEPT[next(e for n, e in sent_documents(CAR_OF_NAME, Stage.PLAN) if n == "scanner_report").path]
    )
    leaked = {"leaked": URL, "kept": document}
    record, entry = _with_report(leaked)
    found = sent_document_problems(record, Stage.PLAN, entry, canonical_bytes(leaked))
    assert [(problem.path, problem.rule) for problem in found.problems] == [(("leaked",), "value_shape")]


def test_a_kept_document_holding_a_credential_is_listed_by_its_register_entry() -> None:
    files = KeptFiles(
        scanner_check_mappings={},
        observations={},
        reports={},
        plans={},
        assertions={},
        local_exceptions={},
        served_exceptions={},
        inputs={},
        identities={},
        served_bundles={},
    )
    assert kept_document_redaction_problems(CAR_OF_NAME, files) == []
    plan = next(entry for name, entry in sent_documents(CAR_OF_NAME, Stage.PLAN) if name == "redacted_plan")
    leaked = dataclasses.replace(files, plans={plan.digest: {"leaked": URL}})
    position = CAR_OF_NAME.evidence_refs.index(plan)
    assert kept_document_redaction_problems(CAR_OF_NAME, leaked) == [
        (f"evidence_refs.{position}", "holds a value or a key the record's redaction policy would hide")
    ]


def test_a_report_s_configured_paths_are_read_from_its_root_or_each_item_of_a_list() -> None:
    assert document_marks_and_anchors("scanner_report", "terraform", {"a": 1}) == ([], [()])
    assert document_marks_and_anchors("scanner_report", "terraform", [{}, {}]) == ([], [(0,), (1,)])
    assert document_marks_and_anchors("scanner_observations", "terraform", {"a": 1}) == ([], [])


def test_a_sent_plan_holding_a_value_its_own_flags_mark_sensitive_is_a_problem() -> None:
    plan_entry = next(entry for name, entry in sent_documents(CAR_OF_NAME, Stage.PLAN) if name == "redacted_plan")
    plan = json.loads(KEPT[plan_entry.path])
    changes = plan["resource_changes"]
    changes[0]["change"]["after_sensitive"] = {"left_in_place": True}
    changes[0]["change"]["after"] = {**(changes[0]["change"]["after"] or {}), "left_in_place": "plain-text"}
    data = canonical_bytes(plan)
    changed = plan_entry.model_copy(update={"digest": digest(data), "size_bytes": len(data)})
    record = CAR_OF_NAME.model_copy(
        update={"evidence_refs": [changed if ref is plan_entry else ref for ref in CAR_OF_NAME.evidence_refs]}
    )
    found = sent_document_problems(record, Stage.PLAN, changed, data)
    assert [(problem.path, problem.rule) for problem in found.problems] == [
        (("resource_changes", 0, "change", "after", "left_in_place"), "declared_sensitive")
    ]


def test_a_kept_document_nested_deeper_than_a_check_reads_is_listed_not_raised() -> None:
    files = KeptFiles(
        scanner_check_mappings={},
        observations={},
        reports={},
        plans={},
        assertions={},
        local_exceptions={},
        served_exceptions={},
        inputs={},
        identities={},
        served_bundles={},
    )
    plan = next(entry for name, entry in sent_documents(CAR_OF_NAME, Stage.PLAN) if name == "redacted_plan")
    deep: Any = "x"
    for _ in range(70):
        deep = [deep]
    position = CAR_OF_NAME.evidence_refs.index(plan)
    assert kept_document_redaction_problems(CAR_OF_NAME, dataclasses.replace(files, plans={plan.digest: deep})) == [
        (f"evidence_refs.{position}", "nests deeper than a check of what its redaction policy would hide reads")
    ]


def test_a_kept_plan_whose_flags_its_tools_reader_refuses_is_listed_not_raised() -> None:
    files = KeptFiles(
        scanner_check_mappings={},
        observations={},
        reports={},
        plans={},
        assertions={},
        local_exceptions={},
        served_exceptions={},
        inputs={},
        identities={},
        served_bundles={},
    )
    plan = next(entry for name, entry in sent_documents(CAR_OF_NAME, Stage.PLAN) if name == "redacted_plan")
    bare = {"planned_values": {"root_module": {"resources": [{"address": "terraform_data.bare", "values": {}}]}}}
    position = CAR_OF_NAME.evidence_refs.index(plan)
    assert kept_document_redaction_problems(CAR_OF_NAME, dataclasses.replace(files, plans={plan.digest: bare})) == [
        (f"evidence_refs.{position}", MARKS_NOT_READ)
    ]
    with pytest.raises(RedactionError, match="every resource names its sensitive values"):
        document_marks_and_anchors("redacted_plan", "terraform", bare)


def test_a_kept_plan_whose_sensitive_values_nest_past_the_readers_limit_is_listed_not_raised() -> None:
    files = KeptFiles(
        scanner_check_mappings={},
        observations={},
        reports={},
        plans={},
        assertions={},
        local_exceptions={},
        served_exceptions={},
        inputs={},
        identities={},
        served_bundles={},
    )
    plan = next(entry for name, entry in sent_documents(CAR_OF_NAME, Stage.PLAN) if name == "redacted_plan")
    flags: Any = True
    for _ in range(5000):
        flags = {"inner": flags}
    deep = {"planned_values": {"root_module": {"resources": [{"values": {}, "sensitive_values": flags}]}}}
    position = CAR_OF_NAME.evidence_refs.index(plan)
    assert kept_document_redaction_problems(CAR_OF_NAME, dataclasses.replace(files, plans={plan.digest: deep})) == [
        (f"evidence_refs.{position}", NESTS_TOO_DEEP)
    ]
