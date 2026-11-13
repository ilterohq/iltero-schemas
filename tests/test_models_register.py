"""The evidence register lists the files a record's stages and events name."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.car import CAR, MAX_EVIDENCE_REFS, SKIP_INTEGRITY_CHECKS
from iltero_schemas.vectors.paths import VECTORS
from tests.records import RECORD, SCANNERS, keep_the_scanner_files


def _without_ref(digest: str) -> dict[str, Any]:
    """The captured record with the register entry of ``digest`` removed."""
    document = copy.deepcopy(RECORD)
    document["evidence_refs"] = [ref for ref in document["evidence_refs"] if ref["digest"] != digest]
    return document


def test_the_captured_record_registers_every_file_its_stages_and_events_name() -> None:
    CAR.model_validate(RECORD)


@pytest.mark.parametrize(
    ("digest", "message"),
    [
        (RECORD["stages"]["plan"]["events"]["digest"], "the plan stage's events file is an entry"),
        (RECORD["stages"]["plan"]["assertions"]["digest"], "the plan stage's assertion index is an entry"),
        (RECORD["events"][0]["provenance"]["input_digest"], "the input every event was evaluated over is an entry"),
        (
            RECORD["stages"]["plan"]["redaction"]["input"]["digest"],
            "what the plan stage redacted is an entry of the evidence register that names the redaction policy",
        ),
    ],
    ids=["events file", "assertion index", "input", "plan observation"],
)
def test_a_file_a_record_names_but_does_not_register_is_refused(digest: str, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        CAR.model_validate(_without_ref(digest))


def test_a_stage_names_its_events_file_by_the_path_and_digest_the_register_gives() -> None:
    document = copy.deepcopy(RECORD)
    document["stages"]["plan"]["events"]["path"] = "units/root/plan/other-events.json"
    with pytest.raises(ValidationError, match="the plan stage's events file is an entry"):
        CAR.model_validate(document)


def test_a_register_holds_at_most_five_files_per_event_and_256_per_stage() -> None:
    # Validating a register one entry over the bound takes seconds, so the test reads the bound the field enforces.
    assert MAX_EVIDENCE_REFS == 501_024
    assert [getattr(rule, "max_length", None) for rule in CAR.model_fields["evidence_refs"].metadata] == [
        MAX_EVIDENCE_REFS
    ]


def test_what_the_plan_stage_redacted_is_kept_as_an_entry_the_redaction_policy_ran_over() -> None:
    document = copy.deepcopy(RECORD)
    redacted = document["stages"]["plan"]["redaction"]["input"]["digest"]
    for ref in document["evidence_refs"]:
        if ref["digest"] == redacted:
            ref["redaction_policy"] = None
    with pytest.raises(ValidationError, match="what the plan stage redacted is an entry of the evidence register that"):
        CAR.model_validate(document)


def _with_scanners() -> dict[str, Any]:
    """The captured record whose plan stage read a scanner report, its scanner files kept in the register."""
    document = copy.deepcopy(RECORD)
    document["stages"]["plan"]["scanners"] = copy.deepcopy(SCANNERS)
    keep_the_scanner_files(document)
    return document


def test_a_stage_keeps_its_scanner_files_in_the_evidence_register() -> None:
    CAR.model_validate(_with_scanners())


@pytest.mark.parametrize(
    ("named", "message"),
    [
        ("bindings", "the plan stage's copy of its scanner bindings is an entry of the evidence register"),
        ("report", "the checkov report the plan stage kept is an entry of the evidence register"),
        ("observations", "the observations the plan stage read from its checkov report are an entry of the evidence"),
    ],
)
def test_a_scanner_file_a_stage_names_but_does_not_register_is_refused(named: str, message: str) -> None:
    document = _with_scanners()
    scanners = document["stages"]["plan"]["scanners"]
    report = scanners["reports"][0]
    path, digest = {
        "bindings": (scanners["evaluator_binding_set"]["copy_path"], scanners["evaluator_binding_set"]["digest"]),
        "report": (None, report["report_digest"]),
        "observations": (report["observations"], None),
    }[named]
    document["evidence_refs"] = [r for r in document["evidence_refs"] if r["path"] != path and r["digest"] != digest]
    with pytest.raises(ValidationError, match=message):
        CAR.model_validate(document)


def test_a_stage_names_its_scanner_bindings_copy_by_the_digest_the_register_gives() -> None:
    document = _with_scanners()
    document["stages"]["plan"]["scanners"]["evaluator_binding_set"]["digest"] = "sha256:" + "e" * 64
    with pytest.raises(ValidationError, match="copy of its scanner bindings is an entry of the evidence register"):
        CAR.model_validate(document)


@pytest.mark.parametrize("field", ["source", "redaction_policy"])
def test_a_stage_keeps_its_scanner_report_redacted_from_the_file_the_pipeline_gave(field: str) -> None:
    document = _with_scanners()
    kept = document["stages"]["plan"]["scanners"]["reports"][0]["report_digest"]
    for ref in document["evidence_refs"]:
        if ref["digest"] == kept:
            ref[field] = None
    with pytest.raises(ValidationError, match="kept is an entry of the evidence register, redacted from the file"):
        CAR.model_validate(document)


@pytest.mark.parametrize("named", ["events", "assertions", "bindings"])
def test_each_scanner_file_a_stage_keeps_is_an_entry_of_its_own(named: str) -> None:
    document = _with_scanners()
    plan = document["stages"]["plan"]
    plan["scanners"]["reports"][0]["observations"] = {
        "events": plan["events"]["path"],
        "assertions": plan["assertions"]["index"],
        "bindings": plan["scanners"]["evaluator_binding_set"]["copy_path"],
    }[named]
    with pytest.raises(ValidationError, match="each scanner file a stage keeps is an entry of its own"):
        CAR.model_validate(document)


def test_one_scanner_report_given_to_two_stages_is_kept_as_the_same_entries() -> None:
    # The report and the observations read from it are kept at paths named by their digest, so both stages name them.
    document = json.loads((VECTORS / "records" / "iac" / "local_run_deployed.json").read_text(encoding="utf-8"))
    for stage in ("plan", "pre_deploy"):
        scanners = copy.deepcopy(SCANNERS)
        scanners["evaluator_binding_set"]["copy_path"] = f"units/root/{stage}/scanner-bindings.json"
        document["stages"][stage]["scanners"] = scanners
        keep_the_scanner_files(document, stage)
    refs: dict[str, dict[str, Any]] = {}
    for ref in document["evidence_refs"]:
        refs.setdefault(ref["path"], ref)
        if ref["path"].endswith("scanner-bindings.json"):
            ref["ref_id"] = ref["path"].split("/")[2] + "-bindings"
    document["evidence_refs"] = list(refs.values())
    CAR.model_validate(document, context={SKIP_INTEGRITY_CHECKS: True})


def test_two_scanners_reports_with_the_same_bytes_are_never_kept_as_the_same_entry() -> None:
    document = _with_scanners()
    scanners = document["stages"]["plan"]["scanners"]
    first = scanners["reports"][0]
    second = {**copy.deepcopy(first), "tool": "trivy", "observations": first["observations"][:-1] + "9"}
    scanners["reports"].append(second)
    scanners["results_accepted"] *= 2
    scanners["results_without_binding"] *= 2
    observations = next(ref for ref in document["evidence_refs"] if ref["path"] == first["observations"])
    document["evidence_refs"].append({**copy.deepcopy(observations), "ref_id": "trivy", "path": second["observations"]})
    with pytest.raises(ValidationError, match="each scanner file a stage keeps is an entry of its own"):
        CAR.model_validate(document)
