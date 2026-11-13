"""The redaction report of a stage after the deployment: of the part it counts, which the record keeps as it is."""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.car import CAR
from tests.conftest import VECTORS

# The record of each change type that reached its post-verify stage, by its path from the records folder.
VERIFIED_RECORDS = ("iac/local_run_post_verify.json", "image/local_run_deploy.json")
KEPT_STAGES = ("post_deploy", "post_verify")
CASES = [(vector, stage) for vector in VERIFIED_RECORDS for stage in KEPT_STAGES]
IDS = [f"{vector.split('/')[0]}-{stage}" for vector, stage in CASES]


def _record(vector: str) -> dict[str, Any]:
    document: dict[str, Any] = json.loads((VECTORS / "records" / vector).read_text(encoding="utf-8"))
    return document


@pytest.mark.parametrize("vector", VERIFIED_RECORDS)
def test_a_stage_after_the_deployment_reports_redacting_the_part_it_counts(vector: str) -> None:
    stages = CAR.model_validate(_record(vector)).stages
    for record in (stages[stage] for stage in stages if stage.value in KEPT_STAGES):
        assert record.redaction.input.digest == record.coverage.subjects_in_scope.source_digest


@pytest.mark.parametrize(("vector", "stage"), CASES, ids=IDS)
def test_a_redaction_report_of_another_part_than_the_stage_counts_is_refused(vector: str, stage: str) -> None:
    document = _record(vector)
    document["stages"][stage]["redaction"]["input"]["digest"] = "sha256:" + "e" * 64
    with pytest.raises(ValidationError, match=f"the {stage} stage's redaction report is of the part it counts"):
        CAR.model_validate(document)


# A path a redaction report lists, in each of its lists: one the policy hid, one it left unknown, one allowed through.
LISTED_PATHS: dict[str, Any] = {
    "redacted": [{"path": "/apply/changes/0/address", "reason": "secret"}],
    "unknown": ["/apply/changes/0/address"],
    "allowed": [{"path": "/apply/changes/0/address", "reason": "The address names no secret."}],
}


@pytest.mark.parametrize("listed", sorted(LISTED_PATHS))
@pytest.mark.parametrize(("vector", "stage"), CASES, ids=IDS)
def test_a_stage_after_the_deployment_that_lists_a_path_is_refused(vector: str, stage: str, listed: str) -> None:
    document = _record(vector)
    document["stages"][stage]["redaction"][listed] = LISTED_PATHS[listed]
    with pytest.raises(ValidationError, match=f"the {stage} stage redacts nothing: the part it counts is kept as it"):
        CAR.model_validate(document)


@pytest.mark.parametrize("vector", VERIFIED_RECORDS)
def test_a_post_verify_redaction_report_of_the_deployment_is_refused(vector: str) -> None:
    document = _record(vector)
    document["stages"]["post_verify"]["redaction"]["input"]["kind"] = "deployment"
    with pytest.raises(ValidationError, match="the post_verify stage's redaction report is of the drift check it read"):
        CAR.model_validate(document)
