"""Which digest a record's evidence register names for a file the pipeline gave, by how it keeps the file and who
opened the run."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.common.fields import RunOpenedBy
from iltero_schemas.models.common.given_file_digests import (
    KEPT_AS_GIVEN,
    PROJECT_MAPPING_COPY,
    SERVER_RUN_FORM,
    TOOL_RUN_FORM,
    check_given_file_digest_form,
    follows_the_run,
    form_problem,
    project_mapping_copies,
)
from tests.conftest import VECTORS
from tests.records import DEPLOYED

KEYED = "hmac-sha256:" + "a" * 64
PLAIN = "sha256:" + "a" * 64
# A record of a run the tool opened whose plan stage applied a project's scanner check mapping, kept as canonical JSON.
PROJECT_MAPPING: dict[str, Any] = json.loads(
    (VECTORS / "records" / "iac" / "local_run_scanned_project.json").read_text(encoding="utf-8")
)


def _record(name: str) -> dict[str, Any]:
    document: dict[str, Any] = json.loads((VECTORS / "records" / f"{name}.json").read_text(encoding="utf-8"))
    return document


@pytest.mark.parametrize(
    ("value", "run_opened_by", "follows"),
    [
        (KEYED, "server", True),
        (PLAIN, "server", False),
        (None, "server", False),
        (None, "local", True),
        (PLAIN, "local", False),
        (KEYED, "local", False),
    ],
)
def test_a_file_kept_redacted_or_not_kept_is_keyed_in_a_run_the_server_opened_and_unnamed_in_one_the_tool_opened(
    value: str | None, run_opened_by: RunOpenedBy, follows: bool
) -> None:
    assert follows_the_run(value, run_opened_by) is follows
    expected = None if follows else (SERVER_RUN_FORM if run_opened_by == "server" else TOOL_RUN_FORM)
    assert form_problem([value], run_opened_by) == expected


@pytest.mark.parametrize(
    "name",
    [
        "iac/local_run_post_verify",
        "iac/tracked_run_deployed",
        "iac/tracked_run_post_verify",
        "image/tracked_run_deploy_rolled_out",
    ],
)
def test_every_record_vector_names_its_files_in_the_form_of_who_opened_its_run(name: str) -> None:
    check_given_file_digest_form(CAR.model_validate(_record(name)))


def test_a_file_kept_as_the_pipeline_gave_it_is_named_by_its_own_digest() -> None:
    document = copy.deepcopy(DEPLOYED)
    ref = next(ref for ref in document["evidence_refs"] if ref["source"] is not None)
    ref["redaction_policy"] = None
    ref["source"]["digest"] = ref["digest"]
    CAR.model_validate(document)
    for other in (None, KEYED, PLAIN):
        ref["source"]["digest"] = other
        with pytest.raises(ValidationError, match=KEPT_AS_GIVEN):
            CAR.model_validate(document)


def test_only_the_copy_of_a_projects_scanner_check_mapping_names_another_plain_digest_than_its_own() -> None:
    car = CAR.model_validate(PROJECT_MAPPING)
    (copy_path,) = project_mapping_copies(car)
    (entry,) = [ref for ref in PROJECT_MAPPING["evidence_refs"] if ref["path"] == copy_path]
    assert entry["redaction_policy"] is None and entry["canonicalization"] is not None
    assert entry["source"]["digest"] != entry["digest"] and entry["source"]["digest"].startswith("sha256:")
    for value in (None, KEYED):
        document = copy.deepcopy(PROJECT_MAPPING)
        next(ref for ref in document["evidence_refs"] if ref["path"] == copy_path)["source"]["digest"] = value
        with pytest.raises(ValidationError, match=PROJECT_MAPPING_COPY):
            CAR.model_validate(document)


def test_an_entry_canonicalized_like_the_mapping_copy_but_not_it_is_named_by_its_own_digest() -> None:
    document = copy.deepcopy(PROJECT_MAPPING)
    copies = {used["copy_path"] for used in document["stages"]["plan"]["scanners"]["scanner_check_mappings"]}
    other = next(
        ref
        for ref in document["evidence_refs"]
        if ref["source"] is None and ref["redaction_policy"] is None and ref["path"] not in copies
    )
    other.update(canonicalization="RFC8785", source={"name": "other.json", "digest": PLAIN})
    with pytest.raises(ValidationError, match=KEPT_AS_GIVEN):
        CAR.model_validate(document)
