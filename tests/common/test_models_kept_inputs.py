"""Every evaluation input a stage kept is the one its evaluation names, about the record's environment, change,
deployment, drift check and reports, naming files kept redacted, or not kept, in the form of who opened the run."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from typing import Any

import pytest

from iltero_schemas.canonical import canonical_bytes, digest
from iltero_schemas.models.common.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.common.context import MAX_INPUT_BYTES
from iltero_schemas.models.common.kept_inputs import (
    ANOTHER_APPLY_JOB,
    ANOTHER_CHANGE,
    ANOTHER_DEPLOYMENT,
    ANOTHER_DRIFT_CHECK,
    ANOTHER_ENVIRONMENT,
    GIVEN_FILE_DIGESTS_OF_ANOTHER_RUN,
    INPUT_NOT_CANONICAL,
    INPUT_NOT_GIVEN,
    INPUT_TOO_LARGE,
    NOT_AN_INPUT,
    REPORT_NOT_KEPT,
    kept_input_problems,
)
from tests.conftest import VECTORS
from tests.records import keep_events_files, kept_files_by_digest

RECORD: dict[str, Any] = json.loads((VECTORS / "records" / "iac" / "local_run.json").read_text(encoding="utf-8"))
CONTEXT: dict[str, Any] = json.loads((VECTORS / "contexts" / "iac" / "plan_resource.json").read_text(encoding="utf-8"))


def _with_one_kept_input(
    context: dict[str, Any], data: bytes | None = None, change_digest: str = CONTEXT["change"]["digest"]
) -> tuple[CAR, dict[str, bytes], list[int]]:
    """The local run's record of the change ``change_digest`` names (the sample input's, unless given), whose every
    evaluation the policy evaluator decided names ``context`` as its input, kept as ``data`` (its canonical JSON
    unless given), with the bytes kept for it by digest and the indexes of those evaluations. The record is read
    without its integrity checks, which would compare its change digest with its plan."""
    record = copy.deepcopy(RECORD)
    record["change"]["digest"] = change_digest
    data = canonical_bytes(context) if data is None else data
    decided = [
        index
        for index, event in enumerate(record["events"])
        if event["provenance"]["input_digest"] is not None and event["provenance"]["scanner_checks"] is None
    ]
    named = {record["events"][index]["provenance"]["input_digest"] for index in decided}
    for index in decided:
        record["events"][index]["provenance"]["input_digest"] = digest(data)
    # The register lists the input the evaluations now name in place of the ones they named.
    for ref in record["evidence_refs"]:
        if ref["digest"] in named:
            ref.update(digest=digest(data), size_bytes=len(data))
    keep_events_files(record)
    return CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True}), {digest(data): data}, decided


def _about_the_record(sample: dict[str, Any] = CONTEXT, **environment: Any) -> dict[str, Any]:
    """``sample`` made about the local run's environment, with the parts of it ``environment`` gives changed."""
    context = copy.deepcopy(sample)
    context["organization_scope"]["environment"] = {**RECORD["subject"]["environment"], **environment}
    return context


def _problems(context: dict[str, Any], inputs: dict[str, bytes] | None = None) -> list[tuple[str, str]]:
    car, kept, _ = _with_one_kept_input(context)
    return kept_input_problems(car, kept if inputs is None else inputs)


def _everywhere(context: dict[str, Any], what: str) -> list[tuple[str, str]]:
    """``what`` listed at every evaluation the policy evaluator decided."""
    _, _, decided = _with_one_kept_input(context)
    return [(f"events.{index}.provenance.input_digest", what) for index in decided]


def test_an_input_about_the_records_environment_and_change_has_no_problem() -> None:
    assert _problems(_about_the_record()) == []


def test_an_input_the_stage_did_not_keep_is_listed() -> None:
    context = _about_the_record()
    assert _problems(context, inputs={}) == _everywhere(context, INPUT_NOT_GIVEN)


def test_an_input_whose_bytes_have_another_digest_is_listed() -> None:
    context = _about_the_record()
    car, kept, _ = _with_one_kept_input(context)
    ((named, data),) = kept.items()
    assert kept_input_problems(car, {named: data + b" "}) == _everywhere(context, INPUT_NOT_GIVEN)


def test_an_input_not_kept_as_canonical_json_is_listed() -> None:
    context = _about_the_record()
    car, kept, _ = _with_one_kept_input(context, json.dumps(context, indent=2).encode("utf-8"))
    assert kept_input_problems(car, kept) == _everywhere(context, INPUT_NOT_CANONICAL)


def test_a_kept_file_that_is_not_an_evaluation_input_is_listed() -> None:
    not_an_input = {"apiVersion": "iltero.com/v1", "kind": "AssuranceContext"}
    assert _problems(not_an_input) == _everywhere(not_an_input, NOT_AN_INPUT)


def _with_its_kept_input_edited(
    name: str, stage: str, part: str, edit: Callable[[dict[str, Any]], None]
) -> tuple[CAR, dict[str, bytes], list[tuple[str, str]]]:
    """The record ``name`` whose kept input of ``stage`` that carries ``part`` is edited by ``edit``, with the files it
    kept by digest and where each evaluation of that input is named, so a problem listed for it is listed there."""
    record = json.loads((VECTORS / "records" / f"{name}.json").read_text(encoding="utf-8"))
    kept = kept_files_by_digest(name)
    decided = [
        index
        for index, event in enumerate(record["events"])
        if event["evaluation"]["stage"] == stage
        and event["provenance"]["input_digest"] is not None
        and event["provenance"]["scanner_checks"] is None
        and json.loads(kept[event["provenance"]["input_digest"]]).get(part) is not None
    ]
    named = record["events"][decided[0]]["provenance"]["input_digest"]
    context = json.loads(kept[named])
    edit(context)
    data = canonical_bytes(context)
    for index in decided:
        record["events"][index]["provenance"]["input_digest"] = digest(data)
    for ref in record["evidence_refs"]:
        if ref["digest"] == named:
            ref.update(digest=digest(data), size_bytes=len(data))
    keep_events_files(record)
    car = CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})
    return car, {**kept, digest(data): data}, [(f"events.{index}.provenance.input_digest", "") for index in decided]


def _listed(
    name: str, stage: str, part: str, edit: Callable[[dict[str, Any]], None], what: str
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """The problems listed for the record ``name`` whose kept input carrying ``part`` is edited, and ``what`` listed
    at each evaluation of that input."""
    car, kept, where = _with_its_kept_input_edited(name, stage, part, edit)
    return kept_input_problems(car, kept), [(at, what) for at, _ in where]


def _unchanged(context: dict[str, Any]) -> None:
    """Leave the input as the stage kept it."""


def _set(path: str, value: Any) -> Callable[[dict[str, Any]], None]:
    """An edit that sets the dotted ``path`` of an input to ``value``."""

    def edit(context: dict[str, Any]) -> None:
        *parents, last = path.split(".")
        node: Any = context
        for key in parents:
            node = node[int(key)] if isinstance(node, list) else node[key]
        node[int(last) if isinstance(node, list) else last] = value

    return edit


def test_an_input_about_an_environment_of_another_name_is_listed() -> None:
    name, stage = "iac/local_run_post_verify", "post_verify"
    problems, _ = _listed(name, stage, "drift_check", _unchanged, "")
    assert problems == []
    problems, expected = _listed(
        name, stage, "drift_check", _set("organization_scope.environment.name", "staging"), ANOTHER_ENVIRONMENT
    )
    assert problems == expected


def test_an_input_about_another_deployment_than_the_records_is_listed() -> None:
    edit = _set("deployment.apply.source.tool_version", "1.15.0")
    problems, expected = _listed("iac/local_run_deployed", "post_deploy", "deployment", edit, ANOTHER_DEPLOYMENT)
    assert problems == expected


@pytest.mark.parametrize(
    ("name", "path", "value"),
    [
        ("iac/local_run_post_verify", "drift_check.tool_version", "1.15.0"),
        ("image/local_run_deploy_rolled_out", "drift_check.pods_resource_version", "999999"),
    ],
    ids=["an infrastructure change", "an image deploy"],
)
def test_an_input_whose_drift_check_is_not_the_one_the_post_verify_stage_counts_is_listed(
    name: str, path: str, value: str
) -> None:
    problems, expected = _listed(name, "post_verify", "drift_check", _set(path, value), ANOTHER_DRIFT_CHECK)
    assert problems == expected


@pytest.mark.parametrize(
    ("name", "value"),
    [("iac/local_run_deployed", "hmac-sha256:" + "a" * 64), ("iac/governed_run_deployed", None)],
    ids=["keyed in a run the tool opened", "null in a run the server opened"],
)
def test_an_input_naming_a_file_kept_redacted_or_not_kept_in_the_form_of_another_run_is_listed(
    name: str, value: str | None
) -> None:
    edit = _set("deployment.apply.source.digest", value)
    problems, expected = _listed(name, "post_deploy", "deployment", edit, GIVEN_FILE_DIGESTS_OF_ANOTHER_RUN)
    assert problems == expected


@pytest.mark.parametrize(
    ("part", "path", "value"),
    [
        ("tests", "tests.0.file_digest", "sha256:" + "0" * 64),
        ("scans", "scans.0.file_digest", "sha256:" + "0" * 64),
        ("scans", "scans.0.image_digest_source", "pipeline"),
        ("scans", "scans.0.image_digest", "sha256:" + "0" * 64),
        ("tests", "tests.0.image_digest", "sha256:" + "0" * 64),
        ("scans", "scans.0.format", "trivy_json"),
    ],
    ids=[
        "a test report of another file",
        "a scan report of another file",
        "a scan report tied to its image otherwise",
        "a scan report of another image",
        "a test report of another image",
        "a scan report of another format",
    ],
)
def test_an_input_naming_a_report_the_records_build_does_not_name_is_listed(part: str, path: str, value: str) -> None:
    problems, expected = _listed("image/local_run_build", "plan", part, _set(path, value), REPORT_NOT_KEPT)
    assert problems == expected


def test_an_input_naming_the_reports_the_records_build_names_has_no_problem() -> None:
    problems, _ = _listed("image/local_run_build", "plan", "tests", _unchanged, "")
    assert problems == []


def test_an_input_that_says_otherwise_whether_the_environment_is_production_is_listed() -> None:
    context = _about_the_record(production=True)
    assert _problems(context) == _everywhere(context, ANOTHER_ENVIRONMENT)


def test_an_input_about_another_change_is_listed() -> None:
    context = _about_the_record()
    car, kept, _ = _with_one_kept_input(context, change_digest="sha256:" + "0" * 64)
    assert kept_input_problems(car, kept) == _everywhere(context, ANOTHER_CHANGE)


def test_one_kept_input_named_by_several_evaluations_is_listed_at_each() -> None:
    problems = _problems(_about_the_record(production=False))
    assert len(problems) > 1 and {what for _, what in problems} == {ANOTHER_ENVIRONMENT}


def test_an_input_larger_than_an_input_may_be_is_listed_unread() -> None:
    context = _about_the_record()
    car, kept, _ = _with_one_kept_input(context)
    ((named, _data),) = kept.items()
    assert kept_input_problems(car, {named: b" " * (MAX_INPUT_BYTES + 1)}) == _everywhere(context, INPUT_TOO_LARGE)


def test_an_input_whose_apply_job_facts_or_approvals_are_not_the_ones_its_stage_kept_is_listed() -> None:
    name = "iac/governed_run_deployed"
    record = json.loads((VECTORS / "records" / f"{name}.json").read_text(encoding="utf-8"))
    kept = kept_files_by_digest(name)
    assert kept_input_problems(CAR.model_validate(record), kept) == []
    record["stages"]["pre_deploy"]["apply_job_facts"]["plan_age_limit"]["seconds"] = 3600
    pre_deploy = [index for index, event in enumerate(record["events"]) if event["evaluation"]["stage"] == "pre_deploy"]
    problems = kept_input_problems(CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True}), kept)
    assert problems == [(f"events.{index}.provenance.input_digest", ANOTHER_APPLY_JOB) for index in pre_deploy]
