"""Comparing a record with its run statement: how the statement lists the record, every difference with its reason
in the order the function documents, the notes, and the served parts not compared; none raises."""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
from typing import Any

import pytest

from iltero_schemas.canonical import digest_of
from iltero_schemas.models.common.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.common.run_statement import RunStatement, ServedPartDigests
from iltero_schemas.statement import (
    RecordComparison,
    ServedPartDiffers,
    VerifiedRunStatement,
    compare_record,
    kept_served_parts,
)
from iltero_schemas.trust import SigningKey
from iltero_schemas.vectors.vector_run_statements import (
    OPERATOR_RUN_STATEMENT_KEY_ID,
    RUN_STATEMENT_KEY_ID,
    run_statement_vector_keys,
)
from tests.statements import DEPLOYED, IMAGE_DEPLOY, record_of, statement_document, statement_parts

Edit = Callable[[list[dict[str, Any]], dict[str, Any]], None]
OTHER = "sha256:" + "0" * 63 + "1"
PRE_DEPLOY = 1


KEYS = run_statement_vector_keys()


def _compare(
    edit: Edit,
    name: str = DEPLOYED,
    car: CAR | None = None,
    *,
    key: SigningKey = KEYS[RUN_STATEMENT_KEY_ID],
    keys: Mapping[str, SigningKey] = KEYS,
) -> RecordComparison:
    """``car`` (the record vector ``name`` by default) compared with its statement changed by ``edit``, as if ``key``
    signed it and verified against ``keys``."""
    subjects, predicate = copy.deepcopy(statement_parts(name))
    predicate["run"]["server"] = key.server
    edit(subjects, predicate)
    statement = RunStatement.model_validate(statement_document(subjects, predicate))
    verified = VerifiedRunStatement(statement, b"", "sha256:" + "0" * 64, key)
    return compare_record(car or record_of(name)[0], verified, keys)


def _reasons(edit: Edit, name: str = DEPLOYED, car: CAR | None = None) -> list[str]:
    return [found.reason for found in _compare(edit, name, car).differences]


def _sets(path: list[str | int], value: Any) -> Edit:
    def edit(_subjects: list[dict[str, Any]], predicate: dict[str, Any]) -> None:
        target: Any = predicate
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = value

    return edit


def _changed(name: str, path: list[str], value: Any) -> CAR:
    document = record_of(name)[0].model_dump(mode="json", by_alias=True)
    target: Any = document
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    return CAR.model_validate(document, context={SKIP_INTEGRITY_CHECKS: True})


def _final_is(digest: str, *, earlier_copy: bool = False) -> Edit:
    def edit(subjects: list[dict[str, Any]], predicate: dict[str, Any]) -> None:
        last = predicate["units"][0]["stages"][-1]["accepted_records"]
        last[:] = [{"digest": last[0]["digest"], "counts": False}] if earlier_copy else []
        last.append({"digest": digest, "counts": True})
        subjects[0]["digest"]["sha256"] = digest.removeprefix("sha256:")

    return edit


@pytest.mark.parametrize("name", [DEPLOYED, IMAGE_DEPLOY])
def test_a_record_and_the_statement_of_its_run_do_not_differ_and_the_record_is_the_subject(name: str) -> None:
    found = _compare(lambda _s, _p: None, name)
    assert (found.listed_as, found.differences, found.notes, found.not_compared) == ("subject", [], [], [])


def test_the_record_digest_is_computed_from_the_record_itself() -> None:
    car, file_digest = record_of(DEPLOYED)
    assert _compare(lambda _s, _p: None).record_digest == file_digest == digest_of(car.model_dump(by_alias=True))


def test_a_statement_of_another_run_lists_that_difference_only() -> None:
    assert _reasons(_sets(["run", "id"], "1c0a4d63-7d2e-4e5f-8a1b-3b8e6c2d9f54")) == ["another_run"]


def test_a_record_of_a_run_the_server_did_not_open_differs() -> None:
    assert _reasons(lambda _s, _p: None, "iac/local_run.json") == ["run_not_opened_by_the_server"]


def test_a_statement_of_another_activity_or_environment_lists_each() -> None:
    assert _reasons(_sets(["run", "environment"], "staging")) == ["another_environment"]
    build = statement_parts(IMAGE_DEPLOY)[1]["units"][0]["accepted_build"]

    def image_deploy(_subjects: list[dict[str, Any]], predicate: dict[str, Any]) -> None:
        predicate["run"]["activity"] = "image_deploy"
        predicate["units"][0]["accepted_build"] = build

    assert _reasons(image_deploy) == ["another_activity"]


def test_a_record_of_a_unit_the_statement_does_not_name_is_listed_and_not_listed() -> None:
    def another_unit(subjects: list[dict[str, Any]], predicate: dict[str, Any]) -> None:
        subjects[0]["name"] = predicate["units"][0]["unit"] = "network"
        predicate["run"]["units"] = ["network"]
        predicate["gaps"]["stages_never_accepted"][0]["unit"] = "network"

    assert _reasons(another_unit) == ["another_unit", "record_not_listed"]


def test_a_record_the_statement_does_not_list_is_not_listed() -> None:
    found = _compare(_final_is(OTHER))
    assert (found.listed_as, [d.reason for d in found.differences]) == ("not_listed", ["record_not_listed"])


def test_a_record_the_statement_lists_as_refused_is_refused_by_the_server() -> None:
    def refused(subjects: list[dict[str, Any]], predicate: dict[str, Any]) -> None:
        digest = "sha256:" + subjects.pop()["digest"]["sha256"]
        for stage in predicate["units"][0]["stages"]:
            stage["accepted_records"] = []
        expected = predicate["settings"]["expected_stages"]
        predicate["gaps"]["stages_never_accepted"] = [{"unit": "root", "stage": stage} for stage in expected]
        reason = "record_not_accepted"
        predicate["gaps"]["refused_records"] = [{"unit": "root", "stage": "plan", "digest": digest, "reason": reason}]

    found = _compare(refused)
    assert (found.listed_as, [d.reason for d in found.differences]) == ("refused", ["record_refused_by_the_server"])


def test_a_record_the_statement_lists_as_a_conflicting_upload_is_not_listed_as_accepted() -> None:
    def conflicting(subjects: list[dict[str, Any]], predicate: dict[str, Any]) -> None:
        digest = "sha256:" + subjects[0]["digest"]["sha256"]
        _final_is(OTHER)(subjects, predicate)
        predicate["units"][0]["stages"][-1]["conflicting_uploads"] = [digest]

    found = _compare(conflicting)
    assert found.listed_as == "conflicting_upload"
    assert [d.reason for d in found.differences] == ["record_is_a_conflicting_upload"]


def test_an_earlier_accepted_copy_is_listed_with_a_note_naming_the_record_that_replaced_it() -> None:
    found = _compare(_final_is(OTHER, earlier_copy=True))
    assert (found.listed_as, found.replaced_by, found.differences) == ("earlier_copy", OTHER, [])
    assert [note.reason for note in found.notes] == ["record_not_the_one_that_counts"]


def test_a_record_that_counts_at_an_earlier_stage_is_listed_with_the_subject_that_replaced_it() -> None:
    def earlier_counts(subjects: list[dict[str, Any]], predicate: dict[str, Any]) -> None:
        digest = "sha256:" + subjects[0]["digest"]["sha256"]
        predicate["units"][0]["stages"][0]["accepted_records"] = [{"digest": digest, "counts": True}]
        _final_is(OTHER)(subjects, predicate)

    found = _compare(earlier_counts)
    assert (found.listed_as, found.replaced_by, found.differences, found.notes) == ("counting_record", OTHER, [], [])


@pytest.mark.parametrize("part", ["approvals", "commit_review", "apply_job_facts"])
def test_a_served_part_the_record_keeps_whose_digest_is_not_the_signed_one_differs(part: str) -> None:
    for signed in (OTHER, None):
        edit = _sets(["units", 0, "stages", PRE_DEPLOY, "served_parts", part], signed)
        assert _reasons(edit) == ["served_part_differs"]


@pytest.mark.parametrize("part", ["approvals", "commit_review", "apply_job_facts"])
def test_a_served_part_that_differs_names_its_stage_and_part(part: str) -> None:
    (found,) = _compare(_sets(["units", 0, "stages", PRE_DEPLOY, "served_parts", part], OTHER)).differences
    assert isinstance(found, ServedPartDiffers) and (found.stage, found.part) == ("pre_deploy", part)


def test_served_exceptions_the_record_keeps_are_compared_by_the_digest_of_its_copy() -> None:
    edit = _sets(["units", 0, "stages", 0, "served_parts", "served_exceptions"], OTHER)
    assert _reasons(edit) == ["served_part_differs"]


def test_a_part_the_server_signed_that_the_record_keeps_no_copy_of_is_returned_as_not_compared() -> None:
    name = "iac/tracked_run_deployed_without_server_facts.json"
    found = _compare(_sets(["units", 0, "stages", PRE_DEPLOY, "served_parts", "approvals"], OTHER), name)
    assert found.differences == []
    assert [(n.stage, n.part) for n in found.not_compared] == [("pre_deploy", "approvals")]


def test_the_served_parts_compared_are_the_fields_a_statement_signs() -> None:
    car, _ = record_of(DEPLOYED)
    pre_deploy = next(stage for key, stage in car.stages.items() if key.value == "pre_deploy")
    assert isinstance(kept_served_parts(pre_deploy), ServedPartDigests)


def test_the_record_commit_is_compared_with_the_ci_job_of_each_stage() -> None:
    edit = _sets(["units", 0, "stages", PRE_DEPLOY, "ci_job", "commit"], "a1b2c3d000000000000000000000000000000000")
    assert _reasons(edit) == ["ci_job_differs"]


def test_the_repository_is_compared_only_when_the_record_names_one() -> None:
    car = _changed(DEPLOYED, ["subject", "source", "repository"], {"name": "example/another"})
    assert record_of(DEPLOYED)[0].subject.source.repository is None
    assert _reasons(lambda _s, _p: None, car=car)[-3:] == ["ci_job_differs"] * 3


def test_required_assertions_and_expected_stages_are_compared_with_the_settings() -> None:
    assert _reasons(_sets(["settings", "required_assertion_digests", "plan"], OTHER)) == ["required_assertions_differ"]

    def fewer(_subjects: list[dict[str, Any]], predicate: dict[str, Any]) -> None:
        predicate["settings"]["expected_stages"] = ["plan", "pre_deploy", "post_deploy"]
        predicate["gaps"]["stages_never_accepted"] = []

    assert _reasons(fewer) == ["expected_stages_differ"]


def test_a_stage_of_the_record_the_statement_does_not_list_differs() -> None:
    def drop_plan(_subjects: list[dict[str, Any]], predicate: dict[str, Any]) -> None:
        predicate["units"][0]["stages"].pop(0)
        predicate["gaps"]["stages_never_accepted"].insert(0, {"unit": "root", "stage": "plan"})

    assert _reasons(drop_plan) == ["stage_not_listed"]


def test_a_reference_time_from_the_server_is_compared_with_when_it_issued_the_facts() -> None:
    edit = _sets(["units", 0, "stages", 0, "facts", "issued_at"], "2026-09-16T18:29:00Z")
    assert _reasons(edit) == ["reference_time_differs"]


def test_the_bundle_enforcement_mode_and_scanner_check_mapping_are_compared_with_the_settings() -> None:
    assert _reasons(_sets(["settings", "bundle_tarball_digest"], OTHER)) == ["bundle_differs"] * 3
    assert _reasons(_sets(["settings", "enforcement_mode"], "advisory")) == ["enforcement_mode_differs"] * 2
    scanned = "iac/tracked_run_scanned_with_the_served_mapping.json"
    edit = _sets(["settings", "scanner_check_mapping_descriptor_digest"], OTHER)
    assert _reasons(edit, scanned) == ["scanner_check_mapping_differs"]


def test_a_bundle_signed_by_a_key_of_another_server_than_the_statements_differs() -> None:
    operator = KEYS[OPERATOR_RUN_STATEMENT_KEY_ID]
    assert operator.server != KEYS["dev-signing-key-vectors"].server
    assert [d.reason for d in _compare(lambda _s, _p: None, key=operator).differences] == [
        "bundle_of_another_server"
    ] * 3


def test_a_bundle_signed_by_a_key_the_trust_set_does_not_hold_differs() -> None:
    keys = {key_id: key for key_id, key in KEYS.items() if key_id != "dev-signing-key-vectors"}
    assert [d.reason for d in _compare(lambda _s, _p: None, keys=keys).differences] == ["bundle_of_another_server"] * 3


def test_a_record_the_statement_lists_as_a_refused_upload_is_refused_by_the_server() -> None:
    def refused(subjects: list[dict[str, Any]], predicate: dict[str, Any]) -> None:
        digest = "sha256:" + subjects[0]["digest"]["sha256"]
        _final_is(OTHER)(subjects, predicate)
        refused_upload = {"unit": "root", "stage": "plan", "digest": digest, "reason": "too_large"}
        predicate["gaps"]["refused_uploads"] = [refused_upload]

    found = _compare(refused)
    assert (found.listed_as, [d.reason for d in found.differences]) == ("refused", ["record_refused_by_the_server"])


def test_an_image_deploy_of_another_build_differs() -> None:
    edit = _sets(["units", 0, "accepted_build", "record_digest"], OTHER)
    assert _reasons(edit, IMAGE_DEPLOY) == ["another_build"]


def test_every_difference_is_listed_in_the_documented_order() -> None:
    def many(subjects: list[dict[str, Any]], predicate: dict[str, Any]) -> None:
        predicate["run"]["environment"] = "staging"
        _final_is(OTHER)(subjects, predicate)
        predicate["settings"]["expected_stages"] = ["plan", "pre_deploy", "post_deploy"]
        predicate["gaps"]["stages_never_accepted"] = []
        predicate["settings"]["required_assertion_digests"]["plan"] = OTHER
        predicate["units"][0]["stages"][PRE_DEPLOY]["served_parts"]["approvals"] = OTHER

    assert _reasons(many) == [
        "another_environment",
        "record_not_listed",
        "expected_stages_differ",
        "required_assertions_differ",
        "served_part_differs",
    ]
