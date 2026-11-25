"""The served bundle a stage kept, against the trust set, the stage and its events: one test per problem the check
lists."""

from __future__ import annotations

import base64
import copy
import json
from typing import Any

import pytest

from iltero_schemas.canonical import digest
from iltero_schemas.models.common.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.common.kept_bundles import (
    ANOTHER_BUNDLE,
    ANOTHER_CAPABILITIES_DIGEST,
    ANOTHER_CONTENT_DIGEST,
    ANOTHER_MODULE,
    ANOTHER_TARBALL,
    BUNDLE_NOT_IN_THE_REGISTER,
    KEY_NOT_IN_THE_TRUST_SET,
    KEY_REVOKED,
    MODULE_NOT_IN_THE_BUNDLE,
    REVISION_NOT_THE_METADATA,
    SIGNATURE_NOT_COVERING_THE_FILES,
    SIGNATURE_NOT_VALID,
    TARBALL_NOT_GIVEN,
    TARBALL_NOT_READABLE,
    served_bundle_problems,
    served_bundle_results,
)
from iltero_schemas.vectors.kept_files import kept_files_of, kept_served_bundles
from iltero_schemas.vectors.plans import set_pointer
from tests.common.test_kept_bundles_vectors import CASES, KEYS, problems_of
from tests.conftest import VECTORS
from tests.server_runs import verify_es256


def _case(name: str, change_type: str = "iac") -> dict[str, Any]:
    return next(case for case in CASES if case["vector"].startswith(f"{change_type}/") and case["name"] == name)


def _whats(name: str, change_type: str = "iac") -> set[str]:
    return {what for _, what in problems_of(_case(name, change_type))}


def test_the_stages_own_entry_naming_another_tarball_than_the_stage_is_listed() -> None:
    assert _whats("register_naming_another_tarball_than_the_stage") == {ANOTHER_TARBALL}


def test_a_stage_whose_tarball_digest_no_entry_of_the_register_names_is_listed() -> None:
    assert _whats("register_keeping_no_entry_with_the_digest_of_the_stages_tarball") == {BUNDLE_NOT_IN_THE_REGISTER}


def test_a_tarball_not_given_is_listed_at_each_stage_that_kept_one() -> None:
    problems = problems_of(_case("no_tarball_given"))
    assert {what for _, what in problems} == {TARBALL_NOT_GIVEN} and len(problems) == 3


def test_bytes_given_under_the_entrys_digest_that_are_not_its_bytes_are_listed() -> None:
    assert _whats("tarball_given_under_its_entrys_digest_with_other_bytes") == {TARBALL_NOT_GIVEN}


def test_a_tarball_the_bundle_reader_refuses_is_listed_not_raised() -> None:
    assert _whats("tarball_the_reader_refuses") == {TARBALL_NOT_READABLE}


def test_a_tarball_pinned_with_a_key_the_trust_set_does_not_hold_is_listed() -> None:
    assert _whats("tarball_pinned_with_a_key_not_in_the_trust_set") == {KEY_NOT_IN_THE_TRUST_SET}


def test_a_tarball_pinned_with_a_revoked_key_is_listed() -> None:
    assert _whats("tarball_pinned_with_a_revoked_key") == {KEY_REVOKED}


def test_a_tarball_whose_signature_does_not_verify_under_its_key_is_listed() -> None:
    assert _whats("tarball_whose_signature_does_not_verify_under_its_key") == {SIGNATURE_NOT_VALID}


def test_a_stage_naming_another_content_digest_than_its_signed_manifest_is_listed() -> None:
    assert _whats("stage_naming_another_content_digest_than_its_signed_manifest") == {ANOTHER_CONTENT_DIGEST}


def test_a_stage_naming_another_allowlist_digest_than_its_signed_manifest_is_listed() -> None:
    assert _whats("stage_naming_another_allowlist_digest_than_its_signed_manifest") == {ANOTHER_CAPABILITIES_DIGEST}


def test_the_results_name_the_stages_whose_kept_bundle_passed_every_check() -> None:
    document = json.loads((VECTORS / "records" / "iac" / "tracked_run_deployed.json").read_text(encoding="utf-8"))
    car = CAR.model_validate(document)
    bundles = kept_served_bundles(document, kept_files_of("iac/tracked_run_deployed"))
    results = served_bundle_results(car, bundles, KEYS, verify_es256)
    assert results.problems == [] and results.verified_stages == {stage.value for stage in car.stages}
    case = _case("tarball_holding_no_module_of_an_assertion_its_stage_evaluated")
    edited = copy.deepcopy(document)
    for pointer, value in case["set"].items():
        set_pointer(edited, pointer, value)
    data = base64.b64decode(case["tarballs"]["base64"])
    car = CAR.model_validate(edited, context={SKIP_INTEGRITY_CHECKS: True})
    results = served_bundle_results(car, {**bundles, digest(data): data}, KEYS, verify_es256)
    assert results.problems and results.verified_stages == {"plan", "post_deploy"}


def test_a_tarball_whose_manifest_revision_is_not_its_metadata_is_listed() -> None:
    assert _whats("tarball_whose_manifest_revision_is_not_its_metadata") == {REVISION_NOT_THE_METADATA}


def test_a_tarball_whose_signed_bytes_do_not_cover_its_files_is_listed() -> None:
    assert _whats("tarball_whose_signature_does_not_cover_its_files") == {SIGNATURE_NOT_COVERING_THE_FILES}


@pytest.mark.parametrize("change_type", ["iac", "image"])
def test_an_event_whose_assertion_has_no_module_in_the_kept_bundle_is_listed(change_type: str) -> None:
    name = "tarball_holding_no_module_of_an_assertion_its_stage_evaluated"
    assert _whats(name, change_type) == {MODULE_NOT_IN_THE_BUNDLE}


def test_an_event_whose_compiled_digest_is_not_its_modules_is_listed() -> None:
    assert _whats("tarball_holding_another_module_than_its_event_ran") == {ANOTHER_MODULE}


@pytest.mark.parametrize(
    "name",
    [
        "event_naming_another_bundle_than_its_stage_ran_over",
        "event_whose_bundle_differs_from_its_stages_only_by_its_key",
        "event_naming_a_served_bundle_in_a_stage_that_ran_over_none",
    ],
)
def test_an_event_naming_another_bundle_than_its_stage_ran_over_is_listed(name: str) -> None:
    assert _whats(name) == {ANOTHER_BUNDLE}


@pytest.mark.parametrize("name", ["local_run.json", "local_run_deployed.json"])
def test_a_record_that_ran_over_no_served_bundle_has_nothing_to_check(name: str) -> None:
    record = CAR.model_validate(json.loads((VECTORS / "records" / "iac" / name).read_text(encoding="utf-8")))
    assert served_bundle_problems(record, {}, KEYS, verify_es256) == []
