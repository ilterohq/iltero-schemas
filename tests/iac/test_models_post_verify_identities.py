"""The resource identities document a post-verify stage keeps, checked against the record."""

from __future__ import annotations

import json
from typing import Any

import pytest

from iltero_schemas.canonical import canonical_bytes, digest
from iltero_schemas.canonical.common.run_digest_key import keyed_given_file_digest
from iltero_schemas.change_types.common.kept_file_problems import kept_file_problems
from iltero_schemas.change_types.iac.change import IacChange
from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.common.kept_files import KeptFiles
from iltero_schemas.models.iac.post_verify_identities import (
    ANOTHER_TOOL,
    ANOTHER_UNIT,
    APPLIED_PLAN_NAMED,
    IDENTITIES_NOT_GIVEN,
    IDENTITIES_NOT_READABLE,
    IDENTITIES_WITHOUT_A_POST_VERIFY_STAGE,
    NOT_READ_FROM_A_REFRESH_ONLY_PLAN,
    NOT_THE_SECOND_READING,
    POST_VERIFY_IDENTITIES_REF_ID,
    REFRESH_ONLY_PLAN_NOT_NAMED_BY_A_KEYED_DIGEST,
    STATE_NAMED_BY_A_KEYED_DIGEST_IN_A_TOOL_RUN,
    check_post_verify_identities_entry,
    post_verify_identities_problems,
)
from iltero_schemas.vectors.kept_files import kept_files_of
from iltero_schemas.vectors.run_digest_key import vector_run_digest_key
from iltero_schemas.vectors.vector_signing_keys import vector_signing_keys
from tests.conftest import VECTORS
from tests.server_runs import verify_es256

POST_VERIFY = "iac/local_run_post_verify"
SECOND_READING = keyed_given_file_digest("sha256:" + "5" * 64, vector_run_digest_key())
ANOTHER_READING = keyed_given_file_digest("sha256:" + "6" * 64, vector_run_digest_key())


def _entry_of_the_identities(name: str = POST_VERIFY) -> str:
    """Where the problems of the record ``name``'s post-verify identities are listed: their register entry."""
    record: dict[str, Any] = json.loads((VECTORS / "records" / f"{name}.json").read_text(encoding="utf-8"))
    found = (i for i, ref in enumerate(record["evidence_refs"]) if ref["ref_id"] == POST_VERIFY_IDENTITIES_REF_ID)
    return f"evidence_refs.{next(found)}"


ENTRY = _entry_of_the_identities()


def _record(name: str = POST_VERIFY) -> dict[str, Any]:
    document: dict[str, Any] = json.loads((VECTORS / "records" / f"{name}.json").read_text(encoding="utf-8"))
    return document


def _kept_identities_bytes() -> bytes:
    """The bytes of the resource identities document the sample record's post-verify stage kept."""
    entry = next(ref for ref in _record()["evidence_refs"] if ref["ref_id"] == POST_VERIFY_IDENTITIES_REF_ID)
    return kept_files_of(POST_VERIFY)[entry["path"]]


def _kept_identities() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(_kept_identities_bytes())
    return document


def _files(identities: dict[str, bytes]) -> KeptFiles:
    return KeptFiles(
        scanner_check_mappings={},
        observations={},
        reports={},
        plans={},
        assertions={},
        local_exceptions={},
        served_exceptions={},
        inputs={},
        identities=identities,
        served_bundles={},
    )


def _following(record: dict[str, Any], data: bytes) -> CAR:
    """``record`` with the register entry of its post-verify identities naming ``data``."""
    entry = next(ref for ref in record["evidence_refs"] if ref["ref_id"] == POST_VERIFY_IDENTITIES_REF_ID)
    entry["digest"], entry["size_bytes"] = digest(data), len(data)
    return CAR.model_validate(record)


def _change(car: CAR) -> IacChange:
    assert isinstance(car.change, IacChange)
    return car.change


def _problems(car: CAR, data: bytes) -> list[tuple[str, str]]:
    return post_verify_identities_problems(car, _change(car), _files({digest(data): data}))


def _with_state_digest(value: str | None) -> bytes:
    """The kept identities naming ``value`` as the state's digest, under the version its form names."""
    document = _kept_identities()
    state = document["sources"]["state"]
    state["digest"] = value
    state["digest_version"] = "1" if value is not None and value.startswith("hmac-sha256:") else "redacted-1"
    return canonical_bytes(document)


def _of_a_server_run(car: CAR, second_reading: str) -> CAR:
    """``car`` as a record of a run the server opened whose drift check names ``second_reading``: only the values the
    check reads change, so no other rule of a record of a run the server opened is met."""
    change = _change(car)
    assert change.drift_check is not None
    drift_check = change.drift_check.model_copy(update={"second_reading_digest": second_reading})
    return car.model_copy(
        update={
            "run": car.run.model_copy(update={"opened_by": "server"}),
            "change": change.model_copy(update={"drift_check": drift_check}),
        }
    )


def test_identities_as_the_post_verify_stage_of_a_run_the_tool_opened_kept_them_have_no_problem() -> None:
    data = _kept_identities_bytes()
    car = CAR.model_validate(_record())
    state = _kept_identities()["sources"]["state"]
    assert state["digest"].startswith("sha256:") and state["digest_version"] == "redacted-1"
    assert _problems(car, data) == []


def test_a_record_whose_post_verify_stage_kept_no_identities_document_has_no_problem() -> None:
    car = CAR.model_validate(_record("iac/local_run_deployed"))
    assert post_verify_identities_problems(car, _change(car), _files({})) == []


def test_identities_not_given_are_listed() -> None:
    car = CAR.model_validate(_record())
    problems = post_verify_identities_problems(car, _change(car), _files({}))
    assert problems == [(ENTRY, IDENTITIES_NOT_GIVEN)]


def test_identities_whose_bytes_have_another_digest_are_listed() -> None:
    car = CAR.model_validate(_record())
    edited = _kept_identities_bytes() + b" "
    entry = car.evidence_refs[int(ENTRY.removeprefix("evidence_refs."))]
    files = _files({entry.digest: edited})
    assert post_verify_identities_problems(car, _change(car), files) == [(ENTRY, IDENTITIES_NOT_GIVEN)]


def test_a_kept_file_that_is_not_a_resource_identities_document_is_listed() -> None:
    document = _kept_identities()
    document["kind"] = "AssuranceEvent"
    data = canonical_bytes(document)
    assert _problems(_following(_record(), data), data) == [(ENTRY, IDENTITIES_NOT_READABLE)]


def test_a_kept_file_that_is_not_json_is_listed() -> None:
    data = b"{not json"
    assert _problems(_following(_record(), data), data) == [(ENTRY, IDENTITIES_NOT_READABLE)]


def test_identities_about_a_unit_other_than_the_records_are_listed() -> None:
    document = _kept_identities()
    document["unit"] = "another_unit"
    data = canonical_bytes(document)
    assert _problems(_following(_record(), data), data) == [(ENTRY, ANOTHER_UNIT)]


def test_identities_naming_an_applied_plan_are_listed() -> None:
    record = _record()
    document = _kept_identities()
    # Identities that name an applied plan are read from the state file and list what left it.
    document["sources"]["read_from"] = "state_file"
    document["sources"]["plan"] = record["change"]["identity"]["sources"]["plan"]
    document["removed"], document["removed_unresolved"] = [], []
    document["tool_data"]["deposed_deleted"] = 0
    data = canonical_bytes(document)
    assert _problems(_following(record, data), data) == [
        (ENTRY, NOT_READ_FROM_A_REFRESH_ONLY_PLAN),
        (ENTRY, APPLIED_PLAN_NAMED),
    ]


def test_a_register_entry_named_as_the_post_verify_identities_needs_a_reported_post_verify_stage() -> None:
    record = _record("iac/local_run_deployed")
    car = CAR.model_validate(record)
    entry = car.evidence_refs[0].model_copy(
        update={"path": "artifacts/sha256-" + "0" * 64, "ref_id": POST_VERIFY_IDENTITIES_REF_ID}
    )
    with pytest.raises(ValueError, match=IDENTITIES_WITHOUT_A_POST_VERIFY_STAGE):
        check_post_verify_identities_entry(car.model_copy(update={"evidence_refs": [*car.evidence_refs, entry]}))
    check_post_verify_identities_entry(CAR.model_validate(_record()))


def test_identities_not_read_from_a_refresh_only_plan_are_listed() -> None:
    document = _kept_identities()
    document["sources"]["read_from"] = "state_file"
    data = canonical_bytes(document)
    assert _problems(_following(_record(), data), data) == [(ENTRY, NOT_READ_FROM_A_REFRESH_ONLY_PLAN)]


def test_identities_naming_a_tool_other_than_the_one_that_applied_the_deployment_are_listed() -> None:
    data = _kept_identities_bytes()
    car = _following(_record(), data)
    change = _change(car)
    assert change.deployment is not None
    # The contract knows one IaC tool today, so another is written past the model's check.
    source = change.deployment.apply.source.model_copy(update={"tool": "another_tool"})
    apply = change.deployment.apply.model_copy(update={"source": source})
    other = change.model_copy(update={"deployment": change.deployment.model_copy(update={"apply": apply})})
    assert post_verify_identities_problems(car, other, _files({digest(data): data})) == [(ENTRY, ANOTHER_TOOL)]


def test_identities_of_a_run_the_tool_opened_naming_the_state_by_a_keyed_digest_are_listed() -> None:
    data = _with_state_digest(SECOND_READING)
    assert _problems(_following(_record(), data), data) == [(ENTRY, STATE_NAMED_BY_A_KEYED_DIGEST_IN_A_TOOL_RUN)]


def test_identities_of_a_run_the_tool_opened_naming_the_state_by_a_plain_digest_have_no_problem() -> None:
    """Only a holder of the refresh-only plan computes the redacted state digest of its prior state again."""
    data = _with_state_digest("sha256:" + "5" * 64)
    assert _problems(_following(_record(), data), data) == []


def test_identities_naming_the_state_by_no_digest_are_not_readable() -> None:
    data = _with_state_digest(None)
    assert _problems(_following(_record(), data), data) == [(ENTRY, IDENTITIES_NOT_READABLE)]


def test_identities_of_a_run_the_server_opened_naming_the_second_reading_by_its_keyed_digest_have_no_problem() -> None:
    data = _with_state_digest(SECOND_READING)
    car = _of_a_server_run(_following(_record(), data), SECOND_READING)
    assert _problems(car, data) == []


def test_identities_of_a_run_the_server_opened_naming_the_refresh_plan_by_no_keyed_digest_are_listed() -> None:
    data = _with_state_digest("sha256:" + "5" * 64)
    car = _of_a_server_run(_following(_record(), data), SECOND_READING)
    assert _problems(car, data) == [(ENTRY, REFRESH_ONLY_PLAN_NOT_NAMED_BY_A_KEYED_DIGEST)]


def test_identities_of_a_run_the_server_opened_naming_another_reading_than_the_second_are_listed() -> None:
    data = _with_state_digest(ANOTHER_READING)
    car = _of_a_server_run(_following(_record(), data), SECOND_READING)
    assert _problems(car, data) == [(ENTRY, NOT_THE_SECOND_READING)]


def test_every_check_a_reader_makes_lists_the_problems_of_the_post_verify_identities() -> None:
    car = CAR.model_validate(_record())
    assert (ENTRY, IDENTITIES_NOT_GIVEN) in kept_file_problems(car, _files({}), vector_signing_keys(), verify_es256)
