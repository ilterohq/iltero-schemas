"""The run statement vectors: each record of a tracked run has a statement that verifies and names the record as it is
now, and each case gives what it names: the refusal, or what comparing it with its record finds."""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.canonical import digest, digest_of
from iltero_schemas.models.common.run_statement import RunStatement
from iltero_schemas.models.common.strict_json import strict_json
from iltero_schemas.statement import (
    NOT_A_RUN_STATEMENT,
    RECORD_DIFFERENCES,
    RECORD_NOTES,
    RUN_STATEMENT_DOES_NOT_HOLD,
    RunStatementError,
    compare_record,
    read_envelope,
    verify_run_statement,
)
from iltero_schemas.vectors.vector_run_statements import (
    PACKAGED_RECORD,
    TRUST_SET_NAMES,
    case_record,
    run_statement_trust_sets,
    run_statement_vector_keys,
    tracked_records,
)
from tests.conftest import CHANGE_TYPES, VECTORS
from tests.server_runs import verify_es256

TRUST_SETS = run_statement_trust_sets(run_statement_vector_keys())
CASES = [
    (folder, case)
    for folder in ("run_statements_invalid", "run_statements_valid")
    for change_type in CHANGE_TYPES
    for case in json.loads((VECTORS / folder / change_type / "cases.json").read_text(encoding="utf-8"))
]
IDS = [f"{folder}:{case['record'].split('/')[0]}:{case['name']}" for folder, case in CASES]


def _envelope(case: dict[str, Any]) -> bytes:
    return json.dumps(case["envelope"]).encode("utf-8")


def test_every_record_of_a_tracked_run_but_the_packaged_one_has_a_statement() -> None:
    listed = json.loads((VECTORS / "run_statements" / "digests.json").read_text(encoding="utf-8"))
    assert sorted(listed) == tracked_records()
    assert PACKAGED_RECORD not in listed


@pytest.mark.parametrize("name", tracked_records())
def test_each_statement_verifies_and_names_its_record_as_the_record_is_now(name: str) -> None:
    """A statement names its record's digest, so a record vector that changed needs the statements signed again
    (``scripts/sign_run_statement_vectors.py``)."""
    verified = verify_run_statement(
        (VECTORS / "run_statements" / name).read_bytes(), TRUST_SETS["development"], verify_es256
    )
    found = compare_record(case_record({"record": name}), verified, TRUST_SETS["development"])
    assert (found.listed_as, found.differences, found.notes, found.not_compared) == ("subject", [], [], [])
    assert [subject.record_digest for subject in verified.statement.subject] == [
        digest((VECTORS / "records" / name).read_bytes())
    ]


@pytest.mark.parametrize("name", tracked_records())
def test_a_record_file_is_its_canonical_json_so_its_file_digest_is_its_digest(name: str) -> None:
    raw = (VECTORS / "records" / name).read_bytes()
    assert digest(raw) == digest_of(json.loads(raw))


def test_the_cases_name_known_trust_sets_and_codes() -> None:
    for _folder, case in CASES:
        assert case["trust_set"] in TRUST_SET_NAMES
        if "refused" in case:
            assert case["refused"] in NOT_A_RUN_STATEMENT | RUN_STATEMENT_DOES_NOT_HOLD
        else:
            assert set(case["differences"]) <= RECORD_DIFFERENCES and set(case["notes"]) <= RECORD_NOTES


def test_the_valid_cases_list_no_difference_and_the_invalid_ones_a_refusal_or_a_difference() -> None:
    for folder, case in CASES:
        assert (folder == "run_statements_valid") == (case.get("differences") == []), case["name"]


@pytest.mark.parametrize(("folder", "case"), CASES, ids=IDS)
def test_each_case_gives_the_refusal_or_the_comparison_it_names(folder: str, case: dict[str, Any]) -> None:
    trust = TRUST_SETS[case["trust_set"]]
    if "refused" in case:
        with pytest.raises(RunStatementError) as refused:
            verify_run_statement(_envelope(case), trust, verify_es256)
        assert refused.value.reason == case["refused"]
        return
    verified = verify_run_statement(_envelope(case), trust, verify_es256)
    found = compare_record(case_record(case), verified, trust, case.get("unpackaged_paths"))
    assert [difference.reason for difference in found.differences] == case["differences"]
    assert (found.listed_as, found.replaced_by) == (case["listed_as"], case["replaced_by"])
    assert [note.reason for note in found.notes] == case["notes"]
    assert [{"stage": n.stage, "part": n.part} for n in found.not_compared] == case["not_compared"]


@pytest.mark.parametrize(
    ("folder", "case"),
    [(folder, case) for folder, case in CASES if "payload_rule" in case],
    ids=[case["name"] for _folder, case in CASES if "payload_rule" in case],
)
def test_each_payload_that_is_not_a_run_statement_breaks_the_rule_its_case_names(
    folder: str, case: dict[str, Any]
) -> None:
    with pytest.raises(ValidationError) as broken:
        RunStatement.model_validate(strict_json(read_envelope(_envelope(case)).payload, "a payload"))
    assert str(broken.value.errors()[0]["msg"]).removeprefix("Value error, ") == case["payload_rule"]


def test_a_packaged_record_matches_the_statement_of_the_record_it_was_packaged_from_only_with_its_paths() -> None:
    (case,) = [case for _folder, case in CASES if case["record"] == PACKAGED_RECORD]
    verified = verify_run_statement(_envelope(case), TRUST_SETS["development"], verify_es256)
    car = case_record(case)
    trust = TRUST_SETS["development"]
    assert compare_record(car, verified, trust, case["unpackaged_paths"]).listed_as == "subject"
    assert compare_record(car, verified, trust).listed_as == "not_listed"
