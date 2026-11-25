"""The keyed plan digests a record of a run the server opened names, made again from the raw plans it was keyed from,
and the keyed digest of each raw plan's bytes its register names as the file the pipeline gave."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from iltero_schemas.canonical import digest
from iltero_schemas.canonical.common.run_digest_key import KEYED_DIGEST_PREFIX, keyed_given_file_digest
from iltero_schemas.canonical.iac.plan import keyed_plan_digest
from iltero_schemas.vectors.run_digest_key import vector_run_digest_key
from tests.conftest import VECTORS

RAW_PLANS = VECTORS / "raw_plans" / "iac"
CASES: list[dict[str, Any]] = json.loads((RAW_PLANS / "cases.json").read_text(encoding="utf-8"))


def _keyed(name: str) -> str:
    return keyed_plan_digest(
        "terraform", json.loads((RAW_PLANS / name).read_text(encoding="utf-8")), vector_run_digest_key()
    )


def _keyed_values(value: Any) -> list[str]:
    """Every keyed digest a document names, wherever it sits: a plan digest beside its rule's version, a checked
    plan's, the apply job's, and each value an evaluation observed."""
    if isinstance(value, str):
        return [value] if value.startswith(KEYED_DIGEST_PREFIX) else []
    if isinstance(value, dict):
        value = list(value.values())
    if isinstance(value, list):
        return [found for item in value for found in _keyed_values(item)]
    return []


def _given_file_digests(record: dict[str, Any]) -> set[str]:
    """Every digest the record names of a file it keeps redacted, or never keeps: each register entry's given file
    digest, the apply log's and the state's, and the drift check's readings. They are keyed too, but are no plan
    digest."""
    change = record["change"]
    named = [ref["source"]["digest"] for ref in record["evidence_refs"] if ref["source"] is not None]
    deployment, identity, check = change.get("deployment"), change.get("identity"), change.get("drift_check")
    if deployment is not None:
        named += [deployment["apply"]["source"]["digest"], deployment["apply"]["state"].get("digest")]
    if identity is not None:
        named.append(identity["sources"]["state"]["digest"])
    if check is not None:
        named += [check["first_reading_digest"], check["second_reading_digest"]]
    return {value for value in named if value is not None}


def _raw(name: str) -> Path:
    return RAW_PLANS / name


def test_every_record_of_a_run_the_server_opened_names_the_raw_plans_it_was_keyed_from() -> None:
    tracked = {
        f"iac/{path.name}"
        for path in (VECTORS / "records" / "iac").glob("*.json")
        if json.loads(path.read_text(encoding="utf-8"))["run"]["opened_by"] == "server"
    }
    assert {case["record"] for case in CASES} == tracked
    named = {case["plan"] for case in CASES} | {case["applied_plan"] for case in CASES} - {None}
    # The plans the re-plan comparison cases are edited from.
    replans = json.loads((VECTORS / "replan_differences" / "iac" / "inputs.json").read_text(encoding="utf-8"))["cases"]
    named |= {side["raw"] for case in replans for side in (case["evaluated_plan"], case["replan"]) if "raw" in side}
    assert {path.name for path in RAW_PLANS.glob("*.json")} - {"cases.json"} == named


@pytest.mark.parametrize("case", CASES, ids=[case["record"] for case in CASES])
def test_every_keyed_digest_a_record_names_is_made_again_from_its_raw_plans_under_the_vector_key(
    case: dict[str, Any],
) -> None:
    record = json.loads((VECTORS / "records" / case["record"]).read_text(encoding="utf-8"))
    change = record["change"]
    assert change["plan"]["digest"] == _keyed(case["plan"])
    if case["applied_plan"] is None:
        assert change["deployment"] is None
    else:
        assert change["deployment"]["plan"]["digest"] == _keyed(case["applied_plan"])
    expected = {_keyed(case["plan"])} | (set() if case["applied_plan"] is None else {_keyed(case["applied_plan"])})
    assert set(_keyed_values(record)) - _given_file_digests(record) == expected


@pytest.mark.parametrize("case", CASES, ids=[case["record"] for case in CASES])
def test_the_register_names_each_raw_plan_by_the_keyed_digest_of_its_bytes(case: dict[str, Any]) -> None:
    record = json.loads((VECTORS / "records" / case["record"]).read_text(encoding="utf-8"))
    given = {ref["source"]["digest"] for ref in record["evidence_refs"] if ref["collector"]["tool"] == "terraform_plan"}
    raw = {case["plan"]} | ({case["applied_plan"]} - {None})
    key = vector_run_digest_key()
    assert given == {keyed_given_file_digest(digest(_raw(name).read_bytes()), key) for name in raw}
