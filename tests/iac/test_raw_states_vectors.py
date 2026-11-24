"""The states the record vectors of runs the tool opened were written from.

Each record of ``raw_states/iac/cases.json`` names its state, and the identities read from it, by the redacted state
digest of its captured state under the record's redaction policy; a record whose post-verify stage kept its identities
names their state by the redacted state digest of the second refresh-only plan's ``prior_state``. Every other document
of a run the tool opened that names a state names the redacted state digest of a captured state too. None names the
digest of the empty state, which a writer that digests an empty document by mistake would give: only the case
``terraform_state_that_is_empty`` holds it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from iltero_schemas.canonical import digest
from iltero_schemas.canonical.common.run_digest_key import keyed_given_file_digest
from iltero_schemas.models.common.redaction import RedactionPolicyDocument
from iltero_schemas.models.iac.post_verify_identities import POST_VERIFY_IDENTITIES_REF_ID
from iltero_schemas.redaction.common.policy import BUILT_IN_REDACTION_POLICY, policy_from_document
from iltero_schemas.redaction.iac.state import redacted_state_digest
from iltero_schemas.vectors.kept_files import kept_files_of
from iltero_schemas.vectors.run_digest_key import vector_run_digest_key
from tests.conftest import VECTORS

RAW_STATES = VECTORS / "raw_states" / "iac"
CASES: list[dict[str, Any]] = json.loads((RAW_STATES / "cases.json").read_text(encoding="utf-8"))
EMPTY_STATE_DIGEST = redacted_state_digest("terraform", {"format_version": "1.0"}, BUILT_IN_REDACTION_POLICY)
# Each document of a run the tool opened that names a state but was not written from one, by its path or by its cases
# file and case, and the captured state whose redacted state digest it names, chosen for the form of its digest: the
# document's own resources are not that state's.
STATE_CHOSEN_FOR_ITS_FORM = {
    ("contexts/iac/post_deploy.json", None): "apply_create.json",
    ("contexts/iac/post_verify.json", None): "refresh_verified.json",
    ("identities/resource_identities.json", None): "apply_create.json",
    ("evaluation/cases.json", "state_read_after_the_apply"): "apply_create.json",
    ("records_invalid/iac/cases.json", "state_not_read_with_its_identities"): "apply_create.json",
}
# The record of a run the server opened through post-verify, and the captured file of each digest it keys: its state
# (the deployment's and the identities'), its first reading and its second reading.
KEYED_RUN = "iac/governed_run_post_verify.json"
KEYED_FILES = {
    ("deployment", "apply", "state", "digest"): "refresh_verified.json",
    ("identity", "sources", "state", "digest"): "refresh_verified.json",
    ("drift_check", "first_reading_digest"): "refresh_verified_first_reading.json",
    ("drift_check", "second_reading_digest"): "refresh_verified_second_reading.json",
}
# The one vector file that names the empty state's digest, and the one case in it that does.
NAMES_THE_EMPTY_STATE_DIGEST = {"redaction/iac/state_cases.json": {"terraform_state_that_is_empty"}}


def _raw(name: str) -> Any:
    return json.loads((RAW_STATES / name).read_text(encoding="utf-8"))


def _record(case: dict[str, Any]) -> dict[str, Any]:
    document: dict[str, Any] = json.loads((VECTORS / "records" / case["record"]).read_text(encoding="utf-8"))
    return document


def test_every_captured_state_is_named_by_a_case_or_a_state_redaction_case() -> None:
    redaction = json.loads((VECTORS / "redaction" / "iac" / "state_inputs.json").read_text(encoding="utf-8"))["cases"]
    named = {case["state"] for case in CASES} | {case["second_reading"] for case in CASES if case["second_reading"]}
    named |= {case["raw_state"]["file"] for case in redaction if "raw_state" in case}
    named |= set(KEYED_FILES.values())
    assert named == {path.name for path in RAW_STATES.glob("*.json")} - {"cases.json"}


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["record"])
def test_a_record_of_a_run_the_tool_opened_names_its_state_by_the_redacted_state_digest(case: dict[str, Any]) -> None:
    record = _record(case)
    assert record["governance"]["run_opened_by"] == "local"
    policy = policy_from_document(RedactionPolicyDocument.model_validate(record["redaction_policy"]))
    expected = {
        "digest": redacted_state_digest("terraform", _raw(case["state"]), policy),
        "digest_version": "redacted-1",
    }
    for state in (record["change"]["deployment"]["apply"]["state"], record["change"]["identity"]["sources"]["state"]):
        assert {key: state[key] for key in expected} == expected
    paths = [ref["path"] for ref in record["evidence_refs"] if ref["ref_id"] == POST_VERIFY_IDENTITIES_REF_ID]
    identities = kept_files_of(case["record"])[paths[0]] if paths else None
    assert (identities is None) == (case["second_reading"] is None)
    if identities is not None:
        prior = _raw(case["second_reading"])["prior_state"]
        assert json.loads(identities)["sources"]["state"]["digest"] == redacted_state_digest("terraform", prior, policy)


def test_every_record_of_a_run_the_tool_opened_that_names_a_state_is_written_from_a_captured_state() -> None:
    named = set()
    for path in (VECTORS / "records").rglob("*.json"):
        if path.name == "digests.json":
            continue
        record = json.loads(path.read_text(encoding="utf-8"))
        deployment = record["change"].get("deployment")
        state = deployment["apply"]["state"] if deployment is not None and "apply" in deployment else {}
        if record["governance"]["run_opened_by"] == "local" and "digest" in state:
            named.add(path.relative_to(VECTORS / "records").as_posix())
    assert named == {case["record"] for case in CASES}


def _names(node: Any) -> bool:
    return EMPTY_STATE_DIGEST in json.dumps(node)


def test_no_document_names_the_empty_state_digest_but_the_empty_state_case() -> None:
    found: dict[str, set[str] | None] = {}
    for path in sorted(VECTORS.rglob("*.json")):
        text = path.read_text(encoding="utf-8")
        if EMPTY_STATE_DIGEST not in text:
            continue
        where = path.relative_to(VECTORS).as_posix()
        document = json.loads(text)
        cases = document["cases"] if isinstance(document, dict) and "cases" in document else document
        if isinstance(cases, list) and all(isinstance(case, dict) and "name" in case for case in cases):
            found[where] = {case["name"] for case in cases if _names(case)}
        else:
            found[where] = None
    assert found == NAMES_THE_EMPTY_STATE_DIGEST


def _document_of(text: str) -> Any:
    """The JSON document a kept file's text holds, or None for text that is not JSON."""
    try:
        return json.loads(text)
    except ValueError:
        return None


def _state_digests(node: Any) -> list[str]:
    """Every state digest ``node`` names, wherever it sits: the ``digest`` of a ``state`` beside its
    ``digest_version``, ``tool`` and ``tool_version``, and in kept files the documents each text holds."""
    found: list[str] = []
    pending: list[tuple[object, Any]] = [(None, node)]
    while pending:
        key, value = pending.pop()
        if isinstance(value, dict):
            if key == "state" and {"digest", "digest_version", "tool", "tool_version"} <= set(value):
                found.append(value["digest"])
            pending.extend(value.items())
            if isinstance(value.get("text"), str):
                pending.append((None, _document_of(value["text"])))
        elif isinstance(value, list):
            pending.extend((None, item) for item in value)
    return found


def test_no_state_digest_in_the_vectors_is_the_empty_state_digest() -> None:
    named = [
        digest
        for path in VECTORS.rglob("*.json")
        if path.relative_to(VECTORS).as_posix() != "redaction/iac/state_cases.json"
        for digest in _state_digests(json.loads(path.read_text(encoding="utf-8")))
    ]
    assert named and EMPTY_STATE_DIGEST not in named


def test_the_empty_state_case_gives_the_empty_state_digest() -> None:
    cases = json.loads((VECTORS / "redaction" / "iac" / "state_cases.json").read_text(encoding="utf-8"))["cases"]
    empty = next(case for case in cases if case["name"] == "terraform_state_that_is_empty")
    assert empty["redacted_state_digest"] == EMPTY_STATE_DIGEST


def test_one_captured_state_holds_check_results() -> None:
    holding = {path.name for path in Path(RAW_STATES).glob("*.json") if "checks" in _raw(path.name)}
    assert holding == {"apply_with_checks.json"}


@pytest.mark.parametrize(("where", "state"), STATE_CHOSEN_FOR_ITS_FORM.items(), ids=lambda value: str(value))
def test_a_document_not_written_from_a_state_names_the_redacted_state_digest_of_the_state_chosen_for_it(
    where: tuple[str, str | None], state: str
) -> None:
    path, case = where
    document = json.loads((VECTORS / path).read_text(encoding="utf-8"))
    if case is not None:
        document = next(item for item in document if item["name"] == case)
    expected = redacted_state_digest("terraform", _raw(state), BUILT_IN_REDACTION_POLICY)
    named = _state_digests(document)
    assert named and set(named) == {expected}


def test_the_keyed_record_through_post_verify_keys_the_bytes_of_its_captured_files() -> None:
    change = json.loads((VECTORS / "records" / KEYED_RUN).read_text(encoding="utf-8"))["change"]
    key = vector_run_digest_key()
    for pointer, name in KEYED_FILES.items():
        value: Any = change
        for token in pointer:
            value = value[token]
        assert value == keyed_given_file_digest(digest((RAW_STATES / name).read_bytes()), key), pointer
