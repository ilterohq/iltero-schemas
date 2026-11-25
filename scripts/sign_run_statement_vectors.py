"""Sign the run statement vectors again, with a new development key.

An ES256 signature is not a pure function of its input, so ``refresh_vectors.py`` cannot rebuild a signed vector.
This script makes two throwaway development keys, ``dev-run-statements`` of the development server and
``dev-operator-run-statements`` of the sample operator's, writes them as the keys of the development trust file
``vectors/signing_keys/run_statements.json``, and forgets the private keys once they have signed:

- ``vectors/run_statements/<change type>/<record>.json``: the statement of each record of a tracked run under
  ``vectors/records``, as the server that opened the run would sign it when the run ended. Its subject is the record's
  digest, so a record that changes needs this script run again (a test finds a stale statement);
- ``vectors/run_statements_invalid/<change type>/cases.json`` and ``run_statements_valid/<change type>/cases.json``:
  each case of ``run_statement_vector_cases.py``, with its envelope and what reading it with its record gives. The
  script checks that the package agrees with each case before it writes anything.

Run ``refresh_vectors.py`` afterwards to update the digests.

Usage: python scripts/sign_run_statement_vectors.py
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from es256 import verify_es256
from pydantic import ValidationError
from run_statement_vector_builders import Signer, payload_of
from run_statement_vector_cases import cases

from iltero_schemas.models.common.base import API_VERSION
from iltero_schemas.models.common.run_statement import RunStatement
from iltero_schemas.models.common.strict_json import strict_json
from iltero_schemas.statement import RunStatementError, compare_record, read_envelope, verify_run_statement
from iltero_schemas.statement.reasons import PAYLOAD_NOT_A_RUN_STATEMENT
from iltero_schemas.trust import TRUST_FILE_KIND, SigningKey, parse_signing_keys
from iltero_schemas.vectors.vector_run_statements import (
    OPERATOR_RUN_STATEMENT_KEY_ID,
    OPERATOR_SERVER,
    RUN_STATEMENT_KEY_ID,
    case_record,
    run_statement_trust_sets,
    tracked_records,
)
from iltero_schemas.vectors.vector_signing_keys import DEVELOPMENT_SERVER, active_key_entry, vector_signing_keys

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "src" / "iltero_schemas" / "vectors"
# The time the key's status began, before every vector run ended: fixed, so signing again changes only the key and the
# signatures.
VALID_FROM = "2026-01-01T00:00:00Z"


def _write(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def outcome(case: Mapping[str, Any], keys: Mapping[str, SigningKey]) -> dict[str, Any]:
    """What reading the case gives with the package: the refusal's reason code, or what comparing it found."""
    data = json.dumps(case["envelope"]).encode("utf-8")
    try:
        trust = run_statement_trust_sets(keys)[case["trust_set"]]
        verified = verify_run_statement(data, trust, verify_es256)
    except RunStatementError as error:
        if error.reason != PAYLOAD_NOT_A_RUN_STATEMENT:
            return {"refused": error.reason}
        return {"refused": error.reason, "payload_rule": payload_rule(data)}
    found = compare_record(case_record(case), verified, trust, case.get("unpackaged_paths"))
    return {
        "differences": [difference.reason for difference in found.differences],
        "listed_as": found.listed_as,
        "replaced_by": found.replaced_by,
        "notes": [note.reason for note in found.notes],
        "not_compared": [{"stage": skipped.stage, "part": skipped.part} for skipped in found.not_compared],
    }


def payload_rule(data: bytes) -> str:
    """The first rule the payload of the envelope ``data`` breaks, as the run statement model says it."""
    try:
        RunStatement.model_validate(strict_json(read_envelope(data).payload, "a payload"))
    except ValidationError as error:
        return str(error.errors()[0]["msg"]).removeprefix("Value error, ")
    return "none"


def _expected(case: Mapping[str, Any]) -> dict[str, Any]:
    if "refused" in case:
        keys: tuple[str, ...] = ("refused", "payload_rule") if "payload_rule" in case else ("refused",)
    else:
        keys = ("differences", "listed_as", "replaced_by", "notes", "not_compared")
    return {key: case[key] for key in keys}


def main() -> int:
    signer, operator = Signer(), Signer()
    entries = [
        active_key_entry(key.public_der, key_id=key_id, purpose="run_statement", server=server, valid_from=VALID_FROM)
        for key, key_id, server in sorted(
            [
                (signer, RUN_STATEMENT_KEY_ID, DEVELOPMENT_SERVER),
                (operator, OPERATOR_RUN_STATEMENT_KEY_ID, OPERATOR_SERVER),
            ],
            key=lambda named: named[1],
        )
    ]
    trust_file = {"apiVersion": API_VERSION, "kind": TRUST_FILE_KIND, "keys": entries}
    keys = {**vector_signing_keys(), **parse_signing_keys(json.dumps(trust_file).encode("utf-8"), development=True)}
    statements = {name: signer.envelope(payload_of({"record": name})) for name in tracked_records()}
    listed = cases(signer, operator)
    # The package reads each statement and case as written before anything is written.
    wrong = [
        f"{folder}: {case['name']} gives {found}"
        for folder, folder_cases in listed.items()
        for case in folder_cases
        if (found := outcome(case, keys)) != _expected(case)
    ]
    plain: dict[str, Any] = {
        "differences": [],
        "listed_as": "subject",
        "replaced_by": None,
        "notes": [],
        "not_compared": [],
    }
    wrong += [
        f"run_statements/{name} gives {found}"
        for name, statement in statements.items()
        if (found := outcome({"envelope": statement, "trust_set": "development", "record": name}, keys)) != plain
    ]
    if wrong:
        print("\n".join(wrong), file=sys.stderr)
        return 1
    _write(VECTORS / "signing_keys" / "run_statements.json", trust_file)
    for name, statement in statements.items():
        _write(VECTORS / "run_statements" / name, statement)
    for folder, folder_cases in listed.items():
        _write(VECTORS / folder / "cases.json", folder_cases)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
