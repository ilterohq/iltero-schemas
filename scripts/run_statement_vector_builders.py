"""Builders of the run statement vector cases, for ``run_statement_vector_cases.py``: a key that signs while the
script runs, the payload of a record vector's statement changed by an edit, and what a case gives."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from iltero_schemas.canonical import canonical_bytes, digest_of
from iltero_schemas.models.common.run_statement import (
    RUN_STATEMENT_PREDICATE_TYPE,
    STATEMENT_TYPE,
    RunClosePredicate,
    StatementSubject,
)
from iltero_schemas.signing import SIGNATURE_BYTES, normalized_signature
from iltero_schemas.statement import (
    dsse_signing_input,
    envelope,
    record_path_fields,
    run_statement_payload,
)
from iltero_schemas.vectors.plans import set_pointer
from iltero_schemas.vectors.vector_run_statements import (
    PACKAGED_RECORD,
    RUN_STATEMENT_KEY_ID,
    UNPACKAGED_RECORD,
    case_record,
    vector_run_statement_predicate,
)

HALF = SIGNATURE_BYTES // 2
OTHER_DIGEST = "sha256:" + "0" * 63 + "1"
DEPLOYED = "iac/tracked_run_deployed.json"
IMAGE = "image/tracked_run_deploy_rolled_out.json"
# A change to a statement before it is signed: to its predicate and its subjects.
Edit = Callable[[dict[str, Any], list[dict[str, Any]]], None]


class Signer:
    """A new P-256 key, held only while the script runs."""

    def __init__(self) -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        self.public_der = self._key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def signature(self, payload: bytes) -> bytes:
        """The raw ``r‖s`` signature of ``payload``'s signing input, in its low-S form."""
        r, s = decode_dss_signature(self._key.sign(dsse_signing_input(payload), ec.ECDSA(hashes.SHA256())))
        return normalized_signature(r.to_bytes(HALF, "big") + s.to_bytes(HALF, "big"))

    def envelope(self, payload: bytes, *, key_id: str = RUN_STATEMENT_KEY_ID) -> dict[str, Any]:
        """The envelope of ``payload``, exactly as given, signed with this key under ``key_id``."""
        document: dict[str, Any] = json.loads(envelope(payload, key_id=key_id, signature=self.signature(payload)))
        return document


def sets(pointers: Mapping[str, Any]) -> Edit:
    """An edit that sets each JSON Pointer of ``pointers`` in the predicate, or in the subjects for one that starts
    ``/subject/``."""

    def edit(predicate: dict[str, Any], subjects: list[dict[str, Any]]) -> None:
        for pointer, value in pointers.items():
            if pointer.startswith("/subject/"):
                set_pointer(subjects, pointer.removeprefix("/subject"), value)
            else:
                set_pointer(predicate, pointer, value)

    return edit


def payload_of(case: Mapping[str, Any], edit: Edit | None = None, *, checked: bool = True) -> bytes:
    """The payload of the statement of the record ``case`` names, changed by ``edit`` first; with ``checked`` false,
    the canonical JSON of the statement as changed, whether or not it is one."""
    car = case_record(case)
    record_digest = digest_of(car.model_dump(mode="json", by_alias=True))
    predicate = vector_run_statement_predicate(car, record_digest)
    subjects = [{"name": car.unit, "digest": {"sha256": record_digest.removeprefix("sha256:")}}]
    if edit is not None:
        edit(predicate, subjects)
    predicate["settings_digest"] = digest_of(predicate["settings"])
    if not checked:
        statement = {"_type": STATEMENT_TYPE, "subject": subjects, "predicateType": RUN_STATEMENT_PREDICATE_TYPE}
        return canonical_bytes({**statement, "predicate": predicate})
    return run_statement_payload(
        [StatementSubject.model_validate(subject) for subject in subjects], RunClosePredicate.model_validate(predicate)
    ).payload


def refused(reason: str, payload_rule: str | None = None) -> dict[str, Any]:
    """What a case refused with ``reason`` gives; for a payload that is not a run statement, the rule it breaks, as the
    model's first refusal says it."""
    return {"refused": reason} if payload_rule is None else {"refused": reason, "payload_rule": payload_rule}


def differs(
    *reasons: str,
    listed_as: str = "subject",
    replaced_by: str | None = None,
    notes: tuple[str, ...] = (),
    not_compared: tuple[tuple[str, str], ...] = (),
) -> dict[str, Any]:
    """What a case that verifies gives when compared with its record."""
    return {
        "differences": list(reasons),
        "listed_as": listed_as,
        "replaced_by": replaced_by,
        "notes": list(notes),
        "not_compared": [{"stage": stage, "part": part} for stage, part in not_compared],
    }


def no_record_accepted(predicate: dict[str, Any], subjects: list[dict[str, Any]]) -> None:
    """No stage accepts a record, so the unit has no subject and every expected stage was never accepted."""
    subjects.clear()
    for stage in predicate["units"][0]["stages"]:
        stage["accepted_records"] = []
    predicate["gaps"]["stages_never_accepted"] = [
        {"unit": "root", "stage": stage} for stage in predicate["settings"]["expected_stages"]
    ]


def final_is(digest: str, *, also: list[dict[str, Any]] | None = None) -> Edit:
    """The unit's latest stage counts ``digest``, beside the records of ``also``, and its subject names it."""

    def edit(predicate: dict[str, Any], subjects: list[dict[str, Any]]) -> None:
        predicate["units"][0]["stages"][-1]["accepted_records"] = [*(also or []), {"digest": digest, "counts": True}]
        subjects[0]["digest"]["sha256"] = digest.removeprefix("sha256:")

    return edit


def unpackaged_paths() -> dict[str, str]:
    """The path each path field of the packaged record vector held in the record it was packaged from."""
    before = record_path_fields(case_record({"record": UNPACKAGED_RECORD}))
    after = record_path_fields(case_record({"record": PACKAGED_RECORD}))
    if set(before) != set(after):
        raise ValueError("the packaged record vector has other path fields than the record it was packaged from")
    return {pointer: before[pointer] for pointer in after}


def packaged_case(signer: Signer) -> dict[str, Any]:
    """The packaged record vector against the statement of the record it was packaged from, with the paths it held."""
    return {
        "record": PACKAGED_RECORD,
        "unpackaged_paths": unpackaged_paths(),
        "envelope": signer.envelope(payload_of({"record": UNPACKAGED_RECORD})),
        "trust_set": "development",
    }
