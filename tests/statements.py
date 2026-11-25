"""Builders of run statements for the tests: the predicate and subjects of a record vector's statement, and a key that
signs them while the test runs."""

from __future__ import annotations

import json
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from iltero_schemas.canonical import digest, digest_of
from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.common.run_statement import RunClosePredicate, RunStatement, StatementSubject
from iltero_schemas.signing import SIGNATURE_BYTES, normalized_signature
from iltero_schemas.statement import dsse_signing_input, envelope, run_statement_payload
from iltero_schemas.trust import KeyPurpose, SigningKey
from iltero_schemas.vectors.vector_run_statements import vector_run_statement_predicate
from iltero_schemas.vectors.vector_signing_keys import DEVELOPMENT_SERVER
from tests.conftest import VECTORS

DEPLOYED = "iac/tracked_run_deployed.json"
IMAGE_DEPLOY = "image/tracked_run_deploy_rolled_out.json"
KEY_ID = "dev-run-statement-test"
HALF = SIGNATURE_BYTES // 2


def record_of(name: str = DEPLOYED) -> tuple[CAR, str]:
    """The record vector ``name`` and the digest of its file."""
    raw = (VECTORS / "records" / name).read_bytes()
    return CAR.model_validate(json.loads(raw)), digest(raw)


def statement_parts(name: str = DEPLOYED) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """The subjects and predicate of the statement of the record vector ``name``, as JSON values to change."""
    car, record_digest = record_of(name)
    subjects = [{"name": car.unit, "digest": {"sha256": record_digest.removeprefix("sha256:")}}]
    return subjects, vector_run_statement_predicate(car, record_digest)


def statement_document(subjects: list[dict[str, Any]], predicate: dict[str, Any]) -> dict[str, Any]:
    """The statement of ``subjects`` and ``predicate`` as a JSON value, its settings digest recomputed."""
    predicate = {**predicate, "settings_digest": digest_of(predicate["settings"])}
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://iltero.com/statements/run-close/v1",
        "predicate": predicate,
    }


def statement_of(name: str = DEPLOYED) -> RunStatement:
    """The statement of the record vector ``name``."""
    return RunStatement.model_validate(statement_document(*statement_parts(name)))


def payload_of(name: str = DEPLOYED) -> bytes:
    """The payload of the statement of the record vector ``name``."""
    subjects, predicate = statement_parts(name)
    return run_statement_payload(
        [StatementSubject.model_validate(subject) for subject in subjects], RunClosePredicate.model_validate(predicate)
    ).payload


class Signer:
    """A P-256 key held while a test runs."""

    def __init__(self) -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        self.public_der = self._key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def raw_signature(self, data: bytes) -> bytes:
        """The raw ``r‖s`` signature of ``data``, in its low-S form."""
        r, s = decode_dss_signature(self._key.sign(data, ec.ECDSA(hashes.SHA256())))
        return normalized_signature(r.to_bytes(HALF, "big") + s.to_bytes(HALF, "big"))

    def envelope(self, payload: bytes, *, key_id: str = KEY_ID) -> bytes:
        """The envelope of ``payload`` signed with this key under ``key_id``."""
        return envelope(payload, key_id=key_id, signature=self.raw_signature(dsse_signing_input(payload)))

    def key(self, *, key_id: str = KEY_ID, purpose: KeyPurpose = "run_statement") -> SigningKey:
        """This key as a trust set lists it, active, for ``purpose``."""
        return SigningKey(
            key_id=key_id,
            algorithm="ES256",
            public_key_der=self.public_der,
            spki_sha256=digest(self.public_der),
            purpose=purpose,
            server=DEVELOPMENT_SERVER,
            status="active",
            valid_from="2026-01-01T00:00:00Z",
            retired_at=None,
            revoked_at=None,
            revocation_reason=None,
        )
