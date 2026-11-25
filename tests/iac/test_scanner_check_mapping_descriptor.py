"""Signing a scanner check mapping the server serves, and checking a served one before its entries are read."""

from __future__ import annotations

import base64
import copy
import dataclasses
import json
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.serialization import load_der_public_key
from pydantic import ValidationError

from iltero_schemas.canonical import digest_of
from iltero_schemas.models.iac.scanner_check_mapping_descriptor import ScannerCheckMappingDescriptor
from iltero_schemas.scanner_check_mappings.iac.descriptor import (
    ScannerCheckMappingDescriptorError,
    check_scanner_check_mapping_descriptor,
    descriptor,
    descriptor_digest,
    kept_descriptor,
    read_scanner_check_mapping_descriptor,
    signing_input,
)
from iltero_schemas.signing import P256_ORDER, SCANNER_CHECK_MAPPING_SIGNING_SCOPE, base64url
from iltero_schemas.trust import KeyStatus
from iltero_schemas.trust.keys import SigningKey
from iltero_schemas.vectors.plans import remove_pointer, set_pointer
from iltero_schemas.vectors.vector_run_statements import run_statement_vector_keys
from tests.conftest import VECTORS

FOLDER = VECTORS / "scanner_check_mapping_descriptors" / "iac"
SERVED: dict[str, Any] = json.loads((FOLDER / "served_catalog.json").read_text(encoding="utf-8"))
MAPPING: dict[str, Any] = json.loads(
    (VECTORS / "scanner_check_mappings" / "iac" / "served_catalog.json").read_text(encoding="utf-8")
)
# The vectors' development keys, those of the run statements' own file included; the key that signed the sample
# descriptor is one of them.
KEYS = run_statement_vector_keys()
CASES: list[dict[str, Any]] = json.loads(
    (VECTORS / "scanner_check_mapping_descriptors_invalid" / "iac" / "cases.json").read_text(encoding="utf-8")
)
PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())


def _raw(der: bytes) -> bytes:
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _verifies(key: SigningKey, signed: bytes, signature: bytes) -> bool:
    public = load_der_public_key(key.public_key_der)
    assert isinstance(public, ec.EllipticCurvePublicKey)
    der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
    try:
        public.verify(der, signed, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def test_the_sample_descriptor_passes_every_check_and_its_signature_verifies_with_the_key_it_names() -> None:
    checked = check_scanner_check_mapping_descriptor(ScannerCheckMappingDescriptor.model_validate(SERVED), KEYS)
    assert checked.mapping.metadata.id == MAPPING["metadata"]["id"]
    assert SERVED["mapping"] == MAPPING
    assert checked.descriptor_digest == digest_of(SERVED)
    assert _verifies(checked.key, checked.signed, checked.signature)


def test_the_signature_covers_the_mappings_digest_under_the_scanner_check_mapping_scope() -> None:
    header, payload = signing_input(MAPPING, key_id="k1").split(b".")
    body = json.loads(_decoded(payload))
    assert body == {"digest": digest_of(MAPPING), "keyid": "k1", "scope": SCANNER_CHECK_MAPPING_SIGNING_SCOPE}
    assert json.loads(_decoded(header)) == {"alg": "ES256", "kid": "k1", "typ": "JWT"}


def _decoded(part: bytes) -> bytes:
    return base64.urlsafe_b64decode(part + b"=" * (-len(part) % 4))


def test_a_descriptor_is_written_with_the_low_s_form_of_the_signature_the_signer_returned() -> None:
    signed = signing_input(MAPPING, key_id="k1")
    signature = _raw(PRIVATE_KEY.sign(signed, ec.ECDSA(hashes.SHA256())))
    s = int.from_bytes(signature[32:], "big")
    high = signature[:32] + max(s, P256_ORDER - s).to_bytes(32, "big")
    written = descriptor(MAPPING, key_id="k1", signature=high)
    low = signature[:32] + min(s, P256_ORDER - s).to_bytes(32, "big")
    assert written.signature == base64url(low).decode("ascii")
    assert written.digest == digest_of(MAPPING)


def _patched(case: dict[str, Any]) -> dict[str, Any]:
    document = copy.deepcopy(SERVED)
    for pointer, value in case["set"].items():
        set_pointer(document, pointer, copy.deepcopy(value))
    for pointer in case["remove"]:
        remove_pointer(document, pointer)
    return document


@pytest.mark.parametrize("case", [c for c in CASES if c["refused_by"] == "model"], ids=lambda case: case["name"])
def test_a_descriptor_the_model_refuses_is_refused_before_any_check(case: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match=case["message"]):
        ScannerCheckMappingDescriptor.model_validate(_patched(case))


@pytest.mark.parametrize("case", [c for c in CASES if c["refused_by"] == "check"], ids=lambda case: case["name"])
def test_a_descriptor_that_breaks_a_rule_of_the_check_is_refused_by_it(case: dict[str, Any]) -> None:
    served = ScannerCheckMappingDescriptor.model_validate(_patched(case))
    with pytest.raises(ScannerCheckMappingDescriptorError, match=case["message"]):
        check_scanner_check_mapping_descriptor(served, KEYS)


def test_every_case_names_the_stage_that_refuses_it() -> None:
    assert {case["refused_by"] for case in CASES} == {"model", "check"}


def test_a_key_that_may_not_verify_is_refused() -> None:
    key = KEYS[SERVED["key_id"]]
    revoked = {**KEYS, key.key_id: dataclasses.replace(key, status="revoked")}
    with pytest.raises(ScannerCheckMappingDescriptorError, match="not trusted, or is revoked"):
        check_scanner_check_mapping_descriptor(ScannerCheckMappingDescriptor.model_validate(SERVED), revoked)


@pytest.mark.parametrize("status", ["active", "revoked"])
def test_a_key_of_another_purpose_is_refused_for_its_purpose_whatever_its_status(status: KeyStatus) -> None:
    key = KEYS[SERVED["key_id"]]
    keys = {**KEYS, key.key_id: dataclasses.replace(key, purpose="run_statement", status=status)}
    with pytest.raises(ScannerCheckMappingDescriptorError, match="is not for signing scanner check mappings"):
        check_scanner_check_mapping_descriptor(ScannerCheckMappingDescriptor.model_validate(SERVED), keys)


def test_only_a_mapping_in_iltero_s_namespace_is_signed_as_served() -> None:
    with pytest.raises(ScannerCheckMappingDescriptorError, match="starts ILT.SCANNER_CHECKS."):
        signing_input({**MAPPING, "metadata": {**MAPPING["metadata"], "id": "ACME.SCANNER_CHECKS.X"}}, key_id="k1")


def test_a_runs_served_mapping_is_read_back_under_a_revoked_key() -> None:
    key = KEYS[SERVED["key_id"]]
    revoked = {**KEYS, key.key_id: dataclasses.replace(key, status="revoked")}
    read = read_scanner_check_mapping_descriptor(
        ScannerCheckMappingDescriptor.model_validate(SERVED), key_id=key.key_id, keys=revoked
    )
    assert read.key.status == "revoked" and _verifies(read.key, read.signed, read.signature)


@pytest.mark.parametrize("pinned", ["another-key", "never-held"], ids=["another pinned key", "a key never held"])
def test_a_served_mapping_read_back_under_a_key_other_than_its_pin_or_never_held_is_refused(pinned: str) -> None:
    key = KEYS[SERVED["key_id"]]
    keys = {**KEYS, "another-key": dataclasses.replace(key, key_id="another-key")}
    with pytest.raises(ScannerCheckMappingDescriptorError, match="is not the pinned one, or names a key the trust set"):
        read_scanner_check_mapping_descriptor(
            ScannerCheckMappingDescriptor.model_validate(SERVED), key_id=pinned, keys=keys
        )


def test_a_runs_served_mapping_read_back_under_a_key_of_another_purpose_is_refused() -> None:
    key = KEYS[SERVED["key_id"]]
    keys = {**KEYS, key.key_id: dataclasses.replace(key, purpose="run_statement", status="revoked")}
    with pytest.raises(ScannerCheckMappingDescriptorError, match="is not for signing scanner check mappings"):
        read_scanner_check_mapping_descriptor(
            ScannerCheckMappingDescriptor.model_validate(SERVED), key_id=key.key_id, keys=keys
        )


def test_a_records_copy_key_id_and_signature_rebuild_the_descriptor_and_its_signature_verifies() -> None:
    rebuilt = kept_descriptor(MAPPING, key_id=SERVED["key_id"], signature=SERVED["signature"])
    assert rebuilt.model_dump(mode="json", by_alias=True) == SERVED
    assert descriptor_digest(rebuilt) == digest_of(SERVED)
    read = read_scanner_check_mapping_descriptor(rebuilt, key_id=SERVED["key_id"], keys=KEYS)
    assert _verifies(read.key, read.signed, read.signature)
