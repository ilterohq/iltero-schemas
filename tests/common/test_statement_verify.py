"""A run statement is relied on only when a trusted key of the run statement purpose signed exactly its canonical
payload."""

from __future__ import annotations

import base64
import dataclasses
import json

import pytest

from iltero_schemas.canonical import canonical_bytes, digest
from iltero_schemas.signing import P256_ORDER, SignatureError
from iltero_schemas.statement import (
    RunStatementError,
    der_signature,
    dsse_signing_input,
    envelope,
    read_run_statement,
    verify_run_statement,
)
from iltero_schemas.trust import SIGNING_KEYS, OperatorSigningKeys, SigningKey, TrustedKey, trusted_keys
from tests.server_runs import verify_es256
from tests.statements import KEY_ID, Signer, payload_of, statement_document, statement_parts

SIGNER = Signer()
PAYLOAD = payload_of()
KEYS: dict[str, SigningKey] = {KEY_ID: SIGNER.key()}


def _reason(data: bytes, keys: dict[str, SigningKey]) -> str:
    with pytest.raises(RunStatementError) as refused:
        verify_run_statement(data, keys, verify_es256)
    return refused.value.reason


def test_a_statement_signed_by_a_trusted_run_statement_key_verifies() -> None:
    verified = verify_run_statement(SIGNER.envelope(PAYLOAD), KEYS, verify_es256)
    assert (verified.payload, verified.digest, verified.key) == (PAYLOAD, digest(PAYLOAD), KEYS[KEY_ID])
    assert verified.statement == read_run_statement(PAYLOAD)


def _payload_of_server(server: str) -> bytes:
    """The payload of the statement of the deployed record vector, naming ``server`` as the one that opened the run."""
    subjects, predicate = statement_parts()
    predicate["run"]["server"] = server
    return canonical_bytes(statement_document(subjects, predicate))


def test_a_statement_signed_by_a_key_of_another_server_than_the_one_it_names_is_refused() -> None:
    payload = _payload_of_server("iltero.operator.example")
    assert _reason(SIGNER.envelope(payload), KEYS) == "key_of_another_server"


def test_a_signature_in_its_high_s_form_is_refused() -> None:
    raw = SIGNER.raw_signature(dsse_signing_input(PAYLOAD))
    high = raw[:32] + (P256_ORDER - int.from_bytes(raw[32:], "big")).to_bytes(32, "big")
    document = json.loads(SIGNER.envelope(PAYLOAD))
    document["signatures"][0]["sig"] = base64.b64encode(der_signature(high)).decode("ascii")
    assert _reason(json.dumps(document).encode("utf-8"), KEYS) == "signature_invalid"


def test_the_signer_refuses_a_signature_in_its_high_s_form() -> None:
    raw = SIGNER.raw_signature(dsse_signing_input(PAYLOAD))
    high = raw[:32] + (P256_ORDER - int.from_bytes(raw[32:], "big")).to_bytes(32, "big")
    with pytest.raises(SignatureError, match="low-S form"):
        envelope(PAYLOAD, key_id=KEY_ID, signature=high)


def test_a_payload_with_a_lone_surrogate_is_not_a_run_statement() -> None:
    surrogate = PAYLOAD.replace(b'"citation":"The', b'"citation":"\\ud800The', 1)
    assert surrogate != PAYLOAD
    assert _reason(SIGNER.envelope(surrogate), KEYS) == "payload_not_a_run_statement"


def test_a_statement_signed_by_a_key_the_trust_set_does_not_hold_is_refused() -> None:
    assert _reason(SIGNER.envelope(PAYLOAD, key_id="dev-other"), KEYS) == "key_not_trusted"


def test_a_statement_signed_by_a_key_of_another_purpose_is_refused() -> None:
    keys = {KEY_ID: SIGNER.key(purpose="check_definitions")}
    assert _reason(SIGNER.envelope(PAYLOAD), keys) == "key_of_another_purpose"


def test_a_statement_signed_by_a_revoked_key_is_refused() -> None:
    revoked = dataclasses.replace(
        KEYS[KEY_ID], status="revoked", revoked_at="2026-11-25T00:00:00Z", revocation_reason="key_compromised"
    )
    assert _reason(SIGNER.envelope(PAYLOAD), {KEY_ID: revoked}) == "key_revoked"


def test_a_statement_signed_by_a_retired_key_still_verifies() -> None:
    retired = dataclasses.replace(KEYS[KEY_ID], status="retired", retired_at="2026-11-26T00:00:00Z")
    assert verify_run_statement(SIGNER.envelope(PAYLOAD), {KEY_ID: retired}, verify_es256).key == retired


@pytest.mark.parametrize(
    "key",
    [
        dataclasses.replace(KEYS[KEY_ID], valid_from="2026-12-01T00:00:00Z"),
        dataclasses.replace(KEYS[KEY_ID], status="retired", retired_at="2026-09-01T00:00:00Z"),
    ],
    ids=["the key's status began after the run ended", "the key was retired before the run ended"],
)
def test_a_statement_of_a_run_that_ended_while_its_key_was_not_valid_is_refused(key: SigningKey) -> None:
    assert _reason(SIGNER.envelope(PAYLOAD), {KEY_ID: key}) == "key_not_valid_at_the_run_end"


def test_a_signature_made_with_another_key_is_refused() -> None:
    assert _reason(Signer().envelope(PAYLOAD), KEYS) == "signature_invalid"


def test_the_signature_check_is_given_the_key_the_pre_authentication_encoding_and_the_raw_signature() -> None:
    seen: list[tuple[bytes, bytes, int]] = []

    def check(key: bytes, signed: bytes, signature: bytes) -> bool:
        seen.append((key, signed, len(signature)))
        return True

    verify_run_statement(SIGNER.envelope(PAYLOAD), KEYS, check)
    assert seen == [(SIGNER.public_der, b"DSSEv1 28 application/vnd.in-toto+json %d %s" % (len(PAYLOAD), PAYLOAD), 64)]


def test_a_signed_payload_that_is_not_its_canonical_json_is_refused() -> None:
    pretty = json.dumps(json.loads(PAYLOAD), indent=2).encode("utf-8")
    assert _reason(SIGNER.envelope(pretty), KEYS) == "payload_not_canonical"


@pytest.mark.parametrize("payload", [b"[]", b"not json", b'{"_type": "https://in-toto.io/Statement/v1"}'])
def test_a_signed_payload_that_is_not_a_run_statement_is_refused(payload: bytes) -> None:
    assert _reason(SIGNER.envelope(payload), KEYS) == "payload_not_a_run_statement"


def test_the_payload_is_read_only_after_its_signature_verifies() -> None:
    assert _reason(Signer().envelope(b"not json"), KEYS) == "signature_invalid"


def test_the_payload_is_read_strictly_so_a_key_named_twice_is_refused() -> None:
    document = json.dumps(statement_document(*statement_parts()), separators=(",", ":"))
    doubled = ('{"_type":"x",' + document[1:]).encode("utf-8")
    assert _reason(SIGNER.envelope(doubled), KEYS) == "payload_not_a_run_statement"


def test_a_statement_signed_by_an_operators_key_returns_the_key_with_the_file_that_lists_it() -> None:
    key_id, server = "operator-run-statements", "iltero.operator.example"
    key = dataclasses.replace(SIGNER.key(key_id=key_id), server=server)
    operator = OperatorSigningKeys("Example Operator", server, {key_id: key}, "sha256:" + "0" * 64)
    payload = _payload_of_server(server)
    verified = verify_run_statement(
        SIGNER.envelope(payload, key_id=key_id), trusted_keys(SIGNING_KEYS, operator), verify_es256
    )
    assert isinstance(verified.key, TrustedKey) and verified.key.listed_in == "operator"
