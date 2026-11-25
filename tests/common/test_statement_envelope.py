"""The envelope a run statement is signed in is read strictly, and its signature is read from strict DER only."""

from __future__ import annotations

import base64
import importlib
import json
from typing import Any

import pytest

from iltero_schemas.models.common.run_statement import RunClosePredicate, StatementSubject
from iltero_schemas.signing import P256_ORDER, SignatureError
from iltero_schemas.statement import (
    MAX_RUN_STATEMENT_BYTES,
    MAX_RUN_STATEMENT_PAYLOAD_BYTES,
    NOT_A_RUN_STATEMENT,
    PAYLOAD_TYPE,
    RECORD_DIFFERENCES,
    RUN_STATEMENT_DOES_NOT_HOLD,
    RUN_STATEMENT_FILE_NAME,
    RunStatementError,
    check_payload_size,
    der_signature,
    dsse_signing_input,
    envelope,
    raw_signature,
    read_envelope,
    run_statement_payload,
)
from tests.statements import KEY_ID, Signer, payload_of, statement_parts

SIGNER = Signer()
PAYLOAD = payload_of()
ENVELOPE: dict[str, Any] = json.loads(SIGNER.envelope(PAYLOAD))


def _bytes(document: Any) -> bytes:
    return json.dumps(document).encode("utf-8")


def _refused(data: bytes, reason: str) -> None:
    with pytest.raises(RunStatementError) as refused:
        read_envelope(data)
    assert refused.value.reason == reason


def test_the_signing_input_is_the_dsse_pre_authentication_encoding() -> None:
    assert dsse_signing_input(b"hello") == b"DSSEv1 28 application/vnd.in-toto+json 5 hello"


def test_an_envelope_is_read_with_its_payload_key_and_raw_signature() -> None:
    read = read_envelope(SIGNER.envelope(PAYLOAD))
    assert (read.payload, read.key_id, len(read.signature)) == (PAYLOAD, KEY_ID, 64)


def test_the_two_groups_of_refusals_and_the_record_differences_are_apart() -> None:
    assert not NOT_A_RUN_STATEMENT & RUN_STATEMENT_DOES_NOT_HOLD
    assert not (NOT_A_RUN_STATEMENT | RUN_STATEMENT_DOES_NOT_HOLD) & RECORD_DIFFERENCES
    assert "another_run" in RECORD_DIFFERENCES


def test_the_statement_file_beside_a_record_package_has_a_fixed_plain_name() -> None:
    assert RUN_STATEMENT_FILE_NAME == "run-statement.json"


def test_an_envelope_larger_than_the_cap_is_refused_before_it_is_read() -> None:
    _refused(b" " * (MAX_RUN_STATEMENT_BYTES + 1), "too_large")


def test_bytes_that_are_not_strict_json_are_refused() -> None:
    _refused(b"\xef\xbb\xbf{}", "not_json")
    _refused(b'{"payloadType": 1, "payloadType": 2}', "not_json")


@pytest.mark.parametrize(
    "document",
    [
        [],
        {"payloadType": PAYLOAD_TYPE, "payload": ""},
        {**ENVELOPE, "extra": 1},
        {**ENVELOPE, "signatures": {}},
        {**ENVELOPE, "signatures": [{"sig": ENVELOPE["signatures"][0]["sig"]}]},
        {**ENVELOPE, "signatures": [{**ENVELOPE["signatures"][0], "cert": "x"}]},
        {**ENVELOPE, "signatures": [{**ENVELOPE["signatures"][0], "keyid": 7}]},
    ],
)
def test_anything_but_an_envelope_of_exactly_its_fields_is_refused(document: Any) -> None:
    _refused(_bytes(document), "not_an_envelope")


def test_an_envelope_of_another_payload_type_is_refused() -> None:
    _refused(_bytes({**ENVELOPE, "payloadType": "application/json"}), "another_payload_type")


@pytest.mark.parametrize("payload", ["not base64!", ENVELOPE["payload"][:-1], "\n" + ENVELOPE["payload"], 7])
def test_a_payload_in_anything_but_its_one_standard_base64_spelling_is_refused(payload: Any) -> None:
    _refused(_bytes({**ENVELOPE, "payload": payload}), "payload_not_base64")


def test_a_payload_in_url_safe_base64_is_refused() -> None:
    spelled = base64.urlsafe_b64encode(b"\xfb\xff" * 4).decode("ascii")
    _refused(_bytes({**ENVELOPE, "payload": spelled}), "payload_not_base64")


@pytest.mark.parametrize("count", [0, 2])
def test_an_envelope_without_exactly_one_signature_is_refused(count: int) -> None:
    _refused(_bytes({**ENVELOPE, "signatures": ENVELOPE["signatures"][:1] * count}), "not_exactly_one_signature")


def test_a_signature_that_is_not_strict_der_is_refused_as_invalid() -> None:
    raw = base64.b64decode(ENVELOPE["signatures"][0]["sig"])
    for sig in (base64.b64encode(raw + b"\x00").decode("ascii"), "%%%"):
        _refused(_bytes({**ENVELOPE, "signatures": [{"keyid": KEY_ID, "sig": sig}]}), "signature_invalid")


def _der(r: bytes, s: bytes) -> bytes:
    body = b"\x02" + bytes([len(r)]) + r + b"\x02" + bytes([len(s)]) + s
    return b"\x30" + bytes([len(body)]) + body


def test_der_and_raw_signatures_convert_both_ways() -> None:
    raw = SIGNER.raw_signature(b"data")
    assert raw_signature(der_signature(raw)) == raw
    small = (1).to_bytes(32, "big") + (P256_ORDER - 1).to_bytes(32, "big")
    assert der_signature(small)[:5] == b"\x30\x26\x02\x01\x01"
    assert raw_signature(der_signature(small)) == small


@pytest.mark.parametrize(
    ("der", "rule"),
    [
        (b"\x31\x06\x02\x01\x01\x02\x01\x01", "one SEQUENCE"),
        (b"\x30\x81\x06\x02\x01\x01\x02\x01\x01", "one SEQUENCE"),
        (b"\x30\x07\x02\x01\x01\x02\x01\x01", "one SEQUENCE"),
        (b"\x30\x06\x02\x01\x01\x02\x01\x01\x00", "one SEQUENCE"),
        (_der(b"\x00\x01", b"\x01"), "shortest form"),
        (_der(b"\x81", b"\x01"), "is positive"),
        (_der(b"", b"\x01"), "1 to 33 bytes"),
        (_der(b"\x01" * 33, b"\x01"), "fits in 32 bytes"),
        (b"\x30\x03\x02\x01\x01", "two INTEGERs"),
        (b"\x30\x09\x02\x01\x01\x02\x01\x01\x02\x01\x01", "nothing else"),
        (_der(b"\x00", b"\x01"), "between 0 and the curve order"),
        (_der(b"\x00" + P256_ORDER.to_bytes(32, "big"), b"\x01"), "between 0 and the curve order"),
    ],
)
def test_a_der_signature_is_read_only_in_its_one_strict_form(der: bytes, rule: str) -> None:
    with pytest.raises(SignatureError, match=rule):
        raw_signature(der)


def test_a_payload_larger_than_its_envelope_allows_is_refused_by_the_signer() -> None:
    check_payload_size(b"x" * MAX_RUN_STATEMENT_PAYLOAD_BYTES)
    with pytest.raises(RunStatementError) as refused:
        check_payload_size(b"x" * (MAX_RUN_STATEMENT_PAYLOAD_BYTES + 1))
    assert refused.value.reason == "too_large"


def test_the_largest_payload_a_signer_writes_makes_an_envelope_a_reader_reads() -> None:
    largest = b"x" * MAX_RUN_STATEMENT_PAYLOAD_BYTES
    written = envelope(largest, key_id="k" * 128, signature=SIGNER.raw_signature(dsse_signing_input(largest)))
    assert len(written) <= MAX_RUN_STATEMENT_BYTES
    assert read_envelope(written).payload == largest


def test_the_payload_builder_refuses_a_statement_whose_envelope_a_reader_would_refuse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = importlib.import_module("iltero_schemas.statement.envelope")
    monkeypatch.setattr(module, "MAX_RUN_STATEMENT_PAYLOAD_BYTES", len(PAYLOAD) - 1)
    subjects, predicate = statement_parts()
    with pytest.raises(RunStatementError, match="payload is at most"):
        run_statement_payload(
            [StatementSubject.model_validate(subject) for subject in subjects],
            RunClosePredicate.model_validate(predicate),
        )
