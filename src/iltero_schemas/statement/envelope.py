"""The envelope a run statement is signed in: Dead Simple Signing Envelope (DSSE), version 1.

An envelope is a JSON object with exactly three fields: ``payloadType``, always ``application/vnd.in-toto+json``;
``payload``, the statement's bytes in standard base64 with padding; and ``signatures``, a list of exactly one object
with exactly a ``keyid`` and a ``sig``, the signature in standard base64. The payload is the canonical JSON (RFC 8785)
of the statement, and the statement's digest is the sha256 digest of the payload bytes. A reader reads at most
``MAX_RUN_STATEMENT_BYTES``, and a signer writes no larger envelope (``check_payload_size``). Beside a record package a
statement is kept as ``RUN_STATEMENT_FILE_NAME``.

The key signs the DSSE pre-authentication encoding of the payload type and payload (``dsse_signing_input``) with
ES256. An envelope carries the signature in ASN.1 DER form (the Distinguished Encoding Rules of Abstract Syntax
Notation One), as in-toto tools write it; ``raw_signature`` reads it as the raw 64 bytes ``r‖s`` a ``SignatureCheck``
takes, and ``der_signature`` writes raw bytes back as DER, for a signer that returns raw bytes. A signature is
accepted in its low-S form only, as every signature of the contract (``signing.check_low_s``).
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from typing import Any, Final, Literal

from iltero_schemas.canonical.common.encoding import canonical_bytes
from iltero_schemas.models.common.strict_json import strict_json
from iltero_schemas.signing import SIGNATURE_BYTES, SignatureError, check_low_s, r_and_s
from iltero_schemas.statement.reasons import (
    ANOTHER_PAYLOAD_TYPE,
    NOT_AN_ENVELOPE,
    NOT_EXACTLY_ONE_SIGNATURE,
    NOT_JSON,
    PAYLOAD_NOT_BASE64,
    SIGNATURE_INVALID,
    TOO_LARGE,
    RunStatementError,
)

PAYLOAD_TYPE: Final[Literal["application/vnd.in-toto+json"]] = "application/vnd.in-toto+json"
# The name of the file a run statement is kept under beside a record package, never inside it.
RUN_STATEMENT_FILE_NAME: Final = "run-statement.json"
# The largest run statement a reader reads. A signer refuses to write a larger one (``check_payload_size``).
MAX_RUN_STATEMENT_BYTES: Final = 16 * 1024 * 1024
_ENVELOPE_FIELDS = frozenset({"payloadType", "payload", "signatures"})
_SIGNATURE_FIELDS = frozenset({"keyid", "sig"})
_HALF = SIGNATURE_BYTES // 2
# The longest key id (``trust.keys.KEY_ID_PATTERN``) and the longest DER signature, in base64.
_MAX_KEY_ID_LENGTH = 128
_MAX_DER_SIGNATURE_BASE64 = 96
_SEQUENCE = 0x30
_INTEGER = 0x02


@dataclass(frozen=True)
class Envelope:
    """An envelope as read: the payload's bytes, and the one signature's key id and raw ``r‖s`` bytes, still to
    verify."""

    payload: bytes
    key_id: str
    signature: bytes


def dsse_signing_input(payload: bytes) -> bytes:
    """The bytes a key signs: DSSE's pre-authentication encoding of ``PAYLOAD_TYPE`` and ``payload``,
    ``DSSEv1 <length> <type> <length> <payload>``, each length the byte count in ASCII decimal."""
    kind = PAYLOAD_TYPE.encode("ascii")
    return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(payload), payload)


def _integer(value: int) -> bytes:
    """``value``, a positive integer, as a DER INTEGER: its shortest big-endian bytes, with a zero byte first when the
    top bit is set, so it does not read as negative."""
    body = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return bytes([_INTEGER, len(body)]) + body


def der_signature(signature: bytes) -> bytes:
    """The raw 64-byte ``r‖s`` ES256 ``signature`` in ASN.1 DER form: a SEQUENCE of the two INTEGERs."""
    r, s = r_and_s(signature)
    body = _integer(r) + _integer(s)
    return bytes([_SEQUENCE, len(body)]) + body


def _read_integer(data: bytes, start: int) -> tuple[int, int]:
    """The DER INTEGER at ``start`` of ``data`` and where it ends: refused unless it is written in its one shortest
    form, is positive and fits in 32 bytes."""
    if len(data) < start + 2 or data[start] != _INTEGER:
        raise SignatureError("a DER signature holds two INTEGERs")
    length = data[start + 1]
    body = data[start + 2 : start + 2 + length]
    if length == 0 or length > _HALF + 1 or len(body) != length:
        raise SignatureError("a DER signature's INTEGER holds 1 to 33 bytes")
    if body[0] & 0x80:
        raise SignatureError("a DER signature's INTEGER is positive")
    if length > 1 and body[0] == 0 and not body[1] & 0x80:
        raise SignatureError("a DER signature's INTEGER is written in its shortest form")
    value = int.from_bytes(body, "big")
    if value.bit_length() > _HALF * 8:
        raise SignatureError("a DER signature's INTEGER fits in 32 bytes")
    return value, start + 2 + length


def raw_signature(der: bytes) -> bytes:
    """The raw 64-byte ``r‖s`` form of an ES256 signature in strict ASN.1 DER: a SEQUENCE of two positive INTEGERs,
    each in its shortest form, with nothing after it. Raises ``SignatureError`` for any other bytes."""
    # The SEQUENCE holds at most 70 bytes, so its length is one byte under 128: the long form would not be the shortest.
    if len(der) < 2 or der[0] != _SEQUENCE or der[1] >= 0x80 or der[1] != len(der) - 2:
        raise SignatureError("a DER signature is one SEQUENCE, its length in one byte, with nothing after it")
    r, end = _read_integer(der, 2)
    s, end = _read_integer(der, end)
    if end != len(der):
        raise SignatureError("a DER signature's SEQUENCE holds two INTEGERs and nothing else")
    raw = r.to_bytes(_HALF, "big") + s.to_bytes(_HALF, "big")
    r_and_s(raw)
    return raw


def _base64(text: Any, reason: str, what: str) -> bytes:
    """The bytes standard base64 ``text`` spells, refused unless ``text`` is their one spelling, padding included."""
    try:
        data = base64.b64decode(text, validate=True) if isinstance(text, str) else None
    except (ValueError, binascii.Error):
        data = None
    if data is None or base64.b64encode(data).decode("ascii") != text:
        raise RunStatementError(reason, f"the envelope's {what} is standard base64, with padding, spelled one way")
    return data


def read_envelope(data: bytes) -> Envelope:
    """The envelope in ``data``, read strictly; raises ``RunStatementError`` naming why it is refused.

    The signature is read but not verified: ``verify.verify_run_statement`` does that.
    """
    if len(data) > MAX_RUN_STATEMENT_BYTES:
        raise RunStatementError(TOO_LARGE, f"a run statement is at most {MAX_RUN_STATEMENT_BYTES} bytes")
    try:
        document = strict_json(data, "a run statement")
    except ValueError as error:
        raise RunStatementError(NOT_JSON, str(error)) from None
    if not isinstance(document, dict) or set(document) != _ENVELOPE_FIELDS:
        raise RunStatementError(
            NOT_AN_ENVELOPE, "a run statement is an envelope with exactly payloadType, payload and signatures"
        )
    if document["payloadType"] != PAYLOAD_TYPE:
        raise RunStatementError(ANOTHER_PAYLOAD_TYPE, f"a run statement's payloadType is {PAYLOAD_TYPE}")
    payload = _base64(document["payload"], PAYLOAD_NOT_BASE64, "payload")
    signatures = document["signatures"]
    if not isinstance(signatures, list) or not all(
        isinstance(entry, dict) and set(entry) == _SIGNATURE_FIELDS for entry in signatures
    ):
        raise RunStatementError(
            NOT_AN_ENVELOPE, "a run statement's signatures are a list of objects with exactly keyid and sig"
        )
    if len(signatures) != 1:
        raise RunStatementError(NOT_EXACTLY_ONE_SIGNATURE, "a run statement carries exactly one signature")
    (entry,) = signatures
    if not isinstance(entry["keyid"], str):
        raise RunStatementError(NOT_AN_ENVELOPE, "a run statement's signature names its key by a keyid")
    der = _base64(entry["sig"], SIGNATURE_INVALID, "signature")
    try:
        signature = raw_signature(der)
        check_low_s(signature)
    except SignatureError as error:
        raise RunStatementError(SIGNATURE_INVALID, str(error)) from None
    return Envelope(payload, entry["keyid"], signature)


def _envelope_overhead() -> int:
    """The bytes an envelope takes besides its payload's base64, at the longest key id and signature."""
    return len(
        canonical_bytes(
            {
                "payloadType": PAYLOAD_TYPE,
                "payload": "",
                "signatures": [{"keyid": "k" * _MAX_KEY_ID_LENGTH, "sig": "s" * _MAX_DER_SIGNATURE_BASE64}],
            }
        )
    )


# The largest payload whose envelope a reader reads: its base64 and the envelope around it fit
# ``MAX_RUN_STATEMENT_BYTES``.
MAX_RUN_STATEMENT_PAYLOAD_BYTES: Final = (MAX_RUN_STATEMENT_BYTES - _envelope_overhead()) // 4 * 3


def check_payload_size(payload: bytes) -> None:
    """Raise ``RunStatementError`` (``too_large``) when ``payload`` is longer than ``MAX_RUN_STATEMENT_PAYLOAD_BYTES``,
    so a signer never writes a statement a reader refuses."""
    if len(payload) > MAX_RUN_STATEMENT_PAYLOAD_BYTES:
        raise RunStatementError(
            TOO_LARGE, f"a run statement's payload is at most {MAX_RUN_STATEMENT_PAYLOAD_BYTES} bytes"
        )


def envelope(payload: bytes, *, key_id: str, signature: bytes) -> bytes:
    """The envelope of ``payload`` signed by ``key_id`` with the raw 64-byte ``r‖s`` ``signature``, as canonical JSON
    (RFC 8785), the signature in DER form. Raises ``RunStatementError`` (``too_large``) when a reader would refuse it
    for its size, and ``signing.SignatureError`` for a signature not in its low-S form
    (``signing.normalized_signature`` gives it)."""
    check_payload_size(payload)
    check_low_s(signature)
    if len(key_id) > _MAX_KEY_ID_LENGTH:
        raise ValueError(f"a key id is at most {_MAX_KEY_ID_LENGTH} characters")
    return canonical_bytes(
        {
            "payloadType": PAYLOAD_TYPE,
            "payload": base64.b64encode(payload).decode("ascii"),
            "signatures": [{"keyid": key_id, "sig": base64.b64encode(der_signature(signature)).decode("ascii")}],
        }
    )
