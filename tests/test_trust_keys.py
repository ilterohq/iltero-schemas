"""The trusted bundle keys: the shipped file holds, and every rule of a trust file refuses what breaks it."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from iltero_schemas.canonical import digest
from iltero_schemas.trust import (
    API_VERSION,
    BUNDLE_KEYS,
    DEV_KEY_PREFIX,
    TRUST_FILE_DIGEST,
    TrustFileError,
    parse_bundle_keys,
)
from tests.conftest import ROOT

TRUST_FILE = ROOT / "src" / "iltero_schemas" / "trust" / "bundle-keys.json"
# Two P-256 public keys made for these tests; their private halves were never kept.
KEY_A = (
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEi9AB0NG9vP6rFJMlTsN6H0ZeJoH8"
    "DTPKYdVyHrQ0mqH66RJe6qQPNTR14YFUEbJN+4UHNlNB3evM08/IBp7wJg=="
)
KEY_B = (
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELYdhqTRItDY+Uel9sFQ4vedNPgv7"
    "03TXMI8P8lDpf7t8+Uo/jqFJwrTpSwcxNu39IUjNXu/7Z7PgZZJQhV7/Ug=="
)
VALID_FROM = "2026-09-01T00:00:00Z"


def _entry(keyid: str, public_key: str = KEY_A, **fields: Any) -> dict[str, Any]:
    entry = {
        "keyid": keyid,
        "algorithm": "ES256",
        "public_key": public_key,
        "spki_sha256": digest(base64.b64decode(public_key)),
        "status": "active",
        "valid_from": VALID_FROM,
        "retired_at": None,
        "revoked_at": None,
        "revocation_reason": None,
    }
    return {**entry, **fields}


def _with_byte(index: int, value: int) -> str:
    """``KEY_A`` with one byte of its encoding replaced, keeping the length."""
    der = bytearray(base64.b64decode(KEY_A))
    der[index] = value
    return base64.b64encode(bytes(der)).decode("ascii")


def _file(*entries: dict[str, Any], **top: Any) -> bytes:
    return json.dumps({"apiVersion": API_VERSION, "keys": list(entries), **top}).encode("utf-8")


def test_the_shipped_file_is_valid_and_its_digest_is_of_its_bytes() -> None:
    raw = TRUST_FILE.read_bytes()
    assert parse_bundle_keys(raw, dev=False) == BUNDLE_KEYS
    assert TRUST_FILE_DIGEST == digest(raw)


def test_the_shipped_file_holds_no_development_key() -> None:
    assert not any(keyid.startswith(DEV_KEY_PREFIX) for keyid in BUNDLE_KEYS)


def test_an_empty_set_is_allowed() -> None:
    assert parse_bundle_keys(_file(), dev=False) == {}


def test_a_valid_key_is_read_with_its_der_bytes() -> None:
    key = parse_bundle_keys(_file(_entry("iltero-bundle-2026-09")), dev=False)["iltero-bundle-2026-09"]
    assert key.public_key_der == base64.b64decode(KEY_A)
    assert key.algorithm == "ES256" and key.status == "active"


@pytest.mark.parametrize(
    ("fields", "can_sign", "can_verify"),
    [
        ({}, True, True),
        ({"status": "retired", "retired_at": "2026-10-01T00:00:00Z"}, False, True),
        (
            {"status": "revoked", "revoked_at": "2026-10-01T00:00:00Z", "revocation_reason": "compromised"},
            False,
            False,
        ),
        (
            {
                "status": "revoked",
                "retired_at": "2026-10-01T00:00:00Z",
                "revoked_at": "2026-10-02T00:00:00Z",
                "revocation_reason": "lost",
            },
            False,
            False,
        ),
    ],
    ids=["active", "retired", "revoked", "revoked after retiring"],
)
def test_the_status_decides_what_a_key_may_do(fields: dict[str, Any], can_sign: bool, can_verify: bool) -> None:
    key = parse_bundle_keys(_file(_entry("k1", **fields)), dev=False)["k1"]
    assert (key.can_sign, key.can_verify) == (can_sign, can_verify)


def test_the_keys_are_read_only() -> None:
    keys = parse_bundle_keys(_file(_entry("k1")), dev=False)
    with pytest.raises(TypeError):
        keys["k2"] = keys["k1"]  # type: ignore[index]


@pytest.mark.parametrize(
    ("dev", "keyid", "message"),
    [
        (False, "dev-0a1b2c3d", "is not trusted here"),
        (True, "iltero-bundle-2026-09", "only a development key"),
    ],
    ids=["a development key in the shipped set", "a real key in a development file"],
)
def test_development_keys_and_real_keys_never_mix(dev: bool, keyid: str, message: str) -> None:
    with pytest.raises(TrustFileError, match=message):
        parse_bundle_keys(_file(_entry(keyid)), dev=dev)


def test_a_development_tool_reads_its_own_development_keys() -> None:
    assert list(parse_bundle_keys(_file(_entry("dev-0a1b2c3d")), dev=True)) == ["dev-0a1b2c3d"]


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        (_entry("k1", spki_sha256="sha256:" + "0" * 64), "is not the digest of public_key"),
        (_entry("k1", spki_sha256="0" * 64), "sha256: and 64 lowercase hex"),
        ({**_entry("k1"), "public_key": "not base64!"}, "standard base64"),
        (
            _entry("k1", public_key=base64.b64encode(base64.b64decode(KEY_A)[:-1]).decode()),
            "uncompressed P-256",
        ),
        (_entry("k1", algorithm="RS256"), "must be ES256"),
        (_entry("k1", status="expired"), "must be one of"),
        (_entry("K1"), "keyid"),
        (_entry("k1", valid_from="2026-09-01"), "RFC 3339"),
        (_entry("k1", valid_from="2026-02-30T00:00:00Z"), "real date"),
        (_entry("k1", status="retired"), "a retired key has a retired_at"),
        (_entry("k1", retired_at="2026-10-01T00:00:00Z"), "an active key has no retired_at"),
        (_entry("k1", status="revoked", revoked_at="2026-10-01T00:00:00Z"), "revocation_reason are present"),
        (_entry("k1", revocation_reason="compromised"), "revocation_reason are present"),
        (
            _entry("k1", status="revoked", revoked_at="2026-10-01T00:00:00Z", revocation_reason="Key Lost"),
            "short lower-case token",
        ),
        (_entry("k1", status="retired", retired_at="2026-08-01T00:00:00Z"), "in that order"),
        (
            _entry("k1", status="revoked", revoked_at="2026-08-01T00:00:00Z", revocation_reason="lost"),
            "in that order",
        ),
        (
            _entry(
                "k1",
                status="revoked",
                retired_at="2026-10-02T00:00:00Z",
                revoked_at="2026-10-01T00:00:00Z",
                revocation_reason="lost",
            ),
            "in that order",
        ),
        (_entry("k1", status=["active"]), "must be one of"),
        (
            _entry("k1", status="revoked", revoked_at="2026-10-01T00:00:00Z", revocation_reason=5),
            "short lower-case token",
        ),
        ({**_entry("k1"), "public_key": "\u00e9" * 8}, "standard base64"),
        ({**_entry("k1"), "public_key": 5}, "standard base64"),
        (_entry("k1", public_key=_with_byte(0, 0x31)), "uncompressed P-256"),
        (_entry("k1", public_key=_with_byte(20, 0x21)), "uncompressed P-256"),
        (_entry("k1", public_key=_with_byte(26, 0x02)), "uncompressed P-256"),
        (_entry("k" * 129), "keyid"),
        (_entry("-k1"), "keyid"),
        ({**_entry("k1"), "keyid": 5}, "keyid"),
        ({**_entry("k1"), "comment": "x"}, "exactly the fields"),
        ({k: v for k, v in _entry("k1").items() if k != "retired_at"}, "exactly the fields"),
    ],
    ids=[
        "digest of another key",
        "digest without prefix",
        "key not base64",
        "key truncated",
        "another algorithm",
        "unknown status",
        "upper-case key id",
        "date without time",
        "impossible date",
        "retired without a date",
        "active with a retirement date",
        "revoked without a reason",
        "active with a reason",
        "reason not a token",
        "retired before it was valid",
        "revoked before it was valid",
        "revoked before it was retired",
        "status not a string",
        "reason not a string",
        "key not ascii",
        "key not a string",
        "not a SubjectPublicKeyInfo",
        "another curve",
        "compressed point",
        "key id too long",
        "key id starting with a dash",
        "key id not a string",
        "an extra field",
        "a missing field",
    ],
)
def test_a_key_that_breaks_a_rule_is_refused(entry: dict[str, Any], message: str) -> None:
    with pytest.raises(TrustFileError, match=message):
        parse_bundle_keys(_file(entry), dev=False)


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (_file(_entry("k2"), _entry("k1", KEY_B)), "key-id order"),
        (_file(_entry("k1"), _entry("k1", KEY_B)), "no key id twice"),
        (_file(_entry("k1"), _entry("k2")), "two key ids"),
        (_file(apiVersion="iltero.io/bundle-keys/v2"), "apiVersion"),
        (_file(signature="x"), "exactly the fields"),
        (json.dumps({"apiVersion": API_VERSION, "keys": {}}).encode(), "must be a list"),
        (b"{", "not a JSON document"),
        (b"[]", "exactly the fields apiVersion and keys"),
        (
            _file(_entry("k1")).replace(b'"status": "active"', b'"status": "revoked", "status": "active"'),
            "appears twice",
        ),
        (b'{"apiVersion": "' + API_VERSION.encode() + b'", "keys": [], "keys": []}', "appears twice"),
    ],
    ids=[
        "out of order",
        "a key id twice",
        "a public key twice",
        "another version",
        "an extra field",
        "not a list",
        "not JSON",
        "not an object",
        "a field twice in a key",
        "keys twice",
    ],
)
def test_a_file_that_breaks_a_rule_is_refused(raw: bytes, message: str) -> None:
    with pytest.raises(TrustFileError, match=message):
        parse_bundle_keys(raw, dev=False)
