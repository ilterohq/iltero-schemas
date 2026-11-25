"""The trusted signing keys: the shipped file holds, and every rule of a trust file refuses what breaks it."""

from __future__ import annotations

import base64
import json
import re
from typing import Any

import pytest

from iltero_schemas.canonical import digest
from iltero_schemas.trust import (
    API_VERSION,
    DEVELOPMENT_KEY_PREFIX,
    ILTERO_KEY_PREFIX,
    KEY_ID_PATTERN,
    MAX_SERVER_NAME_LENGTH,
    SERVER_NAME_PATTERN,
    SIGNING_KEYS,
    TRUST_FILE_DIGEST,
    TRUST_FILE_KIND,
    KeyNotHeldError,
    KeyOfAnotherPurposeError,
    TrustFileError,
    key_of_purpose,
    parse_signing_keys,
)
from tests.conftest import ROOT

TRUST_FILE = ROOT / "src" / "iltero_schemas" / "trust" / "signing-keys.json"
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


def _entry(key_id: str, public_key: str = KEY_A, **fields: Any) -> dict[str, Any]:
    entry = {
        "key_id": key_id,
        "algorithm": "ES256",
        "public_key": public_key,
        "spki_sha256": digest(base64.b64decode(public_key)),
        "purpose": "check_definitions",
        "server": "iltero.example",
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
    return json.dumps({"apiVersion": API_VERSION, "kind": TRUST_FILE_KIND, "keys": list(entries), **top}).encode(
        "utf-8"
    )


def test_the_shipped_file_is_valid_and_its_digest_is_of_its_bytes() -> None:
    raw = TRUST_FILE.read_bytes()
    assert parse_signing_keys(raw, development=False) == SIGNING_KEYS
    assert TRUST_FILE_DIGEST == digest(raw)


def test_the_shipped_file_holds_no_development_key() -> None:
    assert not any(key_id.startswith(DEVELOPMENT_KEY_PREFIX) for key_id in SIGNING_KEYS)


def test_an_empty_set_is_allowed() -> None:
    assert parse_signing_keys(_file(), development=False) == {}


def test_a_valid_key_is_read_with_its_der_bytes() -> None:
    key = parse_signing_keys(_file(_entry("iltero-signing-test")), development=False)["iltero-signing-test"]
    assert key.public_key_der == base64.b64decode(KEY_A)
    assert key.algorithm == "ES256" and key.status == "active"
    assert (key.purpose, key.server) == ("check_definitions", "iltero.example")


def test_a_key_is_read_with_either_purpose() -> None:
    keys = parse_signing_keys(_file(_entry("k1"), _entry("k2", KEY_B, purpose="run_statement")), development=False)
    assert (keys["k1"].purpose, keys["k2"].purpose) == ("check_definitions", "run_statement")


def test_one_public_key_has_one_purpose() -> None:
    with pytest.raises(TrustFileError, match="two key ids"):
        parse_signing_keys(_file(_entry("k1"), _entry("k2", purpose="run_statement")), development=False)


def test_a_server_name_as_long_as_the_longest_host_name_is_read() -> None:
    server = ".".join(["a" * 63] * 3 + ["a" * 61])
    assert len(server) == MAX_SERVER_NAME_LENGTH
    assert parse_signing_keys(_file(_entry("k1", server=server)), development=False)["k1"].server == server


@pytest.mark.parametrize("server", ["development", "iltero.example", "a-1.b2.example", "0.example"])
def test_a_server_name_is_a_lower_case_host_name(server: str) -> None:
    assert parse_signing_keys(_file(_entry("k1", server=server)), development=False)["k1"].server == server
    # A model field matches its pattern anywhere in the string, so the pattern itself holds the whole name.
    assert re.search(SERVER_NAME_PATTERN, f" {server} ") is None


def test_a_checker_takes_a_key_of_its_purpose_whatever_its_status() -> None:
    revoked = {"status": "revoked", "revoked_at": "2026-10-01T00:00:00Z", "revocation_reason": "lost"}
    keys = parse_signing_keys(_file(_entry("k1", **revoked)), development=False)
    assert key_of_purpose(keys, "k1", "check_definitions") is keys["k1"]


def test_a_checker_refuses_a_key_the_trust_set_does_not_hold() -> None:
    with pytest.raises(KeyNotHeldError):
        key_of_purpose(parse_signing_keys(_file(_entry("k1")), development=False), "k2", "check_definitions")


def test_a_checker_refuses_a_key_of_another_purpose() -> None:
    keys = parse_signing_keys(_file(_entry("k1", purpose="run_statement")), development=False)
    with pytest.raises(KeyOfAnotherPurposeError):
        key_of_purpose(keys, "k1", "check_definitions")


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
    key = parse_signing_keys(_file(_entry("k1", **fields)), development=False)["k1"]
    assert (key.can_sign, key.can_verify) == (can_sign, can_verify)


def test_the_keys_are_read_only() -> None:
    keys = parse_signing_keys(_file(_entry("k1")), development=False)
    with pytest.raises(TypeError):
        keys["k2"] = keys["k1"]  # type: ignore[index]


@pytest.mark.parametrize(
    ("development", "key_id", "message"),
    [
        (False, "dev-0a1b2c3d", "is not trusted here"),
        (True, "iltero-signing-test", "only a development key"),
    ],
    ids=["a development key in the shipped set", "a real key in a development file"],
)
def test_development_keys_and_real_keys_never_mix(development: bool, key_id: str, message: str) -> None:
    with pytest.raises(TrustFileError, match=message):
        parse_signing_keys(_file(_entry(key_id)), development=development)


def test_a_development_tool_reads_its_own_development_keys() -> None:
    assert list(parse_signing_keys(_file(_entry("dev-0a1b2c3d")), development=True)) == ["dev-0a1b2c3d"]


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
        (_entry("K1"), "key_id"),
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
        (_entry("k1", purpose="period_package"), "purpose: must be one of check_definitions, run_statement"),
        (_entry("k1", purpose=None), "purpose: must be one of"),
        (_entry("k1", server=""), "server: must be a lower-case host name of at most 253 characters"),
        (_entry("k1", server=".".join(["a" * 63] * 3 + ["a" * 62])), "server: must be a lower-case host name"),
        (_entry("k1", server=" iltero.example"), "server: must be a lower-case host name"),
        (_entry("k1", server="iltero.example\n"), "server: must be a lower-case host name"),
        (_entry("k1", server="Iltero.example"), "server: must be a lower-case host name"),
        (_entry("k1", server="iltero.example."), "server: must be a lower-case host name"),
        (_entry("k1", server="iltero..example"), "server: must be a lower-case host name"),
        (_entry("k1", server="-iltero.example"), "server: must be a lower-case host name"),
        (_entry("k1", server="iltero-.example"), "server: must be a lower-case host name"),
        (_entry("k1", server="a" * 64 + ".example"), "server: must be a lower-case host name"),
        (_entry("k1", server="iltero_example"), "server: must be a lower-case host name"),
        (_entry("k1", server=5), "server: must be a lower-case host name"),
        (
            _entry("k1", status="revoked", revoked_at="2026-10-01T00:00:00Z", revocation_reason=5),
            "short lower-case token",
        ),
        ({**_entry("k1"), "public_key": "\u00e9" * 8}, "standard base64"),
        ({**_entry("k1"), "public_key": 5}, "standard base64"),
        (_entry("k1", public_key=_with_byte(0, 0x31)), "uncompressed P-256"),
        (_entry("k1", public_key=_with_byte(20, 0x21)), "uncompressed P-256"),
        (_entry("k1", public_key=_with_byte(26, 0x02)), "uncompressed P-256"),
        (_entry("k" * 129), "key_id"),
        (_entry("-k1"), "key_id"),
        ({**_entry("k1"), "key_id": 5}, "key_id"),
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
        "an unknown purpose",
        "no purpose",
        "an empty server",
        "a server name too long",
        "a server name with a space at its start",
        "a server name ending in a line break",
        "a server name in upper case",
        "a server name ending in a dot",
        "a server name with an empty label",
        "a label starting with a dash",
        "a label ending with a dash",
        "a label too long",
        "a server name with an underscore",
        "a server name not a string",
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
        parse_signing_keys(_file(entry), development=False)


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (_file(_entry("k2"), _entry("k1", KEY_B)), "key-id order"),
        (_file(_entry("k1"), _entry("k1", KEY_B)), "no key id twice"),
        (_file(_entry("k1"), _entry("k2")), "two key ids"),
        (_file(apiVersion="iltero.io/signing-keys/v1"), "apiVersion"),
        (_file(apiVersion=API_VERSION + "1"), "apiVersion"),
        (_file(kind="AssertionBundleDescriptor"), "kind"),
        (_file(kind=TRUST_FILE_KIND.lower()), "kind"),
        (_file(signature="x"), "exactly the fields"),
        (json.dumps({"apiVersion": API_VERSION, "kind": TRUST_FILE_KIND, "keys": {}}).encode(), "must be a list"),
        (b"{", "is a JSON document in UTF-8"),
        (b"\xef\xbb\xbf" + _file(), "no byte order mark"),
        (_file().replace(b'"keys": []', b'"keys": NaN'), "holds no NaN"),
        (b"[]", "exactly the fields apiVersion, kind and keys"),
        (json.dumps({"apiVersion": API_VERSION, "keys": []}).encode(), "exactly the fields"),
        (
            _file(_entry("k1")).replace(b'"status": "active"', b'"status": "revoked", "status": "active"'),
            "names each key once",
        ),
        (
            b'{"apiVersion": "'
            + API_VERSION.encode()
            + b'", "kind": "'
            + TRUST_FILE_KIND.encode()
            + b'", "keys": [], "keys": []}',
            "names each key once",
        ),
    ],
    ids=[
        "out of order",
        "a key id twice",
        "a public key twice",
        "the old name",
        "a longer version",
        "another document's kind",
        "a kind in other case",
        "an extra field",
        "not a list",
        "not JSON",
        "a byte order mark",
        "a constant",
        "not an object",
        "no kind",
        "a field twice in a key",
        "keys twice",
    ],
)
def test_a_file_that_breaks_a_rule_is_refused(raw: bytes, message: str) -> None:
    with pytest.raises(TrustFileError, match=message):
        parse_signing_keys(raw, development=False)


@pytest.mark.parametrize(
    ("key_id", "matches"),
    [
        ("dev-signing-key-vectors", True),
        ("iltero.2026_11", True),
        ("Dev-key", False),
        ("-key", False),
        ("a" * 129, False),
    ],
)
def test_the_published_key_id_pattern_is_the_form_the_trust_file_accepts(key_id: str, matches: bool) -> None:
    assert (re.fullmatch(KEY_ID_PATTERN, key_id) is not None) is matches
    # A model field matches its pattern anywhere in the string, so the pattern itself holds the whole id.
    assert re.search(KEY_ID_PATTERN, f" {key_id} ") is None


def test_every_key_iltero_ships_has_an_id_under_the_prefix_kept_for_iltero() -> None:
    assert all(key_id.startswith(ILTERO_KEY_PREFIX) for key_id in SIGNING_KEYS)
