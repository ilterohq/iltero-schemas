"""The operator trust file: its reader refuses what breaks a rule, its keys only ever make trust stricter when combined
with Iltero's, and the trust data's digest names both files."""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from typing import Any

import pytest

from iltero_schemas.canonical import canonical_bytes, digest
from iltero_schemas.trust import (
    API_VERSION,
    ILTERO_KEY_PREFIX,
    MAX_OPERATOR_TRUST_FILE_BYTES,
    OPERATOR_TRUST_FILE_KIND,
    TRUST_FILE_DIGEST,
    TRUST_FILE_KIND,
    OperatorSigningKeys,
    SigningKey,
    TrustFileError,
    parse_operator_signing_keys,
    parse_signing_keys,
    trust_data_digest,
    trusted_keys,
)
from iltero_schemas.vectors.vector_signing_keys import VECTOR_SIGNING_KEYS_FILE, vector_signing_keys
from tests.common.test_trust_keys import KEY_A, KEY_B, VALID_FROM
from tests.conftest import VECTORS

OPERATOR_VECTOR = VECTORS / "signing_keys" / "operator.json"
ILTERO_SERVER = "iltero.example"
OPERATOR_SERVER = "iltero.operator.example"
OPERATOR = "Example Operator"
RETIRED = {"status": "retired", "retired_at": "2026-10-01T00:00:00Z"}
REVOKED = {"status": "revoked", "revoked_at": "2026-10-02T00:00:00Z", "revocation_reason": "key_compromised"}


def _entry(key_id: str, public_key: str, **fields: Any) -> dict[str, Any]:
    entry = {
        "key_id": key_id,
        "algorithm": "ES256",
        "public_key": public_key,
        "spki_sha256": digest(base64.b64decode(public_key)),
        "purpose": "check_definitions",
        "server": OPERATOR_SERVER,
        "status": "active",
        "valid_from": VALID_FROM,
        "retired_at": None,
        "revoked_at": None,
        "revocation_reason": None,
    }
    return {**entry, **fields}


def _operator_file(*entries: dict[str, Any], **top: Any) -> bytes:
    document = {
        "apiVersion": API_VERSION,
        "kind": OPERATOR_TRUST_FILE_KIND,
        "operator": OPERATOR,
        "server": OPERATOR_SERVER,
        "keys": list(entries),
        **top,
    }
    return json.dumps(document).encode("utf-8")


def _iltero(**fields: Any) -> Mapping[str, SigningKey]:
    """Iltero's keys: one key, ``iltero-1`` with ``KEY_A``, of Iltero's server."""
    entry = _entry("iltero-1", KEY_A, server=ILTERO_SERVER, **fields)
    raw = json.dumps({"apiVersion": API_VERSION, "kind": TRUST_FILE_KIND, "keys": [entry]}).encode("utf-8")
    return parse_signing_keys(raw, development=False)


def _operator(*entries: dict[str, Any], **top: Any) -> OperatorSigningKeys:
    return parse_operator_signing_keys(_operator_file(*entries, **top))


def test_the_operator_vector_is_read_with_its_name_server_keys_and_digest() -> None:
    raw = OPERATOR_VECTOR.read_bytes()
    operator = parse_operator_signing_keys(raw)
    assert (operator.operator, operator.server, list(operator.keys)) == (
        OPERATOR,
        OPERATOR_SERVER,
        ["operator-check-definitions"],
    )
    assert operator.file_digest == digest(raw)


def test_the_operator_vector_combines_with_the_development_keys() -> None:
    combined = trusted_keys(vector_signing_keys(), parse_operator_signing_keys(OPERATOR_VECTOR.read_bytes()))
    assert {key_id: (key.listed_in, key.revoked_by_operator) for key_id, key in combined.items()} == {
        "dev-scanner-check-mapping-vectors": ("iltero", False),
        "dev-signing-key-vectors": ("iltero", False),
        "operator-check-definitions": ("operator", False),
    }
    assert combined["operator-check-definitions"].server == OPERATOR_SERVER


def test_without_an_operator_file_the_trust_set_is_iltero_s_keys() -> None:
    combined = trusted_keys(_iltero(), None)
    key = combined["iltero-1"]
    assert (key.listed_in, key.revoked_by_operator, key.server, key.status) == (
        "iltero",
        False,
        ILTERO_SERVER,
        "active",
    )


def test_a_trust_set_combines_again_with_its_own_keys() -> None:
    combined = trusted_keys(_iltero(), None)
    assert trusted_keys(combined, None) == combined


def test_the_trust_set_is_read_only() -> None:
    combined = trusted_keys(_iltero(), _operator(_entry("op-1", KEY_B)))
    with pytest.raises(TypeError):
        combined["op-2"] = combined["op-1"]  # type: ignore[index]


def test_an_operator_key_is_added_for_the_operator_s_server() -> None:
    combined = trusted_keys(_iltero(), _operator(_entry("op-1", KEY_B)))
    assert set(combined) == {"iltero-1", "op-1"}
    key = combined["op-1"]
    assert (key.listed_in, key.revoked_by_operator, key.server) == ("operator", False, OPERATOR_SERVER)


@pytest.mark.parametrize(
    ("iltero", "entry"),
    [({}, REVOKED), (RETIRED, {**RETIRED, **REVOKED})],
    ids=["active revoked", "retired revoked"],
)
def test_an_operator_entry_may_revoke_one_of_iltero_s_keys(iltero: dict[str, Any], entry: dict[str, Any]) -> None:
    combined = trusted_keys(_iltero(**iltero), _operator(_entry("iltero-1", KEY_A, server=ILTERO_SERVER, **entry)))
    key = combined["iltero-1"]
    assert (key.status, key.listed_in, key.revoked_by_operator, key.server) == (
        "revoked",
        "iltero",
        True,
        ILTERO_SERVER,
    )
    assert (key.revoked_at, key.revocation_reason) == (REVOKED["revoked_at"], REVOKED["revocation_reason"])
    assert not key.can_verify


@pytest.mark.parametrize("status", [{}, RETIRED, REVOKED], ids=["active", "retired", "revoked"])
def test_an_operator_entry_that_keeps_one_of_iltero_s_keys_as_it_is_changes_nothing(status: dict[str, Any]) -> None:
    combined = trusted_keys(_iltero(**status), _operator(_entry("iltero-1", KEY_A, server=ILTERO_SERVER, **status)))
    assert combined == trusted_keys(_iltero(**status), None)


@pytest.mark.parametrize(
    ("iltero", "entry", "message"),
    [
        ({}, RETIRED, "may only revoke one of Iltero's keys"),
        (RETIRED, {}, "may only revoke one of Iltero's keys"),
        (REVOKED, {}, "may only revoke one of Iltero's keys"),
        (REVOKED, RETIRED, "may only revoke one of Iltero's keys"),
        (RETIRED, {"status": "retired", "retired_at": "2026-10-03T00:00:00Z"}, "may only revoke one of Iltero's keys"),
        (REVOKED, {**REVOKED, "revocation_reason": "lost"}, "may only revoke one of Iltero's keys"),
        ({}, {"purpose": "run_statement"}, "may only revoke one of Iltero's keys"),
        ({}, {"valid_from": "2026-08-01T00:00:00Z"}, "may only revoke one of Iltero's keys"),
    ],
    ids=[
        "active retired",
        "retired made active",
        "revoked made active",
        "revoked made retired",
        "a retirement date rewritten",
        "a revocation reason rewritten",
        "another purpose",
        "another start",
    ],
)
def test_an_operator_entry_never_makes_one_of_iltero_s_keys_looser_or_rewrites_it(
    iltero: dict[str, Any], entry: dict[str, Any], message: str
) -> None:
    with pytest.raises(TrustFileError, match=message):
        trusted_keys(_iltero(**iltero), _operator(_entry("iltero-1", KEY_A, server=ILTERO_SERVER, **entry)))


def test_an_operator_entry_for_one_of_iltero_s_keys_keeps_iltero_s_server() -> None:
    with pytest.raises(TrustFileError, match="may only revoke one of Iltero's keys"):
        trusted_keys(_iltero(), _operator(_entry("iltero-1", KEY_A, **REVOKED)))


@pytest.mark.parametrize(
    "entry",
    [_entry("iltero-1", KEY_B), _entry("op-1", KEY_A), _entry("op-1", KEY_A, server=ILTERO_SERVER, **REVOKED)],
    ids=[
        "iltero's key id with another public key",
        "iltero's public key under another id",
        "a revocation by another id",
    ],
)
def test_an_operator_key_never_takes_iltero_s_key_id_or_public_key(entry: dict[str, Any]) -> None:
    with pytest.raises(TrustFileError, match="Iltero's keys hold its id or its public key under another"):
        trusted_keys(_iltero(), _operator(entry))


def test_an_operator_file_never_names_the_server_of_iltero_s_keys() -> None:
    with pytest.raises(TrustFileError, match="names a server that Iltero's own keys belong to"):
        trusted_keys(_iltero(), _operator(_entry("op-1", KEY_B, server=ILTERO_SERVER), server=ILTERO_SERVER))


def test_an_operator_file_never_adds_a_key_under_an_id_kept_for_iltero() -> None:
    with pytest.raises(TrustFileError, match=f"an id starting {ILTERO_KEY_PREFIX} is kept for Iltero's own keys"):
        trusted_keys(_iltero(), _operator(_entry(ILTERO_KEY_PREFIX + "2", KEY_B)))


def test_an_operator_key_names_the_operator_s_server() -> None:
    with pytest.raises(TrustFileError, match="names another server than the operator trust file"):
        trusted_keys(_iltero(), _operator(_entry("op-1", KEY_B, server="another.example")))


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (_operator_file(_entry("dev-operator", KEY_B)), "is not trusted here"),
        (_operator_file(operator=""), "operator: must be 1 to 253 printable characters"),
        (_operator_file(operator=None), "operator: must be"),
        (_operator_file(operator=" Example Operator"), "with no space at either end"),
        (_operator_file(operator="o" * 254), "operator: must be 1 to 253 printable characters"),
        (_operator_file(server="Iltero.Operator.Example"), "server: must be a lower-case host name"),
        (_operator_file(_entry("op-1", KEY_B, server="iltero.operator.example.")), "server: must be a lower-case"),
        (_operator_file(kind=TRUST_FILE_KIND), "kind: must be OperatorSigningKeys"),
        (_operator_file(apiVersion="iltero.com/v2"), "apiVersion: must be iltero.com/v1"),
        (_operator_file(signature="x"), "exactly the fields apiVersion, kind, operator, server and keys"),
        (
            json.dumps({"apiVersion": API_VERSION, "kind": OPERATOR_TRUST_FILE_KIND, "keys": []}).encode(),
            "exactly the fields apiVersion, kind, operator, server and keys",
        ),
        (_operator_file(keys={}), "keys: must be a list"),
        (_operator_file(_entry("op-2", KEY_A), _entry("op-1", KEY_B)), "key-id order"),
        (_operator_file(_entry("op-1", KEY_A), _entry("op-2", KEY_A)), "two key ids"),
        (_operator_file(_entry("op-1", KEY_A, status="expired")), "status: must be one of"),
        (_operator_file().replace(b'"keys": []', b'"keys": [], "keys": []'), "names each key once"),
        (b"\xef\xbb\xbf" + _operator_file(), "no byte order mark"),
        (_operator_file().replace(b'"keys": []', b'"keys": Infinity'), "holds no Infinity"),
        (b"{", "is a JSON document in UTF-8"),
    ],
    ids=[
        "a development key",
        "an empty operator name",
        "no operator name",
        "an operator name with a space at its start",
        "an operator name too long",
        "a server name in upper case",
        "a key's server ending in a dot",
        "Iltero's file's kind",
        "another apiVersion",
        "an extra field",
        "no operator or server",
        "keys not a list",
        "keys out of order",
        "a public key twice",
        "a key breaking a rule",
        "a field twice",
        "a byte order mark",
        "a constant",
        "not JSON",
    ],
)
def test_an_operator_file_that_breaks_a_rule_is_refused(raw: bytes, message: str) -> None:
    with pytest.raises(TrustFileError, match=message):
        parse_operator_signing_keys(raw)


def test_an_operator_file_larger_than_the_cap_is_refused_before_it_is_read() -> None:
    raw = _operator_file()
    padded = raw[:-1] + b" " * (MAX_OPERATOR_TRUST_FILE_BYTES - len(raw)) + b"}"
    assert len(padded) == MAX_OPERATOR_TRUST_FILE_BYTES
    assert parse_operator_signing_keys(padded).keys == {}
    with pytest.raises(TrustFileError, match=f"at most {MAX_OPERATOR_TRUST_FILE_BYTES} bytes"):
        parse_operator_signing_keys(padded + b" ")


def test_without_an_operator_file_the_trust_data_digest_is_iltero_s_file_digest() -> None:
    assert trust_data_digest(TRUST_FILE_DIGEST, None) == TRUST_FILE_DIGEST


def test_with_an_operator_file_the_trust_data_digest_is_over_the_sorted_pair_of_file_digests() -> None:
    iltero = digest(VECTOR_SIGNING_KEYS_FILE.read_bytes())
    operator = digest(OPERATOR_VECTOR.read_bytes())
    expected = digest(canonical_bytes(sorted([iltero, operator])))
    assert trust_data_digest(iltero, operator) == trust_data_digest(operator, iltero) == expected
    assert expected == digest(f'["{min(iltero, operator)}","{max(iltero, operator)}"]'.encode())


@pytest.mark.parametrize(
    ("iltero", "operator"),
    [("sha256:" + "A" * 64, None), (TRUST_FILE_DIGEST, "0" * 64), ("sha256:" + "0" * 63, TRUST_FILE_DIGEST)],
    ids=["upper-case digest", "no prefix", "too short"],
)
def test_the_trust_data_digest_refuses_what_is_not_a_digest(iltero: str, operator: str | None) -> None:
    with pytest.raises(ValueError, match="sha256: and 64 lowercase hex digits"):
        trust_data_digest(iltero, operator)
