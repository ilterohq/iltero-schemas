"""The trusted bundle keys: which public keys may sign an assertion bundle, and which no longer may.

Iltero Compass signs every assertion bundle it serves. A tool that evaluates
the bundle checks the signature against the keys listed in
``bundle-keys.json`` next to this module. The list ships inside the package,
so a tool that pins one exact package version also pins which keys it trusts,
and never fetches trust over the network.

A key has one of three statuses:

- ``active``: bundles may be signed with it, and its signatures verify;
- ``retired``: nothing new is signed with it, but bundles it signed still verify;
- ``revoked``: its signatures never verify again, whenever they were made.

A signature carries no trusted time, so revocation applies to every signature
the key ever made, and ``revoked_at`` records when trust was withdrawn, not a
cut-off. A key is revoked only when it is lost or compromised; routine
rotation retires it. Keys are never removed from the file, only moved forward
(``active`` to ``retired`` or ``revoked``, ``retired`` to ``revoked``), and a
revoked key keeps its ``retired_at``, so the history of what was trusted stays
readable.

A key whose id starts with ``dev-`` is a local development key and is refused
here: only a development tool, reading its own file, may accept one.

The file is data, reviewed like code. ``TRUST_FILE_DIGEST`` is the digest of
its exact bytes, for a consumer to record which set of keys it checked
against.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from importlib import resources
from types import MappingProxyType
from typing import Any, Literal, cast

from iltero_schemas.canonical.encoding import digest
from iltero_schemas.models.fields import DIGEST_PATTERN, TIMESTAMP_PATTERN

API_VERSION = "iltero.io/bundle-keys/v1"
# Local development keys carry this prefix, and only a development tool accepts them.
DEV_KEY_PREFIX = "dev-"
KeyStatus = Literal["active", "retired", "revoked"]
_STATUSES = frozenset({"active", "retired", "revoked"})
_FIELDS = frozenset(
    {
        "keyid",
        "algorithm",
        "public_key",
        "spki_sha256",
        "status",
        "valid_from",
        "retired_at",
        "revoked_at",
        "revocation_reason",
    }
)
_KEY_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
_REASON = re.compile(r"[a-z][a-z0-9_]{0,63}")
_DIGEST = re.compile(DIGEST_PATTERN)
_TIMESTAMP = re.compile(TIMESTAMP_PATTERN)
# Every P-256 public key in SubjectPublicKeyInfo form (the standard DER, Distinguished Encoding Rules, form of a
# public key) starts with these bytes — the EC key type and the P-256 curve — then 0x04 and the 64-byte point.
_P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
_P256_SPKI_LENGTH = len(_P256_SPKI_PREFIX) + 65


class TrustFileError(ValueError):
    """The trust file breaks one of its rules; the message names the key and the rule."""


@dataclass(frozen=True)
class BundleKey:
    """One public key, its status, and when that status began."""

    keyid: str
    algorithm: Literal["ES256"]
    # The key in SubjectPublicKeyInfo DER form, as Open Policy Agent (OPA) and most libraries read it.
    public_key_der: bytes
    spki_sha256: str
    status: KeyStatus
    valid_from: str
    retired_at: str | None
    revoked_at: str | None
    revocation_reason: str | None

    @property
    def can_sign(self) -> bool:
        """Whether a new bundle may be signed with this key."""
        return self.status == "active"

    @property
    def can_verify(self) -> bool:
        """Whether a signature made with this key may be accepted."""
        return self.status != "revoked"


def _unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """A JSON object whose names are all different; a repeated name would hide the value a reviewer read."""
    names = [name for name, _ in pairs]
    repeated = sorted({name for name in names if names.count(name) > 1})
    if repeated:
        raise TrustFileError(f"a field appears twice in one object: {', '.join(repeated)}")
    return dict(pairs)


def _timestamp(value: Any, where: str) -> str:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise TrustFileError(f"{where}: must be an RFC 3339 UTC timestamp ending in Z")
    try:
        datetime.fromisoformat(value)
    except ValueError:
        raise TrustFileError(f"{where}: must be a real date and time") from None
    return value


def _optional_timestamp(value: Any, where: str) -> str | None:
    return None if value is None else _timestamp(value, where)


def _public_key(entry: dict[str, Any], where: str) -> bytes:
    try:
        der = base64.b64decode(entry["public_key"], validate=True)
    except (ValueError, TypeError):
        raise TrustFileError(f"{where}.public_key: must be standard base64") from None
    if len(der) != _P256_SPKI_LENGTH or not der.startswith(_P256_SPKI_PREFIX) or der[len(_P256_SPKI_PREFIX)] != 4:
        raise TrustFileError(f"{where}.public_key: must be an uncompressed P-256 SubjectPublicKeyInfo")
    if not isinstance(entry["spki_sha256"], str) or not _DIGEST.fullmatch(entry["spki_sha256"]):
        raise TrustFileError(f"{where}.spki_sha256: must be sha256: and 64 lowercase hex digits")
    if digest(der) != entry["spki_sha256"]:
        raise TrustFileError(f"{where}.spki_sha256: is not the digest of public_key")
    return der


def _status_dates(key: BundleKey, where: str) -> None:
    """The dates a status needs are present, the others absent, and in the order the statuses were reached."""
    if key.status == "retired" and key.retired_at is None:
        raise TrustFileError(f"{where}: a retired key has a retired_at")
    if key.status == "active" and key.retired_at is not None:
        raise TrustFileError(f"{where}: an active key has no retired_at")
    revoked = key.status == "revoked"
    if (key.revoked_at is not None) != revoked or (key.revocation_reason is not None) != revoked:
        raise TrustFileError(f"{where}: revoked_at and revocation_reason are present exactly when revoked")
    reason = key.revocation_reason
    if reason is not None and not (isinstance(reason, str) and _REASON.fullmatch(reason)):
        raise TrustFileError(f"{where}.revocation_reason: must be a short lower-case token")
    order = [key.valid_from, *(moment for moment in (key.retired_at, key.revoked_at) if moment is not None)]
    moments = [datetime.fromisoformat(moment) for moment in order]
    if moments != sorted(moments):
        raise TrustFileError(f"{where}: valid_from, retired_at and revoked_at must be in that order")


def _key(entry: Any, where: str, *, dev: bool) -> BundleKey:
    if not isinstance(entry, dict) or set(entry) != _FIELDS:
        raise TrustFileError(f"{where}: must have exactly the fields {', '.join(sorted(_FIELDS))}")
    keyid = entry["keyid"]
    if not isinstance(keyid, str) or not _KEY_ID.fullmatch(keyid):
        raise TrustFileError(f"{where}.keyid: must be lower-case letters, digits, '.', '_' or '-', at most 128")
    if keyid.startswith(DEV_KEY_PREFIX) != dev:
        rule = "only a development key" if dev else f"a development key ({DEV_KEY_PREFIX}…) is not trusted here"
        raise TrustFileError(f"{where}.keyid: {rule}")
    if entry["algorithm"] != "ES256":
        raise TrustFileError(f"{where}.algorithm: must be ES256")
    if not isinstance(entry["status"], str) or entry["status"] not in _STATUSES:
        raise TrustFileError(f"{where}.status: must be one of {', '.join(sorted(_STATUSES))}")
    key = BundleKey(
        keyid=keyid,
        algorithm="ES256",
        public_key_der=_public_key(entry, where),
        spki_sha256=entry["spki_sha256"],
        status=cast(KeyStatus, entry["status"]),
        valid_from=_timestamp(entry["valid_from"], f"{where}.valid_from"),
        retired_at=_optional_timestamp(entry["retired_at"], f"{where}.retired_at"),
        revoked_at=_optional_timestamp(entry["revoked_at"], f"{where}.revoked_at"),
        revocation_reason=entry["revocation_reason"],
    )
    _status_dates(key, where)
    return key


def parse_bundle_keys(raw: bytes, *, dev: bool) -> Mapping[str, BundleKey]:
    """The keys of a trust file, by key id, read-only; raises ``TrustFileError`` on any broken rule.

    ``dev`` is true only for a development tool reading its own local file:
    then every key must be a ``dev-`` key, and otherwise none may be. The keys
    are listed in key-id order, and no key id or public key appears twice.
    """
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_fields)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TrustFileError(f"not a JSON document: {exc}") from None
    if not isinstance(document, dict) or set(document) != {"apiVersion", "keys"}:
        raise TrustFileError("must have exactly the fields apiVersion and keys")
    if document["apiVersion"] != API_VERSION:
        raise TrustFileError(f"apiVersion: must be {API_VERSION}")
    if not isinstance(document["keys"], list):
        raise TrustFileError("keys: must be a list")
    keys = [_key(entry, f"keys[{index}]", dev=dev) for index, entry in enumerate(document["keys"])]
    ids = [key.keyid for key in keys]
    if any(earlier >= later for earlier, later in zip(ids, ids[1:], strict=False)):
        raise TrustFileError("keys: must be in key-id order, with no key id twice")
    if len({key.spki_sha256 for key in keys}) != len(keys):
        raise TrustFileError("keys: no public key may appear under two key ids")
    return MappingProxyType({key.keyid: key for key in keys})


_TRUST_FILE: bytes = resources.files("iltero_schemas.trust").joinpath("bundle-keys.json").read_bytes()
TRUST_FILE_DIGEST: str = digest(_TRUST_FILE)
BUNDLE_KEYS: Mapping[str, BundleKey] = parse_bundle_keys(_TRUST_FILE, dev=False)
