"""The trusted signing keys: which public keys may sign what the server serves, and which no longer may.

Each key has one purpose. A ``check_definitions`` key signs the check definitions the server serves, assertion bundles
and scanner check mappings; each signature names the kind of document it is over, so one is never accepted for the
other. A ``run_statement`` key signs the statement the server makes when a run ends. Every checker refuses a key of
another purpose than the one it checks. Each key names the server it belongs to; the checkers do not tell servers
apart, and the trust data's digest a stage records shows which keys were used. A tool checks a signature against the
keys listed in ``signing-keys.json`` next to this module. The list ships inside the package,
so a tool that pins one exact package version also pins which keys it trusts,
and never fetches trust over the network.

A key has one of three statuses:

- ``active``: documents may be signed with it, and its signatures verify;
- ``retired``: nothing new is signed with it, but what it signed still verifies;
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
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from importlib import resources
from types import MappingProxyType
from typing import Any, Literal, cast, get_args

from iltero_schemas.canonical.common.encoding import digest
from iltero_schemas.models.common.base import API_VERSION as API_VERSION
from iltero_schemas.models.common.fields import DIGEST_PATTERN, TIMESTAMP_PATTERN
from iltero_schemas.models.common.strict_json import strict_json

TRUST_FILE_KIND = "SigningKeys"
# Local development keys carry this prefix, and only a development tool accepts them.
DEVELOPMENT_KEY_PREFIX = "dev-"
KeyStatus = Literal["active", "retired", "revoked"]
_STATUSES: frozenset[str] = frozenset(get_args(KeyStatus))
# What a key signs: check definitions (assertion bundles and scanner check mappings), or the statement a server makes
# when a run ends.
KeyPurpose = Literal["check_definitions", "run_statement"]
_PURPOSES: frozenset[str] = frozenset(get_args(KeyPurpose))
# The longest server name: that of the longest host name, since a server is named by its host.
MAX_SERVER_NAME_LENGTH = 253
# A server's name is a lower-case host name: labels of letters, digits and '-', not starting or ending with '-', joined
# by '.', with no dot at the end.
SERVER_NAME_PATTERN = r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
_SERVER_NAME = re.compile(SERVER_NAME_PATTERN)
# The history of a key, kept the same between two versions of a trust file: what never changes once a key is listed,
# what never changes once it is written, and the moves a status may make besides staying the same.
FIXED_KEY_FIELDS = ("algorithm", "public_key_der", "purpose", "server", "valid_from")
WRITTEN_ONCE_KEY_FIELDS = ("retired_at", "revoked_at", "revocation_reason")
FORWARD_STATUS_MOVES = frozenset({("active", "retired"), ("active", "revoked"), ("retired", "revoked")})
_FIELDS = frozenset(
    {
        "key_id",
        "algorithm",
        "public_key",
        "spki_sha256",
        "purpose",
        "server",
        "status",
        "valid_from",
        "retired_at",
        "revoked_at",
        "revocation_reason",
    }
)
# The form of a signing key's id, wherever one is named: the trust file, a signed document, a record, a run's settings.
# Anchored, like every pattern a consumer may put in a model field, which matches anywhere in a string.
KEY_ID_PATTERN = r"^[a-z0-9][a-z0-9._-]{0,127}$"
_KEY_ID = re.compile(KEY_ID_PATTERN)
_REASON = re.compile(r"[a-z][a-z0-9_]{0,63}")
_DIGEST = re.compile(DIGEST_PATTERN)
_TIMESTAMP = re.compile(TIMESTAMP_PATTERN)
# Every P-256 public key in SubjectPublicKeyInfo form (the standard DER, Distinguished Encoding Rules, form of a
# public key) starts with these bytes — the EC key type and the P-256 curve — then 0x04 and the 64-byte point.
_P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
_P256_SPKI_LENGTH = len(_P256_SPKI_PREFIX) + 65


class TrustFileError(ValueError):
    """The trust file breaks one of its rules; the message names the key and the rule."""


class KeyNotHeldError(LookupError):
    """The trust set holds no key with the id a document names."""


class KeyOfAnotherPurposeError(LookupError):
    """The trust set holds the key a document names, for another purpose than the one the checker checks."""


@dataclass(frozen=True)
class SigningKey:
    """One public key, what it signs, the server it belongs to, its status, and when that status began."""

    key_id: str
    algorithm: Literal["ES256"]
    # The key in SubjectPublicKeyInfo DER form, as Open Policy Agent (OPA) and most libraries read it.
    public_key_der: bytes
    spki_sha256: str
    purpose: KeyPurpose
    server: str
    status: KeyStatus
    valid_from: str
    retired_at: str | None
    revoked_at: str | None
    revocation_reason: str | None

    @property
    def can_sign(self) -> bool:
        """Whether a new bundle or scanner check mapping may be signed with this key."""
        return self.status == "active"

    @property
    def can_verify(self) -> bool:
        """Whether a signature made with this key may be accepted."""
        return self.status != "revoked"


def key_of_purpose(keys: Mapping[str, SigningKey], key_id: str, purpose: KeyPurpose) -> SigningKey:
    """The key ``key_id`` names in the trust set ``keys``, whatever its status, when its purpose is ``purpose``.

    Raises ``KeyNotHeldError`` when ``keys`` holds no such key, ``KeyOfAnotherPurposeError`` when it holds one for
    another purpose.
    """
    key = keys.get(key_id)
    if key is None:
        raise KeyNotHeldError(key_id)
    if key.purpose != purpose:
        raise KeyOfAnotherPurposeError(key_id)
    return key


def key_history_problems(before: SigningKey, after: SigningKey) -> list[str]:
    """Every way ``after`` breaks the history of ``before``, the same key in an earlier version of a trust file: a
    field of ``FIXED_KEY_FIELDS`` changed, a field of ``WRITTEN_ONCE_KEY_FIELDS`` changed once written, or a status
    moved other than forward."""
    problems = [f"{field} changed" for field in FIXED_KEY_FIELDS if getattr(before, field) != getattr(after, field)]
    if before.status != after.status and (before.status, after.status) not in FORWARD_STATUS_MOVES:
        problems.append(f"status moved from {before.status} to {after.status}")
    for field in WRITTEN_ONCE_KEY_FIELDS:
        written = getattr(before, field)
        if written is not None and getattr(after, field) != written:
            problems.append(f"{field} changed after it was written")
    return problems


def server_name(value: Any, where: str) -> str:
    """``value`` as a server's name: a lower-case host name (``SERVER_NAME_PATTERN``) of at most
    ``MAX_SERVER_NAME_LENGTH`` characters."""
    if not isinstance(value, str) or len(value) > MAX_SERVER_NAME_LENGTH or not _SERVER_NAME.fullmatch(value):
        raise TrustFileError(
            f"{where}: must be a lower-case host name of at most {MAX_SERVER_NAME_LENGTH} characters: labels of "
            "letters, digits and '-', not starting or ending with '-', joined by '.'"
        )
    return value


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


def _status_dates(key: SigningKey, where: str) -> None:
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


def _key(entry: Any, where: str, *, development: bool) -> SigningKey:
    if not isinstance(entry, dict) or set(entry) != _FIELDS:
        raise TrustFileError(f"{where}: must have exactly the fields {', '.join(sorted(_FIELDS))}")
    key_id = entry["key_id"]
    if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
        raise TrustFileError(f"{where}.key_id: must be lower-case letters, digits, '.', '_' or '-', at most 128")
    if key_id.startswith(DEVELOPMENT_KEY_PREFIX) != development:
        rule = (
            "only a development key"
            if development
            else f"a development key ({DEVELOPMENT_KEY_PREFIX}…) is not trusted here"
        )
        raise TrustFileError(f"{where}.key_id: {rule}")
    if entry["algorithm"] != "ES256":
        raise TrustFileError(f"{where}.algorithm: must be ES256")
    if not isinstance(entry["purpose"], str) or entry["purpose"] not in _PURPOSES:
        raise TrustFileError(f"{where}.purpose: must be one of {', '.join(sorted(_PURPOSES))}")
    if not isinstance(entry["status"], str) or entry["status"] not in _STATUSES:
        raise TrustFileError(f"{where}.status: must be one of {', '.join(sorted(_STATUSES))}")
    key = SigningKey(
        key_id=key_id,
        algorithm="ES256",
        public_key_der=_public_key(entry, where),
        spki_sha256=entry["spki_sha256"],
        purpose=cast(KeyPurpose, entry["purpose"]),
        server=server_name(entry["server"], f"{where}.server"),
        status=cast(KeyStatus, entry["status"]),
        valid_from=_timestamp(entry["valid_from"], f"{where}.valid_from"),
        retired_at=_optional_timestamp(entry["retired_at"], f"{where}.retired_at"),
        revoked_at=_optional_timestamp(entry["revoked_at"], f"{where}.revoked_at"),
        revocation_reason=entry["revocation_reason"],
    )
    _status_dates(key, where)
    return key


def trust_file_document(raw: bytes, kind: str, fields: tuple[str, ...]) -> dict[str, Any]:
    """The JSON object of a trust file of ``kind``, read strictly, with exactly ``fields`` beside ``apiVersion`` and
    ``kind``; raises ``TrustFileError`` otherwise."""
    try:
        document = strict_json(raw, "a trust file")
    except ValueError as error:
        raise TrustFileError(str(error)) from None
    names = ("apiVersion", "kind", *fields)
    if not isinstance(document, dict) or set(document) != set(names):
        raise TrustFileError(f"must have exactly the fields {', '.join(names[:-1])} and {names[-1]}")
    if document["apiVersion"] != API_VERSION:
        raise TrustFileError(f"apiVersion: must be {API_VERSION}")
    if document["kind"] != kind:
        raise TrustFileError(f"kind: must be {kind}")
    return document


def trust_file_keys(entries: Any, *, development: bool) -> Mapping[str, SigningKey]:
    """The keys of a trust file's ``keys`` list, by key id, read-only: in key-id order, with no key id or public key
    twice; raises ``TrustFileError`` on any broken rule."""
    if not isinstance(entries, list):
        raise TrustFileError("keys: must be a list")
    keys = [_key(entry, f"keys[{index}]", development=development) for index, entry in enumerate(entries)]
    ids = [key.key_id for key in keys]
    if any(earlier >= later for earlier, later in zip(ids, ids[1:], strict=False)):
        raise TrustFileError("keys: must be in key-id order, with no key id twice")
    if len({key.spki_sha256 for key in keys}) != len(keys):
        raise TrustFileError("keys: no public key may appear under two key ids")
    return MappingProxyType({key.key_id: key for key in keys})


def parse_signing_keys(raw: bytes, *, development: bool) -> Mapping[str, SigningKey]:
    """The keys of a trust file, by key id, read-only; raises ``TrustFileError`` on any broken rule.

    ``development`` is true only for a development tool reading its own local file:
    then every key must be a ``dev-`` key, and otherwise none may be. The keys
    are listed in key-id order, and no key id or public key appears twice, so a
    public key has one purpose.
    """
    document = trust_file_document(raw, TRUST_FILE_KIND, ("keys",))
    return trust_file_keys(document["keys"], development=development)


@dataclass(frozen=True)
class TrustFile:
    """A signing keys file as read: its keys by key id, and the digest of its bytes, so the two always describe the
    same file (``read_trust_file``)."""

    keys: Mapping[str, SigningKey]
    file_digest: str


def read_trust_file(raw: bytes, *, development: bool) -> TrustFile:
    """The signing keys file ``raw``, its keys read as ``parse_signing_keys`` reads them, with its digest."""
    return TrustFile(parse_signing_keys(raw, development=development), digest(raw))


_TRUST_FILE: bytes = resources.files("iltero_schemas.trust").joinpath("signing-keys.json").read_bytes()
TRUST_FILE_DIGEST: str = digest(_TRUST_FILE)
SIGNING_KEYS: Mapping[str, SigningKey] = parse_signing_keys(_TRUST_FILE, development=False)
# Iltero's signing keys file shipped with this contract, with its digest.
SHIPPED_TRUST_FILE = TrustFile(SIGNING_KEYS, TRUST_FILE_DIGEST)
