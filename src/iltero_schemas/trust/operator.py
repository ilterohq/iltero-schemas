"""The keys of a self-hosted server, from its operator's trust file, combined with Iltero's into one trust set.

An operator who runs their own server gives its public keys in an operator trust file (``kind:
OperatorSigningKeys``): the operator's name, the server the keys belong to, and keys in the same shape as Iltero's
signing keys. The tool reads the file's bytes and hands them to ``parse_operator_signing_keys``, which opens no file and
reads no environment; the tool applies ``MAX_OPERATOR_TRUST_FILE_BYTES`` before it reads them, and the parser applies
it too.

``trusted_keys`` combines Iltero's keys with an operator's into the trust set a checker uses. An operator's file
cannot weaken Iltero's keys: it adds keys for its own server, never under an id Iltero reserves
(``ILTERO_KEY_PREFIX``), and it may name one of Iltero's keys only to revoke it. Keys are compared by public key as
well as by id, so a key Iltero lists stays as Iltero lists it, or revoked, under any id. Each key names the server it
belongs to, but the checkers do not tell servers apart: an operator's ``check_definitions`` key verifies a bundle in
any record. The trust data's digest (``trust_data_digest``) a stage records shows which keys were used, and a
verification report names which file listed the key that signed its run statement.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, fields
from types import MappingProxyType
from typing import Any, Literal

from iltero_schemas.canonical.common.encoding import digest, digest_of
from iltero_schemas.models.common.fields import DIGEST_PATTERN
from iltero_schemas.trust.keys import (
    SigningKey,
    TrustFileError,
    key_history_problems,
    server_name,
    trust_file_document,
    trust_file_keys,
)

OPERATOR_TRUST_FILE_KIND = "OperatorSigningKeys"
# The largest operator trust file a tool reads: room for about a hundred keys, far more than one server rotates through.
MAX_OPERATOR_TRUST_FILE_BYTES = 64 * 1024
# The longest operator name: a display name, as long as a server's name may be.
MAX_OPERATOR_NAME_LENGTH = 253
# The key ids Iltero keeps for its own keys: an operator trust file never adds a key under one.
ILTERO_KEY_PREFIX = "iltero-"
# Which file lists a key of the trust set: Iltero's shipped file, or an operator's.
ListedIn = Literal["iltero", "operator"]
_DIGEST = re.compile(DIGEST_PATTERN)


@dataclass(frozen=True)
class OperatorSigningKeys:
    """An operator trust file as read: the operator's name, the server its keys belong to, the keys by key id, and the
    digest of the file's bytes."""

    operator: str
    server: str
    keys: Mapping[str, SigningKey]
    file_digest: str


@dataclass(frozen=True)
class TrustedKey(SigningKey):
    """A key of the trust set a checker uses, with the file that lists it, and whether the operator's file revoked one
    of Iltero's keys."""

    listed_in: ListedIn
    revoked_by_operator: bool


def _operator_name(value: Any) -> str:
    """``value`` as an operator's name: printable text of at most ``MAX_OPERATOR_NAME_LENGTH`` characters, with no
    space at either end."""
    if (
        not isinstance(value, str)
        or not 0 < len(value) <= MAX_OPERATOR_NAME_LENGTH
        or not value.isprintable()
        or value != value.strip()
    ):
        raise TrustFileError(
            f"operator: must be 1 to {MAX_OPERATOR_NAME_LENGTH} printable characters, with no space at either end"
        )
    return value


def parse_operator_signing_keys(raw: bytes) -> OperatorSigningKeys:
    """The operator trust file in ``raw``; raises ``TrustFileError`` on any broken rule.

    The file has exactly ``apiVersion``, ``kind``, ``operator``, ``server`` and ``keys``; its keys follow every rule of
    Iltero's signing keys, and no key is a development (``dev-``) key.
    """
    if len(raw) > MAX_OPERATOR_TRUST_FILE_BYTES:
        raise TrustFileError(f"an operator trust file is at most {MAX_OPERATOR_TRUST_FILE_BYTES} bytes")
    document = trust_file_document(raw, OPERATOR_TRUST_FILE_KIND, ("operator", "server", "keys"))
    return OperatorSigningKeys(
        operator=_operator_name(document["operator"]),
        server=server_name(document["server"], "server"),
        keys=trust_file_keys(document["keys"], development=False),
        file_digest=digest(raw),
    )


def _trusted(key: SigningKey, listed_in: ListedIn, *, revoked_by_operator: bool) -> TrustedKey:
    """``key`` as a key of the trust set, built from the fields of ``SigningKey`` only."""
    values = {field.name: getattr(key, field.name) for field in fields(SigningKey)}
    return TrustedKey(**values, listed_in=listed_in, revoked_by_operator=revoked_by_operator)


def trusted_keys(iltero: Mapping[str, SigningKey], operator: OperatorSigningKeys | None) -> Mapping[str, TrustedKey]:
    """The trust set a checker uses, by key id, read-only: Iltero's keys ``iltero`` and, when given, an operator's.

    Raises ``TrustFileError`` when the operator's file names a server one of Iltero's keys belongs to; adds a key that
    names another server than the file, or whose id starts ``ILTERO_KEY_PREFIX``; names one of Iltero's key ids or
    public keys under another public key or id; or gives one of Iltero's keys anything but its own entry or that entry
    revoked.
    A key the operator revoked stays listed in Iltero's file, with ``revoked_by_operator`` set.
    """
    combined = {key_id: _trusted(key, "iltero", revoked_by_operator=False) for key_id, key in iltero.items()}
    if operator is None:
        return MappingProxyType(combined)
    if operator.server in {key.server for key in iltero.values()}:
        raise TrustFileError("server: names a server that Iltero's own keys belong to")
    public_keys = {key.spki_sha256 for key in iltero.values()}
    for key_id, entry in operator.keys.items():
        named = iltero.get(key_id)
        if named is None and entry.spki_sha256 not in public_keys:
            if key_id.startswith(ILTERO_KEY_PREFIX):
                raise TrustFileError(f"key {key_id}: an id starting {ILTERO_KEY_PREFIX} is kept for Iltero's own keys")
            if entry.server != operator.server:
                raise TrustFileError(f"key {key_id}: names another server than the operator trust file")
            combined[key_id] = _trusted(entry, "operator", revoked_by_operator=False)
            continue
        if named is None or named.spki_sha256 != entry.spki_sha256:
            raise TrustFileError(f"key {key_id}: Iltero's keys hold its id or its public key under another")
        if key_history_problems(named, entry) or entry.status not in (named.status, "revoked"):
            raise TrustFileError(f"key {key_id}: an operator trust file may only revoke one of Iltero's keys")
        if entry.status != named.status:
            combined[key_id] = _trusted(entry, "iltero", revoked_by_operator=True)
    return MappingProxyType(combined)


def trust_data_digest(iltero_file_digest: str, operator_file_digest: str | None) -> str:
    """The digest of the trust data a tool checked against.

    With no operator trust file it is the digest of Iltero's file, ``iltero_file_digest``. With one, it is the digest
    of the canonical JSON (RFC 8785) of the list of the two files' digests, sorted: the digest of
    ``["sha256:<lower>","sha256:<higher>"]``. Raises ``ValueError`` when a digest is not ``sha256:`` and 64
    lowercase hex digits.
    """
    given = [iltero_file_digest] if operator_file_digest is None else [iltero_file_digest, operator_file_digest]
    if not all(_DIGEST.fullmatch(value) for value in given):
        raise ValueError("a trust file's digest is sha256: and 64 lowercase hex digits")
    return iltero_file_digest if operator_file_digest is None else digest_of(sorted(given))
