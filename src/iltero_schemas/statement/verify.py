"""Verifying a run statement: its envelope, its key, its signature and its payload.

``verify_run_statement`` reads the envelope strictly, takes the key its signature names from the trust set, for the
``run_statement`` purpose only, refuses a revoked key (a retired key still verifies what it signed), verifies the
signature with the reader's ``SignatureCheck``, and only then reads the payload: a run statement, read strictly, whose
bytes are exactly its canonical JSON (RFC 8785), so no two readers read different content, naming as the server that
opened the run the server the key belongs to, and a run that ended while the key was valid: no earlier than its status
began and, for a retired key, no later than it was retired (a signature carries no trusted time, so this is a check of
consistency only). Whether the statement is
the one of a given record is ``differences.compare_record``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Generic, TypeVar, cast

from pydantic import ValidationError

from iltero_schemas.canonical.common.encoding import digest
from iltero_schemas.models.common.fields import nanoseconds_between
from iltero_schemas.models.common.run_statement import RunStatement
from iltero_schemas.models.common.strict_json import strict_json
from iltero_schemas.statement.envelope import dsse_signing_input, read_envelope
from iltero_schemas.statement.payload import statement_payload
from iltero_schemas.statement.reasons import (
    KEY_NOT_TRUSTED,
    KEY_NOT_VALID_AT_THE_RUN_END,
    KEY_OF_ANOTHER_PURPOSE,
    KEY_OF_ANOTHER_SERVER,
    KEY_REVOKED,
    PAYLOAD_NOT_A_RUN_STATEMENT,
    PAYLOAD_NOT_CANONICAL,
    SIGNATURE_INVALID,
    RunStatementError,
)
from iltero_schemas.trust import KeyNotHeldError, KeyOfAnotherPurposeError, SignatureCheck, SigningKey, key_of_purpose

Key = TypeVar("Key", bound=SigningKey)


@dataclass(frozen=True)
class VerifiedRunStatement(Generic[Key]):
    """A run statement whose signature verified: the statement, its payload bytes, its digest (the sha256 digest of
    the payload), and the key of the trust set that signed it."""

    statement: RunStatement
    payload: bytes
    digest: str
    key: Key


def read_run_statement(payload: bytes) -> RunStatement:
    """The run statement ``payload`` holds, which must be exactly its canonical JSON; raises ``RunStatementError``
    otherwise. It verifies nothing: a statement is relied on only through ``verify_run_statement``."""
    try:
        statement = RunStatement.model_validate(strict_json(payload, "a run statement's payload"))
        canonical = statement_payload(statement)
    except (ValueError, ValidationError, UnicodeError, RecursionError):
        # Whatever fails while reading the payload, such as a lone surrogate with no canonical form, refuses it.
        raise RunStatementError(
            PAYLOAD_NOT_A_RUN_STATEMENT, "the envelope's payload is not a run statement this contract reads"
        ) from None
    if canonical != payload:
        raise RunStatementError(
            PAYLOAD_NOT_CANONICAL, "the envelope's payload is not the canonical JSON (RFC 8785) of its statement"
        )
    return statement


def verify_run_statement(
    data: bytes, keys: Mapping[str, Key], signature_check: SignatureCheck
) -> VerifiedRunStatement[Key]:
    """The run statement in the envelope ``data``, verified against the trust set ``keys`` (``SIGNING_KEYS``, or
    ``trust.trusted_keys`` with an operator's file) with ``signature_check``.

    Raises ``RunStatementError`` with the reason code of the first rule that fails.
    """
    envelope = read_envelope(data)
    try:
        key = cast(Key, key_of_purpose(keys, envelope.key_id, "run_statement"))
    except KeyNotHeldError:
        raise RunStatementError(KEY_NOT_TRUSTED, "the run statement's key is not one the trust set holds") from None
    except KeyOfAnotherPurposeError:
        raise RunStatementError(
            KEY_OF_ANOTHER_PURPOSE, "the run statement's key is trusted for another purpose than run statements"
        ) from None
    if not key.can_verify:
        raise RunStatementError(KEY_REVOKED, "the run statement's key is revoked, so nothing it signed is trusted")
    if not signature_check(key.public_key_der, dsse_signing_input(envelope.payload), envelope.signature):
        raise RunStatementError(SIGNATURE_INVALID, "the run statement's signature does not verify with its key")
    statement = read_run_statement(envelope.payload)
    run = statement.predicate.run
    if run.server != key.server:
        raise RunStatementError(
            KEY_OF_ANOTHER_SERVER, "the run statement's key belongs to another server than the one that opened the run"
        )
    if nanoseconds_between(key.valid_from, run.ended_at) < 0 or (
        key.retired_at is not None and nanoseconds_between(run.ended_at, key.retired_at) < 0
    ):
        raise RunStatementError(
            KEY_NOT_VALID_AT_THE_RUN_END,
            "the run statement says the run ended before its key's status began or after its key was retired",
        )
    return VerifiedRunStatement(statement, envelope.payload, digest(envelope.payload), key)
