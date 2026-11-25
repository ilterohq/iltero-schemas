"""Building the payload a server signs when a run ends, and the digests of the parts it served each stage.

The server's signer calls ``run_statement_payload`` with what it read of the run, and signs the result's
``signing_input``; it never signs a payload it was handed. The digest of each served part a record keeps a copy of is
``served_part_digest`` over the part as the record keeps it: the canonical JSON (RFC 8785) of that JSON value, the same
bytes whoever computes them. The server keeps the apply job's facts as a document, not as a digest, so its signer
computes their digest with ``apply_job_facts_digest`` over that document.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from iltero_schemas.canonical.common.encoding import canonical_bytes, digest, digest_of
from iltero_schemas.models.common.run_statement import (
    RUN_STATEMENT_PREDICATE_TYPE,
    STATEMENT_TYPE,
    RunClosePredicate,
    RunStatement,
    StatementSubject,
)
from iltero_schemas.models.iac.apply_job_facts import ApplyJobFacts
from iltero_schemas.statement.envelope import check_payload_size, dsse_signing_input


@dataclass(frozen=True)
class RunStatementPayload:
    """A run statement ready to sign: the statement, its payload bytes, its digest, and the bytes the key signs."""

    statement: RunStatement
    payload: bytes
    digest: str
    signing_input: bytes


def statement_payload(statement: RunStatement) -> bytes:
    """The payload of ``statement``: the canonical JSON (RFC 8785) of its JSON form."""
    return canonical_bytes(statement.model_dump(mode="json", by_alias=True))


def run_statement_payload(subjects: Sequence[StatementSubject], predicate: RunClosePredicate) -> RunStatementPayload:
    """The run statement of ``subjects``, the accepted records, and ``predicate``, as the bytes to sign.

    Raises ``pydantic.ValidationError`` when the two do not make a run statement, and ``RunStatementError``
    (``too_large``) when its envelope would be larger than a reader reads.
    """
    statement = RunStatement.model_validate(
        {
            "_type": STATEMENT_TYPE,
            "subject": [subject.model_dump(mode="json") for subject in subjects],
            "predicateType": RUN_STATEMENT_PREDICATE_TYPE,
            "predicate": predicate.model_dump(mode="json", by_alias=True),
        }
    )
    payload = statement_payload(statement)
    check_payload_size(payload)
    return RunStatementPayload(statement, payload, digest(payload), dsse_signing_input(payload))


def served_part_digest(part: Any) -> str:
    """The digest of a served part, ``part`` being the JSON value a record keeps a copy of: a stage's list of
    approvals or its commit review."""
    return digest_of(part)


def apply_job_facts_digest(facts: ApplyJobFacts) -> str:
    """The digest of the apply job's facts: of the canonical JSON (RFC 8785) of the facts document, as the pre-deploy
    stage's record keeps it under ``apply_job_facts``."""
    return digest_of(facts.model_dump(mode="json", by_alias=True))
