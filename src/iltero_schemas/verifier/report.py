"""The verification report of one record: the one function a verifier calls.

``verification_report`` takes a record whose structure holds, the files its stages kept, whether the reader's own
checks of it held, the run statement it was given (the envelope's bytes, or None), the trust set (Iltero's keys and,
when the reader was given one, an operator's trust file) and the reader's signature check, and gives the report. It is
pure: it opens no file, reads no clock or environment, and holds no cryptography.

It works out, in this order:

1. integrity: the reader's own checks (that every file the record cites is present with its digest and size, and the
   record is its own canonical form, among them) and every check of ``change_types.common.kept_file_problems``. When
   either finds a problem, the integrity failed and no other property is decided;
2. the run statement: verified against the trust set (``statement.verify_run_statement``), then compared with the
   record (``statement.compare_record``). Bytes that are not a run statement are refused with ``RunStatementError``;
   a statement that does not verify, or does not hold for the record, is a problem the report lists;
3. the trust level (``models.common.report_trust``), and the trust root when the statement verified: its key, the file
   that lists it, the operator's name for an operator's key, and the digest of the trust data the reader holds;
4. each property: from the record alone (``record_results``), upgraded where a statement that holds covers it, or
   failed where the statement shows otherwise (``statement_results``). ``bundle_signature`` is verified when every stage
   that names the server's bundle read it back under the trust set, which the integrity checks require, and names the
   trust data the reader holds; a stage that names other trust data fails it.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from iltero_schemas.canonical.common.encoding import digest_of
from iltero_schemas.change_types.common.kept_file_problems import kept_file_problems
from iltero_schemas.models.common.base import API_VERSION
from iltero_schemas.models.common.report_trust import (
    AssignedTrustLevel,
    PartNotCompared,
    ReportedRunEnd,
    RunStatementFindings,
    StatementFinding,
    StatementTrustRoot,
)
from iltero_schemas.models.common.run_statement import ACCEPTED_LISTINGS
from iltero_schemas.models.common.verification import KIND, Properties, PropertyResult, VerificationReport
from iltero_schemas.models.common.verification_states import (
    BUNDLE_SIGNATURE_CHECKED,
    COULD_NOT_DECIDE,
    INTEGRITY_FAILED,
    REFUSED_BY_SERVER,
)
from iltero_schemas.statement.differences import RecordComparison, compare_record
from iltero_schemas.statement.reasons import (
    ANOTHER_RUN,
    NOT_A_RUN_STATEMENT,
    RECORD_REFUSED_BY_THE_SERVER,
    RunStatementError,
)
from iltero_schemas.statement.verify import VerifiedRunStatement, verify_run_statement
from iltero_schemas.trust.operator import OperatorSigningKeys, TrustedKey, trust_data_digest, trusted_keys
from iltero_schemas.verifier.record_results import record_results, result
from iltero_schemas.verifier.statement_results import failed_by_differences, held_by_run_statement, refusal_detail

if TYPE_CHECKING:
    from iltero_schemas.models.common.car import CAR
    from iltero_schemas.models.common.kept_files import KeptFiles
    from iltero_schemas.trust.keys import TrustFile
    from iltero_schemas.trust.signature_check import SignatureCheck

# The name a verification report gives its verifier.
VERIFIER_NAME = "iltero"


def _findings(
    car: CAR,
    statement: bytes,
    keys: Mapping[str, TrustedKey],
    signature_check: SignatureCheck,
    unpackaged_paths: Mapping[str, str] | None,
) -> tuple[RunStatementFindings, VerifiedRunStatement[TrustedKey] | None, RecordComparison | None]:
    """What reading ``statement`` with ``car`` found, the statement when it verified, and the comparison."""
    try:
        verified = verify_run_statement(statement, keys, signature_check)
    except RunStatementError as error:
        if error.reason in NOT_A_RUN_STATEMENT:
            raise
        problem = StatementFinding(reason=error.reason, sentence=str(error))
        findings = RunStatementFindings(
            digest=None, listed_as=None, run=None, problems=[problem], notes=[], not_compared=[]
        )
        return findings, None, None
    comparison = compare_record(car, verified, keys, unpackaged_paths)
    predicate = verified.statement.predicate
    run = ReportedRunEnd(
        ending=predicate.run.ending,
        ending_reason=predicate.run.ending_reason,
        ended_at=predicate.run.ended_at,
        unanswered_results=len(predicate.gaps.unanswered_results),
        stages_never_accepted=len(predicate.gaps.stages_never_accepted),
    )
    # A statement of another run says nothing of this record's run, its ending included.
    of_another_run = any(found.reason == ANOTHER_RUN for found in comparison.differences)
    findings = RunStatementFindings(
        digest=verified.digest,
        listed_as=comparison.listed_as,
        run=None if of_another_run else run,
        problems=[
            StatementFinding(reason=found.reason, sentence=found.problem)
            for found in comparison.differences
            if found.reason != RECORD_REFUSED_BY_THE_SERVER
        ],
        notes=[StatementFinding(reason=note.reason, sentence=note.problem) for note in comparison.notes],
        not_compared=[
            PartNotCompared.model_validate({"stage": part.stage, "part": part.part}) for part in comparison.not_compared
        ],
    )
    return findings, verified, comparison


def _trust_level(car: CAR, integrity_holds: bool, findings: RunStatementFindings | None) -> AssignedTrustLevel:
    """The trust level of the record, by the first reason that holds."""
    if not integrity_holds:
        reason = "integrity_failed"
    elif findings is None:
        reason = "no_statement_given" if car.run.opened_by == "server" else "run_opened_locally"
    elif findings.listed_as == "refused":
        reason = "refused_by_server"
    elif findings.problems or findings.listed_as not in ACCEPTED_LISTINGS:
        reason = "run_statement_does_not_hold"
    else:
        return AssignedTrustLevel(level="policy_enforced", reason="run_statement")
    return AssignedTrustLevel(level="self_attested", reason=reason)


def _bundle_signature(car: CAR, held_trust_data: str) -> PropertyResult:
    """``bundle_signature`` of a record whose integrity holds, so every served bundle its stages kept read back under
    the trust set: failed for the first stage that names other trust data than the reader holds."""
    served = [
        (stage.value, kept.execution.bundle)
        for stage, kept in car.stages.items()
        if kept.execution.bundle is not None and kept.execution.bundle.kind == "server"
    ]
    if not served:
        return result("not_performed", "local_assertions")
    other = [(name, bundle.trust_data_digest) for name, bundle in served if bundle.trust_data_digest != held_trust_data]
    if other:
        name, named = other[0]
        detail = (
            f"the {name} stage checked its bundle against the trust data {named}, and the reader holds "
            f"{held_trust_data}"
        )
        return result("failed", "trust_data_differs", detail)
    return result(*BUNDLE_SIGNATURE_CHECKED)


def _properties(
    car: CAR,
    files: KeptFiles,
    *,
    finished: bool,
    level: AssignedTrustLevel,
    held_trust_data: str,
    verified: VerifiedRunStatement[TrustedKey] | None,
    comparison: RecordComparison | None,
) -> Properties:
    """The properties of a record whose integrity holds."""
    found: dict[str, PropertyResult] = {
        "integrity": result("claimed_by_record", "file_digests"),
        "bundle_signature": _bundle_signature(car, held_trust_data),
        **record_results(car, files, finished=finished),
    }
    if verified is None or comparison is None:
        return Properties.model_validate(found)
    if level.reason == "refused_by_server":
        found["integrity"] = result(*REFUSED_BY_SERVER, refusal_detail(verified.statement, comparison.record_digest))
    if level.level == "policy_enforced":
        found = held_by_run_statement(car, files, found, verified.statement, comparison)
    else:
        found.update(failed_by_differences(comparison))
    return Properties.model_validate(found)


def verification_report(
    car: CAR,
    files: KeptFiles,
    *,
    reader_checks_hold: bool,
    unpackaged_paths: Mapping[str, str] | None,
    statement: bytes | None,
    iltero: TrustFile,
    operator: OperatorSigningKeys | None,
    signature_check: SignatureCheck,
    verifier_version: str,
    verified_at: str,
) -> VerificationReport:
    """The verification report of ``car``, written by version ``verifier_version`` of the verifier at ``verified_at``,
    by its own clock.

    ``files`` are the files its stages kept (``KeptFiles``). ``reader_checks_hold`` says the reader's own checks of the
    record, which need the files it cites and this function cannot make, found nothing. ``unpackaged_paths`` is given
    exactly when ``car`` is a packaged record (``statement.package_record``), and so also marks the record as finished:
    a stage it lacks will never be reported. ``statement`` is the run statement's envelope, as read, or None when none
    was given. ``iltero`` is Iltero's signing keys file, its keys and digest together (``trust.SHIPPED_TRUST_FILE``),
    and ``operator`` the operator's trust file the reader was given, or None. ``signature_check`` verifies an ES256
    signature.

    Raises ``RunStatementError`` when ``statement`` is not a run statement (a reason of
    ``statement.NOT_A_RUN_STATEMENT``), ``TrustFileError`` when the operator's file cannot be combined with Iltero's,
    and ``PackagedRecordError`` when ``unpackaged_paths`` do not make the record ``car`` was packaged from.
    """
    keys = trusted_keys(iltero.keys, operator)
    held_trust_data = trust_data_digest(iltero.file_digest, None if operator is None else operator.file_digest)
    integrity_holds = reader_checks_hold and not kept_file_problems(car, files, keys, signature_check)
    findings, verified, comparison = (
        (None, None, None) if statement is None else _findings(car, statement, keys, signature_check, unpackaged_paths)
    )
    level = _trust_level(car, integrity_holds, findings)
    # A packaged record is finished, and so is the record a statement that holds names as its unit's subject: the run
    # ended, so a stage the record lacks will never be reported.
    finished = unpackaged_paths is not None or (
        level.level == "policy_enforced" and findings is not None and findings.listed_as == "subject"
    )
    if integrity_holds:
        properties = _properties(
            car,
            files,
            finished=finished,
            level=level,
            held_trust_data=held_trust_data,
            verified=verified,
            comparison=comparison,
        )
    else:
        undecided = {name: result(*COULD_NOT_DECIDE) for name in Properties.model_fields}
        properties = Properties.model_validate({**undecided, "integrity": result(*INTEGRITY_FAILED)})
    root = None
    if verified is not None:
        key = verified.key
        root = StatementTrustRoot(
            key_id=key.key_id,
            listed_in=key.listed_in,
            operator=operator.operator if key.listed_in == "operator" and operator is not None else None,
            trust_data_digest=held_trust_data,
        )
    return VerificationReport.model_validate(
        {
            "apiVersion": API_VERSION,
            "kind": KIND,
            "metadata": {"verifier": {"name": VERIFIER_NAME, "version": verifier_version}, "verified_at": verified_at},
            "record": {"uuid": car.metadata.uuid, "digest": digest_of(car.model_dump(mode="json", by_alias=True))},
            "trust_level": level,
            "trust_root": root,
            "run_statement": findings,
            "stage_trust_data_digests": {
                stage: None if kept.execution.bundle is None else kept.execution.bundle.trust_data_digest
                for stage, kept in car.stages.items()
            },
            "properties": properties,
        }
    )
