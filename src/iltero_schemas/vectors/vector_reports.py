"""The verification reports of the conformance vectors: what ``verifier.verification_report`` gives a record of the
vectors, read with its kept files and, when a source names one, a run statement.

A source names its record as ``{"vector": "<change type>/<record>.json"}``, a record of ``vectors/records``;
``{"case": "<name>"}``, the record of a ``records_valid`` case of the source's change type; or
``{"run_statement_case": "<change type>/<name>"}``, the record of a case of ``run_statements_valid`` or
``run_statements_invalid``, read with that case's statement, trust set and paths before packaging. A source whose
record is a vector may name its statement as ``"run_statement": {"vector": "<change type>/<record>.json"}``, the
statement of ``vectors/run_statements`` of that record, or ``"operator_trust_file": true``, for a reader also given the
sample operator's trust file ``signing_keys/operator.json``, whose trust set is then the keys of
``signing_keys/development.json`` and that file. Every report is written at ``REPORT_VERIFIED_AT`` by version
``REPORT_VERIFIER_VERSION`` of the verifier. The reader's trust set is the vectors' development keys
(``run_statement_vector_keys``, or the trust set a case names), and the trust data it holds is that of
``signing_keys/development.json`` alone, the trust data the vector records name: the run statement keys are kept in a
file of their own so that signing the statements again never changes the records.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from iltero_schemas.canonical.common.encoding import digest
from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.common.kept_files import KeptFiles
from iltero_schemas.models.common.verification import VerificationReport
from iltero_schemas.trust.keys import SigningKey, TrustFile, read_trust_file
from iltero_schemas.trust.operator import OperatorSigningKeys, parse_operator_signing_keys
from iltero_schemas.trust.signature_check import SignatureCheck
from iltero_schemas.vectors.kept_files import kept_files_of, kept_files_of_case
from iltero_schemas.vectors.paths import VECTORS
from iltero_schemas.vectors.reader_files import case_reader_kept_files, reader_kept_files
from iltero_schemas.vectors.record_cases import case_document, valid_case
from iltero_schemas.vectors.vector_run_statements import (
    case_record,
    run_statement_trust_sets,
    run_statement_vector_keys,
)
from iltero_schemas.vectors.vector_signing_keys import VECTOR_SIGNING_KEYS_FILE
from iltero_schemas.verifier.report import verification_report

# When every report of the vectors was written, by the verifier's clock, and by which version of it.
REPORT_VERIFIED_AT = "2026-09-22T13:10:00.000Z"
REPORT_VERIFIER_VERSION = "0.1.0"
# The folders that hold run statement cases.
RUN_STATEMENT_CASE_FOLDERS = ("run_statements_valid", "run_statements_invalid")
# The not-reviewed commit's record: a run the server opened whose pre-deploy stage kept a commit not reviewed.
NOT_REVIEWED_CASE = "iac_record_of_a_run_the_server_opened_keeping_its_commit_review_without_a_commit_review_check"
# Each report of ``vectors/reports``, by its path from that folder, and its source.
REPORT_VECTORS: Mapping[str, Mapping[str, Any]] = {
    "iac/verification_report.json": {"record": {"vector": "iac/local_run.json"}},
    "iac/verification_report_commit_not_reviewed.json": {"record": {"case": NOT_REVIEWED_CASE}},
    "iac/verification_report_tracked_run_without_its_run_statement.json": {
        "record": {"vector": "iac/tracked_run_deployed.json"}
    },
    "iac/verification_report_tracked_run_with_its_run_statement.json": {
        "record": {"vector": "iac/tracked_run_deployed.json"},
        "run_statement": {"vector": "iac/tracked_run_deployed.json"},
    },
    "iac/verification_report_packaged_record_with_its_run_statement.json": {
        "record": {"run_statement_case": "iac/packaged_record_against_its_statement"}
    },
    "iac/verification_report_run_statement_signed_with_a_revoked_key.json": {
        "record": {"run_statement_case": "iac/statement_signed_with_a_revoked_key"}
    },
    "iac/verification_report_record_the_server_refused.json": {
        "record": {"run_statement_case": "iac/statement_listing_the_record_as_refused"}
    },
    "iac/verification_report_run_statement_signing_other_approvals.json": {
        "record": {"run_statement_case": "iac/statement_whose_approvals_digest_differs"}
    },
    "iac/verification_report_run_statement_signing_parts_the_record_keeps_no_copy_of.json": {
        "record": {"run_statement_case": "iac/statement_signing_parts_the_record_keeps_no_copy_of"}
    },
    "image/verification_report_build.json": {"record": {"vector": "image/local_run_build.json"}},
    "image/verification_report_tracked_run_deploy_with_its_run_statement.json": {
        "record": {"vector": "image/tracked_run_deploy_rolled_out.json"},
        "run_statement": {"vector": "image/tracked_run_deploy_rolled_out.json"},
    },
}


@dataclass(frozen=True)
class ReportSource:
    """What a report of the vectors is written from: the record, the files it kept as a reader gives them, its paths
    before packaging (None for a record not packaged), the statement's envelope (None when none is given) and the
    reader's trust set: Iltero's keys, and the operator's trust file when the reader is given one."""

    record: CAR
    files: KeptFiles
    unpackaged_paths: Mapping[str, str] | None
    statement: bytes | None
    iltero: TrustFile
    operator: OperatorSigningKeys | None


def vector_reader_trust_file(keys: Mapping[str, SigningKey]) -> TrustFile:
    """The trust file a reader of the vectors holds as Iltero's: ``keys`` (the development keys, with the run statement
    keys of ``signing_keys/run_statements.json`` for a reader of a statement) and the digest of
    ``signing_keys/development.json``, the trust data every vector record's stages name. The two files are kept apart
    so that signing the statements again never changes the records; a real reader's file is one file
    (``trust.read_trust_file``)."""
    return TrustFile(keys, digest(VECTOR_SIGNING_KEYS_FILE.read_bytes()))


def run_statement_case(path: str) -> dict[str, Any]:
    """The run statement case ``<change type>/<name>``, of ``run_statements_valid`` or ``run_statements_invalid``."""
    change_type, name = path.split("/")
    for folder in RUN_STATEMENT_CASE_FOLDERS:
        cases = json.loads((VECTORS / folder / change_type / "cases.json").read_text(encoding="utf-8"))
        found: dict[str, Any] | None = next((case for case in cases if case["name"] == name), None)
        if found is not None:
            return found
    raise KeyError(f"the vectors hold no run statement case {path}")


def _statement_case_source(path: str) -> ReportSource:
    """What the report of the record of the run statement case ``path`` is written from, read with its statement."""
    case = run_statement_case(path)
    record = case_record(case)
    files = reader_kept_files(record.model_dump(mode="json", by_alias=True), kept_files_of(case["record"]))
    envelope = json.dumps(case["envelope"]).encode("utf-8")
    trust = run_statement_trust_sets(run_statement_vector_keys())[case["trust_set"]]
    return ReportSource(record, files, case.get("unpackaged_paths"), envelope, vector_reader_trust_file(trust), None)


def report_source(change_type: str, source: Mapping[str, Any]) -> ReportSource:
    """What the report of ``source``, a source of ``change_type`` the module describes, is written from."""
    named = source["record"]
    if "run_statement_case" in named:
        return _statement_case_source(named["run_statement_case"])
    if "case" in named:
        case = valid_case(change_type, named["case"])
        document = case_document(case)
        files = case_reader_kept_files(document, kept_files_of_case(case))
    else:
        document = json.loads((VECTORS / "records" / named["vector"]).read_text(encoding="utf-8"))
        files = reader_kept_files(document, kept_files_of(named["vector"]))
    given = source.get("run_statement")
    statement = None if given is None else (VECTORS / "run_statements" / given["vector"]).read_bytes()
    record = CAR.model_validate(document)
    if source.get("operator_trust_file"):
        operator = parse_operator_signing_keys((VECTORS / "signing_keys" / "operator.json").read_bytes())
        development = read_trust_file(VECTOR_SIGNING_KEYS_FILE.read_bytes(), development=True)
        return ReportSource(record, files, None, statement, development, operator)
    return ReportSource(record, files, None, statement, vector_reader_trust_file(run_statement_vector_keys()), None)


def vector_report(change_type: str, source: Mapping[str, Any], signature_check: SignatureCheck) -> VerificationReport:
    """The verification report of ``source``, a source of ``change_type``, checking signatures with
    ``signature_check``; the reader's own checks of the vector records hold."""
    given = report_source(change_type, source)
    return verification_report(
        given.record,
        given.files,
        reader_checks_hold=True,
        unpackaged_paths=given.unpackaged_paths,
        statement=given.statement,
        iltero=given.iltero,
        operator=given.operator,
        signature_check=signature_check,
        verifier_version=REPORT_VERIFIER_VERSION,
        verified_at=REPORT_VERIFIED_AT,
    )
