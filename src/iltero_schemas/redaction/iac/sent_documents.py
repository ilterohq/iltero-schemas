"""Checking the documents a stage of an IaC change sends with its record against the record's redaction policy.

A stage that reads scanner reports sends the redacted plan, each scanner report it kept and the observations it read
from each (``models.iac.stage_files.sent_documents``). Each was redacted under the policy the record writes out. A
reader rebuilds that policy and, for each document, the marks and anchors the stage redacted it with: those the plan
reader of the record's IaC tool gives for the plan, a report's root or each item of a report that is a list, and none
for observations, which were read from a report already redacted. The anchors come from the contract alone, so every
reader checks a document the same way.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from iltero_schemas.change_types.common.activity import DocumentName
from iltero_schemas.change_types.iac.change import IacChange
from iltero_schemas.models.common.kept_files import KeptFiles
from iltero_schemas.models.common.sent_documents import SentDocumentError, read_sent_document
from iltero_schemas.models.iac.sent_document_limits import SENT_DOCUMENT_LIMITS
from iltero_schemas.models.iac.stage_files import sent_documents
from iltero_schemas.models.iac.tool_names import IacTool
from iltero_schemas.redaction.common.apply import RedactionError
from iltero_schemas.redaction.common.marks import Mark
from iltero_schemas.redaction.common.paths import TreePath
from iltero_schemas.redaction.common.policy import policy_from_document
from iltero_schemas.redaction.common.problems import RedactionProblems, redaction_problems
from iltero_schemas.redaction.iac.plan import PLAN_MARK_READERS

if TYPE_CHECKING:
    from iltero_schemas.models.common.assertion import Stage
    from iltero_schemas.models.common.car import CAR, EvidenceRef

# A kept plan whose own flags the plan reader of the record's IaC tool refuses to read, such as one with a resource that
# names no sensitive values.
MARKS_NOT_READ = "is a plan whose flags for sensitive values its tool's reader refuses to read"
# A kept document nested deeper than its reader, or a check of what its redaction policy would hide, reads.
NESTS_TOO_DEEP = "nests deeper than a check of what its redaction policy would hide reads"


def _report_anchors(document: Any) -> list[TreePath]:
    """Where a report's configured paths are read from: its root, or each item of a report that is a list, as a tool
    that ran several times, such as Checkov once for each framework, writes one item for each run."""
    return [(index,) for index in range(len(document))] if isinstance(document, list) else [()]


def document_marks_and_anchors(name: DocumentName, tool: IacTool, document: Any) -> tuple[list[Mark], list[TreePath]]:
    """The marks and anchors a stage redacted a document of kind ``name`` with, read from the document itself."""
    if name == "redacted_plan":
        return PLAN_MARK_READERS[tool](document)
    if name == "scanner_report":
        return [], _report_anchors(document)
    return [], []


def _marks_and_anchors(car: CAR, name: DocumentName, document: Any) -> tuple[list[Mark], list[TreePath]]:
    if not isinstance(car.change, IacChange):
        raise ValueError("only a record of a change made with an IaC tool sends these documents")
    return document_marks_and_anchors(name, car.change.plan.tool, document)


def _checked(car: CAR, document: Any, marks: list[Mark], anchors: list[TreePath]) -> RedactionProblems:
    return redaction_problems(policy_from_document(car.redaction_policy), document, marks=marks, anchors=anchors)


def sent_document_problems(car: CAR, stage: Stage, entry: EvidenceRef, data: bytes) -> RedactionProblems:
    """What the record's redaction policy would still hide in ``data``, received as the register ``entry`` that
    ``stage`` sends with its record. Raises ``SentDocumentError`` when the entry is not one the stage sends, or the
    bytes are not that entry or lie outside its limits (``read_sent_document``), and ``RedactionError`` for a document
    nested deeper than a check reads, or a plan with a resource that names no sensitive values. Call only on a record
    whose structure holds (``check_structure``)."""
    name = next((name for name, sent in sent_documents(car, stage) if sent == entry), None)
    if name is None:
        raise SentDocumentError("the document is not one the stage sends with its record")
    limits = SENT_DOCUMENT_LIMITS[name]
    document = read_sent_document(data, size_bytes=entry.size_bytes, named_digest=entry.digest, limits=limits)
    try:
        marks, anchors = _marks_and_anchors(car, name, document)
    except RecursionError as error:
        raise RedactionError(f"the document {NESTS_TOO_DEEP}") from error
    return _checked(car, document, marks, anchors)


def _kept(files: KeptFiles, name: DocumentName, entry: EvidenceRef) -> object | None:
    if name == "redacted_plan":
        return files.plans.get(entry.digest)
    if name == "scanner_report":
        return files.reports.get(entry.digest)
    return files.observations.get(entry.path)


def kept_document_redaction_problems(car: CAR, files: KeptFiles) -> list[tuple[str, str]]:
    """For each document a stage sends with its record that ``files`` holds, the register entry it is, when the record's
    redaction policy would still hide a value or a key in it, as (where, what) pairs. A document ``files`` does not hold
    is a problem of the checks that read it; one nested too deep to check, and one whose flags its tool's reader
    refuses, are listed. Call only on a record whose structure holds (``check_structure``)."""
    problems: list[tuple[str, str]] = []
    positions = {id(entry): index for index, entry in enumerate(car.evidence_refs)}
    for stage in car.stages:
        for name, entry in sent_documents(car, stage):
            document = _kept(files, name, entry)
            if document is None:
                continue
            where = f"evidence_refs.{positions[id(entry)]}"
            try:
                marks, anchors = _marks_and_anchors(car, name, document)
            except RecursionError:
                problems.append((where, NESTS_TOO_DEEP))
                continue
            except RedactionError:
                problems.append((where, MARKS_NOT_READ))
                continue
            try:
                found = _checked(car, document, marks, anchors).count
            except (RedactionError, RecursionError):
                problems.append((where, NESTS_TOO_DEEP))
                continue
            if found:
                problems.append((where, "holds a value or a key the record's redaction policy would hide"))
    return problems
