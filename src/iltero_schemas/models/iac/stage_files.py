"""The files a stage of a change made with an IaC (infrastructure as code) tool sends the server with its record.

A stage that reads scanner reports keeps, in the record's evidence register, the redacted plan the reports were read
against, each report as it kept it and the observations it read from each. In a run the server opened, the stage sends
these files with its record (``named_documents``). Each file is one entry of the register, kept as canonical JSON, so a
reader can check the bytes it receives against the entry's digest; the redacted plan names the redaction policy that
ran over it. A later record of the run still names a stage's files; they are sent with the record of that stage.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from iltero_schemas.canonical.common.encoding import CANONICALIZATION
from iltero_schemas.change_types.common.activity import DocumentName
from iltero_schemas.models.iac.kept_files import MAX_STAGE_SENT_DOCUMENT_BYTES, SENT_DOCUMENT_LIMITS
from iltero_schemas.models.iac.tool_names import PLAN_COLLECTORS, IacTool

if TYPE_CHECKING:
    from iltero_schemas.models.common.assertion import Stage
    from iltero_schemas.models.common.car import CAR, EvidenceRef


def redacted_plan_entry(car: CAR, stage: Stage) -> EvidenceRef | None:
    """The register entry of the redacted plan ``stage``'s scanner reports were read against, the one its scanners
    name; None for a stage that reads no scanner report or names a path the register does not hold."""
    scanners = car.stages[stage].scanners
    if scanners is None:
        return None
    return next((ref for ref in car.evidence_refs if ref.path == scanners.redacted_plan), None)


def sent_documents(car: CAR, stage: Stage) -> list[tuple[DocumentName, EvidenceRef]]:
    """Each file ``stage`` sends with its record, by the name of its kind, in the order it sends them: the redacted
    plan, then each scanner report it kept and the observations it read from it, in the order the stage lists its
    reports."""
    scanners = car.stages[stage].scanners
    if scanners is None:
        return []
    plan = redacted_plan_entry(car, stage)
    sent: list[tuple[DocumentName, EvidenceRef]] = [("redacted_plan", plan)] if plan is not None else []
    for report in scanners.reports:
        sent += [("scanner_report", ref) for ref in _report_entries(car, report.report_digest)]
        sent += [("scanner_observations", ref) for ref in car.evidence_refs if ref.path == report.observations]
    return sent


def stage_file_entries(car: CAR, stage: Stage) -> list[EvidenceRef]:
    """The register entries ``stage`` sends with its record, in the order it sends them (``sent_documents``); none
    for a stage that reads no scanner report. Call only on a record whose stage files hold (``check_stage_files``)."""
    return [ref for _name, ref in sent_documents(car, stage)]


def _report_entries(car: CAR, report_digest: str) -> list[EvidenceRef]:
    return [ref for ref in car.evidence_refs if ref.digest == report_digest]


def check_stage_files(car: CAR, tool: IacTool) -> None:
    """Raise ``ValueError`` unless each stage that reads scanner reports names each file it would send once, under one
    name: the redacted plan its scanners name, an entry the plan's collector wrote that names the redaction policy, and
    one entry of each report and of its observations, each kept as canonical JSON. In a run the server opened, such a
    stage exempts no path from its redaction policy, since the files it sends were redacted under it."""
    for stage, record in car.stages.items():
        if record.scanners is None:
            continue
        where = f"the {stage.value} stage"
        plan = redacted_plan_entry(car, stage)
        if plan is None or plan.collector.tool != PLAN_COLLECTORS[tool]:
            raise ValueError(
                f"the redacted plan {where}'s scanner reports were read against is an entry of the evidence register "
                "that the plan's collector wrote"
            )
        if plan.redaction_policy is None:
            raise ValueError(
                f"the redacted plan {where}'s scanner reports were read against names the redaction policy that ran "
                "over it"
            )
        for report in record.scanners.reports:
            if len(_report_entries(car, report.report_digest)) != 1:
                raise ValueError(f"{where} keeps one entry of its {report.tool} report")
        if car.governance.run_opened_by == "server" and record.redaction.exempted:
            raise ValueError(
                f"{where} of a run the server opened, which reads scanner reports, exempts no path from its redaction "
                "policy"
            )
        entries = stage_file_entries(car, stage)
        if len({ref.ref_id for ref in entries}) != len(entries):
            raise ValueError(f"{where} sends each file with its record once, under one name")
        if any(ref.canonicalization != CANONICALIZATION for ref in entries):
            raise ValueError(f"{where} keeps the files it sends with its record as canonical JSON ({CANONICALIZATION})")


def sent_documents_within_limits(car: CAR, stage: Stage) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """The ``ref_id`` of each file ``stage`` sends with its record, in the order it sends them, split into those within
    the limits (``SENT_DOCUMENT_LIMITS``, ``MAX_STAGE_SENT_DOCUMENT_BYTES``) and those over one, decided from the sizes
    the register names so the writer and every reader decide the same: a file larger than its own limit is over it, and
    so is a file that would take the files sent before it past the total. Values are counted only when a file is read
    (``read_sent_document``), so a writer reads each file it sends that way first. The stage's scanner verdicts rest on
    every file it names, so one over a limit leaves them resting on a file a reader was not sent. Call only on a record
    whose stage files hold (``check_stage_files``)."""
    sent: list[str] = []
    over: list[str] = []
    total = 0
    for name, ref in sent_documents(car, stage):
        if (
            ref.size_bytes > SENT_DOCUMENT_LIMITS[name].max_bytes
            or total + ref.size_bytes > MAX_STAGE_SENT_DOCUMENT_BYTES
        ):
            over.append(ref.ref_id)
            continue
        total += ref.size_bytes
        sent.append(ref.ref_id)
    return tuple(sent), tuple(over)
