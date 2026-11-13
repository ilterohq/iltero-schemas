"""The record's evidence register: the files a record's stages and events name that must be entries of it."""

from __future__ import annotations

from typing import TYPE_CHECKING

from iltero_schemas.models.assertion import Stage

if TYPE_CHECKING:
    from iltero_schemas.models.car import CAR


def check_register(car: CAR) -> None:
    """These files that a record's stages and events name are entries of its evidence register: each stage's events file
    and assertion index, by path and digest; each stage's copy of the scanner bindings it used, by path and digest,
    the observations it read from each scanner report, by path, and each report as it kept it, by digest, redacted
    from a file the pipeline gave; every input an event was evaluated over; and what the plan stage redacted, kept as
    an entry the redaction policy ran over. Each scanner file is an entry of its own: neither another scanner file nor
    a stage's events file or assertion index."""
    kept = {(ref.path, ref.digest) for ref in car.evidence_refs}
    paths = {ref.path for ref in car.evidence_refs}
    digests = {ref.digest for ref in car.evidence_refs}
    stage_files = {path for record in car.stages.values() for path in (record.events.path, record.assertions.index)}
    scanner_files: list[str] = []
    first_report: dict[str, tuple[tuple[str, str], str]] = {}
    for stage, record in car.stages.items():
        if (record.events.path, record.events.digest) not in kept:
            raise ValueError(f"the {stage.value} stage's events file is an entry of the evidence register")
        if (record.assertions.index, record.assertions.digest) not in kept:
            raise ValueError(f"the {stage.value} stage's assertion index is an entry of the evidence register")
        if record.scanners is None:
            continue
        bindings = record.scanners.evaluator_binding_set
        if (bindings.copy_path, bindings.digest) not in kept:
            raise ValueError(
                f"the {stage.value} stage's copy of its scanner bindings is an entry of the evidence register"
            )
        scanner_files.append(bindings.copy_path)
        for report in record.scanners.reports:
            if report.observations not in paths:
                raise ValueError(
                    f"the observations the {stage.value} stage read from its {report.tool} report are an entry of the "
                    "evidence register"
                )
            entries = [ref for ref in car.evidence_refs if ref.digest == report.report_digest]
            if not any(ref.source is not None and ref.redaction_policy is not None for ref in entries):
                raise ValueError(
                    f"the {report.tool} report the {stage.value} stage kept is an entry of the evidence register, "
                    "redacted from the file the pipeline gave"
                )
            # One scanner's report given to two stages is kept as the same files; two scanners' never share them.
            tool, kept_files = (report.tool, report.tool_version), [ref.path for ref in entries]
            first = first_report.get(report.report_digest)
            if first is None:
                first_report[report.report_digest] = (tool, report.observations)
                scanner_files += [report.observations, *kept_files]
            elif first[0] != tool:
                scanner_files += [report.observations, *kept_files]
            elif first[1] != report.observations:
                scanner_files.append(report.observations)
    if len(set(scanner_files)) != len(scanner_files) or stage_files & set(scanner_files):
        raise ValueError(
            "each scanner file a stage keeps is an entry of its own, not a file the record names for another part"
        )
    inputs = {e.provenance.input_digest for e in car.events} - {None}
    if not inputs <= digests:
        raise ValueError("the input every event was evaluated over is an entry of the evidence register")
    plan = car.stages.get(Stage.PLAN)
    if plan is not None and not any(
        ref.digest == plan.redaction.input.digest and ref.redaction_policy is not None for ref in car.evidence_refs
    ):
        raise ValueError(
            "what the plan stage redacted is an entry of the evidence register that names the redaction policy"
        )
