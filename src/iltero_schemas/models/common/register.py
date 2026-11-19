"""The record's evidence register: the files a record's stages and events name that must be entries of it."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from iltero_schemas.canonical.common.encoding import CANONICALIZATION
from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.scanner_evaluator import ScannerEvaluator

if TYPE_CHECKING:
    from iltero_schemas.models.common.car import CAR
    from iltero_schemas.models.common.local_exceptions import LocalExceptionsUsed


def check_register(car: CAR) -> None:
    """These files that a record's stages and events name are entries of its evidence register: each stage's events file
    and assertion index, by path and digest; each stage's copy of each scanner check mapping it used, by path and
    digest, naming the file it was read from; the observations it read from each scanner report, by path, read from
    the file that report was kept from, and each report as it kept it, by digest, collected as that scanner's report
    and redacted from one file the pipeline gave; every input an event was evaluated over; what the plan stage
    redacted, kept as an entry the redaction policy ran over; and each stage's canonical copy of the exceptions the
    server served it. Each scanner file is an entry of its own: neither another scanner file, nor a stage's events file
    or assertion index, nor the input of an evaluation that stands on no scanner's result."""
    kept = {(ref.path, ref.digest) for ref in car.evidence_refs}
    paths = {ref.path for ref in car.evidence_refs}
    digests = {ref.digest for ref in car.evidence_refs}
    stage_files = {path for record in car.stages.values() for path in (record.events.path, record.assertions.index)}
    scanner_files: list[str] = []
    misread: list[tuple[Stage, str]] = []
    scanner_digests: set[str] = set()
    for stage, record in car.stages.items():
        if (record.events.path, record.events.digest) not in kept:
            raise ValueError(f"the {stage.value} stage's events file is an entry of the evidence register")
        events_entries = [ref for ref in car.evidence_refs if ref.path == record.events.path]
        if any(ref.canonicalization != CANONICALIZATION for ref in events_entries):
            raise ValueError(f"the {stage.value} stage's events file is kept as canonical JSON ({CANONICALIZATION})")
        if (record.assertions.index, record.assertions.digest) not in kept:
            raise ValueError(f"the {stage.value} stage's assertion index is an entry of the evidence register")
        if record.scanners is None:
            continue
        for used in record.scanners.scanner_check_mappings:
            if (used.copy_path, used.digest) not in kept:
                raise ValueError(
                    "the evidence register lists the copy of each scanner check mapping "
                    f"the {stage.value} stage applied"
                )
            copy_source = next(
                ref.source for ref in car.evidence_refs if (ref.path, ref.digest) == (used.copy_path, used.digest)
            )
            if (copy_source is None) != (used.file_path is None) or (
                copy_source is not None
                and used.file_path is not None
                and copy_source.name != PurePosixPath(used.file_path).name
            ):
                raise ValueError(
                    "in the evidence register, the copy of a project's scanner check mapping names the file it was "
                    "read from, and the copy of the shipped mapping names no file"
                )
            scanner_files.append(used.copy_path)
        for report in record.scanners.reports:
            if report.observations not in paths:
                raise ValueError(
                    f"the observations the {stage.value} stage read from its {report.tool} report are an entry of the "
                    "evidence register"
                )
            entries = [ref for ref in car.evidence_refs if ref.digest == report.report_digest]
            kept_from = {
                ref.source.digest
                for ref in entries
                if ref.source is not None and ref.redaction_policy is not None and ref.collector.tool == report.tool
            }
            if len(kept_from) != 1:
                raise ValueError(
                    f"the {report.tool} report the {stage.value} stage kept is an entry of the evidence register, "
                    "redacted from the file the pipeline gave"
                )
            observations = [ref for ref in car.evidence_refs if ref.path == report.observations]
            scanner_digests |= {report.report_digest, *(ref.digest for ref in observations)}
            if (
                not misread
                and {ref.source.digest if ref.source is not None else None for ref in observations} != kept_from
            ):
                misread = [(stage, report.tool)]
            scanner_files += [report.observations, *(ref.path for ref in entries)]
        if record.scanners.local_exceptions is not None:
            scanner_files.append(_exceptions_copy(car, stage, record.scanners.local_exceptions))
    # The input of an evaluation that stands on no scanner's result is no scanner's file.
    other_inputs = {e.provenance.input_digest for e in car.events if e.provenance.scanner_checks is None}
    if (
        len(set(scanner_files)) != len(scanner_files)
        or stage_files & set(scanner_files)
        or scanner_digests & other_inputs
    ):
        raise ValueError(
            "each scanner file a stage keeps is an entry of its own, not a file the record names for another part"
        )
    if misread:
        stage, scanner = misread[0]
        raise ValueError(
            f"the observations the {stage.value} stage read from its {scanner} report were read from the file that "
            "report was kept from"
        )
    _check_served_exceptions_copy(car, stage_files | set(scanner_files))
    _check_exceptions_named(car)
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


def _check_served_exceptions_copy(car: CAR, other_files: set[str]) -> None:
    """Each stage's copy of the served exceptions it applied is an entry of the register of its own, kept as canonical
    JSON, from no file the pipeline gave and with nothing redacted."""
    for stage, record in car.stages.items():
        used = record.served_exceptions
        if used is None:
            continue
        entries = [ref for ref in car.evidence_refs if ref.path == used.copy_path]
        if (
            not entries
            or used.copy_path in other_files
            or any(
                ref.digest != used.digest
                or ref.source is not None
                or ref.redaction_policy is not None
                or ref.canonicalization != CANONICALIZATION
                for ref in entries
            )
        ):
            raise ValueError(
                f"the {stage.value} stage's copy of the exceptions the server served it is an entry of the evidence "
                f"register of its own, kept as canonical JSON ({CANONICALIZATION}) and not copied from a file the "
                "pipeline gave"
            )


def _exceptions_copy(car: CAR, stage: Stage, used: LocalExceptionsUsed) -> str:
    """The path of the stage's byte copy of the project's exceptions file, once it is an entry of the register that
    names the file it was copied from, unredacted and as the project wrote it."""
    entries = [ref for ref in car.evidence_refs if (ref.path, ref.digest) == (used.copy_path, used.digest)]
    if not entries or any(
        ref.source is None
        or ref.source.name != PurePosixPath(used.file_path).name
        or ref.source.digest != used.digest
        or ref.redaction_policy is not None
        or ref.canonicalization is not None
        for ref in entries
    ):
        raise ValueError(
            f"the {stage.value} stage's copy of the project's exceptions file is an entry of the evidence register, "
            "copied byte for byte from the file it names"
        )
    return used.copy_path


def _check_exceptions_named(car: CAR) -> None:
    """Each exception a suppressed scanner result names is in the exceptions file its stage applied."""
    for event in car.events:
        evaluator = event.provenance.evaluator
        if not isinstance(evaluator, ScannerEvaluator) or evaluator.local_exception is None:
            continue
        record = car.stages.get(event.evaluation.stage)
        used = record.scanners.local_exceptions if record is not None and record.scanners is not None else None
        if used is None or evaluator.local_exception.file_digest != used.digest:
            raise ValueError(
                "a scanner result names an exception only from the project's exceptions file its stage applied"
            )
