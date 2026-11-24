"""The scanner verdicts a record decided, by the digest of each event, for matching events read apart from the record.

A result a scanner decided counts only when the record of its stage decided it from the files the stage kept:
``scanner_event_digests`` checks one stage's files and, only when they give every verdict of that stage and every served
exception it relies on, gives that stage's scanner-decided events by their digest (``event_digest``). A digest names an
event's content only, not its run: a reader matches it only against events of the same run, unit, stage and attempt as
the record, and counts each digest once. Exceptions from a project's own files are not checked here; a record of a run
the server opened names none (``models.common.provenance``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from iltero_schemas.models.common.event import event_digest
from iltero_schemas.models.common.scanner_evaluator import ScannerEvaluator
from iltero_schemas.models.iac.exception_evidence import served_exception_problems
from iltero_schemas.models.iac.scanner_results import scanner_evidence_problems

if TYPE_CHECKING:
    from iltero_schemas.models.common.assertion import Stage
    from iltero_schemas.models.common.car import CAR
    from iltero_schemas.models.iac.kept_files import KeptFiles


def scanner_event_digests(car: CAR, files: KeptFiles, stage: Stage) -> tuple[list[tuple[str, str]], frozenset[str]]:
    """Every way ``stage``'s scanner verdicts and served exceptions do not follow from ``files``, the files that stage
    kept, as (where, what) pairs, and, when there is none, the digest of each event of ``stage`` a scanner decided; no
    digest at all when there is one, so no result counts on a stage whose files do not hold. Each stage is decided with
    the record sent at that stage, from its own files; the other stages of ``car`` are not read. Call only on a record
    whose structure holds."""
    problems = scanner_evidence_problems(car, files, only=stage) + served_exception_problems(car, files, only=stage)
    if problems:
        return problems, frozenset()
    return [], frozenset(
        event_digest(event)
        for event in car.events
        if event.evaluation.stage is stage and isinstance(event.provenance.evaluator, ScannerEvaluator)
    )
