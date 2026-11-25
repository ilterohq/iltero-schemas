"""The scanner verdicts a record decided, by event digest, given only when the files its stages kept give them."""

from __future__ import annotations

import copy

from iltero_schemas.canonical import canonical_bytes, digest
from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.common.event import event_digest
from iltero_schemas.models.common.kept_files import KeptFiles
from iltero_schemas.models.common.scanner_evaluator import ScannerEvaluator
from iltero_schemas.models.iac.scanner_event_digests import scanner_event_digests
from tests.iac.test_models_scanner_results import SCANNED, _tracked_scanned, kept_files
from tests.server_runs import (
    SERVED_NONE,
)


def test_a_record_whose_files_give_its_scanner_verdicts_names_each_scanner_decided_event_by_its_digest() -> None:
    car = CAR.model_validate(copy.deepcopy(SCANNED), context={SKIP_INTEGRITY_CHECKS: True})
    problems, digests = scanner_event_digests(car, KeptFiles(**kept_files(SCANNED)), Stage.PLAN)
    assert problems == []
    expected = {event_digest(event) for event in car.events if isinstance(event.provenance.evaluator, ScannerEvaluator)}
    assert expected and digests == frozenset(expected)


def test_a_record_whose_files_do_not_hold_names_no_scanner_decided_event() -> None:
    car = CAR.model_validate(copy.deepcopy(SCANNED), context={SKIP_INTEGRITY_CHECKS: True})
    files = kept_files(SCANNED)
    files["observations"] = {}
    problems, digests = scanner_event_digests(car, KeptFiles(**files), Stage.PLAN)
    assert problems and digests == frozenset()


def test_a_record_whose_served_exceptions_copy_is_not_given_names_no_scanner_decided_event() -> None:
    record, files = _tracked_scanned()
    car = CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})
    # The copy of the exceptions the server served the run, none in force, as its plan stage names it.
    served = canonical_bytes({**SERVED_NONE, "metadata": {**SERVED_NONE["metadata"], "run_id": record["run"]["id"]}})
    files = {**files, "served_exceptions": {digest(served): served}}
    assert scanner_event_digests(car, KeptFiles(**files), Stage.PLAN)[0] == []
    problems, digests = scanner_event_digests(car, KeptFiles(**{**files, "served_exceptions": {}}), Stage.PLAN)
    assert problems and digests == frozenset()


def test_a_stage_is_decided_from_its_own_files_alone() -> None:
    # The plan stage's files do not hold; another stage is decided without reading them, so it has no problem.
    car = CAR.model_validate(copy.deepcopy(SCANNED), context={SKIP_INTEGRITY_CHECKS: True})
    files = kept_files(SCANNED)
    files["observations"] = {}
    assert scanner_event_digests(car, KeptFiles(**files), Stage.PLAN)[0]
    assert scanner_event_digests(car, KeptFiles(**files), Stage.POST_DEPLOY) == ([], frozenset())
