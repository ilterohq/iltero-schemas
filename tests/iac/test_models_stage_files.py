"""The files a stage of a change made with an IaC tool sends the server with its record."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from iltero_schemas.change_types.common.registry import ACTIVITIES
from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.common.redaction import ExemptedPath
from iltero_schemas.models.iac.sent_document_limits import MAX_STAGE_SENT_DOCUMENT_BYTES, SENT_DOCUMENT_LIMITS
from iltero_schemas.models.iac.stage_files import check_stage_files, sent_documents_within_limits, stage_file_entries
from tests.conftest import VECTORS
from tests.records import (
    ran_by_the_cli,
)
from tests.server_runs import (
    served,
)

SCANNED: dict[str, Any] = json.loads(
    (VECTORS / "records" / "iac" / "local_run_scanned.json").read_text(encoding="utf-8")
)


def _car(document: dict[str, Any]) -> CAR:
    return CAR.model_validate(document, context={SKIP_INTEGRITY_CHECKS: True})


def _tracked_scanned() -> CAR:
    """The scanned record as a record of a run the server opened, with reports the Iltero CLI ran."""
    document = served(copy.deepcopy(SCANNED))
    ran_by_the_cli(document)
    return _car(document)


def test_a_stage_of_a_run_the_server_opened_sends_its_redacted_plan_then_each_report_and_its_observations() -> None:
    car = _tracked_scanned()
    named = ACTIVITIES["iac_change"].named_documents(car)
    assert list(named) == [Stage.PLAN]
    scanners = car.stages[Stage.PLAN].scanners
    assert scanners is not None
    by_ref = {ref.ref_id: ref for ref in car.evidence_refs}
    (plan,) = named[Stage.PLAN]["redacted_plan"]
    assert by_ref[plan].collector.tool == "terraform_plan"
    reports, observations = named[Stage.PLAN]["scanner_report"], named[Stage.PLAN]["scanner_observations"]
    assert [by_ref[ref].digest for ref in reports] == [report.report_digest for report in scanners.reports]
    assert [by_ref[ref].path for ref in observations] == [report.observations for report in scanners.reports]
    assert [ref.ref_id for ref in stage_file_entries(car, Stage.PLAN)] == [
        plan,
        *(ref for pair in zip(reports, observations, strict=True) for ref in pair),
    ]


def test_a_run_the_tool_opened_sends_no_file_beyond_the_required_ones() -> None:
    assert ACTIVITIES["iac_change"].named_documents(_car(copy.deepcopy(SCANNED))) == {}


def test_a_record_with_no_scanner_report_sends_no_file_beyond_the_required_ones() -> None:
    record = json.loads((VECTORS / "records" / "iac" / "local_run.json").read_text(encoding="utf-8"))
    assert ACTIVITIES["iac_change"].named_documents(_car(record)) == {}


def test_a_stage_sends_each_file_once_under_one_name() -> None:
    car = _car(copy.deepcopy(SCANNED))
    scanners = car.stages[Stage.PLAN].scanners
    assert scanners is not None
    plan = next(ref for ref in car.evidence_refs if ref.path == scanners.redacted_plan)
    # A report whose observations are the redacted plan's entry: one file under two names. Built without the record's
    # checks, which already refuse observations that are not of the report, so the rule is called on its own.
    report = scanners.reports[0].model_copy(update={"observations": plan.path})
    record = car.stages[Stage.PLAN].model_copy(
        update={"scanners": scanners.model_copy(update={"reports": [report, *scanners.reports[1:]]})}
    )
    changed = car.model_copy(update={"stages": {**car.stages, Stage.PLAN: record}})
    with pytest.raises(ValueError, match="sends each file with its record once, under one name"):
        check_stage_files(changed, "terraform")


def test_a_scanning_stage_of_a_run_the_server_opened_lets_no_path_through_its_redaction_policy() -> None:
    car = _tracked_scanned()
    record = car.stages[Stage.PLAN]
    allowed = record.redaction.model_copy(
        update={"exempted": [ExemptedPath.model_validate({"path": ["a"], "reason": "it is public"})]}
    )
    changed = car.model_copy(
        update={"stages": {**car.stages, Stage.PLAN: record.model_copy(update={"redaction": allowed})}}
    )
    with pytest.raises(ValueError, match="which reads scanner reports, exempts no path from its redaction policy"):
        check_stage_files(changed, "terraform")
    local = _car(copy.deepcopy(SCANNED))
    local_record = local.stages[Stage.PLAN]
    check_stage_files(
        local.model_copy(
            update={"stages": {**local.stages, Stage.PLAN: local_record.model_copy(update={"redaction": allowed})}}
        ),
        "terraform",
    )


def test_a_stage_sends_its_files_in_order_and_counts_as_over_a_limit_each_that_does_not_fit() -> None:
    car = _car(copy.deepcopy(SCANNED))
    order = [ref.ref_id for ref in stage_file_entries(car, Stage.PLAN)]
    assert sent_documents_within_limits(car, Stage.PLAN) == (tuple(order), ())
    plan = next(ref for ref in car.evidence_refs if ref.ref_id == order[0])
    too_large = plan.model_copy(update={"size_bytes": SENT_DOCUMENT_LIMITS["redacted_plan"].max_bytes + 1})
    over_plan = car.model_copy(update={"evidence_refs": [too_large if r is plan else r for r in car.evidence_refs]})
    assert sent_documents_within_limits(over_plan, Stage.PLAN) == (tuple(order[1:]), (order[0],))
    # Each file within its own limit, but together past the total: a plan of 5 MiB and four files of 2 MiB come to
    # 13 MiB, so the last, which would take them past 12 MiB, is over.
    mib = 1024 * 1024
    sizes = dict(zip(order, [5 * mib, 2 * mib, 2 * mib, 2 * mib, 2 * mib], strict=True))
    sized = [
        r.model_copy(update={"size_bytes": sizes[r.ref_id]}) if r.ref_id in sizes else r for r in car.evidence_refs
    ]
    assert sum(sizes.values()) > MAX_STAGE_SENT_DOCUMENT_BYTES
    assert sent_documents_within_limits(car.model_copy(update={"evidence_refs": sized}), Stage.PLAN) == (
        tuple(order[:4]),
        (order[4],),
    )


def test_a_stage_that_reads_no_scanner_report_sends_nothing_beyond_its_record() -> None:
    record = json.loads((VECTORS / "records" / "iac" / "local_run.json").read_text(encoding="utf-8"))
    assert sent_documents_within_limits(_car(record), Stage.PLAN) == ((), ())
