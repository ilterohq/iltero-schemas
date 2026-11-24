"""The re-plan check: its differences, totals and deposed keys, when a record or an input names it, how its time is
read, and the status its built-in gives."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.change_types.iac.apply_job import replan_check_status
from iltero_schemas.models.common.facts import ServerFactsUnavailable
from iltero_schemas.models.iac.apply_job_facts import ApplyJobFacts
from iltero_schemas.models.iac.replan_check import (
    COUNT_NOT_LISTED,
    DEPOSED_KEY_SHAPE,
    INPUT_REPLAN_OF_ANOTHER_RUN,
    LATER_JOB_NAMES_ITS_REPLAN,
    NOT_SORTED,
    ONE_JOB_NAMES_NO_REPLAN,
    TOTALS,
    ReplanCheck,
    ReplanNotCompared,
    check_input_replan,
    check_replan_presence,
    read_no_later_than,
)
from tests.conftest import VECTORS

CONTEXT: dict[str, Any] = json.loads(
    (VECTORS / "contexts" / "iac" / "pre_deploy_apply_in_a_later_job.json").read_text(encoding="utf-8")
)
REPLAN: dict[str, Any] = CONTEXT["replan_check"]
LATER_JOB = ApplyJobFacts.model_validate(CONTEXT["apply_job_facts"])
ONE_JOB = ApplyJobFacts.model_validate(
    {
        **CONTEXT["apply_job_facts"],
        "flow": "plan_and_apply_in_one_job",
        "received_plan_file_digest": None,
        "rendered_plan": None,
    }
)
MARKER = ServerFactsUnavailable.model_validate({"__unknown": True, "reason": "server_facts_unavailable"})
NOT_COMPARED = ReplanNotCompared(outcome="not_compared")


def _difference(address: Any, kind: str, deposed: str | None = None) -> dict[str, Any]:
    return {"address": address, "deposed_key": deposed, "difference": kind}


def _replan(**changes: Any) -> dict[str, Any]:
    replan = copy.deepcopy(REPLAN)
    replan.update(changes)
    if "differences" in changes and "differences_count" not in changes:
        replan["differences_count"] = len(changes["differences"])
    return replan


REDACTED = {"__redacted": True, "present": True, "reason": "deny_key", "type": "string"}


def test_a_replan_lists_plain_addresses_first_by_address_then_redacted_ones_by_kind() -> None:
    ReplanCheck.model_validate(
        _replan(
            evaluated_plan_resources=4,
            replan_resources=2,
            differences=[
                _difference("aws_db_instance.a", "actions_changed"),
                _difference("aws_db_instance.b", "removed"),
                _difference(REDACTED, "actions_changed"),
                _difference(REDACTED, "removed"),
            ],
        )
    )
    for differences in (
        [_difference("aws_db_instance.b", "removed"), _difference("aws_db_instance.a", "actions_changed")],
        [_difference(REDACTED, "removed"), _difference("aws_db_instance.a", "actions_changed")],
        [_difference("aws_db_instance.a", "removed"), _difference("aws_db_instance.a", "actions_changed")],
    ):
        with pytest.raises(ValidationError, match=NOT_SORTED):
            ReplanCheck.model_validate(_replan(differences=differences))


def test_a_replan_counts_its_differences() -> None:
    with pytest.raises(ValidationError, match=COUNT_NOT_LISTED):
        ReplanCheck.model_validate(_replan(differences_count=1))


@pytest.mark.parametrize(
    ("evaluated", "replanned", "differences"),
    [
        (2, 2, [_difference("a.x", "added")]),
        (2, 1, [_difference("a.x", "removed"), _difference("a.y", "removed"), _difference("a.z", "removed")]),
        (1, 1, [_difference("a.x", "actions_changed"), _difference("a.y", "actions_changed")]),
    ],
)
def test_a_replan_whose_differences_do_not_fit_its_totals_is_refused(
    evaluated: int, replanned: int, differences: list[dict[str, Any]]
) -> None:
    with pytest.raises(ValidationError, match=TOTALS):
        ReplanCheck.model_validate(
            _replan(evaluated_plan_resources=evaluated, replan_resources=replanned, differences=differences)
        )


def test_a_replan_names_a_deposed_key_in_its_tools_shape() -> None:
    ReplanCheck.model_validate(_replan(differences=[_difference("a.x", "actions_changed", "1a2b3c4d")]))
    with pytest.raises(ValidationError, match=DEPOSED_KEY_SHAPE):
        ReplanCheck.model_validate(_replan(differences=[_difference("a.x", "actions_changed", "not-a-key")]))


def test_a_later_job_names_its_replan_check_and_a_one_job_run_names_none() -> None:
    replan = ReplanCheck.model_validate(REPLAN)
    check_replan_presence(LATER_JOB, replan)
    check_replan_presence(LATER_JOB, NOT_COMPARED)
    check_replan_presence(ONE_JOB, None)
    check_replan_presence(MARKER, replan)
    check_replan_presence(MARKER, None)
    with pytest.raises(ValueError, match=LATER_JOB_NAMES_ITS_REPLAN):
        check_replan_presence(LATER_JOB, None)
    with pytest.raises(ValueError, match=ONE_JOB_NAMES_NO_REPLAN):
        check_replan_presence(ONE_JOB, NOT_COMPARED)


def test_an_inputs_replan_check_is_for_its_run_change_and_tool() -> None:
    replan = ReplanCheck.model_validate(REPLAN)
    run, change = CONTEXT["run"]["id"], CONTEXT["change"]["digest"]
    check_input_replan(LATER_JOB, replan, run, change, "terraform")
    check_input_replan(LATER_JOB, NOT_COMPARED, None, None, None)
    for other in ((None, change, "terraform"), (run, "sha256:" + "6" * 64, "terraform"), (run, change, None)):
        with pytest.raises(ValueError, match=INPUT_REPLAN_OF_ANOTHER_RUN):
            check_input_replan(LATER_JOB, replan, *other)


def test_a_replan_time_is_read_no_later_than_an_event_at_its_own_precision() -> None:
    assert read_no_later_than("2026-09-22T00:05:00Z", "2026-09-22T00:05:00.900Z")
    assert not read_no_later_than("2026-09-22T00:05:01Z", "2026-09-22T00:05:00.900Z")
    assert read_no_later_than("2026-09-22T00:05:00.900Z", "2026-09-22T00:05:00.900Z")
    assert not read_no_later_than("2026-09-22T00:05:00.901Z", "2026-09-22T00:05:00.900Z")


def test_the_replan_check_status_follows_the_facts_and_the_replan() -> None:
    same = ReplanCheck.model_validate(REPLAN)
    other = ReplanCheck.model_validate(_replan(differences=[_difference("a.x", "actions_changed")]))
    assert replan_check_status(LATER_JOB, same) == "pass"
    assert replan_check_status(LATER_JOB, other) == "fail"
    assert replan_check_status(LATER_JOB, NOT_COMPARED) == "unknown"
    assert replan_check_status(ONE_JOB, None) == "not_applicable"
    assert replan_check_status(MARKER, same) == "unknown"
