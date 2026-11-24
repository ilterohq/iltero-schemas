"""Which plan digest a record of a change made with an IaC tool names, by who opened the run."""

from __future__ import annotations

import copy
import dataclasses
import json
from typing import Any

import pytest

from iltero_schemas.canonical.iac.plan import redacted_plan_digest_of_kept
from iltero_schemas.change_types.iac.change import IacChange
from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.iac.kept_files import KeptFiles
from iltero_schemas.models.iac.plan_digests import check_plan_digest_form, kept_plan_digest_problems
from tests.conftest import VECTORS
from tests.records import kept_files_by_digest

_READER = {SKIP_INTEGRITY_CHECKS: True}


def _record(name: str) -> dict[str, Any]:
    document: dict[str, Any] = json.loads((VECTORS / "records" / f"{name}.json").read_text(encoding="utf-8"))
    return document


def _change(car: CAR) -> IacChange:
    assert isinstance(car.change, IacChange)
    return car.change


def _plans(name: str) -> KeptFiles:
    """The plans the record ``name`` kept, by the digest its register names each by."""
    record = _record(name)
    kept = kept_files_by_digest(name)
    plans = {
        ref["digest"]: json.loads(kept[ref["digest"]])
        for ref in record["evidence_refs"]
        if ref["collector"]["tool"] == "terraform_plan" and ref["digest"] in kept
    }
    return KeptFiles(
        scanner_check_mappings={},
        observations={},
        reports={},
        plans=plans,
        assertions={},
        local_exceptions={},
        served_exceptions={},
        inputs={},
        identities={},
        served_bundles={},
    )


@pytest.mark.parametrize("name", ["iac/local_run_deployed", "iac/governed_run_deployed"])
def test_every_plan_digest_a_record_names_has_the_form_of_who_opened_its_run(name: str) -> None:
    car = CAR.model_validate(_record(name))
    check_plan_digest_form(car, _change(car))


def test_a_record_of_a_run_the_tool_opened_names_its_plans_by_the_digest_of_the_redacted_plan_it_keeps() -> None:
    files = _plans("iac/local_run_deployed")
    (kept,) = files.plans.values()
    assert isinstance(kept, dict)
    car = CAR.model_validate(_record("iac/local_run_deployed"))
    assert _change(car).plan.digest == redacted_plan_digest_of_kept("terraform", kept)
    assert kept_plan_digest_problems(car, _change(car), files) == []


def test_a_plan_digest_that_is_not_the_digest_of_the_kept_redacted_plan_is_listed() -> None:
    files = _plans("iac/local_run_deployed")
    (key,) = files.plans
    edited = copy.deepcopy(files.plans[key])
    assert isinstance(edited, dict)
    edited["planned_values"] = {"edited": True}
    car = CAR.model_validate(_record("iac/local_run_deployed"))
    changed = dataclasses.replace(files, plans={key: edited})
    what = "is not the digest of a redacted plan the record keeps, among the files given"
    assert kept_plan_digest_problems(car, _change(car), changed) == [
        ("change.plan.digest", what),
        ("change.deployment.plan.digest", what),
    ]


def test_a_record_of_a_run_the_tool_opened_whose_kept_plan_is_not_given_is_listed() -> None:
    files = _plans("iac/local_run_deployed")
    car = CAR.model_validate(_record("iac/local_run_deployed"))
    problems = kept_plan_digest_problems(car, _change(car), dataclasses.replace(files, plans={}))
    assert [where for where, _what in problems] == ["change.plan.digest", "change.deployment.plan.digest"]


def test_no_reader_recomputes_a_keyed_plan_digest() -> None:
    car = CAR.model_validate(_record("iac/governed_run_deployed"), context=_READER)
    files = _plans("iac/local_run_deployed")
    assert kept_plan_digest_problems(car, _change(car), dataclasses.replace(files, plans={})) == []


def test_a_given_plan_that_is_not_the_file_the_register_names_is_not_used() -> None:
    files = _plans("iac/local_run_deployed")
    (key,) = files.plans
    other = {"resource_changes": [], "planned_values": {"other": True}}
    car = CAR.model_validate(_record("iac/local_run_deployed"))
    change = _change(car)
    # The record names the other plan's digest, and the other plan is given under the register's digest.
    claimed = change.model_copy(
        update={"plan": change.plan.model_copy(update={"digest": redacted_plan_digest_of_kept("terraform", other)})}
    )
    problems = kept_plan_digest_problems(car, claimed, dataclasses.replace(files, plans={key: other}))
    assert [where for where, _what in problems] == ["change.plan.digest", "change.deployment.plan.digest"]


def test_a_given_plan_that_cannot_be_read_is_listed_and_never_raises() -> None:
    files = _plans("iac/local_run_deployed")
    (key,) = files.plans
    unreadable = {"resource_changes": [], "count": 2**60}
    car = CAR.model_validate(_record("iac/local_run_deployed"))
    problems = kept_plan_digest_problems(car, _change(car), dataclasses.replace(files, plans={key: unreadable}))
    assert [where for where, _what in problems] == ["change.plan.digest", "change.deployment.plan.digest"]


def test_a_kept_plan_that_is_the_registers_file_but_not_the_applied_plan_lists_the_applied_plan() -> None:
    name = "iac/local_run_scanned_then_another_plan_applied"
    car = CAR.model_validate(_record(name))
    files = _plans(name)
    evaluated = car.stages[Stage.PLAN].scanners
    assert evaluated is not None and len(files.plans) == 2
    assert kept_plan_digest_problems(car, _change(car), files) == []
    only_evaluated = {
        digest: plan
        for digest, plan in files.plans.items()
        if evaluated.redacted_plan.endswith(digest[len("sha256:") :])
    }
    assert kept_plan_digest_problems(car, _change(car), dataclasses.replace(files, plans=only_evaluated)) == [
        (
            "change.deployment.plan.digest",
            "is not the digest of a redacted plan the record keeps, among the files given",
        )
    ]
