"""The target of each rule a stage evaluated, from the documents the stage kept."""

from __future__ import annotations

from typing import Any

import pytest

from iltero_schemas.canonical import digest_of
from iltero_schemas.models.common.assertion import Stage, ToolSelector
from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.common.event import AssuranceEvent
from iltero_schemas.models.common.kept_files import KeptFiles
from iltero_schemas.models.iac.plan_exclusions import named_resource_types_of_targets
from iltero_schemas.models.iac.stage_assertions import kept_target, stage_targets
from tests.iac.test_models_scanner_results import SCANNED, kept_files

# The policy entry of a rule written by hand in Rego that checks random passwords.
POLICY_ENTRY: dict[str, Any] = {
    "title": "A random password is long",
    "assertion": {"id": "ACME.IAC.RESOURCE.RANDOM.PASSWORD.LONG", "version": "1.0.0"},
    "stage": "plan",
    "target": {
        "kind": "resource",
        "resources": [{"tool": "terraform", "provider": "random", "resource_types": ["random_password"]}],
    },
    "file": "random_password_long.rego",
}


def _hand_written(event: AssuranceEvent, entry: dict[str, Any]) -> AssuranceEvent:
    """``event`` as an evaluation of the rule whose policy entry is ``entry``."""
    assertion = event.assertion.model_copy(
        update={"id": entry["assertion"]["id"], "version": entry["assertion"]["version"], "digest": digest_of(entry)}
    )
    provenance = event.provenance.model_copy(update={"assertion_source": "custom_rego"})
    return event.model_copy(update={"assertion": assertion, "provenance": provenance})


def _files(**assertions: object) -> KeptFiles:
    files = kept_files(SCANNED)
    return KeptFiles(**{**files, "assertions": {**files["assertions"], **assertions}})


def test_a_hand_written_rule_s_target_is_the_one_its_kept_policy_entry_declares() -> None:
    event = _hand_written(CAR.model_validate(SCANNED).events[0], POLICY_ENTRY)
    target = kept_target(event, _files(**{digest_of(POLICY_ENTRY): POLICY_ENTRY}))
    assert target is not None and target.resources is not None and isinstance(target.resources[0], ToolSelector)
    assert named_resource_types_of_targets("terraform", [target]) == {("random", "random_password")}


def test_a_hand_written_rule_whose_policy_entry_is_missing_has_no_target() -> None:
    event = _hand_written(CAR.model_validate(SCANNED).events[0], POLICY_ENTRY)
    assert kept_target(event, _files()) is None


@pytest.mark.parametrize(
    "change",
    [
        {"stage": "post_deploy"},
        {"assertion": {"id": "ACME.IAC.RESOURCE.RANDOM.PASSWORD.SHORT", "version": "1.0.0"}},
        {"assertion": {"id": "ACME.IAC.RESOURCE.RANDOM.PASSWORD.LONG", "version": "2.0.0"}},
    ],
    ids=["another_stage", "another_assertion", "another_version"],
)
def test_a_hand_written_rule_whose_kept_policy_entry_is_of_another_rule_has_no_target(change: dict[str, Any]) -> None:
    event = _hand_written(CAR.model_validate(SCANNED).events[0], POLICY_ENTRY)
    other = {**POLICY_ENTRY, **change}
    named = event.assertion.model_copy(update={"digest": digest_of(other)})
    assert kept_target(event.model_copy(update={"assertion": named}), _files(**{digest_of(other): other})) is None


def test_an_assertion_s_event_never_takes_its_target_from_a_policy_entry() -> None:
    event = _hand_written(CAR.model_validate(SCANNED).events[0], POLICY_ENTRY)
    compiled = event.provenance.model_copy(update={"assertion_source": "local"})
    files = _files(**{digest_of(POLICY_ENTRY): POLICY_ENTRY})
    assert kept_target(event.model_copy(update={"provenance": compiled}), files) is None


def test_every_event_of_a_stage_whose_document_is_not_kept_is_listed() -> None:
    record = CAR.model_validate(SCANNED)
    files = _files()
    found, missing = stage_targets(record, Stage.PLAN, KeptFiles(**{**vars(files), "assertions": {}}))
    assert found == [] and missing == [i for i, e in enumerate(record.events) if e.evaluation.stage is Stage.PLAN]
