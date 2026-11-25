"""The change types: the registry of every change type and activity, and what each activity's declaration names."""

from __future__ import annotations

import json
from typing import get_args

from iltero_schemas.change_types import ACTIVITIES, CHANGE_TYPES, ActivityName, ChangeTypeName
from iltero_schemas.change_types.iac.change import IacChange
from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.common.change_type import CHANGE_TYPE_OF, CHECKED_CONTENT_KIND_OF
from tests.conftest import VECTORS


def test_every_change_type_and_activity_the_contract_names_is_registered() -> None:
    assert set(CHANGE_TYPES) == set(get_args(ChangeTypeName))
    assert set(ACTIVITIES) == set(get_args(ActivityName))
    assert all(activity.change_type in CHANGE_TYPES for activity in ACTIVITIES.values())


def test_the_change_type_and_checked_content_of_each_activity_agree_with_its_declaration() -> None:
    assert dict(CHANGE_TYPE_OF) == {name: activity.change_type for name, activity in ACTIVITIES.items()}
    assert set(CHECKED_CONTENT_KIND_OF) == set(ACTIVITIES)


def test_only_an_infrastructure_changes_pre_deploy_inputs_carry_a_part_of_the_record() -> None:
    record = CAR.model_validate(
        json.loads((VECTORS / "records" / "iac" / "tracked_run_deployed.json").read_text(encoding="utf-8"))
    )
    assert isinstance(record.change, IacChange)
    for name, activity in ACTIVITIES.items():
        for stage in Stage:
            parts = activity.input_parts_of_the_record(record, stage)
            if name == "iac_change" and stage is Stage.PRE_DEPLOY:
                assert parts == {"replan_check": record.change.replan_check}
            else:
                assert parts == {}
