"""The change types: the registry of every change type and activity, and what each activity's declaration names."""

from __future__ import annotations

from typing import get_args

from iltero_schemas.change_types import ACTIVITIES, CHANGE_TYPES, ActivityName, ChangeTypeName
from iltero_schemas.models.change_type import CHANGE_TYPE_OF, CHECKED_CONTENT_KIND_OF


def test_every_change_type_and_activity_the_contract_names_is_registered() -> None:
    assert set(CHANGE_TYPES) == set(get_args(ChangeTypeName))
    assert set(ACTIVITIES) == set(get_args(ActivityName))
    assert all(activity.change_type in CHANGE_TYPES for activity in ACTIVITIES.values())


def test_the_change_type_and_checked_content_of_each_activity_agree_with_its_declaration() -> None:
    assert dict(CHANGE_TYPE_OF) == {name: activity.change_type for name, activity in ACTIVITIES.items()}
    assert set(CHECKED_CONTENT_KIND_OF) == set(ACTIVITIES)
