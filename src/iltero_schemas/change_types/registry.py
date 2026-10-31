"""Every change type the contract knows, and every activity of each, by name."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from iltero_schemas.change_types.activity import Activity, ChangeType
from iltero_schemas.change_types.iac import IAC_CHANGE
from iltero_schemas.models.change_type import IAC_CHANGE_TYPE, ActivityName, ChangeTypeName

CHANGE_TYPES: Mapping[ChangeTypeName, ChangeType] = MappingProxyType(
    {IAC_CHANGE_TYPE: ChangeType(name=IAC_CHANGE_TYPE, activities=(IAC_CHANGE,))}
)
ACTIVITIES: Mapping[ActivityName, Activity] = MappingProxyType(
    {activity.name: activity for change_type in CHANGE_TYPES.values() for activity in change_type.activities}
)
