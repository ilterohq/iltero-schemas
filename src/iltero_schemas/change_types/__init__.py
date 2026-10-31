"""Change types: the kinds of change a record describes, their activities, and each activity's record body.

``CHANGE_TYPES`` and ``ACTIVITIES`` are the registry: a record's ``change`` is
the body of one activity, and the activity's declaration says which stages its
records pass through and holds the rules that compare its body with them.
"""

from iltero_schemas.change_types.activity import (
    Activity,
    ChangeType,
    DocumentName,
    RunType,
)
from iltero_schemas.change_types.iac import IAC_CHANGE, IacChange, PlanRecord
from iltero_schemas.change_types.registry import ACTIVITIES, CHANGE_TYPES
from iltero_schemas.models.change_type import ActivityName, ChangeTypeName

__all__ = [
    "ACTIVITIES",
    "CHANGE_TYPES",
    "IAC_CHANGE",
    "Activity",
    "ActivityName",
    "ChangeType",
    "ChangeTypeName",
    "DocumentName",
    "IacChange",
    "PlanRecord",
    "RunType",
]
