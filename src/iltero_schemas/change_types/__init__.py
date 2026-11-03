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
from iltero_schemas.change_types.iac import IAC_CHANGE, IacChange, PlanRecord, not_supported_by
from iltero_schemas.change_types.image import (
    IMAGE_BUILD,
    AttestationRef,
    BuildCommit,
    ImageBuild,
    ImageRef,
    ReportRef,
    ScanCoverage,
    TagResolution,
    check_attestation_outcome,
    check_build_metadata,
    scan_coverage,
)
from iltero_schemas.change_types.image_deploy import IMAGE_DEPLOY, ImageDeploy
from iltero_schemas.change_types.registry import ACTIVITIES, CHANGE_TYPES
from iltero_schemas.models.change_type import ActivityName, ChangeTypeName

__all__ = [
    "ACTIVITIES",
    "CHANGE_TYPES",
    "IAC_CHANGE",
    "IMAGE_BUILD",
    "IMAGE_DEPLOY",
    "Activity",
    "ActivityName",
    "AttestationRef",
    "BuildCommit",
    "ChangeType",
    "ChangeTypeName",
    "DocumentName",
    "IacChange",
    "ImageBuild",
    "ImageDeploy",
    "ImageRef",
    "PlanRecord",
    "ReportRef",
    "RunType",
    "ScanCoverage",
    "TagResolution",
    "check_attestation_outcome",
    "check_build_metadata",
    "not_supported_by",
    "scan_coverage",
]
