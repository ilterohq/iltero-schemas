"""The names of the change types and activities the contract knows.

A **change type** is the kind of thing a change changes; an **activity** is
one kind of work a single record describes. The names stand alone, so every
module that names a change type, from an assertion to a record, uses this one
list (``change_types`` holds what each declares).
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final, Literal

# The change types the contract knows. Anything else is refused.
ChangeTypeName = Literal["iac_change", "image_release"]
# The activities the contract knows, each the name of a record body.
ActivityName = Literal["iac_change", "image_build", "image_deploy"]
# The change type of a change made with an infrastructure-as-code (IaC) tool, whichever tool made it, and the one
# activity it is made of, of the same name.
IAC_CHANGE_TYPE: Final = "iac_change"
IAC_CHANGE_ACTIVITY: Final = "iac_change"
# The change type of a container image released to an environment, its activity that builds the image, and its
# activity that deploys a built image to one environment.
IMAGE_RELEASE_TYPE: Final = "image_release"
IMAGE_BUILD_ACTIVITY: Final = "image_build"
IMAGE_DEPLOY_ACTIVITY: Final = "image_deploy"
# The change type each activity belongs to.
CHANGE_TYPE_OF: Mapping[ActivityName, ChangeTypeName] = MappingProxyType(
    {
        IAC_CHANGE_ACTIVITY: IAC_CHANGE_TYPE,
        IMAGE_BUILD_ACTIVITY: IMAGE_RELEASE_TYPE,
        IMAGE_DEPLOY_ACTIVITY: IMAGE_RELEASE_TYPE,
    }
)
# The kind of content each activity's evaluations check: a plan, or a container image.
CHECKED_CONTENT_KIND_OF: Mapping[ActivityName, Literal["plan", "container_image"]] = MappingProxyType(
    {IAC_CHANGE_ACTIVITY: "plan", IMAGE_BUILD_ACTIVITY: "container_image", IMAGE_DEPLOY_ACTIVITY: "container_image"}
)
