"""The continuous integration (CI) systems the contract names.

A CI system runs a pipeline's jobs. Every place in the contract that names one
uses this list, so adding a CI system is a change in one place.
"""

from __future__ import annotations

from typing import Literal, get_args

# The CI systems a document may name; a new CI system adds its name here.
CiSystem = Literal["github_actions"]
CI_SYSTEMS: tuple[str, ...] = get_args(CiSystem)
