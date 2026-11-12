"""The fixed context profiles: which parts of the facts each stage and target provides (see ``stage``)."""

from iltero_schemas.profiles.stage import (
    ALWAYS_REQUIRED_PARTS,
    PROFILES,
    Profile,
    profile_for,
    reads_checked_content,
    reads_part,
    reads_server_facts,
    roots_for,
)

__all__ = [
    "ALWAYS_REQUIRED_PARTS",
    "PROFILES",
    "Profile",
    "profile_for",
    "reads_part",
    "reads_checked_content",
    "reads_server_facts",
    "roots_for",
]
