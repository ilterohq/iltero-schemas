"""The fixed context profiles: which parts of the facts each stage and target provides (see ``stage``)."""

from iltero_schemas.profiles.stage import (
    ALWAYS_REQUIRED_PARTS,
    PROFILES,
    Profile,
    profile_for,
    reads_plan,
    reads_server_facts,
)

__all__ = ["ALWAYS_REQUIRED_PARTS", "PROFILES", "Profile", "profile_for", "reads_plan", "reads_server_facts"]
