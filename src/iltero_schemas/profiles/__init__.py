"""The fixed context profiles: which parts of the facts each stage and target provides (see ``stage``)."""

from iltero_schemas.profiles.stage import ALWAYS, PROFILES, Profile, profile_for, reads_server_facts

__all__ = ["ALWAYS", "PROFILES", "Profile", "profile_for", "reads_server_facts"]
