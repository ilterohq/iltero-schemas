"""The digest of a change: one deployment of the checked content, by its change type, unit and environment.

A unit is planned, approved and applied on its own, so a change is one unit's
change. Its digest is taken over ``{"change_type", "unit", "environment_key",
"checked_content"}``: the checked content is what the change's checks ran on,
as every evaluation names it (``models.checked_content``), such as the unit's
plan with the rule that computed its digest, and the environment key names the
environment it is deployed to, or is null for a change made outside any
environment. An approval binds to this digest, so it counts for that content,
in that unit and environment: a plan that does something else, or the same
plan deployed to another environment, is another change. The digest names no
project or organization, so the server holds an approval to the project it was
given in.
"""

from __future__ import annotations

from collections.abc import Mapping

from iltero_schemas.canonical.encoding import canonical_bytes, digest


def canonical_change_bytes(
    change_type: str, unit: str, environment_key: str | None, checked_content: Mapping[str, str]
) -> bytes:
    """``{"change_type", "unit", "environment_key", "checked_content"}`` as RFC 8785 bytes.

    ``checked_content`` is the checked content as JSON, such as ``{"kind": "plan", "digest", "digest_version",
    "tool"}``.
    """
    return canonical_bytes(
        {
            "change_type": change_type,
            "unit": unit,
            "environment_key": environment_key,
            "checked_content": dict(checked_content),
        }
    )


def change_digest(change_type: str, unit: str, environment_key: str | None, checked_content: Mapping[str, str]) -> str:
    """``sha256:<hex>`` over :func:`canonical_change_bytes`."""
    return digest(canonical_change_bytes(change_type, unit, environment_key, checked_content))
