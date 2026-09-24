"""The digest of a Terraform plan: the same bytes wherever it is computed.

``terraform show -json`` renders a saved plan. A few top-level keys describe
the rendering or the walk that produced it rather than what the plan will
change — when it was rendered, by which Terraform, the state it started
from, which attributes the graph walk touched — and would make two renderings
of the same change differ. They are dropped; the rest is canonicalized (keys
sorted, arrays kept in Terraform's order) and digested.

The Iltero CLI computes this from the plan it evaluates and again from the
plan the apply used; the two must match. Iltero Compass records both the
value and the version but cannot recompute it: what it receives is the
redacted artifact, whose own digest is a different value.
"""

from __future__ import annotations

from typing import Any

from iltero_schemas.canonical.encoding import canonical_bytes, digest

# The first public version of this rule; bumped when the bytes change.
PLAN_DIGEST_VERSION = "1"
# Removed at the top level only; a same-named key deeper in the plan is content.
EXCLUDED_TOP_LEVEL_KEYS = frozenset(
    {"timestamp", "terraform_version", "format_version", "prior_state", "resource_drift", "relevant_attributes"}
)


def canonical_plan_bytes(plan: dict[str, Any]) -> bytes:
    """The plan without its rendering metadata, as RFC 8785 bytes."""
    return canonical_bytes({key: value for key, value in plan.items() if key not in EXCLUDED_TOP_LEVEL_KEYS})


def plan_digest(plan: dict[str, Any]) -> str:
    """``sha256:<hex>`` over :func:`canonical_plan_bytes`."""
    return digest(canonical_plan_bytes(plan))
