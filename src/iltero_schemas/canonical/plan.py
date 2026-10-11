"""The digest of a plan: the same bytes wherever it is computed, by a rule each IaC tool has.

Each tool's rule removes what describes the rendering of a plan rather than
what the plan will change, canonicalizes the rest and digests it. A
document that holds a plan digest also names the tool, which chooses the
rule; ``digest_version`` names the rule's version. A new tool adds its
entry to each table below.

Terraform: ``terraform show -json`` renders a saved plan. A few top-level
keys describe the rendering or the walk that produced it — when it was
rendered, by which Terraform, the state it started from, which attributes
the graph walk touched — and would make two renderings of the same change
differ. They are dropped; the rest is canonicalized (keys sorted, arrays
kept in Terraform's order) and digested.

The Iltero CLI computes this from the plan it evaluates and again from the
plan the apply used; the two must match. The server records both the
value and the version but cannot recompute it: what it receives is the
redacted artifact, whose own digest is a different value.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from iltero_schemas.canonical.encoding import canonical_bytes, digest
from iltero_schemas.models.iac import IacTool

# The version of each tool's rule; it moves when the bytes the rule produces change.
PLAN_DIGEST_VERSIONS: Mapping[IacTool, str] = MappingProxyType({"terraform": "1"})
# Removed at the top level only; a same-named key deeper in the plan is content.
EXCLUDED_TOP_LEVEL_KEYS: Mapping[IacTool, frozenset[str]] = MappingProxyType(
    {
        "terraform": frozenset(
            {"timestamp", "terraform_version", "format_version", "prior_state", "resource_drift", "relevant_attributes"}
        )
    }
)


def canonical_plan_bytes(tool: IacTool, plan: dict[str, Any]) -> bytes:
    """``tool``'s plan without its rendering metadata, as RFC 8785 bytes."""
    excluded = EXCLUDED_TOP_LEVEL_KEYS[tool]
    return canonical_bytes({key: value for key, value in plan.items() if key not in excluded})


def plan_digest(tool: IacTool, plan: dict[str, Any]) -> str:
    """``sha256:<hex>`` over :func:`canonical_plan_bytes`."""
    return digest(canonical_plan_bytes(tool, plan))
