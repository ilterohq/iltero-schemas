"""A plan's digest, by a rule for each IaC tool: the same value wherever it is computed.

Each rule drops what describes how the plan was rendered rather than what
it will change, canonicalizes the rest and digests it. A document that
holds a plan digest names the plan's tool, which picks the rule, and the
rule's version (``digest_version``, from ``PLAN_DIGEST_VERSIONS``). A new
tool adds its entry to each table below.

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
PLAN_EXCLUDED_TOP_LEVEL_KEYS: Mapping[IacTool, frozenset[str]] = MappingProxyType(
    {
        "terraform": frozenset(
            {"timestamp", "terraform_version", "format_version", "prior_state", "resource_drift", "relevant_attributes"}
        )
    }
)


def check_plan_digest_version(tool: IacTool, version: str) -> None:
    """Raise ``ValueError`` unless ``version`` is the version of ``tool``'s rule."""
    if version != PLAN_DIGEST_VERSIONS.get(tool):
        raise ValueError(f"digest_version {version!r} is not the version of the {tool} plan digest rule")


def canonical_plan_bytes(tool: IacTool, plan: dict[str, Any]) -> bytes:
    """``tool``'s plan without its rendering metadata, as RFC 8785 bytes; ``ValueError`` for a tool with no rule."""
    excluded = PLAN_EXCLUDED_TOP_LEVEL_KEYS.get(tool)
    if excluded is None:
        raise ValueError(f"no plan digest rule for {tool!r}")
    return canonical_bytes({key: value for key, value in plan.items() if key not in excluded})


def plan_digest(tool: IacTool, plan: dict[str, Any]) -> str:
    """``sha256:<hex>`` over :func:`canonical_plan_bytes`."""
    return digest(canonical_plan_bytes(tool, plan))
