"""A plan's digest, by a rule for each IaC tool.

Each rule drops what describes how the plan was rendered rather than what
it will change, and canonicalizes the rest. A document that holds a plan
digest names the plan's tool, which picks the rule, and the rule's version
(``digest_version``).

Terraform: ``terraform show -json`` renders a saved plan. A few top-level
keys describe the rendering or the walk that produced it — when it was
rendered, by which Terraform, the state it started from, which attributes
the graph walk touched — and would make two renderings of the same change
differ. They are dropped; the rest is canonicalized (keys sorted, arrays
kept in Terraform's order).

Plan digests are keyed per run. In a run the server opened, a plan digest
is keyed with the run's digest key (``keyed_plan_digest``, versions from
``KEYED_PLAN_DIGEST_VERSIONS``): the Iltero CLI computes it from the plan it
evaluates and again from the plan the apply used, and no other program
recomputes it. In a run the tool opened, there is no key: a plan digest is
the digest of the plan as the record's redaction policy leaves it
(``redacted_plan_digest_of_kept``, versions from
``REDACTED_PLAN_DIGEST_VERSIONS``), which any reader recomputes from the
redacted plan the record keeps. Each table gives its own version values, so
a tool and a version name one rule.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from iltero_schemas.canonical.common.digest_versions import check_digest_version
from iltero_schemas.canonical.common.encoding import canonical_bytes, digest_of
from iltero_schemas.canonical.common.run_digest_key import (
    KEYED_PLAN_DIGEST_RULE,
    REDACTED_PLAN_DIGEST_RULE,
    RunDigestKey,
    keyed_digest,
)
from iltero_schemas.models.iac.tool_names import IacTool

# The version of each tool's keyed rule; it moves when the bytes the rule produces change.
KEYED_PLAN_DIGEST_VERSIONS: Mapping[IacTool, str] = MappingProxyType({"terraform": "1"})
# The version of each tool's rule over the redacted plan; it moves too when the redaction rules change what they hide.
REDACTED_PLAN_DIGEST_VERSIONS: Mapping[IacTool, str] = MappingProxyType({"terraform": "redacted-1"})
# Removed at the top level only; a same-named key deeper in the plan is content.
PLAN_EXCLUDED_TOP_LEVEL_KEYS: Mapping[IacTool, frozenset[str]] = MappingProxyType(
    {
        "terraform": frozenset(
            {"timestamp", "terraform_version", "format_version", "prior_state", "resource_drift", "relevant_attributes"}
        )
    }
)


def check_plan_digest_version(tool: IacTool, version: str, plan_digest: str) -> None:
    """Raise ``ValueError`` unless ``version`` is the version of ``tool``'s rule that ``plan_digest`` is made under:
    the keyed rule for a keyed digest, the rule over the redacted plan for any other."""
    check_digest_version("plan", KEYED_PLAN_DIGEST_VERSIONS, REDACTED_PLAN_DIGEST_VERSIONS, tool, version, plan_digest)


def _without_rendering(tool: IacTool, plan: dict[str, Any]) -> dict[str, Any]:
    """``tool``'s plan without its rendering metadata; ``ValueError`` for a tool with no rule."""
    excluded = PLAN_EXCLUDED_TOP_LEVEL_KEYS.get(tool)
    if excluded is None:
        raise ValueError("no plan digest rule for this tool")
    return {key: value for key, value in plan.items() if key not in excluded}


def canonical_plan_bytes(tool: IacTool, plan: dict[str, Any]) -> bytes:
    """``tool``'s plan without its rendering metadata, as RFC 8785 bytes; ``ValueError`` for a tool with no rule."""
    return canonical_bytes(_without_rendering(tool, plan))


def keyed_plan_digest(tool: IacTool, plan: dict[str, Any], key: RunDigestKey) -> str:
    """``hmac-sha256:<hex>``: the plan's digest in a run the server opened, keyed with the run's digest key."""
    without = _without_rendering(tool, plan)
    return keyed_digest(
        KEYED_PLAN_DIGEST_RULE, {"tool": tool, "digest_version": KEYED_PLAN_DIGEST_VERSIONS[tool], "plan": without}, key
    )


def redacted_plan_digest_of_kept(tool: IacTool, redacted_plan: dict[str, Any]) -> str:
    """``sha256:<hex>``: the plan's digest in a run the tool opened, from the plan as its record keeps it, redacted."""
    without = _without_rendering(tool, redacted_plan)
    return digest_of(
        {
            "rule": REDACTED_PLAN_DIGEST_RULE,
            "tool": tool,
            "digest_version": REDACTED_PLAN_DIGEST_VERSIONS[tool],
            "plan": without,
        }
    )
