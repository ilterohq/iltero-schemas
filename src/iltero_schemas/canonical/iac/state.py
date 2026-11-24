"""A state's digest, by a rule for each IaC tool.

A record never keeps the state the deployment was held to. In a run the server opened, it names the state by the keyed
digest of the state's bytes as the tool wrote them (``keyed_given_file_digest``, versions from
``KEYED_STATE_DIGEST_VERSIONS``). In a run the tool opened, it names the state by the digest of the state as the
record's redaction policy leaves it (``redacted_state_digest_of_kept``, versions from
``REDACTED_STATE_DIGEST_VERSIONS``), without the tool's excluded top-level keys (``STATE_EXCLUDED_TOP_LEVEL_KEYS``).
Each table gives its own version values, so a tool and a version name one rule, and a digest's prefix says which table
its version is read from.

Terraform: the state is as ``terraform show -json`` prints it, without ``format_version``, ``terraform_version`` and
``checks``.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from iltero_schemas.canonical.common.digest_versions import check_digest_version
from iltero_schemas.canonical.common.encoding import canonical_bytes, digest
from iltero_schemas.canonical.common.run_digest_key import REDACTED_STATE_DIGEST_RULE
from iltero_schemas.models.iac.tool_names import IacTool

# The version of each tool's keyed rule, the keyed digest of the state's bytes.
KEYED_STATE_DIGEST_VERSIONS: Mapping[IacTool, str] = MappingProxyType({"terraform": "1"})
# The version of each tool's rule over the redacted state; it moves when the redaction rules change what they hide.
REDACTED_STATE_DIGEST_VERSIONS: Mapping[IacTool, str] = MappingProxyType({"terraform": "redacted-1"})
# Removed at the top level only; a same-named key deeper in the state is content.
STATE_EXCLUDED_TOP_LEVEL_KEYS: Mapping[IacTool, frozenset[str]] = MappingProxyType(
    {"terraform": frozenset({"format_version", "terraform_version", "checks"})}
)


def check_state_digest_version(tool: IacTool, version: str, state_digest: str) -> None:
    """Raise ``ValueError`` unless ``version`` is the version of ``tool``'s rule that ``state_digest`` is made under:
    the keyed rule for a keyed digest, the rule over the redacted state for any other."""
    check_digest_version(
        "state", KEYED_STATE_DIGEST_VERSIONS, REDACTED_STATE_DIGEST_VERSIONS, tool, version, state_digest
    )


def canonical_redacted_state_bytes(tool: IacTool, redacted_state: dict[str, Any]) -> bytes:
    """The RFC 8785 bytes the redacted state digest is the SHA-256 of: ``{"rule", "tool", "digest_version", "state"}``,
    where ``state`` is ``redacted_state`` without ``tool``'s excluded top-level keys. ``ValueError`` for a tool with no
    rule."""
    excluded = STATE_EXCLUDED_TOP_LEVEL_KEYS.get(tool)
    if excluded is None:
        raise ValueError("no state digest rule for this tool")
    without = {key: value for key, value in redacted_state.items() if key not in excluded}
    return canonical_bytes(
        {
            "rule": REDACTED_STATE_DIGEST_RULE,
            "tool": tool,
            "digest_version": REDACTED_STATE_DIGEST_VERSIONS[tool],
            "state": without,
        }
    )


def redacted_state_digest_of_kept(tool: IacTool, redacted_state: dict[str, Any]) -> str:
    """``sha256:<hex>``: the state's digest in a run the tool opened, from the state as the record's redaction policy
    leaves it. ``ValueError`` for a tool with no rule."""
    return digest(canonical_redacted_state_bytes(tool, redacted_state))
