"""Which version a digest of a tool's file names, by the digest's form.

A plan digest and a state digest are each keyed in a run the server opened and plain in a run the tool opened, and each
form has its own table of versions, one per tool. A digest's prefix picks the table its version is read from.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TypeVar

from iltero_schemas.canonical.common.run_digest_key import KEYED_DIGEST_PREFIX

# A tool's name, the key of each version table.
Tool = TypeVar("Tool", bound=str)


def check_digest_version(
    what: str,
    keyed_versions: Mapping[Tool, str],
    redacted_versions: Mapping[Tool, str],
    tool: Tool,
    version: str,
    named_digest: str,
) -> None:
    """Raise ``ValueError`` unless ``version`` is the version of ``tool``'s rule that ``named_digest``, a digest of a
    ``what`` (``plan``, ``state``), is made under: ``keyed_versions`` for a keyed digest, ``redacted_versions`` for any
    other."""
    if named_digest.startswith(KEYED_DIGEST_PREFIX):
        if version != keyed_versions.get(tool):
            raise ValueError(f"a keyed {what} digest names the version of the {tool} keyed {what} digest rule")
    elif version != redacted_versions.get(tool):
        raise ValueError(
            f"a {what} digest that is not keyed names the version of the {tool} redacted {what} digest rule"
        )
