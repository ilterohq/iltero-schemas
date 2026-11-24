"""Refusing a tool's output that already holds what only redaction writes.

Redaction writes a marker where it hid a value (``{"__redacted": true, ...}``) and where a tool knows a value only after
the deployment (``{"__unknown": true, ...}``). A digest of the redacted output cannot tell a marker redaction wrote from
one the input already held, so an input holding an object a reader could take for either marker is refused before it is
redacted: any object with a ``__redacted`` or ``__unknown`` key, whatever its other keys and values. A redacted copy,
which holds the markers redaction wrote, is never passed through this check.
"""

from __future__ import annotations

from typing import Any, Literal

from iltero_schemas.redaction.common.apply import REDACTED_KEY, UNKNOWN_KEY, RedactionError
from iltero_schemas.redaction.common.paths import TreePath, named_path, path_before_credential_key

MARKER_KEYS = frozenset({REDACTED_KEY, UNKNOWN_KEY})
# What a checked input is, as its refusal names it: a tool's plan or its state.
CheckedInput = Literal["plan", "state"]


def _named(path: TreePath) -> str:
    """Where a refusal points: ``path`` up to its first key shaped like a credential, which it never repeats, each key
    cut as a listed path's is."""
    before = path_before_credential_key(path)
    return f"at {named_path(path)}" if before is None else f"at or under {named_path(before)}"


def refuse_planted_markers(tree: Any, what: CheckedInput) -> None:
    """Raise ``RedactionError`` when ``tree``, a ``what`` (``plan``, ``state``) as the tool wrote it, holds an object
    with a ``__redacted`` or ``__unknown`` key, naming the path to the first such object in a walk of the tree, never
    a value. Walked without recursion, so a deep tree is read to its end."""
    pending: list[tuple[TreePath, Any]] = [((), tree)]
    while pending:
        path, node = pending.pop()
        if isinstance(node, dict):
            if MARKER_KEYS & node.keys():
                raise RedactionError(
                    f"the {what} holds an object {_named(path)} that a reader could take for a redaction or unknown "
                    "marker, which only redaction writes"
                )
            pending.extend(((*path, key), child) for key, child in reversed(list(node.items())))
        elif isinstance(node, list):
            pending.extend(((*path, index), child) for index, child in reversed(list(enumerate(node))))
