"""Whether a hidden value changed: the value change the plan stage's redaction report names.

What the plan stage observed lists each resource change with its values before and after the change (``resources[i]``,
and each related resource's copy at ``resources[i].related[k].resource``). Redaction pairs a path under a change's
``after`` with the same relative path under its ``before``, and names on each report entry under ``after`` whether the
value there changed:

- ``changed`` or ``unchanged``: both sides were hidden, both are present, and they differ or are equal, compared during
  redaction before the values are dropped;
- ``unknown``: the side under ``before`` was not hidden, either side is absent (a create, a delete, or a list whose
  shape changed), the value is known only after the deployment, or the values have no canonical form.

A list item pairs with the item at the same position under ``before``, so an item that moved reads as changed. A value
is compared only when both sides were hidden, so the statement never says anything of a hidden value that a
plain value beside it would give away. Every other report entry names no value change. It is the redacting program's
statement: the record keeps neither value, so no reader can check it later.
"""

from __future__ import annotations

from typing import Any, Final, Literal

from iltero_schemas.canonical.common.encoding import CanonicalizationError, canonical_bytes
from iltero_schemas.redaction.common.paths import TreePath

# What redaction says of a hidden value under a change's after.
ValueChange = Literal["changed", "unchanged", "unknown"]
# What a redaction report names when it is the report of what the plan stage observed.
OBSERVATION_SUBJECT: Final = "observation"
# Where a resource change starts in what the plan stage observed: a resource, or the copy of a related resource.
_CHANGE_OF_A_RESOURCE_LENGTH = 2
_CHANGE_OF_A_RELATED_RESOURCE_LENGTH = 5


def _change_prefix(path: TreePath) -> TreePath | None:
    """Where the resource change that ``path`` lies under its ``after`` starts, or None."""
    if len(path) >= 3 and path[0] == "resources" and isinstance(path[1], int):
        if path[2] == "after":
            return path[:_CHANGE_OF_A_RESOURCE_LENGTH]
        if (
            len(path) >= 6
            and path[2] == "related"
            and isinstance(path[3], int)
            and path[4] == "resource"
            and path[5] == "after"
        ):
            return path[:_CHANGE_OF_A_RELATED_RESOURCE_LENGTH]
    return None


def paired_before(path: TreePath) -> TreePath | None:
    """The path under the change's ``before`` that ``path``, a path under a resource change's ``after`` in what the
    plan stage observed, is paired with; None for any other path."""
    prefix = _change_prefix(path)
    if prefix is None:
        return None
    return (*prefix, "before", *path[len(prefix) + 1 :])


def is_hidden_at_or_above(path: TreePath, hidden: set[TreePath]) -> bool:
    """Whether ``path``, or a path above it, is one of ``hidden``."""
    return any(path[:length] in hidden for length in range(len(path) + 1))


def present_at(tree: Any, path: TreePath) -> tuple[bool, Any]:
    """Whether ``path`` is in ``tree``, and the value there (None when it is not)."""
    node = tree
    for key in path:
        if isinstance(node, dict) and isinstance(key, str) and key in node:
            node = node[key]
        elif isinstance(node, list) and isinstance(key, int) and 0 <= key < len(node):
            node = node[key]
        else:
            return False, None
    return True, node


def value_change_of(tree: Any, path: TreePath, hidden: set[TreePath], unknown: set[TreePath]) -> ValueChange | None:
    """What redaction says of the value at ``path`` of what the plan stage observed, ``tree`` as it was before
    redaction: None off a change's ``after``; ``unknown`` when the paired side was not hidden (``hidden`` holds the
    paths the report lists), either side is absent, the value is known only after the deployment (``unknown``), or the
    values have no canonical form; else whether the two hidden values differ."""
    before = paired_before(path)
    if before is None:
        return None
    if path in unknown or not is_hidden_at_or_above(before, hidden):
        return "unknown"
    (after_present, after_value), (before_present, before_value) = present_at(tree, path), present_at(tree, before)
    if not (after_present and before_present):
        return "unknown"
    try:
        same = canonical_bytes(after_value) == canonical_bytes(before_value)
    except CanonicalizationError:
        return "unknown"
    return "unchanged" if same else "changed"


def with_value_changes(tree: Any, entries: list[dict[str, Any]], unknown: set[TreePath]) -> None:
    """Each report entry of what the plan stage observed, ``tree`` as it was before redaction, with what redaction
    says of its value's change; every entry of one path names the same."""
    hidden = {tuple(entry["path"]) for entry in entries}
    for entry in entries:
        entry["value_change"] = value_change_of(tree, tuple(entry["path"]), hidden, unknown)
