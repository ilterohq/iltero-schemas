"""Apply a redaction policy to a tree: sensitive values become markers, not gaps.

A hidden value is replaced by a marker that says a value was there, why it
was hidden and what type it had, so an assertion that reaches it comes out
"unknown" rather than silently false. A value the tool knows only after
the deployment becomes a second kind of marker. A string that equals a value a tool
marked sensitive is hidden wherever else it appears, because providers copy
values (a sensitive tag into ``tags_all``) without copying the mark. The
report lists every path touched and why — paths, which include map keys,
never values — in path order, and names the bytes it describes.

A key cannot be hidden without changing the tree's shape, so a tree with an
object key shaped like a credential is refused, naming only the path to the
object that holds it. A whole marker already in the tree is kept as it is.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal

from iltero_schemas.canonical.common.encoding import digest_of
from iltero_schemas.models.common.fields import RAW_TEXT_MAX_BYTES
from iltero_schemas.models.common.redaction import (
    KNOWN_AFTER_DEPLOY,
    MAX_REPORTED_PATH_DEPTH,
    MAX_REPORTED_PATHS,
    JsonTypeName,
    RedactionReason,
    SensitiveMarkReason,
    is_redaction_marker,
    is_unknown_marker,
    path_order,
)
from iltero_schemas.models.common.sent_documents import MAX_JSON_DEPTH
from iltero_schemas.redaction.common.marks import Mark
from iltero_schemas.redaction.common.paths import PathKey, TreePath, named_path, path_before_credential_key
from iltero_schemas.redaction.common.policy import REUSE_MIN_CHARS, RedactionPolicy
from iltero_schemas.redaction.common.value_change import OBSERVATION_SUBJECT, present_at, with_value_changes
from iltero_schemas.redaction.common.words import (
    assigns_a_credential,
    key_is_denied,
    key_is_shaped_like_a_credential,
    matching_shape,
    names_by_value_key,
)

REDACTED_KEY = "__redacted"
UNKNOWN_KEY = "__unknown"
_TYPE_NAMES: dict[type, JsonTypeName] = {
    dict: "object",
    list: "array",
    str: "string",
    bool: "boolean",
    int: "number",
    float: "number",
}


# How deep a check reads a tree: as deep as a document a stage sends may nest, so a check never runs out of stack.
MAX_CHECKED_DEPTH = MAX_JSON_DEPTH


class RedactionError(ValueError):
    """A tree redaction cannot report on: a key shaped like a credential, or more paths than one report lists."""


@dataclass(frozen=True)
class RedactionReport:
    """What was hidden or marked, by path and reason; no value ever appears here."""

    policy: dict[str, str]
    subject: dict[str, str]
    redacted: list[dict[str, Any]]
    unknown: list[list[PathKey]]
    exempted: list[dict[str, Any]]

    def as_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy,
            "input": self.subject,
            "redacted": self.redacted,
            "unknown": self.unknown,
            "exempted": self.exempted,
        }


@dataclass(frozen=True)
class Redacted:
    """A tree that went through redaction, with its report. Only this type is written to a record."""

    tree: Any
    report: RedactionReport


def _type_name(value: Any) -> JsonTypeName:
    return "null" if value is None else _TYPE_NAMES.get(type(value), "object")


def redacted_marker(reason: RedactionReason, value: Any) -> dict[str, Any]:
    return {REDACTED_KEY: True, "reason": reason, "present": value is not None, "type": _type_name(value)}


def unknown_marker() -> dict[str, Any]:
    return {UNKNOWN_KEY: True, "reason": KNOWN_AFTER_DEPLOY, "present": True}


def value_at(tree: Any, path: TreePath) -> Any:
    """The value at ``path``, or None when the path is not in the tree."""
    return present_at(tree, path)[1]


def _strings_in(value: Any, found: set[str]) -> None:
    if isinstance(value, str):
        if len(value) >= REUSE_MIN_CHARS:
            found.add(value)
    elif isinstance(value, dict):
        for child in value.values():
            _strings_in(child, found)
    elif isinstance(value, list):
        for child in value:
            _strings_in(child, found)


def _under(path: TreePath, anchors: set[TreePath]) -> bool:
    return any(path[:length] in anchors for length in range(len(path) + 1))


def sensitive_strings(tree: Any, marks: Sequence[Mark], anchors: Sequence[TreePath]) -> set[str]:
    """The strings the tool itself declared sensitive in ``tree``.

    These are every declared string, and everything declared inside a
    resource's values. A declared container elsewhere, such as a
    configuration expression, names things rather than holding a value. Taking
    its strings would hide every name it mentions.
    """
    anchor_set = set(anchors)
    found: set[str] = set()
    for mark in marks:
        if mark.declared_sensitive:
            value = value_at(tree, mark.path)
            if isinstance(value, str) or _under(mark.path, anchor_set):
                _strings_in(value, found)
    return found


def _is_whole_marker(value: Any) -> bool:
    """Whether ``value`` is exactly a marker redaction writes: it holds no value, so it is kept as it is."""
    return isinstance(value, dict) and (
        (value.get(REDACTED_KEY) is True and is_redaction_marker(value))
        or (value.get(UNKNOWN_KEY) is True and is_unknown_marker(value))
    )


def _key_shaped_like_a_credential_at(parent: TreePath) -> RedactionError:
    """The refusal of a tree whose object at ``parent`` holds a key shaped like a credential, naming only
    ``parent``."""
    where = named_path(parent)
    return RedactionError(f"an object key at {where} is shaped like a credential, and no marker can stand for a key")


def _refuse_a_key_shaped_like_a_credential(path: TreePath) -> None:
    """Raise ``RedactionError`` when a key on ``path`` is shaped like a credential, naming only the path before it."""
    before = path_before_credential_key(path)
    if before is not None:
        raise _key_shaped_like_a_credential_at(before)


def _sorted_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(entries, key=lambda entry: (path_order(entry["path"]), entry["reason"]))


# What a check finds at a path: a value a rule would hide, by the reason redaction would report, or an object holding
# a key shaped like a credential.
RedactionRule = RedactionReason | Literal["credential_shaped_key"]


@dataclass(frozen=True)
class Finding:
    """What redaction would do at one path of a tree it checks: hide the value there for ``rule``, the reason it would
    report, or refuse the tree for a key shaped like a credential in the object there (``at`` is ``key``)."""

    path: TreePath
    at: Literal["value", "key"]
    rule: RedactionRule


class _Redactor:
    """Redacts a tree, or, when ``checking``, walks it without building a copy and lists what redaction would do."""

    def __init__(
        self,
        tree: Any,
        marks: Sequence[Mark],
        policy: RedactionPolicy,
        anchors: Sequence[TreePath],
        known_sensitive: Sequence[str],
        *,
        checking: bool,
    ) -> None:
        self.checking = checking
        # A check keeps the first findings in path order, up to its limit, and counts them all.
        self.finding_limit = 0
        self.findings: list[tuple[tuple[Any, ...], Finding]] = []
        self.finding_count = 0
        # Whether each container seen holds a string, by its identity, so each is searched once.
        self.holds_a_string_at: dict[int, bool] = {}
        self.policy = policy
        self.anchors = set(anchors)
        # A value both sensitive and not yet known is unknown — there is no value to hide —
        # but the tool's sensitive mark is still reported.
        self.unknown_at: set[TreePath] = set()
        self.sensitive_at: dict[TreePath, SensitiveMarkReason] = {}
        # Unknown values are absent from the tree; they are added under their parent, in mark order.
        self.unknown_under: dict[TreePath, list[PathKey]] = {}
        for mark in marks:
            if not checking:
                _refuse_a_key_shaped_like_a_credential(mark.path)
            if mark.reason != "known_after_deploy":
                self.sensitive_at[mark.path] = mark.reason
            elif mark.path not in self.unknown_at:
                self.unknown_at.add(mark.path)
                if mark.path:
                    self.unknown_under.setdefault(mark.path[:-1], []).append(mark.path[-1])
        # Marks under a path, so a hidden parent can still report the tool's word about its children. A check writes
        # no report, so it keeps none.
        self.marks_under: dict[TreePath, list[tuple[TreePath, SensitiveMarkReason]]] = {}
        for path, reason in () if checking else self.sensitive_at.items():
            for length in range(len(path)):
                self.marks_under.setdefault(path[:length], []).append((path, reason))
        # A sensitive string is hidden wherever it appears again, whole or inside another string. A check never looks
        # for copies: in a redacted tree the strings are hidden, and searching for many strings at once takes time
        # that grows with their number.
        self.sensitive_values = set() if checking else sensitive_strings(tree, marks, anchors) | set(known_sensitive)
        longest_first = sorted(self.sensitive_values, key=lambda value: (-len(value), value))
        self.sensitive_pattern = re.compile("|".join(map(re.escape, longest_first))) if longest_first else None
        self.redacted: list[dict[str, Any]] = []
        self.unknown: list[list[PathKey]] = []
        self.exempted: list[dict[str, Any]] = []

    def find(self, finding: Finding) -> None:
        """Count ``finding`` and keep it if it is among the first ``finding_limit`` in path order."""
        self.finding_count += 1
        order = (path_order(finding.path), finding.at, finding.rule)
        if len(self.findings) < self.finding_limit or (self.findings and order < self.findings[-1][0]):
            bisect.insort(self.findings, (order, finding), key=lambda kept: kept[0])
            del self.findings[self.finding_limit :]

    def holds_a_string(self, value: Any) -> bool:
        """Whether a value is a string or a container with a string somewhere inside it."""
        if isinstance(value, str):
            return True
        if not isinstance(value, dict | list):
            return False
        known = self.holds_a_string_at.get(id(value))
        if known is None:
            children = value.values() if isinstance(value, dict) else value
            known = any(self.holds_a_string(child) for child in children)
            self.holds_a_string_at[id(value)] = known
        return known

    def hide(self, path: TreePath, reason: RedactionReason, value: Any) -> dict[str, Any]:
        if self.checking:
            self.find(Finding(path, "value", reason))
            return redacted_marker(reason, value)
        self.redacted.append({"path": list(path), "reason": reason, "value_change": None})
        for marked, marked_reason in self.marks_under.get(path, []):
            self.redacted.append({"path": list(marked), "reason": marked_reason, "value_change": None})
        return redacted_marker(reason, value)

    def note_unknown(self, path: TreePath) -> dict[str, Any]:
        self.unknown.append(list(path))
        if path in self.sensitive_at:
            self.redacted.append({"path": list(path), "reason": self.sensitive_at[path], "value_change": None})
        return unknown_marker()

    def node(self, value: Any, path: TreePath, relative: TreePath | None, named_as_credential: bool = False) -> Any:
        """Redact one node. ``relative`` is its path under the nearest anchor, or None outside any.
        ``named_as_credential`` says its parent writes a credential's name beside it, such as ``DB_PASSWORD`` beside a
        ``value``."""
        if _is_whole_marker(value):
            return value
        if self.checking and len(path) > MAX_CHECKED_DEPTH:
            raise RedactionError(f"the tree nests deeper than the {MAX_CHECKED_DEPTH} levels a check reads")
        # In a redacted tree the unknown marker stands where the tool knows a value only after the deployment, and is
        # kept as a whole marker above; a check reads any other value there like every value.
        if path in self.unknown_at and not self.checking:
            return self.note_unknown(path)
        if path in self.sensitive_at:
            return self.hide(path, self.sensitive_at[path], value)
        if isinstance(value, str) and self.sensitive_pattern is not None and self.sensitive_pattern.search(value):
            return self.hide(path, "sensitive_value_reuse", value)
        exempt_reason = self.policy.exempt_reason(relative) if relative else None
        if exempt_reason is not None:
            self.exempted.append({"path": list(path), "reason": exempt_reason})
        else:
            if relative and self.policy.is_additional_path(relative):
                return self.hide(path, "configured_path", value)
            # A credential is a string or a container holding one, never a number, a boolean or null.
            denied = named_as_credential or (path and isinstance(path[-1], str) and key_is_denied(path[-1]))
            if denied and self.holds_a_string(value):
                return self.hide(path, "deny_key", value)
            if isinstance(value, str) and assigns_a_credential(value):
                return self.hide(path, "deny_key", value)
            if isinstance(value, str) and matching_shape(value) is not None:
                return self.hide(path, "value_shape", value)
        if isinstance(value, dict):
            shaped = {key for key in value if isinstance(key, str) and key_is_shaped_like_a_credential(key)}
            if shaped and not self.checking:
                raise _key_shaped_like_a_credential_at(path)
            if shaped:
                self.find(Finding(path, "key", "credential_shaped_key"))
            # Whether a credential's name is written beside each value key, worked out once for the whole object.
            named = {
                value_key: any(key_is_denied(name) for name in names)
                for value_key, names in names_by_value_key(value).items()
            }
            if self.checking:
                for key, child in value.items():
                    if key not in shaped:
                        self.node(child, (*path, key), self._child(path, relative, key), named.get(key.lower(), False))
                return None
            result = {
                key: self.node(child, (*path, key), self._child(path, relative, key), named.get(key.lower(), False))
                for key, child in value.items()
                if key not in shaped
            }
            for key in self.unknown_under.get(path, []):
                if key not in result:
                    result[str(key)] = self.note_unknown((*path, key))
            return result
        if isinstance(value, list) and self.checking:
            for i, child in enumerate(value):
                self.node(child, (*path, i), self._child(path, relative, i))
            return None
        if isinstance(value, list):
            return [self.node(child, (*path, i), self._child(path, relative, i)) for i, child in enumerate(value)]
        return value

    def _child(self, path: TreePath, relative: TreePath | None, key: PathKey) -> TreePath | None:
        """The child's path under the nearest anchor: a new anchor starts one, else the parent's grows."""
        if path in self.anchors:
            return (key,)
        return None if relative is None else (*relative, key)


def redact(
    tree: Any,
    marks: Sequence[Mark],
    policy: RedactionPolicy,
    *,
    subject: str,
    anchors: Sequence[TreePath] = (),
    known_sensitive: Sequence[str] = (),
) -> Redacted:
    """A redacted copy of ``tree``; the input is never modified. Raises ``RedactionError`` for a tree it cannot
    report on.

    ``anchors`` are the paths at which a resource's values start, so the
    policy's configured attribute paths apply under each of them.
    ``known_sensitive`` are strings marked sensitive elsewhere in the tool's
    output, to hide here too. ``subject`` names what the tree is
    (``observation``, ``artifact``); the report records it with the digest of
    the redacted bytes. In the report of what the plan stage observed
    (``observation``), each entry under a resource change's ``after`` names
    whether its value changed (``value_change``); every other entry names none.
    """
    redactor = _Redactor(tree, marks, policy, anchors, known_sensitive, checking=False)
    redacted_tree = redactor.node(tree, (), None)
    if max(len(redactor.redacted), len(redactor.unknown), len(redactor.exempted)) > MAX_REPORTED_PATHS:
        raise RedactionError(f"redaction touched more than the {MAX_REPORTED_PATHS} paths one report lists")
    if subject == OBSERVATION_SUBJECT:
        with_value_changes(tree, redactor.redacted, redactor.unknown_at)
    paths = [entry["path"] for entry in redactor.redacted + redactor.exempted] + redactor.unknown
    if any(
        len(path) > MAX_REPORTED_PATH_DEPTH
        or any(isinstance(key, str) and len(key.encode("utf-8")) > RAW_TEXT_MAX_BYTES for key in path)
        for path in paths
    ):
        raise RedactionError(
            f"redaction touched a path deeper than {MAX_REPORTED_PATH_DEPTH} keys, or with a key longer than "
            f"{RAW_TEXT_MAX_BYTES} bytes, which a report cannot list"
        )
    report = RedactionReport(
        policy=policy.identity(),
        subject={"kind": subject, "digest": digest_of(redacted_tree)},
        redacted=_sorted_entries(redactor.redacted),
        unknown=sorted(redactor.unknown, key=path_order),
        exempted=_sorted_entries(redactor.exempted),
    )
    return Redacted(redacted_tree, report)


def redaction_findings(
    tree: Any, marks: Sequence[Mark], policy: RedactionPolicy, *, anchors: Sequence[TreePath], limit: int
) -> tuple[list[Finding], int]:
    """What ``redact`` would do to ``tree`` under ``marks``, ``policy`` and ``anchors``, without building a copy: the
    first ``limit`` findings in path order, then by where and reason, and how many there are. A finding is a value it
    would hide, by the path and reason it would report, or an object holding a key shaped like a credential, whose
    values are then not read. A whole marker is kept as it is and never looked inside. Copies of a marked value are not
    looked for. Raises ``RedactionError`` for a tree nested deeper than ``MAX_CHECKED_DEPTH``."""
    redactor = _Redactor(tree, marks, policy, anchors, (), checking=True)
    redactor.finding_limit = limit
    redactor.node(tree, (), None)
    return [finding for _order, finding in redactor.findings], redactor.finding_count
