"""Paths in a tree of JSON values, and the attribute paths a redaction policy names.

A tree path is the keys and list indexes from a tree's root to one value. A configured path, such as
``ingress[*].cidr_blocks``, names an attribute of a resource and is matched relative to where a resource's values
start.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TypeAlias

from iltero_schemas.redaction.common.words import key_is_shaped_like_a_credential

# One step of a tree path: an object's key, or a list's index.
PathKey: TypeAlias = str | int
TreePath: TypeAlias = tuple[PathKey, ...]

# A configured path: dotted names, each optionally indexed with ``[*]`` (any index) or ``[n]``.
_SEGMENT = r"[A-Za-z0-9_-]+(?:\[(?:\*|[0-9]+)\])?"
REDACTION_PATH_PATTERN = re.compile(rf"{_SEGMENT}(?:\.{_SEGMENT})*")
_INDEX = re.compile(r"\[(\*|[0-9]+)\]")


@dataclass(frozen=True)
class PathPattern:
    """A configured attribute path such as ``ingress[*].cidr_blocks``, matched relative to a resource's values."""

    text: str
    segments: tuple[PathKey | None, ...]  # None matches any index

    def matches(self, relative: TreePath) -> bool:
        if len(relative) != len(self.segments):
            return False
        return all(
            (isinstance(actual, int) if wanted is None else wanted == actual)
            for wanted, actual in zip(self.segments, relative, strict=True)
        )


def parse_path(text: str) -> PathPattern:
    """Compile a configured path written in the grammar of ``REDACTION_PATH_PATTERN``; anything else is refused."""
    if not REDACTION_PATH_PATTERN.fullmatch(text):
        raise ValueError(f"not a redaction path: {text!r}")
    segments: list[PathKey | None] = []
    for part in text.split("."):
        name, _, rest = part.partition("[")
        segments.append(name)
        for index in _INDEX.findall("[" + rest if rest else ""):
            segments.append(None if index == "*" else int(index))
    return PathPattern(text, tuple(segments))


def dotted(path: TreePath) -> str:
    """``a.b[0].c`` for a tree path, the way a redaction report and a configured path write it."""
    text = ""
    for key in path:
        text += f"[{key}]" if isinstance(key, int) else (f".{key}" if text else key)
    return text


# The longest key a path a message or a listing names keeps: a longer one is cut to its first this many characters.
MAX_LISTED_KEY_LENGTH = 256


def listed_path(path: TreePath) -> TreePath:
    """``path`` with each key cut to its first ``MAX_LISTED_KEY_LENGTH`` characters, so a crafted long key never reaches
    a message or a listing whole."""
    return tuple(key[:MAX_LISTED_KEY_LENGTH] if isinstance(key, str) else key for key in path)


def path_before_credential_key(path: TreePath) -> TreePath | None:
    """The part of ``path`` before its first key shaped like a credential, or None when it holds no such key."""
    for length, key in enumerate(path):
        if isinstance(key, str) and key_is_shaped_like_a_credential(key):
            return path[:length]
    return None


def named_path(path: TreePath) -> str:
    """``path`` as a message names it: dotted, each key cut as ``listed_path`` cuts it, or ``the root``."""
    return dotted(listed_path(path)) or "the root"
