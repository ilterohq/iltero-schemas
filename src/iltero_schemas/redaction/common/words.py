"""Whether a key's name, or a value, looks like a credential: the tests every redaction rule is built from.

Each test reads only its argument and the lists in ``credentials``, and takes time in proportion to the length of its
argument. This module imports no model, so the models that check a redaction report can use it.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from functools import lru_cache
from typing import Any

from iltero_schemas.redaction.common.credentials import (
    ASSIGNMENT,
    CREDENTIAL_WORDS,
    IDENTIFIER_WORDS,
    KEY_FORMAT_WORDS,
    KEY_QUALIFIERS,
    KEY_WORD,
    NAMED_VALUE_PAIRS,
    VALUE_SHAPES,
)

# Words the lists name as written (``status``, ``pass``) are never read as plurals.
_KNOWN_WORDS = CREDENTIAL_WORDS | IDENTIFIER_WORDS | KEY_QUALIFIERS | KEY_FORMAT_WORDS | {KEY_WORD}
# How a key's name is split into words: at separators, and where a lower-case letter or digit meets an upper-case one.
WORD_SPLIT = re.compile(r"[_\-.\s/:]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
# The digits dropped from the end of each word, as the policy records the rule. They are dropped with ``str.rstrip``,
# which takes time in proportion to the word's length; the two agree on every word, as no word holds a line break (the
# one place ``$`` and the end of the text differ).
TRAILING_DIGITS_PATTERN = "[0-9]+$"
DIGITS = "0123456789"
# How many distinct keys each test of a key's name remembers, and the longest key it remembers: keys repeat across a
# document, so most are judged once. A longer key is judged each time, so the answers kept hold at most this many keys
# of at most this length, whatever a document holds.
KEY_CACHE_SIZE = 65_536
CACHED_KEY_LENGTH = 256


def _scoped(pattern: str) -> str:
    """``pattern`` as a group of an alternation, its leading flags scoped to it (``(?i)x`` → ``(?i:x)``)."""
    return f"(?i:{pattern.removeprefix('(?i)')})" if pattern.startswith("(?i)") else f"(?:{pattern})"


# Every credential shape at once: a value none of them is found in is passed over in one search.
_ANY_SHAPE = re.compile("|".join(_scoped(pattern.pattern) for _name, pattern in VALUE_SHAPES))


def singular(word: str) -> str:
    """``passwords`` → ``password``, ``policies`` → ``policy``; short words and ``ss`` endings are left alone."""
    if len(word) > 4 and word.endswith("ies"):
        return word[:-3] + "y"
    if len(word) > 3 and word.endswith("s") and not word.endswith("ss"):
        return word[:-1]
    return word


def _words(key: str) -> list[str]:
    """The words of a key name: lower-cased, a trailing number dropped (``password1``), plurals made singular."""
    words = [word.lower().rstrip(DIGITS) for word in WORD_SPLIT.split(key)]
    return [word if word in _KNOWN_WORDS else singular(word) for word in words if word]


def _key_is_denied(key: str) -> bool:
    words = _words(key)
    if not words:
        return False
    joined = f"_{'_'.join(words)}_"
    holds_credential_word = any(f"_{word}_" in joined for word in CREDENTIAL_WORDS)
    qualified_key = len(words) >= 2 and (
        (words[-1] == KEY_WORD and words[-2] in KEY_QUALIFIERS)
        or (words[-2] == KEY_WORD and words[-1] in KEY_FORMAT_WORDS)
    )
    names_something_about_it = len(words) >= 2 and words[-1] in IDENTIFIER_WORDS
    return (holds_credential_word or qualified_key) and not names_something_about_it


_remembered_key_is_denied = lru_cache(maxsize=KEY_CACHE_SIZE)(_key_is_denied)


def key_is_denied(key: str) -> bool:
    """Whether a key name looks like it holds a credential rather than a setting or an identifier about one."""
    return _remembered_key_is_denied(key) if len(key) <= CACHED_KEY_LENGTH else _key_is_denied(key)


def names_by_value_key(entry: Mapping[str, Any]) -> dict[str, tuple[str, ...]]:
    """For each value key of ``entry``, in lower case, the names ``entry`` writes beside it.

    In ``{"name": "DB_PASSWORD", "value": "..."}`` the name beside ``value`` is ``DB_PASSWORD``. An entry can hold more
    than one naming key, so every one is kept, in the entry's order. The entry is read once, so the time this takes
    grows with its size, whatever the number of its keys.
    """
    found: dict[str, list[str]] = {}
    for sibling, named in entry.items():
        if isinstance(sibling, str) and isinstance(named, str):
            naming = sibling.lower()
            for naming_key, value_key in NAMED_VALUE_PAIRS:
                if naming_key == naming:
                    found.setdefault(value_key, []).append(named)
    return {value_key: tuple(names) for value_key, names in found.items()}


def assigns_a_credential(value: str) -> bool:
    """Whether ``value`` holds ``NAME=...`` where ``NAME`` looks like the key of a credential."""
    return "=" in value and any(key_is_denied(match.group(1)) for match in ASSIGNMENT.finditer(value))


def matching_shape(value: str) -> str | None:
    """The name of the first credential shape found in ``value``, or None."""
    if _ANY_SHAPE.search(value) is None:
        return None
    for name, pattern in VALUE_SHAPES:
        if pattern.search(value):
            return name
    return None


def _key_is_shaped_like_a_credential(key: str) -> bool:
    return matching_shape(key) is not None or assigns_a_credential(key)


_remembered_key_is_shaped_like_a_credential = lru_cache(maxsize=KEY_CACHE_SIZE)(_key_is_shaped_like_a_credential)


def key_is_shaped_like_a_credential(key: str) -> bool:
    """Whether an object's key itself holds what looks like a credential: a credential's shape, or ``NAME=...`` where
    ``NAME`` looks like a credential's key. A key's words alone never count: ``password`` is a name, not a secret."""
    if len(key) <= CACHED_KEY_LENGTH:
        return _remembered_key_is_shaped_like_a_credential(key)
    return _key_is_shaped_like_a_credential(key)
