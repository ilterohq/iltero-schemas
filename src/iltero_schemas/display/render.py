"""Filling a sentence's placeholders: the one way every consumer turns a display words entry into text."""

from __future__ import annotations

from collections.abc import Mapping

from iltero_schemas.display.model import PLACEHOLDER, Text
from iltero_schemas.models.common.assertion import CONTROL_CHARACTERS


def render(entry: Text, values: Mapping[str, str]) -> str:
    """``entry``'s sentence with each placeholder replaced by its value in ``values``, in one pass: a value is shown
    as it is, braces and all, and never filled again.

    ``values`` names exactly the placeholders ``entry`` allows, each with text that is not empty and holds no control
    character, so a value never starts a line of its own or hides text. ``ValueError`` otherwise, naming the first
    placeholder at fault in sorted order: one the sentence does not allow, then one it needs and was not given, then a
    value it cannot show.
    """
    allowed = set(entry.placeholders)
    unknown = sorted(set(values) - allowed)
    if unknown:
        raise ValueError(f"the sentence has no placeholder named {unknown[0]}")
    missing = sorted(allowed - set(values))
    if missing:
        raise ValueError(f"the sentence needs a value for its placeholder {missing[0]}")
    for name in entry.placeholders:
        value = values[name]
        if not isinstance(value, str):
            raise ValueError(f"the value for {name} is not text")
        if not value:
            raise ValueError(f"the value for {name} is empty, and a sentence never shows a gap")
        if CONTROL_CHARACTERS.search(value):
            raise ValueError(f"the value for {name} holds a control character, which a sentence never shows")
    return PLACEHOLDER.sub(lambda match: values[match.group(1)], entry.text)
