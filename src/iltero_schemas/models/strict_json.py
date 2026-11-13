"""Reading a JSON file a pipeline gave, strictly, so every reader reads the same bytes the same way."""

from __future__ import annotations

import json
from typing import Any


def strict_json(data: bytes, what: str) -> Any:
    """The JSON document in ``data``: UTF-8 with no byte order mark, each key once, and no constant such as NaN.

    Raises ``ValueError`` naming ``what`` otherwise.
    """

    def unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        keys = [key for key, _value in pairs]
        if len(set(keys)) != len(keys):
            raise ValueError(f"{what} names each key once")
        return dict(pairs)

    def no_constant(name: str) -> None:
        raise ValueError(f"{what} holds no {name}: it is plain JSON")

    if data.startswith(b"\xef\xbb\xbf"):
        raise ValueError(f"{what} is a JSON document in UTF-8, with no byte order mark")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique_keys, parse_constant=no_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ValueError(f"{what} is a JSON document in UTF-8, nested no deeper than a reader can follow") from None
