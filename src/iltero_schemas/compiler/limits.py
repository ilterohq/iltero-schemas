"""How large an answer from a compiled module can be, and what a consumer may refuse.

The runtime bounds every value it records (short scalars, lists of at most
four short scalars, everything else by shape), so the size of an answer is a
function of the language's own limits: at most 128 checks, each with a path
of at most 16 names of 64 characters. The caps below hold for every
assertion the parser accepts; a consumer that receives more than this from a
policy is looking at something the compiler did not produce and refuses it.
"""

from __future__ import annotations

from typing import Any

# Strings longer than this, and lists longer than SHORT_LIST_MAX, are recorded
# by shape (`{"type": "string", "length": n}`); mirrors `_short` in runtime.rego.
SHORT_STRING_MAX_CHARS = 128
SHORT_LIST_MAX = 4
# `subject` is echoed as {kind, id}, each bounded like any recorded value.
SUBJECT_FIELD_MAX_CHARS = SHORT_STRING_MAX_CHARS
# reason: "<path>: <marker reason>" at most 16 names of 64 chars plus a
# 64-char token, or a fixed sentence naming one predicate; 2 KiB is ample.
REASON_MAX_BYTES = 2 * 1024
# observations: at most 125 predicate entries (128 expressions less the
# combinators that hold them), each under 4 KiB in the worst case (a long
# path, two lists of four 128-char strings, a scalar and the fixed keys) in
# canonical JSON — about 390 KiB measured; `tests/test_limits.py` pins it.
OBSERVATIONS_MAX_BYTES = 512 * 1024
# observations -> predicates[] -> entry -> a list or object value -> scalar.
OBSERVATIONS_MAX_DEPTH = 4


def nesting_depth(value: Any) -> int:
    """How deeply objects and arrays nest in ``value``; a scalar is 0."""
    if isinstance(value, dict):
        return 1 + max((nesting_depth(child) for child in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((nesting_depth(child) for child in value), default=0)
    return 0
