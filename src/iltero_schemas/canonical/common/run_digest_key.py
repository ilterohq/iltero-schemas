"""The run's digest key, and the keyed digests made with it.

The server that opens a run gives each of the run's stages the same random
key. A plan digest in a run the server opened is a keyed digest: HMAC-SHA-256
under that key, written ``hmac-sha256:<hex>``. Only a program holding the key
computes one, and the record never names the key. A keyed digest shows that
two values named in the same run are equal; it is not a signature.

``RunDigestKey`` keeps the key's bytes out of reprs, copies and pickles. It
guards against showing the key by mistake, not against code that reads its
private attribute.
"""

from __future__ import annotations

import base64
import hmac
import re
from collections.abc import Mapping
from typing import Final, NoReturn

from iltero_schemas.canonical.common.encoding import canonical_bytes, digest

# The key's text: ``irk_`` and 43 base64url characters without padding, naming 32 bytes. The last character carries
# two bits past the 256 the key holds; they are zero, so each key has one text.
RUN_DIGEST_KEY_PREFIX: Final = "irk_"
# For ``re.fullmatch``, which refuses a trailing newline that ``re.match`` would let through ``$``.
RUN_DIGEST_KEY_PATTERN: Final = rf"^{RUN_DIGEST_KEY_PREFIX}[A-Za-z0-9_-]{{42}}[AEIMQUYcgkosw048]$"
RUN_DIGEST_KEY_BYTES: Final = 32
RUN_DIGEST_KEY_TEXT_LENGTH: Final = len(RUN_DIGEST_KEY_PREFIX) + 43
KEYED_DIGEST_PREFIX: Final = "hmac-sha256:"
# The rules a keyed digest is made under, named in the message so a value made under one is never another's.
KEYED_PLAN_DIGEST_RULE: Final = "iltero.plan_digest"
GIVEN_FILE_DIGEST_RULE: Final = "iltero.given_file_digest"
# The rules of a plan's and a state's digest in a run the tool opened, plain digests of the redacted plan or state,
# named the same way.
REDACTED_PLAN_DIGEST_RULE: Final = "iltero.redacted_plan_digest"
REDACTED_STATE_DIGEST_RULE: Final = "iltero.redacted_state_digest"
# The digest of the text of the published key the conformance vectors are keyed with
# (``vectors/run_digest_keys/development.txt``): a test key, never a run's.
VECTOR_RUN_DIGEST_KEY_TEXT_DIGEST: Final = "sha256:e3d995465c3e403090d10115e6d3150068545fa56187c44e57f2b7849024a233"

_KEY_TEXT = re.compile(RUN_DIGEST_KEY_PATTERN)
_SHA256_HEX = re.compile(r"^sha256:[0-9a-f]{64}$")
_HIDDEN: Final = "<hidden>"


class RunDigestKey:
    """A run's digest key. Built only from its text; it never shows its bytes, changes, compares, copies or pickles.

    Comparing two keys raises ``TypeError``, so ``==``, ``!=`` and ``in`` never fall back to identity by mistake.
    """

    __slots__ = ("_bytes",)
    _bytes: bytes
    __hash__ = None  # type: ignore[assignment]

    def __init__(self, data: bytes, *, _from: object) -> None:
        if _from is not _CONSTRUCTOR:
            raise TypeError("a run digest key is built from its text, with RunDigestKey.from_text")
        object.__setattr__(self, "_bytes", data)

    def __setattr__(self, name: str, value: object) -> NoReturn:
        raise TypeError("a run digest key does not change")

    def __delattr__(self, name: str) -> NoReturn:
        raise TypeError("a run digest key does not change")

    @classmethod
    def from_text(cls, text: str) -> RunDigestKey:
        """The key ``text`` names. Raise ``ValueError`` for any other text, and for the published vector key."""
        _check_text(text)
        if _is_vector_key(text):
            raise ValueError("the vector key is a test key, never a run key")
        return _decoded(text)

    @classmethod
    def for_vectors(cls, text: str) -> RunDigestKey:
        """The published vector key ``text`` names, for building and checking the conformance vectors only. Raise
        ``ValueError`` for any other key."""
        _check_text(text)
        if not _is_vector_key(text):
            raise ValueError("only the published vector key is read for the vectors")
        return _decoded(text)

    def __repr__(self) -> str:
        return _HIDDEN

    def __str__(self) -> str:
        return _HIDDEN

    def __eq__(self, other: object) -> bool:
        raise TypeError("run digest keys are not compared")

    def __reduce__(self) -> NoReturn:
        raise TypeError("a run digest key is not pickled")

    def __reduce_ex__(self, protocol: object) -> NoReturn:
        raise TypeError("a run digest key is not pickled")

    def __getstate__(self) -> NoReturn:
        raise TypeError("a run digest key is not pickled")

    def __copy__(self) -> NoReturn:
        raise TypeError("a run digest key is not copied")

    def __deepcopy__(self, memo: object) -> NoReturn:
        raise TypeError("a run digest key is not copied")


_CONSTRUCTOR = object()


def _check_text(text: object) -> None:
    if not isinstance(text, str) or not _KEY_TEXT.fullmatch(text):
        raise ValueError("a run digest key is irk_ and 43 base64url characters naming 32 bytes")


def _is_vector_key(text: str) -> bool:
    return hmac.compare_digest(digest(text.encode("ascii")), VECTOR_RUN_DIGEST_KEY_TEXT_DIGEST)


def _decoded(text: str) -> RunDigestKey:
    return RunDigestKey(base64.urlsafe_b64decode(text[len(RUN_DIGEST_KEY_PREFIX) :] + "="), _from=_CONSTRUCTOR)


def keyed_digest(rule: str, fields: Mapping[str, object], key: RunDigestKey) -> str:
    """``hmac-sha256:<hex>``: HMAC-SHA-256 under ``key`` of the canonical bytes of ``{"rule": rule, **fields}``."""
    if "rule" in fields:
        raise ValueError("a keyed digest's fields do not name its rule; the rule is given apart")
    message = canonical_bytes({"rule": rule, **fields})
    return KEYED_DIGEST_PREFIX + hmac.new(key._bytes, message, "sha256").hexdigest()


def keyed_given_file_digest(plain_digest: str, key: RunDigestKey) -> str:
    """The keyed digest of a file the pipeline gave, whose plain digest, ``sha256:<hex>``, is ``plain_digest``."""
    if not _SHA256_HEX.fullmatch(plain_digest):
        raise ValueError("a given file's plain digest is sha256: and 64 lowercase hexadecimal digits")
    return keyed_digest(GIVEN_FILE_DIGEST_RULE, {"sha256": plain_digest.removeprefix("sha256:")}, key)
