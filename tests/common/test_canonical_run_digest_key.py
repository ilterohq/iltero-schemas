"""The run's digest key: built only from its text, never shown, compared, copied or pickled; and the keyed digests."""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import pickle
import re
from pathlib import Path

import pytest

from iltero_schemas.canonical.common.encoding import canonical_bytes
from iltero_schemas.canonical.common.run_digest_key import (
    RUN_DIGEST_KEY_BYTES,
    RUN_DIGEST_KEY_PATTERN,
    RUN_DIGEST_KEY_TEXT_LENGTH,
    VECTOR_RUN_DIGEST_KEY_TEXT_DIGEST,
    RunDigestKey,
    keyed_digest,
    keyed_given_file_digest,
)
from iltero_schemas.models.common.fields import KEYED_DIGEST_PATTERN, MAX_DIGEST_LENGTH, PLAN_DIGEST_PATTERN
from iltero_schemas.vectors.run_digest_key import VECTOR_RUN_DIGEST_KEY_FILE, vector_run_digest_key

SOURCE = Path(__file__).resolve().parents[2] / "src" / "iltero_schemas"
KEY_BYTES = bytes(range(32))
KEY_TEXT = "irk_" + base64.urlsafe_b64encode(KEY_BYTES).decode("ascii").rstrip("=")


def test_a_key_is_read_from_its_text() -> None:
    key = RunDigestKey.from_text(KEY_TEXT)
    expected = hmac.new(KEY_BYTES, canonical_bytes({"rule": "r", "x": 1}), "sha256").hexdigest()
    assert keyed_digest("r", {"x": 1}, key) == f"hmac-sha256:{expected}"
    assert len(KEY_TEXT) == RUN_DIGEST_KEY_TEXT_LENGTH
    assert re.fullmatch(RUN_DIGEST_KEY_PATTERN, KEY_TEXT)
    assert RUN_DIGEST_KEY_BYTES == len(KEY_BYTES)


@pytest.mark.parametrize(
    "text",
    [
        KEY_TEXT[4:],
        "irt_" + KEY_TEXT[4:],
        KEY_TEXT + "A",
        KEY_TEXT[:-1],
        KEY_TEXT[:-1] + "B",
        KEY_TEXT[:-1] + "=",
        KEY_TEXT[:10] + "+" + KEY_TEXT[11:],
        KEY_TEXT + "\n",
        "",
    ],
    ids=[
        "no prefix",
        "another prefix",
        "too long",
        "too short",
        "spare bits set",
        "padding",
        "not base64url",
        "a trailing newline",
        "empty",
    ],
)
def test_any_other_text_is_refused_without_naming_it(text: str) -> None:
    with pytest.raises(ValueError, match="^a run digest key is irk_ and 43 base64url characters naming 32 bytes$"):
        RunDigestKey.from_text(text)


def test_a_key_shows_no_bytes() -> None:
    key = RunDigestKey.from_text(KEY_TEXT)
    assert repr(key) == str(key) == f"{key}" == "<hidden>"


def test_a_key_is_never_compared_or_hashed() -> None:
    key = RunDigestKey.from_text(KEY_TEXT)
    with pytest.raises(TypeError, match="run digest keys are not compared"):
        _ = key == RunDigestKey.from_text(KEY_TEXT)
    with pytest.raises(TypeError):
        hash(key)


def test_a_key_is_never_pickled_or_copied() -> None:
    key = RunDigestKey.from_text(KEY_TEXT)
    with pytest.raises(TypeError, match="not pickled"):
        pickle.dumps(key)
    with pytest.raises(TypeError, match="not copied"):
        copy.copy(key)
    with pytest.raises(TypeError, match="not copied"):
        copy.deepcopy(key)


def test_a_key_never_changes() -> None:
    key = RunDigestKey.from_text(KEY_TEXT)
    with pytest.raises(TypeError, match="does not change"):
        key._bytes = bytes(32)
    with pytest.raises(TypeError, match="does not change"):
        del key._bytes


def test_a_key_is_made_from_its_text_alone() -> None:
    with pytest.raises(TypeError, match="built from its text"):
        RunDigestKey(KEY_BYTES, _from=object())


def test_the_vector_key_is_refused_as_a_run_key_and_read_only_for_the_vectors() -> None:
    text = VECTOR_RUN_DIGEST_KEY_FILE.read_text(encoding="ascii").strip()
    assert f"sha256:{hashlib.sha256(text.encode('ascii')).hexdigest()}" == VECTOR_RUN_DIGEST_KEY_TEXT_DIGEST
    with pytest.raises(ValueError, match="^the vector key is a test key, never a run key$"):
        RunDigestKey.from_text(text)
    with pytest.raises(ValueError, match="^only the published vector key is read for the vectors$"):
        RunDigestKey.for_vectors(KEY_TEXT)
    assert repr(vector_run_digest_key()) == "<hidden>"


def test_no_module_but_the_keys_own_reads_its_bytes() -> None:
    readers = [
        path.relative_to(SOURCE).as_posix()
        for path in SOURCE.rglob("*.py")
        if "._bytes" in path.read_text(encoding="utf-8")
    ]
    assert readers == ["canonical/common/run_digest_key.py"]


def test_keyed_digests_are_made_under_their_rule_and_never_name_it_twice() -> None:
    key = RunDigestKey.from_text(KEY_TEXT)
    assert keyed_digest("a", {"x": 1}, key) != keyed_digest("b", {"x": 1}, key)
    with pytest.raises(ValueError, match="do not name its rule"):
        keyed_digest("a", {"rule": "b"}, key)


def test_a_source_is_keyed_by_its_plain_digest() -> None:
    key = RunDigestKey.from_text(KEY_TEXT)
    plain = "sha256:" + "a" * 64
    assert keyed_given_file_digest(plain, key) == keyed_digest("iltero.given_file_digest", {"sha256": "a" * 64}, key)
    with pytest.raises(ValueError, match="a given file's plain digest is sha256:"):
        keyed_given_file_digest("hmac-sha256:" + "a" * 64, key)


def test_every_digest_fits_the_longest_digest_length() -> None:
    keyed = "hmac-sha256:" + "0" * 64
    assert re.fullmatch(KEYED_DIGEST_PATTERN, keyed) and re.fullmatch(PLAN_DIGEST_PATTERN, keyed)
    assert re.fullmatch(PLAN_DIGEST_PATTERN, "sha256:" + "0" * 64)
    assert len(keyed) == MAX_DIGEST_LENGTH
