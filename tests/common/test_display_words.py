"""The display words file ships with the package under its digest, is read as strict JSON, and gives the sentence of
each verification result."""

from __future__ import annotations

import base64
import hashlib

import pytest

from iltero_schemas.canonical import digest
from iltero_schemas.display import (
    DISPLAY_WORDS,
    DISPLAY_WORDS_BYTES,
    DISPLAY_WORDS_DIGEST,
    read_display_words,
    result_sentence,
)
from iltero_schemas.distribution import record_digest
from tests.conftest import ROOT

WORDS_FILE = ROOT / "src" / "iltero_schemas" / "display" / "words.json"


def test_the_shipped_words_are_the_file_in_the_package_under_its_digest() -> None:
    assert WORDS_FILE.read_bytes() == DISPLAY_WORDS_BYTES
    assert DISPLAY_WORDS_DIGEST == digest(DISPLAY_WORDS_BYTES)
    assert read_display_words(DISPLAY_WORDS_BYTES) == DISPLAY_WORDS


def test_the_words_file_is_one_of_the_package_files_the_contract_digest_covers() -> None:
    file_hash = base64.urlsafe_b64encode(hashlib.sha256(DISPLAY_WORDS_BYTES).digest()).rstrip(b"=").decode("ascii")
    listed = f"iltero_schemas/__init__.py,sha256=x,1\niltero_schemas/display/words.json,sha256={file_hash},1\n"
    assert record_digest(listed) != record_digest("iltero_schemas/__init__.py,sha256=x,1\n")


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b'{"kind": "DisplayWords", "kind": "DisplayWords"}', "the display words file names each key once"),
        (b"\xef\xbb\xbf{}", "the display words file is a JSON document in UTF-8, with no byte order mark"),
        (b'{"apiVersion": NaN}', "the display words file holds no NaN: it is plain JSON"),
    ],
    ids=["a_key_twice", "a_byte_order_mark", "a_constant"],
)
def test_the_words_file_is_read_as_strict_json(data: bytes, message: str) -> None:
    with pytest.raises(ValueError, match=f"^{message}$"):
        read_display_words(data)


def test_a_result_the_property_lists_reads_its_own_sentence() -> None:
    sentence = result_sentence(DISPLAY_WORDS, "integrity", "failed", "refused_by_server")
    assert sentence.text == "The run statement says the server refused this record."


def test_a_result_with_no_reason_reads_its_own_sentence() -> None:
    sentence = result_sentence(DISPLAY_WORDS, "deployment_coverage", "not_assessed", None)
    assert sentence.text.startswith("One record cannot show deployments")


def test_a_result_the_words_do_not_give_is_refused() -> None:
    with pytest.raises(
        ValueError, match="^the display words give integrity no result in state failed with reason stray$"
    ):
        result_sentence(DISPLAY_WORDS, "integrity", "failed", "stray")


def test_a_property_the_words_do_not_give_is_refused() -> None:
    with pytest.raises(ValueError, match="^the display words give no property named stray$"):
        result_sentence(DISPLAY_WORDS, "stray", "failed", None)
