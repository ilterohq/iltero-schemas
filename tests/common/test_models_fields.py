"""Shared field types: a timestamp orders to the nanosecond it was written with."""

from __future__ import annotations

import sys
import unicodedata

import pytest
from pydantic import TypeAdapter, ValidationError

from iltero_schemas.models.common.assertion import CONTROL_CHARACTERS
from iltero_schemas.models.common.fields import (
    DirectoryPath,
    FileName,
    GitObjectId,
    ProjectPath,
    parse_timestamp,
    plain_text,
)


@pytest.mark.parametrize(
    ("earlier", "later"),
    [
        ("2026-09-22T12:59:58.000000001Z", "2026-09-22T12:59:58.000000002Z"),
        ("2026-09-22T12:59:58Z", "2026-09-22T12:59:58.000000001Z"),
        ("2026-09-22T12:59:58.9Z", "2026-09-22T12:59:59Z"),
        ("2026-09-22T12:59:58.123Z", "2026-09-22T12:59:58.1231Z"),
    ],
)
def test_a_timestamp_orders_to_the_nanosecond(earlier: str, later: str) -> None:
    assert parse_timestamp(earlier) < parse_timestamp(later)


def test_the_same_moment_written_with_more_digits_is_the_same_instant() -> None:
    assert parse_timestamp("2026-09-22T12:59:58.5Z") == parse_timestamp("2026-09-22T12:59:58.500000000Z")


@pytest.mark.parametrize(
    "value", ["tfplan", "plan.out", "my plan.tfplan", "plan.v2", "\u00e9" * 127 + "p", "\ufdfa" * 14]
)
def test_a_file_name_is_accepted(value: str) -> None:
    assert TypeAdapter(FileName).validate_python(value) == value


@pytest.mark.parametrize("value", ["build/tfplan", "build\\tfplan", "..", ".", "plan\x07", ""])
def test_a_file_name_with_directories_a_directory_name_or_a_control_character_is_refused(value: str) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(FileName).validate_python(value)


@pytest.mark.parametrize("value", ["C:tfplan", "tfplan:stream"])
def test_a_file_name_with_a_colon_is_refused(value: str) -> None:
    with pytest.raises(ValidationError, match="without its directories"):
        TypeAdapter(FileName).validate_python(value)


@pytest.mark.parametrize("value", ["build\uff0ftfplan", "build\u2215tfplan", "build\u2216tfplan", "build\u29f5tfplan"])
def test_a_file_name_with_a_look_alike_slash_is_refused(value: str) -> None:
    with pytest.raises(ValidationError, match="without its directories"):
        TypeAdapter(FileName).validate_python(value)


@pytest.mark.parametrize("value", ["...", ".. ", "   "])
def test_a_file_name_of_only_dots_and_spaces_is_refused(value: str) -> None:
    with pytest.raises(ValidationError, match="without its directories"):
        TypeAdapter(FileName).validate_python(value)


@pytest.mark.parametrize("value", ["p" * 256, "\u00e9" * 128])
def test_a_file_name_over_255_utf8_bytes_as_written_is_refused(value: str) -> None:
    with pytest.raises(ValidationError, match="at most 255 bytes"):
        TypeAdapter(FileName).validate_python(value)


# Each range of control and format characters a text field refuses beyond the C0 and C1 controls, by its first and last
# code point.
REFUSED_RANGES = [
    (0x0600, 0x0605),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x206A, 0x206F),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE007F),
]


@pytest.mark.parametrize(("first", "last"), REFUSED_RANGES, ids=[f"U+{a:04X}-U+{b:04X}" for a, b in REFUSED_RANGES])
def test_text_with_a_control_or_format_character_of_each_range_is_refused(first: int, last: int) -> None:
    for code_point in (first, last):
        with pytest.raises(ValueError, match="must not contain control characters"):
            plain_text(f"a{chr(code_point)}b")


@pytest.mark.parametrize("value", ["\u26a0\ufe0f deploy", "\u2764\ufe0e", "\u82a6\U000e0100"])
def test_text_with_a_variation_selector_is_accepted(value: str) -> None:
    assert plain_text(value) == value


# The general categories of the characters a text field refuses: controls, format characters, and line and paragraph
# separators.
REFUSED_CATEGORIES = {"Cc", "Cf", "Zl", "Zp"}
# The variation selectors, which choose how the character before them is drawn and stay accepted.
VARIATION_SELECTORS = [0x180B, 0x180C, 0x180D, 0x180F, *range(0xFE00, 0xFE10), *range(0xE0100, 0xE01F0)]


def test_text_refuses_every_control_and_format_character_the_running_unicode_tables_name() -> None:
    missed = [
        f"U+{code_point:04X}"
        for code_point in range(sys.maxunicode + 1)
        if unicodedata.category(chr(code_point)) in REFUSED_CATEGORIES
        and code_point not in VARIATION_SELECTORS
        and not CONTROL_CHARACTERS.search(chr(code_point))
    ]
    assert missed == []


def test_text_refuses_no_variation_selector() -> None:
    assert [f"U+{c:04X}" for c in VARIATION_SELECTORS if CONTROL_CHARACTERS.search(chr(c))] == []


@pytest.mark.parametrize("value", [".", "infra", "infra/payments", "a.b/c-d_e", "eu-west-1"])
def test_a_directory_path_is_the_same_directory_or_a_plain_relative_path(value: str) -> None:
    assert TypeAdapter(DirectoryPath).validate_python(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "./infra",
        "infra/",
        "infra//payments",
        "../infra",
        "infra/..",
        "infra/./payments",
        "/infra",
        "C:/infra",
        "D:infra",
        "infra\\payments",
    ],
)
def test_a_directory_path_outside_its_directory_or_not_in_its_plain_form_is_refused(value: str) -> None:
    with pytest.raises(ValidationError, match="must be '.' or a relative path with no"):
        TypeAdapter(DirectoryPath).validate_python(value)


@pytest.mark.parametrize("value", ["...", "infra/. ", "infra\u2215payments", "infra\uff0fpayments", "infra/ "])
def test_a_path_with_a_part_of_only_dots_and_spaces_or_a_look_alike_slash_is_refused(value: str) -> None:
    for path_type in (DirectoryPath, ProjectPath):
        with pytest.raises(ValidationError, match="must name each part plainly"):
            TypeAdapter(path_type).validate_python(value)


def test_an_empty_directory_path_is_refused() -> None:
    with pytest.raises(ValidationError, match="at least 1 character"):
        TypeAdapter(DirectoryPath).validate_python("")


@pytest.mark.parametrize("value", ["a" * 40, "0123456789abcdef" * 4])
def test_a_git_object_id_is_a_sha1_or_sha256_id_in_lowercase_hex(value: str) -> None:
    assert TypeAdapter(GitObjectId).validate_python(value) == value


@pytest.mark.parametrize("value", ["a" * 39, "a" * 41, "a" * 63, "a" * 65, "A" * 40, "g" * 40])
def test_a_git_object_id_of_another_length_or_not_in_lowercase_hex_is_refused(value: str) -> None:
    with pytest.raises(ValidationError, match="should match pattern"):
        TypeAdapter(GitObjectId).validate_python(value)
