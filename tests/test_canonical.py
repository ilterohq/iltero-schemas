from __future__ import annotations

import pytest

from iltero_schemas.canonical import (
    CANONICALIZATION,
    DIGEST_PREFIX,
    INT_MAX,
    CanonicalizationError,
    canonical_bytes,
    digest,
    digest_of,
)


def test_canonical_bytes_sort_keys_and_keep_array_order() -> None:
    assert canonical_bytes({"b": [3, 1], "a": {"y": 1, "x": 2}}) == b'{"a":{"x":2,"y":1},"b":[3,1]}'


def test_integral_floats_render_as_integers() -> None:
    assert canonical_bytes({"n": 7.0}) == b'{"n":7}'


def test_digest_has_the_sha256_prefix_and_lowercase_hex() -> None:
    value = digest(b"")
    assert value == DIGEST_PREFIX + "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_digest_of_is_the_digest_of_the_canonical_bytes() -> None:
    assert digest_of({"a": 1}) == digest(canonical_bytes({"a": 1}))


@pytest.mark.parametrize(
    "value", [float("nan"), float("inf"), INT_MAX + 1, -(INT_MAX + 1), {1: "a"}, object(), {"a": b"x"}]
)
def test_values_without_a_canonical_form_are_refused(value: object) -> None:
    with pytest.raises(CanonicalizationError):
        canonical_bytes(value)


def test_canonicalization_name_is_recorded_as_rfc8785() -> None:
    assert CANONICALIZATION == "RFC8785"
