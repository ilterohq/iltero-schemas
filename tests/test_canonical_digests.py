"""The digests of an assertion set and of a change: order-free, and every input part changes the digest."""

from __future__ import annotations

import pytest

from iltero_schemas.canonical import change_digest, required_assertion_digest

A = "sha256:" + "a" * 64
B = "sha256:" + "b" * 64


def test_the_set_digest_ignores_the_order_the_assertions_were_loaded_in() -> None:
    triples = [("ILT.B.X", "1.0.0", A), ("ILT.A.X", "1.0.0", B)]
    assert required_assertion_digest(triples) == required_assertion_digest(reversed(triples))


@pytest.mark.parametrize(
    "other",
    [("ILT.A.Y", "1.0.0", A), ("ILT.A.X", "1.0.1", A), ("ILT.A.X", "1.0.0", B)],
    ids=["id", "version", "document digest"],
)
def test_each_part_of_a_triple_changes_the_set_digest(other: tuple[str, str, str]) -> None:
    assert required_assertion_digest([("ILT.A.X", "1.0.0", A)]) != required_assertion_digest([other])


def test_the_change_digest_ignores_the_order_units_are_given_in() -> None:
    assert change_digest({"app": A, "network": B}) == change_digest({"network": B, "app": A})


def test_re_planning_one_unit_changes_the_change_digest() -> None:
    assert change_digest({"app": A, "network": B}) != change_digest({"app": A, "network": A})


def test_renaming_a_unit_changes_the_change_digest() -> None:
    assert change_digest({"app": A}) != change_digest({"root": A})


def test_a_change_of_no_units_has_no_digest() -> None:
    with pytest.raises(ValueError, match="at least one unit"):
        change_digest({})
