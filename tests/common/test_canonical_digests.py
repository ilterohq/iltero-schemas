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


def _plan(digest: str, digest_version: str = "1") -> dict[str, str]:
    return {"kind": "plan", "digest": digest, "digest_version": digest_version, "tool": "terraform"}


def test_re_planning_one_unit_changes_the_change_digest() -> None:
    assert change_digest("iac_change", "app", "production", _plan(A)) != change_digest(
        "iac_change", "app", "production", _plan(B)
    )


def test_renaming_a_unit_changes_the_change_digest() -> None:
    assert change_digest("iac_change", "app", "production", _plan(A)) != change_digest(
        "iac_change", "root", "production", _plan(A)
    )


def test_deploying_the_same_plan_to_another_environment_changes_the_change_digest() -> None:
    production = change_digest("iac_change", "app", "production", _plan(A))
    assert production != change_digest("iac_change", "app", "staging", _plan(A))
    assert production != change_digest("iac_change", "app", None, _plan(A))


def test_the_rule_that_computed_the_plan_digest_is_part_of_the_change_digest() -> None:
    assert change_digest("iac_change", "app", "production", _plan(A)) != change_digest(
        "iac_change", "app", "production", _plan(A, "2")
    )


def test_the_change_type_is_part_of_the_change_digest() -> None:
    assert change_digest("iac_change", "app", "production", _plan(A)) != change_digest(
        "another", "app", "production", _plan(A)
    )
