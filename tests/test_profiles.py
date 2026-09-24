"""Profiles: one per valid combination, the path roots derived from them, `resource` only for a resource target."""

from __future__ import annotations

import pytest

from iltero_schemas.ast import allowed_roots
from iltero_schemas.models.assertion import VALID_COMBINATIONS, Stage, TargetKind
from iltero_schemas.profiles import ALWAYS, PROFILES, profile_for

# The documented table: which parts each stage provides, beyond the three every stage has.
DOCUMENTED = {
    Stage.PLAN: {"source", "change", "plan", "subject"},
    Stage.PRE_DEPLOY: {"source", "change", "plan", "subject", "evaluations", "approvals", "exceptions"},
    Stage.POST_DEPLOY: {"source", "change", "plan", "subject", "deployment"},
    Stage.POST_VERIFY: {"source", "subject", "deployment", "verification", "assurance"},
    Stage.RUNTIME: {"source", "subject", "deployment", "assurance", "exceptions"},
}


def test_every_valid_combination_has_exactly_one_profile() -> None:
    assert set(PROFILES) == {(stage, kind) for _type, stage, kind in VALID_COMBINATIONS}


@pytest.mark.parametrize("combination", sorted(PROFILES), ids=lambda c: f"{c[0].value}-{c[1].value}")
def test_every_profile_always_carries_the_envelope_and_a_subject(combination: tuple[Stage, TargetKind]) -> None:
    profile = PROFILES[combination]
    assert ALWAYS | {"subject"} <= profile.required
    assert not profile.required & profile.optional


def test_the_plan_resource_profile_is_exactly_what_a_plan_can_know() -> None:
    profile = profile_for(Stage.PLAN, TargetKind.RESOURCE)
    assert profile.name == "plan_resource"
    assert profile.required == ALWAYS | {"source", "change", "plan", "subject", "resource"}
    assert profile.optional == frozenset()


def test_resource_is_required_only_for_a_resource_target() -> None:
    assert "resource" in profile_for(Stage.POST_VERIFY, TargetKind.RESOURCE).required
    assert "resource" not in profile_for(Stage.POST_VERIFY, TargetKind.DEPLOYMENT).roots
    assert "resource" not in profile_for(Stage.PRE_DEPLOY, TargetKind.CHANGE).roots


def test_the_path_roots_are_the_documented_table() -> None:
    for (stage, kind), profile in PROFILES.items():
        expected = ALWAYS | DOCUMENTED[stage] | ({"resource"} if kind is TargetKind.RESOURCE else set())
        assert allowed_roots(stage, kind) == profile.roots == expected


def test_always_is_what_every_profile_requires() -> None:
    assert ALWAYS == {"evaluation", "context", "reference_time"}


def test_an_invalid_combination_has_no_profile() -> None:
    with pytest.raises(ValueError, match="stage 'plan' is not valid for target kind 'change'"):
        profile_for(Stage.PLAN, TargetKind.CHANGE)
