"""Profiles: one per activity and valid combination, the path roots derived from them, `resource` only for a resource
target."""

from __future__ import annotations

import pytest

from iltero_schemas.ast import allowed_roots
from iltero_schemas.change_types import ACTIVITIES
from iltero_schemas.models.assertion import COMBINATIONS, Stage, TargetKind
from iltero_schemas.models.change_type import CHANGE_TYPE_OF, ActivityName
from iltero_schemas.profiles import (
    ALWAYS_REQUIRED_PARTS,
    PROFILES,
    profile_for,
    reads_approvals,
    reads_checked_content,
    reads_server_facts,
    roots_for,
)

# The documented table: which parts each stage of an infrastructure change provides, beyond the three every stage has.
DOCUMENTED = {
    Stage.PLAN: {"source", "change", "plan", "subject"},
    Stage.PRE_DEPLOY: {"source", "change", "plan", "subject", "evaluations", "approvals", "exceptions", "run"},
    Stage.POST_DEPLOY: {"source", "change", "plan", "subject", "deployment"},
    Stage.POST_VERIFY: {"source", "subject", "deployment", "drift_check", "assurance"},
    Stage.RUNTIME: {"source", "subject", "deployment", "assurance", "exceptions"},
}
# The parts a build's input provides at its plan stage, beyond the three every stage has.
BUILD = {"source", "subject", "artifact", "tests", "scans", "verified_source"}


def test_every_activity_has_one_profile_for_each_combination_at_its_stages() -> None:
    expected = {
        (activity, stage, kind)
        for activity, change_type in CHANGE_TYPE_OF.items()
        for _type, stage, kind in COMBINATIONS[change_type]
        if stage in ACTIVITIES[activity].stages or stage is Stage.RUNTIME
    }
    assert set(PROFILES) == expected


@pytest.mark.parametrize("key", sorted(PROFILES), ids=lambda key: "-".join(str(part) for part in key))
def test_every_profile_always_carries_the_envelope_and_a_subject(key: tuple[ActivityName, Stage, TargetKind]) -> None:
    profile = PROFILES[key]
    assert ALWAYS_REQUIRED_PARTS | {"subject"} <= profile.required
    assert not profile.required & profile.optional


def test_the_plan_resource_profile_is_exactly_what_a_plan_can_know() -> None:
    profile = profile_for("iac_change", Stage.PLAN, TargetKind.RESOURCE)
    assert profile.name == "plan_resource"
    assert profile.required == ALWAYS_REQUIRED_PARTS | {"source", "change", "plan", "subject", "resource"}
    assert profile.optional == frozenset()


def test_the_plan_artifact_profile_is_exactly_what_a_build_can_know() -> None:
    profile = profile_for("image_build", Stage.PLAN, TargetKind.ARTIFACT)
    assert profile.name == "plan_artifact"
    assert profile.required == ALWAYS_REQUIRED_PARTS | BUILD
    assert profile.optional == frozenset()


def test_resource_is_required_only_for_a_resource_target() -> None:
    assert "resource" in profile_for("iac_change", Stage.RUNTIME, TargetKind.RESOURCE).required
    assert "resource" not in profile_for("iac_change", Stage.RUNTIME, TargetKind.DEPLOYMENT).roots
    assert "resource" not in profile_for("iac_change", Stage.PRE_DEPLOY, TargetKind.CHANGE).roots


def test_the_path_roots_are_the_documented_table() -> None:
    for (activity, stage, kind), profile in PROFILES.items():
        if activity != "iac_change":
            continue
        expected = ALWAYS_REQUIRED_PARTS | DOCUMENTED[stage] | ({"resource"} if kind is TargetKind.RESOURCE else set())
        assert allowed_roots("iac_change", stage, kind) == profile.roots == expected


def test_an_assertion_about_any_change_reads_what_every_activity_there_shares() -> None:
    infrastructure = profile_for("iac_change", Stage.PRE_DEPLOY, TargetKind.CHANGE).roots
    image = profile_for("image_deploy", Stage.PRE_DEPLOY, TargetKind.CHANGE).roots
    assert roots_for(None, Stage.PRE_DEPLOY, TargetKind.CHANGE) == infrastructure & image
    assert {"change", "approvals", "run"} <= infrastructure & image and "plan" not in image
    assert roots_for(None, Stage.PLAN, TargetKind.ARTIFACT) == ALWAYS_REQUIRED_PARTS | BUILD


def test_an_assertion_about_a_change_type_reads_only_its_own_activities_profiles() -> None:
    with pytest.raises(ValueError, match="stage 'plan' is not valid for target kind 'artifact'"):
        roots_for("iac_change", Stage.PLAN, TargetKind.ARTIFACT)


def test_only_a_build_reads_server_facts_at_the_plan_stage() -> None:
    assert reads_server_facts("image_build", Stage.PLAN)
    assert not reads_server_facts("iac_change", Stage.PLAN)
    assert reads_server_facts("iac_change", Stage.PRE_DEPLOY)


def test_a_build_reads_no_approvals() -> None:
    assert not reads_approvals("image_build", Stage.PLAN)
    assert reads_approvals("iac_change", Stage.PRE_DEPLOY)


@pytest.mark.parametrize(
    ("stage", "reads"),
    [
        (Stage.PLAN, {"plan", "container_image"}),
        (Stage.PRE_DEPLOY, {"plan", "container_image"}),
        (Stage.POST_DEPLOY, {"plan", "container_image"}),
        (Stage.POST_VERIFY, {None, "container_image"}),
        (Stage.RUNTIME, {None}),
    ],
)
def test_the_stages_that_read_the_checked_content(stage: Stage, reads: set[str | None]) -> None:
    assert reads_checked_content(stage) == reads


def test_always_is_what_every_profile_requires() -> None:
    assert ALWAYS_REQUIRED_PARTS == {"evaluation", "organization_scope", "reference_time"}


def test_an_invalid_combination_has_no_profile() -> None:
    with pytest.raises(ValueError, match="stage 'plan' is not valid for target kind 'change'"):
        profile_for("iac_change", Stage.PLAN, TargetKind.CHANGE)


@pytest.mark.parametrize("kind", [TargetKind.RESOURCE, TargetKind.ASSURANCE])
def test_the_post_verify_stage_has_a_profile_only_for_the_deployment(kind: TargetKind) -> None:
    with pytest.raises(ValueError, match=f"stage 'post_verify' is not valid for target kind '{kind.value}'"):
        profile_for("iac_change", Stage.POST_VERIFY, kind)
