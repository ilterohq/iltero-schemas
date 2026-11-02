"""The shipped assertions, and the ones a runner evaluates at every post-deploy and post-verify stage."""

from __future__ import annotations

from iltero_schemas.assertions import (
    ASSERTIONS,
    BUILT_FROM_RUN_COMMIT,
    BUILT_FROM_RUN_COMMIT_ID,
    NO_DRIFT_AFTER_APPLY,
    NO_DRIFT_AFTER_APPLY_ID,
    PLAN_BINDING,
    PLAN_BINDING_ID,
)
from iltero_schemas.ast import parse
from iltero_schemas.ast.document import load_document
from iltero_schemas.models.assertion import Stage, TargetKind, TechnicalAssertion


def test_the_shipped_binding_check_is_a_post_deploy_assertion_about_the_deployment() -> None:
    assertion = parse(PLAN_BINDING.read_text(encoding="utf-8"))
    assert assertion.id == PLAN_BINDING_ID
    assert assertion.stage == Stage.POST_DEPLOY and assertion.target.kind == TargetKind.DEPLOYMENT


def test_the_shipped_drift_check_is_a_post_verify_assertion_about_the_deployment() -> None:
    assertion = parse(NO_DRIFT_AFTER_APPLY.read_text(encoding="utf-8"))
    assert assertion.id == NO_DRIFT_AFTER_APPLY_ID
    assert assertion.stage == Stage.POST_VERIFY and assertion.target.kind == TargetKind.DEPLOYMENT


def test_the_shipped_build_binding_check_compares_the_artifact_with_the_verified_commit() -> None:
    assertion = parse(BUILT_FROM_RUN_COMMIT.read_text(encoding="utf-8"))
    assert assertion.id == BUILT_FROM_RUN_COMMIT_ID and assertion.change_type == "image_release"
    assert assertion.stage == Stage.PLAN and assertion.target.kind == TargetKind.ARTIFACT
    assert "verified_source.commit" in BUILT_FROM_RUN_COMMIT.read_text(encoding="utf-8")


def test_every_shipped_assertion_parses_and_the_three_a_runner_always_evaluates_are_among_them() -> None:
    files = [entry for entry in ASSERTIONS.iterdir() if entry.name.endswith(".yaml")]
    ids = {parse(entry.read_text(encoding="utf-8")).id for entry in files}
    assert {PLAN_BINDING_ID, NO_DRIFT_AFTER_APPLY_ID, BUILT_FROM_RUN_COMMIT_ID} <= ids and len(ids) == len(files)


def test_every_shipped_assertion_suggests_an_action() -> None:
    for entry in ASSERTIONS.iterdir():
        if entry.name.endswith(".yaml"):
            model = TechnicalAssertion.model_validate(load_document(entry.read_text(encoding="utf-8")))
            assert model.metadata.remediation, entry.name
