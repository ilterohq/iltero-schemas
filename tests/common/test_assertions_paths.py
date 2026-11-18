"""The shipped assertions, and the ones a runner evaluates at every post-deploy and post-verify stage."""

from __future__ import annotations

from typing import Any

from iltero_schemas.assertions import (
    APPLIED_PLAN_MATCHES_EVALUATED_PLAN,
    APPLIED_PLAN_MATCHES_EVALUATED_PLAN_ID,
    ASSERTIONS,
    BUILD_COMMIT_MATCHES_VERIFIED_COMMIT,
    BUILD_COMMIT_MATCHES_VERIFIED_COMMIT_ID,
    NO_DRIFT_AFTER_APPLY,
    NO_DRIFT_AFTER_APPLY_ID,
)
from iltero_schemas.assertions.paths import BUILT_IN_IDS, NOT_DECIDED_BY_SCANNERS
from iltero_schemas.ast import parse, to_json
from iltero_schemas.ast.document import load_document
from iltero_schemas.models.common.assertion import Stage, TargetKind, TechnicalAssertion
from iltero_schemas.profiles.stage import SERVER_FACTS


def test_the_shipped_match_check_is_a_post_deploy_assertion_about_the_deployment() -> None:
    assertion = parse(APPLIED_PLAN_MATCHES_EVALUATED_PLAN.read_text(encoding="utf-8"))
    assert assertion.id == APPLIED_PLAN_MATCHES_EVALUATED_PLAN_ID
    assert assertion.stages == (Stage.POST_DEPLOY,) and assertion.target.kind == TargetKind.DEPLOYMENT


def test_the_shipped_drift_check_is_a_post_verify_assertion_about_the_deployment() -> None:
    assertion = parse(NO_DRIFT_AFTER_APPLY.read_text(encoding="utf-8"))
    assert assertion.id == NO_DRIFT_AFTER_APPLY_ID
    assert assertion.stages == (Stage.POST_VERIFY,) and assertion.target.kind == TargetKind.DEPLOYMENT


def test_the_shipped_build_match_check_compares_the_artifact_with_the_verified_commit() -> None:
    assertion = parse(BUILD_COMMIT_MATCHES_VERIFIED_COMMIT.read_text(encoding="utf-8"))
    assert assertion.id == BUILD_COMMIT_MATCHES_VERIFIED_COMMIT_ID and assertion.change_type == "image_release"
    assert assertion.stages == (Stage.PLAN,) and assertion.target.kind == TargetKind.ARTIFACT
    assert "verified_source.commit" in BUILD_COMMIT_MATCHES_VERIFIED_COMMIT.read_text(encoding="utf-8")


def test_every_shipped_assertion_parses_and_the_three_a_runner_always_evaluates_are_among_them() -> None:
    files = [entry for entry in ASSERTIONS.iterdir() if entry.name.endswith(".yaml")]
    ids = {parse(entry.read_text(encoding="utf-8")).id for entry in files}
    assert {
        APPLIED_PLAN_MATCHES_EVALUATED_PLAN_ID,
        NO_DRIFT_AFTER_APPLY_ID,
        BUILD_COMMIT_MATCHES_VERIFIED_COMMIT_ID,
    } <= ids and len(ids) == len(files)


def test_every_shipped_assertion_suggests_an_action() -> None:
    for entry in ASSERTIONS.iterdir():
        if entry.name.endswith(".yaml"):
            model = TechnicalAssertion.model_validate(load_document(entry.read_text(encoding="utf-8")))
            assert model.metadata.remediation, entry.name


def _roots(node: Any) -> set[str]:
    """The input parts a syntax tree reads: the first name of every path, list and reference in it."""
    if isinstance(node, list):
        return {root for item in node for root in _roots(item)}
    if not isinstance(node, dict):
        return set()
    roots = set()
    for key, value in node.items():
        if key in ("path", "in", "ref") and isinstance(value, str):
            roots.add(value.split(".")[0])
        else:
            roots |= _roots(value)
    return roots


def test_no_scanner_stands_for_an_assertion_every_run_evaluates_or_that_reads_server_facts() -> None:
    reading = set()
    for path in ASSERTIONS.iterdir():
        if path.name.endswith(".yaml"):
            assertion = parse(path.read_text(encoding="utf-8"))
            if _roots(to_json(assertion)) & SERVER_FACTS:
                reading.add(assertion.id)
    assert NOT_DECIDED_BY_SCANNERS == BUILT_IN_IDS | reading
