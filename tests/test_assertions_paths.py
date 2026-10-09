"""The shipped assertions, and the one a runner evaluates at every post-deploy stage."""

from __future__ import annotations

from iltero_schemas.assertions import ASSERTIONS, PLAN_BINDING, PLAN_BINDING_ID
from iltero_schemas.ast import parse
from iltero_schemas.models.assertion import Stage, TargetKind


def test_the_shipped_binding_check_is_a_post_deploy_assertion_about_the_deployment() -> None:
    assertion = parse(PLAN_BINDING.read_text(encoding="utf-8"))
    assert assertion.id == PLAN_BINDING_ID
    assert assertion.stage == Stage.POST_DEPLOY and assertion.target.kind == TargetKind.DEPLOYMENT


def test_every_shipped_assertion_parses_and_the_binding_check_is_one_of_them() -> None:
    files = [entry for entry in ASSERTIONS.iterdir() if entry.name.endswith(".yaml")]
    ids = {parse(entry.read_text(encoding="utf-8")).id for entry in files}
    assert PLAN_BINDING_ID in ids and len(ids) == len(files)
