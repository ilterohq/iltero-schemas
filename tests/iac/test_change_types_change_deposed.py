"""The deposed objects an infrastructure change's apply names are those its plan stage left out as deposed."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.canonical import digest_of
from iltero_schemas.models.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.coverage import IDENTITY_REASONS
from tests.records import count_by_digest, valid_case_record

_CASE = "state_not_read_with_a_deposed_delete_left_unknown"
NOT_READ = {"__unknown": True, "reason": "state_not_read"}
# A gap left out for its identity changes the plan stage's counted outcome; these tests are about the structure.
_READER = {SKIP_INTEGRITY_CHECKS: True}


def _with(excluded: list[tuple[str | None, str]], deposed: list[tuple[str, str]]) -> dict[str, Any]:
    """The record whose plan stage also left out ``excluded``, as (address, reason), each left out for its identity
    a gap too, and whose apply names the ``deposed`` objects, as (address, key)."""
    document = valid_case_record("iac", _CASE)
    scope = document["stages"]["plan"]["coverage"]["subjects_in_scope"]
    kept = [entry for entry in scope["excluded"] if entry["reason"] != "deposed"]
    first = max(entry["plan_index"] for entry in kept) + 1
    added = [{"plan_index": first + i, "id": a, "reason": r} for i, (a, r) in enumerate(excluded)]
    scope["excluded"] = kept + added
    gaps = [{"kind": e["reason"], "plan_index": e["plan_index"]} for e in added if e["reason"] in IDENTITY_REASONS]
    document["stages"]["plan"]["coverage"]["gaps"] += gaps
    document["coverage"]["subjects_in_scope"]["excluded"] = copy.deepcopy(scope["excluded"])
    document["coverage"]["gaps"] += [{**gap, "stage": "plan"} for gap in gaps]
    apply = document["change"]["deployment"]["apply"]
    apply["tool_data"]["deposed"] = [{"address": a, "key": k, "outcome": NOT_READ} for a, k in sorted(deposed)]
    count_by_digest(document["stages"]["post_deploy"], digest_of(document["change"]["deployment"]))
    return document


def _validated(document: dict[str, Any]) -> CAR:
    return CAR.model_validate(document, context=_READER)


RETIRED = "random_id.retired"


def test_the_apply_names_the_deposed_objects_the_plan_stage_left_out_as_deposed() -> None:
    _validated(_with([(RETIRED, "deposed")], [(RETIRED, "bb9fd791")]))
    _validated(_with([(RETIRED, "deposed")] * 2, [(RETIRED, "bb9fd791"), (RETIRED, "cc0a1b2d")]))


def test_the_apply_names_every_deposed_object_the_plan_stage_left_out_as_deposed() -> None:
    with pytest.raises(ValidationError, match="the apply names every deposed object the plan stage left out as"):
        _validated(_with([(RETIRED, "deposed")] * 2, [(RETIRED, "bb9fd791")]))


def test_the_apply_names_no_deposed_object_the_plan_stage_did_not_leave_out() -> None:
    with pytest.raises(ValidationError, match="names no deposed object beyond those the plan stage left out"):
        _validated(_with([], [(RETIRED, "bb9fd791")]))


def test_two_deposed_objects_at_one_address_are_matched_by_their_count_only_since_the_plan_names_no_key() -> None:
    # The plan stage's exclusion names an address, not a key: another key at the same address passes. The resource
    # identities document's count of deposed objects remaining is the check that covers the key.
    _validated(_with([(RETIRED, "deposed")], [(RETIRED, "ee5f6a7b")]))


@pytest.mark.parametrize("reason", ["identity_redacted", "identity_unnameable"])
def test_a_resource_left_out_for_its_identity_at_an_address_may_be_a_deposed_object_there(reason: str) -> None:
    _validated(_with([(RETIRED, reason)], [(RETIRED, "bb9fd791")]))
    with pytest.raises(ValidationError, match="names no deposed object beyond those the plan stage left out"):
        _validated(_with([("random_id.other", reason)], [(RETIRED, "bb9fd791")]))


def test_the_apply_names_a_deposed_object_for_each_one_the_plan_stage_left_out_with_its_address_redacted() -> None:
    _validated(
        _with([(None, "deposed"), (RETIRED, "deposed")], [(RETIRED, "bb9fd791"), ("random_id.other", "cc0a1b2d")])
    )
    with pytest.raises(ValidationError, match="the apply names every deposed object the plan stage left out as"):
        _validated(_with([(None, "deposed"), (RETIRED, "deposed")], [(RETIRED, "bb9fd791")]))


@pytest.mark.parametrize("reason", ["identity_redacted", "identity_unnameable"])
def test_a_deposed_object_left_out_with_its_address_redacted_is_named_beside_one_left_out_for_its_identity(
    reason: str,
) -> None:
    _validated(_with([(None, "deposed"), (RETIRED, reason)], [(RETIRED, "bb9fd791")]))
    with pytest.raises(ValidationError, match="the apply names every deposed object the plan stage left out as"):
        _validated(_with([(None, "deposed"), (None, reason), (RETIRED, "deposed")], [(RETIRED, "bb9fd791")]))


def test_a_resource_left_out_whose_address_was_redacted_may_be_a_deposed_object_at_any_address() -> None:
    _validated(_with([(None, "identity_redacted")], [(RETIRED, "bb9fd791")]))
    with pytest.raises(ValidationError, match="names no deposed object beyond those the plan stage left out"):
        _validated(_with([(None, "identity_redacted")], [(RETIRED, "bb9fd791"), (RETIRED, "cc0a1b2d")]))


def test_the_deposed_objects_of_an_apply_of_a_re_plan_are_not_matched_to_the_plan_stage() -> None:
    document = _with([], [(RETIRED, "bb9fd791")])
    deployment = document["change"]["deployment"]
    deployment["plan"]["digest"] = "sha256:" + "f" * 64
    deployment["superseded_by"] = {"reason": "dependency_replanned"}
    count_by_digest(document["stages"]["post_deploy"], digest_of(deployment))
    _validated(document)


def test_a_resource_left_out_as_not_managed_is_never_a_deposed_object_even_when_its_address_was_redacted() -> None:
    with pytest.raises(ValidationError, match="names no deposed object beyond those the plan stage left out"):
        _validated(_with([(None, "not_managed")], [(RETIRED, "bb9fd791")]))
