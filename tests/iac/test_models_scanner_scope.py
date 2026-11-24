"""What a stage's kept plan gives its scanner verdicts, and whether each resource the stage left out of scope is one
the plan shows it may leave out."""

from __future__ import annotations

from typing import Any

import pytest

from iltero_schemas.models.common.coverage import Excluded
from iltero_schemas.models.iac.scanner_scope import exclusion_holds, left_out_of_scope, plan_scope

REDACTED = {"__redacted": True, "reason": "value_shape", "present": True, "type": "string"}


def _change(address: Any, actions: list[str], unknown: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {
        "address": address,
        "mode": "managed",
        "type": "aws_s3_bucket",
        "provider_name": "registry.terraform.io/hashicorp/aws",
        "change": {"actions": actions, "after_unknown": unknown},
        **extra,
    }


def _excluded(plan_index: int, id: str | None, reason: str) -> Excluded:
    return Excluded.model_validate({"plan_index": plan_index, "id": id, "reason": reason})


def test_a_resource_left_out_for_its_identity_or_as_making_no_outside_object_leaves_a_scanner_assertion_s_scope() -> (
    None
):
    excluded = [
        _excluded(0, "data.aws_caller_identity.current", "not_managed"),
        _excluded(1, "aws_s3_bucket.old", "deposed"),
        _excluded(2, None, "identity_redacted"),
        _excluded(3, "aws_s3_bucket.x", "identity_unnameable"),
        _excluded(4, "random_id.suffix", "makes_no_outside_object"),
    ]
    assert left_out_of_scope(excluded) == frozenset({2, 3, 4})


def test_a_resource_left_out_for_its_identity_is_out_of_scope() -> None:
    plan = {
        "resource_changes": [
            _change("aws_s3_bucket.kept", ["create"], {}),
            _change("aws_s3_bucket.unnameable", ["create"], {}),
        ]
    }
    assert plan_scope(plan, frozenset()).in_scope["aws_s3_bucket"] == ["aws_s3_bucket.kept", "aws_s3_bucket.unnameable"]
    assert plan_scope(plan, frozenset({1})).in_scope["aws_s3_bucket"] == ["aws_s3_bucket.kept"]


def test_a_resource_whose_address_was_redacted_gives_nothing_to_the_scope() -> None:
    scope = plan_scope(PLAN, left_out_of_scope([_excluded(1, None, "identity_redacted")]))
    assert scope.in_scope["aws_s3_bucket"] == [
        "aws_s3_bucket.logs",
        "aws_s3_bucket.named",
        "aws_s3_bucket.null_deposed",
        "aws_s3_bucket.other_provider",
    ]
    assert "aws_s3_bucket.logs" in scope.unknown_paths


def test_a_deposed_object_never_takes_the_live_resources_unknown_paths() -> None:
    plan = {
        "resource_changes": [
            _change("aws_s3_bucket.logs", ["create"], {"policy": True}),
            _change("aws_s3_bucket.logs", ["delete"], {}, deposed="0a1b2c3d"),
        ]
    }
    assert plan_scope(plan, frozenset()).unknown_paths["aws_s3_bucket.logs"] == ["policy"]


PLAN = {
    "resource_changes": [
        _change("aws_s3_bucket.logs", ["create"], {}),
        _change(REDACTED, ["create"], {}),
        _change("aws_s3_bucket.named", ["create"], {}, provider_name=REDACTED),
        _change("aws_s3_bucket.old", ["delete"], {}, deposed="0a1b2c3d"),
        _change("aws_s3_bucket.null_deposed", ["create"], {}, deposed=None),
        {**_change("data.aws_caller_identity.current", ["read"], {}), "mode": "data"},
        _change("aws_s3_bucket.other_provider", ["create"], {}, provider_name="registry.example/Odd.Provider"),
    ]
}


@pytest.mark.parametrize(
    ("excluded", "holds"),
    [
        ((1, None, "identity_redacted"), True),
        ((2, "aws_s3_bucket.named", "identity_redacted"), True),
        ((0, "aws_s3_bucket.logs", "identity_redacted"), False),
        ((0, None, "identity_redacted"), False),
        ((1, "aws_s3_bucket.logs", "identity_redacted"), False),
        ((3, "aws_s3_bucket.old", "deposed"), True),
        ((0, "aws_s3_bucket.logs", "deposed"), False),
        ((4, "aws_s3_bucket.null_deposed", "deposed"), False),
        ((0, "aws_s3_bucket.logs", "identity_unnameable"), False),
        ((6, "aws_s3_bucket.other_provider", "identity_unnameable"), True),
        ((5, "data.aws_caller_identity.current", "not_managed"), True),
        ((0, "aws_s3_bucket.logs", "not_managed"), False),
        ((5, None, "not_managed"), False),
        ((9, None, "not_managed"), False),
    ],
    ids=[
        "redacted_address",
        "redacted_provider",
        "nothing_redacted",
        "address_left_out_although_written",
        "address_named_although_redacted",
        "deposed_object",
        "live_resource_called_deposed",
        "deposed_written_as_null",
        "nameable_resource_called_unnameable",
        "provider_with_no_short_name",
        "data_source",
        "managed_resource_called_not_managed",
        "address_left_out",
        "no_such_position",
    ],
)
def test_a_resource_left_out_of_scope_is_one_the_plan_shows_it_may_leave_out(
    excluded: tuple[int, str | None, str], holds: bool
) -> None:
    assert exclusion_holds("terraform", PLAN, _excluded(*excluded), {}, frozenset()) is holds


def test_a_resource_left_out_as_redacted_whose_plan_holds_no_redaction_marker_cannot_be_read() -> None:
    plan = {"resource_changes": [_change(0, ["create"], {})]}
    with pytest.raises(ValueError, match="neither text nor a redaction marker"):
        exclusion_holds("terraform", plan, _excluded(0, None, "identity_redacted"), {}, frozenset())


def test_a_resource_of_a_type_an_assertion_names_cannot_be_left_out_as_creating_nothing_outside_the_tool() -> None:
    change = {
        "address": "random_password.db",
        "mode": "managed",
        "type": "random_password",
        "name": "db",
        "provider_name": "registry.terraform.io/hashicorp/random",
        "change": {"actions": ["create"], "before": None, "after": {}},
    }
    plan = {
        "resource_changes": [change],
        "configuration": {"root_module": {"resources": [{"address": "random_password.db"}]}},
    }
    excluded = Excluded(plan_index=0, id="random_password.db", reason="makes_no_outside_object")
    declared = {"random_password.db": False}
    assert exclusion_holds("terraform", plan, excluded, declared, frozenset()) is True
    named = frozenset({("random", "random_password")})
    assert exclusion_holds("terraform", plan, excluded, declared, named) is False
