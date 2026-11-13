from __future__ import annotations

import pytest

from iltero_schemas.canonical import digest
from iltero_schemas.canonical.iac.plan import (
    PLAN_DIGEST_VERSIONS,
    PLAN_EXCLUDED_TOP_LEVEL_KEYS,
    canonical_plan_bytes,
    check_plan_digest_version,
    plan_digest,
)
from iltero_schemas.models.iac.tool_names import IAC_TOOLS


def test_plan_digest_drops_rendering_metadata_at_the_top_level_only() -> None:
    plan = {"timestamp": "2026-01-01T00:00:00Z", "terraform_version": "1.14.0", "resource_changes": [{"timestamp": 1}]}
    assert canonical_plan_bytes("terraform", plan) == b'{"resource_changes":[{"timestamp":1}]}'
    assert plan_digest("terraform", plan) == digest(b'{"resource_changes":[{"timestamp":1}]}')
    assert plan_digest("terraform", {}) == digest(b"{}")


def test_every_iac_tool_has_a_plan_digest_rule() -> None:
    assert set(PLAN_DIGEST_VERSIONS) == set(PLAN_EXCLUDED_TOP_LEVEL_KEYS) == set(IAC_TOOLS)


def test_a_tool_with_no_plan_digest_rule_is_refused() -> None:
    with pytest.raises(ValueError, match="no plan digest rule for this tool"):
        plan_digest("pulumi", {})  # type: ignore[arg-type]


def test_a_digest_version_other_than_the_tools_is_refused() -> None:
    check_plan_digest_version("terraform", "1")
    with pytest.raises(ValueError, match="is not the version of the terraform plan digest rule"):
        check_plan_digest_version("terraform", "2")
