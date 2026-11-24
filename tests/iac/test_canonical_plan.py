from __future__ import annotations

import base64

import pytest

from iltero_schemas.canonical import canonical_bytes, digest, digest_of
from iltero_schemas.canonical.common.run_digest_key import RunDigestKey, keyed_digest
from iltero_schemas.canonical.iac.plan import (
    KEYED_PLAN_DIGEST_VERSIONS,
    PLAN_EXCLUDED_TOP_LEVEL_KEYS,
    REDACTED_PLAN_DIGEST_VERSIONS,
    canonical_plan_bytes,
    check_plan_digest_version,
    keyed_plan_digest,
    redacted_plan_digest_of_kept,
)
from iltero_schemas.models.iac.tool_names import IAC_TOOLS

KEY = RunDigestKey.from_text("irk_" + base64.urlsafe_b64encode(bytes(32)).decode("ascii").rstrip("="))
PLAN = {"timestamp": "2026-01-01T00:00:00Z", "terraform_version": "1.14.0", "resource_changes": [{"timestamp": 1}]}


def test_plan_digest_drops_rendering_metadata_at_the_top_level_only() -> None:
    assert canonical_plan_bytes("terraform", PLAN) == b'{"resource_changes":[{"timestamp":1}]}'


def test_a_keyed_plan_digest_is_made_under_the_plan_rule_with_the_keyed_version() -> None:
    fields = {"tool": "terraform", "digest_version": "1", "plan": {"resource_changes": [{"timestamp": 1}]}}
    assert keyed_plan_digest("terraform", PLAN, KEY) == keyed_digest("iltero.plan_digest", fields, KEY)


def test_a_redacted_plan_digest_is_a_plain_digest_under_its_own_rule() -> None:
    expected = digest_of(
        {
            "rule": "iltero.redacted_plan_digest",
            "tool": "terraform",
            "digest_version": "redacted-1",
            "plan": {"resource_changes": [{"timestamp": 1}]},
        }
    )
    assert redacted_plan_digest_of_kept("terraform", PLAN) == expected
    assert expected != digest(canonical_bytes({"resource_changes": [{"timestamp": 1}]}))


def test_every_iac_tool_has_both_plan_digest_rules_with_distinct_versions() -> None:
    assert set(KEYED_PLAN_DIGEST_VERSIONS) == set(REDACTED_PLAN_DIGEST_VERSIONS) == set(PLAN_EXCLUDED_TOP_LEVEL_KEYS)
    assert set(KEYED_PLAN_DIGEST_VERSIONS) == set(IAC_TOOLS)
    assert all(KEYED_PLAN_DIGEST_VERSIONS[tool] != REDACTED_PLAN_DIGEST_VERSIONS[tool] for tool in IAC_TOOLS)


def test_a_tool_with_no_plan_digest_rule_is_refused() -> None:
    for refused in (
        lambda: canonical_plan_bytes("pulumi", {}),  # type: ignore[arg-type]
        lambda: keyed_plan_digest("pulumi", {}, KEY),  # type: ignore[arg-type]
        lambda: redacted_plan_digest_of_kept("pulumi", {}),  # type: ignore[arg-type]
    ):
        with pytest.raises(ValueError, match="no plan digest rule for this tool"):
            refused()


def test_a_digest_names_the_version_of_the_rule_it_was_made_under() -> None:
    keyed, redacted = "hmac-sha256:" + "0" * 64, "sha256:" + "0" * 64
    check_plan_digest_version("terraform", "1", keyed)
    check_plan_digest_version("terraform", "redacted-1", redacted)
    with pytest.raises(ValueError, match="a keyed plan digest names the version of the terraform keyed"):
        check_plan_digest_version("terraform", "redacted-1", keyed)
    with pytest.raises(ValueError, match="a plan digest that is not keyed names the version of the terraform redacted"):
        check_plan_digest_version("terraform", "1", redacted)
