"""A state's digest: keyed in a run the server opened, of the redacted state in a run the tool opened, each rule with
its own versions, and without the tool's version keys."""

from __future__ import annotations

import pytest

from iltero_schemas.canonical import digest_of
from iltero_schemas.canonical.common.run_digest_key import REDACTED_STATE_DIGEST_RULE
from iltero_schemas.canonical.iac.plan import KEYED_PLAN_DIGEST_VERSIONS, REDACTED_PLAN_DIGEST_VERSIONS
from iltero_schemas.canonical.iac.state import (
    KEYED_STATE_DIGEST_VERSIONS,
    REDACTED_STATE_DIGEST_VERSIONS,
    STATE_EXCLUDED_TOP_LEVEL_KEYS,
    canonical_redacted_state_bytes,
    check_state_digest_version,
    redacted_state_digest_of_kept,
)
from iltero_schemas.models.iac.tool_names import IAC_TOOLS

PLAIN = "sha256:" + "a" * 64
KEYED = "hmac-sha256:" + "a" * 64
STATE = {"format_version": "1.0", "terraform_version": "1.14.0", "values": {"outputs": {"terraform_version": {}}}}


def test_every_iac_tool_has_a_rule_and_a_version_in_each_table() -> None:
    assert set(STATE_EXCLUDED_TOP_LEVEL_KEYS) == set(KEYED_STATE_DIGEST_VERSIONS) == set(IAC_TOOLS)
    assert set(REDACTED_STATE_DIGEST_VERSIONS) == set(IAC_TOOLS)


def test_the_two_tables_name_distinct_versions_so_a_tool_and_a_version_name_one_rule() -> None:
    for tool in IAC_TOOLS:
        assert KEYED_STATE_DIGEST_VERSIONS[tool] != REDACTED_STATE_DIGEST_VERSIONS[tool]
        # The state's versions are those of the plan's rules of the same form, so one version names one form.
        assert KEYED_STATE_DIGEST_VERSIONS[tool] == KEYED_PLAN_DIGEST_VERSIONS[tool]
        assert REDACTED_STATE_DIGEST_VERSIONS[tool] == REDACTED_PLAN_DIGEST_VERSIONS[tool]


def test_a_redacted_state_digest_is_a_plain_digest_under_its_own_rule_without_the_version_keys() -> None:
    expected = digest_of(
        {
            "rule": REDACTED_STATE_DIGEST_RULE,
            "tool": "terraform",
            "digest_version": "redacted-1",
            "state": {"values": {"outputs": {"terraform_version": {}}}},
        }
    )
    assert REDACTED_STATE_DIGEST_RULE == "iltero.redacted_state_digest"
    assert redacted_state_digest_of_kept("terraform", STATE) == expected


def test_the_version_keys_are_left_out_at_the_top_level_only() -> None:
    assert b'"terraform_version":{}' in canonical_redacted_state_bytes("terraform", STATE)
    assert b'"format_version"' not in canonical_redacted_state_bytes("terraform", STATE)


def test_a_state_written_by_another_version_of_the_tool_has_the_same_digest() -> None:
    other = {**STATE, "format_version": "1.1", "terraform_version": "1.9.8"}
    assert redacted_state_digest_of_kept("terraform", other) == redacted_state_digest_of_kept("terraform", STATE)


def test_a_tool_with_no_state_digest_rule_is_refused() -> None:
    with pytest.raises(ValueError, match="no state digest rule for this tool"):
        redacted_state_digest_of_kept("pulumi", STATE)  # type: ignore[arg-type]


@pytest.mark.parametrize(("digest", "version"), [(KEYED, "1"), (PLAIN, "redacted-1")], ids=["keyed", "redacted"])
def test_a_state_digest_names_the_version_of_the_rule_its_form_names(digest: str, version: str) -> None:
    check_state_digest_version("terraform", version, digest)


@pytest.mark.parametrize(
    ("digest", "version", "message"),
    [
        (KEYED, "redacted-1", "a keyed state digest names the version of the terraform keyed state digest rule"),
        (PLAIN, "1", "a state digest that is not keyed names the version of the terraform redacted state digest rule"),
        (PLAIN, "redacted-2", "a state digest that is not keyed names the version of the terraform redacted state"),
    ],
    ids=["keyed under the redacted version", "plain under the keyed version", "an unknown version"],
)
def test_a_state_digest_under_another_version_is_refused(digest: str, version: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        check_state_digest_version("terraform", version, digest)
