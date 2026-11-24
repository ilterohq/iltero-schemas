"""The version a digest of a tool's file names, read from the table its form picks."""

from __future__ import annotations

import pytest

from iltero_schemas.canonical.common.digest_versions import check_digest_version

KEYED = {"terraform": "1"}
REDACTED = {"terraform": "redacted-1"}
PLAIN_DIGEST = "sha256:" + "a" * 64
KEYED_DIGEST = "hmac-sha256:" + "a" * 64


def test_each_form_names_the_version_of_its_own_table() -> None:
    check_digest_version("plan", KEYED, REDACTED, "terraform", "1", KEYED_DIGEST)
    check_digest_version("plan", KEYED, REDACTED, "terraform", "redacted-1", PLAIN_DIGEST)


def test_a_keyed_digest_under_the_redacted_version_is_refused() -> None:
    with pytest.raises(ValueError, match="a keyed state digest names the version of the terraform keyed state"):
        check_digest_version("state", KEYED, REDACTED, "terraform", "redacted-1", KEYED_DIGEST)


def test_a_plain_digest_under_the_keyed_version_is_refused() -> None:
    with pytest.raises(ValueError, match="a plan digest that is not keyed names the version of the terraform redacted"):
        check_digest_version("plan", KEYED, REDACTED, "terraform", "1", PLAIN_DIGEST)


@pytest.mark.parametrize("named_digest", [KEYED_DIGEST, PLAIN_DIGEST], ids=["keyed", "plain"])
def test_a_tool_missing_from_the_tables_is_refused(named_digest: str) -> None:
    with pytest.raises(ValueError, match="names the version of the pulumi"):
        check_digest_version("state", KEYED, REDACTED, "pulumi", "1", named_digest)
