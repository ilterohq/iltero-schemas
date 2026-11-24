"""Marks: what a tool itself says about a value."""

from __future__ import annotations

import pytest

from iltero_schemas.redaction.common.marks import Mark


def test_a_value_not_known_until_the_deployment_cannot_be_declared_sensitive() -> None:
    with pytest.raises(ValueError, match="cannot be declared sensitive"):
        Mark(("after", "arn"), "known_after_deploy", declared_sensitive=True)
