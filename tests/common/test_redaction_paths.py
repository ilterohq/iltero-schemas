"""Tree paths and the configured attribute paths of a redaction policy."""

from __future__ import annotations

import pytest

from iltero_schemas.redaction.common.paths import REDACTION_PATH_PATTERN, dotted, parse_path


def test_configured_paths_match_names_and_indexes_relative_to_a_resource() -> None:
    pattern = parse_path("ingress[*].cidr_blocks")
    assert pattern.matches(("ingress", 3, "cidr_blocks"))
    assert not pattern.matches(("ingress", 3))
    assert not pattern.matches(("ingress", "x", "cidr_blocks"))
    exact = parse_path("tags.owner")
    assert exact.matches(("tags", "owner")) and not exact.matches(("tags", "team"))
    indexed = parse_path("rules[1].value")
    assert indexed.matches(("rules", 1, "value")) and not indexed.matches(("rules", 2, "value"))


@pytest.mark.parametrize("text", ["", ".a", "a.", "a..b", "a[x]", "a[*", "a b", "a/b", "a[0][1]", "[*]"])
def test_paths_outside_the_grammar_are_refused(text: str) -> None:
    with pytest.raises(ValueError, match="not a redaction path"):
        parse_path(text)


def test_the_path_grammar_accepts_dotted_names_each_optionally_indexed() -> None:
    assert REDACTION_PATH_PATTERN.fullmatch("tags.owner") and REDACTION_PATH_PATTERN.fullmatch("a-b[3].c_d[*]")


def test_a_tree_path_is_written_with_dots_between_keys_and_brackets_around_indexes() -> None:
    assert dotted(("resources", 0, "after", "tags", "owner")) == "resources[0].after.tags.owner"
    assert dotted((0, "a")) == "[0].a" and dotted(()) == ""
