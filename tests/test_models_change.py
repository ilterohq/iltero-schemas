"""A record's change and its project's units file."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from iltero_schemas.models.change import MAX_UNITS, Change, UnitsFile

FILE = {"path": ".iltero/units.json", "digest": "sha256:" + "7" * 64, "units": ["network", "app"]}


def test_a_units_file_keeps_its_deploy_order() -> None:
    assert UnitsFile.model_validate(FILE).units == ["network", "app"]


@pytest.mark.parametrize(
    ("units", "message"),
    [([], "at least 1"), ([f"u{index}" for index in range(MAX_UNITS + 1)], f"at most {MAX_UNITS}")],
)
def test_a_units_file_declares_at_least_one_unit_and_a_bounded_number(units: list[str], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        UnitsFile.model_validate({**FILE, "units": units})


def test_a_units_file_path_stays_inside_the_project() -> None:
    with pytest.raises(ValidationError, match="no '..'"):
        UnitsFile.model_validate({**FILE, "path": "../units.json"})


@pytest.mark.parametrize(
    ("units", "message"),
    [([{"unit": "root", "plan": {}}], "digest"), ([], "at least 1")],
    ids=["a unit with no plan digest", "no unit"],
)
def test_a_change_names_one_unit_with_its_plan_digest(units: list[object], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        Change.model_validate({"digest": None, "units": units})


@pytest.mark.parametrize("name", ["App", "-app", "a/b", "a" * 65])
def test_a_declared_unit_is_named_in_lowercase_plain_characters(name: str) -> None:
    with pytest.raises(ValidationError, match="String should match pattern"):
        UnitsFile.model_validate({**FILE, "units": [name]})


@pytest.mark.parametrize("path", ["infra/teams/x/stacks/y/.iltero/units.json", "my stack/units.json"])
def test_a_units_file_may_sit_anywhere_in_the_project(path: str) -> None:
    UnitsFile.model_validate({**FILE, "path": path})


@pytest.mark.parametrize("path", ["/units.json", "./units.json", "a//units.json", "a\\units.json", "a/\tb"])
def test_a_units_file_path_is_a_plain_relative_path(path: str) -> None:
    with pytest.raises(ValidationError):
        UnitsFile.model_validate({**FILE, "path": path})
