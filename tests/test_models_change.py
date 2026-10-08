"""A record's change and its project's units file."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from iltero_schemas.models.change import MAX_UNITS, Change, UnitsFile

FILE = {"path": ".iltero/units.json", "digest": "sha256:" + "7" * 64, "units": ["network", "app"]}


def test_a_units_file_keeps_its_deploy_order() -> None:
    assert UnitsFile.model_validate(FILE).units == ["network", "app"]


@pytest.mark.parametrize("name", ["app", "_shared", "0net", "a" * 64, "eu_west-1"])
def test_a_unit_name_is_lowercase_letters_digits_underscores_and_hyphens(name: str) -> None:
    UnitsFile.model_validate({**FILE, "units": [name]})


@pytest.mark.parametrize("name", ["App", "-app", "", "a" * 65, "app.prod", "app/prod"])
def test_a_unit_name_outside_that_set_or_starting_with_a_hyphen_is_refused(name: str) -> None:
    with pytest.raises(ValidationError, match="String should"):
        UnitsFile.model_validate({**FILE, "units": [name]})


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
    ("change", "message"),
    [
        ({"digest": None, "unit": {"name": "root", "plan": {}}}, "digest"),
        ({"digest": None}, "unit"),
        ({"digest": None, "units": [{"name": "root", "plan": {"digest": "sha256:" + "4" * 64}}]}, "unit"),
    ],
    ids=["a unit with no plan digest", "no unit", "a list of units"],
)
def test_a_change_names_one_unit_with_its_plan_digest(change: dict[str, object], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        Change.model_validate(change)


@pytest.mark.parametrize("path", ["infra/teams/x/stacks/y/.iltero/units.json", "my stack/units.json"])
def test_a_units_file_may_sit_anywhere_in_the_project(path: str) -> None:
    UnitsFile.model_validate({**FILE, "path": path})


@pytest.mark.parametrize(
    "path",
    ["/units.json", "./units.json", "a//units.json", "a\\units.json", "a/\tb", "C:/outside/units.json", "D:units.json"],
)
def test_a_units_file_path_is_a_plain_relative_path(path: str) -> None:
    with pytest.raises(ValidationError, match="relative path inside the project|control characters"):
        UnitsFile.model_validate({**FILE, "path": path})
