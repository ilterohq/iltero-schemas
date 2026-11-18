"""A project's units file, as a record names it."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from iltero_schemas.models.common.units_file import MAX_UNITS, UnitsFile


def _unit(name: str, *depends_on: str) -> dict[str, object]:
    """A declared unit in the directory of its own name, depending on ``depends_on``."""
    return {"name": name, "directory": name, "depends_on": list(depends_on)}


def _units(*names: str) -> list[dict[str, object]]:
    return [_unit(name) for name in names]


FILE = {
    "path": ".iltero/units.json",
    "digest": "sha256:" + "7" * 64,
    "units": [
        _unit("network"),
        _unit("app", "network"),
    ],
}


def test_a_units_file_keeps_its_deploy_order() -> None:
    assert UnitsFile.model_validate(FILE).names == ["network", "app"]


@pytest.mark.parametrize("name", ["app", "_shared", "0net", "a" * 64, "eu_west-1"])
def test_a_unit_name_is_lowercase_letters_digits_underscores_and_hyphens(name: str) -> None:
    UnitsFile.model_validate({**FILE, "units": _units(name)})


@pytest.mark.parametrize("name", ["App", "-app", "", "a" * 65, "app.prod", "app/prod"])
def test_a_unit_name_outside_that_set_or_starting_with_a_hyphen_is_refused(name: str) -> None:
    with pytest.raises(ValidationError, match="String should"):
        UnitsFile.model_validate({**FILE, "units": _units(name)})


@pytest.mark.parametrize(
    ("units", "message"),
    [([], "at least 1"), ([f"u{index}" for index in range(MAX_UNITS + 1)], f"at most {MAX_UNITS}")],
)
def test_a_units_file_declares_at_least_one_unit_and_a_bounded_number(units: list[str], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        UnitsFile.model_validate({**FILE, "units": _units(*units)})


def test_a_unit_names_the_units_it_depends_on() -> None:
    (network, app) = UnitsFile.model_validate(FILE).units
    assert (network.depends_on, app.depends_on) == ([], ["network"])


@pytest.mark.parametrize(
    ("units", "message"),
    [
        (
            [
                _unit("network"),
                _unit("app", "database"),
            ],
            "depends only on units the units file declares",
        ),
        (
            [
                _unit("app", "network"),
                _unit("network"),
            ],
            "comes after every unit it depends on",
        ),
        ([_unit("app", "app")], "does not depend on itself"),
        (
            [
                *_units("network", "database"),
                _unit("app", "network", "database"),
            ],
            "sorted by name and name each unit once",
        ),
        (
            [*_units("network"), _unit("app", "network", "network")],
            "sorted by name and name each unit once",
        ),
    ],
    ids=["an undeclared unit", "a unit declared after it", "itself", "out of order", "twice"],
)
def test_a_unit_depends_only_on_declared_units_that_come_before_it(
    units: list[dict[str, object]], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        UnitsFile.model_validate({**FILE, "units": units})


def test_a_units_file_path_stays_inside_the_project() -> None:
    with pytest.raises(ValidationError, match="no '..'"):
        UnitsFile.model_validate({**FILE, "path": "../units.json"})


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


@pytest.mark.parametrize("directory", [".", "network", "stacks/eu-west-1/app"])
def test_a_unit_names_its_directory_relative_to_the_project(directory: str) -> None:
    units = [{"name": "app", "directory": directory, "depends_on": []}]
    assert UnitsFile.model_validate({**FILE, "units": units}).units[0].directory == directory


@pytest.mark.parametrize("directory", ["./app", "app/", "../app", "/app", "app/../db", "C:/app", "a\\b"])
def test_a_unit_directory_outside_the_project_or_not_in_its_plain_form_is_refused(directory: str) -> None:
    with pytest.raises(ValidationError, match="must be '.' or a relative path"):
        UnitsFile.model_validate({**FILE, "units": [{"name": "app", "directory": directory, "depends_on": []}]})
