"""A record's change and its project's units file."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from iltero_schemas.models.change import MAX_UNITS, UnitsFile

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
