"""The pins of a governed run.

The checks a run owes are one sorted set matching its digest, at least one
and a bounded number. No string of the pins can carry an identity token.
"""

from __future__ import annotations

import copy
from typing import Any, get_args

import pytest
from pydantic import ValidationError

from iltero_schemas.canonical import required_assertion_digest
from iltero_schemas.models.assertion import Stage
from iltero_schemas.models.bundle import MAX_BUNDLE_ASSERTIONS
from iltero_schemas.models.fields import RunStage
from iltero_schemas.models.run import RunPins
from tests.records import PINS

# A JSON Web Token's shape: three base64url parts joined by dots, the first two starting with ``{"``.
JWT = ".".join(("eyJhbGciOiJSUzI1NiJ9", "eyJzdWIiOiJyZXBvIn0", "c2lnbmF0dXJl"))


def _pins(required: list[dict[str, str]]) -> dict[str, Any]:
    triples = [(a["id"], a["version"], a["digest"]) for a in required]
    return {**PINS, "required_assertions": required, "required_assertion_digest": required_assertion_digest(triples)}


def test_the_vector_pins_validate() -> None:
    RunPins.model_validate(PINS)


def test_the_stages_of_a_run_are_the_lifecycle_stages_without_runtime() -> None:
    assert set(get_args(RunStage)) == {stage.value for stage in Stage} - {Stage.RUNTIME.value}


def test_the_required_digest_must_be_the_digest_of_the_required_set() -> None:
    with pytest.raises(ValidationError, match="digest of required_assertions"):
        RunPins.model_validate({**PINS, "required_assertion_digest": "sha256:" + "0" * 64})


def test_the_required_set_must_be_sorted() -> None:
    reversed_set = list(reversed(PINS["required_assertions"]))
    with pytest.raises(ValidationError, match="sorted by"):
        RunPins.model_validate(_pins(reversed_set))


def test_an_assertion_is_required_once() -> None:
    first = PINS["required_assertions"][0]
    twice = [first, {**first, "digest": "sha256:" + "9" * 64}]
    with pytest.raises(ValidationError, match="no id twice"):
        RunPins.model_validate(_pins(twice))


def test_a_run_owes_one_version_of_an_assertion() -> None:
    first = PINS["required_assertions"][0]
    with pytest.raises(ValidationError, match="no id twice"):
        RunPins.model_validate(_pins([first, {**first, "version": "2.0.0"}]))


def test_a_run_owes_at_least_one_check_and_a_bounded_number() -> None:
    with pytest.raises(ValidationError, match="at least 1"):
        RunPins.model_validate(_pins([]))
    template = PINS["required_assertions"][0]
    many = sorted(
        ({**template, "id": f"ACME.CHECK.N{index:05d}"} for index in range(MAX_BUNDLE_ASSERTIONS + 1)),
        key=lambda a: a["id"],
    )
    with pytest.raises(ValidationError, match=f"at most {MAX_BUNDLE_ASSERTIONS}"):
        RunPins.model_validate(_pins(many))


def test_a_required_assertion_names_its_document_digest() -> None:
    without = [{k: v for k, v in a.items() if k != "digest"} for a in PINS["required_assertions"]]
    with pytest.raises(ValidationError, match="digest"):
        RunPins.model_validate({**PINS, "required_assertions": without})


@pytest.mark.parametrize("environment", ["Production", "-prod", "", "p" * 51, "prod env"])
def test_an_environment_key_is_short_and_lowercase(environment: str) -> None:
    with pytest.raises(ValidationError) as refused:
        RunPins.model_validate({**PINS, "environment": environment})
    assert [error["loc"] for error in refused.value.errors()] == [("environment",)]


def _string_paths(value: Any, path: tuple[str | int, ...] = ()) -> list[tuple[str | int, ...]]:
    """Every path in ``value`` that holds a string."""
    if isinstance(value, str):
        return [path]
    if isinstance(value, dict):
        return [p for key, child in value.items() for p in _string_paths(child, (*path, key))]
    if isinstance(value, list):
        return [p for index, child in enumerate(value) for p in _string_paths(child, (*path, index))]
    return []


@pytest.mark.parametrize("path", _string_paths(PINS), ids=str)
def test_no_string_of_the_pins_can_carry_an_identity_token(path: tuple[str | int, ...]) -> None:
    changed = copy.deepcopy(PINS)
    node: Any = changed
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = JWT
    with pytest.raises(ValidationError) as refused:
        RunPins.model_validate(changed)
    # The field's own shape refused it.
    assert path in [error["loc"] for error in refused.value.errors()]
