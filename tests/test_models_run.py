"""The run contract.

The pins are one sorted set matching its digest. A token expires after it was
issued. No response can carry an identity token.
"""

from __future__ import annotations

import copy
import json
from typing import Any, get_args

import pytest
from pydantic import ValidationError

from iltero_schemas.canonical import required_assertion_digest
from iltero_schemas.models.assertion import Stage
from iltero_schemas.models.bundle import MAX_BUNDLE_ASSERTIONS
from iltero_schemas.models.fields import OIDC_TOKEN_MAX_LENGTH, RunStage
from iltero_schemas.models.run import (
    API_VERSION,
    RunOpenRequest,
    RunOpenResponse,
    RunPins,
    TokenRefreshRequest,
    TokenRefreshResponse,
)
from tests.conftest import VECTORS

WIRE = VECTORS / "wire"
OPEN: dict[str, Any] = json.loads((WIRE / "run_open_response.json").read_text(encoding="utf-8"))
REFRESH: dict[str, Any] = json.loads((WIRE / "token_refresh_response.json").read_text(encoding="utf-8"))
REQUEST: dict[str, Any] = json.loads((WIRE / "run_open_request.json").read_text(encoding="utf-8"))
PINS: dict[str, Any] = OPEN["pins"]
# A JSON Web Token's shape: three base64url parts joined by dots, the first two starting with ``{"``.
JWT = ".".join(("eyJhbGciOiJSUzI1NiJ9", "eyJzdWIiOiJyZXBvIn0", "c2lnbmF0dXJl"))


def _pins(required: list[dict[str, str]]) -> dict[str, Any]:
    triples = [(a["id"], a["version"], a["digest"]) for a in required]
    return {**PINS, "required_assertions": required, "required_assertion_digest": required_assertion_digest(triples)}


def test_the_vectors_validate_and_name_this_api_version() -> None:
    assert RunOpenResponse.model_validate(OPEN).api_version == API_VERSION
    assert TokenRefreshResponse.model_validate(REFRESH).api_version == API_VERSION
    RunOpenRequest.model_validate(REQUEST)


def test_the_stages_of_a_run_are_the_lifecycle_stages_without_runtime() -> None:
    assert set(get_args(RunStage)) == {stage.value for stage in Stage} - {Stage.RUNTIME.value}


def test_a_refresh_repeats_the_pins_of_the_open() -> None:
    assert RunOpenResponse.model_validate(OPEN).pins == TokenRefreshResponse.model_validate(REFRESH).pins


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


def _string_paths(value: Any, path: tuple[str | int, ...] = ()) -> list[tuple[str | int, ...]]:
    """Every path in ``value`` that holds a string, other than the fixed ``apiVersion``."""
    if isinstance(value, str):
        return [] if path == ("apiVersion",) else [path]
    if isinstance(value, dict):
        return [p for key, child in value.items() for p in _string_paths(child, (*path, key))]
    if isinstance(value, list):
        return [p for index, child in enumerate(value) for p in _string_paths(child, (*path, index))]
    return []


def _set(document: dict[str, Any], path: tuple[str | int, ...], value: Any) -> dict[str, Any]:
    changed = copy.deepcopy(document)
    node: Any = changed
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return changed


@pytest.mark.parametrize(
    ("model", "path"),
    [(RunOpenResponse, p) for p in _string_paths(OPEN)] + [(TokenRefreshResponse, p) for p in _string_paths(REFRESH)],
    ids=str,
)
def test_no_response_string_can_carry_an_identity_token(
    model: type[RunOpenResponse | TokenRefreshResponse], path: tuple[str | int, ...]
) -> None:
    document = OPEN if model is RunOpenResponse else REFRESH
    with pytest.raises(ValidationError) as refused:
        model.model_validate(_set(document, path, JWT))
    assert path in [error["loc"] for error in refused.value.errors()]  # the field's own shape refused it


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("run_token", "irt_" + "A" * 42),
        ("run_token", "irs_" + "A" * 43),
        ("run_token", "irt_" + "A" * 42 + "="),
        ("context_key", "B" * 44),
        ("context_key", "B" * 42 + "+"),
    ],
)
def test_a_credential_of_the_wrong_shape_is_refused(field: str, value: str) -> None:
    with pytest.raises(ValidationError, match="String should match pattern"):
        RunOpenResponse.model_validate({**OPEN, field: value})


@pytest.mark.parametrize("stage", ["runtime", "PLAN", "deploy"])
def test_only_the_four_run_stages_are_accepted(stage: str) -> None:
    with pytest.raises(ValidationError):
        RunOpenRequest.model_validate({**REQUEST, "stage": stage})


@pytest.mark.parametrize("environment", ["Production", "-prod", "", "p" * 51, "prod env"])
def test_an_environment_key_is_short_and_lowercase(environment: str) -> None:
    with pytest.raises(ValidationError):
        RunOpenRequest.model_validate({**REQUEST, "environment": environment})


def test_the_identity_token_is_bounded() -> None:
    RunOpenRequest.model_validate({**REQUEST, "oidc_token": "t" * OIDC_TOKEN_MAX_LENGTH})
    for value in ("", "t" * (OIDC_TOKEN_MAX_LENGTH + 1)):
        with pytest.raises(ValidationError):
            TokenRefreshRequest.model_validate({"stage": "plan", "oidc_token": value})


def test_an_unknown_key_is_refused() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RunOpenRequest.model_validate({**REQUEST, "organization_id": "acme"})


@pytest.mark.parametrize("model", [RunOpenResponse, TokenRefreshResponse], ids=["open", "refresh"])
@pytest.mark.parametrize("expires_at", ["2026-09-16T18:30:00Z", "2026-09-16T18:00:00.5Z"], ids=["at", "before"])
def test_a_token_expires_after_it_was_issued(model: type[RunOpenResponse], expires_at: str) -> None:
    document = {**(OPEN if model is RunOpenResponse else REFRESH), "server_time": "2026-09-16T18:30:00Z"}
    with pytest.raises(ValidationError, match="expires after the time it was issued"):
        model.model_validate({**document, "expires_at": expires_at})
