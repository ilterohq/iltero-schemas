"""The run contract.

The pins are one sorted set matching its digest. A token expires after it was
issued. No response can carry an identity token, and no request body can either.
A run keeps one artifact store, or none, from start to end. Its prefix ends
with the run's id, its prefix and key never change, and its lock date never
moves earlier.
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
from iltero_schemas.models.fields import RunStage
from iltero_schemas.models.run import (
    API_VERSION,
    ArtifactStore,
    RunCloseResponse,
    RunOpenRequest,
    RunOpenResponse,
    RunPins,
    TokenRefreshRequest,
    TokenRefreshResponse,
    check_continues,
)
from tests.conftest import VECTORS

WIRE = VECTORS / "wire"
OPEN: dict[str, Any] = json.loads((WIRE / "run_open_response.json").read_text(encoding="utf-8"))
REFRESH: dict[str, Any] = json.loads((WIRE / "token_refresh_response.json").read_text(encoding="utf-8"))
REQUEST: dict[str, Any] = json.loads((WIRE / "run_open_request.json").read_text(encoding="utf-8"))
REFRESH_REQUEST: dict[str, Any] = json.loads((WIRE / "token_refresh_request.json").read_text(encoding="utf-8"))
CLOSE: dict[str, Any] = json.loads((WIRE / "run_close_response.json").read_text(encoding="utf-8"))
STORE: dict[str, Any] = OPEN["artifact_store"]
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
    assert RunCloseResponse.model_validate(CLOSE).api_version == API_VERSION


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
    [(RunOpenResponse, p) for p in _string_paths(OPEN)]
    + [(TokenRefreshResponse, p) for p in _string_paths(REFRESH)]
    + [(RunCloseResponse, p) for p in _string_paths(CLOSE)],
    ids=str,
)
def test_no_response_string_can_carry_an_identity_token(
    model: type[RunOpenResponse | TokenRefreshResponse | RunCloseResponse], path: tuple[str | int, ...]
) -> None:
    document = {RunOpenResponse: OPEN, TokenRefreshResponse: REFRESH, RunCloseResponse: CLOSE}[model]
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


@pytest.mark.parametrize(
    ("request_model", "body"), [(RunOpenRequest, REQUEST), (TokenRefreshRequest, REFRESH_REQUEST)], ids=str
)
def test_a_request_body_carrying_the_identity_token_is_refused(
    request_model: type[RunOpenRequest | TokenRefreshRequest], body: dict[str, Any]
) -> None:
    request_model.model_validate(body)
    with pytest.raises(ValidationError) as refused:
        request_model.model_validate({**body, "oidc_token": JWT})
    assert [(e["type"], e["loc"]) for e in refused.value.errors()] == [("extra_forbidden", ("oidc_token",))]


@pytest.mark.parametrize("model", [RunOpenResponse, TokenRefreshResponse], ids=str)
def test_a_response_names_the_ci_job_it_answered(model: type[RunOpenResponse | TokenRefreshResponse]) -> None:
    document = {k: v for k, v in (OPEN if model is RunOpenResponse else REFRESH).items() if k != "ci_identity"}
    with pytest.raises(ValidationError) as refused:
        model.model_validate(document)
    assert [(e["type"], e["loc"]) for e in refused.value.errors()] == [("missing", ("ci_identity",))]


def test_an_unknown_key_is_refused() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RunOpenRequest.model_validate({**REQUEST, "organization_id": "acme"})


@pytest.mark.parametrize("model", [RunOpenResponse, TokenRefreshResponse], ids=["open", "refresh"])
@pytest.mark.parametrize("expires_at", ["2026-09-16T18:30:00Z", "2026-09-16T18:00:00.5Z"], ids=["at", "before"])
def test_a_token_expires_after_it_was_issued(model: type[RunOpenResponse], expires_at: str) -> None:
    document = {**(OPEN if model is RunOpenResponse else REFRESH), "server_time": "2026-09-16T18:30:00Z"}
    with pytest.raises(ValidationError, match="expires after the time it was issued"):
        model.model_validate({**document, "expires_at": expires_at})


@pytest.mark.parametrize("key", ["mrk-" + "0123456789abcdef" * 2, "1234abcd-12ab-34cd-56ef-1234567890ab", None])
def test_an_artifact_store_names_a_kms_key_by_its_id_or_none(key: str | None) -> None:
    assert ArtifactStore.model_validate({**STORE, "kms_key_id": key}).kms_key_id == key


@pytest.mark.parametrize(
    "key",
    [
        "alias/evidence",
        "1234ABCD-12AB-34CD-56EF-1234567890AB",
        # A key's ARN could name a key in any account, so only the bare id is accepted. Built from its parts.
        ":".join(("arn", "aws", "kms", "eu-west-1", "1" * 12, "key/1234abcd-12ab-34cd-56ef-1234567890ab")),
    ],
)
def test_an_artifact_store_refuses_anything_else_as_a_kms_key(key: str) -> None:
    with pytest.raises(ValidationError, match="String should match pattern"):
        ArtifactStore.model_validate({**STORE, "kms_key_id": key})


def test_an_artifact_prefix_is_bounded() -> None:
    long_prefix = "s3://acme-iltero-evidence/" + "a" * 500 + "/"
    with pytest.raises(ValidationError, match="at most 512"):
        ArtifactStore.model_validate({**STORE, "uri_prefix": long_prefix})


@pytest.mark.parametrize("model", [RunOpenResponse, TokenRefreshResponse], ids=["open", "refresh"])
def test_a_response_may_name_no_artifact_store(model: type[RunOpenResponse | TokenRefreshResponse]) -> None:
    document = OPEN if model is RunOpenResponse else REFRESH
    assert model.model_validate({**document, "artifact_store": None}).artifact_store is None


def test_the_artifact_prefix_may_not_hold_an_identity_token_in_a_folder() -> None:
    prefix = f"s3://acme-iltero-evidence/{JWT}/{OPEN['run_id']}/"
    with pytest.raises(ValidationError, match="must not contain a JSON Web Token"):
        ArtifactStore.model_validate({**STORE, "uri_prefix": prefix})


def test_the_artifact_prefix_may_not_hold_the_context_key() -> None:
    prefix = f"s3://acme-iltero-evidence/{OPEN['context_key']}/{OPEN['run_id']}/"
    with pytest.raises(ValidationError, match="holds no credential"):
        RunOpenResponse.model_validate({**OPEN, "artifact_store": {**STORE, "uri_prefix": prefix}})


def _refresh(**changes: Any) -> TokenRefreshResponse:
    store = changes.pop("store", {})
    document = {**REFRESH, **changes}
    if store is not None:
        document["artifact_store"] = {**REFRESH["artifact_store"], **store}
    else:
        document["artifact_store"] = None
    return TokenRefreshResponse.model_validate(document)


def _continues(later: TokenRefreshResponse, earlier: dict[str, Any] = OPEN) -> None:
    check_continues(RunOpenResponse.model_validate(earlier), later)


def test_a_refresh_continues_the_run_it_was_issued_for() -> None:
    _continues(TokenRefreshResponse.model_validate(REFRESH))


def test_a_refresh_is_for_the_same_run() -> None:
    other = "1c9f3c52-6c1e-4d3a-9f0e-2a7d5b1c8e43"
    with pytest.raises(ValueError, match="same run"):
        _continues(_refresh(run_id=other, store={"uri_prefix": f"s3://acme-iltero-evidence/runs/{other}/"}))


def test_a_refresh_repeats_the_pins_unchanged() -> None:
    with pytest.raises(ValueError, match="pins unchanged"):
        _continues(_refresh(pins={**PINS, "environment": "staging"}))


def test_a_refresh_is_not_issued_before_the_earlier_response() -> None:
    with pytest.raises(ValueError, match="not issued before"):
        _continues(_refresh(server_time="2026-09-16T18:29:59Z"))


@pytest.mark.parametrize("claim", ["repository_id", "repository_owner_id"])
def test_a_refresh_is_for_a_job_of_the_same_repository(claim: str) -> None:
    with pytest.raises(ValueError, match="same repository and owner"):
        _continues(_refresh(ci_identity={**REFRESH["ci_identity"], claim: "42"}))


@pytest.mark.parametrize(
    "store",
    [{"uri_prefix": f"s3://acme-iltero-evidence/other/{OPEN['run_id']}/"}, {"kms_key_id": "mrk-" + "0" * 32}],
    ids=["prefix", "key"],
)
def test_the_artifact_prefix_and_key_never_change_within_a_run(store: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="prefix and key never change"):
        _continues(_refresh(store=store))


def test_the_artifact_lock_date_never_moves_earlier() -> None:
    with pytest.raises(ValueError, match="never moves earlier"):
        _continues(_refresh(store={"retention_until": "2033-09-14T18:39:59Z"}))


def test_the_artifact_lock_date_may_stay_the_same() -> None:
    _continues(_refresh(store={"retention_until": STORE["retention_until"]}))


def test_a_run_names_an_artifact_store_in_every_response_or_in_none() -> None:
    with pytest.raises(ValueError, match="in every response, or in none"):
        _continues(_refresh(store=None))
    with pytest.raises(ValueError, match="in every response, or in none"):
        _continues(TokenRefreshResponse.model_validate(REFRESH), {**OPEN, "artifact_store": None})
    _continues(_refresh(store=None), {**OPEN, "artifact_store": None})


def test_a_close_with_no_gaps_lists_none() -> None:
    closed = RunCloseResponse.model_validate({**CLOSE, "materialized_not_evaluated": 0, "not_evaluated": []})
    assert closed.not_evaluated == []


def test_a_close_names_each_check_once() -> None:
    twice = [CLOSE["not_evaluated"][0]] * 2
    with pytest.raises(ValidationError, match="no assertion twice"):
        RunCloseResponse.model_validate({**CLOSE, "materialized_not_evaluated": 2, "not_evaluated": twice})
