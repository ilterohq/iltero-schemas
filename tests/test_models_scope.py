"""The package describes durable documents only: no request or answer a pipeline exchanges with a server.

A document stays in the contract when a record, an evaluation input or a file a
tool writes for someone else holds it. The messages of a run's exchange with a
server are that server's own API. So every model's ``apiVersion`` is one of the
contract's documents, and never one of those messages.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import Any, get_args

import pytest
from pydantic import BaseModel

import iltero_schemas
from iltero_schemas.models.car import CAR

# Every document the contract defines. A new document is added here on purpose.
DOCUMENT_API_VERSIONS = frozenset(
    {
        "iltero.io/v1",
        "iltero.io/assertion-bundle/v1",
        "iltero.io/assurance-context/v1",
        "iltero.io/car/v1",
        "iltero.io/identity-bindings/v1",
        "iltero.io/verification-report/v1",
    }
)
# The apiVersion values of the run's exchange with a server, which never return to the contract.
EXCHANGE_API_VERSIONS = frozenset(
    {
        "iltero.io/run/v1",
        "iltero.io/submission-outcome/v1",
        "iltero.io/assurance-event-batch/v1",
        "iltero.io/assurance-facts/v1",
    }
)
MODULES = sorted(info.name for info in pkgutil.walk_packages(iltero_schemas.__path__, "iltero_schemas."))


def _strings(annotation: Any) -> set[str]:
    """Every string a type accepts as a literal, through any union or ``Optional``."""
    if isinstance(annotation, str):
        return {annotation}
    return {value for arg in get_args(annotation) for value in _strings(arg)}


def _api_versions(model: type[BaseModel]) -> set[str]:
    return {
        value
        for field in model.model_fields.values()
        if field.alias == "apiVersion"
        for value in _strings(field.annotation)
    }


@pytest.mark.parametrize("name", MODULES)
def test_every_api_version_is_a_document_of_the_contract(name: str) -> None:
    module = importlib.import_module(name)
    for _, model in inspect.getmembers(module, inspect.isclass):
        if issubclass(model, BaseModel):
            versions = _api_versions(model)
            assert versions <= DOCUMENT_API_VERSIONS, f"{name}.{model.__name__}: {versions}"


def test_no_message_of_the_runs_exchange_is_a_document() -> None:
    assert not DOCUMENT_API_VERSIONS & EXCHANGE_API_VERSIONS


def test_the_check_reads_the_api_version_of_a_model() -> None:
    assert _api_versions(CAR) == {"iltero.io/car/v1"}
