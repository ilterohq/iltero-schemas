"""The package describes durable documents only: no request or answer a pipeline exchanges with a server.

A document stays in the contract when a record, an evaluation input or a file a
tool writes for someone else holds it. The messages of a run's exchange with a
server are that server's own API. So every model's ``kind`` is one of the
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
from iltero_schemas.models.common.base import API_VERSION
from iltero_schemas.models.common.car import CAR

# Every document the contract defines, by its kind; every one has the apiVersion ``API_VERSION``. A new document is
# added here on purpose.
DOCUMENT_KINDS = frozenset(
    {
        "AssertionBundleDescriptor",
        "AssuranceContext",
        "ChangeAssuranceRecord",
        "ScannerCheckMapping",
        "LocalExceptions",
        "PolicySource",
        "ResourceIdentities",
        "ScannerObservations",
        "ServedExceptions",
        "TechnicalAssertion",
        "VerificationReport",
    }
)
# The kinds of the run's exchange with a server, which never become documents of the contract.
EXCHANGE_KINDS = frozenset(
    {"RunToken", "RunClosure", "AssuranceFacts", "AssuranceEventBatch", "SubmissionOutcome", "PostDeployRefusal"}
)
MODULES = sorted(info.name for info in pkgutil.walk_packages(iltero_schemas.__path__, "iltero_schemas."))


def _strings(annotation: Any) -> set[str]:
    """Every string a type accepts as a literal, through any union or ``Optional``."""
    if isinstance(annotation, str):
        return {annotation}
    return {value for arg in get_args(annotation) for value in _strings(arg)}


def _literals(model: type[BaseModel], name: str) -> set[str]:
    return {
        value
        for field_name, field in model.model_fields.items()
        if (field.alias or field_name) == name
        for value in _strings(field.annotation)
    }


@pytest.mark.parametrize("name", MODULES)
def test_every_document_is_one_of_the_contract_by_its_api_version_and_kind(name: str) -> None:
    module = importlib.import_module(name)
    for _, model in inspect.getmembers(module, inspect.isclass):
        if issubclass(model, BaseModel) and _literals(model, "apiVersion"):
            assert _literals(model, "apiVersion") == {API_VERSION}, f"{name}.{model.__name__}"
            kinds = _literals(model, "kind")
            assert len(kinds) == 1, f"{name}.{model.__name__}: one kind"
            assert kinds <= DOCUMENT_KINDS, f"{name}.{model.__name__}: {kinds}"


def test_the_check_reads_the_api_version_and_kind_of_a_model() -> None:
    assert _literals(CAR, "apiVersion") == {"iltero.com/v1"}
    assert _literals(CAR, "kind") == {"ChangeAssuranceRecord"}


def test_no_message_of_the_runs_exchange_is_a_document() -> None:
    assert not DOCUMENT_KINDS & EXCHANGE_KINDS
