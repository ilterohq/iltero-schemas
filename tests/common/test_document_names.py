"""Every document names itself by one apiVersion and its kind, and a reader accepts exactly its own pair.

A document handed to the model of another document, a document under a name it
had before, and a name that only starts or ends like the right one are refused
by the name alone.
"""

from __future__ import annotations

import importlib
import json
from typing import Any, get_args

import pytest
from pydantic import BaseModel, ValidationError

from iltero_schemas.ast.document import load_document
from iltero_schemas.models.common.assertion import TechnicalAssertion
from iltero_schemas.models.common.base import API_VERSION
from iltero_schemas.models.common.bundle import BUNDLE_KIND, BundleDescriptor
from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.common.context import AssuranceContext
from iltero_schemas.models.common.event import EVENTS_FILE_KIND
from iltero_schemas.models.common.local_exceptions import LocalExceptions
from iltero_schemas.models.common.policy_source import PolicySource
from iltero_schemas.models.common.served_exceptions import ServedExceptions
from iltero_schemas.models.common.verification import VerificationReport
from iltero_schemas.models.iac.resource_identities import ResourceIdentities
from iltero_schemas.models.iac.scanner_check_mapping import ScannerCheckMapping
from iltero_schemas.models.iac.scanner_observations import ScannerObservations
from iltero_schemas.trust import TRUST_FILE_KIND
from tests.common.test_models_bundle import DESCRIPTOR
from tests.common.test_models_policy_source import CHANGE, _source
from tests.conftest import STARTER_ASSERTIONS, VECTORS
from tests.exceptions import FILE


def _vector(path: str) -> dict[str, Any]:
    document: dict[str, Any] = json.loads((VECTORS / path).read_text(encoding="utf-8"))
    return document


# Each document's model, a valid document of it, and the name it had before.
DOCUMENTS: list[tuple[type[BaseModel], dict[str, Any], str]] = [
    (CAR, _vector("records/iac/local_run.json"), "iltero.io/car/v1"),
    (AssuranceContext, _vector("contexts/iac/plan_resource.json"), "iltero.io/assurance-context/v1"),
    (VerificationReport, _vector("reports/iac/verification_report.json"), "iltero.io/verification-report/v1"),
    (ResourceIdentities, _vector("identities/resource_identities.json"), "iltero.io/resource-identities/v1"),
    (
        ScannerObservations,
        _vector("scanner_observations/iac/cloudtrail_checkov.json"),
        "iltero.io/scanner-observations/v1",
    ),
    (ScannerCheckMapping, _vector("scanner_check_mappings/iac/payments.json"), "iltero.io/v1"),
    (
        TechnicalAssertion,
        load_document(
            (STARTER_ASSERTIONS / "ILT.IAC.RESOURCE.AWS.RDS.STORAGE_ENCRYPTED.yaml").read_text(encoding="utf-8")
        ),
        "iltero.io/v1",
    ),
    (BundleDescriptor, DESCRIPTOR, "iltero.io/assertion-bundle/v1"),
    (LocalExceptions, FILE, "iltero.io/local-exceptions/v1"),
    (PolicySource, _source(CHANGE), "iltero.io/v1"),
    (ServedExceptions, _vector("served_exceptions/plan.json"), "iltero.io/v1"),
]
IDS = [model.__name__ for model, _, _ in DOCUMENTS]
# Every kind of the contract, the documents without a model of their own too: the bundle's description inside its
# manifest, the trust file and a stage's events file.
KINDS = {document["kind"] for _, document, _ in DOCUMENTS} | {BUNDLE_KIND, TRUST_FILE_KIND, EVENTS_FILE_KIND}
# The documents whose fixed facts are kept in a metadata block.
WITH_METADATA = [(model, document) for model, document, _ in DOCUMENTS if "metadata" in document]


@pytest.mark.parametrize(("model", "document", "old"), DOCUMENTS, ids=IDS)
def test_a_documents_module_names_its_kind_and_api_version_as_its_model_does(
    model: type[BaseModel], document: dict[str, Any], old: str
) -> None:
    module = importlib.import_module(model.__module__)
    assert get_args(model.model_fields["kind"].annotation) == (module.KIND,)
    assert get_args(model.model_fields["api_version"].annotation) == (API_VERSION,)
    assert getattr(module, "API_VERSION", API_VERSION) == API_VERSION


def test_no_two_documents_share_a_kind() -> None:
    kinds = [document["kind"] for _, document, _ in DOCUMENTS] + [BUNDLE_KIND, TRUST_FILE_KIND, EVENTS_FILE_KIND]
    assert len(set(kinds)) == len(kinds)


@pytest.mark.parametrize(("model", "document"), WITH_METADATA, ids=[m.__name__ for m, _ in WITH_METADATA])
@pytest.mark.parametrize("extra", ["labels", "annotations", "server_id"])
def test_a_documents_metadata_holds_its_fixed_facts_and_nothing_else(
    model: type[BaseModel], document: dict[str, Any], extra: str
) -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        model.model_validate({**document, "metadata": {**document["metadata"], extra: {}}})


@pytest.mark.parametrize(("model", "document", "old"), DOCUMENTS, ids=IDS)
def test_a_document_validates_under_the_one_api_version_and_its_kind(
    model: type[BaseModel], document: dict[str, Any], old: str
) -> None:
    assert document["apiVersion"] == API_VERSION
    model.model_validate(document)


@pytest.mark.parametrize(("model", "document", "old"), DOCUMENTS, ids=IDS)
def test_a_document_under_the_name_it_had_before_is_refused(
    model: type[BaseModel], document: dict[str, Any], old: str
) -> None:
    with pytest.raises(ValidationError, match="apiVersion"):
        model.model_validate({**document, "apiVersion": old})


@pytest.mark.parametrize(("model", "document", "old"), DOCUMENTS, ids=IDS)
@pytest.mark.parametrize("version", [API_VERSION + " ", "x" + API_VERSION, API_VERSION.upper(), "iltero.com/v2"])
def test_only_the_exact_api_version_is_accepted(
    model: type[BaseModel], document: dict[str, Any], old: str, version: str
) -> None:
    with pytest.raises(ValidationError, match="apiVersion"):
        model.model_validate({**document, "apiVersion": version})


@pytest.mark.parametrize(("model", "document", "old"), DOCUMENTS, ids=IDS)
def test_a_document_without_its_kind_is_refused(model: type[BaseModel], document: dict[str, Any], old: str) -> None:
    with pytest.raises(ValidationError, match="kind"):
        model.model_validate({key: value for key, value in document.items() if key != "kind"})


@pytest.mark.parametrize(("model", "document", "old"), DOCUMENTS, ids=IDS)
def test_a_document_naming_another_kind_is_refused(model: type[BaseModel], document: dict[str, Any], old: str) -> None:
    for kind in sorted(KINDS - {document["kind"]}) + [document["kind"].lower(), document["kind"] + "s"]:
        with pytest.raises(ValidationError, match="kind"):
            model.model_validate({**document, "kind": kind})


@pytest.mark.parametrize(("model", "document", "old"), DOCUMENTS, ids=IDS)
def test_a_document_handed_to_another_documents_model_is_refused_by_its_kind(
    model: type[BaseModel], document: dict[str, Any], old: str
) -> None:
    for other, _, _ in DOCUMENTS:
        if other is not model:
            with pytest.raises(ValidationError) as refused:
                other.model_validate(document)
            assert any(error["loc"] == ("kind",) for error in refused.value.errors())
