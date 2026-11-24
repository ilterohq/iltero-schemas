"""Every digest field of the contract's documents is listed under one rule, so a new field cannot go unclassified.

Plan digests are keyed per run: a plan digest field is keyed in a run the server opened and of the redacted plan in a
run the tool opened. A state digest is keyed in a run the server opened and of the redacted state in a run the tool
opened. A digest of bytes a record keeps only redacted, or never keeps, is keyed in a run the server opened
and null in a run the tool opened. Every other digest names a file the record keeps, a value it derives, a published
program or bundle, an image by its content address, a saved plan file, or a reading the server names.
"""

from __future__ import annotations

import json
import typing
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.common.context import AssuranceContext
from iltero_schemas.models.common.event import AssuranceEvent
from iltero_schemas.models.common.fields import DIGEST_PATTERN, KEYED_DIGEST_PATTERN, PLAN_DIGEST_PATTERN
from iltero_schemas.models.common.verification import VerificationReport
from iltero_schemas.models.iac.resource_identities import ResourceIdentities
from iltero_schemas.models.iac.scanner_observations import ScannerObservations
from tests.conftest import VECTORS

DOCUMENTS = (CAR, AssuranceContext, AssuranceEvent, VerificationReport, ResourceIdentities, ScannerObservations)
PATTERN_NAMES = {DIGEST_PATTERN: "plain", KEYED_DIGEST_PATTERN: "keyed", PLAN_DIGEST_PATTERN: "plan"}

# A plan's digest: keyed in a run the server opened, of the redacted plan in a run the tool opened.
PLAN_DIGESTS = {
    "AppliedPlan.digest",
    "CheckedPlan.digest",
    "Plan.digest",
    "PlanRecord.digest",
    "PlanSource.digest",
    "PostponedCheck.plan_digest",
}
# A plan's digest in the facts the server gives a run it opened: keyed only.
KEYED_PLAN_DIGESTS = {"AcceptedPlanStageRecord.plan_digest", "ApplyJobFacts.pinned_plan_digest", "RenderedPlan.digest"}
# The digest of bytes the record keeps only redacted, or never keeps: keyed in a run the server opened, null in a run
# the tool opened. ``EvidenceSource.digest`` is one only where its entry names a redaction policy; where none ran, the
# file is kept as the pipeline gave it and named by its own digest.
KEPT_REDACTED_OR_NOT_KEPT = {
    "ApplySource.digest",
    "DriftCheck.first_reading_digest",
    "DriftCheck.second_reading_digest",
    "EvidenceSource.digest",
}
# A state's digest: keyed in a run the server opened, of the redacted state in a run the tool opened; never null.
STATE_DIGESTS = {"StateSource.digest"}
# The saved plan file's digest: a file the record never keeps, recomputed by a holder of the file.
SAVED_PLAN_FILES = {
    "AcceptedPlanStageRecord.artifact_digest",
    "AppliedPlan.artifact_digest",
    "ApplyJobFacts.received_plan_file_digest",
    "Plan.artifact_digest",
    "PlanRecord.artifact_digest",
}
# The digest of a file or document the record or its kept files hold, as kept.
KEPT = {
    "AssertionIndex.digest",
    "AssertionRef.digest",
    "DeclaredIn.digest",
    "EventsFile.digest",
    "EvidenceRef.digest",
    "LocalExceptionRef.file_digest",
    "LocalExceptionsUsed.digest",
    "PlanRecord.context_digest",
    "Provenance.assertion_source_digest",
    "Provenance.compiled_digest",
    "Provenance.input_digest",
    "RedactedInput.digest",
    "RedactionPolicyRef.digest",
    "RefusedAttestation.attestation_digest",
    "ReportedRecord.digest",
    "ScannerCheckMappingUsed.digest",
    "ScannerChecksRef.digest",
    "ScannerObservations.kept_plan_digest",
    "ScannerObservations.report_digest",
    "ScannerReport.report_digest",
    # A test or scan report an image build keeps as the pipeline gave it, with nothing redacted.
    "ScanReport.file_digest",
    "ServedExceptionsUsed.digest",
    "SubjectsInScope.source_digest",
    "TestReport.file_digest",
    "UnitsFile.digest",
    "VerifiedAttestation.attestation_digest",
}
# A value derived from other values: a change, a subject, an assertion set, the contract, a record.
DERIVED = {
    "AcceptedBuild.record_digest",
    "AcceptedPlanStageRecord.change_digest",
    "AssertionsRequired.required_assertion_digest",
    "ChangeSubject.digest",
    "Compiler.contract_digest",
    "DriftCheck.change_digest",
    "ReplanCheck.change_digest",
    "EvaluatedSubject.key",
    "EventSubject.key",
    "IacChange.digest",
    "ImageChange.digest",
    "ImageDeploy.digest",
    "ImageDriftCheck.change_digest",
    "PostponedCheck.subject_key",
    "ProposedChange.digest",
    "RecordedDeployment.change_digest",
    "Subject.key",
}
# A published program, bundle, configuration or trust root, by its digest.
PUBLISHED = {
    "Bundle.content_digest",
    "Bundle.tarball_digest",
    "EvaluationLimits.capabilities_digest",
    "ExecutionBundle.capabilities_digest",
    "ExecutionBundle.content_digest",
    "ExecutionBundle.tarball_digest",
    "ExecutionEvaluator.digest",
    "OpaEvaluator.digest",
    "ScannerCheckMappingUsed.descriptor_digest",
    "ScannerObservations.configuration_digest",
    "ScannerObservations.rules_digest",
    "ScannerReport.configuration_digest",
    "ScannerReport.scanner_digest",
    "TrustRoot.digest",
}
# A container image by its content address.
IMAGES = {
    "AcceptedBuild.platform_digests",
    "CheckedImage.digest",
    "ContainerRead.digest",
    "DeployedImageRef.digest",
    "ImageArtifact.digest",
    "ImageArtifact.platform_digests",
    "ImageBuild.platform_digests",
    "ImageDeployment.digest",
    "ImageRef.digest",
    "ReportRef.image_digest",
    "ScanReport.image_digest",
    "TestReport.image_digest",
    "VerifiedAttestation.image_digest",
}
# The server's reading of a repository host, by the digest the server gives it.
SERVER_READINGS = {
    "BuildCommitNotVerifiedCommit.host_reading_digest",
    "CommitsNotReviewed.host_reading_digest",
    "CommitsReviewed.host_reading_digest",
    "EarlierReading.host_reading_digest",
    "HeadCommitBeforeReviewStartingPoint.host_reading_digest",
    "NoReviewStartingPoint.host_reading_digest",
    "ReviewStartingPointNotInHistory.host_reading_digest",
    "SourceCommitNotVerifiedCommit.host_reading_digest",
    "TooManyCommits.host_reading_digest",
}
CLASSES = (
    PLAN_DIGESTS,
    KEYED_PLAN_DIGESTS,
    KEPT_REDACTED_OR_NOT_KEPT,
    STATE_DIGESTS,
    SAVED_PLAN_FILES,
    KEPT,
    DERIVED,
    PUBLISHED,
    IMAGES,
    SERVER_READINGS,
)


def _patterns(annotation: Any, found: set[str], models: list[type[BaseModel]]) -> None:
    if typing.get_origin(annotation) is typing.Annotated:
        base, *metadata = typing.get_args(annotation)
        for item in metadata:
            for constraint in [item, *(getattr(item, "metadata", None) or [])]:
                pattern = getattr(constraint, "pattern", None)
                if pattern in PATTERN_NAMES:
                    found.add(PATTERN_NAMES[pattern])
        _patterns(base, found, models)
    elif isinstance(annotation, type) and issubclass(annotation, BaseModel):
        models.append(annotation)
    else:
        for argument in typing.get_args(annotation):
            _patterns(argument, found, models)


def _digest_fields() -> dict[str, set[str]]:
    """Every digest field reachable from the documents, as ``Model.field``, with the digest forms it accepts."""
    fields: dict[str, set[str]] = {}
    seen: set[type[BaseModel]] = set()
    todo: list[type[BaseModel]] = list(DOCUMENTS)
    while todo:
        model = todo.pop()
        if model in seen:
            continue
        seen.add(model)
        for name, info in model.model_fields.items():
            found: set[str] = set()
            models: list[type[BaseModel]] = []
            _patterns(info.annotation, found, models)
            for constraint in info.metadata:
                pattern = getattr(constraint, "pattern", None)
                if pattern in PATTERN_NAMES:
                    found.add(PATTERN_NAMES[pattern])
            if found:
                fields[f"{model.__name__}.{name}"] = found
            todo += models
    return fields


def test_every_digest_field_is_listed_under_exactly_one_rule() -> None:
    listed = [name for group in CLASSES for name in group]
    assert len(listed) == len(set(listed)), "a field is listed under two rules"
    assert set(_digest_fields()) == set(listed)


def test_a_plan_digest_field_takes_either_form_and_a_served_plan_digest_only_the_keyed_one() -> None:
    fields = _digest_fields()
    assert all(fields[name] == {"plan"} for name in PLAN_DIGESTS)
    assert all(fields[name] == {"keyed"} for name in KEYED_PLAN_DIGESTS)
    assert all(fields[name] == {"plain", "keyed"} for name in KEPT_REDACTED_OR_NOT_KEPT | STATE_DIGESTS)
    other = set(fields) - PLAN_DIGESTS - KEYED_PLAN_DIGESTS - KEPT_REDACTED_OR_NOT_KEPT - STATE_DIGESTS
    assert all(fields[name] == {"plain"} for name in other)


def _kept_redacted_or_not_kept(record: dict[str, Any]) -> list[str | None]:
    """Every digest ``record`` names of a file it keeps redacted, or never keeps: the given file digest of each register
    entry that names a redaction policy, the apply log's in the deployment, and the drift check's readings."""
    change = record["change"]
    named = [
        ref["source"]["digest"]
        for ref in record["evidence_refs"]
        if ref["source"] is not None and ref["redaction_policy"] is not None
    ]
    deployment, check = change.get("deployment"), change.get("drift_check")
    if deployment is not None and "apply" in deployment:
        named.append(deployment["apply"]["source"]["digest"])
    if check is not None and "first_reading_digest" in check:
        named += [check["first_reading_digest"], check["second_reading_digest"]]
    return named


def _states(record: dict[str, Any]) -> list[dict[str, Any]]:
    """The states ``record`` names: the deployment's, when it was read, and the identities'."""
    change = record["change"]
    deployment, identity = change.get("deployment"), change.get("identity")
    states = [deployment["apply"]["state"]] if deployment is not None and "apply" in deployment else []
    states = [state for state in states if "digest" in state]
    return states + ([identity["sources"]["state"]] if identity is not None else [])


RECORD_VECTORS = sorted(path for path in (VECTORS / "records").rglob("*.json") if path.name != "digests.json")


@pytest.mark.parametrize("path", RECORD_VECTORS, ids=lambda path: f"{path.parent.name}/{path.name}")
def test_every_record_vector_names_each_file_kept_redacted_or_not_kept_and_each_state_in_the_form_of_who_opened_its_run(
    path: Path,
) -> None:
    record = json.loads(path.read_text(encoding="utf-8"))
    named = _kept_redacted_or_not_kept(record)
    if record["governance"]["run_opened_by"] == "server":
        assert named and all(value is not None and value.startswith("hmac-sha256:") for value in named)
    else:
        assert all(value is None for value in named)
    # Each state is keyed in a run the server opened, and the digest of the redacted state in a run the tool opened.
    prefix = "hmac-sha256:" if record["governance"]["run_opened_by"] == "server" else "sha256:"
    assert all(state["digest"].startswith(prefix) for state in _states(record))
    # A file kept with nothing redacted is named by its own digest, plain.
    assert all(
        ref["source"]["digest"] is not None and ref["source"]["digest"].startswith("sha256:")
        for ref in record["evidence_refs"]
        if ref["source"] is not None and ref["redaction_policy"] is None
    )
