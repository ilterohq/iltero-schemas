"""The ``image_build`` activity of the ``image_release`` change type: its declaration, its record body and the rules
of its records."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.assertions import (
    APPLIED_PLAN_MATCHES_EVALUATED_PLAN_ID,
    BUILD_COMMIT_MATCHES_VERIFIED_COMMIT_ID,
    NO_DRIFT_AFTER_APPLY_ID,
    SIGNED_PROVENANCE_MATCHES_RUN_ID,
)
from iltero_schemas.canonical import digest_of
from iltero_schemas.change_types import (
    CHANGE_TYPES,
    IAC_CHANGE,
    IMAGE_BUILD,
    IMAGE_DEPLOY,
    ImageBuild,
    ScanCoverage,
    check_attestation_outcome,
    check_build_metadata,
    scan_coverage,
)
from iltero_schemas.models.assertion import Stage
from iltero_schemas.models.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.checked_content import CheckedImage
from iltero_schemas.models.server_facts import AttestationNotSent, VerifiedAttestation
from tests.conftest import VECTORS
from tests.records import RECORD

BUILD: dict[str, Any] = json.loads((VECTORS / "records" / "image" / "local_run_build.json").read_text(encoding="utf-8"))
# The evaluation input the record's report check read, as its evidence register keeps it.
BUILD_INPUT: dict[str, Any] = json.loads(
    (VECTORS / "contexts" / "image" / "plan_artifact.json").read_text(encoding="utf-8")
)


def test_an_image_release_is_a_build_then_a_deploy() -> None:
    assert CHANGE_TYPES["image_release"].activities == (IMAGE_BUILD, IMAGE_DEPLOY)
    assert IMAGE_BUILD.change_type == IMAGE_DEPLOY.change_type == "image_release"
    assert (IMAGE_BUILD.name, IMAGE_DEPLOY.name) == ("image_build", "image_deploy")


def test_a_build_is_a_build_run_checked_at_its_plan_stage_only() -> None:
    assert IMAGE_BUILD.run_type == "build"
    assert IMAGE_BUILD.stages == (Stage.PLAN,)
    assert IMAGE_BUILD.project_may_leave_out == IMAGE_BUILD.environment_policy_may_leave_out == frozenset()
    assert IMAGE_BUILD.not_supported(CAR.model_validate(BUILD)) == frozenset()


def test_a_build_owes_its_record_and_its_raw_index_and_no_other_file() -> None:
    assert dict(IMAGE_BUILD.required_documents) == {Stage.PLAN: ("record",)}
    car = CAR.model_validate(BUILD)
    assert isinstance(car.change, ImageBuild)
    assert {stage: dict(named) for stage, named in IMAGE_BUILD.named_documents(car).items()} == {
        Stage.PLAN: {"image_index": ("plan/image-index.json",)}
    }


def test_a_build_that_names_no_file_owes_only_its_record() -> None:
    change = copy.deepcopy(BUILD["change"])
    change.update(platform_digests=[], index_evidence_ref=None, reports=[], build_commit=None)
    change["image"]["tag_resolution"] = None
    car = CAR.model_construct(**{**BUILD, "change": ImageBuild.model_validate(change)})
    assert dict(IMAGE_BUILD.named_documents(car)[Stage.PLAN]) == {}


def test_each_activity_names_the_check_that_binds_its_evaluations() -> None:
    assert IMAGE_BUILD.carried_out_matches_checked == (BUILD_COMMIT_MATCHES_VERIFIED_COMMIT_ID, Stage.PLAN)
    assert IAC_CHANGE.carried_out_matches_checked == (APPLIED_PLAN_MATCHES_EVALUATED_PLAN_ID, Stage.POST_DEPLOY)
    for activity in (IMAGE_BUILD, IAC_CHANGE):
        assertion_id, stage = activity.carried_out_matches_checked
        assert activity.always_evaluated[stage] == assertion_id
    assert dict(IAC_CHANGE.always_evaluated) == {
        Stage.POST_DEPLOY: APPLIED_PLAN_MATCHES_EVALUATED_PLAN_ID,
        Stage.POST_VERIFY: NO_DRIFT_AFTER_APPLY_ID,
    }


def test_every_report_a_build_record_keeps_names_the_file_the_pipeline_gave() -> None:
    car = CAR.model_validate(BUILD)
    assert isinstance(car.change, ImageBuild) and car.change.reports
    refs = {ref.ref_id: ref for ref in car.evidence_refs}
    kept = {}
    for report in car.change.reports:
        source = refs[report.evidence_ref].source
        assert source is not None
        kept[source.digest] = report.image_digest_source
    read = {
        report["file_digest"]: report["image_digest_source"] for report in BUILD_INPUT["tests"] + BUILD_INPUT["scans"]
    }
    assert read.items() <= kept.items()


def test_the_build_commit_is_the_one_its_metadata_file_names_for_its_image() -> None:
    car = CAR.model_validate(BUILD)
    assert isinstance(car.change, ImageBuild) and car.change.build_commit is not None
    stored = next(ref for ref in car.evidence_refs if ref.ref_id == car.change.build_commit.evidence_ref)
    assert stored.redaction_policy is None and stored.source is not None and stored.source.digest == stored.digest
    assert BUILD_INPUT["artifact"]["build_commit"] == car.change.build_commit.commit


def test_the_checked_content_of_a_build_is_its_image() -> None:
    car = CAR.model_validate(BUILD)
    checked = IMAGE_BUILD.checked_content(car)
    assert isinstance(checked, CheckedImage) and isinstance(car.change, ImageBuild)
    assert (checked.repository, checked.digest) == (car.change.image.repository, car.change.image.digest)


def test_a_build_has_no_change_digest_and_nothing_to_approve() -> None:
    car = CAR.model_validate(BUILD)
    assert "digest" not in ImageBuild.model_fields
    assert IMAGE_BUILD.change_digest_problems(car) == IMAGE_BUILD.integrity_problems(car) == []
    assert car.stages[Stage.PLAN].approvals is None


def test_a_local_build_is_undecided_until_a_server_verifies_its_commit() -> None:
    car = CAR.model_validate(BUILD)
    statuses = {event.assertion.id: event.evaluation.status for event in car.events}
    assert statuses["ILT.IMAGE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT"] == "unknown"
    assert car.verdict.value == "indeterminate" and car.complete


def _with_provenance_event(status: str, reason: str | None) -> dict[str, Any]:
    """The local build record with its scan check's event made the signed provenance check's, of ``status``."""
    record = copy.deepcopy(BUILD)
    (event,) = [event for event in record["events"] if event["assertion"]["id"] == "ILT.IMAGE.SCAN_RAN"]
    event["assertion"]["id"] = SIGNED_PROVENANCE_MATCHES_RUN_ID
    event["evaluation"].update(status=status, status_reason=reason)
    for coverage in (record["coverage"], record["stages"]["plan"]["coverage"]):
        counted = coverage["subjects_per_assertion"]
        counted[f"{SIGNED_PROVENANCE_MATCHES_RUN_ID}@1.0.0"] = counted.pop("ILT.IMAGE.SCAN_RAN@1.0.0")
    return record


@pytest.mark.parametrize(
    ("status", "reason"), [("pass", None), ("fail", None), ("not_applicable", "when_guard_excluded")]
)
def test_a_local_build_never_decides_its_signed_provenance(status: str, reason: str | None) -> None:
    with pytest.raises(ValidationError, match="never pass, fail or not_applicable, on a run the tool opened"):
        CAR.model_validate(_with_provenance_event(status, reason), context={SKIP_INTEGRITY_CHECKS: True})


def test_a_local_build_leaves_its_signed_provenance_unknown_for_want_of_the_servers_facts() -> None:
    CAR.model_validate(
        _with_provenance_event("unknown", "server_facts_unavailable"), context={SKIP_INTEGRITY_CHECKS: True}
    )
    with pytest.raises(ValidationError, match="is unknown with reason server_facts_unavailable"):
        CAR.model_validate(_with_provenance_event("unknown", "path_missing"), context={SKIP_INTEGRITY_CHECKS: True})


def _opened_by_server(record: dict[str, Any]) -> dict[str, Any]:
    """``record`` as a record of a run the server opened, whose evaluations read the server's facts."""
    record["governance"]["run_opened_by"] = "server"
    for coverage in (record["coverage"], record["stages"]["plan"]["coverage"]):
        coverage["assertions_expected"]["origin"] = "server_pinned"
    for event in record["events"]:
        event["provenance"]["facts_source"] = "server"
    return record


@pytest.mark.parametrize("attestation", [None, "not_sent"], ids=["none kept", "kept, not sent"])
def test_signed_provenance_passes_only_for_a_build_whose_record_keeps_the_attestation_it_sent(
    attestation: str | None,
) -> None:
    record = _opened_by_server(_with_provenance_event("pass", None))
    if attestation is None:
        record["change"]["attestation"] = None
    with pytest.raises(ValidationError, match="passes only for a build whose record keeps the attestation it sent"):
        CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})


def test_signed_provenance_may_pass_for_a_build_that_sent_the_server_its_attestation() -> None:
    record = _opened_by_server(_with_provenance_event("pass", None))
    record["change"]["attestation"]["sent_to_server"] = True
    for coverage in (record["coverage"], record["stages"]["plan"]["coverage"]):
        coverage["subjects_in_scope"]["source_digest"] = digest_of(record["change"])
    CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})


def test_a_run_the_tool_opened_sent_the_server_no_attestation() -> None:
    record = copy.deepcopy(BUILD)
    record["change"]["attestation"]["sent_to_server"] = True
    with pytest.raises(ValidationError, match="a run the tool opened sent the server no attestation"):
        CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})


def _sent(car: CAR) -> CAR:
    """``car`` as if its build had sent the server the attestation it keeps."""
    build = car.change
    assert isinstance(build, ImageBuild) and build.attestation is not None
    attestation = build.attestation.model_copy(update={"sent_to_server": True})
    return car.model_copy(update={"change": build.model_copy(update={"attestation": attestation})})


def test_the_servers_answer_is_about_the_attestation_the_record_keeps() -> None:
    kept_only = CAR.model_validate(BUILD)
    sent = _sent(kept_only)
    verified = VerifiedAttestation.model_validate(BUILD_INPUT["attestation_outcome"])
    kept = next(ref for ref in sent.evidence_refs if ref.ref_id == "plan/attestation.sigstore.json")
    check_attestation_outcome(sent, verified.model_copy(update={"attestation_digest": kept.digest}))
    check_attestation_outcome(kept_only, AttestationNotSent(outcome="not_sent"))
    with pytest.raises(ValueError, match="the server checked the attestation the build's record keeps"):
        check_attestation_outcome(sent, verified.model_copy(update={"attestation_digest": "sha256:" + "e" * 64}))
    message = "sent an attestation exactly when the build's record says it sent the one it keeps"
    with pytest.raises(ValueError, match=message):
        check_attestation_outcome(sent, AttestationNotSent(outcome="not_sent"))
    with pytest.raises(ValueError, match=message):
        check_attestation_outcome(kept_only, verified.model_copy(update={"attestation_digest": kept.digest}))


def test_a_build_rule_called_on_a_record_of_another_activity_says_so() -> None:
    with pytest.raises(TypeError, match="an image_build rule was called on a record of iac_change"):
        IMAGE_BUILD.check_record(CAR.model_validate(RECORD))


def test_a_build_names_its_raw_index_exactly_when_it_names_platform_digests() -> None:
    change = copy.deepcopy(BUILD["change"])
    ImageBuild.model_validate(change)
    with pytest.raises(ValidationError, match="names both its raw index and its platform digests"):
        ImageBuild.model_validate({**change, "index_evidence_ref": None})
    on_the_image = [{**report, "image_digest": change["image"]["digest"]} for report in change["reports"]]
    with pytest.raises(ValidationError, match="names both its raw index and its platform digests"):
        ImageBuild.model_validate({**change, "platform_digests": [], "reports": on_the_image})


def test_a_scan_of_an_image_of_several_platforms_names_the_platform_it_scanned() -> None:
    change = copy.deepcopy(BUILD["change"])
    on_the_index = [{**report, "image_digest": change["image"]["digest"]} for report in change["reports"]]
    with pytest.raises(ValidationError, match="a scan of an image built for several platforms names the platform"):
        ImageBuild.model_validate({**change, "reports": on_the_index})
    tests_only = [report for report in on_the_index if report["format"] == "junit"]
    ImageBuild.model_validate({**change, "reports": tests_only})


def test_scan_coverage_counts_the_platforms_a_scanners_own_report_names() -> None:
    build = ImageBuild.model_validate(BUILD["change"])
    first, second = build.platform_digests
    assert scan_coverage(build) == ScanCoverage((first,), (second,))
    by_pipeline = [
        report.model_copy(update={"image_digest_source": "pipeline"}) if report.format != "junit" else report
        for report in build.reports
    ]
    assert scan_coverage(build.model_copy(update={"reports": by_pipeline})) == ScanCoverage((), (first, second))
    single = build.model_copy(update={"platform_digests": [], "reports": []})
    assert scan_coverage(single) == ScanCoverage((), (build.image.digest,))


def test_an_attestation_is_only_ever_kept_unverified() -> None:
    change = copy.deepcopy(BUILD["change"])
    change["attestation"]["verification"] = "verified"
    with pytest.raises(ValidationError, match="Input should be 'not_verified'"):
        ImageBuild.model_validate(change)


def build_with(**changes: Any) -> ImageBuild:
    change = copy.deepcopy(BUILD["change"])
    change.update(changes)
    return ImageBuild.model_validate(change)


def metadata(image_digest: str, commit: str | None, names: str = "ghcr.io/acme/api:1.4.2") -> bytes:
    document: dict[str, Any] = {"containerimage.digest": image_digest, "image.name": names}
    if commit is not None:
        document["buildx.build.provenance"] = {"invocation": {"configSource": {"digest": {"sha1": commit}}}}
    return json.dumps(document).encode()


def test_the_build_tool_metadata_file_kept_is_the_builds() -> None:
    build = build_with()
    assert build.build_commit is not None
    check_build_metadata(build, metadata(build.image.digest, build.build_commit.commit))
    with pytest.raises(ValueError, match="names the image's digest"):
        check_build_metadata(build, metadata("sha256:" + "4" * 64, build.build_commit.commit))
    for names in ("ghcr.io/acme/api:2.0", "other.io/x/y:1.4.2", "ghcr.io/acme/api", "acme/api:1.4.2"):
        with pytest.raises(ValueError, match="names the image's repository with its tag"):
            check_build_metadata(build, metadata(build.image.digest, build.build_commit.commit, names))
    for names in ("ghcr.io:443/acme/api:1.4.2", "other.io/x/y:1.4.2,ghcr.io/acme/api:1.4.2"):
        check_build_metadata(build, metadata(build.image.digest, build.build_commit.commit, names))
    with pytest.raises(ValueError, match="the build commit is the one the build tool's metadata file names"):
        check_build_metadata(build, metadata(build.image.digest, "d" * 40))


def test_a_record_names_no_build_commit_only_when_its_metadata_file_names_none() -> None:
    build = build_with(build_commit=None)
    check_build_metadata(build, metadata(build.image.digest, None))
    with pytest.raises(ValueError, match="the build commit is the one the build tool's metadata file names"):
        check_build_metadata(build, metadata(build.image.digest, "d" * 40))


def test_a_docker_hub_image_given_by_its_short_name_is_the_records_repository() -> None:
    build = build_with(image={**BUILD["change"]["image"], "repository": "docker.io/acme/api"}, reports=[])
    assert build.build_commit is not None
    check_build_metadata(build, metadata(build.image.digest, build.build_commit.commit, "acme/api:1.4.2"))
