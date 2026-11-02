"""The image_release change type's build activity: its declaration, its record body and the rules of its records."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.assertions import BUILT_FROM_RUN_COMMIT_ID, NO_DRIFT_AFTER_APPLY_ID, PLAN_BINDING_ID
from iltero_schemas.change_types import (
    CHANGE_TYPES,
    IAC_CHANGE,
    IMAGE_BUILD,
    IMAGE_DEPLOY,
    ImageBuild,
    check_build_metadata,
)
from iltero_schemas.models.assertion import Stage
from iltero_schemas.models.car import CAR
from iltero_schemas.models.checked_content import CheckedImage
from tests.conftest import VECTORS
from tests.records import RECORD

BUILD: dict[str, Any] = json.loads((VECTORS / "records" / "local_run_image_build.json").read_text(encoding="utf-8"))
# The evaluation input the record's report check read, as its evidence register keeps it.
BUILD_INPUT: dict[str, Any] = json.loads((VECTORS / "contexts" / "plan_artifact.json").read_text(encoding="utf-8"))


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
    assert IMAGE_BUILD.binding_check == (BUILT_FROM_RUN_COMMIT_ID, Stage.PLAN)
    assert IAC_CHANGE.binding_check == (PLAN_BINDING_ID, Stage.POST_DEPLOY)
    for activity in (IMAGE_BUILD, IAC_CHANGE):
        assertion_id, stage = activity.binding_check
        assert activity.always_evaluated[stage] == assertion_id
    assert dict(IAC_CHANGE.always_evaluated) == {
        Stage.POST_DEPLOY: PLAN_BINDING_ID,
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
        kept[source["digest"]] = report.image_digest_source
    read = {
        report["file_digest"]: report["image_digest_source"] for report in BUILD_INPUT["tests"] + BUILD_INPUT["scans"]
    }
    assert read.items() <= kept.items()


def test_the_build_commit_is_the_one_its_metadata_file_names_for_its_image() -> None:
    car = CAR.model_validate(BUILD)
    assert isinstance(car.change, ImageBuild) and car.change.build_commit is not None
    stored = next(ref for ref in car.evidence_refs if ref.ref_id == car.change.build_commit.evidence_ref)
    assert stored.redaction_policy is None and stored.source is not None and stored.source["digest"] == stored.digest
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
    assert statuses["ILT.IMAGE.BUILT_FROM_RUN_COMMIT"] == "unknown"
    assert car.verdict.value == "indeterminate" and car.complete


def test_a_build_rule_called_on_a_record_of_another_activity_says_so() -> None:
    with pytest.raises(TypeError, match="an image_build rule was called on a record of iac_change"):
        IMAGE_BUILD.check_record(CAR.model_validate(RECORD))


def test_a_build_names_its_raw_index_exactly_when_it_names_platform_digests() -> None:
    change = copy.deepcopy(BUILD["change"])
    ImageBuild.model_validate(change)
    with pytest.raises(ValidationError, match="names both its raw index and its platform digests"):
        ImageBuild.model_validate({**change, "index_evidence_ref": None})
    with pytest.raises(ValidationError, match="names both its raw index and its platform digests"):
        ImageBuild.model_validate({**change, "platform_digests": []})


def test_a_tags_metadata_file_is_read_by_the_pipeline_at_its_runners_time() -> None:
    change = copy.deepcopy(BUILD["change"])
    change["image"]["tag_resolution"]["read_at"] = {
        "value": "2026-11-01T10:01:30Z",
        "source": "timestamp_authority",
        "trust": "attested",
        "time_window": {
            "not_before": "2026-11-01T10:01:00Z",
            "not_after": "2026-11-01T10:02:00Z",
            "nonce_digest": "sha256:" + "9" * 64,
        },
    }
    with pytest.raises(ValidationError, match="at the time its runner's clock gives"):
        ImageBuild.model_validate(change)


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
    with pytest.raises(ValueError, match="names the image's tag"):
        check_build_metadata(build, metadata(build.image.digest, build.build_commit.commit, "ghcr.io/acme/api:2.0"))
    with pytest.raises(ValueError, match="the build commit is the one the build tool's metadata file names"):
        check_build_metadata(build, metadata(build.image.digest, "d" * 40))


def test_a_record_names_no_build_commit_only_when_its_metadata_file_names_none() -> None:
    build = build_with(build_commit=None)
    check_build_metadata(build, metadata(build.image.digest, None))
    with pytest.raises(ValueError, match="the build commit is the one the build tool's metadata file names"):
        check_build_metadata(build, metadata(build.image.digest, "d" * 40))
