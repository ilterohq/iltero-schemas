"""The ``image_deploy`` activity: a built container image deployed to one environment.

A record of it starts at the pre-deploy stage, where the change is approved:
the image, by its repository and digest, in the record's unit and
environment, which its change digest names. The build of the image is the one
the server found by the digest and accepted for the environment; the record
keeps what the server served, and a run the tool opened names none. After the
deployment the pipeline reports the image it deployed, and at post-verify what
the workload ran when it was read, each dated by the pipeline's runner clock.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING, Literal

from pydantic import model_validator

from iltero_schemas.assertions.paths import IMAGE_BINDING_ID, RUNNING_DIGEST_MATCHES_ID
from iltero_schemas.canonical import change_digest, digest_of
from iltero_schemas.change_types.activity import Activity
from iltero_schemas.change_types.bindings import bound_to_change_digest_problems
from iltero_schemas.change_types.evidence import JSON_MEDIA_TYPE, given_digest
from iltero_schemas.change_types.image import ImageRef
from iltero_schemas.change_types.owed_status import owed_status_problems
from iltero_schemas.models.assertion import Stage
from iltero_schemas.models.base import StrictModel
from iltero_schemas.models.change_type import IMAGE_DEPLOY_ACTIVITY, IMAGE_RELEASE_TYPE
from iltero_schemas.models.checked_content import CheckedImage, checked_image
from iltero_schemas.models.fields import Digest, parse_timestamp
from iltero_schemas.models.image import check_platform_digests
from iltero_schemas.models.image_deploy import AcceptedBuild, ImageDeployment, ImageDriftCheck, check_compared

if TYPE_CHECKING:
    from iltero_schemas.models.car import CAR, StageRecord


class ImageDeploy(StrictModel):
    """One deployment of a built image: the image, the build the server accepted, and what the pipeline reported."""

    activity: Literal["image_deploy"]
    # The change digest (``canonical.change_digest``), which an approval binds to.
    digest: Digest
    image: ImageRef
    # Null when no server opened the run, or the server accepted no build of the image for the environment.
    build: AcceptedBuild | None
    # Null until the post-deploy stage has reported.
    deployment: ImageDeployment | None
    # Null until the post-verify stage has read the workload.
    drift_check: ImageDriftCheck | None

    @model_validator(mode="after")
    def _build_of_the_image(self) -> ImageDeploy:
        if self.build is not None:
            check_platform_digests(self.image.digest, self.build.platform_digests)
        return self


def _body(car: CAR) -> ImageDeploy:
    """The record's change, which this activity's rules are only ever called on."""
    if not isinstance(car.change, ImageDeploy):
        raise TypeError(f"an image_deploy rule was called on a record of {car.change.activity}")
    return car.change


def _checked_content(car: CAR) -> CheckedImage:
    image = _body(car).image
    return checked_image(image.repository, image.digest)


def _counted(stage: StageRecord, part: StrictModel, what: str) -> None:
    """``stage`` counts the one deployment by the digest of ``part``."""
    scope = stage.coverage.subjects_in_scope
    if scope.value != 1 or scope.source_digest != digest_of(part.model_dump(mode="json", by_alias=True)):
        raise ValueError(f"the {stage.stage.value} stage must count the one deployment by {what}")


def _check_tag(car: CAR, deploy: ImageDeploy) -> None:
    """A tag the pipeline gave was tied to the digest by a file the record keeps, before the change was approved."""
    resolution = deploy.image.tag_resolution
    if resolution is None:
        return
    if resolution.read_from_evidence_ref not in {ref.ref_id for ref in car.evidence_refs}:
        raise ValueError(
            "change.image.tag_resolution.read_from_evidence_ref names a file of the record's evidence register"
        )
    if parse_timestamp(resolution.read_at.value) > parse_timestamp(car.stages[Stage.PRE_DEPLOY].observed_at):
        raise ValueError("the tag's metadata file was read no later than the pre-deploy stage was observed")


def _check_deployment(car: CAR, deploy: ImageDeploy) -> None:
    """The post-deploy stage counts the one deployment, which happened after the change was approved."""
    deployment = deploy.deployment
    stage = car.stages.get(Stage.POST_DEPLOY)
    if (deployment is None) != (stage is None):
        raise ValueError("a record describes the deployment exactly when its post-deploy stage has reported")
    if deployment is None or stage is None:
        return
    deployed = parse_timestamp(deployment.deployed_at.value)
    if not parse_timestamp(car.stages[Stage.PRE_DEPLOY].observed_at) <= deployed <= parse_timestamp(stage.observed_at):
        raise ValueError("the image was deployed after the pre-deploy stage and before the post-deploy stage reported")
    _counted(stage, deployment, "its digest")


def _check_drift_check(car: CAR, deploy: ImageDeploy) -> None:
    """The reading of the workload is of this record's run, taken after the deployment, and counted by its stage."""
    check = deploy.drift_check
    stage = car.stages.get(Stage.POST_VERIFY)
    if (check is None) != (stage is None):
        raise ValueError("a record carries its drift check exactly when its post-verify stage has reported")
    if check is None or stage is None:
        return
    if check.run_id != car.run.id:
        raise ValueError("the drift check names the record's run")
    check_compared(check, deploy.image.repository)
    post_deploy = car.stages.get(Stage.POST_DEPLOY)
    read = parse_timestamp(check.read_at.value)
    if post_deploy is not None and read < parse_timestamp(post_deploy.observed_at):
        raise ValueError("the workload was read no earlier than the post-deploy stage was observed")
    if parse_timestamp(stage.observed_at) < read:
        raise ValueError("the post-verify stage was observed no earlier than the workload was read")
    _check_files_read(car, deploy, check)
    _counted(stage, check, "the drift check that read it")


def _check_files_read(car: CAR, deploy: ImageDeploy, check: ImageDriftCheck) -> None:
    """The files the reading was taken from are JSON files of the record's evidence register,
    redacted under the record's redaction policy, kept no earlier than the reading, and named by no other part of the
    record."""
    refs = {ref.ref_id: ref for ref in car.evidence_refs}
    tag = deploy.image.tag_resolution
    for field, what, ref_id in check.files_read():
        ref = refs.get(ref_id)
        if ref is None:
            raise ValueError(f"change.drift_check.{field} names a file of the record's evidence register")
        if ref.media_type != JSON_MEDIA_TYPE:
            raise ValueError(f"{what} is a file of type {JSON_MEDIA_TYPE}")
        if ref.redaction_policy is None:
            raise ValueError(f"{what} names the redaction policy that ran over it")
        given_digest(ref, what)
        if parse_timestamp(ref.collected_at) < parse_timestamp(check.read_at.value):
            raise ValueError(f"{what} was kept no earlier than it was read")
        if tag is not None and ref_id == tag.read_from_evidence_ref:
            raise ValueError(f"{what} is not the tag's metadata file")


def _check_record(car: CAR) -> None:
    deploy = _body(car)
    if car.run.origin != "server_issued" and deploy.build is not None:
        raise ValueError("a run the tool opened names no build: only the server accepts one for the environment")
    _check_tag(car, deploy)
    _check_deployment(car, deploy)
    _check_drift_check(car, deploy)


def _change_digest_problems(car: CAR) -> list[tuple[str, str]]:
    """The change digest is the digest of the unit's image in the record's environment, and every part bound to the
    change names it."""
    deploy = _body(car)
    problems: list[tuple[str, str]] = []
    checked = _checked_content(car).model_dump(mode="json")
    if deploy.digest != change_digest(IMAGE_RELEASE_TYPE, car.unit, car.subject.environment, checked):
        problems.append(("change.digest", "is not the digest of the change type, unit, environment and image"))
    if deploy.drift_check is not None and deploy.drift_check.change_digest != deploy.digest:
        problems.append(("change.drift_check.change_digest", "is not change.digest"))
    return problems + bound_to_change_digest_problems(car, deploy.digest)


def running_digest_status(image_digest: str, platform_digests: list[str] | None, check: ImageDriftCheck) -> str:
    """The status ``RUNNING_DIGEST_MATCHES`` owes, given the deployed image's digest and the accepted build's platform
    digests (None without an accepted build).

    Fail when the rollout had not finished, the live pods read are not the ones it calls for, the template compares
    no container, no live pod has a compared container, or one runs an image the change does not name; unknown when
    such a digest is not known or there is no accepted build to name the platform images.
    """
    live = [entry for entry in check.containers_read if entry.pod_state == "live" and entry.compared]
    digests = {entry.digest for entry in live if isinstance(entry.digest, str)} - {image_digest}
    platforms = set(platform_digests) if platform_digests is not None else None
    if (
        not check.rollout.complete
        or check.live_pods_read != check.rollout.expected_live_pods
        or not any(container.compared for container in check.template_containers)
        or not live
        or (platforms is not None and digests - platforms)
    ):
        return "fail"
    if any(not isinstance(entry.digest, str) for entry in live) or (platforms is None and digests):
        return "unknown"
    return "pass"


def _owed_statuses(deploy: ImageDeploy) -> dict[str, str]:
    """The status each built-in check must have, recomputed from what the record holds: whether the deployed image
    is the checked one, and whether the workload's live pods run it."""
    owed: dict[str, str] = {}
    if deploy.deployment is not None:
        deployed = (deploy.deployment.repository, deploy.deployment.digest)
        owed[IMAGE_BINDING_ID] = "pass" if deployed == (deploy.image.repository, deploy.image.digest) else "fail"
    if deploy.drift_check is not None:
        platforms = deploy.build.platform_digests if deploy.build is not None else None
        owed[RUNNING_DIGEST_MATCHES_ID] = running_digest_status(deploy.image.digest, platforms, deploy.drift_check)
    return owed


def _integrity_problems(car: CAR) -> list[tuple[str, str]]:
    """Each built-in check found what the record's own image, deployment and reading say it must."""
    return owed_status_problems(car, _owed_statuses(_body(car)))


IMAGE_DEPLOY = Activity(
    name=IMAGE_DEPLOY_ACTIVITY,
    change_type=IMAGE_RELEASE_TYPE,
    run_type="change",
    stages=(Stage.PRE_DEPLOY, Stage.POST_DEPLOY, Stage.POST_VERIFY),
    project_may_leave_out=frozenset({Stage.POST_VERIFY}),
    environment_policy_may_leave_out=frozenset({Stage.POST_VERIFY}),
    # The workload the image runs in may be of a kind no reader reads, such as one a cloud's own service runs.
    not_supported=lambda _car: frozenset({Stage.POST_VERIFY}),
    required_documents=MappingProxyType(
        {Stage.PRE_DEPLOY: ("record",), Stage.POST_DEPLOY: ("record",), Stage.POST_VERIFY: ("record",)}
    ),
    named_documents=lambda _car: MappingProxyType({}),
    checked_content=_checked_content,
    check_record=_check_record,
    change_digest_problems=_change_digest_problems,
    integrity_problems=_integrity_problems,
    binding_check=(IMAGE_BINDING_ID, Stage.POST_DEPLOY),
    always_evaluated=MappingProxyType(
        {Stage.POST_DEPLOY: IMAGE_BINDING_ID, Stage.POST_VERIFY: RUNNING_DIGEST_MATCHES_ID}
    ),
)
