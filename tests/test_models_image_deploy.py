"""What a deployment of a built image reports: the accepted build, the deployed image and the workload's reading."""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.context import AssuranceContext
from iltero_schemas.models.image_deploy import (
    MAX_POD_CONTAINERS,
    MAX_PODS,
    AcceptedBuild,
    ImageDeployment,
    ImageDriftCheck,
    check_compared,
)
from tests.conftest import VECTORS

DIGEST = "sha256:" + "1" * 64
RUNNER = {"value": "2026-11-02T09:02:00Z", "source": "runner_clock", "trust": "asserted", "time_window": None}
SERVER = {**RUNNER, "source": "server", "trust": "attested"}
DEPLOYMENT: dict[str, Any] = {
    "repository": "ghcr.io/acme/api",
    "digest": DIGEST,
    "deployed_at": RUNNER,
    "reported_by": "pipeline",
}
CONTEXT: dict[str, Any] = json.loads((VECTORS / "contexts" / "image_post_verify.json").read_text(encoding="utf-8"))
CHECK: dict[str, Any] = CONTEXT["drift_check"]
READ: list[dict[str, Any]] = CHECK["containers_read"]
SIDECAR = {"name": "migrate", "role": "init", "image_reference": "ghcr.io/acme/api:1.4.2", "compared": False}
# A rollout still under way, whose live pods may be of an older template.
UNFINISHED = {**CHECK["rollout"], "updated_replicas": 1, "complete": False}


def reading(**changes: Any) -> dict[str, Any]:
    return {**CHECK, **changes}


def test_a_deployment_is_the_pipelines_word_dated_by_its_runner() -> None:
    ImageDeployment.model_validate(DEPLOYMENT)
    with pytest.raises(ValidationError, match="the pipeline deployed the image at the time its runner's clock gives"):
        ImageDeployment.model_validate({**DEPLOYMENT, "deployed_at": SERVER})
    with pytest.raises(ValidationError, match="Input should be 'pipeline'"):
        ImageDeployment.model_validate({**DEPLOYMENT, "reported_by": "server"})


def test_a_reading_of_the_workload_is_dated_by_the_runner() -> None:
    assert ImageDriftCheck.model_validate(CHECK).live_pods_read == 2
    with pytest.raises(ValidationError, match="the pipeline read the workload at the time its runner's clock gives"):
        ImageDriftCheck.model_validate(reading(read_at=SERVER))


def test_a_reading_lists_every_container_of_the_pod_template_once_sorted_by_name() -> None:
    with pytest.raises(ValidationError, match="at least 1 item"):
        ImageDriftCheck.model_validate(reading(template_containers=[]))
    template = CHECK["template_containers"]
    for containers in (template[::-1], [template[0]] * 2):
        with pytest.raises(ValidationError, match="lists each container of the pod template once, sorted by name"):
            ImageDriftCheck.model_validate(reading(template_containers=containers))


def test_a_reading_groups_the_pods_that_ran_a_container_alike_once_each_sorted() -> None:
    with pytest.raises(ValidationError, match="containers_read lists each group once, sorted"):
        ImageDriftCheck.model_validate(reading(containers_read=READ[::-1]))
    with pytest.raises(ValidationError, match="containers_read lists each group once, sorted"):
        ImageDriftCheck.model_validate(reading(containers_read=[READ[0], READ[0], READ[1]]))
    with pytest.raises(ValidationError, match="pods names each pod once, sorted"):
        ImageDriftCheck.model_validate(reading(containers_read=[{**READ[0], "pods": READ[0]["pods"][::-1]}, READ[1]]))


def test_a_pod_lists_each_container_once_with_one_state_and_one_revision() -> None:
    twice = {**READ[0], "digest": "sha256:" + "f" * 64}
    with pytest.raises(ValidationError, match="a pod lists each of its containers once"):
        ImageDriftCheck.model_validate(reading(containers_read=[READ[0], twice, READ[1]]))
    with pytest.raises(ValidationError, match="each pod has one state and one revision"):
        ImageDriftCheck.model_validate(reading(containers_read=[READ[0], {**READ[1], "revision": "5c4b3a291"}]))


def test_the_live_pods_read_are_counted_from_the_pods_listed() -> None:
    with pytest.raises(ValidationError, match="live_pods_read is the number of live pods containers_read lists"):
        ImageDriftCheck.model_validate(reading(live_pods_read=3))
    old = {**READ[0], "pod_state": "terminating", "revision": "5c4b3a291", "pods": ["api-5c4b3a291-zzzzz"]}
    assert ImageDriftCheck.model_validate(reading(containers_read=[READ[0], old, READ[1]])).live_pods_read == 2


def test_a_pods_container_is_compared_when_its_template_container_is() -> None:
    mirror = {**READ[0], "image_reference": "mirror.example.com/acme/api@" + READ[0]["digest"], "compared": False}
    with pytest.raises(ValidationError, match="a pod's container is compared when its template container is"):
        ImageDriftCheck.model_validate(reading(containers_read=[mirror, READ[1]]))


def test_once_the_rollout_has_finished_every_live_pod_lists_every_template_container_in_its_role() -> None:
    one_pod = {**READ[0], "pods": READ[0]["pods"][:1]}
    with pytest.raises(ValidationError, match="once the rollout has finished, every live pod lists every template"):
        ImageDriftCheck.model_validate(reading(containers_read=[one_pod, READ[1]]))
    with pytest.raises(ValidationError, match="once the rollout has finished, every live pod lists every template"):
        ImageDriftCheck.model_validate(reading(containers_read=[READ[0], {**READ[1], "role": "init"}]))
    ImageDriftCheck.model_validate(reading(rollout=UNFINISHED, containers_read=[one_pod, READ[1]]))


def test_once_the_rollout_has_finished_every_live_pod_is_of_its_current_revision() -> None:
    first, second = READ[0]["pods"]
    split = sorted(
        (
            {**entry, "revision": revision, "pods": [pod]}
            for entry in READ
            for revision, pod in ((READ[0]["revision"], first), ("8e5d4c3b2", second))
        ),
        key=lambda entry: (entry["name"], entry["revision"]),
    )
    with pytest.raises(ValidationError, match="once the rollout has finished, every live pod is of its current"):
        ImageDriftCheck.model_validate(reading(containers_read=split))


def test_a_stateful_sets_live_pods_are_of_its_update_revision_once_its_rollout_has_finished() -> None:
    rollout = {
        "kind": "stateful_set",
        "resource_version": "48213",
        "generation": 4,
        "observed_generation": 4,
        "desired_replicas": 2,
        "replicas": 2,
        "updated_replicas": 2,
        "available_replicas": 2,
        "current_revision": "api-6d5c4b3a2",
        "update_revision": "api-6d5c4b3a2",
        "strategy": "rolling_update",
        "partition": 0,
        "complete": True,
        "expected_live_pods": 2,
    }
    stateful = reading(workload={**CHECK["workload"], "kind": "stateful_set"}, rollout=rollout)
    stateful["pod_owners_evidence_ref"] = None
    on_update = [{**entry, "revision": "api-6d5c4b3a2"} for entry in READ]
    ImageDriftCheck.model_validate({**stateful, "containers_read": on_update})
    with pytest.raises(ValidationError, match="once the rollout has finished, every live pod is of its current"):
        ImageDriftCheck.model_validate(stateful)


def test_a_reading_lists_at_most_its_limits_of_pods_and_of_containers_of_pods() -> None:
    pods = [f"api-{number:05}" for number in range(MAX_PODS + 1)]
    halves = [{**READ[0], "pods": pods[:5000]}, {**READ[1], "pods": pods[5000:]}]
    with pytest.raises(ValidationError, match=f"a reading lists at most {MAX_PODS} pods"):
        ImageDriftCheck.model_validate(reading(containers_read=halves))
    many = [
        {**READ[1], "name": f"debug-{number:02}", "role": "ephemeral", "pods": pods[:MAX_PODS]}
        for number in range(MAX_POD_CONTAINERS // MAX_PODS + 1)
    ]
    with pytest.raises(ValidationError, match=f"a reading lists at most {MAX_POD_CONTAINERS} containers of pods"):
        ImageDriftCheck.model_validate(reading(containers_read=many))


def test_a_container_whose_digest_was_not_reported_holds_the_unknown_marker() -> None:
    marker = {"__unknown": True, "reason": "not_reported_by_tool"}
    check = ImageDriftCheck.model_validate(reading(containers_read=[{**READ[0], "digest": marker}, READ[1]]))
    assert not isinstance(check.containers_read[0].digest, str)


def test_a_reading_names_its_workloads_kind_of_rollout_and_the_files_it_was_taken_from() -> None:
    workload = {**CHECK["workload"], "kind": "stateful_set"}
    with pytest.raises(ValidationError, match="rollout is the state of the workload's kind of rollout"):
        ImageDriftCheck.model_validate(reading(workload=workload))
    before = CHECK["workload_before_pods_listing_evidence_ref"]
    for field in ("workload_after_pods_listing_evidence_ref", "pods_evidence_ref", "pod_owners_evidence_ref"):
        with pytest.raises(ValidationError, match="the files a reading was taken from are each a different file"):
            ImageDriftCheck.model_validate(reading(**{field: before}))


def test_only_a_deployments_reading_names_the_pods_owners() -> None:
    with pytest.raises(ValidationError, match="pod_owners_evidence_ref names a deployment's replica sets"):
        ImageDriftCheck.model_validate(reading(pod_owners_evidence_ref=None))
    daemon_set = {
        "kind": "daemon_set",
        "resource_version": "48213",
        "generation": 4,
        "observed_generation": 4,
        "desired_number_scheduled": 2,
        "current_number_scheduled": 2,
        "updated_number_scheduled": 2,
        "number_available": 2,
        "number_misscheduled": 0,
        "strategy": "rolling_update",
        "complete": True,
        "expected_live_pods": 2,
    }
    owns_its_pods = reading(workload={**CHECK["workload"], "kind": "daemon_set"}, rollout=daemon_set)
    assert ImageDriftCheck.model_validate({**owns_its_pods, "pod_owners_evidence_ref": None}).files_read()[
        -1
    ].field == ("pods_evidence_ref")
    with pytest.raises(ValidationError, match="pod_owners_evidence_ref names a deployment's replica sets"):
        ImageDriftCheck.model_validate(owns_its_pods)


@pytest.mark.parametrize("kind", ["deployment_config", "replica_set", "pod"])
def test_a_workload_of_a_kind_no_reader_reads_is_refused(kind: str) -> None:
    with pytest.raises(ValidationError, match="Input should be 'deployment', 'stateful_set' or 'daemon_set'"):
        ImageDriftCheck.model_validate(reading(workload={**CHECK["workload"], "kind": kind}))


def test_a_reading_compares_every_container_of_the_deployed_repository_in_the_template_and_in_each_pod() -> None:
    template = ImageDriftCheck.model_validate(
        reading(rollout=UNFINISHED, template_containers=[*CHECK["template_containers"], SIDECAR])
    )
    check_compared(template, "ghcr.io/acme/other")
    with pytest.raises(ValueError, match="compares every container whose image is from the deployed repository"):
        check_compared(template, "ghcr.io/acme/api")
    pod = {**READ[1], "image_reference": "ghcr.io/acme/api:1.4.2"}
    with pytest.raises(ValueError, match="compares every container whose image is from the deployed repository"):
        check_compared(ImageDriftCheck.model_validate(reading(containers_read=[READ[0], pod])), "ghcr.io/acme/api")


def test_a_deploy_inputs_reading_compares_every_container_of_the_deployed_repository() -> None:
    check = reading(rollout=UNFINISHED, template_containers=[*CHECK["template_containers"], SIDECAR])
    with pytest.raises(ValidationError, match="compares every container whose image is from the deployed repository"):
        AssuranceContext.model_validate({**CONTEXT, "drift_check": check})


def test_an_accepted_build_names_its_platform_digests_once_each_in_order() -> None:
    build = {"run_id": CHECK["run_id"], "record_digest": DIGEST, "platform_digests": ["sha256:" + "3" * 64]}
    AcceptedBuild.model_validate(build)
    with pytest.raises(ValidationError, match="named once each, in order"):
        AcceptedBuild.model_validate({**build, "platform_digests": ["sha256:" + "3" * 64, "sha256:" + "2" * 64]})


def test_a_deploy_inputs_reading_is_taken_no_earlier_than_the_deployment() -> None:
    before = {
        **CONTEXT["drift_check"],
        "read_at": {**CONTEXT["drift_check"]["read_at"], "value": "2026-11-02T09:01:00Z"},
    }
    with pytest.raises(ValidationError, match="drift_check.read_at must be no earlier than deployment.deployed_at"):
        AssuranceContext.model_validate({**CONTEXT, "drift_check": before})
    at_deployment = {**CONTEXT["drift_check"]["read_at"], "value": CONTEXT["deployment"]["deployed_at"]["value"]}
    AssuranceContext.model_validate({**CONTEXT, "drift_check": {**CONTEXT["drift_check"], "read_at": at_deployment}})
