"""What a deployment of a built image to one environment reports: the build it used, the image it deployed, and what
was running afterwards.

The server finds the build of the image by its digest and accepts it against
the environment's accepted build sources; the record keeps what the server
served (``AcceptedBuild``), never a build the pipeline named. The deployed image
and the reading of the workload afterwards are the pipeline's word, and so is
when each happened: neither names a time. The stage that reports each was
observed no earlier than the pipeline reported it.
"""

from __future__ import annotations

from typing import Annotated, Literal, NamedTuple

from pydantic import Field, model_validator

from iltero_schemas.models.base import StrictModel, sorted_unique
from iltero_schemas.models.facts import NotReported
from iltero_schemas.models.fields import Count, Digest, Identifier, Uuid
from iltero_schemas.models.image import (
    MAX_PLATFORM_DIGESTS,
    ImageReference,
    ImageRepository,
    check_platform_digests,
    repository_of,
)
from iltero_schemas.models.kubernetes import KubernetesRollout, KubernetesWorkload, StatefulSetRollout

# More containers than one pod template lists.
MAX_CONTAINERS = 256
# More pods than one workload runs: a daemon set on the largest cluster Kubernetes supports, with room for a rollout.
MAX_PODS = 10_000
# More containers of pods than one reading lists: every pod's every container, counted once per pod.
MAX_POD_CONTAINERS = 100_000
# More groups of containers than one reading finds: pods whose container shares every field but pods share a group.
MAX_CONTAINERS_READ = 1024
# What a container is to its pod: one of its containers, an init container that runs to completion first, a sidecar
# (an init container that keeps running), or a debugging container added to the running pod.
TemplateRole = Literal["app", "init", "sidecar"]
ContainerRole = Literal["app", "init", "sidecar", "ephemeral"]
# A pod being deleted is terminating; one whose containers all stopped is finished; any other is live.
PodState = Literal["live", "terminating", "finished"]


class AcceptedBuild(StrictModel):
    """The build of the image the server accepted for the environment: its run, its record and its platform digests."""

    run_id: Uuid
    record_digest: Digest
    platform_digests: Annotated[list[Digest], Field(max_length=MAX_PLATFORM_DIGESTS)]

    @model_validator(mode="after")
    def _in_order(self) -> AcceptedBuild:
        if not sorted_unique(self.platform_digests):
            raise ValueError("platform_digests are named once each, in order")
        return self


class DeployedImageRef(StrictModel):
    """An image by its repository and digest."""

    repository: ImageRepository
    digest: Digest


class ImageChange(StrictModel):
    """A deployment of an image, as an evaluation input carries it: its change digest, the image, and its build."""

    digest: Digest
    image: DeployedImageRef
    # Null when the server accepted no build of the image, or no server opened the run.
    build: AcceptedBuild | None

    @model_validator(mode="after")
    def _platforms(self) -> ImageChange:
        if self.build is not None:
            check_platform_digests(self.image.digest, self.build.platform_digests)
        return self


class ImageDeployment(StrictModel):
    """The image the pipeline reports it deployed, on its word. The post-deploy stage was observed no earlier than the
    pipeline reported it."""

    repository: ImageRepository
    digest: Digest
    reported_by: Literal["pipeline"]


# The workload a reading read, and the state of its rollout, told apart by the platform that runs it; another
# platform adds its own shapes.
Workload = KubernetesWorkload
Rollout = KubernetesRollout


class FileRead(NamedTuple):
    """One file a reading was taken from: the field that names it, what it is, and its name in the evidence
    register."""

    field: str
    description: str
    ref_id: str


class TemplateContainer(StrictModel):
    """One container of the workload's pod template: what it is to the pod, the image it names, with its repository
    in its one spelling, and whether the reading compares what it runs."""

    name: Identifier
    role: TemplateRole
    image_reference: ImageReference
    compared: bool


class ContainerRead(StrictModel):
    """One container as the pods listed ran it: those pods share its name, role, image, digest, state and revision.

    The image reference is the pod's own, which can differ from the template's. The digest is the image the
    container runs, from its status; it is the unknown marker when the status names no registry digest.
    """

    name: Identifier
    role: ContainerRole
    image_reference: ImageReference
    compared: bool
    digest: Digest | NotReported
    pod_state: PodState
    # The pod's template revision: its pod-template-hash or controller-revision-hash label; null when it has none.
    revision: Identifier | None
    pods: Annotated[list[Identifier], Field(min_length=1, max_length=MAX_PODS)]

    @model_validator(mode="after")
    def _pods_in_order(self) -> ContainerRead:
        if not sorted_unique(self.pods):
            raise ValueError("pods names each pod once, sorted")
        return self

    def sort_key(self) -> tuple[str, str, str, bool, str, str, str]:
        """The fields an entry is sorted by, in their order; an unknown digest and a null revision sort first."""
        digest = self.digest if isinstance(self.digest, str) else ""
        return (
            self.name,
            self.role,
            self.image_reference,
            self.compared,
            digest,
            self.pod_state,
            self.revision or "",
        )


class _Pod:
    """One pod as containers_read lists it: its state, its revision, and its containers by name and role."""

    def __init__(self, entry: ContainerRead) -> None:
        self.state = entry.pod_state
        self.revision = entry.revision
        self.containers: dict[str, str] = {}


class ImageDriftCheck(StrictModel):
    """What one reading of the workload, after the deployment, found: the state of its rollout, its pod template,
    and what every container of every pod it owns ran, with the raw files the reading was taken from."""

    run_id: Uuid
    change_digest: Digest
    workload: Workload
    rollout: Rollout
    # Every container of the pod template, by name, whether or not it is compared.
    template_containers: Annotated[list[TemplateContainer], Field(min_length=1, max_length=MAX_CONTAINERS)]
    containers_read: Annotated[list[ContainerRead], Field(max_length=MAX_CONTAINERS_READ)]
    # The live pods read; recomputed from containers_read.
    live_pods_read: Count
    # The version the cluster gave the pod list read.
    pods_resource_version: Identifier
    # The files the reading was taken from, each by its name in the record's evidence register: the workload object
    # read before and again after the pods were listed, the pod list, and the objects between the workload and its
    # pods (a deployment's replica sets), null for a workload that owns its pods.
    workload_before_pods_listing_evidence_ref: Identifier
    workload_after_pods_listing_evidence_ref: Identifier
    pods_evidence_ref: Identifier
    pod_owners_evidence_ref: Identifier | None

    def files_read(self) -> list[FileRead]:
        """Each file the reading was taken from, in the order its fields are written."""
        files = [
            FileRead(
                "workload_before_pods_listing_evidence_ref",
                "the workload read before the pods were listed",
                self.workload_before_pods_listing_evidence_ref,
            ),
            FileRead(
                "workload_after_pods_listing_evidence_ref",
                "the workload read after the pods were listed",
                self.workload_after_pods_listing_evidence_ref,
            ),
            FileRead("pods_evidence_ref", "the pod list read", self.pods_evidence_ref),
        ]
        if self.pod_owners_evidence_ref is not None:
            files.append(FileRead("pod_owners_evidence_ref", "the pod owners read", self.pod_owners_evidence_ref))
        return files

    @model_validator(mode="after")
    def _read(self) -> ImageDriftCheck:
        if self.rollout.kind != self.workload.kind:
            raise ValueError("rollout is the state of the workload's kind of rollout")
        if not sorted_unique([container.name for container in self.template_containers]):
            raise ValueError("template_containers lists each container of the pod template once, sorted by name")
        keys = [entry.sort_key() for entry in self.containers_read]
        if keys != sorted(set(keys)):
            raise ValueError("containers_read lists each group once, sorted")
        if sum(len(entry.pods) for entry in self.containers_read) > MAX_POD_CONTAINERS:
            raise ValueError(f"a reading lists at most {MAX_POD_CONTAINERS} containers of pods")
        pods = self._pods()
        if len(pods) > MAX_PODS:
            raise ValueError(f"a reading lists at most {MAX_PODS} pods")
        live = [pod for pod in pods.values() if pod.state == "live"]
        if self.live_pods_read != len(live):
            raise ValueError("live_pods_read is the number of live pods containers_read lists")
        if self.rollout.complete:
            self._check_finished_rollout(live)
        if (self.pod_owners_evidence_ref is not None) != (self.workload.kind == "deployment"):
            raise ValueError("pod_owners_evidence_ref names a deployment's replica sets, and only a deployment's")
        names = [file.ref_id for file in self.files_read()]
        if len(set(names)) != len(names):
            raise ValueError("the files a reading was taken from are each a different file")
        return self

    def _pods(self) -> dict[str, _Pod]:
        """Each pod read, by name; a pod lists each container once, in one state and revision, and compares a
        container its template compares."""
        compared = {container.name for container in self.template_containers if container.compared}
        pods: dict[str, _Pod] = {}
        for entry in self.containers_read:
            if entry.name in compared and not entry.compared:
                raise ValueError("a pod's container is compared when its template container is")
            for name in entry.pods:
                pod = pods.setdefault(name, _Pod(entry))
                if (pod.state, pod.revision) != (entry.pod_state, entry.revision):
                    raise ValueError("each pod has one state and one revision")
                if entry.name in pod.containers:
                    raise ValueError("a pod lists each of its containers once")
                pod.containers[entry.name] = entry.role
        return pods

    def _check_finished_rollout(self, live: list[_Pod]) -> None:
        """Once the rollout has finished, every live pod is of the current template: it lists every template
        container in its role, and all are of one revision, a stateful set's update revision."""
        template = {container.name: container.role for container in self.template_containers}
        if any(pod.containers.get(name) != role for pod in live for name, role in template.items()):
            raise ValueError("once the rollout has finished, every live pod lists every template container")
        revisions = {pod.revision for pod in live}
        current = self.rollout.update_revision if isinstance(self.rollout, StatefulSetRollout) else None
        if len(revisions) > 1 or (live and current is not None and revisions != {current}):
            raise ValueError("once the rollout has finished, every live pod is of its current revision")


def check_compared(check: ImageDriftCheck, repository: str) -> None:
    """Raise ``ValueError`` unless the reading compares every container, of the template or of a pod, that names an
    image of ``repository``, the deployed one."""
    named = [(c.compared, c.image_reference) for c in check.template_containers] + [
        (c.compared, c.image_reference) for c in check.containers_read
    ]
    if any(not compared and repository_of(reference) == repository for compared, reference in named):
        raise ValueError("a reading compares every container whose image is from the deployed repository")
