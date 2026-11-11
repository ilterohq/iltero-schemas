"""A Kubernetes workload, and the state of its rollout as one reading of it found.

A reading names the workload by its cluster, kind, namespace, name and uid, and
copies the counts its status reported, each read in the same request as its
pod template; a count the status left out is written as 0. From them the reading
says whether the rollout had finished, by the test ``kubectl rollout status``
applies, and how many live pods the workload should have once it has. Both are
recomputed from the counts and refused when they differ.
"""

from __future__ import annotations

from abc import abstractmethod
from typing import Annotated, Literal

from pydantic import Field, model_validator

from iltero_schemas.models.base import StrictModel
from iltero_schemas.models.fields import Count, Identifier, Uuid

# The Kubernetes workload kinds whose running images a reader can read: those whose pods a controller rolls out.
KubernetesWorkloadKind = Literal["deployment", "stateful_set", "daemon_set"]


class KubernetesWorkload(StrictModel):
    """A Kubernetes workload whose pods run the image: the cluster, by the id of its kube-system namespace, and the
    workload's kind, namespace, name and uid in it."""

    platform: Literal["kubernetes"]
    cluster_id: Identifier
    kind: KubernetesWorkloadKind
    namespace: Identifier
    name: Identifier
    # The workload object's own id: a name can be used again by a workload deleted and created anew.
    uid: Uuid


class _Rollout(StrictModel):
    """What every kind's rollout state carries: the generation of the workload's spec, the generation its controller
    last acted on, and the two values derived from the counts."""

    # The version the cluster gave the workload object read, so the reading names the state it was taken from.
    resource_version: Identifier
    generation: Count
    observed_generation: Count
    # Whether the rollout had finished when it was read; recomputed from the counts.
    complete: bool
    # The live pods the workload has once its rollout has finished; recomputed from the counts.
    expected_live_pods: Count

    @abstractmethod
    def complete_by_counts(self) -> bool:
        """Whether the counts show every pod the workload calls for on its current template, and no other."""

    @abstractmethod
    def expected_live_pods_by_counts(self) -> int:
        """The live pods the workload has once its rollout has finished."""

    @model_validator(mode="after")
    def _derived(self) -> _Rollout:
        if self.complete != (self.observed_generation >= self.generation and self.complete_by_counts()):
            raise ValueError("rollout.complete is whether the rollout's counts show it finished")
        if self.expected_live_pods != self.expected_live_pods_by_counts():
            raise ValueError("rollout.expected_live_pods is the live pods the rollout's counts call for")
        return self


class DeploymentRollout(_Rollout):
    """A deployment's rollout: finished when every desired pod runs the current template and is available, and no
    pod of an older template is left."""

    kind: Literal["deployment"]
    desired_replicas: Count
    replicas: Count
    updated_replicas: Count
    available_replicas: Count
    paused: bool
    strategy: Literal["rolling_update", "recreate"]

    def complete_by_counts(self) -> bool:
        return (
            not self.paused
            and self.updated_replicas == self.desired_replicas
            and self.replicas == self.updated_replicas
            and self.available_replicas == self.updated_replicas
        )

    def expected_live_pods_by_counts(self) -> int:
        return self.desired_replicas


class StatefulSetRollout(_Rollout):
    """A stateful set's rollout: finished when every desired pod runs the update revision and is available. A
    partitioned or on-delete rollout leaves pods on the old revision on purpose, so it never finishes by itself."""

    kind: Literal["stateful_set"]
    desired_replicas: Count
    replicas: Count
    updated_replicas: Count
    available_replicas: Count
    # Null while the stateful set's status names no revision yet.
    current_revision: Identifier | None
    update_revision: Identifier | None
    strategy: Literal["rolling_update", "on_delete"]
    partition: Count

    def complete_by_counts(self) -> bool:
        return (
            self.strategy == "rolling_update"
            and self.partition == 0
            and self.updated_replicas == self.desired_replicas
            and self.update_revision is not None
            and self.current_revision == self.update_revision
            and self.available_replicas == self.desired_replicas
        )

    def expected_live_pods_by_counts(self) -> int:
        return self.desired_replicas


class DaemonSetRollout(_Rollout):
    """A daemon set's rollout: finished when every node it should run on runs the current template, available, and no
    pod is left on a node it no longer selects. An on-delete rollout never finishes by itself."""

    kind: Literal["daemon_set"]
    desired_number_scheduled: Count
    current_number_scheduled: Count
    updated_number_scheduled: Count
    number_available: Count
    number_misscheduled: Count
    strategy: Literal["rolling_update", "on_delete"]

    def complete_by_counts(self) -> bool:
        return (
            self.strategy == "rolling_update"
            and self.updated_number_scheduled == self.desired_number_scheduled
            and self.number_available == self.desired_number_scheduled
            and self.number_misscheduled == 0
        )

    def expected_live_pods_by_counts(self) -> int:
        return self.desired_number_scheduled


# A workload's rollout state, told apart by the workload's kind.
KubernetesRollout = Annotated[DeploymentRollout | StatefulSetRollout | DaemonSetRollout, Field(discriminator="kind")]
