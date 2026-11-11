"""A Kubernetes workload's rollout: whether it finished and the live pods it calls for, recomputed from its counts."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import TypeAdapter, ValidationError

from iltero_schemas.models.image.kubernetes import KubernetesRollout

ROLLOUT: TypeAdapter[Any] = TypeAdapter(KubernetesRollout)
GENERATIONS = {"resource_version": "48213", "generation": 4, "observed_generation": 4}
DEPLOYMENT: dict[str, Any] = {
    "kind": "deployment",
    **GENERATIONS,
    "desired_replicas": 3,
    "replicas": 3,
    "updated_replicas": 3,
    "available_replicas": 3,
    "paused": False,
    "strategy": "rolling_update",
    "complete": True,
    "expected_live_pods": 3,
}
STATEFUL_SET: dict[str, Any] = {
    "kind": "stateful_set",
    **GENERATIONS,
    "desired_replicas": 3,
    "replicas": 3,
    "updated_replicas": 3,
    "available_replicas": 3,
    "current_revision": "api-6d5c4b3a2",
    "update_revision": "api-6d5c4b3a2",
    "strategy": "rolling_update",
    "partition": 0,
    "complete": True,
    "expected_live_pods": 3,
}
DAEMON_SET: dict[str, Any] = {
    "kind": "daemon_set",
    **GENERATIONS,
    "desired_number_scheduled": 5,
    "current_number_scheduled": 5,
    "updated_number_scheduled": 5,
    "number_available": 5,
    "number_misscheduled": 0,
    "strategy": "rolling_update",
    "complete": True,
    "expected_live_pods": 5,
}


@pytest.mark.parametrize("rollout", [DEPLOYMENT, STATEFUL_SET, DAEMON_SET])
def test_a_finished_rollout_is_complete(rollout: dict[str, Any]) -> None:
    assert ROLLOUT.validate_python(rollout).complete


@pytest.mark.parametrize(
    "rollout",
    [
        {**DEPLOYMENT, "observed_generation": 3},
        {**DEPLOYMENT, "paused": True},
        {**DEPLOYMENT, "updated_replicas": 2},
        {**DEPLOYMENT, "replicas": 4},
        {**DEPLOYMENT, "available_replicas": 2},
        {**STATEFUL_SET, "partition": 1},
        {**STATEFUL_SET, "strategy": "on_delete"},
        {**STATEFUL_SET, "update_revision": "api-7e6d5c4b3"},
        {**STATEFUL_SET, "current_revision": None, "update_revision": None},
        {**STATEFUL_SET, "available_replicas": 2},
        {**DAEMON_SET, "strategy": "on_delete"},
        {**DAEMON_SET, "updated_number_scheduled": 4},
        {**DAEMON_SET, "number_available": 4},
        {**DAEMON_SET, "number_misscheduled": 1},
    ],
)
def test_a_rollout_whose_counts_show_it_unfinished_is_not_complete(rollout: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match="rollout.complete is whether the rollout's counts show it finished"):
        ROLLOUT.validate_python(rollout)
    assert not ROLLOUT.validate_python({**rollout, "complete": False}).complete


@pytest.mark.parametrize(
    ("rollout", "live"),
    [({**DEPLOYMENT, "expected_live_pods": 2}, 3), ({**DAEMON_SET, "expected_live_pods": 6}, 5)],
)
def test_the_live_pods_a_rollout_calls_for_are_recomputed(rollout: dict[str, Any], live: int) -> None:
    with pytest.raises(ValidationError, match="expected_live_pods is the live pods the rollout.s counts call for"):
        ROLLOUT.validate_python(rollout)
    assert ROLLOUT.validate_python({**rollout, "expected_live_pods": live}).expected_live_pods == live


def test_a_rollout_names_its_kind() -> None:
    with pytest.raises(ValidationError, match="does not match any of the expected tags"):
        ROLLOUT.validate_python({**DEPLOYMENT, "kind": "replica_set"})
