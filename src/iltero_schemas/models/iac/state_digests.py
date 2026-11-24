"""The form of the state digests a change made with an IaC tool names, by who opened the run.

A record never keeps the state. In a run the server opened, it names a state by the keyed digest of the bytes read
(``canonical.common.run_digest_key.keyed_given_file_digest``, ``hmac-sha256:``). In a run the tool opened, it names a
state by the digest of the state as the record's redaction policy leaves it (``redaction.iac.state``, ``sha256:``),
which only a holder of the state computes again. The state the deployment was held to and the one the identities were
read from each name one; ``StateSource`` checks that its ``digest_version`` is the one its digest's form names.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING

from iltero_schemas.canonical.common.run_digest_key import KEYED_DIGEST_PREFIX
from iltero_schemas.models.iac.deployment import Deployment, StateSource

if TYPE_CHECKING:
    from iltero_schemas.change_types.iac.change import IacChange
    from iltero_schemas.models.common.car import CAR
    from iltero_schemas.models.common.context import AssuranceContext
    from iltero_schemas.models.common.fields import RunOpenedBy

SERVER_RUN_STATE_FORM = "a record of a run the server opened names every state by its keyed digest"
TOOL_RUN_STATE_FORM = (
    "a record of a run the tool opened names every state by the digest of the state as its redaction policy leaves it"
)


def state_digest_follows_the_run(state_digest: str, run_opened_by: RunOpenedBy) -> bool:
    """Whether ``state_digest`` has the form of who opened the run: keyed in a run the server opened, plain in a run
    the tool opened."""
    return state_digest.startswith(KEYED_DIGEST_PREFIX) == (run_opened_by == "server")


def state_form_problem(states: Iterable[StateSource], run_opened_by: RunOpenedBy) -> str | None:
    """The refusal for ``states`` when any of them names its digest in another form than who opened the run gives;
    None when every one has it."""
    if all(state_digest_follows_the_run(state.digest, run_opened_by) for state in states):
        return None
    return SERVER_RUN_STATE_FORM if run_opened_by == "server" else TOOL_RUN_STATE_FORM


def deployment_states(deployment: Deployment) -> list[StateSource]:
    """The state a deployment was held to, when it was read."""
    return [deployment.apply.state] if isinstance(deployment.apply.state, StateSource) else []


def context_states(context: AssuranceContext) -> list[StateSource]:
    """The state an evaluation input's deployment of a change made with an IaC tool names; none for an input of another
    change type, or one whose state was not read."""
    return deployment_states(context.deployment) if isinstance(context.deployment, Deployment) else []


def check_change_state_digest_form(car: CAR, change: IacChange) -> None:
    """Raise ``ValueError`` unless the states ``change`` names, the deployment's and the identities', name their digests
    in the form of who opened the run."""
    states = deployment_states(change.deployment) if change.deployment is not None else []
    if change.identity is not None:
        states.append(change.identity.sources.state)
    problem = state_form_problem(states, car.governance.run_opened_by)
    if problem is not None:
        raise ValueError(problem)
