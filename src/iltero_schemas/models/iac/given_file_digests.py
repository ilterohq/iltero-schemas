"""The digests a change made with an IaC tool names of files its record never keeps whole, and their form by who
opened the run (``models.common.given_file_digests``): the apply log's in the deployment, and the drift check's two
readings. Each is keyed in a run the server opened and null in a run the tool opened. The state is named another way
(``models.iac.state_digests``)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from iltero_schemas.models.common.given_file_digests import form_problem
from iltero_schemas.models.iac.deployment import Deployment
from iltero_schemas.models.iac.drift_check import DriftCheck

if TYPE_CHECKING:
    from iltero_schemas.change_types.iac.change import IacChange
    from iltero_schemas.models.common.car import CAR
    from iltero_schemas.models.common.context import AssuranceContext


def deployment_given_file_digests(deployment: Deployment) -> list[str | None]:
    """The digest a deployment names of a file the record never keeps whole: the apply log's."""
    return [deployment.apply.source.digest]


def drift_check_given_file_digests(check: DriftCheck) -> list[str | None]:
    """The digests of the drift check's two readings, which the record never keeps."""
    return [check.first_reading_digest, check.second_reading_digest]


def context_given_file_digests(context: AssuranceContext) -> list[str | None]:
    """The digests an evaluation input names of files the record keeps redacted, or never keeps: those of the
    deployment and of the drift check of a change made with an IaC tool; none for an input of another change type."""
    named: list[str | None] = []
    if isinstance(context.deployment, Deployment):
        named += deployment_given_file_digests(context.deployment)
    if isinstance(context.drift_check, DriftCheck):
        named += drift_check_given_file_digests(context.drift_check)
    return named


def check_change_given_file_digest_form(car: CAR, change: IacChange) -> None:
    """Raise ``ValueError`` unless the digests ``change`` names of files the record never keeps whole have the form of
    who opened the run: the deployment's apply log and the drift check's readings."""
    named: list[str | None] = []
    if change.deployment is not None:
        named += deployment_given_file_digests(change.deployment)
    if change.drift_check is not None:
        named += drift_check_given_file_digests(change.drift_check)
    problem = form_problem(named, car.run.opened_by)
    if problem is not None:
        raise ValueError(problem)
