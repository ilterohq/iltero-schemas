"""``AssuranceContext`` v1: the facts one evaluation is run against.

The context is the one JSON document the evaluator receives for one
assertion about one subject. It says what is being evaluated
(``evaluation``), for whom (``context``), what the trusted time is
(``reference_time``), and then only the parts the stage's profile provides:
the source, the change and plan, the subject, and — for a resource — that
resource as observed. The runner computes ``input_digest`` over exactly this
document, so it carries nothing the evaluator does not need: no evaluator
metadata, no bundle digests, no provenance. Every model refuses unknown
keys and coerces nothing, and the parts present must match the profile
exactly.

Two conventions hold throughout. A resource is named by its address in the
configuration of the infrastructure-as-code (IaC) tool, which is Terraform in
the current implementation. That address is the subject's local identity
(``models.common.subjects``) and the ``id`` on the resource and on the plan's table of
contents. The resources that refer to it
(``resource.related``) are embedded as the plan adapter observed them,
``address`` included. ``provider`` is the short name an assertion targets
(``aws``); what only the tool says about a resource is under ``tool_data``. A
value removed by redaction is a marker (``__redacted``), and the fields where
a redacted value may legitimately sit accept one. A fact the server could not
supply is an unknown marker (``__unknown``, see ``models.common.facts``) in place of
the list it would have filled, and a fact the IaC tool did not report is one
with its own reason. Null means a fact has no value, never that it is unknown:
the evaluator reads a null as a known value. The one exception is a related
resource's ``resource``, null when its values were not carried; an evaluation that
reads through it is ``unknown``.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import (
    Field,
    ValidationInfo,
    ValidatorFunctionWrapHandler,
    field_validator,
    model_validator,
)

from iltero_schemas.canonical.common.change import change_digest
from iltero_schemas.canonical.common.encoding import canonical_bytes
from iltero_schemas.models.common.assurance import Assurance
from iltero_schemas.models.common.base import API_VERSION as API_VERSION
from iltero_schemas.models.common.base import StrictModel
from iltero_schemas.models.common.change_type import (
    IAC_CHANGE_ACTIVITY,
    IAC_CHANGE_TYPE,
    IMAGE_BUILD_ACTIVITY,
    IMAGE_DEPLOY_ACTIVITY,
    IMAGE_RELEASE_TYPE,
)
from iltero_schemas.models.common.checked_content import checked_image, checked_plan
from iltero_schemas.models.common.commit_review import CommitReview, check_commit_review
from iltero_schemas.models.common.context_parts import (
    EvaluationRun,
    OrganizationScope,
    Plan,
    PlanResource,
    ProposedChange,
    RunRef,
    Source,
    Subject,
    check_kinds,
)
from iltero_schemas.models.common.facts import ServerFactsUnavailable
from iltero_schemas.models.common.fields import (
    Identity,
    parse_timestamp,
)
from iltero_schemas.models.common.reference_time import ReferenceTime
from iltero_schemas.models.common.server_facts import (
    Approvals,
    AttestationOutcome,
    Evaluations,
    VerifiedSource,
)
from iltero_schemas.models.common.subjects import ADDRESS_IDENTITY_SCHEMES, check_subject, local_identity, unit_of
from iltero_schemas.models.iac.apply_job_facts import (
    AcceptedPlanStageRecord,
    ApplyJobFacts,
    ApplyJobTiming,
    check_input_apply_job,
)
from iltero_schemas.models.iac.deployment import Deployment, check_superseded, check_tool
from iltero_schemas.models.iac.drift_check import NO_DRIFT_CHECK_WITHOUT_THE_STATE, DriftCheck, check_against_deployment
from iltero_schemas.models.iac.replan_check import ReplanCheck, ReplanNotCompared, check_input_replan
from iltero_schemas.models.iac.tool_names import ADDRESS_SCHEMES
from iltero_schemas.models.iac.tools.variants import check_tool_data
from iltero_schemas.models.image.build_reports import ScanReports, TestReports, check_scans_name_their_platform
from iltero_schemas.models.image.deploy import ImageChange, ImageDeployment, ImageDriftCheck, check_compared
from iltero_schemas.models.image.naming import ImageArtifact
from iltero_schemas.profiles import ALWAYS_REQUIRED_PARTS, profile_for

KIND = "AssuranceContext"
# The largest input an evaluation reads, measured over the canonical JSON of the input as this model writes it (every
# part, a part not given written as null): far more than one resource's plan, its related resources
# and the server's facts need, and a bound on what an evaluator is given to read.
MAX_INPUT_BYTES = 16 * 1024 * 1024
# The parts a profile may name, whether or not this version specifies their shape.
PARTS = (
    "source",
    "subject",
    "resource",
    "change",
    "plan",
    "evaluations",
    "approvals",
    "run",
    "deployment",
    "drift_check",
    "assurance",
    "artifact",
    "tests",
    "scans",
    "verified_source",
    "attestation_outcome",
    "commit_review",
    "apply_job_facts",
    "apply_job_timing",
    "replan_check",
)


def _production(scope: OrganizationScope) -> bool | None:
    """Whether the input's environment is production, when the input knows: None for no environment or the marker."""
    environment = scope.environment
    return environment.production if environment is not None and isinstance(environment.production, bool) else None


class AssuranceContext(StrictModel):
    """The document; the parts present are exactly what the stage's profile provides for the subject's kind."""

    api_version: Literal["iltero.com/v1"] = Field(alias="apiVersion")
    kind: Literal["AssuranceContext"]
    evaluation: EvaluationRun
    organization_scope: OrganizationScope
    reference_time: ReferenceTime
    source: Source | None = None
    # The change: an infrastructure change's resources, or a deployed image and its build; its digest either way.
    change: ProposedChange | ImageChange | None = None
    plan: Plan | None = None
    subject: Subject | None = None
    resource: PlanResource | None = None
    deployment: Deployment | ImageDeployment | None = None
    # Facts only the server holds (``models.common.server_facts``); a marker when it could not supply them.
    evaluations: Evaluations | ServerFactsUnavailable | None = None
    approvals: Approvals | ServerFactsUnavailable | None = None
    # Iltero's run this input belongs to, which an approval of a run names.
    run: RunRef | None = None
    drift_check: DriftCheck | ImageDriftCheck | None = None
    # An assertion's results about one subject over time (``models.common.assurance``).
    assurance: Assurance | None = None
    # The image a build produced, and the test and scan reports the build was given.
    artifact: ImageArtifact | None = None
    tests: TestReports | None = None
    scans: ScanReports | None = None
    # The commit the server verified for the run's job; a marker when it could not supply it.
    verified_source: VerifiedSource | ServerFactsUnavailable | None = None
    # What the server found when it checked the build's attestation; a marker when it could not supply it.
    attestation_outcome: AttestationOutcome | ServerFactsUnavailable | None = None
    # Whether the change's commits were reviewed (``models.common.commit_review``); a marker when it could not say.
    commit_review: CommitReview | ServerFactsUnavailable | None = None
    # What the server says about the job that applies an infrastructure change (``models.iac.apply_job_facts``); a
    # marker when it could not supply it. ``apply_job_timing`` is what ``apply_job_timing`` works out from it.
    apply_job_facts: ApplyJobFacts | ServerFactsUnavailable | None = None
    apply_job_timing: ApplyJobTiming | None = None
    # The re-plan check the apply job made (``models.iac.replan_check``): a comparison, or the marker that none was.
    replan_check: ReplanCheck | ReplanNotCompared | None = None

    @field_validator("change", "deployment", "drift_check", mode="wrap")
    @classmethod
    def _shape_of_the_activity(cls, value: Any, handler: ValidatorFunctionWrapHandler, info: ValidationInfo) -> Any:
        """The change, deployment and drift check parts are read in the shapes of the input's activity."""
        evaluation = info.data.get("evaluation")
        shapes = _SHAPES.get(evaluation.activity) if isinstance(evaluation, EvaluationRun) else None
        if value is None or shapes is None or info.field_name is None:
            return handler(value)
        return shapes[_SHAPED_PARTS.index(info.field_name)].model_validate(value)

    def _check_image_change(self, change: ImageChange, local: Identity) -> None:
        """A deployed image's change digest is of its image in its unit and environment, and what the deployment
        and the reading after it name is that change."""
        environment = self.organization_scope.environment
        key = environment.name if environment is not None else None
        image = checked_image(change.image.repository, change.image.digest).model_dump(mode="json")
        if change.digest != change_digest(IMAGE_RELEASE_TYPE, unit_of(local), key, image):
            raise ValueError("change.digest is the digest of the change type, unit, environment and image")
        if environment is not None and isinstance(change.build, ServerFactsUnavailable) != isinstance(
            environment.production, ServerFactsUnavailable
        ):
            raise ValueError(
                "change.build holds the unknown marker exactly when the environment's production flag does: "
                "both hold it only in a run no server opened"
            )
        if isinstance(self.drift_check, ImageDriftCheck):
            if self.drift_check.change_digest != change.digest:
                raise ValueError("drift_check.change_digest is change.digest")
            check_compared(self.drift_check, change.image.repository)

    @model_validator(mode="after")
    def _bounded(self) -> AssuranceContext:
        if len(canonical_bytes(self.model_dump(mode="json", by_alias=True))) > MAX_INPUT_BYTES:
            raise ValueError(f"an evaluation input is at most {MAX_INPUT_BYTES} bytes of canonical JSON")
        return self

    @model_validator(mode="after")
    def _parts_match_the_profile(self) -> AssuranceContext:
        if self.subject is None:
            raise ValueError("subject is required")
        profile = profile_for(self.evaluation.activity, self.evaluation.stage, self.subject.kind)
        present = {name for name in PARTS if getattr(self, name) is not None} | ALWAYS_REQUIRED_PARTS
        missing = sorted(profile.required - present)
        extra = sorted(present - profile.roots)
        if missing:
            raise ValueError(f"{profile.name}: missing {', '.join(missing)}")
        if extra:
            raise ValueError(f"{profile.name}: not part of this profile: {', '.join(extra)}")
        if self.reference_time.source == "runner_clock" and parse_timestamp(
            self.reference_time.value
        ) != parse_timestamp(self.evaluation.timestamp):
            raise ValueError("an input that reads its runner's clock uses the time of its evaluation")
        if self.plan is not None and self.source is not None and self.plan.source_commit != self.source.commit.sha:
            raise ValueError("plan.source_commit must be the source commit")
        check_subject(self.subject.kind, self.subject.key, self.subject.identities, self.evaluation.stage, None)
        local = local_identity(self.subject.kind, self.subject.identities)
        if self.resource is not None and local.scheme in ADDRESS_IDENTITY_SCHEMES:
            if (local.scheme, local.value) != (ADDRESS_SCHEMES[self.resource.tool_data.tool], self.resource.id):
                raise ValueError("a resource subject is named by the address of the resource the input carries")
        if self.plan is not None and isinstance(self.change, ProposedChange):
            environment = self.organization_scope.environment
            key = environment.name if environment is not None else None
            plan = checked_plan(self.plan.digest, self.plan.digest_version, self.plan.tool).model_dump(mode="json")
            if self.change.digest != change_digest(IAC_CHANGE_TYPE, unit_of(local), key, plan):
                raise ValueError("change.digest is the digest of the change type, unit, environment and plan")
        if self.plan is not None:
            change_resources = self.change.resources if isinstance(self.change, ProposedChange) else []
            check_kinds(self.plan.tool, self.plan.resources + change_resources)
            if self.resource is not None:
                check_tool_data(self.plan.tool, [self.resource.tool_data], "resource.tool_data")
            deployment = self.deployment if isinstance(self.deployment, Deployment) else None
            check_superseded(self.plan.digest, deployment)
            check_tool(self.plan.tool, deployment)
        if isinstance(self.drift_check, DriftCheck) and isinstance(self.deployment, Deployment):
            if not self.deployment.apply.state_read:
                raise ValueError(NO_DRIFT_CHECK_WITHOUT_THE_STATE)
            check_against_deployment(self.drift_check, self.deployment)
        if self.evaluation.activity == IMAGE_BUILD_ACTIVITY and self.organization_scope.environment is not None:
            raise ValueError("a build's input names no environment: a build belongs to none")
        if self.evaluation.activity == IMAGE_DEPLOY_ACTIVITY and self.organization_scope.environment is None:
            raise ValueError("a deploy's input names its environment: a deploy is to one")
        if isinstance(self.change, ImageChange):
            self._check_image_change(self.change, local)
        if self.commit_review is not None:
            environment = self.organization_scope.environment
            check_commit_review(
                self.commit_review,
                self.evaluation.activity,
                self.source.commit.sha if self.source is not None else None,
                environment.production if environment is not None else None,
                self.change.build if isinstance(self.change, ImageChange) else None,
            )
        check_input_apply_job(
            self.apply_job_facts,
            self.apply_job_timing,
            self.approvals,
            _accepted_plan_stage_record(self.run, self.change, self.plan),
            self.plan.artifact_digest_source if self.plan is not None else None,
            _production(self.organization_scope),
        )
        check_input_replan(
            self.apply_job_facts,
            self.replan_check,
            self.run.id if self.run is not None else None,
            self.change.digest if self.change is not None else None,
            self.plan.tool if self.plan is not None else None,
        )
        if self.artifact is not None and self.scans is not None:
            scanned = [scan.image_digest for scan in self.scans]
            check_scans_name_their_platform(self.artifact.digest, self.artifact.platform_digests, scanned)
        return self


def _accepted_plan_stage_record(
    run: RunRef | None, change: ProposedChange | ImageChange | None, plan: Plan | None
) -> AcceptedPlanStageRecord | None:
    """The plan-stage record an infrastructure change's input is about, as the apply job's facts name it."""
    if run is None or not isinstance(change, ProposedChange) or plan is None:
        return None
    return AcceptedPlanStageRecord(
        run_id=run.id, change_digest=change.digest, plan_digest=plan.digest, artifact_digest=plan.artifact_digest
    )


# The parts whose shape depends on the input's activity, and their shapes for each activity that has them.
_SHAPED_PARTS = ("change", "deployment", "drift_check")
_SHAPES: dict[str, tuple[type[StrictModel], type[StrictModel], type[StrictModel]]] = {
    IAC_CHANGE_ACTIVITY: (ProposedChange, Deployment, DriftCheck),
    IMAGE_DEPLOY_ACTIVITY: (ImageChange, ImageDeployment, ImageDriftCheck),
}
