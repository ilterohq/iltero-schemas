"""Which parts of the facts an evaluation input carries, per activity, stage and target.

An evaluation input is a projection, not an accumulation: it carries only
the parts the stage can know. A profile names the parts that must be
present (``required``) and the parts that may be (``optional``); a part
outside the profile is never present. Each activity has a profile for every
stage and target its change type's assertions may declare, and ``resource``
is added for a resource target. The path roots the parser accepts for an
assertion are exactly what its input will hold: its profile's parts, or for an
assertion about any change, the parts every activity's profile there shares.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from iltero_schemas.models.assertion import COMBINATIONS, Stage, TargetKind
from iltero_schemas.models.change_type import (
    CHANGE_TYPE_OF,
    CHECKED_CONTENT_KIND_OF,
    IAC_CHANGE_ACTIVITY,
    IAC_CHANGE_TYPE,
    IMAGE_BUILD_ACTIVITY,
    IMAGE_DEPLOY_ACTIVITY,
    ActivityName,
    ChangeTypeName,
)

# Present at every stage: what is being evaluated, for which organization,
# workspace and environment, and the trusted time.
ALWAYS_REQUIRED_PARTS = frozenset({"evaluation", "organization_scope", "reference_time"})
_SOURCE = frozenset({"source"})
_CHANGE = frozenset({"change", "plan", "subject"})
# The facts only the server holds about a change before it is deployed: earlier evaluations, approvals, exceptions.
_CHANGE_FACTS = frozenset({"evaluations", "approvals", "exceptions"})
# The parts only the server holds. An input that may carry one reads server facts.
SERVER_FACTS = _CHANGE_FACTS | {"verified_source", "attestation_outcome"}
# The parts that name the content the change checked: the plan, the built image, or the deployed image's change.
CHECKED_CONTENT_PARTS = frozenset({"plan", "artifact", "change"})


@dataclass(frozen=True)
class Profile:
    """The parts an input carries: ``required`` are always there, ``optional`` may be."""

    name: str
    required: frozenset[str]
    optional: frozenset[str]

    @property
    def roots(self) -> frozenset[str]:
        return self.required | self.optional

    def with_resource(self) -> Profile:
        """The same profile for a resource target: ``resource`` is required too."""
        return Profile(self.name, self.required | {"resource"}, self.optional)


PLAN_RESOURCE = Profile("plan_resource", ALWAYS_REQUIRED_PARTS | _SOURCE | _CHANGE, frozenset())
# A pre-deploy input names the run it belongs to, which an approval of a run names.
PRE_DEPLOY_CHANGE = Profile(
    "pre_deploy_change", ALWAYS_REQUIRED_PARTS | _SOURCE | _CHANGE | _CHANGE_FACTS | {"run"}, frozenset()
)
POST_DEPLOY = Profile("post_deploy", ALWAYS_REQUIRED_PARTS | _SOURCE | _CHANGE | {"deployment"}, frozenset())
# A post-verify input carries the drift check: what reading the deployed resources back found.
POST_VERIFY = Profile(
    "post_verify", ALWAYS_REQUIRED_PARTS | {"subject", "deployment", "drift_check"}, _SOURCE | {"assurance"}
)
RUNTIME = Profile("runtime", ALWAYS_REQUIRED_PARTS | {"subject"}, _SOURCE | {"deployment", "assurance", "exceptions"})
# A build's input: the image it built, the test and scan reports it was given, the commit the server verified from
# the build job's identity, and what the server found when it checked the build's attestation.
PLAN_ARTIFACT = Profile(
    "plan_artifact",
    ALWAYS_REQUIRED_PARTS
    | _SOURCE
    | {"subject", "artifact", "tests", "scans", "verified_source", "attestation_outcome"},
    frozenset(),
)

# A deploy of a built image: the change names the image and the build the server accepted; no plan. Before the
# deployment it reads the server's facts about the change, after it the image the pipeline deployed, and at
# post-verify the reading of the workload.
IMAGE_PRE_DEPLOY = Profile(
    "image_pre_deploy_change",
    ALWAYS_REQUIRED_PARTS | _SOURCE | {"change", "subject"} | _CHANGE_FACTS | {"run"},
    frozenset(),
)
IMAGE_POST_DEPLOY = Profile(
    "image_post_deploy", ALWAYS_REQUIRED_PARTS | _SOURCE | {"change", "subject", "deployment"}, frozenset()
)
IMAGE_POST_VERIFY = Profile(
    "image_post_verify", ALWAYS_REQUIRED_PARTS | {"change", "subject", "deployment", "drift_check"}, _SOURCE
)

_IAC_BY_STAGE: dict[Stage, Profile] = {
    Stage.PLAN: PLAN_RESOURCE,
    Stage.PRE_DEPLOY: PRE_DEPLOY_CHANGE,
    Stage.POST_DEPLOY: POST_DEPLOY,
    Stage.POST_VERIFY: POST_VERIFY,
    Stage.RUNTIME: RUNTIME,
}

# The profile of each activity at each stage and target its change type's assertions may declare.
PROFILES: Mapping[tuple[ActivityName, Stage, TargetKind], Profile] = MappingProxyType(
    {
        **{
            (IAC_CHANGE_ACTIVITY, stage, kind): (
                _IAC_BY_STAGE[stage].with_resource() if kind is TargetKind.RESOURCE else _IAC_BY_STAGE[stage]
            )
            for _type, stage, kind in COMBINATIONS[IAC_CHANGE_TYPE]
        },
        (IMAGE_BUILD_ACTIVITY, Stage.PLAN, TargetKind.ARTIFACT): PLAN_ARTIFACT,
        (IMAGE_DEPLOY_ACTIVITY, Stage.PRE_DEPLOY, TargetKind.CHANGE): IMAGE_PRE_DEPLOY,
        (IMAGE_DEPLOY_ACTIVITY, Stage.POST_DEPLOY, TargetKind.DEPLOYMENT): IMAGE_POST_DEPLOY,
        (IMAGE_DEPLOY_ACTIVITY, Stage.POST_VERIFY, TargetKind.DEPLOYMENT): IMAGE_POST_VERIFY,
    }
)


def reads_server_facts(activity: ActivityName, stage: Stage) -> bool:
    """Whether an input of ``activity`` at ``stage`` may carry facts only the server holds."""
    return any(
        profile.roots & SERVER_FACTS for (of, at, _kind), profile in PROFILES.items() if (of, at) == (activity, stage)
    )


def reads_approvals(activity: ActivityName, stage: Stage) -> bool:
    """Whether an input of ``activity`` at ``stage`` carries approvals."""
    return any(
        "approvals" in profile.roots for (of, at, _kind), profile in PROFILES.items() if (of, at) == (activity, stage)
    )


def reads_checked_content(stage: Stage) -> frozenset[str | None]:
    """The kinds of checked content the inputs at ``stage`` carry, one per activity evaluated there, such as ``plan``
    or ``container_image``; ``None`` for an activity whose input there carries none."""
    return frozenset(
        CHECKED_CONTENT_KIND_OF[activity] if profile.roots & CHECKED_CONTENT_PARTS else None
        for (activity, at, _kind), profile in PROFILES.items()
        if at is stage
    )


def profile_for(activity: ActivityName, stage: Stage, target_kind: TargetKind) -> Profile:
    """The profile of ``activity`` at ``stage`` about ``target_kind``; an invalid combination has none."""
    try:
        return PROFILES[(activity, stage, target_kind)]
    except KeyError:
        raise ValueError(
            f"stage {stage.value!r} is not valid for target kind {target_kind.value!r} in an {activity} input"
        ) from None


def roots_for(change_type: ChangeTypeName | None, stage: Stage, target_kind: TargetKind) -> frozenset[str]:
    """The parts an assertion about ``change_type``, or about any change when None, at ``stage`` and ``target_kind``
    may read: those the profile of every activity it is evaluated for holds."""
    profiles = [
        profile
        for (activity, at, kind), profile in PROFILES.items()
        if (at, kind) == (stage, target_kind) and change_type in (None, CHANGE_TYPE_OF[activity])
    ]
    if not profiles:
        raise ValueError(f"stage {stage.value!r} is not valid for target kind {target_kind.value!r}")
    return frozenset.intersection(*(profile.roots for profile in profiles))
