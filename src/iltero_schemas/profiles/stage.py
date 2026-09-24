"""Which parts of the facts an evaluation input carries, per stage and target.

An evaluation input is a projection, not an accumulation: it carries only
the parts the stage can know. A profile names the parts that must be
present (``required``) and the parts that may be (``optional``); a part
outside the profile is never present. Five profiles cover the nine valid
stage and target combinations, and ``resource`` is added for a resource
target. The path roots the parser accepts for an assertion are exactly a
profile's parts, so an assertion can only name what its input will hold.
"""

from __future__ import annotations

from dataclasses import dataclass

from iltero_schemas.models.assertion import VALID_COMBINATIONS, Stage, TargetKind

# Present at every stage: what is being evaluated, for which organization,
# workspace and environment, and the trusted time.
ALWAYS = frozenset({"evaluation", "context", "reference_time"})
_SOURCE = frozenset({"source"})
_CHANGE = frozenset({"change", "plan", "subject"})


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


PLAN_RESOURCE = Profile("plan_resource", ALWAYS | _SOURCE | _CHANGE, frozenset())
PRE_DEPLOY_CHANGE = Profile(
    "pre_deploy_change", ALWAYS | _SOURCE | _CHANGE | {"evaluations", "approvals", "exceptions"}, frozenset()
)
POST_DEPLOY = Profile("post_deploy", ALWAYS | _SOURCE | _CHANGE | {"deployment"}, frozenset())
VERIFICATION = Profile("verification", ALWAYS | {"subject", "deployment"}, _SOURCE | {"verification", "assurance"})
RUNTIME = Profile("runtime", ALWAYS | {"subject"}, _SOURCE | {"deployment", "assurance", "exceptions"})

_BY_STAGE: dict[Stage, Profile] = {
    Stage.PLAN: PLAN_RESOURCE,
    Stage.PRE_DEPLOY: PRE_DEPLOY_CHANGE,
    Stage.POST_DEPLOY: POST_DEPLOY,
    Stage.POST_VERIFY: VERIFICATION,
    Stage.RUNTIME: RUNTIME,
}

# One profile per valid (stage, target) combination.
PROFILES: dict[tuple[Stage, TargetKind], Profile] = {
    (stage, kind): (_BY_STAGE[stage].with_resource() if kind is TargetKind.RESOURCE else _BY_STAGE[stage])
    for _type, stage, kind in VALID_COMBINATIONS
}


def profile_for(stage: Stage, target_kind: TargetKind) -> Profile:
    """The profile of an assertion at ``stage`` about ``target_kind``; an invalid combination has none."""
    try:
        return PROFILES[(stage, target_kind)]
    except KeyError:
        raise ValueError(f"stage {stage.value!r} is not valid for target kind {target_kind.value!r}") from None
