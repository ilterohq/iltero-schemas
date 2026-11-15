"""Checks postponed until after the deployment: a plan-stage check that read a value the plan knows only after the
deployment, evaluated again at post-verify over the values Terraform's state holds after the apply.

At plan, such a check is ``unknown`` for the reason ``known_after_deploy``. Whether
that stops the plan gate is a setting of the run the plan stage records
(``values_known_after_deployment``): it blocks on it, or postpones it, listing
each check in ``postponed_checks`` and counting them in its coverage under the gap
kind ``checked_after_deployment``, so its gate treats them as decided later. A
check is postponed only in a run that includes post-verify, and only when its
verdict at plan is unknown for that reason alone: the assertion's own condition
(Open Policy Agent, OPA) left a value of the resource after the plan
(``resource.after``) unsettled, its ``when`` guard settled, and every other
evaluator of it passed or left it unknown for the same reason.

A postponed check names its assertion (id, version and document digest), its
subject, the path its condition could not settle, and the plan it was evaluated
over. At post-verify the same assertion is evaluated for the same subject over
the resource's values after the apply, with ``plan`` naming that same plan: one
evaluation per postponed check. A record that reaches post-verify settles every
check its plan stage postponed. The values after the apply that these
evaluations read are redacted, and reported in the post-verify stage's
``resource_redaction``.

What a postponed check is evaluated over is the tool's own knowledge after the
apply, not a reading of the cloud: it never stands for a running state.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field

from iltero_schemas.ast import AssertionSyntaxError, parse_document
from iltero_schemas.ast.nodes import All, AnyOf, Assertion, Exists, Expr, Not, Path, Predicate
from iltero_schemas.ast.roots import ITEM_ROOT
from iltero_schemas.canonical.encoding import digest_of
from iltero_schemas.models.assertion import Stage, TargetKind
from iltero_schemas.models.base import StrictModel
from iltero_schemas.models.change_type import ActivityName
from iltero_schemas.models.coverage import (
    CHECKED_AFTER_DEPLOYMENT,
    INCOMPLETE_REASON_PRECEDENCE,
    OPEN_CHECKS_REASON,
    AssuranceStatus,
    postponed_count,
)
from iltero_schemas.models.event import AssertionRef, AssuranceEvent, OpaEvaluator
from iltero_schemas.models.fields import MAX_RESOURCES, Digest
from iltero_schemas.models.iac.scanner_verdicts import plan_unknown_paths
from iltero_schemas.models.kept_files import KeptFiles
from iltero_schemas.models.subjects import local_identity
from iltero_schemas.profiles import profile_for

if TYPE_CHECKING:
    from iltero_schemas.models.car import CAR

# The one reason a check is postponed for.
POSTPONED_REASON = "known_after_deploy"
# The longest path a postponed check names.
MAX_PATH_LENGTH = 1024
# The values a postponed check is settled over: the resource after the apply, as the plan names them.
SETTLED_ROOT = "resource.after."


# What tells postponed checks apart: the assertion's id, version and document digest, and the subject's key.
CheckKey = tuple[str, str, str, str]


class PostponedCheck(StrictModel):
    """One plan-stage check postponed until after the deployment."""

    assertion: AssertionRef
    subject_key: Digest
    # The path the condition could not settle, as the condition names it (``resource.after.storage_encrypted``).
    path: Annotated[str, Field(pattern=r"^resource\.after\.[A-Za-z0-9_.-]+$", max_length=MAX_PATH_LENGTH)]
    plan_digest: Digest

    @property
    def key(self) -> CheckKey:
        return self.assertion.id, self.assertion.version, self.assertion.digest, self.subject_key


PostponedChecks = Annotated[list[PostponedCheck], Field(max_length=MAX_RESOURCES)]


def _paths_of(expr: Expr | None) -> Iterable[Path]:
    if expr is None:
        return
    if isinstance(expr, Predicate):
        yield expr.path
        if isinstance(expr.operand, Path):
            yield expr.operand
    elif isinstance(expr, All | AnyOf):
        for arg in expr.args:
            yield from _paths_of(arg)
    elif isinstance(expr, Not):
        yield from _paths_of(expr.arg)
    elif isinstance(expr, Exists):
        yield expr.collection
        yield from _paths_of(expr.where)


def postponable(assertion: Assertion, activity: ActivityName) -> bool:
    """Whether a check of ``assertion`` may be postponed until after the deployment: it has a condition, is about a
    resource at plan, and reads only what a post-verify input about a resource holds."""
    if (
        assertion.assert_ is None
        or assertion.stages != (Stage.PLAN,)
        or assertion.target.kind is not TargetKind.RESOURCE
    ):
        return False
    roots = profile_for(activity, Stage.POST_VERIFY, TargetKind.RESOURCE).roots
    return all(
        path.root in roots or path.root == ITEM_ROOT
        for path in (*_paths_of(assertion.when), *_paths_of(assertion.assert_))
    )


def postponable_checks(events: Iterable[AssuranceEvent]) -> dict[CheckKey, tuple[AssuranceEvent, str]]:
    """The checks of a plan stage's ``events`` its run may postpone (see the module docstring), by (assertion id,
    version, digest, subject key), each with its evaluation by the condition and the path it could not settle."""
    grouped: dict[CheckKey, list[AssuranceEvent]] = {}
    for event in events:
        if event.subject.key is not None:
            key = (event.assertion.id, event.assertion.version, event.assertion.digest, event.subject.key)
            grouped.setdefault(key, []).append(event)
    found = {}
    for key, group in grouped.items():
        own = next((e for e in group if isinstance(e.provenance.evaluator, OpaEvaluator)), None)
        if own is None or (own.evaluation.status, own.evaluation.status_reason) != ("unknown", POSTPONED_REASON):
            continue
        observations = own.evaluation.observations or {}
        unknown = observations.get("unknown")
        if observations.get("when") == "unknown" or not isinstance(unknown, dict):
            continue
        path = unknown.get("path")
        if unknown.get("reason") != POSTPONED_REASON or not isinstance(path, str) or not path.startswith(SETTLED_ROOT):
            continue
        others = [(e.evaluation.status, e.evaluation.status_reason) for e in group if e is not own]
        if all(other in (("pass", None), ("unknown", POSTPONED_REASON)) for other in others):
            found[key] = (own, path)
    return found


def open_postponed_checks(car: CAR) -> int:
    """How many checks the record's plan stage postponed that no post-verify stage of the record settles."""
    plan = car.stages.get(Stage.PLAN)
    if plan is None or not plan.postponed_checks or Stage.POST_VERIFY in car.stages:
        return 0
    return len(plan.postponed_checks)


def open_checks_status(count: int, stages: AssuranceStatus) -> AssuranceStatus:
    """The status of a record that leaves ``count`` postponed checks open, given the status its stages combine into:
    incomplete, for the open checks unless the stages give a reason that comes first in
    ``INCOMPLETE_REASON_PRECEDENCE``."""
    if count == 0 or (
        stages.reason in INCOMPLETE_REASON_PRECEDENCE
        and INCOMPLETE_REASON_PRECEDENCE.index(stages.reason) < INCOMPLETE_REASON_PRECEDENCE.index(OPEN_CHECKS_REASON)
    ):
        return stages
    checks = "check" if count == 1 else "checks"
    detail = f"{count} {checks} postponed until after the deployment {'was' if count == 1 else 'were'} not settled"
    return AssuranceStatus(value="incomplete", reason=OPEN_CHECKS_REASON, detail=detail)


def settles_a_postponed_check(event: AssuranceEvent) -> bool:
    """Whether ``event`` settles a check the plan stage postponed: an evaluation about a resource at post-verify."""
    return event.evaluation.stage is Stage.POST_VERIFY and TargetKind(event.subject.kind) is TargetKind.RESOURCE


def _settling(car: CAR) -> list[AssuranceEvent]:
    return [event for event in car.events if settles_a_postponed_check(event)]


def check_postponed_checks(car: CAR) -> None:
    """Raise ``ValueError`` unless only the plan stage lists postponed checks, it lists exactly the checks it may
    postpone and counts them, every resource evaluation at post-verify settles one of them over the same plan, and a
    record that reached post-verify settles each once."""
    for stage, record in car.stages.items():
        at_plan = stage is Stage.PLAN
        if at_plan != (record.values_known_after_deployment is not None):
            raise ValueError("the plan stage, and only it, says what its gate does with a value known after deployment")
        if (record.postponed_checks is not None) != (record.values_known_after_deployment == "postpone"):
            raise ValueError("a stage lists postponed checks exactly when it postpones them")
        if not at_plan and postponed_count(record.coverage.gaps):
            raise ValueError(f"only the plan stage counts checks as {CHECKED_AFTER_DEPLOYMENT}")
        if stage is not Stage.POST_VERIFY and record.resource_redaction is not None:
            raise ValueError("only the post-verify stage redacts values after the apply")
        if record.resource_redaction is not None and record.resource_redaction.input.kind != "post_apply_resources":
            raise ValueError("the post-verify stage's resource redaction is of the values after the apply")
    plan = car.stages.get(Stage.PLAN)
    listed = plan.postponed_checks if plan is not None and plan.postponed_checks is not None else []
    counted = postponed_count(plan.coverage.gaps) if plan is not None else 0
    if plan is not None and plan.postponed_checks is not None:
        found = postponable_checks(e for e in car.events if e.evaluation.stage is Stage.PLAN)
        # A check left off the list stays unknown at plan and holds its gate: the list may be shorter, never longer.
        if not {check.key for check in listed} <= set(found) or len({check.key for check in listed}) != len(listed):
            raise ValueError("the plan stage lists, once each, only checks it may postpone")
        for check in listed:
            event, path = found[check.key]
            if check.plan_digest != event.provenance.checked_content.digest or check.path != path:
                raise ValueError("a postponed check names the plan and the path of the evaluation it postpones")
        if listed and Stage.POST_VERIFY not in car.expected_stages:
            raise ValueError("a check is postponed only in a run that includes post-verify, which settles it")
    if counted != len(listed):
        raise ValueError(f"the plan stage counts its postponed checks as {CHECKED_AFTER_DEPLOYMENT}")
    settling = _settling(car)
    by_key = {check.key: check for check in listed}
    seen: set[CheckKey] = set()
    for event in settling:
        key = (event.assertion.id, event.assertion.version, event.assertion.digest, event.subject.key or "")
        postponed = by_key.get(key)
        evaluator = event.provenance.evaluator
        # The assertion's own rule settles it, or, when no evaluator could run, the check stays not evaluated.
        ran = isinstance(evaluator, OpaEvaluator) or (evaluator is None and event.evaluation.status == "not_evaluated")
        if postponed is None or not ran or key in seen:
            raise ValueError("a resource evaluation at post-verify settles, once, a check the plan stage postponed")
        if event.provenance.checked_content.digest != postponed.plan_digest:
            raise ValueError("a postponed check is settled over the plan it was postponed from")
        seen.add(key)
    post_verify = car.stages.get(Stage.POST_VERIFY)
    if post_verify is not None:
        if seen != set(by_key):
            raise ValueError("a record that reached post-verify settles every check its plan stage postponed")
        if (post_verify.resource_redaction is not None) != bool(settling):
            raise ValueError("the post-verify stage reports what it redacted of the values its settling checks read")


def _meets(segments: list[str], path: str) -> bool:
    """Whether a condition's path and a path the plan leaves unknown name the same value or one inside the other."""
    unknown = path.split("/")
    shorter = min(len(segments), len(unknown))
    return segments[:shorter] == unknown[:shorter]


def _kept_plan(car: CAR, files: KeptFiles) -> dict[str, Any] | None:
    """The one plan the record keeps among ``files``: given, an entry of its evidence register, and a plan."""
    register = {ref.digest for ref in car.evidence_refs}
    kept = [
        plan
        for digest, plan in files.plans.items()
        if digest in register and isinstance(plan, dict) and isinstance(plan.get("resource_changes"), list)
    ]
    return kept[0] if len(kept) == 1 else None


def postponed_check_problems(car: CAR, files: KeptFiles) -> list[tuple[str, str]]:
    """Every postponed check that the files its plan stage kept do not bear out, as (where, what) pairs: its assertion's
    document (``files.assertions``, by its digest) is one whose check may be postponed, and the one plan the stage kept
    (``files.plans``, an entry of the evidence register) leaves the value at its path unknown on its subject's
    resource."""
    stage = car.stages.get(Stage.PLAN)
    listed = stage.postponed_checks if stage is not None and stage.postponed_checks is not None else []
    if not listed:
        return []
    plan = _kept_plan(car, files)
    if plan is None:
        return [("stages.plan.postponed_checks", "names checks of a plan the record does not keep")]
    unknown: dict[str, list[str]] = {}
    for change in plan["resource_changes"]:
        body = change.get("change") if isinstance(change, dict) else None
        if isinstance(body, dict) and change.get("mode") == "managed" and isinstance(change.get("address"), str):
            unknown[change["address"]] = plan_unknown_paths(body.get("after_unknown"))
    subjects = {
        e.subject.key: local_identity(e.subject.kind, e.subject.identities).value
        for e in car.events
        if e.evaluation.stage is Stage.PLAN and e.subject.key is not None
    }
    problems = []
    for number, check in enumerate(listed):
        where = f"stages.plan.postponed_checks.{number}"
        document = files.assertions.get(check.assertion.digest)
        try:
            if not isinstance(document, dict) or digest_of(document) != check.assertion.digest:
                raise AssertionSyntaxError([])
            assertion = parse_document(document)
        except AssertionSyntaxError:
            problems.append((where, "names an assertion document that is not given"))
            continue
        if not postponable(assertion, car.change.activity):
            problems.append((where, "postpones a check whose condition reads what post-verify does not hold"))
            continue
        segments = check.path.removeprefix(SETTLED_ROOT).split(".")
        if not any(_meets(segments, path) for path in unknown.get(subjects.get(check.subject_key, ""), [])):
            problems.append((where, "postpones a check on a value the plan it kept does not leave unknown"))
    return problems
