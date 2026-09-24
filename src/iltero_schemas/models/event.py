"""``AssuranceEvent`` v1, as a runner submits it: one verdict with its provenance.

The evaluator's answer is not the event. The runner wraps it: which
assertion, about which subject, with what status and why, and everything
needed to reproduce the verdict — the input's digest, the evaluator and its
limits, the bundle, the compiler. Nothing here is set by the policy; the
policy's own ``reason`` and ``observations`` are carried as what it said,
within the same bounds the evaluator's output contract puts on them.

This is the claim as submitted. Fields assigned on receipt are not part of
it and are refused if present.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import AfterValidator, Field, model_validator

from iltero_schemas.canonical.encoding import CanonicalizationError, canonical_bytes
from iltero_schemas.compiler.limits import (
    OBSERVATIONS_MAX_BYTES,
    OBSERVATIONS_MAX_DEPTH,
    REASON_MAX_BYTES,
    nesting_depth,
)
from iltero_schemas.models.assertion import ID_MAX_LENGTH, ID_PATTERN, VERSION_MAX_LENGTH, VERSION_PATTERN
from iltero_schemas.models.base import StageValue, StrictModel, TargetKindValue
from iltero_schemas.models.context import Authority, Identity
from iltero_schemas.models.fields import Address, Commit, Digest, Identifier, Timestamp, plain_text

Status = Literal["pass", "fail", "unknown", "not_applicable", "not_evaluated", "error"]
# Why a status is what it is; the runner sets it, a policy never does.
STATUS_REASONS: dict[str, frozenset[str]] = {
    "pass": frozenset(),
    # The applied plan is not the evaluated one.
    "fail": frozenset({"plan_superseded"}),
    "unknown": frozenset(
        {
            "known_after_apply",
            "redacted",
            "path_missing",
            "not_a_list",
            "unspecified",
            "server_facts_unavailable",
            "reference_time_untrusted",
            "apply_log_incomplete",
        }
    ),
    "not_applicable": frozenset({"when_guard_excluded", "no_subject_in_scope"}),
    "not_evaluated": frozenset(
        {
            "scanner_not_run",
            "credential_denied",
            "resource_type_unsupported",
            "binding_unverified",
            "timeout",
            "subject_unresolved",
            "evaluator_unavailable",
            "identity_unverified",
            "stage_not_run",
        }
    ),
    "error": frozenset(
        {
            "evaluator_crash",
            "evaluator_timeout",
            "evaluator_memory_cap",
            "output_overflow",
            "output_contract_violation",
            "adapter_parse_failure",
            "bundle_verification_failed",
            "compile_failure",
        }
    ),
}
# Statuses a policy answer may carry; the others come only from the runner's own observation.
POLICY_STATUSES = frozenset({"pass", "fail", "unknown", "not_applicable"})
# The checks for which no evaluator ran, so none can be named: there was none to run, or nothing to run it on.
NO_EVALUATOR_REASONS = frozenset({"evaluator_unavailable", "no_subject_in_scope"})
# The runner's own words about a status (what went wrong, in one sentence): the same cap as a policy's reason.
DETAIL_MAX_LENGTH = REASON_MAX_BYTES
# An hour is already far longer than any evaluation this CLI starts; a record may not ask for more.
MAX_TIMEOUT_S = 3600.0

Detail = Annotated[str, Field(max_length=DETAIL_MAX_LENGTH), AfterValidator(plain_text)]


def _reason(value: str) -> str:
    if len(value.encode("utf-8")) > REASON_MAX_BYTES:
        raise ValueError(f"must be at most {REASON_MAX_BYTES} bytes")
    return plain_text(value)


Reason = Annotated[str, AfterValidator(_reason)]


def _clean(value: Any) -> bool:
    """Whether no string anywhere in ``value`` holds a control character."""
    if isinstance(value, str):
        try:
            plain_text(value)
        except ValueError:
            return False
        return True
    if isinstance(value, dict):
        return all(_clean(key) and _clean(child) for key, child in value.items())
    if isinstance(value, list):
        return all(_clean(child) for child in value)
    return True


def _observations(value: dict[str, Any]) -> dict[str, Any]:
    if nesting_depth(value) > OBSERVATIONS_MAX_DEPTH:
        raise ValueError(f"must not nest deeper than {OBSERVATIONS_MAX_DEPTH}")
    if not _clean(value):
        raise ValueError("must not contain control characters")
    try:
        size = len(canonical_bytes(value))
    except CanonicalizationError as exc:
        raise ValueError(f"has no canonical form ({type(exc).__name__})") from None
    if size > OBSERVATIONS_MAX_BYTES:
        raise ValueError(f"must be at most {OBSERVATIONS_MAX_BYTES} bytes in canonical form")
    return value


Observations = Annotated[dict[str, Any], AfterValidator(_observations)]


class AssertionRef(StrictModel):
    """The assertion, with the digest of its document as it was read."""

    id: Annotated[str, Field(pattern=ID_PATTERN, max_length=ID_MAX_LENGTH)]
    version: Annotated[str, Field(pattern=VERSION_PATTERN, max_length=VERSION_MAX_LENGTH)]
    digest: Digest


class Subject(StrictModel):
    """What the verdict is about; ``id`` is absent only when the assertion had no subject in scope."""

    kind: TargetKindValue
    id: Address | None
    identities: list[Identity]
    authority: Authority


class Evaluation(StrictModel):
    """The verdict: the status, the runner's reason for it, and what the policy itself said."""

    stage: StageValue
    status: Status
    status_reason: Identifier | None
    status_detail: Detail | None
    reason: Reason | None
    observations: Observations | None

    @model_validator(mode="after")
    def _reason_fits_status(self) -> Evaluation:
        allowed = STATUS_REASONS[self.status]
        if self.status_reason is None:
            if self.status not in ("pass", "fail"):
                raise ValueError(f"status {self.status!r} needs a status_reason")
        elif self.status_reason not in allowed:
            raise ValueError(f"{self.status_reason!r} is not a reason for status {self.status!r}")
        return self


class Run(StrictModel):
    """The run this event belongs to, and the unit of the stack it was evaluated in."""

    id: Identifier
    basis: Literal["server_issued", "locally_derived"]
    unit: Identifier


class PlanDigest(StrictModel):
    value: Digest
    version: Identifier


class MemoryCap(StrictModel):
    """The memory cap as applied: not every platform can enforce one, and the record says which."""

    bytes: Annotated[int, Field(ge=0)] | None
    enforced: bool
    kind: Identifier


class Environment(StrictModel):
    """The limits an evaluation ran under, as applied, so the same limits can be applied again."""

    timeout_s: Annotated[float, Field(gt=0, le=MAX_TIMEOUT_S)]
    memory_cap: MemoryCap
    output_bytes_per_answer: Annotated[int, Field(ge=0)]
    contexts_per_process: Annotated[int, Field(ge=1)]
    capabilities_digest: Digest
    platform: Identifier
    python_platform: Identifier


class OpaEvaluator(StrictModel):
    """The program this CLI ran to produce the verdict, and the limits it ran under, as applied."""

    engine: Literal["opa"]
    version: Identifier
    digest: Digest
    environment: Environment


class ScannerEvaluator(StrictModel):
    """A scanner that ran elsewhere and whose result was credited to an assertion by a binding.

    Nothing was executed here, so there are no limits to record and usually
    no digest: the version is the one the tool wrote into its own output.
    """

    engine: Literal["checkov", "trivy", "prowler"]
    version: Identifier
    digest: Digest | None
    basis: Literal["not_executed_by_cli"]


Evaluator = Annotated[OpaEvaluator | ScannerEvaluator, Field(discriminator="engine")]


class BindingRef(StrictModel):
    """The entry that licensed a scanner's result to stand for an assertion (see ``models.binding``)."""

    id: Annotated[str, Field(pattern=ID_PATTERN, max_length=ID_MAX_LENGTH)]
    version: Annotated[str, Field(pattern=VERSION_PATTERN, max_length=VERSION_MAX_LENGTH)]
    digest: Digest


class Bundle(StrictModel):
    kind: Literal["compass", "local_bundle"]
    digest: Digest


class Compiler(StrictModel):
    """The compiler that produced the module: the contract package's version and installed digest."""

    version: Identifier
    contract_version: Identifier
    contract_digest: Digest | None
    # An installed wheel always has a digest; a source checkout of the contract has none.
    install: Literal["wheel", "editable"]

    @model_validator(mode="after")
    def _a_wheel_has_a_digest(self) -> Compiler:
        if self.install == "wheel" and self.contract_digest is None:
            raise ValueError("an installed contract package has a digest")
        return self


class Executor(StrictModel):
    """Who ran the evaluation: a person on a machine, or a pipeline workload."""

    type: Literal["human", "workload"]
    provider: Identifier
    run_id: Identifier | None


class CiContext(StrictModel):
    integrity: Literal["verified", "unverified", "absent"]
    basis: Literal["context_key_mac", "none"]


class Provenance(StrictModel):
    """Everything needed to reproduce the verdict and to say who produced it."""

    run: Run
    source_commit: Commit
    plan_digest: PlanDigest
    input_digest: Digest | None
    # Absent only for a check no evaluator ran at all (see ``NO_EVALUATOR_REASONS``).
    evaluator: Evaluator | None
    # The bundle belongs to the evaluator this CLI ran; a scanner has none.
    bundle: Bundle | None
    # Present exactly when a scanner's result was read for this check (see ``ScannerEvaluator``).
    binding: BindingRef | None
    assertion_source: Literal["compass_bundle", "local", "custom_rego"]
    assertion_source_digest: Digest
    compiled_digest: Digest | None
    compiler: Compiler | None
    executor: Executor
    ci_context: CiContext
    fs_hardening: Literal["posix", "windows_profile_acl", "none"]


class AssuranceEvent(StrictModel):
    """One verdict as submitted."""

    assertion: AssertionRef
    subject: Subject
    evaluation: Evaluation
    provenance: Provenance
    observed_at: Timestamp

    @model_validator(mode="after")
    def _consistent(self) -> AssuranceEvent:
        no_subject = self.evaluation.status_reason == "no_subject_in_scope"
        if (self.subject.id is None) != no_subject:
            raise ValueError("a subject id is absent exactly when no subject was in scope")
        if no_subject and self.provenance.input_digest is not None:
            raise ValueError("no input was built when no subject was in scope")
        if self.evaluation.status in POLICY_STATUSES and not no_subject and self.provenance.input_digest is None:
            raise ValueError("a policy verdict names the input it was computed over")
        if self.provenance.evaluator is None and self.evaluation.status_reason not in NO_EVALUATOR_REASONS:
            raise ValueError(
                f"a check with status_reason {self.evaluation.status_reason!r} names the evaluator that ran it"
            )
        # A scanner's result was read for this check — credited as a verdict, or found not to apply.
        from_scanner = isinstance(self.provenance.evaluator, ScannerEvaluator)
        if (self.provenance.bundle is not None) != isinstance(self.provenance.evaluator, OpaEvaluator):
            raise ValueError("a bundle is named exactly when this CLI ran the evaluator over one")
        if (self.provenance.binding is not None) != from_scanner:
            raise ValueError("a binding is named exactly when a scanner's result was read for this check")
        if from_scanner and (self.provenance.compiled_digest is not None or self.provenance.compiler is not None):
            raise ValueError("a scanner's result was not compiled here, so it names no module and no compiler")
        return self
