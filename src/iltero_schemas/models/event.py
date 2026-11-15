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

from collections.abc import Sequence
from typing import Annotated, Literal

from pydantic import AfterValidator, Field, model_validator

from iltero_schemas.assertions.built_in import BUILT_INS, SHIPPED_ASSERTIONS
from iltero_schemas.assertions.paths import NOT_DECIDED_BY_SCANNERS
from iltero_schemas.canonical.encoding import canonical_bytes
from iltero_schemas.compiler.limits import REASON_MAX_BYTES
from iltero_schemas.models import fields
from iltero_schemas.models.assertion import (
    TargetKind,
)
from iltero_schemas.models.assertion_id import ILTERO_NAMESPACE
from iltero_schemas.models.base import API_VERSION, StageValue, StrictModel, TargetKindValue
from iltero_schemas.models.change_type import CHECKED_CONTENT_KIND_OF, ActivityName
from iltero_schemas.models.checked_content import CheckedContent
from iltero_schemas.models.ci import CiSystem
from iltero_schemas.models.fields import (
    MAX_SUBJECT_IDENTITIES,
    BoundedObject,
    Commit,
    Digest,
    Identifier,
    Identity,
    Status,
    Timestamp,
    check_server_bundle,
    plain_text,
)
from iltero_schemas.models.scanner_evaluator import (
    NO_SCANNER_REPORT,
    SCANNER_NOT_RUN,
    SCANNER_ONLY_REASONS,
    SCANNER_OUTCOMES,
    SCANNER_REPORT_INCOMPLETE,
    SCANNER_RESULT_UNRESOLVED,
    SCANNER_VERSION_NOT_ALLOWED,
    SUPPRESSED_IN_SOURCE,
    TOOL_REPORTS_ONLY_FAILURES,
    EvaluatorBindingRef,
    ScannerEvaluator,
)
from iltero_schemas.models.subjects import check_subject
from iltero_schemas.profiles import profile_for, reads_server_facts

# Why a status is what it is; the runner sets it, a policy never does.
STATUS_REASONS: dict[str, frozenset[str]] = {
    "pass": frozenset(),
    # A failure's reason is the policy's own ``reason``; the runner adds none.
    "fail": frozenset(),
    "unknown": frozenset(
        {
            "known_after_deploy",
            "redacted",
            "path_missing",
            "not_a_list",
            "unspecified",
            "server_facts_unavailable",
            "not_reported_by_tool",
            "reference_time_untrusted",
            "deployment_log_incomplete",
            "state_not_read",
            "kind_unmapped",
            SCANNER_RESULT_UNRESOLVED,
            SCANNER_REPORT_INCOMPLETE,
        }
    ),
    "not_applicable": frozenset({"when_guard_excluded", "no_subject_in_scope"}),
    "not_evaluated": frozenset(
        {
            SCANNER_NOT_RUN,
            "credential_denied",
            "resource_type_unsupported",
            SCANNER_VERSION_NOT_ALLOWED,
            "timeout",
            "subject_unresolved",
            "evaluator_unavailable",
            "identity_unverified",
            "stage_not_run",
            SUPPRESSED_IN_SOURCE,
            TOOL_REPORTS_ONLY_FAILURES,
            NO_SCANNER_REPORT,
        }
    ),
    "error": frozenset(
        {
            "evaluator_crash",
            "evaluator_timeout",
            "evaluator_memory_limit",
            "output_overflow",
            "output_contract_violation",
            "adapter_parse_failure",
            "bundle_verification_failed",
            "compile_failure",
        }
    ),
}
# The reasons an evaluation did not run, or ended in an error, that blame the evaluator, never the subject or its facts.
EVALUATOR_FAULT_REASONS: dict[str, frozenset[str]] = {
    "not_evaluated": frozenset({"timeout", "evaluator_unavailable"}),
    "error": frozenset(
        {
            "evaluator_crash",
            "evaluator_timeout",
            "evaluator_memory_limit",
            "output_overflow",
            "output_contract_violation",
            "bundle_verification_failed",
            "compile_failure",
        }
    ),
}
# Every status, worst first: an evaluation that did not run is worse than an error, an error worse than an
# unknown result, and an unknown result worse than a failure.
# ``not_applicable`` claims less than ``pass``, so it ranks as worse.
STATUS_SEVERITY: tuple[Status, ...] = ("not_evaluated", "error", "unknown", "fail", "not_applicable", "pass")


# Statuses a policy answer may carry; the others come only from the runner's own observation.
POLICY_STATUSES = frozenset({"pass", "fail", "unknown", "not_applicable"})
# The evaluations for which no evaluator ran, so none can be named: there was none to run, or nothing to run it on.
NO_EVALUATOR_REASONS = frozenset({"evaluator_unavailable", "no_subject_in_scope", NO_SCANNER_REPORT})
# The runner's own words about a status (what went wrong, in one sentence): the same cap as a policy's reason.
DETAIL_MAX_LENGTH = REASON_MAX_BYTES
# An hour is already far longer than any evaluation this CLI starts; a record may not ask for more.
MAX_TIMEOUT_SECONDS = 3600.0
# The engine an event names when no evaluator ran.
NO_ENGINE = "none"
Detail = Annotated[str, Field(max_length=DETAIL_MAX_LENGTH), AfterValidator(plain_text)]


def _reason(value: str) -> str:
    if len(value.encode("utf-8")) > REASON_MAX_BYTES:
        raise ValueError(f"must be at most {REASON_MAX_BYTES} bytes")
    return plain_text(value)


Reason = Annotated[str, AfterValidator(_reason)]


class AssertionRef(fields.AssertionKey):
    """The assertion, with the digest of its document as it was read."""

    digest: Digest


class EventSubject(StrictModel):
    """What the verdict is about; no key and no identity only when the assertion had no subject in scope."""

    kind: TargetKindValue
    # The digest of its kind and its local identity (``models.subjects``).
    key: Digest | None
    identities: Annotated[list[Identity], Field(max_length=MAX_SUBJECT_IDENTITIES)]


class Evaluation(StrictModel):
    """The verdict: the activity and stage it belongs to, the status, the runner's reason for it, and what the policy
    itself said."""

    activity: ActivityName
    stage: StageValue
    status: Status
    status_reason: Identifier | None
    status_detail: Detail | None
    policy_reason: Reason | None
    observations: BoundedObject | None

    @model_validator(mode="after")
    def _reason_fits_status(self) -> Evaluation:
        allowed = STATUS_REASONS[self.status]
        if self.status_reason is None:
            if self.status not in ("pass", "fail"):
                raise ValueError("a status other than pass or fail needs a status_reason")
        elif not allowed:
            raise ValueError(f"a status of {self.status} has no status_reason")
        elif self.status_reason not in allowed:
            raise ValueError(f"status_reason must be a reason for status {self.status}: {', '.join(sorted(allowed))}")
        return self


class Run(StrictModel):
    """The run this event belongs to, and the unit of the stack it was evaluated in."""

    id: Identifier
    unit: Identifier


class MemoryLimit(StrictModel):
    """The memory cap as applied: not every platform can enforce one, and the record says which."""

    bytes: Annotated[int, Field(ge=0)] | None
    enforced: bool
    kind: Identifier


class EvaluationLimits(StrictModel):
    """The limits an evaluation ran under, as applied, so the same limits can be applied again."""

    timeout_seconds: Annotated[float, Field(gt=0, le=MAX_TIMEOUT_SECONDS)]
    memory_limit: MemoryLimit
    max_output_bytes: Annotated[int, Field(ge=0)]
    evaluations_per_process: Annotated[int, Field(ge=1)]
    capabilities_digest: Digest
    platform: Identifier


class OpaEvaluator(StrictModel):
    """The program this CLI ran to produce the verdict, and the limits it ran under, as applied."""

    engine: Literal["opa"]
    version: Identifier
    digest: Digest
    limits: EvaluationLimits


Evaluator = Annotated[OpaEvaluator | ScannerEvaluator, Field(discriminator="engine")]


class Bundle(StrictModel):
    """The bundle the evaluator loaded: who built it, the SHA-256 of its tarball's bytes, and for a served bundle
    the descriptor's content digest and signing key."""

    kind: Literal["server", "local_bundle"]
    tarball_digest: Digest
    content_digest: Digest | None
    key_id: Identifier | None

    @model_validator(mode="after")
    def _a_server_bundle_names_its_content_and_key(self) -> Bundle:
        check_server_bundle(self.kind, self.content_digest, self.key_id)
        return self


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


# Where an evaluation ran: on a person's machine (``local``), in a job of a CI system the tool could not
# name (``ci``), or in a job of a named CI system.
ExecutorProvider = Literal["local", "ci"] | CiSystem


class Executor(StrictModel):
    """Who ran the evaluation: a person on a machine, or a pipeline workload."""

    type: Literal["human", "workload"]
    provider: ExecutorProvider
    ci_run_id: Identifier | None


# Where a built-in assertion may come from: this package, or the server's bundle that ships it.
BUILT_IN_SOURCES = frozenset({"contract_starter", "server_bundle"})
# Where an assertion this package ships is named from, and where a project's own come from.
STARTER_SOURCE = "contract_starter"
PROJECT_ASSERTION_SOURCES = frozenset({"local", "custom_rego"})
# Where the facts document an evaluation read came from: the server, or none.
# It names the document's origin, not whether its parts held values or unknown markers. A value the server supplies
# inside a part not in ``profiles.SERVER_FACTS`` follows who opened the run instead.
FactsSource = Literal["server", "none"]


class Provenance(StrictModel):
    """Everything needed to reproduce the verdict and to say who produced it."""

    run: Run
    source_commit: Commit
    checked_content: CheckedContent
    input_digest: Digest | None
    # Absent only for an evaluation no evaluator ran at all (see ``NO_EVALUATOR_REASONS``).
    evaluator: Evaluator | None
    # The bundle belongs to the evaluator this CLI ran; a scanner has none.
    bundle: Bundle | None
    # Present exactly when the evaluator is a scanner (see ``ScannerEvaluator``).
    evaluator_binding: EvaluatorBindingRef | None
    # Where the assertion came from: the server's bundle, the project's own files (``local``, hand-written Rego as
    # ``custom_rego``), or a starter assertion this package ships (``contract_starter``). The writer's claim.
    assertion_source: Literal["server_bundle", "local", "custom_rego", "contract_starter"]
    assertion_source_digest: Digest
    compiled_digest: Digest | None
    compiler: Compiler | None
    executor: Executor
    # Present exactly for an evaluation whose input may carry server facts (``profiles.reads_server_facts``).
    facts_source: FactsSource | None


class AssuranceEvent(StrictModel):
    """One verdict as submitted."""

    assertion: AssertionRef
    subject: EventSubject
    evaluation: Evaluation
    provenance: Provenance
    observed_at: Timestamp

    @property
    def engine(self) -> str:
        """The engine of the evaluator that ran (``opa``, or a scanner), or ``none`` when no evaluator ran."""
        return self.provenance.evaluator.engine if self.provenance.evaluator is not None else NO_ENGINE

    def _check_from_scanner(self) -> None:
        """An evaluation from a scanner's results is about a resource, gives one of ``SCANNER_OUTCOMES``, and reads
        no facts from the server. No other evaluation gives a reason only scanners give."""
        evaluation = self.evaluation
        if not isinstance(self.provenance.evaluator, ScannerEvaluator):
            if evaluation.status_reason in SCANNER_ONLY_REASONS:
                raise ValueError(f"only an evaluation from a scanner's results is {evaluation.status_reason}")
            return
        if TargetKind(self.subject.kind) is not TargetKind.RESOURCE:
            raise ValueError("an evaluation from a scanner's result is about a resource")
        if (evaluation.status, evaluation.status_reason) not in SCANNER_OUTCOMES:
            outcomes = ", ".join(
                f"{status}/{reason}" if reason else status for status, reason in sorted(SCANNER_OUTCOMES)
            )
            raise ValueError(f"an evaluation from a scanner's results is one of: {outcomes}")
        if self.provenance.facts_source == "server":
            raise ValueError("an evaluation from a scanner's result reads no facts from the server")
        scanner = self.provenance.evaluator
        if scanner.local_exception is not None and evaluation.status_reason != SUPPRESSED_IN_SOURCE:
            raise ValueError("a scanner's evaluation names a project's exception only for a suppressed check")
        not_run = evaluation.status_reason == SCANNER_NOT_RUN
        if (scanner.version is None) != not_run or (self.provenance.input_digest is None) != not_run:
            raise ValueError(
                "a scanner's evaluation names no version and no input exactly when the scanner gave no report"
            )
        if not_run and (
            scanner.result_addresses
            or scanner.unknown_paths
            or scanner.failed_rule_ids
            or scanner.undecided_rule_ids != scanner.rule_ids
        ):
            raise ValueError("a scanner that gave no report decided none of its bound checks and read no resource")

    def _check_namespace(self) -> None:
        """No assertion has a namespace that reads like Iltero's; one from a project's own files is never one of
        Iltero's; and one named as this package's starter is the document this package ships, at its version."""
        source = self.provenance.assertion_source
        namespace = self.assertion.id.split(".")[0]
        if namespace != ILTERO_NAMESPACE and namespace.startswith(ILTERO_NAMESPACE):
            raise ValueError(f"an assertion's namespace is {ILTERO_NAMESPACE} or one not starting {ILTERO_NAMESPACE}")
        if source in PROJECT_ASSERTION_SOURCES and self.assertion.id.split(".")[0].startswith(ILTERO_NAMESPACE):
            raise ValueError(f"an assertion from a project's own files has an id outside {ILTERO_NAMESPACE}")
        shipped = SHIPPED_ASSERTIONS.get(self.assertion.id)
        if source == STARTER_SOURCE and (
            shipped is None or (self.assertion.version, self.assertion.digest) != (shipped.version, shipped.digest)
        ):
            raise ValueError("an assertion named as this package's starter is the document this package ships")

    def _check_built_in(self) -> None:
        """A built-in assertion is evaluated as shipped: its document and version, and the module compiled from it."""
        shipped = BUILT_INS.get(self.assertion.id)
        if shipped is None:
            return
        provenance = self.provenance
        if (self.assertion.version, self.assertion.digest) != (shipped.version, shipped.digest):
            raise ValueError(f"{self.assertion.id} is a built-in assertion: it names the document this package ships")
        if provenance.assertion_source not in BUILT_IN_SOURCES:
            raise ValueError(f"{self.assertion.id} is evaluated from this package or the server's bundle")
        if provenance.compiled_digest not in (None, shipped.compiled_digest) or (
            provenance.compiled_digest is None and provenance.evaluator is not None
        ):
            raise ValueError(f"{self.assertion.id} runs the module compiled from the document this package ships")

    @model_validator(mode="after")
    def _consistent(self) -> AssuranceEvent:
        no_subject = self.evaluation.status_reason == "no_subject_in_scope"
        subject = self.subject
        if (subject.key is None) != no_subject or (not subject.identities) != no_subject:
            raise ValueError("a subject has no key and no identity exactly when no subject was in scope")
        if subject.key is not None:
            stage, unit = self.evaluation.stage.value, self.provenance.run.unit
            check_subject(subject.kind, subject.key, subject.identities, stage, unit)
        if no_subject and self.provenance.input_digest is not None:
            raise ValueError("no input was built when no subject was in scope")
        if self.evaluation.status in POLICY_STATUSES and not no_subject and self.provenance.input_digest is None:
            raise ValueError("a policy verdict names the input it was computed over")
        if self.provenance.evaluator_binding is not None and self.assertion.id in NOT_DECIDED_BY_SCANNERS:
            raise ValueError(f"{self.assertion.id} is never decided by a scanner's result")
        self._check_from_scanner()
        self._check_built_in()
        self._check_namespace()
        activity, stage = self.evaluation.activity, self.evaluation.stage
        profile_for(activity, stage, TargetKind(subject.kind))
        if self.provenance.checked_content.kind != CHECKED_CONTENT_KIND_OF[activity]:
            raise ValueError(f"an {activity} evaluation names the {CHECKED_CONTENT_KIND_OF[activity]} it checked")
        if (self.provenance.facts_source is not None) != reads_server_facts(
            self.evaluation.activity, self.evaluation.stage
        ):
            raise ValueError("facts_source is present exactly when the evaluation's input reads server facts")
        if self.provenance.evaluator is None and self.evaluation.status_reason not in NO_EVALUATOR_REASONS:
            raise ValueError(
                f"an evaluation with status_reason {self.evaluation.status_reason!r} names the evaluator that ran it"
            )
        # A scanner's results decided this evaluation.
        from_scanner = isinstance(self.provenance.evaluator, ScannerEvaluator)
        if (self.provenance.bundle is not None) != isinstance(self.provenance.evaluator, OpaEvaluator):
            raise ValueError("a bundle is named exactly when this CLI ran the evaluator over one")
        bundle = self.provenance.bundle
        if self.provenance.assertion_source == "server_bundle" and bundle is not None and bundle.kind != "server":
            raise ValueError("an assertion from the server's bundle is evaluated over the server's bundle")
        if (self.provenance.evaluator_binding is not None) != from_scanner:
            raise ValueError(
                "an evaluator binding is named exactly when a scanner's result was read for this evaluation"
            )
        if from_scanner and (self.provenance.compiled_digest is not None or self.provenance.compiler is not None):
            raise ValueError("a scanner's result was not compiled here, so it names no module and no compiler")
        return self


# The kind of a stage's events file: the stage's events, in the order its record lists them.
EVENTS_FILE_KIND = "AssuranceEvents"


def events_file_bytes(events: Sequence[AssuranceEvent]) -> bytes:
    """The bytes of a stage's events file holding ``events``: their canonical JSON (RFC 8785), which the stage's
    ``events.digest`` and its evidence register entry are the digest of."""
    return canonical_bytes(
        {
            "apiVersion": API_VERSION,
            "kind": EVENTS_FILE_KIND,
            "events": [event.model_dump(mode="json", by_alias=True) for event in events],
        }
    )
