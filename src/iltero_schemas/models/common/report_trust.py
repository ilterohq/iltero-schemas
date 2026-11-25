"""What a verification report says about the record's trust: the level the verifier assigns it, the key that signed
the run statement it rests on, and what the verifier found reading that statement with the record.

A record names no trust level of its own: the verifier assigns one. ``policy_enforced`` means a run statement the
verifier checked, signed by a trusted key of the server that opened the run, lists the record as one the server
accepted, and the record differs from it in nothing. Every other record is ``self_attested``: the record's own word.
A statement that is given but does not verify, or that does not hold for the record, is a problem the report lists,
never a quiet fall back to a lower level.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Literal

from pydantic import AfterValidator, Field, model_validator

from iltero_schemas.models.common.base import StrictModel
from iltero_schemas.models.common.fields import Digest, RunStage, Timestamp, plain_text
from iltero_schemas.models.common.run_statement import (
    ACCEPTED_LISTINGS,
    RUN_STAGES,
    ReasonCode,
    RecordListing,
    RunEnding,
    ServedPartDigests,
)
from iltero_schemas.models.common.verification_states import (
    BUNDLE_SIGNATURE_CHECKED,
    INTEGRITY_FAILED,
    REFUSED_BY_SERVER,
    RUN_STATEMENT,
    Result,
)
from iltero_schemas.statement.reasons import (
    ANOTHER_RUN,
    RECORD_DIFFERENCES,
    RECORD_NOTES,
    RECORD_REFUSED_BY_THE_SERVER,
    RUN_STATEMENT_DOES_NOT_HOLD,
)
from iltero_schemas.trust.keys import KEY_ID_PATTERN
from iltero_schemas.trust.operator import MAX_OPERATOR_NAME_LENGTH, ListedIn

TrustLevel = Literal["policy_enforced", "self_attested"]
# The trust level a verifier assigns a record, each with its reason. run_statement: a run statement that verified lists
# the record as one the server accepted (the record that counts, or an earlier copy, for the stages it holds), and the
# record differs from it in nothing. run_opened_locally: the tool opened the run, so no server signs for it.
# no_statement_given: the record says the server opened the run, and no run statement was given. refused_by_server: the
# run statement lists the record as one the server refused. run_statement_does_not_hold: the statement given does not
# verify, or does not hold for this record; the report lists why. integrity_failed: the record and the files it cites
# do not hold together, so whatever a statement says of it, nothing it says of itself is taken.
TRUST_LEVEL_RESULTS: frozenset[tuple[TrustLevel, str]] = frozenset(
    {
        ("policy_enforced", "run_statement"),
        ("self_attested", "run_opened_locally"),
        ("self_attested", "no_statement_given"),
        ("self_attested", "refused_by_server"),
        ("self_attested", "run_statement_does_not_hold"),
        ("self_attested", "integrity_failed"),
    }
)
# Long enough for a sentence about what a comparison found.
STATEMENT_PROBLEM_MAX_LENGTH = 1024
# The differences a report lists as problems: every one but a refusal, which the integrity property and the trust
# level report instead.
STATEMENT_PROBLEMS = RUN_STATEMENT_DOES_NOT_HOLD | (RECORD_DIFFERENCES - {RECORD_REFUSED_BY_THE_SERVER})
KeyId = Annotated[str, Field(pattern=KEY_ID_PATTERN)]
Sentence = Annotated[str, Field(min_length=1, max_length=STATEMENT_PROBLEM_MAX_LENGTH), AfterValidator(plain_text)]
OperatorName = Annotated[str, Field(min_length=1, max_length=MAX_OPERATOR_NAME_LENGTH), AfterValidator(plain_text)]


class AssignedTrustLevel(StrictModel):
    """The trust level the verifier assigns the record, and why (``TRUST_LEVEL_RESULTS``)."""

    level: TrustLevel
    reason: str

    @model_validator(mode="after")
    def _known(self) -> AssignedTrustLevel:
        if (self.level, self.reason) not in TRUST_LEVEL_RESULTS:
            raise ValueError("a trust level is one a verifier assigns, with one of its reasons")
        return self


class StatementTrustRoot(StrictModel):
    """The key that signed the run statement, the file of the trust set that lists it (``iltero``, the file shipped with
    this contract, or ``operator``, an operator's trust file the reader gave), the operator's name when an operator's
    file lists it (null otherwise), and the digest of the trust data the reader checked against
    (``trust.trust_data_digest``)."""

    key_id: KeyId
    listed_in: ListedIn
    operator: OperatorName | None
    trust_data_digest: Digest

    @model_validator(mode="after")
    def _operator_named(self) -> StatementTrustRoot:
        if (self.operator is not None) != (self.listed_in == "operator"):
            raise ValueError("a trust root names an operator exactly when an operator's trust file lists its key")
        return self


class StatementFinding(StrictModel):
    """One thing reading the run statement found: its reason code and a sentence."""

    reason: ReasonCode
    sentence: Sentence


class ReportedRunEnd(StrictModel):
    """How the run ended, as its statement says: closed or abandoned, why, when by the server's clock, and how many
    results it required that no accepted record answered and how many expected stages accepted no record."""

    ending: RunEnding
    ending_reason: ReasonCode
    ended_at: Timestamp
    unanswered_results: Annotated[int, Field(ge=0)]
    stages_never_accepted: Annotated[int, Field(ge=0)]


# The parts a run statement signs for a stage, by their names in ``ServedPartDigests``, in its order.
ServedPartName = Literal["approvals", "commit_review", "served_exceptions", "apply_job_facts"]
SERVED_PART_NAMES: tuple[str, ...] = tuple(ServedPartDigests.model_fields)


class PartNotCompared(StrictModel):
    """A part the run statement signs for a stage that the record keeps no copy of (it keeps a marker or nothing), so
    the verifier could not compare it: the stage, and the part's name in ``ServedPartDigests``."""

    stage: RunStage
    part: ServedPartName


class RunStatementFindings(StrictModel):
    """What the verifier found reading the run statement it was given with the record.

    ``digest`` is the statement's digest (the sha256 digest of its payload), ``listed_as`` how it lists the record and
    ``run`` how the run ended; all three are null when the statement did not verify, and ``run`` is null too for the
    statement of another run, whose ending is not this record's run's. ``problems`` are why it does not
    verify (one reason of ``statement.RUN_STATEMENT_DOES_NOT_HOLD``) or every way it does not hold for the record (the
    differences of ``statement.compare_record`` but a refusal), ``notes`` what the comparison says that is not a
    problem, and ``not_compared`` the parts the statement signs that the record keeps no copy of, by stage in the order
    of the lifecycle, then part in the order of ``ServedPartDigests``, each once; empty when the statement did not
    verify.
    """

    digest: Digest | None
    listed_as: RecordListing | None
    run: ReportedRunEnd | None
    problems: list[StatementFinding]
    notes: list[StatementFinding]
    not_compared: Annotated[list[PartNotCompared], Field(max_length=len(RUN_STAGES) * len(SERVED_PART_NAMES))]

    @model_validator(mode="after")
    def _consistent(self) -> RunStatementFindings:
        verified = self.digest is not None
        reasons = [problem.reason for problem in self.problems]
        of_another_run = ANOTHER_RUN in reasons
        if (self.listed_as is not None) != verified or (self.run is not None) != (verified and not of_another_run):
            raise ValueError(
                "a run statement that verified names its digest, how it lists the record and, unless it is the "
                "statement of another run, how the run ended"
            )
        if not verified and (len(reasons) != 1 or reasons[0] not in RUN_STATEMENT_DOES_NOT_HOLD):
            raise ValueError("a run statement that did not verify has exactly one problem, why it does not hold")
        if verified and not set(reasons) <= STATEMENT_PROBLEMS - RUN_STATEMENT_DOES_NOT_HOLD:
            raise ValueError("the problems of a run statement that verified are differences from the record")
        if not {note.reason for note in self.notes} <= RECORD_NOTES:
            raise ValueError("a run statement's notes are notes of a record comparison")
        keys = [(RUN_STAGES.index(part.stage), SERVED_PART_NAMES.index(part.part)) for part in self.not_compared]
        if not verified and keys:
            raise ValueError("a run statement that did not verify names no part it could not compare")
        if not all(earlier < later for earlier, later in zip(keys, keys[1:], strict=False)):
            raise ValueError(
                "a run statement's parts not compared are named each once, by stage in the order of the lifecycle, "
                "then part"
            )
        return self


# The trust level reasons of a record read with no run statement, and those a statement with a problem may give.
NO_STATEMENT_REASONS = frozenset({"run_opened_locally", "no_statement_given"})
WITH_A_PROBLEM_REASONS = frozenset({"run_statement_does_not_hold", "refused_by_server", "integrity_failed"})


def trust_level_problem(
    level: AssignedTrustLevel,
    root: StatementTrustRoot | None,
    found: RunStatementFindings | None,
    results: Mapping[str, Result],
) -> str | None:
    """Why the trust level, the trust root, the run statement's findings and the property ``results`` of one report
    disagree, or None when they agree."""
    integrity = results["integrity"]
    reason = level.reason
    verified = found is not None and found.digest is not None
    problems = found is not None and bool(found.problems)
    policy_enforced = level.level == "policy_enforced"
    signed = [
        name for name, result in results.items() if result[0] == "verified" and result != BUNDLE_SIGNATURE_CHECKED
    ]
    rules = (
        ((root is not None) == verified, "a report names a trust root exactly when a run statement verified"),
        (
            reason not in NO_STATEMENT_REASONS or found is None,
            f"a record whose trust level reason is {reason} was given no run statement",
        ),
        (
            not problems or reason in WITH_A_PROBLEM_REASONS,
            "a run statement with a problem gives a trust level whose reason says so",
        ),
        (
            reason != "run_statement_does_not_hold" or problems,
            "a run statement that does not hold has a problem the report lists",
        ),
        (
            reason != "refused_by_server" or (found is not None and found.listed_as == "refused"),
            "a record whose trust level reason is refused_by_server is one the run statement lists as refused",
        ),
        (
            (reason == "refused_by_server") == (integrity == REFUSED_BY_SERVER),
            "a record's integrity failed as refused_by_server exactly when its trust level reason is refused_by_server",
        ),
        (
            (reason == "integrity_failed") == (integrity == INTEGRITY_FAILED),
            "a record's integrity failed on its files exactly when its trust level reason is integrity_failed",
        ),
        (
            not policy_enforced or (found is not None and found.listed_as in ACCEPTED_LISTINGS),
            "a policy_enforced record is one a run statement that verified lists as accepted",
        ),
        (
            (integrity == RUN_STATEMENT) == policy_enforced,
            "a record's integrity is verified by a run statement exactly when its trust level is policy_enforced",
        ),
        (not signed or policy_enforced, "a property is verified by a run statement only for a policy_enforced record"),
    )
    return next((message for holds, message in rules if not holds), None)
