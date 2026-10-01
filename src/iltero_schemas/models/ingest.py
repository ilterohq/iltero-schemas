"""What a governed run sends Iltero Cloud, and the answer it gets back for each thing it sent.

A pipeline job uploads its checks to Iltero Cloud in batches. A batch names the
run, the stage and the unit it belongs to, and holds up to 2,000 events.
Iltero Cloud answers every upload with a ``SubmissionOutcome``. The answer holds
one result for each event, in the order the events were sent. One bad event
does not fail the others. The identity document and the record are uploaded
one at a time, and each gets an answer with a single result.

Two events are for the same check when they share the run, the stage, the
unit, the assertion id and the subject's id. Each result says what Iltero Cloud
did with the event:

- ``accepted``: the event was stored.
- ``duplicate``: an event for the same check with the same content was
  already stored. The result names that event.
- ``conflict``: an event for the same check with different content was
  already stored. Iltero Cloud stores the new one too and overwrites nothing. Of
  the two statuses, the worse one stands (see ``worse_status``).
- ``rejected``: the event is well formed, but Iltero Cloud did not accept it for
  this run. The result says why. A rejected event never counts.
- ``invalid``: the event does not match its schema. Nothing was stored.

Each stored event is named by its id and by its digest, so a pipeline can
check that Iltero Cloud stored exactly what it sent.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Annotated, Any, Literal

from pydantic import Field, JsonValue, model_validator

from iltero_schemas.canonical.encoding import digest, digest_of
from iltero_schemas.models.base import StrictModel
from iltero_schemas.models.event import AssuranceEvent
from iltero_schemas.models.fields import Digest, Identifier, RunStage, Timestamp, Uuid

EVENTS_API_VERSION = "iltero.io/assurance-event-batch/v1"
OUTCOME_API_VERSION = "iltero.io/submission-outcome/v1"
# The most events one upload may hold.
MAX_BATCH_EVENTS = 2000
# The largest request body Iltero Cloud reads: 5 MiB.
MAX_UPLOAD_BYTES = 5 * 1024 * 1024

Disposition = Literal["accepted", "duplicate", "conflict", "rejected", "invalid"]
# Why Iltero Cloud refused an event or a document. ``schema_invalid`` is the only reason for ``invalid``.
RejectReason = Literal[
    "stage_mismatch",
    "stage_not_allowed",
    "bundle_not_pinned",
    "run_mismatch",
    "assertion_not_in_required_set",
    "assertion_version_mismatch",
    "unit_limit_reached",
    "event_cap_reached",
    "schema_invalid",
    "pins_mismatch",
]


def document_digest(document: Mapping[str, Any]) -> str:
    """The digest a result names a stored event or document by: sha256 of its canonical JSON (RFC 8785)."""
    return digest_of(dict(document))


class _BatchHeader(StrictModel):
    api_version: Literal["iltero.io/assurance-event-batch/v1"] = Field(alias="apiVersion")
    run_id: Uuid
    stage: RunStage
    unit: Identifier


class AssuranceEventBatch(_BatchHeader):
    """One upload of checks. Every event is of the run, the stage and the unit the batch names."""

    events: Annotated[list[AssuranceEvent], Field(min_length=1, max_length=MAX_BATCH_EVENTS)]

    @model_validator(mode="after")
    def _every_event_is_of_this_batch(self) -> AssuranceEventBatch:
        for index, event in enumerate(self.events):
            run = event.provenance.run
            if run.basis != "server_issued" or run.id != self.run_id:
                raise ValueError(f"events[{index}]: every event is of the run Iltero Cloud issued the batch names")
            if run.unit != self.unit:
                raise ValueError(f"events[{index}]: every event is of the unit the batch names")
            if event.evaluation.stage.value != self.stage:
                raise ValueError(f"events[{index}]: every event is of the stage the batch names")
        return self


class AssuranceEventBatchEnvelope(_BatchHeader):
    """The same upload, with each event left unread.

    A receiver reads the envelope with this model first. Then it reads each
    event on its own with ``AssuranceEvent``. One malformed event then gets
    its own ``invalid`` result, instead of failing the whole upload. A sender
    builds ``AssuranceEventBatch``, which checks every event.
    """

    events: Annotated[list[JsonValue], Field(min_length=1, max_length=MAX_BATCH_EVENTS)]


class EventResult(StrictModel):
    """What Iltero Cloud did with one event or document."""

    # The position of the event in the upload. An upload of one document is answered at 0.
    index: Annotated[int, Field(ge=0)]
    disposition: Disposition
    reason: RejectReason | None
    # The stored event. For a duplicate, the one stored first. For a conflict, the new one.
    event_id: Uuid | None
    # The digest of the event exactly as the pipeline sent it (see ``document_digest``). For a duplicate,
    # that of the first submission, which is the same. It is given exactly when event_id is.
    event_digest: Digest | None
    # For a conflict, the event stored first, whose check this one conflicts with.
    conflicts_with: Uuid | None

    @model_validator(mode="after")
    def _fits_the_disposition(self) -> EventResult:
        if (self.reason is not None) != (self.disposition in ("rejected", "invalid")):
            raise ValueError("a reason is given exactly when the event was rejected or invalid")
        if (self.reason == "schema_invalid") != (self.disposition == "invalid"):
            raise ValueError("schema_invalid is the reason exactly when the event was invalid")
        if self.disposition in ("accepted", "duplicate", "conflict") and self.event_id is None:
            raise ValueError("an accepted, duplicate or conflicting event names the stored event")
        if self.disposition == "invalid" and self.event_id is not None:
            raise ValueError("an invalid event was not stored, so it names no stored event")
        if (self.event_digest is None) != (self.event_id is None):
            raise ValueError("a stored event is named by its id and its digest together")
        if (self.conflicts_with is not None) != (self.disposition == "conflict"):
            raise ValueError("conflicts_with is given exactly when the event conflicts with a stored one")
        if self.conflicts_with is not None and self.conflicts_with == self.event_id:
            raise ValueError("a conflict names an earlier event, not itself")
        return self


class SubmissionOutcome(StrictModel):
    """Iltero Cloud's answer to an upload: one result for each event, in the order they were sent."""

    api_version: Literal["iltero.io/submission-outcome/v1"] = Field(alias="apiVersion")
    submission_id: Uuid
    received_at: Timestamp
    # The sha256 of the request body exactly as Iltero Cloud received it.
    body_digest: Digest
    results: Annotated[list[EventResult], Field(min_length=1, max_length=MAX_BATCH_EVENTS)]

    @model_validator(mode="after")
    def _one_result_per_event_in_order(self) -> SubmissionOutcome:
        if [result.index for result in self.results] != list(range(len(self.results))):
            raise ValueError("results hold one result for each event, in the order the events were sent")
        return self


def check_answers(body: bytes, sent: Sequence[Mapping[str, Any]], outcome: SubmissionOutcome) -> None:
    """Raise ``ValueError`` unless ``outcome`` answers exactly the upload ``body`` whose events were ``sent``.

    The answer names the digest of the body, holds one result for each event,
    and names each stored event by the digest of the event that was sent. For
    an upload of one document, ``sent`` holds that document.
    """
    if outcome.body_digest != digest(body):
        raise ValueError("the answer names the digest of another body than the one sent")
    if len(outcome.results) != len(sent):
        raise ValueError(f"the answer holds {len(outcome.results)} results for {len(sent)} events sent")
    for result, event in zip(outcome.results, sent, strict=True):
        if result.event_digest is not None and result.event_digest != document_digest(event):
            raise ValueError(f"results[{result.index}]: the stored event is not the event that was sent")
