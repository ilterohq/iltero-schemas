"""The upload contract.

A batch holds one to 2,000 events, all of the run, stage and unit it names.
The envelope reads the same upload with each event left unread. An answer
holds one result per event, in order. Each result's reason, stored id,
digest and conflict agree with what happened to the event. The rules a single
changed value breaks are also in the wire vectors (``vectors/wire_invalid``).
"""

from __future__ import annotations

import json
from typing import Any, get_args

import pytest
from pydantic import ValidationError

from iltero_schemas.canonical.encoding import canonical_bytes, digest
from iltero_schemas.models.coverage import STATUSES
from iltero_schemas.models.event import STATUS_SEVERITY, worse_status
from iltero_schemas.models.ingest import (
    EVENTS_API_VERSION,
    MAX_BATCH_EVENTS,
    OUTCOME_API_VERSION,
    AssuranceEventBatch,
    AssuranceEventBatchEnvelope,
    Disposition,
    SubmissionOutcome,
    check_answers,
    document_digest,
)
from tests.conftest import VECTORS

WIRE = VECTORS / "wire"
BATCH: dict[str, Any] = json.loads((WIRE / "assurance_event_batch.json").read_text(encoding="utf-8"))
OUTCOME: dict[str, Any] = json.loads((WIRE / "submission_outcome.json").read_text(encoding="utf-8"))
EVENT: dict[str, Any] = BATCH["events"][0]


def test_the_vectors_name_these_api_versions() -> None:
    assert AssuranceEventBatch.model_validate(BATCH).api_version == EVENTS_API_VERSION
    assert AssuranceEventBatchEnvelope.model_validate(BATCH).api_version == EVENTS_API_VERSION
    assert SubmissionOutcome.model_validate(OUTCOME).api_version == OUTCOME_API_VERSION


def test_a_batch_holds_at_most_the_largest_upload() -> None:
    AssuranceEventBatch.model_validate({**BATCH, "events": [EVENT] * MAX_BATCH_EVENTS})
    with pytest.raises(ValidationError, match=f"at most {MAX_BATCH_EVENTS}"):
        AssuranceEventBatch.model_validate({**BATCH, "events": [EVENT] * (MAX_BATCH_EVENTS + 1)})


def test_an_answer_holds_at_most_one_result_per_event_of_the_largest_upload() -> None:
    result = {**OUTCOME["results"][0]}
    results = [{**result, "index": index} for index in range(MAX_BATCH_EVENTS + 1)]
    with pytest.raises(ValidationError, match=f"at most {MAX_BATCH_EVENTS}"):
        SubmissionOutcome.model_validate({**OUTCOME, "results": results})


def test_the_envelope_leaves_a_malformed_event_for_its_own_answer() -> None:
    malformed = {**EVENT, "observed_at": "yesterday"}
    envelope = AssuranceEventBatchEnvelope.model_validate({**BATCH, "events": [EVENT, malformed]})
    assert envelope.events[1] == malformed
    with pytest.raises(ValidationError, match="observed_at"):
        AssuranceEventBatch.model_validate({**BATCH, "events": [EVENT, malformed]})


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"events": []}, "at least 1 item"),
        ({"events": [EVENT] * (MAX_BATCH_EVENTS + 1)}, f"at most {MAX_BATCH_EVENTS} items"),
        ({"run_id": "run_001"}, "run_id"),
        ({"run_token": "irt_" + "A" * 43}, "Extra inputs are not permitted"),
    ],
    ids=["empty", "too_many", "run_id", "unknown_key"],
)
def test_the_envelope_still_checks_its_own_fields(change: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        AssuranceEventBatchEnvelope.model_validate({**BATCH, **change})


def test_the_envelope_leaves_an_event_that_is_not_an_object_for_its_own_answer() -> None:
    envelope = AssuranceEventBatchEnvelope.model_validate({**BATCH, "events": [EVENT, "not an event"]})
    assert envelope.events[1] == "not an event"


def test_the_outcome_vector_holds_every_disposition() -> None:
    assert {result["disposition"] for result in OUTCOME["results"]} == set(get_args(Disposition))


def test_a_rejected_event_may_or_may_not_have_been_stored() -> None:
    rejected = [r for r in SubmissionOutcome.model_validate(OUTCOME).results if r.disposition == "rejected"]
    assert {r.event_id is None for r in rejected} == {True, False}


def test_a_stored_event_is_named_by_the_digest_of_its_canonical_json() -> None:
    accepted = SubmissionOutcome.model_validate(OUTCOME).results[0]
    assert accepted.event_digest == document_digest(EVENT)


def _answer(sent: list[dict[str, Any]], body: bytes) -> SubmissionOutcome:
    """The outcome vector, as the answer to an upload of ``body`` holding the events ``sent``."""
    results = [
        {**result, "event_digest": None if result["event_digest"] is None else document_digest(event)}
        for result, event in zip(OUTCOME["results"], sent, strict=True)
    ]
    return SubmissionOutcome.model_validate({**OUTCOME, "body_digest": digest(body), "results": results})


SENT: list[dict[str, Any]] = [EVENT] + [{"event": index} for index in range(1, len(OUTCOME["results"]))]
BODY = canonical_bytes({**BATCH, "events": SENT})


def test_an_answer_to_exactly_what_was_sent_passes() -> None:
    check_answers(BODY, SENT, _answer(SENT, BODY))


def test_an_answer_for_another_body_is_refused() -> None:
    with pytest.raises(ValueError, match="another body than the one sent"):
        check_answers(BODY + b" ", SENT, _answer(SENT, BODY))


@pytest.mark.parametrize("count", [len(SENT) - 1, len(SENT) + 1], ids=["fewer", "more"])
def test_an_answer_with_another_number_of_results_than_events_sent_is_refused(count: int) -> None:
    sent = (SENT + [{"event": "extra"}])[:count]
    with pytest.raises(ValueError, match=f"results for {count} events sent"):
        check_answers(BODY, sent, _answer(SENT, BODY))


def test_an_answer_that_stored_another_event_is_refused() -> None:
    changed = [*SENT[:1], {"event": "changed"}, *SENT[2:]]
    with pytest.raises(ValueError, match=r"results\[1\]: the stored event is not the event that was sent"):
        check_answers(BODY, changed, _answer(SENT, BODY))


def test_an_upload_of_one_document_is_answered_at_index_0() -> None:
    body = canonical_bytes(EVENT)
    single = SubmissionOutcome.model_validate(
        {**OUTCOME, "body_digest": digest(body), "results": [{**OUTCOME["results"][0], "index": 0}]}
    )
    check_answers(body, [EVENT], single)
    with pytest.raises(ValidationError, match="in the order the events were sent"):
        SubmissionOutcome.model_validate({**OUTCOME, "results": [{**OUTCOME["results"][0], "index": 1}]})


def test_the_status_order_ranks_every_status_once() -> None:
    assert sorted(STATUS_SEVERITY) == sorted(STATUSES)


@pytest.mark.parametrize(
    ("first", "second", "stands"),
    [
        ("pass", "fail", "fail"),
        ("fail", "not_evaluated", "not_evaluated"),
        ("error", "unknown", "error"),
        ("unknown", "fail", "unknown"),
        ("pass", "not_applicable", "not_applicable"),
    ],
)
def test_the_worse_of_two_conflicting_statuses_stands(first: Any, second: Any, stands: str) -> None:
    assert worse_status(first, second) == stands
    assert worse_status(second, first) == stands
