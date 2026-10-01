"""The model each document under ``vectors/wire`` is read as, by file name."""

from __future__ import annotations

from pydantic import BaseModel

from iltero_schemas.models.car import CAR
from iltero_schemas.models.facts import AssuranceFacts
from iltero_schemas.models.ingest import AssuranceEventBatch, SubmissionOutcome
from iltero_schemas.models.run import (
    RunCloseResponse,
    RunOpenRequest,
    RunOpenResponse,
    TokenRefreshRequest,
    TokenRefreshResponse,
)

WIRE_MODELS: dict[str, type[BaseModel]] = {
    "assurance_event_batch.json": AssuranceEventBatch,
    "assurance_facts.json": AssuranceFacts,
    "change_assurance_record.json": CAR,
    "run_close_response.json": RunCloseResponse,
    "run_open_request.json": RunOpenRequest,
    "run_open_response.json": RunOpenResponse,
    "submission_outcome.json": SubmissionOutcome,
    "token_refresh_request.json": TokenRefreshRequest,
    "token_refresh_response.json": TokenRefreshResponse,
}
