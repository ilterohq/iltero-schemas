"""The CI systems the contract names, and one job of a CI run."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from iltero_schemas.models.common.ci import CiJob


def test_a_ci_job_is_named_by_its_run_an_attempt_of_one_or_more_and_its_job() -> None:
    job = CiJob.model_validate({"ci_run_id": "9876543", "ci_run_attempt": 1, "ci_job_id": "28471930012"})
    assert job.ci_run_attempt == 1
    with pytest.raises(ValidationError, match="ci_run_attempt"):
        CiJob.model_validate({"ci_run_id": "9876543", "ci_run_attempt": 0, "ci_job_id": "28471930012"})
