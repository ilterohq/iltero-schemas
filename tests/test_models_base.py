"""The base of every model that reads external input."""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from iltero_schemas.models.assertion import TechnicalAssertion
from iltero_schemas.models.binding import EvaluatorBindingSet
from iltero_schemas.models.event import AssuranceEvent

REFUSED_VALUE = "value-a-refusal-never-repeats"


@pytest.mark.parametrize("model", [AssuranceEvent, EvaluatorBindingSet, TechnicalAssertion])
def test_a_refusal_never_repeats_the_value_it_refused(model: type[BaseModel]) -> None:
    with pytest.raises(ValidationError) as refused:
        model.model_validate({"apiVersion": REFUSED_VALUE, "kind": REFUSED_VALUE, "metadata": REFUSED_VALUE})
    assert REFUSED_VALUE not in str(refused.value)
    assert "input_value" not in str(refused.value)
