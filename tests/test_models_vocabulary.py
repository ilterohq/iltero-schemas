"""The named spellings of values consumers write as plain strings."""

from __future__ import annotations

import json

from iltero_schemas.models.iac import ADDRESS_SCHEMES
from iltero_schemas.models.vocabulary import SCHEME_UNIT
from tests.conftest import VECTORS

# The subject kinds a unit names: the change across a unit, and the unit's deployment.
UNIT_SUBJECTS = ("change", "deployment")


def test_the_context_vectors_name_a_unit_in_the_named_scheme() -> None:
    schemes: list[str] = []
    for path in sorted((VECTORS / "contexts").glob("*.json")):
        subject = json.loads(path.read_text(encoding="utf-8")).get("subject")
        if subject is not None and subject["kind"] in UNIT_SUBJECTS:
            schemes.extend(identity["scheme"] for identity in subject["identities"])
    assert schemes and set(schemes) == {SCHEME_UNIT}


def test_the_vectors_name_a_resource_by_its_address_in_the_named_scheme() -> None:
    schemes: list[str] = []
    for path in sorted((VECTORS / "contexts").glob("*.json")):
        subject = json.loads(path.read_text(encoding="utf-8")).get("subject")
        if subject is not None and subject["kind"] == "resource":
            schemes.extend(identity["scheme"] for identity in subject["identities"])
    assert schemes and set(schemes) == {ADDRESS_SCHEMES["terraform"]}
