"""The kept-bundle check's conformance cases: each names a record, the values it sets in it, the tarballs its reader is
given and the problems ``served_bundle_problems`` lists under the vectors' trust set."""

from __future__ import annotations

import base64
import copy
import dataclasses
import json
from collections.abc import Mapping
from typing import Any

import pytest

from iltero_schemas.canonical import digest
from iltero_schemas.models.common.car import CAR, SKIP_INTEGRITY_CHECKS
from iltero_schemas.models.common.kept_bundles import served_bundle_problems
from iltero_schemas.trust import SigningKey
from iltero_schemas.vectors.kept_files import kept_files_of, kept_served_bundles
from iltero_schemas.vectors.plans import set_pointer
from iltero_schemas.vectors.vector_signing_keys import vector_signing_keys
from tests.conftest import CHANGE_TYPES, VECTORS
from tests.server_runs import verify_es256

CASES: list[dict[str, Any]] = [
    case
    for change_type in CHANGE_TYPES
    for case in json.loads((VECTORS / "kept_bundles" / change_type / "cases.json").read_text(encoding="utf-8"))
]


# The trust set the vectors' served bundles are read back under, and the same set with the development key revoked.
KEYS = vector_signing_keys()
TRUST_SETS = {
    "development": KEYS,
    "development_key_revoked": {
        key_id: dataclasses.replace(
            key, status="revoked", revoked_at="2026-11-01T00:00:00Z", revocation_reason="key_compromised"
        )
        for key_id, key in KEYS.items()
    },
}


def case_inputs(case: dict[str, Any]) -> tuple[dict[str, Any], dict[str, bytes], Mapping[str, SigningKey]]:
    """What the check reads for ``case``: its record with ``set`` applied, the tarballs ``tarballs`` names (the record's
    kept ones, none, or the kept ones and the bytes it holds, under their own digest or under the ``digest`` it names)
    and the trust set it names (``trust_set``)."""
    record = json.loads((VECTORS / "records" / case["vector"]).read_text(encoding="utf-8"))
    bundles = dict(kept_served_bundles(record, kept_files_of(case["vector"])))
    for pointer, value in case["set"].items():
        set_pointer(record, pointer, copy.deepcopy(value))
    given = case["tarballs"]
    if given == "none":
        bundles = {}
    elif given != "kept":
        data = base64.b64decode(given["base64"])
        bundles[given.get("digest", digest(data))] = data
    return record, bundles, TRUST_SETS[case["trust_set"]]


def problems_over(
    record: dict[str, Any], bundles: Mapping[str, bytes], keys: Mapping[str, SigningKey]
) -> list[list[str]]:
    """The problems the check lists for ``record``, read without its integrity checks, with an ES256 signature check."""
    car = CAR.model_validate(record, context={SKIP_INTEGRITY_CHECKS: True})
    return [list(problem) for problem in served_bundle_problems(car, bundles, keys, verify_es256)]


def problems_of(case: dict[str, Any]) -> list[list[str]]:
    """The problems the check lists for ``case``."""
    return problems_over(*case_inputs(case))


@pytest.mark.parametrize("case", CASES, ids=[f"{case['vector'].split('/')[0]}:{case['name']}" for case in CASES])
def test_the_kept_bundle_check_lists_the_problems_each_case_names(case: dict[str, Any]) -> None:
    assert case["trust_set"] in TRUST_SETS
    assert case["tarballs"] in ("kept", "none") or set(case["tarballs"]) in ({"base64"}, {"base64", "digest"})
    assert problems_of(case) == case["problems"]


def test_every_change_type_has_a_record_whose_kept_bundles_hold_every_module_its_events_ran() -> None:
    assert {case["vector"].split("/")[0] for case in CASES if case["problems"] == []} == set(CHANGE_TYPES)
