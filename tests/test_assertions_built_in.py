"""The assertions this package ships: each by the id its document gives, the built-ins among them."""

from __future__ import annotations

from iltero_schemas.assertions import BUILT_IN_IDS, BUILT_INS, SHIPPED_ASSERTIONS
from iltero_schemas.ast import parse
from tests.conftest import STARTER_ASSERTIONS


def test_every_shipped_assertion_is_named_by_its_documents_id_and_file() -> None:
    by_document = {parse(path.read_text(encoding="utf-8")).id: path.stem for path in STARTER_ASSERTIONS.glob("*.yaml")}
    assert all(assertion_id == stem for assertion_id, stem in by_document.items())
    assert set(SHIPPED_ASSERTIONS) == set(by_document)


def test_the_shipped_assertions_hold_every_built_in() -> None:
    assert set(BUILT_INS) == set(BUILT_IN_IDS) <= set(SHIPPED_ASSERTIONS)
    assert all(BUILT_INS[assertion_id] == SHIPPED_ASSERTIONS[assertion_id] for assertion_id in BUILT_INS)
