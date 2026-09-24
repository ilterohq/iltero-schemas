from __future__ import annotations

import pytest

from iltero_schemas.ast.document import MAX_DOCUMENT_BYTES, MAX_NESTING, DocumentError, load_document


def test_a_plain_mapping_loads() -> None:
    assert load_document("a: 1\nb: [x, y]\n") == {"a": 1, "b": ["x", "y"]}


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("a: 1\na: 2\n", "duplicate key"),
        ("a: [1]\nb: *x\n", "aliases are not allowed"),
        ("a: &x [1]\n", "anchors are not allowed"),
        ("a: " + "[" * (MAX_NESTING + 1) + "]" * (MAX_NESTING + 1) + "\n", "nested deeper than"),
        ("a: " + "{b: " * (MAX_NESTING + 1) + "1" + "}" * (MAX_NESTING + 1) + "\n", "nested deeper than"),
        ("base: {a: 1}\nb:\n  <<: {a: 2}\n", "merge keys are not allowed"),
        ("on: 1\n", "mapping keys must be strings"),
        ("1: x\n", "mapping keys must be strings"),
        ("- a\n", "must be a mapping"),
        ("a: 1\n---\nb: 2\n", "not valid YAML"),
        ("a: [\n", "line 2: not valid YAML: while parsing a flow node"),
        ("a: !!binary aGVsbG8=\n", "tags are not allowed"),
        ("a: !!str 1\n", "tags are not allowed"),
        ("", "must be a mapping"),
        ("a: !!python/object:os.system x\n", "tags are not allowed"),
    ],
)
def test_anything_but_plain_data_is_refused(text: str, message: str) -> None:
    with pytest.raises(DocumentError, match=message):
        load_document(text)


def test_nested_mappings_are_checked_too() -> None:
    with pytest.raises(DocumentError, match="line 4: duplicate key 'k'"):
        load_document("a:\n  b:\n    k: 1\n    k: 2\n")


def test_nesting_up_to_the_bound_loads_and_deeper_never_reaches_the_composer() -> None:
    load_document("a: " + "[" * (MAX_NESTING - 1) + "]" * (MAX_NESTING - 1) + "\n")
    with pytest.raises(DocumentError, match="nested deeper than"):
        load_document("a: " + "[" * 5000 + "]" * 5000 + "\n")


def test_a_syntax_error_names_the_line_but_never_echoes_the_text() -> None:
    hidden = "value-that-must-not-be-echoed"
    with pytest.raises(DocumentError) as raised:
        load_document(f'token: "{hidden}" [\n')
    assert hidden not in str(raised.value) and "line 1" in str(raised.value)


def test_oversized_documents_are_refused() -> None:
    with pytest.raises(DocumentError, match="larger than"):
        load_document("a: " + "x" * MAX_DOCUMENT_BYTES)
