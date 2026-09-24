from __future__ import annotations

from typing import Any

import pytest

from iltero_schemas.ast import (
    AST_VERSION,
    All,
    AnyOf,
    AssertionSyntaxError,
    Exists,
    Literal,
    Not,
    Operator,
    Path,
    Predicate,
    allowed_roots,
    parse,
    parse_document,
    source_digest,
    to_json,
)
from iltero_schemas.ast.document import load_document
from iltero_schemas.ast.parse import (
    MAX_ARGS,
    MAX_DEPTH,
    MAX_LIST_LITERAL,
    MAX_NODES,
    MAX_PATH_SEGMENTS,
    MAX_SEGMENT_LENGTH,
    MAX_STRING_LITERAL,
)
from iltero_schemas.canonical import INT_MAX
from iltero_schemas.models.assertion import Stage, TargetKind

RESOURCE = {"kind": "resource", "provider": "aws", "resource_types": ["aws_db_instance"]}


def _document(
    assert_: Any, *, stage: str = "plan", target: dict[str, Any] | None = None, when: Any = None
) -> dict[str, Any]:
    spec: dict[str, Any] = {"stage": stage, "target": target or RESOURCE, "assert": assert_}
    if when is not None:
        spec["when"] = when
    return {
        "apiVersion": "iltero.io/v1",
        "kind": "TechnicalAssertion",
        "metadata": {"id": "ACME.TEST.CASE", "version": "1.0.0", "title": "t"},
        "spec": spec,
    }


def _issues(document: dict[str, Any]) -> list[str]:
    with pytest.raises(AssertionSyntaxError) as raised:
        parse_document(document)
    return [issue.path for issue in raised.value.issues]


def test_predicate_with_literal_and_with_reference() -> None:
    ast = parse_document(_document({"path": "resource.after.x", "equal": {"path": "plan.digest"}}))
    assert ast.assert_ == Predicate(Path(("resource", "after", "x")), Operator.EQUAL, Path(("plan", "digest")))
    ast = parse_document(_document({"path": "resource.after.x", "in": ["a", "b"]}))
    assert ast.assert_ == Predicate(Path(("resource", "after", "x")), Operator.IN, Literal(("a", "b")))


def test_combinators_and_exists_without_where() -> None:
    ast = parse_document(
        _document(
            {
                "all": [
                    {"any": [{"path": "resource.a", "equal": 1}, {"not": {"path": "resource.b", "equal": 2}}]},
                    {"exists": {"in": "resource.related"}},
                ]
            }
        )
    )
    assert isinstance(ast.assert_, All)
    assert isinstance(ast.assert_.args[0], AnyOf)
    assert isinstance(ast.assert_.args[0].args[1], Not)
    assert ast.assert_.args[1] == Exists(Path(("resource", "related")), None)


def test_type_is_derived_and_resource_types_are_sorted() -> None:
    target = {"kind": "resource", "provider": "aws", "resource_types": ["b", "a"]}
    ast = parse_document(_document({"path": "resource.x", "equal": 1}, target=target))
    assert ast.type.value == "state"
    assert ast.target.resource_types == ("a", "b")
    assert to_json(ast)["target"] == {"kind": "resource", "provider": "aws", "resource_types": ["a", "b"]}


def test_process_target_has_no_provider_in_the_ast() -> None:
    ast = parse_document(
        _document({"path": "change.digest", "equal": "x"}, stage="pre_deploy", target={"kind": "change"})
    )
    assert ast.target.provider is None
    assert to_json(ast)["target"] == {"kind": "change"}


def test_ast_json_carries_its_version_and_no_title() -> None:
    encoded = to_json(parse_document(_document({"path": "resource.x", "equal": 1})))
    assert encoded["ast_version"] == AST_VERSION
    assert "title" not in encoded
    assert encoded["when"] is None


def test_source_digest_ignores_the_title_and_key_order() -> None:
    first = _document({"path": "resource.x", "equal": 1})
    second = _document({"equal": 1, "path": "resource.x"})
    second["metadata"]["title"] = "another title"
    assert source_digest(parse_document(first)) == source_digest(parse_document(second))


def test_integral_floats_become_integers_and_others_stay() -> None:
    ast = parse_document(_document({"path": "resource.x", "equal": 7.0}))
    assert ast.assert_ == Predicate(Path(("resource", "x")), Operator.EQUAL, Literal(7))
    ast = parse_document(_document({"path": "resource.x", "greater_than": 0.5}))
    assert ast.assert_ == Predicate(Path(("resource", "x")), Operator.GREATER_THAN, Literal(0.5))


def test_two_operators_or_no_path_is_not_a_predicate() -> None:
    assert _issues(_document({"path": "resource.x", "equal": 1, "less_than": 3})) == ["spec.assert"]
    assert _issues(_document({"equal": 1})) == ["spec.assert"]
    assert _issues(_document({"path": "resource.x"})) == ["spec.assert"]
    assert _issues(_document({"path": "resource.x", "matches": "a"})) == ["spec.assert"]


def test_a_combinator_must_be_the_only_key() -> None:
    assert _issues(_document({"all": [{"path": "resource.x", "equal": 1}], "path": "resource.y"})) == ["spec.assert"]
    assert _issues(_document({"all": [], "any": []})) == ["spec.assert"]


def test_all_and_any_take_a_non_empty_bounded_list() -> None:
    assert _issues(_document({"all": []})) == ["spec.assert.all"]
    assert _issues(_document({"any": {"path": "resource.x", "equal": 1}})) == ["spec.assert.any"]
    too_many = [{"path": "resource.x", "equal": 1}] * (MAX_ARGS + 1)
    assert _issues(_document({"all": too_many})) == ["spec.assert.all"]


def test_exists_shape() -> None:
    assert _issues(_document({"exists": {"where": {"path": "item.x", "equal": 1}}})) == ["spec.assert.exists"]
    assert _issues(_document({"exists": {"in": "resource.related", "limit": 1}})) == ["spec.assert.exists"]
    assert _issues(_document({"exists": "resource.related"})) == ["spec.assert.exists"]


def test_item_is_only_valid_inside_where_and_shadows_in_nested_exists() -> None:
    assert _issues(_document({"path": "item.x", "equal": 1})) == ["spec.assert.path"]
    assert _issues(_document({"exists": {"in": "item.x"}})) == ["spec.assert.exists.in"]
    nested = {
        "exists": {
            "in": "resource.related",
            "where": {"exists": {"in": "item.rules", "where": {"path": "item.port", "equal": 443}}},
        }
    }
    parse_document(_document(nested))


@pytest.mark.parametrize("stage", list(Stage))
def test_path_root_must_be_available_at_the_stage(stage: Stage) -> None:
    target: dict[str, Any] = {"kind": "change"} if stage is Stage.PRE_DEPLOY else {"kind": "deployment"}
    if stage is Stage.PLAN:
        target = RESOURCE
    kind = TargetKind(target["kind"])
    roots = allowed_roots(stage, kind)
    for root in roots:
        parse_document(_document({"path": f"{root}.x", "equal": 1}, stage=stage.value, target=target))
    assert _issues(_document({"path": "nowhere.x", "equal": 1}, stage=stage.value, target=target)) == [
        "spec.assert.path"
    ]


def test_resource_root_exists_only_for_resource_targets() -> None:
    assert "resource" in allowed_roots(Stage.POST_VERIFY, TargetKind.RESOURCE)
    assert "resource" not in allowed_roots(Stage.POST_VERIFY, TargetKind.DEPLOYMENT)
    assert "reference_time" in allowed_roots(Stage.RUNTIME, TargetKind.ASSURANCE)


@pytest.mark.parametrize(
    "path",
    [
        "",
        "resource..b",
        ".resource",
        "resource.",
        "resource.a b",
        "resource.1a",
        "resource.a[0]",
        "resource." + "b" * (MAX_SEGMENT_LENGTH + 1),
        ".".join(["resource"] + ["a"] * MAX_PATH_SEGMENTS),
    ],
)
def test_path_grammar(path: str) -> None:
    assert _issues(_document({"path": path, "equal": 1})) == ["spec.assert.path"]


def test_a_bare_root_and_hyphenated_segments_are_paths() -> None:
    parse_document(_document({"path": "resource", "equal": 1}))
    parse_document(_document({"path": "resource.tags.my-tag", "equal": 1}))


def test_reference_operand_is_a_mapping_with_only_path() -> None:
    assert _issues(_document({"path": "resource.x", "equal": {"path": "plan.digest", "default": 1}})) == [
        "spec.assert.equal"
    ]
    assert _issues(_document({"path": "resource.x", "equal": {"ref": "plan.digest"}})) == ["spec.assert.equal"]
    assert _issues(_document({"path": "resource.x", "equal": {"path": "approvals.x"}})) == ["spec.assert.equal.path"]


def test_list_operators_take_a_non_empty_bounded_list_of_scalars_or_a_reference() -> None:
    assert _issues(_document({"path": "resource.x", "in": "a"})) == ["spec.assert.in"]
    assert _issues(_document({"path": "resource.x", "not_in": []})) == ["spec.assert.not_in"]
    assert _issues(_document({"path": "resource.x", "in": [["a"]]})) == ["spec.assert.in[0]"]
    assert _issues(_document({"path": "resource.x", "in": ["a"] * (MAX_LIST_LITERAL + 1)})) == ["spec.assert.in"]
    parse_document(_document({"path": "resource.x", "in": {"path": "plan.allowed"}}))


def test_scalar_operators_refuse_lists_null_and_dates() -> None:
    assert _issues(_document({"path": "resource.x", "equal": ["a"]})) == ["spec.assert.equal"]
    assert _issues(_document({"path": "resource.x", "equal": None})) == ["spec.assert.equal"]
    assert _issues(_document({"path": "resource.x", "contains": {"a": 1}})) == ["spec.assert.contains"]
    assert _issues(parse_yaml_document("path: resource.x\nequal: 2026-01-01")) == ["spec.assert.equal"]


def parse_yaml_document(assert_yaml: str) -> dict[str, Any]:
    return _document(load_document(assert_yaml))


def test_ordering_operators_refuse_booleans() -> None:
    assert _issues(_document({"path": "resource.x", "greater_than": True})) == ["spec.assert.greater_than"]
    parse_document(_document({"path": "resource.x", "greater_than": "2026-01-01T00:00:00.000Z"}))


def test_numbers_and_strings_are_bounded() -> None:
    assert _issues(_document({"path": "resource.x", "equal": INT_MAX + 1})) == ["spec.assert.equal"]
    assert _issues(_document({"path": "resource.x", "equal": float("inf")})) == ["spec.assert.equal"]
    assert _issues(_document({"path": "resource.x", "equal": "x" * (MAX_STRING_LITERAL + 1)})) == ["spec.assert.equal"]
    assert _issues(_document({"path": "resource.x", "equal": "a\x00b"})) == ["spec.assert.equal"]


def test_nesting_depth_and_node_count_are_bounded() -> None:
    deep: dict[str, Any] = {"path": "resource.x", "equal": 1}
    for _ in range(MAX_DEPTH):
        deep = {"not": deep}
    assert _issues(_document(deep))[0].startswith("spec.assert")
    wide = {"all": [{"any": [{"path": "resource.x", "equal": 1}] * 3}] * (MAX_NODES // 3)}
    assert _issues(_document(wide))[0].startswith("spec.assert")


def test_node_count_spans_when_and_assert() -> None:
    half = {"all": [{"path": "resource.x", "equal": 1}] * (MAX_NODES // 2)}
    parse_document(_document(half))
    assert _issues(_document(half, when=half))[0].startswith("spec.assert")


def test_issue_paths_use_document_keys_only() -> None:
    document = _document({"path": "resource.x", "equal": 1}, target={"kind": "change", "provider": "aws"})
    document["spec"]["stage"] = "pre_deploy"
    with pytest.raises(AssertionSyntaxError) as raised:
        parse_document(document)
    assert [str(issue) for issue in raised.value.issues] == ["spec.target.provider: Extra inputs are not permitted"]


def test_strings_must_be_valid_unicode() -> None:
    assert _issues(_document({"path": "resource.x", "equal": "\ud800"})) == ["spec.assert.equal"]


def test_every_problem_is_reported_with_its_path() -> None:
    document = _document(
        {"all": [{"path": "resource.x"}, {"path": "approvals.x", "equal": 1}]}, when={"path": "item.x", "equal": 1}
    )
    assert _issues(document) == ["spec.when.path", "spec.assert.all[0]", "spec.assert.all[1].path"]


def test_envelope_errors_are_reported_before_expression_errors() -> None:
    document = _document({"path": "resource.x"})
    document["metadata"]["version"] = "1"
    assert _issues(document) == ["metadata.version"]


def test_parse_reads_yaml_text_and_reports_document_errors() -> None:
    ast = parse(
        "apiVersion: iltero.io/v1\nkind: TechnicalAssertion\n"
        "metadata: {id: A.B, version: '1.0.0', title: t}\n"
        "spec:\n  stage: plan\n  target: {kind: resource, provider: aws, resource_types: [x]}\n"
        "  assert: {path: resource.x, equal: 1}\n"
    )
    assert ast.id == "A.B"
    with pytest.raises(AssertionSyntaxError) as raised:
        parse("- not a mapping")
    assert raised.value.issues[0].path == "document"
