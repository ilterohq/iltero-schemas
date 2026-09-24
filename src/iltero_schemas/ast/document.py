"""Strict loading of one assertion document from YAML text.

Only plain data is accepted: one document, string keys, no duplicate keys,
no anchors, aliases, tags or merge keys, bounded size and nesting. Anything
else is an error that names the line and the problem — never the text
around it, which may hold values that must not reach a log — and never a
silently different document.
"""

from __future__ import annotations

from typing import Any

import yaml

# An assertion is a few hundred bytes; this leaves room for a long list literal.
MAX_DOCUMENT_BYTES = 256 * 1024
# Deeper than any assertion the language allows; checked before the
# recursive composer runs, so a hostile document cannot exhaust the stack.
MAX_NESTING = 32
_MERGE_TAG = "tag:yaml.org,2002:merge"


class DocumentError(ValueError):
    """The text is not one plain YAML mapping."""


def _line(mark: Any) -> int:
    return int(mark.line) + 1 if mark is not None else 0


def _check_events(text: str) -> None:
    """Walk the (iterative) event stream: bound nesting, refuse anchors, aliases and tags."""
    depth = 0
    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        if isinstance(event, yaml.AliasEvent):
            raise DocumentError(f"line {_line(event.start_mark)}: aliases are not allowed")
        if isinstance(event, yaml.NodeEvent) and event.anchor is not None:
            raise DocumentError(f"line {_line(event.start_mark)}: anchors are not allowed")
        if isinstance(event, yaml.NodeEvent) and getattr(event, "tag", None) is not None:
            raise DocumentError(f"line {_line(event.start_mark)}: tags are not allowed")
        if isinstance(event, yaml.CollectionStartEvent):
            depth += 1
            if depth > MAX_NESTING:
                raise DocumentError(f"line {_line(event.start_mark)}: nested deeper than {MAX_NESTING}")
        elif isinstance(event, yaml.CollectionEndEvent):
            depth -= 1


def _describe(exc: yaml.MarkedYAMLError) -> str:
    """The line and the parser's own words; the text of the document is never echoed."""
    where = exc.problem_mark if exc.problem_mark is not None else exc.context_mark
    parts = [part for part in (exc.context, exc.problem) if part]
    return f"line {_line(where)}: not valid YAML: {'; '.join(parts) or 'unknown problem'}"


class _Loader(yaml.SafeLoader):
    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[str] = set()
        for key_node, _ in node.value:
            line = _line(key_node.start_mark)
            if key_node.tag == _MERGE_TAG:
                raise DocumentError(f"line {line}: merge keys are not allowed")
            key = self.construct_object(key_node, deep=True)
            if not isinstance(key, str):
                raise DocumentError(f"line {line}: mapping keys must be strings (quote {key!r})")
            if key in seen:
                raise DocumentError(f"line {line}: duplicate key {key!r}")
            seen.add(key)
        return super().construct_mapping(node, deep)


def load_document(text: str) -> dict[str, Any]:
    """Parse ``text`` as one YAML mapping."""
    if len(text.encode("utf-8", errors="surrogatepass")) > MAX_DOCUMENT_BYTES:
        raise DocumentError(f"document larger than {MAX_DOCUMENT_BYTES} bytes")
    try:
        _check_events(text)
        document = yaml.load(text, Loader=_Loader)  # noqa: S506 - _Loader derives from SafeLoader
    except yaml.MarkedYAMLError as exc:
        raise DocumentError(_describe(exc)) from exc
    except yaml.YAMLError as exc:
        raise DocumentError("not valid YAML") from exc
    if not isinstance(document, dict):
        raise DocumentError("the document must be a mapping")
    return document
