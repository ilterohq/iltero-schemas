from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from iltero_schemas.canonical import digest
from iltero_schemas.opa import CAPABILITIES, CAPABILITIES_DIGEST

ROOT = Path(__file__).resolve().parent.parent
DOCUMENT = json.loads(CAPABILITIES)
NAMES = [b["name"] for b in DOCUMENT["builtins"]]
# Families that reach the network, the clock, randomness, the host or a
# parser the assertion language never needs.
FORBIDDEN_PREFIXES = (
    "http.",
    "net.",
    "opa.",
    "rand.",
    "time.",
    "regex.",
    "io.",
    "crypto.",
    "providers.",
    "graphql.",
    "rego.",
    "glob.",
    "uuid.",
    "yaml.",
    "base64",
    "hex.",
    "urlquery.",
    "uri.",
    "units.",
    "bits.",
    "graph.",
    "cast_",
)
FORBIDDEN_NAMES = {
    "trace",
    "print",
    "internal.print",
    "re_match",
    "internal.template_string",
    "internal.test_case",
    "all",
    "any",
    "strings.render_template",
    "json.match_schema",
    "json.verify_schema",
    "json.marshal_with_options",
}


def test_the_allowlist_names_no_forbidden_builtin() -> None:
    assert not [n for n in NAMES if n.startswith(FORBIDDEN_PREFIXES) or n in FORBIDDEN_NAMES]


def test_the_allowlist_is_sorted_unique_and_declares_each_builtin() -> None:
    assert NAMES == sorted(set(NAMES))
    assert all({"name", "decl"} <= set(b) for b in DOCUMENT["builtins"])


def test_the_runtime_calls_only_allowed_builtins() -> None:
    runtime = (ROOT / "src" / "iltero_schemas" / "compiler" / "runtime.rego").read_text(encoding="utf-8")
    defined = set(re.findall(r"^([a-z_][a-z0-9_]*)\(", runtime, flags=re.MULTILINE))
    called = set(re.findall(r"\b([a-z_][a-z0-9_.]*)\(", runtime)) - defined
    assert called <= set(NAMES), called - set(NAMES)
    assert {"object.get", "array.slice", "numbers.range", "split", "count", "sprintf"} <= called


def test_features_and_keywords_are_fixed() -> None:
    assert DOCUMENT["features"] == ["rego_v1", "keywords_in_refs"]
    assert DOCUMENT["future_keywords"] == []
    assert set(DOCUMENT) == {"builtins", "future_keywords", "features"}


def test_the_digest_is_over_the_file_bytes() -> None:
    assert CAPABILITIES_DIGEST == digest((ROOT / "src" / "iltero_schemas" / "opa" / "capabilities.json").read_bytes())


def test_the_allowlist_matches_the_pinned_binary(opa: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "refresh_capabilities.py"), str(opa), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_vectors_match_the_code() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "refresh_vectors.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
