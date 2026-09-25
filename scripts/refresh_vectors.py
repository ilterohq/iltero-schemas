"""Regenerate the conformance vectors that are derived from code.

Compiler vectors: for every assertion under ``src/iltero_schemas/assertions``
and ``src/iltero_schemas/vectors/assertions``, the AST as JSON, its source
digest, and the compiled Rego module with its digest; ``COMPILER_VERSION``
and ``RUNTIME.digest`` (the digest of ``runtime.rego``) record what produced
them. Canonical vectors: the canonical bytes and digest of each value in
``src/iltero_schemas/vectors/canonical/values.json``, and of every case of the
assertion-set and change digests, from the inputs each case names. Document
vectors: the digest of every context under ``vectors/contexts``, every event
under ``vectors/events`` and every run document under ``vectors/wire``, each
validated against its model first.

A changed runtime under an unchanged ``COMPILER_VERSION`` is refused: every
recorded compiled digest would change while the version that explains it
stays the same. Bump the version first, then rerun; review the diff of the
vectors as carefully as the code.

Usage: python scripts/refresh_vectors.py [--check]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from pydantic import BaseModel

from iltero_schemas.ast import parse, source_digest, to_json
from iltero_schemas.canonical import (
    PLAN_DIGEST_VERSION,
    canonical_assertion_set_bytes,
    canonical_bytes,
    canonical_change_bytes,
    canonical_plan_bytes,
    digest,
    digest_of,
    plan_digest,
)
from iltero_schemas.compiler import COMPILER_VERSION, RUNTIME, compile
from iltero_schemas.models.context import AssuranceContext
from iltero_schemas.models.event import AssuranceEvent
from iltero_schemas.models.facts import AssuranceFacts
from iltero_schemas.models.run import RunOpenRequest, RunOpenResponse, TokenRefreshRequest, TokenRefreshResponse

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "src" / "iltero_schemas"
ASSERTION_DIRS = [PACKAGE / "assertions", PACKAGE / "vectors" / "assertions"]
COMPILER_VECTORS = PACKAGE / "vectors" / "compiler"
CANONICAL_VECTORS = PACKAGE / "vectors" / "canonical"
# Each folder holds one kind of document, except ``wire``, whose files are named after theirs.
WIRE_VECTORS: dict[str, type[BaseModel]] = {
    "assurance_facts.json": AssuranceFacts,
    "run_open_request.json": RunOpenRequest,
    "run_open_response.json": RunOpenResponse,
    "token_refresh_request.json": TokenRefreshRequest,
    "token_refresh_response.json": TokenRefreshResponse,
}
DOCUMENT_VECTORS: dict[Path, type[BaseModel] | dict[str, type[BaseModel]]] = {
    PACKAGE / "vectors" / "contexts": AssuranceContext,
    PACKAGE / "vectors" / "events": AssuranceEvent,
    PACKAGE / "vectors" / "wire": WIRE_VECTORS,
}


def _dump(document: object) -> bytes:
    return json.dumps(document, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"


def compiler_vectors() -> dict[str, bytes]:
    files: dict[str, bytes] = {
        "COMPILER_VERSION": f"{COMPILER_VERSION}\n".encode(),
        "RUNTIME.digest": f"{digest(RUNTIME.encode('utf-8'))}\n".encode(),
    }
    for directory in ASSERTION_DIRS:
        for path in sorted(directory.glob("*.yaml")):
            assertion = parse(path.read_text(encoding="utf-8"))
            module = compile(assertion)
            stem = path.stem
            files[f"{stem}.ast.json"] = json.dumps(to_json(assertion), indent=2).encode() + b"\n"
            files[f"{stem}.digest"] = f"{source_digest(assertion)}\n".encode()
            files[f"{stem}.rego"] = module.source
            files[f"{stem}.rego.digest"] = f"{module.digest}\n".encode()
    return files


def canonical_vectors() -> dict[str, bytes]:
    values = json.loads((CANONICAL_VECTORS / "values.json").read_text(encoding="utf-8"))
    cases = []
    for name, value in values.items():
        encoded = canonical_bytes(value)
        cases.append({"name": name, "value": value, "canonical": encoded.decode("utf-8"), "digest": digest(encoded)})
    plans = json.loads((CANONICAL_VECTORS / "plan_values.json").read_text(encoding="utf-8"))
    plan_cases = [
        {
            "name": name,
            "description": entry["description"],
            "plan": entry["plan"],
            "canonical": canonical_plan_bytes(entry["plan"]).decode("utf-8"),
            "digest": plan_digest(entry["plan"]),
        }
        for name, entry in plans.items()
    ]
    document = {"version": PLAN_DIGEST_VERSION, "cases": plan_cases}
    sets = json.loads((CANONICAL_VECTORS / "assertion_set_cases.json").read_text(encoding="utf-8"))
    for case in sets["cases"]:
        encoded = canonical_assertion_set_bytes(tuple(triple) for triple in case["assertions"])
        case.update({"canonical": encoded.decode("utf-8"), "digest": digest(encoded)})
    changes = json.loads((CANONICAL_VECTORS / "change_digest_cases.json").read_text(encoding="utf-8"))
    for case in changes["cases"]:
        encoded = canonical_change_bytes(case["units"])
        case.update({"canonical": encoded.decode("utf-8"), "digest": digest(encoded)})
    return {
        "cases.json": _dump(cases),
        "plan_digest_cases.json": _dump(document),
        "assertion_set_cases.json": _dump(sets),
        "change_digest_cases.json": _dump(changes),
    }


def document_vectors() -> dict[Path, bytes]:
    """The digest of every document vector, each validated against its model first."""
    expected = {}
    for directory, models in DOCUMENT_VECTORS.items():
        digests = {}
        for path in sorted(directory.glob("*.json")):
            if path.name == "digests.json":
                continue
            document = json.loads(path.read_text(encoding="utf-8"))
            model = models[path.name] if isinstance(models, dict) else models
            model.model_validate(document)
            digests[path.name] = digest_of(document)
        expected[directory / "digests.json"] = json.dumps(digests, indent=2).encode("utf-8") + b"\n"
    return expected


def runtime_changed_without_a_bump(expected: dict[Path, bytes]) -> bool:
    version = COMPILER_VECTORS / "COMPILER_VERSION"
    runtime = COMPILER_VECTORS / "RUNTIME.digest"
    if not version.exists() or not runtime.exists():
        return False
    return version.read_bytes() == expected[version] and runtime.read_bytes() != expected[runtime]


def main(argv: list[str]) -> int:
    check = argv[1:] == ["--check"]
    if argv[1:] and not check:
        print(__doc__, file=sys.stderr)
        return 2
    expected = {COMPILER_VECTORS / name: data for name, data in compiler_vectors().items()}
    expected.update({CANONICAL_VECTORS / name: data for name, data in canonical_vectors().items()})
    expected.update(document_vectors())
    if runtime_changed_without_a_bump(expected):
        print("runtime.rego changed but COMPILER_VERSION did not; bump it first", file=sys.stderr)
        return 1
    stale = [path for path, data in expected.items() if not path.exists() or path.read_bytes() != data]
    if check:
        for path in stale:
            print(f"out of date: {path.relative_to(ROOT)}", file=sys.stderr)
        return 1 if stale else 0
    for path in stale:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(expected[path])
        print(f"wrote {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
