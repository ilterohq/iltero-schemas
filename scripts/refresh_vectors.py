"""Regenerate the conformance vectors that are derived from code.

Compiler vectors: for every assertion under ``src/iltero_schemas/assertions``
and ``src/iltero_schemas/vectors/assertions``, the AST as JSON, its source
digest, and the compiled Rego module with its digest; ``COMPILER_VERSION``
and ``RUNTIME.digest`` (the digest of ``runtime.rego``) record what produced
them. Canonical vectors: the canonical bytes and digest of each value in
``src/iltero_schemas/vectors/canonical/values.json``, of each plan in
``canonical/iac/plan_values.json``, and of every case of the assertion-set and
change digests, from the inputs each case names; the keyed given file digest of each
plain digest of ``canonical/given_file_digest_cases.json`` under the vector key, or
why it is refused. Document vectors: the digest
of every scanner check mapping under ``vectors/scanner_check_mappings``, every context under
``vectors/contexts``, every event under ``vectors/events``, every identity
document under ``vectors/identities``, every record under ``vectors/records``,
every verification report under ``vectors/reports`` and every set of scanner
observations under ``vectors/scanner_observations``, each validated against
its model first. Redaction vectors: the built-in redaction policy, what
redaction and its check give for each case of ``vectors/redaction`` and
``vectors/redaction_problems``, and the redacted state and its digest for each
state of ``redaction/iac/state_inputs.json``, inline or under ``raw_states``.
Re-plan vectors: what ``replan_differences`` gives for each case of
``replan_differences/iac/inputs.json``.
Each document folder but ``identities`` keeps its documents in the ``iac/`` or
``image/`` subfolder of their change type; the folder's one ``digests.json`` names each
document by its path from the folder. A ``digests.json`` this script does not
write is reported.

A changed runtime changes ``RUNTIME.digest``; review the diff of the vectors
as carefully as the code.

Usage: python scripts/refresh_vectors.py [--check]
"""

from __future__ import annotations

import json
import sys
from collections.abc import Collection
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from iltero_schemas.ast import parse, source_digest, to_json
from iltero_schemas.canonical import (
    KEYED_PLAN_DIGEST_VERSIONS,
    REDACTED_PLAN_DIGEST_VERSIONS,
    CanonicalizationError,
    canonical_assertion_set_bytes,
    canonical_bytes,
    canonical_change_bytes,
    canonical_plan_bytes,
    canonical_redacted_state_bytes,
    digest,
    digest_of,
    keyed_given_file_digest,
    keyed_plan_digest,
    redacted_plan_digest_of_kept,
)
from iltero_schemas.compiler import COMPILER_VERSION, RUNTIME_REGO, compile
from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.common.context import AssuranceContext
from iltero_schemas.models.common.event import AssuranceEvent
from iltero_schemas.models.common.redaction import RedactionPolicyDocument
from iltero_schemas.models.common.served_exceptions import ServedExceptions
from iltero_schemas.models.common.verification import VerificationReport
from iltero_schemas.models.iac.resource_identities import ResourceIdentities
from iltero_schemas.models.iac.scanner_check_mapping import ScannerCheckMapping
from iltero_schemas.models.iac.scanner_check_mapping_descriptor import ScannerCheckMappingDescriptor
from iltero_schemas.models.iac.scanner_observations import ScannerObservations
from iltero_schemas.redaction.common.apply import RedactionError, redact
from iltero_schemas.redaction.common.marks import Mark
from iltero_schemas.redaction.common.policy import BUILT_IN_REDACTION_POLICY, RedactionPolicy, policy_from_document
from iltero_schemas.redaction.common.problems import redaction_problems
from iltero_schemas.redaction.common.value_change import OBSERVATION_SUBJECT
from iltero_schemas.redaction.iac.plan import redact_plan, redacted_plan_digest
from iltero_schemas.redaction.iac.replan import replan_differences
from iltero_schemas.redaction.iac.sent_documents import document_marks_and_anchors
from iltero_schemas.redaction.iac.state import STATE_MARK_READERS, redact_state, redacted_state_digest
from iltero_schemas.vectors.plans import plan_of
from iltero_schemas.vectors.run_digest_key import vector_run_digest_key

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "src" / "iltero_schemas"
VECTORS = PACKAGE / "vectors"
ASSERTION_DIRS = [PACKAGE / "assertions", VECTORS / "assertions"]
COMPILER_VECTORS = VECTORS / "compiler"
CANONICAL_VECTORS = VECTORS / "canonical"
REDACTION_VECTORS = VECTORS / "redaction"
REDACTION_PROBLEM_VECTORS = VECTORS / "redaction_problems"
RAW_STATES = VECTORS / "raw_states"
REPLAN_VECTORS = VECTORS / "replan_differences" / "iac"
# Each folder holds one kind of document, and one digests.json that lists them all.
DOCUMENT_VECTORS: dict[Path, type[BaseModel]] = {
    VECTORS / "scanner_check_mappings": ScannerCheckMapping,
    VECTORS / "scanner_check_mapping_descriptors": ScannerCheckMappingDescriptor,
    VECTORS / "contexts": AssuranceContext,
    VECTORS / "events": AssuranceEvent,
    VECTORS / "identities": ResourceIdentities,
    VECTORS / "records": CAR,
    VECTORS / "reports": VerificationReport,
    VECTORS / "scanner_observations": ScannerObservations,
    VECTORS / "served_exceptions": ServedExceptions,
}


def _dump(document: object) -> bytes:
    return json.dumps(document, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"


def compiler_vectors() -> dict[str, bytes]:
    files: dict[str, bytes] = {
        "COMPILER_VERSION": f"{COMPILER_VERSION}\n".encode(),
        "RUNTIME.digest": f"{digest(RUNTIME_REGO.encode('utf-8'))}\n".encode(),
    }
    for directory in ASSERTION_DIRS:
        for path in sorted(directory.glob("*.yaml")):
            assertion = parse(path.read_text(encoding="utf-8"))
            module = compile(assertion)
            stem = path.stem
            files[f"{stem}.ast.json"] = json.dumps(to_json(assertion), indent=2, sort_keys=True).encode() + b"\n"
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
    plans = json.loads((CANONICAL_VECTORS / "iac" / "plan_values.json").read_text(encoding="utf-8"))
    plan_cases = [
        {
            "name": name,
            "description": entry["description"],
            "tool": entry["tool"],
            "plan": entry["plan"],
            "canonical": canonical_plan_bytes(entry["tool"], entry["plan"]).decode("utf-8"),
            "keyed_version": KEYED_PLAN_DIGEST_VERSIONS[entry["tool"]],
            "keyed_digest": keyed_plan_digest(entry["tool"], entry["plan"], vector_run_digest_key()),
            "redacted_version": REDACTED_PLAN_DIGEST_VERSIONS[entry["tool"]],
            "redacted_digest": redacted_plan_digest_of_kept(entry["tool"], entry["plan"]),
        }
        for name, entry in plans.items()
    ]
    document = {"cases": plan_cases}
    sets = json.loads((CANONICAL_VECTORS / "assertion_set_cases.json").read_text(encoding="utf-8"))
    for case in sets["cases"]:
        encoded = canonical_assertion_set_bytes(tuple(triple) for triple in case["assertions"])
        case.update({"canonical": encoded.decode("utf-8"), "digest": digest(encoded)})
    changes = json.loads((CANONICAL_VECTORS / "change_digest_cases.json").read_text(encoding="utf-8"))
    for case in changes["cases"]:
        encoded = canonical_change_bytes(
            case["change_type"], case["unit"], case["environment_key"], case["checked_content"]
        )
        case.update({"canonical": encoded.decode("utf-8"), "digest": digest(encoded)})
    given_files = json.loads((CANONICAL_VECTORS / "given_file_digest_cases.json").read_text(encoding="utf-8"))
    for case in given_files["cases"]:
        case.pop("keyed_digest", None)
        case.pop("refused", None)
        try:
            case["keyed_digest"] = keyed_given_file_digest(case["plain_digest"], vector_run_digest_key())
        except ValueError as error:
            case["refused"] = str(error)
    return {
        "cases.json": _dump(cases),
        "iac/plan_digest_cases.json": _dump(document),
        "given_file_digest_cases.json": _dump(given_files),
        "assertion_set_cases.json": _dump(sets),
        "change_digest_cases.json": _dump(changes),
    }


def _redacted(
    case: dict[str, Any], tree: Any, marks: list[Mark], anchors: list[Any], *, subject: str = "vector"
) -> dict[str, Any]:
    """What ``redact`` gives for a case: the redacted tree and its report's lists, or the refusal."""
    policy = policy_of(case)
    try:
        result = redact(
            tree,
            marks,
            policy,
            subject=subject,
            anchors=[tuple(anchor) for anchor in anchors],
            known_sensitive=case.get("known_sensitive", []),
        )
    except RedactionError as error:
        return {"refused": str(error)}
    report = result.report
    return {
        "redacted": result.tree,
        "report": {key: getattr(report, key) for key in ("redacted", "unknown", "exempted")},
    }


def policy_of(case: dict[str, Any]) -> RedactionPolicy:
    """The redaction policy a case writes out."""
    return policy_from_document(RedactionPolicyDocument.model_validate(case["policy"]))


def _marks(written: list[dict[str, Any]]) -> list[Mark]:
    return [Mark(tuple(mark["path"]), mark["reason"], mark["declared_sensitive"]) for mark in written]


def _written_marks(marks: list[Mark]) -> list[dict[str, Any]]:
    return [
        {"path": list(mark.path), "reason": mark.reason, "declared_sensitive": mark.declared_sensitive}
        for mark in marks
    ]


def state_of(case: dict[str, Any]) -> Any:
    """The state a case of ``redaction/iac/state_inputs.json`` names: written in the case, or a captured file of
    ``raw_states/iac``, whole or under one of its top-level keys (a refresh-only plan's ``prior_state``)."""
    if "state" in case:
        return case["state"]
    named = case["raw_state"]
    document = json.loads((RAW_STATES / "iac" / named["file"]).read_text(encoding="utf-8"))
    return document if named["under"] is None else document[named["under"]]


def state_cases() -> list[dict[str, Any]]:
    """For each state of ``redaction/iac/state_inputs.json``: its marks and anchors, the state as the case's policy
    leaves it, the bytes its digest is taken of and the digest, or why the state is refused."""
    cases: list[dict[str, Any]] = json.loads(
        (REDACTION_VECTORS / "iac" / "state_inputs.json").read_text(encoding="utf-8")
    )["cases"]
    for case in cases:
        tool, tree, policy = case["tool"], state_of(case), policy_of(case)
        try:
            marks, anchors = STATE_MARK_READERS[tool](tree)
            kept = redact_state(tool, tree, policy).tree
        except (RedactionError, CanonicalizationError) as error:
            case["refused"] = str(error)
            continue
        case["marks"] = _written_marks(marks)
        case["anchors"] = [list(anchor) for anchor in anchors]
        case["kept_state"] = kept
        case["canonical"] = canonical_redacted_state_bytes(tool, kept).decode("utf-8")
        case["redacted_state_digest"] = redacted_state_digest(tool, tree, policy)
    return cases


def redaction_vectors() -> dict[Path, bytes]:
    """The built-in redaction policy, what ``redact`` gives for each case of ``redaction/inputs.json``, the marks,
    anchors and redacted plan for each plan of ``redaction/iac/plan_inputs.json``, and what ``redaction_problems`` finds
    in each document of ``redaction_problems/inputs.json``."""
    written_policy = {
        "document": BUILT_IN_REDACTION_POLICY.document().model_dump(mode="json"),
        "canonical": canonical_bytes(BUILT_IN_REDACTION_POLICY.as_dict()).decode("utf-8"),
        "digest": BUILT_IN_REDACTION_POLICY.digest,
    }
    cases = json.loads((REDACTION_VECTORS / "inputs.json").read_text(encoding="utf-8"))["cases"]
    for case in cases:
        case.update(_redacted(case, case["tree"], _marks(case["marks"]), case["anchors"]))
    plans = json.loads((REDACTION_VECTORS / "iac" / "plan_inputs.json").read_text(encoding="utf-8"))["cases"]
    for case in plans:
        try:
            # The plan as a record keeps it, every copy of a sensitive string hidden too; or why it is refused.
            kept = redact_plan(case["tool"], case["plan"], policy_of(case))
        except RedactionError as error:
            case["refused"] = str(error)
            continue
        marks, anchors = document_marks_and_anchors("redacted_plan", case["tool"], case["plan"])
        case["marks"] = _written_marks(marks)
        case["anchors"] = [list(anchor) for anchor in anchors]
        case.update(_redacted(case, case["plan"], marks, case["anchors"]))
        if "refused" not in case:
            # Its digest in a run the tool opened.
            case["kept_plan"] = kept.tree
            case["redacted_plan_digest"] = redacted_plan_digest(case["tool"], case["plan"], policy_of(case))
    observed = json.loads((REDACTION_VECTORS / "iac" / "observation_inputs.json").read_text(encoding="utf-8"))["cases"]
    for case in observed:
        # What a plan stage observed, redacted as its record's report names it, value changes included.
        case.update(_redacted(case, case["tree"], _marks(case["marks"]), case["anchors"], subject=OBSERVATION_SUBJECT))
    problems = json.loads((REDACTION_PROBLEM_VECTORS / "inputs.json").read_text(encoding="utf-8"))["cases"]
    for case in problems:
        marks, anchors = document_marks_and_anchors(case["document_name"], case["tool"], case["document"])
        policy = policy_from_document(RedactionPolicyDocument.model_validate(case["policy"]))
        found = redaction_problems(policy, case["document"], marks=marks, anchors=anchors)
        case["problems"] = [
            {"path": list(problem.path), "at": problem.at, "rule": problem.rule} for problem in found.problems
        ]
        case["count"] = found.count
    return {
        REDACTION_VECTORS / "policy.json": _dump(written_policy),
        REDACTION_VECTORS / "cases.json": _dump({"cases": cases}),
        REDACTION_VECTORS / "iac" / "plan_cases.json": _dump({"cases": plans}),
        REDACTION_VECTORS / "iac" / "observation_cases.json": _dump({"cases": observed}),
        REDACTION_VECTORS / "iac" / "state_cases.json": _dump({"cases": state_cases()}),
        REDACTION_PROBLEM_VECTORS / "cases.json": _dump({"cases": problems}),
    }


def replan_vectors() -> dict[Path, bytes]:
    """What ``replan_differences`` gives for each case of ``replan_differences/iac/inputs.json``, or why it refuses."""
    cases: list[dict[str, Any]] = json.loads((REPLAN_VECTORS / "inputs.json").read_text(encoding="utf-8"))["cases"]
    for case in cases:
        try:
            found = replan_differences(
                case["tool"], plan_of(case["evaluated_plan"]), plan_of(case["replan"]), policy_of(case)
            )
        except ValueError as error:
            case["refused"] = str(error)
            continue
        case["evaluated_plan_resources"] = found.evaluated_plan_resources
        case["replan_resources"] = found.replan_resources
        case["differences"] = [difference.model_dump(mode="json", by_alias=True) for difference in found.differences]
        case["evaluated_plan_timestamp"] = found.evaluated_plan_timestamp
        case["replan_timestamp"] = found.replan_timestamp
    return {REPLAN_VECTORS / "cases.json": _dump({"cases": cases})}


def document_files(folder: Path) -> list[Path]:
    """Every document under ``folder`` other than its digests.json files, sorted by its path from the folder; a
    hidden file or folder (a name that starts with a dot), such as a copy an editor or macOS left there, is not a
    vector."""
    return sorted(
        (
            path
            for path in folder.rglob("*.json")
            if path.name != "digests.json" and not any(part.startswith(".") for part in path.relative_to(folder).parts)
        ),
        key=lambda path: path.relative_to(folder).as_posix(),
    )


def document_vectors() -> dict[Path, bytes]:
    """The digest of every document vector, each validated against its model first."""
    expected = {}
    for folder, model in DOCUMENT_VECTORS.items():
        # Each document by its path from the folder, the name a case gives it.
        digests = {}
        for path in document_files(folder):
            document = json.loads(path.read_text(encoding="utf-8"))
            model.model_validate(document)
            digests[path.relative_to(folder).as_posix()] = digest_of(document)
        expected[folder / "digests.json"] = json.dumps(digests, indent=2).encode("utf-8") + b"\n"
    return expected


def unwritten_digests(vectors: Path, written: Collection[Path]) -> list[Path]:
    """Every digests.json under ``vectors`` that is not in ``written``: nothing would check it."""
    return sorted(set(vectors.rglob("digests.json")) - set(written))


def main(argv: list[str]) -> int:
    check = argv[1:] == ["--check"]
    if argv[1:] and not check:
        print(__doc__, file=sys.stderr)
        return 2
    expected = {COMPILER_VECTORS / name: data for name, data in compiler_vectors().items()}
    expected.update({CANONICAL_VECTORS / name: data for name, data in canonical_vectors().items()})
    expected.update(document_vectors())
    expected.update(redaction_vectors())
    expected.update(replan_vectors())
    unwritten = unwritten_digests(VECTORS, expected)
    for path in unwritten:
        print(f"not written by this script: {path.relative_to(ROOT)}", file=sys.stderr)
    stale = [path for path, data in expected.items() if not path.exists() or path.read_bytes() != data]
    if check:
        for path in stale:
            print(f"out of date: {path.relative_to(ROOT)}", file=sys.stderr)
        return 1 if stale or unwritten else 0
    for path in stale:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(expected[path])
        print(f"wrote {path.relative_to(ROOT)}")
    return 1 if unwritten else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
