"""The conformance vectors are reproduced by this implementation.

A consumer that reproduces these files is conformant: canonical bytes and
digests, the AST and digest of every assertion, the compiled module bytes,
and the rejection path of every invalid document. The evaluation vectors run
each compiled module under the pinned evaluator with the capabilities
allowlist and compare the result.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from iltero_schemas.ast import AssertionSyntaxError, parse, source_digest, to_json
from iltero_schemas.ast.parse import parse_document
from iltero_schemas.canonical import (
    PLAN_DIGEST_VERSION,
    canonical_bytes,
    canonical_plan_bytes,
    digest,
    digest_of,
    plan_digest,
)
from iltero_schemas.compiler import COMPILER_VERSION, RUNTIME, compile, package_of
from iltero_schemas.models.context import AssuranceContext
from iltero_schemas.models.event import AssuranceEvent
from iltero_schemas.opa import CAPABILITIES
from iltero_schemas.vectors import VECTORS as PACKAGED_VECTORS
from tests.conftest import STARTER_ASSERTIONS, VECTORS

COMPILER = VECTORS / "compiler"
ASSERTION_FILES = sorted(STARTER_ASSERTIONS.glob("*.yaml")) + sorted((VECTORS / "assertions").glob("*.yaml"))
CANONICAL_CASES = json.loads((VECTORS / "canonical" / "cases.json").read_text(encoding="utf-8"))
PLAN_DIGEST_DOCUMENT = json.loads((VECTORS / "canonical" / "plan_digest_cases.json").read_text(encoding="utf-8"))
EVALUATION_CASES = json.loads((VECTORS / "evaluation" / "cases.json").read_text(encoding="utf-8"))
INVALID_EXPECTED = json.loads((VECTORS / "invalid" / "expected.json").read_text(encoding="utf-8"))
DOCUMENT_VECTORS: dict[str, type[BaseModel]] = {"contexts": AssuranceContext, "events": AssuranceEvent}
DOCUMENT_FILES = sorted(
    (folder, path.name)
    for folder in DOCUMENT_VECTORS
    for path in (VECTORS / folder).glob("*.json")
    if path.name != "digests.json"
)
# The three state assertions of the plan-stage scenario the context vector describes.
CONTEXT_SCENARIO = ("ILT.AWS.RDS.STORAGE_ENCRYPTED", "ILT.AWS.RDS.NOT_PUBLIC", "ILT.AWS.RDS.BACKUP_RETENTION")


def _name(path: Path) -> str:
    return path.stem


@pytest.mark.parametrize("case", CANONICAL_CASES, ids=[c["name"] for c in CANONICAL_CASES])
def test_canonical_vector_is_reproduced(case: dict[str, Any]) -> None:
    encoded = canonical_bytes(case["value"])
    assert encoded.decode("utf-8") == case["canonical"]
    assert digest(encoded) == case["digest"]


@pytest.mark.parametrize("case", PLAN_DIGEST_DOCUMENT["cases"], ids=[c["name"] for c in PLAN_DIGEST_DOCUMENT["cases"]])
def test_plan_digest_vector_is_reproduced(case: dict[str, Any]) -> None:
    assert canonical_plan_bytes(case["plan"]).decode("utf-8") == case["canonical"]
    assert plan_digest(case["plan"]) == case["digest"]


def test_plan_digest_vectors_record_the_current_version() -> None:
    assert PLAN_DIGEST_DOCUMENT["version"] == PLAN_DIGEST_VERSION


def test_compiler_vectors_record_the_compiler_version_and_runtime_digest() -> None:
    assert (COMPILER / "COMPILER_VERSION").read_text(encoding="utf-8") == f"{COMPILER_VERSION}\n"
    assert (COMPILER / "RUNTIME.digest").read_text(encoding="utf-8") == f"{digest(RUNTIME.encode('utf-8'))}\n"


def test_the_vectors_ship_inside_the_package() -> None:
    assert PACKAGED_VECTORS.joinpath("compiler", "COMPILER_VERSION").is_file()
    assert PACKAGED_VECTORS.joinpath("evaluation", "cases.json").is_file()


@pytest.mark.parametrize("path", ASSERTION_FILES, ids=_name)
def test_ast_and_source_digest_are_reproduced(path: Path) -> None:
    assertion = parse(path.read_text(encoding="utf-8"))
    expected = json.loads((COMPILER / f"{path.stem}.ast.json").read_text(encoding="utf-8"))
    assert to_json(assertion) == expected
    assert source_digest(assertion) == (COMPILER / f"{path.stem}.digest").read_text(encoding="utf-8").strip()


@pytest.mark.parametrize("path", ASSERTION_FILES, ids=_name)
def test_compiled_module_is_byte_identical(path: Path) -> None:
    module = compile(parse(path.read_text(encoding="utf-8")))
    assert module.source == (COMPILER / f"{path.stem}.rego").read_bytes()
    assert module.digest == (COMPILER / f"{path.stem}.rego.digest").read_text(encoding="utf-8").strip()
    assert module.assertion_id == path.stem
    assert module.package == package_of(path.stem)


def test_every_compiled_vector_has_its_source_and_nothing_else() -> None:
    stems = {p.stem for p in ASSERTION_FILES}
    generated = {p.name for p in COMPILER.iterdir()} - {"COMPILER_VERSION", "RUNTIME.digest"}
    assert generated == {f"{s}{suffix}" for s in stems for suffix in (".ast.json", ".digest", ".rego", ".rego.digest")}


@pytest.mark.parametrize("name", sorted(INVALID_EXPECTED), ids=str)
def test_invalid_document_is_rejected_at_the_expected_path(name: str) -> None:
    text = (VECTORS / "invalid" / f"{name}.yaml").read_text(encoding="utf-8")
    with pytest.raises(AssertionSyntaxError) as raised:
        parse(text)
    assert raised.value.issues[0].path == INVALID_EXPECTED[name]["path"]
    assert INVALID_EXPECTED[name]["message"] in raised.value.issues[0].message


def test_every_invalid_document_is_listed() -> None:
    assert {p.stem for p in (VECTORS / "invalid").glob("*.yaml")} == set(INVALID_EXPECTED)


@pytest.mark.parametrize(("folder", "name"), DOCUMENT_FILES, ids=str)
def test_document_vector_validates_and_its_digest_is_reproduced(folder: str, name: str) -> None:
    document = json.loads((VECTORS / folder / name).read_text(encoding="utf-8"))
    DOCUMENT_VECTORS[folder].model_validate(document)
    digests = json.loads((VECTORS / folder / "digests.json").read_text(encoding="utf-8"))
    assert digest_of(document) == digests[name]


def test_every_document_vector_has_its_digest_and_nothing_else() -> None:
    for folder in DOCUMENT_VECTORS:
        digests = json.loads((VECTORS / folder / "digests.json").read_text(encoding="utf-8"))
        assert {name for f, name in DOCUMENT_FILES if f == folder} == set(digests)


# --- under the pinned evaluator ---------------------------------------------


@pytest.fixture(scope="module")
def capabilities(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("opa") / "capabilities.json"
    path.write_bytes(CAPABILITIES)
    return path


def _run(opa: Path, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(opa), *args], input=stdin, capture_output=True, text=True, check=False, timeout=60)


@pytest.mark.parametrize("path", ASSERTION_FILES, ids=_name)
def test_compiled_module_checks_under_the_capabilities_and_is_fmt_stable(
    opa: Path, capabilities: Path, path: Path
) -> None:
    module = COMPILER / f"{path.stem}.rego"
    checked = _run(opa, "check", "--strict", "--capabilities", str(capabilities), str(module))
    assert checked.returncode == 0, checked.stderr
    formatted = _run(opa, "fmt", "--diff", str(module))
    assert formatted.returncode == 0 and formatted.stdout == "", formatted.stdout


def _build(opa: Path, capabilities: Path, directory: Path) -> subprocess.CompletedProcess[str]:
    return _run(
        opa, "build", "--capabilities", str(capabilities), "-b", str(directory), "-o", str(directory / "b.tar.gz")
    )


def test_all_compiled_modules_build_into_one_bundle(opa: Path, capabilities: Path, tmp_path: Path) -> None:
    for path in ASSERTION_FILES:
        (tmp_path / f"{path.stem}.rego").write_bytes((COMPILER / f"{path.stem}.rego").read_bytes())
    built = _build(opa, capabilities, tmp_path)
    assert built.returncode == 0, built.stderr


def test_an_id_that_prefixes_another_still_bundles(opa: Path, capabilities: Path, tmp_path: Path) -> None:
    for assertion_id in ("ACME.RDS", "ACME.RDS.STATUS", "ACME.RDS.STATUS.EVALUATE"):
        document = {
            "apiVersion": "iltero.io/v1",
            "kind": "TechnicalAssertion",
            "metadata": {"id": assertion_id, "version": "1.0.0", "title": "t"},
            "spec": {
                "stage": "plan",
                "target": {"kind": "resource", "provider": "aws", "resource_types": ["aws_db_instance"]},
                "assert": {"path": "resource.after.x", "equal": 1},
            },
        }
        (tmp_path / f"{assertion_id}.rego").write_bytes(compile(parse_document(document)).source)
    built = _build(opa, capabilities, tmp_path)
    assert built.returncode == 0, built.stderr


@pytest.mark.parametrize(
    "policy",
    [
        "http.send({})",
        "time.now_ns()",
        'regex.match("a", "a")',
        "opa.runtime()",
        'rand.intn("a", 2)',
        'net.lookup_ip_addr("a")',
        'io.jwt.decode("a")',
    ],
)
def test_forbidden_builtin_is_refused_by_the_capabilities(
    opa: Path, capabilities: Path, tmp_path: Path, policy: str
) -> None:
    module = tmp_path / "policy.rego"
    module.write_text(f"package x\n\nr := {policy}\n", encoding="utf-8")
    checked = _run(opa, "check", "--capabilities", str(capabilities), str(module))
    assert checked.returncode != 0 and "undefined function" in checked.stderr


@pytest.mark.parametrize("case", EVALUATION_CASES, ids=[c["name"] for c in EVALUATION_CASES])
def test_evaluation_vector_is_reproduced(opa: Path, capabilities: Path, case: dict[str, Any]) -> None:
    module = COMPILER / f"{case['assertion']}.rego"
    query = f"data.{package_of(case['assertion'])}.evaluate"
    evaluated = _run(
        opa,
        "eval",
        "--format",
        "json",
        "--strict-builtin-errors",
        "--capabilities",
        str(capabilities),
        "--data",
        str(module),
        "--stdin-input",
        query,
        stdin=json.dumps(case["input"]),
    )
    assert evaluated.returncode == 0, evaluated.stderr
    results = json.loads(evaluated.stdout)["result"][0]["expressions"][0]["value"]
    assert len(results) == 1
    result = results[0]
    expected = case["expected"]
    default_subject = case["input"].get("subject") if isinstance(case["input"], dict) else None
    assert result["subject"] == expected.get("subject", default_subject)
    assert result["status"] == expected["status"]
    assert result["reason"] == expected["reason"]
    assert result["observations"]["unknown"] == expected["unknown"]
    assert result["observations"]["when"] == expected["when"]
    if "predicates" in expected:
        assert result["observations"]["predicates"] == expected["predicates"]


@pytest.mark.parametrize("assertion_id", CONTEXT_SCENARIO)
def test_the_scenario_assertions_pass_on_the_context_vector(opa: Path, capabilities: Path, assertion_id: str) -> None:
    context = json.loads((VECTORS / "contexts" / "plan_resource.json").read_text(encoding="utf-8"))
    context["evaluation"]["assertion"]["id"] = assertion_id
    evaluated = _run(
        opa,
        "eval",
        "--format",
        "json",
        "--strict-builtin-errors",
        "--capabilities",
        str(capabilities),
        "--data",
        str(COMPILER / f"{assertion_id}.rego"),
        "--stdin-input",
        f"data.{package_of(assertion_id)}.evaluate",
        stdin=json.dumps(context),
    )
    assert evaluated.returncode == 0, evaluated.stderr
    result = json.loads(evaluated.stdout)["result"][0]["expressions"][0]["value"][0]
    assert result["status"] == "pass"
    assert result["subject"] == {"kind": "resource", "id": "aws_db_instance.payments"}


@pytest.mark.parametrize(
    ("applied", "status"),
    [({}, "pass"), ({"digest": "sha256:" + "b" * 64}, "fail")],
    ids=["the evaluated plan", "another plan"],
)
def test_plan_binding_decides_on_the_post_deploy_vector(
    opa: Path, capabilities: Path, applied: dict[str, str], status: str
) -> None:
    context = json.loads((VECTORS / "contexts" / "post_deploy.json").read_text(encoding="utf-8"))
    context["deployment"]["plan"].update(applied)
    evaluated = _run(
        opa,
        "eval",
        "--format",
        "json",
        "--strict-builtin-errors",
        "--capabilities",
        str(capabilities),
        "--data",
        str(COMPILER / "ILT.DEPLOYMENT.PLAN_BINDING.rego"),
        "--stdin-input",
        f"data.{package_of('ILT.DEPLOYMENT.PLAN_BINDING')}.evaluate",
        stdin=json.dumps(context),
    )
    assert evaluated.returncode == 0, evaluated.stderr
    result = json.loads(evaluated.stdout)["result"][0]["expressions"][0]["value"][0]
    assert result["status"] == status
    assert result["subject"] == {"kind": "deployment", "id": "root"}


_READS_THE_SUMMARY = """\
apiVersion: iltero.io/v1
kind: TechnicalAssertion
metadata:
  id: ACME.DEPLOYMENT.ONE_CHANGE
  version: "1.0.0"
  title: The apply changed one resource
spec:
  stage: post_deploy
  target:
    kind: deployment
  assert:
    path: deployment.apply.summary.changed
    equal: 1
"""


def _evaluate_post_deploy(opa: Path, capabilities: Path, module: Path, package: str, context: dict[str, Any]) -> Any:
    evaluated = _run(
        opa,
        "eval",
        "--format",
        "json",
        "--strict-builtin-errors",
        "--capabilities",
        str(capabilities),
        "--data",
        str(module),
        "--stdin-input",
        f"data.{package}.evaluate",
        stdin=json.dumps(context),
    )
    assert evaluated.returncode == 0, evaluated.stderr
    return json.loads(evaluated.stdout)["result"][0]["expressions"][0]["value"][0]


def test_a_fact_the_apply_log_lost_is_unknown_to_a_check_that_reads_it_and_nothing_to_one_that_does_not(
    opa: Path, capabilities: Path, tmp_path: Path
) -> None:
    context = json.loads((VECTORS / "contexts" / "post_deploy.json").read_text(encoding="utf-8"))
    context["deployment"]["apply"]["summary"] = {"__unknown": True, "reason": "apply_log_incomplete"}
    module = compile(parse(_READS_THE_SUMMARY))
    path = tmp_path / "one_change.rego"
    path.write_bytes(module.source)
    reads = _evaluate_post_deploy(opa, capabilities, path, module.package, context)
    assert reads["status"] == "unknown" and "apply_log_incomplete" in json.dumps(reads)
    binding = COMPILER / "ILT.DEPLOYMENT.PLAN_BINDING.rego"
    ignores = _evaluate_post_deploy(opa, capabilities, binding, package_of("ILT.DEPLOYMENT.PLAN_BINDING"), context)
    assert ignores["status"] == "pass"
