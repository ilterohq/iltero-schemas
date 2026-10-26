# Conformance vectors

A conformance vector is a known input with the exact output an implementation of the contract must produce. The
vectors ship inside the package, under `src/iltero_schemas/vectors/`, and are available at run time as
`iltero_schemas.vectors.VECTORS`. A consumer that reproduces every vector of the version it pins is conformant. A
consumer that fails one must fail its build.

## Vector folders

| Folder | Contents | What a consumer reproduces |
| --- | --- | --- |
| `canonical/` | `values.json` and `cases.json`: sample values with their canonical bytes and digests. `plan_values.json`: sample plans, each with its IaC tool. `plan_digest_cases.json`: the same plans with the version of their tool's rule, their canonical bytes and their plan digest. `assertion_set_cases.json` and `change_digest_cases.json`: inputs to the assertion-set digest and the change digest, with the canonical bytes and digest of each. | The canonical bytes and every digest. |
| `assertions/` | Assertions written to exercise the language: truth tables, every comparison, nesting and edge-case literals. | Parsing each one. |
| `compiler/` | For every shipped assertion and every vector assertion: the abstract syntax tree (`.ast.json`), its source digest (`.digest`), the compiled Rego program (`.rego`) and the program's digest (`.rego.digest`). Also `COMPILER_VERSION` and `RUNTIME.digest`, the digest of the shared runtime every program embeds. | The AST, the source digest, the compiled bytes and the program digest. |
| `assertions_invalid/` | Assertions that must be refused. `expected.json` names, for each, the key and message of the first problem. | The refusal, at the same key. |
| `contexts/` | One complete assurance context per profile: `plan_resource.json`, `pre_deploy_change.json` and `post_deploy.json`; and `pre_deploy_approvals.json`, the pre-deploy input `evaluation/approvals.json` varies. `digests.json` gives each one's `input_digest`. | Validation, and each document digest. |
| `events/` | `plan_pass.json`, a complete assurance event, and `digests.json`. | Validation and the document digest. |
| `reports/` | `verification_report.json`, a complete verification report, and `digests.json`. | Validation and the document digest. |
| `identities/` | `identity_bindings.json`, an identity bindings document with no bindings (only resources left unresolved), and `digests.json`. | Validation and the document digest. |
| `identities_invalid/` | `cases.json`: identity documents that must be refused, in the same form as `records_invalid/`, each naming an `identities/` document. | The refusal. |
| `identities_valid/` | `cases.json`: changed identity documents that must still be accepted, in the same form as `records_valid/`, such as a document read without an applied plan. | Acceptance. |
| `records/` | Complete CARs, with `digests.json`: `local_run.json`, of a run the tool opened on its own, whose evaluations are of starter assertions (`contract_starter`) and whose evaluation of the production assertion is `unknown`, since nothing from Iltero Platform says whether its environment is production; `local_run_declared_units.json`, the same record of a project that declares its units in a units file; `local_run_on_placeholders.json`, a plan stage that read a placeholder for upstream state, so it is incomplete, whose evaluations pass except the production one, which is `unknown` in a run the tool opened. | Validation and each document digest. |
| `records_invalid/` | `cases.json`: records that must be refused. Each case names a `records/` document, the values to change (`set`) and remove (`remove`) by JSON Pointer, and the expected message: one line that the refusal's text contains. | The refusal. |
| `records_integrity_failed/` | `cases.json`: records whose recomputable values were edited, in the same form as `records_invalid/` with `problems`, a list of `[where, what]` pairs, in place of a message: a forged change digest, the same with a pre-deploy stage bound to it, an approval of another change, an edited plan verdict, and a forged change digest with an edited plan verdict, whose change digest problem comes first. | Read with `SKIP_INTEGRITY_CHECKS` set to `True`, `integrity_problems` returns exactly `problems`; read without it, the record is refused with the first one. |
| `records_valid/` | `cases.json`: changed records that must still be accepted, in the same form without a message: a plan stage that read a placeholder for upstream state, a stage whose gate was advisory, a record of a run Iltero Platform opened, which is self-attested like any other, and a plan whose tool did not report its flags, with a plan-flag gap for each and its stage incomplete. Two cases pin the order of an incomplete stage's reasons: a plan that is not complete on placeholders names the plan, and an evaluator error on such a plan names the error. | Acceptance. |
| `subjects/` | `keys.json`: a subject's `kind` and `identities`, and the key `iltero_schemas.models.subjects.subject_key` gives it: a resource an IaC tool manages, one in a module with a non-ASCII key, the same address with that key's "é" decomposed (`e` followed by U+0301), which has another key, the same address in another unit, a resource only the cloud knows (`scheme: aws_arn`), and a unit's change and deployment. A cloud identity is written as `value_parts` in place of `value`: its value is the parts joined by `:`, so this repository publishes no real-format cloud identifier. | The key, after joining `value_parts`. |
| `evaluation/` | `cases.json`: an assertion, an input (whose subject `key` is opaque to the evaluator, not a computed key), and the expected `status`, `reason`, `unknown`, `when` and, for some cases, `predicates`. Cases include how a `null` leaf, a path through a `null` part, a `null` collection and the `not_reported_by_tool` marker evaluate, and `ILT.DEPLOYMENT.PLAN_BINDING` with neither or only one artifact digest. `facts_unknown.json`: the approval assertions over `contexts/pre_deploy_change.json`, with the facts as unknown markers and as empty lists. `approvals.json`: the approval assertions over `contexts/pre_deploy_approvals.json` with approvals of the change and of the run, of another change or run, a self-approval, none, and unavailable approvals; each case names the status of every `exists` of the assert (`branches`). | The OPA result for each case. |
| `opa/` | `not_allowed.txt`: every built-in function of the pinned OPA release that the capabilities allowlist leaves out. | The allowlist of the pinned release. |

The identity vectors hold no binding, because a binding names a real-format cloud identifier, which this repository
does not publish. So these rules of an identity document have no vector: no two entries of `bindings`, or of
`removed`, name the same cloud identity; a resource is bound or unresolved, never both; only a resource type verified
for its provider's resolver is bound; every binding belongs to the unit and names the tool that wrote the state; an
identifier names a resource of its stated type. A conformant consumer enforces them all; the validating model
`iltero_schemas.models.identity.IdentityBindings` is the reference.

Every document digest is the SHA-256 of the document's RFC 8785 canonical JSON, written `sha256:<hex>`. The
`iltero_schemas.canonical` module computes it with `digest_of`, and the canonical bytes with `canonical_bytes`.
Each document vector is written as its validating model dumps it: every optional field present, `null` when it has
no value. A consumer whose writer produces that form reproduces the vector's bytes and digest.

## The pinned OPA release

Every consumer evaluates with the one Open Policy Agent (OPA) release the package pins.
`iltero_schemas.opa.OPA_RELEASE_PIN` holds the release (`version`, `release_tag`) and the SHA-256 of its binary for
each platform.

| Platform key | Release file |
| --- | --- |
| `linux-x86_64` | `opa_linux_amd64_static` |
| `linux-aarch64` | `opa_linux_arm64_static` |
| `darwin-x86_64` | `opa_darwin_amd64` |
| `darwin-aarch64` | `opa_darwin_arm64_static` |
| `windows-x86_64` | `opa_windows_amd64.exe` |

Before every run, a consumer computes the SHA-256 of the binary and compares it with the pinned digest for its
platform. It refuses to run a binary whose digest differs.

```python
import platform

from iltero_schemas.opa import OPA_RELEASE_PIN, platform_key

entry = OPA_RELEASE_PIN.binaries[platform_key(platform.system(), platform.machine())]
entry.asset, entry.sha256, OPA_RELEASE_PIN.version
```

`platform_key` raises `KeyError` for an unsupported platform.

## Running the evaluation vectors

A compiled program may call only the functions in the capabilities allowlist, `iltero_schemas.opa.CAPABILITIES`
(written to a file for OPA). Its digest is `iltero_schemas.opa.CAPABILITIES_DIGEST`. Each evaluation case runs
the case's compiled program from `compiler/` over the case's input:

```bash
opa eval --format json --strict-builtin-errors \
  --capabilities capabilities.json \
  --data ILT.AWS.RDS.STORAGE_ENCRYPTED.rego \
  --stdin-input \
  'data.iltero.assertions["ILT.AWS.RDS.STORAGE_ENCRYPTED"].evaluate' < input.json
```

The query is always `data.iltero.assertions["<ID>"].evaluate`. OPA returns a list with exactly one result. Its
`subject`, `status`, `reason`, `observations.unknown`, `observations.when` and, where the case gives them,
`observations.predicates` must equal the expected values.

For `facts_unknown.json`, the case's assertion id replaces `evaluation.assertion.id` in the context. With
`unknown_marker`, the facts stay as the markers the context holds. With `empty_list`, each of `evaluations`,
`approvals` and `exceptions` becomes `[]`. A missing fact must give `unknown`, never `fail`.

Each compiled program must also pass `opa check --strict --capabilities capabilities.json`.

## Version rule

Vectors belong to the version that ships them. A consumer pins one exact version (`iltero-schemas==X.Y.Z`) and
reproduces that version's vectors. Before 1.0, a change to any computed result raises the minor version: a digest, a
canonical form, a compiled program or the OPA pin. To upgrade, a consumer moves its pin and reproduces the vectors
again.
