# Document formats

Iltero components exchange JSON documents (an assertion is written in YAML). Each document named here has a
Pydantic model in `iltero_schemas.models`. A consumer validates a document with that model before it uses any value.

- [Conventions](#conventions)
- [TechnicalAssertion](#technicalassertion)
- [AssuranceContext](#assurancecontext)
- [AssuranceEvent](#assuranceevent)
- [Change Assurance Record (CAR)](#change-assurance-record-car)
- [VerificationReport](#verificationreport)
- [ResourceIdentities](#resourceidentities)
- [EvaluatorBindingSet](#evaluatorbindingset)
- [ScannerObservations](#scannerobservations)
- [LocalExceptions](#localexceptions)
- [PolicySource](#policysource)
- [AssertionBundleDescriptor](#assertionbundledescriptor)
- [BundleSigningKeys](#bundlesigningkeys)

## Conventions

Every document names itself by two top-level fields: `apiVersion`, which is `iltero.com/v1` for every document
(`iltero_schemas.models.base.API_VERSION`), and `kind`, which names the document type. A reader accepts exactly its
own pair. A document with any other `apiVersion`, with no `kind`, or with the `kind` of another document is refused.
A `kind` nested inside a document, such as a target's, a subject's or a gap's, is an ordinary field described with
its parent.

| `kind` | Document | Read by |
| --- | --- | --- |
| `TechnicalAssertion` | [An assertion](#technicalassertion) | `iltero_schemas.models.assertion.TechnicalAssertion` |
| `AssuranceContext` | [An evaluation input](#assurancecontext) | `iltero_schemas.models.context.AssuranceContext` |
| `AssuranceEvents` | The events file a stage keeps (see the stage's [`events`](#change-assurance-record-car)) | No model: `iltero_schemas.models.event.events_file_bytes` writes it, and a record names it by path and digest |
| `ChangeAssuranceRecord` | [A record](#change-assurance-record-car) | `iltero_schemas.models.car.CAR` |
| `VerificationReport` | [A verification report](#verificationreport) | `iltero_schemas.models.verification.VerificationReport` |
| `ResourceIdentities` | [A resource identities document](#resourceidentities) | `iltero_schemas.models.iac.resource_identities.ResourceIdentities` |
| `EvaluatorBindingSet` | [An evaluator binding set](#evaluatorbindingset) | `iltero_schemas.models.binding.EvaluatorBindingSet` |
| `ScannerObservations` | [What a stage read from a scanner's report](#scannerobservations) | `iltero_schemas.models.iac.scanner_observations.ScannerObservations` |
| `LocalExceptions` | [A project's own exceptions](#localexceptions) | `iltero_schemas.models.local_exceptions.LocalExceptions` |
| `PolicySource` | [A directory of hand-written policies](#policysource) | `iltero_schemas.models.policy_source.PolicySource` |
| `AssertionBundleDescriptor` | [How Iltero Platform serves a signed assertion bundle](#assertionbundledescriptor) | `iltero_schemas.models.bundle.BundleDescriptor` |
| `AssertionBundle` | The assertion bundle's own description, in its `.manifest` file (`iltero_schemas.models.bundle.BUNDLE_KIND`) | `iltero_schemas.bundle.check_descriptor`, which rebuilds it |
| `BundleSigningKeys` | [The trusted bundle keys](#bundlesigningkeys) | `iltero_schemas.trust.parse_bundle_keys` |

Documents take one of two shapes:

- A document Iltero writes as evidence keeps its content at the top level. Facts about the document itself sit in a
  `metadata` object where the document has any: a record's `metadata` holds its `uuid` and `issuer`, a verification
  report's its `verifier` and `verified_at`, and a resource identities document's its `generator`. An evaluation input,
  a bundle descriptor, scanner observations and the trust file have no `metadata`.
- A document a person writes has four top-level fields: `apiVersion`, `kind`, `metadata`, which says which document
  it is, and `spec`, which holds what it says. A TechnicalAssertion and an EvaluatorBindingSet name themselves by
  `metadata.id` and `metadata.version`. LocalExceptions and PolicySource name themselves by `metadata.name`, a
  name the project chooses: 1 to 63 lowercase letters, digits and hyphens, starting and ending with a letter or a
  digit (`iltero_schemas.models.fields.PROJECT_DOCUMENT_NAME_PATTERN`).

A document's digest covers the whole document, `apiVersion`, `kind` and `metadata` included.

Every model applies the same rules:

- A key the model does not define is refused.
- No value is converted. The string `"true"` is not a boolean, and `"7"` is not a number.
- A text field the model types (a name, an identifier, an address, a title) never contains a control character,
  a zero-width character, a bidirectional formatting character or another character that shows as nothing: a soft
  hyphen, the combining grapheme joiner, the Arabic letter mark, the Mongolian vowel separator or a Hangul filler.
  The refused characters are listed by code point (`iltero_schemas.models.assertion.CONTROL_CHARACTERS`), so every
  reader refuses the same ones whatever its Unicode version: U+0000–U+001F, U+007F–U+009F, U+00AD, U+034F,
  U+0600–U+0605, U+061C, U+06DD, U+070F, U+0890–U+0891, U+08E2, U+115F–U+1160, U+180E, U+200B–U+200F,
  U+2028–U+202E, U+2060–U+2064, U+2066–U+206F, U+3164, U+FEFF, U+FFA0, U+FFF9–U+FFFB, U+110BD, U+110CD,
  U+13430–U+1343F, U+1BCA0–U+1BCA3, U+1D173–U+1D17A, and the tag characters U+E0000–U+E007F, which spell text a
  reader does not see. The message is "must not contain control characters". Variation selectors, which follow
  ordinary emoji, are accepted.
  Fields that carry data as another tool wrote it, such as a resource's planned values in an AssuranceContext,
  accept any JSON value.
- A list of names that the model keeps sorted is sorted by Unicode code point, with no name twice.
- A count (`iltero_schemas.models.fields.Count`) is an integer from 0 to 2^53 − 1
  (`iltero_schemas.canonical.INT_MAX`), the largest integer the evaluator reads exactly.
- A tool that writes a JSON document writes every optional field, as `null` when it has no value: the form the
  model's `model_dump(mode="json", by_alias=True)` gives. One set of facts then has one document digest. A reader
  also accepts the field left out. A TechnicalAssertion is written by a person, in YAML, and keeps its own rules.

The tables below use these value types:

| Type | Form |
| --- | --- |
| digest | `sha256:` followed by 64 lowercase hexadecimal digits. Unless a row says otherwise, it is the SHA-256 of the value's RFC 8785 canonical JSON. |
| timestamp | RFC 3339 in UTC, ending in `Z`, such as `2026-09-21T10:00:00.000Z`. Up to nine fractional digits are accepted, and two timestamps compare to the nanosecond. Iltero writes milliseconds. |
| UUID | A lowercase, hyphenated UUID. |
| commit | A full git object id: 40 hexadecimal digits (SHA-1) or 64 (SHA-256). |
| identifier | Text of 1 to 256 characters. |
| stage | `plan`, `pre_deploy`, `post_deploy`, `post_verify` or `runtime` (see below). |

A stage is a point in a change's life at which assertions are checked:

| Stage | What is checked |
| --- | --- |
| `plan` | The change to deploy, once it is produced and before anyone approves it. For an IaC (infrastructure-as-code) change, the IaC tool's plan. For a container image build, the image the build pushed, before any deployment uses it. |
| `pre_deploy` | The change, at the gate before it is deployed: approvals, exceptions, earlier evaluations and whether its commits were reviewed. |
| `post_deploy` | What the deployment did. |
| `post_verify` | What runs after the deployment: the deployed resources, read back, or the workload that runs a deployed image. |
| `runtime` | Resources as they run, outside any change. No record has a `runtime` stage. |

## TechnicalAssertion

A technical assertion is a rule about infrastructure or a built artifact, written in YAML. It states what must be
true, at which stage of a change it is checked, and what kind of thing it is about. The compiler turns it into one
OPA program.

- **apiVersion:** `iltero.com/v1`, with `kind: TechnicalAssertion`
- **Model:** `iltero_schemas.models.assertion.TechnicalAssertion`. `iltero_schemas.ast.parse` reads the YAML text,
  applies the limits below and validates the rule's grammar.

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion`, `kind` | string | `iltero.com/v1` and `TechnicalAssertion`. |
| `metadata.id` | string | The assertion's id, which says in fixed places what kind of check it is (see [Assertion ids](#assertion-ids)). The namespace `ILT` is Iltero's alone. The first segment must not be a Windows device name (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`): "id must not start with a name Windows reserves for a device", at `metadata`. |
| `metadata.version` | string | A semantic version `X.Y.Z`. Evidence cites the assertion's digest, not this version. |
| `metadata.title` | string | One line, at most 200 characters. |
| `metadata.remediation` | string | Optional; when absent, the key is left out, never `null`. What a person does to make a failing subject meet the assertion. One line, at most 300 characters. |
| `metadata.description` | string | What is true of a subject that meets the assertion, in full. One line, at most 1,000 characters (YAML `>-` folds a long one). Required when `spec.assert` is `null`, optional otherwise; when absent, the key is left out, never `null`. |
| `spec.change_type` | string or null | Required. The [change type](#change-types-and-activities) the assertion is about: `iac_change` or `image_release`. `null` for an assertion about any change, which reads only what every change type's input shares. Left out, it is refused: "change_type is missing: give iac_change or image_release, or null for an assertion about any change". |
| `spec.stage` | stage | When the assertion is checked. Present exactly when `spec.assert` is a rule. |
| `spec.evidence.stages` | list | The stages whose scanner results may decide an assertion that has no rule of its own. The only such stage is `plan`, since Iltero reads scanner results at no other stage (`iltero_schemas.models.assertion.STAGES_WITH_SCANNER_RESULTS`). Stages are in lifecycle order, each once ("stages are in lifecycle order, each stage once"). Present exactly when `spec.assert` is `null`. |
| `spec.target` | object | What the assertion is about. `kind` is `resource`, `change`, `deployment`, `assurance` or `artifact` (the artifact a build produced, such as a container image). `resources` lists resource selectors: a `resource` target names exactly one; a `change` or `deployment` target may name up to 16, and is then in scope only when the change touches a resource one of them picks. Only an assertion about an `iac_change` names them on a `change` or `deployment` target: "a change target names resources only in an assertion about an iac_change". An `assurance` or `artifact` target names none: "an artifact target names no resources: it has no change to scope". |
| `spec.when` | object | Optional condition. When it is false, the result is `not_applicable`. |
| `spec.assert` | object or null | Required. The rule, or `null` for an assertion that only scanners decide (see below). |

Key rules:

- Each change type allows its own stage and target pairs (`iltero_schemas.models.assertion.COMBINATIONS`). Any
  other pair is refused: "stage ... is not valid for target kind ... in an assertion about ...".

  | Change type | Target kind | Stages |
  | --- | --- | --- |
  | `iac_change` | `resource` | `plan`, `runtime` |
  | `iac_change` | `change` | `pre_deploy` |
  | `iac_change` | `deployment` | `post_deploy`, `post_verify`, `runtime` |
  | `iac_change` | `assurance` | `runtime` |
  | `image_release` | `artifact` | `plan` |
  | `image_release` | `change` | `pre_deploy` |
  | `image_release` | `deployment` | `post_deploy`, `post_verify` |

  An assertion whose `change_type` is `null` may use any pair some change type allows (`VALID_COMBINATIONS`). It
  reads only the parts that the input of every activity evaluated at that stage and target carries
  (`iltero_schemas.profiles.roots_for`).

- A resource selector is one of:

  | Selector | Where | Picks |
  | --- | --- | --- |
  | `{tool, provider, resource_types}` | A `resource` target: exactly one. | Resources of `provider` whose type, as the infrastructure-as-code (IaC) `tool` (`terraform`) spells it, is one of `resource_types` (1 to 64). A resource's values are that tool's own attributes. |
  | `{provider, kinds}` | A `change` target, or a `deployment` target at `post_deploy`, of an assertion about an `iac_change`: up to 16. | Resources of `provider` whose kind is one of `kinds` (1 to 64), from the provider's list (`iltero_schemas.kinds.RESOURCE_KINDS`). |

  A kind is a tool-independent name for what a resource is, such as `rds_instance`, so one selector holds for every
  IaC tool. Each tool's table gives its resource types their kinds: `iltero_schemas/kinds/iac/terraform.json`, read with
  `iltero_schemas.kinds.kind_of`. From a `change` or `deployment` target's selectors the compiler writes a scope
  guard (`iltero_schemas.ast.scope.scope_guard`): a condition that decides whether the assertion applies. It is
  checked ahead of `when`, and holds when some resource of the provider has one of the kinds. A resource whose type
  the table lacks holds the unknown marker, so the guard is `unknown`, not `false`. When the guard is `false`, the
  result is `not_applicable`: the policy's reason is `when: false`, and the status reason is `when_guard_excluded`.
  A hand-written policy names no selectors: "a hand-written policy names no resources: no compiler writes its scope
  guard".
- A rule is built from predicates. A predicate names a `path` and exactly one comparison: `equal`, `not_equal`,
  `greater_than`, `greater_than_or_equal`, `less_than`, `less_than_or_equal`, `in`, `not_in` or `contains`. The
  operand is a literal or `{path: ...}`. Predicates combine with `all`, `any`, `not` and `exists` (`in` and an
  optional `where`, in which `item` names the element).
- A path's first segment must be a part of the [assurance context](#assurancecontext) that the assertion's input
  carries at its stage and target.
- A value of the wrong type is never an error: `equal`, the ordering comparisons, `in` and `contains` are `false` on
  it, and `not_equal` and `not_in`, their exact negations, are `true`.
- `equal` and `not_equal` also take the literal `null`, to check whether a value is null: `equal: null` holds for a
  `null`, and `not_equal: null` for any value that is set, even `false` or an empty list. Any other comparison with
  `null` is refused: "only equal and not_equal compare with null". A value that is absent, or an unknown marker, is
  still `unknown`, as the next rule says.
- An `in` or `not_in` list holds no `null`: one is refused at its place in the list, such as `spec.assert.in[1]`, with
  "must be a string, number or boolean (quote dates)".
- A predicate whose value is missing, redacted or not yet known is `unknown`, with a reason: `path_missing`, `redacted`,
  `not_a_list`, or the reason the value's marker carries (such as `known_after_deploy` or `not_reported_by_tool`, or
  `unspecified` when it carries none). `all`, `any`, `not` and `exists` follow three-valued logic. The assertion's
  result is `not_applicable`, `unknown`, `pass` or `fail`.
- The compiled program's `reason` says why: `when: false` for `not_applicable`, `<path>: <reason>` for `unknown`
  (such as `resource.after.server_side_encryption_configuration: known_after_deploy`), and `assert: true` for `pass`.
  A failure is named from the comparisons and `exists` that decided `assert`: a false `all` is decided by its first
  false part, a true `any` by its first true part, and any other decided result by all its parts. A `not` marks what
  decided it as negated, and a second `not` clears the mark. When the first of them is negated, the reason names the
  last, as `assert: false; <path> <op> is true, but must be false`, such as
  `assert: false; resource.after.ingress exists is true, but must be false`: in a negated `all` that held, the last
  part usually states the condition and the earlier ones narrow what it is about. Otherwise it names the first, as
  `assert: false; <path> <op> is false`, such as
  `assert: false; resource.after.backup_retention_period greater_than_or_equal is false`. With none, it is
  `assert: false`.
- The program's `observations.predicates` list each comparison and `exists` it evaluated, those of the scope guard and
  `when` first (`clause: when`), then those of `assert` (`clause: assert`), each with its position (`index`), `path`,
  `op` and `status`.
- Limits: a document of at most 256 KiB, nested at most 32 levels; at most 128 expressions (predicates and
  combinators), nested at most 8 levels, and 64 in one `all` or `any`; a path of at most 16 segments of 64 characters;
  at most 256 values in an `in` list; text values of at most 1024 characters; integers within ±(2^53 − 1). YAML
  anchors, aliases, tags, merge keys and duplicate keys are refused. The document is read as YAML 1.1, so unquoted
  `yes`, `no`, `on` and `off` are booleans.
- No value is written only as the word `null`. YAML also reads an empty value, `~`, `Null` and `NULL` as null, so the
  loader refuses them, as a value or as a key, and a forgotten value is never read as a comparison with null. For
  such a value on line 4: "line 4: no value is written as null, never as an empty value, ~, Null or NULL".
- `iltero_schemas.ast.source_digest` gives the assertion's source digest. It covers the id, version, type, change
  type, stage (or evidence stages), target, `when` and `assert`, and not the title, the remediation or the
  description. The compiler ignores all three. The assertion's digest, the one evidence cites, is taken over the whole
  document and covers them.

An assertion with `assert: null` has no rule of its own: only the scanner checks an
[evaluator binding](#evaluatorbindingset) names decide it, and its `metadata.description` says exactly what they
check. Its rules (`iltero_schemas.models.assertion.Spec`):

| Rule | Refused with |
| --- | --- |
| It names `spec.evidence.stages` and no `spec.stage`. | "an assertion with assert: null names evidence.stages and no stage" |
| Every evidence stage is `plan`, the only stage whose scanner results Iltero reads (`check_evidence_stages`, also run on an abstract syntax tree node built directly). Checked before the order rule. | "evidence.stages may name only plan: Iltero reads scanner results at no other stage", at `spec.evidence` |
| It is about a resource (`spec.target.kind: resource`). | "an assertion with assert: null is about a resource: only a resource is scanned" |
| It has a `metadata.description`. | "an assertion with assert: null has a metadata.description saying exactly what it checks" |
| An assertion with a rule names `spec.stage` and no `spec.evidence`. | "an assertion with a condition names its stage and no evidence" |
| Each evidence stage is a valid pair with the target, as `spec.stage` is. A `when` path is valid only where it resolves at every evidence stage. | The pair or path refusal above. |

Its compiled program never passes or fails it. It applies the scope guard and `when` only: `not_applicable` when they
exclude the subject; `unknown` with the policy reason `assert: observed_by_scanners` (the unknown path `assert`, the
reason `observed_by_scanners`) when they admit it, so the scanners' verdict applies; and `unknown` with the guard's own
reason when the guard cannot be settled. In the abstract syntax tree, such an assertion has `evidence.stages` in place
of `stage`, and `assert` is `null`.

```yaml
apiVersion: iltero.com/v1
kind: TechnicalAssertion
metadata:
  id: ACME.IAC.RESOURCE.AWS.RDS.PRODUCTION_BASELINE
  version: "1.0.0"
  title: Production databases are encrypted and private
  remediation: Set storage_encrypted to true and publicly_accessible to false.
spec:
  change_type: iac_change
  stage: plan
  target:
    kind: resource
    resources:
      - tool: terraform
        provider: aws
        resource_types: [aws_db_instance]
  when:
    path: organization_scope.environment.production
    equal: true
  assert:
    all:
      - path: resource.after.storage_encrypted
        equal: true
      - path: resource.after.publicly_accessible
        equal: false
```

An assertion that only scanners decide:

```yaml
apiVersion: iltero.com/v1
kind: TechnicalAssertion
metadata:
  id: ACME.IAC.RESOURCE.AWS.IAM.NO_ADMIN_POLICY
  version: "1.0.0"
  title: IAM policy does not allow every action on every resource
  description: >-
    An aws_iam_policy the plan defines meets this assertion when none of its statements allows Action "*" on
    Resource "*".
spec:
  change_type: iac_change
  evidence:
    stages: [plan]
  target:
    kind: resource
    resources:
      - tool: terraform
        provider: aws
        resource_types: [aws_iam_policy]
  assert: null
```

### Assertion ids

An assertion id says what kind of check the assertion is. Its segments are joined by dots, and each one sits in a
fixed place (`iltero_schemas.models.assertion_id`):

```text
<NAMESPACE>.<CHANGE_TYPE>.<TARGET>.<SCOPE...>.<CHECK>
```

| Segment | Value |
| --- | --- |
| `NAMESPACE` | `ILT` for Iltero's own assertions (`ILTERO_NAMESPACE`), or the project's own name for its own, which does not start with `ILT`. |
| `CHANGE_TYPE` | The segment of `spec.change_type`, or `COMMON` when it is `null` (see the table below). |
| `TARGET` | `spec.target.kind` in upper case. |
| `SCOPE` | For a `resource` target, two segments: the provider and the service. The provider is the selector's `provider` in upper case, with `-` written as `_` (`provider_segment`: `google-beta` gives `GOOGLE_BETA`). The service, such as `RDS`, is the author's word. For any other target, one segment: the area of the process it checks. |
| `CHECK` | What the assertion checks, in plain words. |

| `spec.change_type` | Segment |
| --- | --- |
| `iac_change` | `IAC` |
| `image_release` | `IMAGE` |
| `null` | `COMMON` |

The segments come from `iltero_schemas.models.change_type.CHANGE_TYPE_SEGMENT` and `COMMON_SEGMENT`.

| Target kind | Segment | Kind of check | Scope segments (`SCOPE_SEGMENTS`) |
| --- | --- | --- | --- |
| `resource` | `RESOURCE` | The state of a resource | 2: `PROVIDER.SERVICE` |
| `change` | `CHANGE` | A process | 1: `AREA` |
| `deployment` | `DEPLOYMENT` | A process | 1: `AREA` |
| `artifact` | `ARTIFACT` | A process | 1: `AREA` |
| `assurance` | `ASSURANCE` | A process | 1: `AREA` |

An Iltero process assertion takes its area from `ASSERTION_AREAS`. A project's own process assertion names an area
of its own.

| Area | Starter assertions in it |
| --- | --- |
| `APPROVAL` | `ILT.COMMON.CHANGE.APPROVAL.PRODUCTION_APPROVED`, `ILT.IAC.CHANGE.APPROVAL.SENSITIVE_CHANGE_APPROVED` |
| `SOURCE` | `ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED`, `ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT` |
| `CONTENT` | `ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN`, `ILT.IMAGE.DEPLOYMENT.CONTENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE` |
| `DRIFT` | `ILT.IAC.DEPLOYMENT.DRIFT.NO_DRIFT_AFTER_APPLY`, `ILT.IMAGE.DEPLOYMENT.DRIFT.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE` |
| `BUILD` | `ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT` |
| `CHECKS` | `ILT.IMAGE.ARTIFACT.CHECKS.TESTS_RAN`, `ILT.IMAGE.ARTIFACT.CHECKS.SCAN_RAN` |
| `PROVENANCE` | `ILT.IMAGE.ARTIFACT.PROVENANCE.SIGNED_PROVENANCE_MATCHES_RUN` |
| `HISTORY` | `ILT.COMMON.ASSURANCE.HISTORY.NO_UNEXPLAINED_REGRESSION` |

Examples:

| Id | Reads as |
| --- | --- |
| `ILT.IAC.RESOURCE.AWS.RDS.STORAGE_ENCRYPTED` | Iltero's check of the state of an AWS RDS resource in an IaC change: its storage is encrypted. |
| `ILT.COMMON.CHANGE.APPROVAL.PRODUCTION_APPROVED` | Iltero's check of a change's approval, for every change type: a production change was approved. |
| `VEC.IAC.CHANGE.TEST.SCOPE_CHANGE` | A conformance vector's check of an IaC change, outside Iltero's namespace, so in an area of its own, `TEST`. |

How to read an id:

- The change-type segment says what an assertion is about, not which change it was evaluated in. A `COMMON`
  assertion is evaluated in records of every change type. Evidence is grouped by change with an event's
  `evaluation.activity`.
- An area compares only within one namespace: `ACME`'s `APPROVAL` need not mean what Iltero's does.
- A resource's service, such as `RDS`, is the author's word, not a value the contract checks.
- Once released, an id is never renamed. A renamed check is a new assertion.

`ILT` is Iltero's alone (`iltero_schemas.models.assertion_id.ILTERO_NAMESPACE`). No other namespace starts with
`ILT`. Where an id is a project's own, `ILT` itself is refused too (`check_project_id`): the assertion of
an event from the project's own files (see [AssuranceEvent](#assuranceevent)), a policy source entry's assertion (see
[PolicySource](#policysource)), and a binding set read from a file, with each assertion it binds (see
[EvaluatorBindingSet](#evaluatorbindingset)). `check_project_id` refuses with "a project's own id has a namespace of
its own, not ILT or one starting so".

Limits: an id is at most 96 characters (`ASSERTION_ID_MAX_LENGTH`), and each segment at most 48
(`SEGMENT_MAX_LENGTH`). Each segment starts with an upper-case letter and holds only upper-case letters, digits and
`_`.

The model checks the id against the assertion's own `spec` (`check_assertion_id`). In a TechnicalAssertion, an id
longer than 96 characters is refused at `metadata.id` first ("String should have at most 96 characters"), and a
Windows device name at `metadata`.

| Rule | Refused with |
| --- | --- |
| The id is at most 96 characters. | "an assertion id must be at most 96 characters" |
| Each segment is at most 48 characters. | "each segment of an assertion id must be at most 48 characters" |
| The first segment is not a Windows device name (`WINDOWS_DEVICE_NAMES`). | "an assertion id must not start with a name Windows reserves for a device" |
| The namespace is `ILT` or one that does not start with `ILT`. | "an assertion id's namespace must be ILT or one not starting ILT" |
| The id has as many segments as its target kind calls for. | "a resource assertion's id must be NAMESPACE.CHANGE_TYPE.RESOURCE.PROVIDER.SERVICE.CHECK", or, for a process target, the same with its kind and `AREA`, such as "a change assertion's id must be NAMESPACE.CHANGE_TYPE.CHANGE.AREA.CHECK" |
| The second segment is that of `spec.change_type`. | "the id's second segment must be IAC, for change_type: iac_change", or "COMMON, for change_type: null" |
| The third segment is the target kind. | "the id's third segment must be RESOURCE, for target kind resource" |
| For a `resource` target, the fourth segment is the selector's provider. | "the id's fourth segment must be AWS, for provider aws" |
| An `ILT` process assertion's area is one of `ASSERTION_AREAS`. | "an Iltero process assertion's area must be one of APPROVAL, BUILD, CHECKS, CONTENT, DRIFT, HISTORY, PROVENANCE, SOURCE" |

A new change type, provider, target kind or area adds a value to its list and changes no existing id.

An id that refers to an assertion, in an event, a record, an evaluator binding or a bundle, keeps only the general
shape: upper-case segments joined by dots, at least two, at most 96 characters
(`iltero_schemas.models.assertion.ID_PATTERN` and `ID_MAX_LENGTH`, which is `ASSERTION_ID_MAX_LENGTH`). A binding
set's id, such as `ILT.BINDINGS.STARTER`, is not an assertion id and keeps the same general shape.

## AssuranceContext

The assurance context is the evaluation input: the one JSON document OPA receives for one assertion about one
subject. The tool that runs OPA records the context's digest in the event as `input_digest`.

- **apiVersion:** `iltero.com/v1`, with `kind: AssuranceContext`
- **Model:** `iltero_schemas.models.context.AssuranceContext`.
  `iltero_schemas.profiles.profile_for(activity, stage, kind)` gives the parts an input of an activity carries at a
  stage, for a target kind.

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion`, `kind` | string | `iltero.com/v1` and `AssuranceContext`. |
| `evaluation` | object | This evaluation: its `id`, the [`activity`](#change-types-and-activities) it belongs to (`iac_change`, `image_build` or `image_deploy`), its `stage`, the runner's `timestamp`, and the `assertion` (`id`, `version`). |
| `organization_scope` | object | The `organization`, `workspace` and `environment`, each `null` when the run has none. The `environment` has its `name` and `production`: whether Iltero Platform's environment policy treats it as production, or the unknown marker in a run Iltero Platform did not open. |
| `reference_time` | object | The time every expiry and ordering comparison uses: `value`, `source` (`server`, `timestamp_authority`, `rekor` or `runner_clock`), `trust` (`attested`, `corroborated` or `asserted`; always `asserted` for `runner_clock`), and `time_window`: the two timestamps the evaluation sits between (`not_before`, `not_after`) and a `nonce_digest`, present exactly when `source` is `timestamp_authority`, otherwise left out or `null`. `not_before` ≤ `value` ≤ `not_after`. Read from the runner's clock, its `value` is the same instant as `evaluation.timestamp`: "an input that reads its runner's clock uses the time of its evaluation". |
| `source` | object | The code the change comes from: `vcs` (`git`) and the `commit` (`sha`); the `repository` (`name`), `null` for a checkout with no remote; the `ref` (`type`: `branch` or `tag`, and `name`), `null` for a detached head; and the `pull_request` (`id`), `null` for a run outside a pull request. A run on a developer's machine is never a pull request. |
| `change` | object | The resources the plan changes (`id`, `provider`, `type`, `kind`, `action`, `module`), and the change `digest`: the [change digest](#the-change-digest) of `iac_change`, the subject's unit, the environment key `organization_scope.environment.name` (`null` when the environment is `null`) and `plan.digest`. A context with any other `digest` is refused: "change.digest is the digest of the change type, unit, environment and plan". `provider` is the provider's short name: lower-case letters, digits, `_` and `-`, starting with a letter (`aws`, `google-beta`). `kind` is the kind the plan tool's table gives the type, or the unknown marker `{"__unknown": true, "reason": "kind_unmapped"}` when the table lacks it; it is `null` exactly for a provider with no kinds. A context whose kinds differ from the table's is refused. In an `image_deploy` input, the change is the deployed image instead: its `digest`, the change digest of `image_release`, the subject's unit, the environment key and the image; the `image` (`repository`, `digest`); and the `build` Iltero Platform accepted, `null` when it accepted none, or the unknown marker `{"__unknown": true, "reason": "server_facts_unavailable"}` in a run the tool opened (see [The `image_deploy` body](#the-image_deploy-body)). An `image_deploy` input names its environment ("a deploy's input names its environment: a deploy is to one"), and `build` holds the marker exactly when `organization_scope.environment.production` does: "change.build holds the unknown marker exactly when the environment's production flag does: both hold it only in a run no server opened". A context with any other `digest` is refused: "change.digest is the digest of the change type, unit, environment and image". |
| `plan` | object | The IaC `tool` and `tool_version`, the plan `format_version`, the plan's digests, `source_commit`, whether the plan is `complete` and `applyable`, and the same table of contents for every resource the plan covers. `tool_version`, `complete` and `applyable` hold the unknown marker `{"__unknown": true, "reason": "not_reported_by_tool"}` when the tool's plan does not say; `null` is refused. |
| `subject` | object | The subject's `kind`, its `key` and its `identities` (`scheme`, `value`, `scope`): one or two, its local identity and, at runtime, its cloud identity (at most `iltero_schemas.models.fields.MAX_SUBJECT_IDENTITIES`, 2). An identity's `scope` holds at most 8 keys (`MAX_SCOPE_KEYS`). |
| `resource` | object | For a resource subject, the resource as planned: `id`, `provider`, `type`, `kind`, `name`, `module`, `action`, `before`, `after`, the resources that refer to it (`related`), and `tool_data`. |
| `deployment` | object | What the apply did: the applied `plan`, and `apply` with its `source` log, the `state` after it, or the `state_not_read` marker when it was not read (see [When the state after the apply was not read](#apply-with-the-state-not-read)), `outcomes_from` (`apply_log`; `apply_log_and_state` when the log lost messages and the state settled what it could; `apply_log_alone` when the state was not read), each change of the applied plan once (`changes`, each saying where its outcome came from in `outcome_from`: `apply_log`, `apply_log_alone`, `state` or `none`), `timing`, and `tool_data`: what only the IaC tool says, keyed by `tool`, which must be `apply.source.tool`. For `terraform`: the `summary` counts it reported, `errors_reported`, the number of error diagnostics the log holds (see [When the state after the apply was not read](#apply-with-the-state-not-read) for the rules on both), the `log_lines` it could not read (`other_output_lines`, `damaged_messages`, `interrupted_operations`), and the delete of each `deposed` object (an old copy a replacement set aside), settled by the state, or the `state_not_read` marker when it was not read. `superseded_by` is `{"reason": "dependency_replanned"}` when the pipeline says it applied a re-plan, which must differ from the evaluated plan, and `null` otherwise. In an `image_deploy` input, the image the pipeline reports it deployed (see [The `image_deploy` body](#the-image_deploy-body)). |
| `evaluations`, `approvals`, `exceptions` | list or marker | Facts only Iltero Platform holds, as the items below (`iltero_schemas.models.server_facts`). |
| `run` | object | The run the input belongs to, by Iltero's run `id`; an approval of a run names it. |
| `drift_check` | object | What two readings of the unit's deployed resources, taken after the apply, found: the shape of a record's [`drift_check`](#change-assurance-record-car). In an `image_deploy` input, what one reading of the workload found (see [The `image_deploy` body](#the-image_deploy-body)); its `change_digest` is `change.digest`: "drift_check.change_digest is change.digest", and it compares every container, of the pod template or of a pod, whose image is from `change.image.repository`: "a reading compares every container whose image is from the deployed repository". |
| `assurance` | object | An assertion's results about one subject over time (`iltero_schemas.models.assurance.Assurance`): the `assertion` (`id`, `version`), the `subject` (`kind`, `key`), the `current` result and the `previous` one (each a `status`, the `stage` that reached it and `observed_at`), and what happened in between (`since_previous`: the `deployments` recorded for the subject's unit, each its `record` UUID, `change_digest` and `deployed_at`, and the `exceptions` approved, as the Exception item below). `previous` and `since_previous` are both `null` for a subject with no earlier result: "what happened since the previous result is given exactly when there is one". The previous result is no later than the current one ("the previous result comes before the current one"), and every deployment falls between them ("a deployment since the previous result comes between it and the current one"). |
| `artifact` | object | The image a build produced: its `repository`, its `digest`, the digest of each platform's image (`platform_digests`) and `build_commit`: the commit the build tool's provenance names, or the unknown marker `{"__unknown": true, "reason": "not_reported_by_tool"}` when the build named none (see [The build's commit](#the-builds-commit)), with the rules of the [`image_build` body](#the-image_build-body). |
| `tests` | list | Each test report the build was given, at most 64 (see below). |
| `scans` | list | Each scan report the build was given, at most 64 (see below). |
| `verified_source` | object or marker | The commit Iltero Platform verified from the identity the continuous integration (CI) system gave the job that opened the run, not the commit the tool reads from its checkout, with what that identity named (see the Verified source item below). A fact only Iltero Platform holds. |
| `attestation_outcome` | object or marker | What Iltero Platform found when it checked the signature of the build's attestation: verified, refused or not sent (see [The build's attestation](#the-builds-attestation)). A fact only Iltero Platform holds. |
| `commit_review` | object or marker | Whether every commit the change ships since its review starting point was reviewed (see [Commit review](#commit-review)). A fact only Iltero Platform holds. |

Key rules:

- The parts present are exactly those the profile of the evaluation's activity, stage and target kind provides. A
  part outside the profile is written as `null` and reads as absent, as does one left out. A missing required part
  or an extra part is refused, and the error names it. `evaluation`, `organization_scope` and `reference_time` are
  always required. A resource target also requires `resource`.

  | Activity | Stage | Required | Optional |
  | --- | --- | --- | --- |
  | `iac_change` | `plan` | `source`, `change`, `plan`, `subject` | none |
  | `iac_change` | `pre_deploy` | `source`, `change`, `plan`, `subject`, `evaluations`, `approvals`, `exceptions`, `commit_review`, `run` | none |
  | `iac_change` | `post_deploy` | `source`, `change`, `plan`, `subject`, `deployment` | none |
  | `iac_change` | `post_verify` | `subject`, `deployment`, `drift_check` | `source`, `assurance` |
  | `iac_change` | `post_verify`, about a resource (a [postponed check](#checks-postponed-until-after-the-deployment)) | `subject`, `resource`, `plan`, `deployment` | `source` |
  | `iac_change` | `runtime` | `subject` | `source`, `deployment`, `assurance`, `exceptions` |
  | `image_build` | `plan` | `source`, `subject`, `artifact`, `tests`, `scans`, `verified_source`, `attestation_outcome` | none |
  | `image_deploy` | `pre_deploy` | `source`, `change`, `subject`, `evaluations`, `approvals`, `exceptions`, `commit_review`, `run` | none |
  | `image_deploy` | `post_deploy` | `source`, `change`, `subject`, `deployment` | none |
  | `image_deploy` | `post_verify` | `change`, `subject`, `deployment`, `drift_check` | `source` |

- An input is at most 16 MiB (`iltero_schemas.models.context.MAX_INPUT_BYTES`, 16,777,216 bytes) of canonical JSON,
  measured over the model's dump with every part present, an absent one as `null`: "an evaluation input is at most
  16777216 bytes of canonical JSON".
- `change`, `deployment` and `drift_check` are read in the shapes of the input's activity: an `iac_change` input's
  as described above, an `image_deploy` input's as the deployed image, the deployment it reports and the reading of
  its workload. A field of the wrong shape is refused by its path in the activity's own shape, such as
  `change.resources`.

- An `image_build` input names no environment (`organization_scope.environment` is `null`): "a build's input names
  no environment: a build belongs to none".
- A build runs its own tests and scanners; the tool reads the reports they wrote and never runs them. Each report
  says which image it is about (`image_digest`) and where that tie comes from (`image_digest_source`): `report` when
  the report itself names the image's digest, as a Trivy or Grype JSON report does when the scan read the pushed image
  from its registry, or `pipeline` when only the pipeline says the report is about the image. `report` is the claim of
  the tool that read the report. An assertion reads these entries; no scanner's verdict answers one. A report's tool
  version and time are the report's own word. When `artifact.platform_digests` is not empty, each `scans` item names
  one of them, never `artifact.digest`: "a scan of an image built for several platforms names the platform it
  scanned".

  | `tests` item field | Meaning |
  | --- | --- |
  | `format` | `junit`. |
  | `file_digest` | The SHA-256 of the report file's bytes as the pipeline gave it. |
  | `image_digest`, `image_digest_source` | The image the report is about, and where that tie comes from. Always `pipeline`: "a JUnit report names no image, so only the pipeline ties it to one". |
  | `counts` | `tests`, `failures`, `errors` and `skipped`, each from 0. `failures`, `errors` and `skipped` together are at most `tests`. |

  | `scans` item field | Meaning |
  | --- | --- |
  | `kind` | `image_vulnerability`: a scan for known vulnerabilities in an image's packages. |
  | `format` | `trivy_json` or `grype_json`. |
  | `tool_version` | The version the report names (identifier). |
  | `file_digest` | The SHA-256 of the report file's bytes. |
  | `image_digest`, `image_digest_source` | The image the report is about, and where that tie comes from. |
  | `reported_at` | When the report says it was written (timestamp). |
  | `finding_counts` | How many findings the report lists by the severity the scanner gave: `critical`, `high`, `medium`, `low`, `negligible` and `unknown`, each from 0. |

- A subject's `key` is `sha256:` and the hex SHA-256 of the canonical bytes of `{"kind": <kind>, "identity": {"scheme":
  ..., "value": ..., "scope": ...}}`, the local identity with all three fields, `scope` as `null` when it has none,
  computed by `iltero_schemas.models.subjects.subject_key`. Every document is checked against it. The key is over
  the identity's text exactly as written, with no Unicode normalization, so a composed and a decomposed spelling of
  one character (`é` as U+00E9, or `e` and U+0301) give two keys. The
  local identity is exactly one of the subject's identities:

  | Subject | Local identity |
  | --- | --- |
  | A resource an IaC tool manages | Its address (`scheme: terraform_address`), with `scope` exactly `{"unit": <its unit>}`. |
  | A resource no IaC tool manages, read at `runtime` | Its cloud identity (`scheme: aws_arn`). |
  | A `change`, `deployment`, `assurance` or `artifact` subject | Its unit (`scheme: iltero_unit`), with no `scope`. |

  The key names an address in a unit, not a cloud resource: a resource replaced in the cloud keeps its key, and a
  resource moved to another address gets a new one. Only a resource identities document ties a key to a cloud resource
  over time. A key is unique within one project's records. Neither a stack nor any other Iltero Platform scope is part
  of it, so a project keeps every key when it connects to Iltero Platform. A cloud identity is read only at runtime,
  beside the local identity, never in its place: at any other stage, a subject with a cloud identity is refused ("a
  resource only the cloud knows is read at runtime, never at plan", for the `plan` stage). Only a resource has a cloud
  identity: "a change subject has no cloud
  identity: only a resource has one", and the same for a `deployment`, `assurance` or `artifact` subject. A resource
  subject's address is the `id` of the `resource` the input carries, and an event's local identity is of the event's
  `provenance.run.unit`.
- A resource's `type`, in `change.resources`, `plan.resources` and `resource`, is never `null`, nor is
  `resource.name`, `resource.tool_data.provider_source` or a related resource's `type`. A redacted value is the
  redaction marker.
- A resource's `provider` is the short name an assertion targets (`aws`). `kind` follows the same rule as a change
  entry's. `name` is the resource's name within its configuration, and `module` the address of the module that
  contains it, in the tool's own syntax, or `null` at the root.
- `tool_data` holds what only the IaC tool that planned the resource says about it, keyed by `tool`, which must be
  the plan's `tool`, as must each related resource's; any other is refused. For `terraform`: `provider_source` (the
  provider's full source address), `action_reason`, `previous_address` (the address before a rename), `importing` and
  `replace_paths`, as the plan wrote them. Each related resource's `tool_data` says how Terraform matched it: `match`
  is `instance` (this instance of a `count` or `for_each`) or `every_instance`.
- `plan.digest` is the plan's digest by the rule for the plan's `tool` (`iltero_schemas.canonical.plan_digest`), and
  `digest_version` is that rule's version (`PLAN_DIGEST_VERSIONS`). A context with any other `digest_version` is
  refused, and `plan_digest` raises `ValueError` for a tool with no rule. `deployment.plan.digest_version` is held to
  the rule of `deployment.apply.source.tool` in the same way: the applied plan may be a re-plan, so it follows its own
  tool's rule. The `terraform` rule, version `1`, digests the plan as `terraform show -json` prints it, without the
  top-level keys `timestamp`, `terraform_version`, `format_version`, `prior_state`, `resource_drift` and
  `relevant_attributes` (`PLAN_EXCLUDED_TOP_LEVEL_KEYS`). `artifact_digest` is the digest of the saved plan file. It is
  present exactly when `artifact_digest_source` is `saved_plan`, and `null` when it is `not_provided`.
  `ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN` compares `plan.digest`, `plan.artifact_digest` and
  `plan.artifact_digest_source` with the same fields of `deployment.plan`. When neither side was given the saved plan
  file, both artifact digests are `null` and both sources `not_provided`: the assertion passes, and the event's
  observations show `not_provided`. Such a pass shows that the applied plan's digest equals the evaluated plan's, not
  that the applied plan file is the evaluated one byte for byte. When only one side has the saved plan file, it fails.
- `plan.source_commit` equals `source.commit.sha`.
- A value removed by redaction is a marker, `{"__redacted": true, "reason": ..., "present": true, "type": ...}`. Only
  the JSON value `true` marks a value redacted, never `1` or `1.0`, as in the evaluator's runtime. A
  value not yet known is `{"__unknown": true, "reason": ..., "present": true}`. A predicate that reaches either is
  `unknown`. A tool writes a value known only after the deploy as the `known_after_deploy` marker, never as `null`;
  the context does not check this, since `resource.after` is the tool's data. An `equal: null` check on the marker
  is `unknown`.
- `null` means a fact has no value, never that it is unknown. The evaluator reads a `null` at the end of a path as a
  known value: `equal: true` on it is `false`, never `unknown`, so `not` over that predicate is `true`. A path through a
  `null` part, or a key left out, is `unknown` with `path_missing`; `exists` over a `null` collection is `unknown`
  with `not_a_list`. A fact that is not known is the unknown marker, and a predicate that reads it is `unknown` with
  the marker's reason. The one `null` that stands for values not carried is a related resource's `resource`: a
  predicate that reads through it is `unknown`.
- `organization_scope.environment.production` comes from Iltero Platform's environment policy for the run's
  environment. A run Iltero Platform did not open cannot know it, so it is the unknown marker, and a guard on it is
  `unknown`, never `false`: such a run never silently skips an assertion that guards on production.
- A fact Iltero Platform could not supply is the marker `{"__unknown": true, "reason": "server_facts_unavailable"}`,
  never an empty list. A predicate that reads it is `unknown`, never `fail`.
- A `drift_check` was read by the IaC tool that applied the `deployment` (`deployment.apply.source.tool`), and its
  first reading is no earlier than the end of the apply (`deployment.apply.timing.ended_at`), when the apply's timing
  is known. A first reading written without a fraction of a second (`2026-10-29T02:28:13Z`) is compared with the whole
  second the apply ended in; one written with a fraction, even `.000`, is compared exactly. An IaC tool may date a
  reading in whole seconds, from when the reading started; Terraform does.
- The context holds no evaluator version, bundle digest or provenance.

The facts only Iltero Platform holds are normalised whatever produced them. Each item is Iltero Platform's claim, as
served.

| Item | Fields |
| --- | --- |
| Approval | `id`, `actor` (`provider`, and `id`: the provider's stable account id, never a login, a name or an address), `roles`, `status` (`approved`), `subject`, `method` (`ci_deployment_review` or `iltero_review`), `independence` (`independent` when the approver neither started the run nor triggered the attempt; `self_permitted_by_policy` otherwise, with the permitting `policy_version`, `null` when independent), `timestamp`. An approval from a CI deployment review names no role, since none is verified. |
| Exception | `id`, `status` (`approved`: only granted exceptions are served), `scope` (`assertion.id`, `environment`, and the `resources` it covers, by their identities), `valid_from`, `expires_at` (after `valid_from`), `approved_by`, `reason`. An exception never names a [built-in assertion](#assuranceevent) in `scope.assertion.id`: "an exception never covers a built-in assertion: what it records is never waived". |
| Earlier evaluation | `id`, `assertion` (`id`, `version`), `stage`, `subject` (`kind`, `key`), `result`, `checked_content` (the [checked content](#checked-content) it read, or `null`: its kind, or `null`, is one an activity's input carries at that stage (`iltero_schemas.profiles.reads_checked_content`, one kind per activity, `None` for an activity whose input carries none). So `plan` and `container_image` are accepted at `plan`, `pre_deploy` and `post_deploy`; `container_image` or `null` at `post_verify`, where an `image_deploy` input carries the image and an `iac_change` input nothing; and only `null` at `runtime`. Any other is refused: "an earlier evaluation names the content it checked exactly when its stage reads that content"), `observed_at`. One earlier evaluation is the [combined verdict](#how-evaluators-combine) of a stage's evaluations of one assertion about one subject: `result.status` is that verdict, and `result.decided_by` names the engine of each evaluator that reached it (`opa`, `checkov`, `trivy` or `none`), sorted, each once ("decided_by is sorted, each engine once"). |
| Verified source | `commit`: the commit Iltero Platform verified from the identity the CI system gave the job that opened the run. What that identity named: `ci_provider`, the CI system (`github_actions`, from `iltero_schemas.models.ci.CI_SYSTEMS`); `ci_instance`, the instance of it by its host name, such as `github.com`; `repository_id`, the repository's id at the CI system, which does not change when the repository is renamed, and `repository`, its name; `ci_run_id` and `ci_run_attempt` (an integer from 1), the CI run and its attempt. A CI system's ids are unique only within one instance of it, so each id is read with `ci_provider` and `ci_instance`. |

- An approval's `subject` names what it approves: `{kind: change, digest}`, that plan and no other, or `{kind: run,
  id}`, Iltero's run, never a CI run. An approval of a run approves the run, not a plan's content: a CI deployment
  review approves the deploy job when it starts, whether or not that run has planned yet.
- `ILT.COMMON.CHANGE.APPROVAL.PRODUCTION_APPROVED` and `ILT.IAC.CHANGE.APPROVAL.SENSITIVE_CHANGE_APPROVED` pass on an
  approved, independent approval of the change by its digest from the `security` role, or on an approval of the run
  whose `subject.id` is the input's `run.id`. Each is its own `exists`, so the observations show which one held. An
  approval of the run may be a self-approval the policy permitted; an approval of the change may not. For an approval of
  the run, both assertions read the same CI environment approval: there is no separate security sign-off behind it.

### Commit review

`commit_review` says whether every commit a change ships since its review starting point was reviewed. At the
change's `pre_deploy` stage, Iltero Platform reads the repository's history at its git host, the service that keeps
the repository and its pull requests, and serves the outcome. It is a fact only Iltero Platform holds, carried by the
`pre_deploy` input of an `iac_change` and of an `image_deploy`.

- **Model:** `iltero_schemas.models.commit_review.CommitReview`, one shape per `outcome`. The input checks it against
  its other parts with `iltero_schemas.models.commit_review.check_commit_review`.

The terms it uses:

- **The commits checked** are the first-parent line from `head_commit` back to, not including, the first commit on it
  that `counted_since.commit` has in its history: the commits that merges and direct pushes put on the branch, found
  by following each commit's first parent. A merge commit's content is checked against the reviewed final head of its
  pull request, which covers the commits the merge brings in, so those are not checked one by one. That includes the
  merge that brought the starting point in. The check covers only the files the pull request changed from its merge
  base, the commit where its final head and the branch before the merge last shared history, so a merge that changes
  any other file is not reviewed.
- **Reviewed.** A commit is reviewed when the merge of a pull request put it on that line (its merge commit, squash
  commit or rebased commits; a pull request that only contains the commit does not count), and before the merge an
  approval qualified for the pull request's final head.
- **A qualifying approval** is the reviewer's latest decision when the git host is read and was not dismissed: a
  re-approval or a request for changes after the merge replaces an earlier approval. The reviewer is a person who can
  write to the repository when the git host is read and is neither the pull request's author nor an author or
  committer of any of its commits.
- **A person** is a user account at the git host, machine users included. Apps, organizations, deleted accounts and
  unknown users are not.
- **The review starting point** is a commit an administrator recorded: the commits before it are not checked. A head
  commit that is the commit the count starts after has no commits to check. A head commit in the starting point's
  history, older than it, is `head_commit_before_review_starting_point`.
- **Where the count starts** (`counted_since`). Iltero Platform chooses where the count starts: after the review
  starting point, or after the head commit of an earlier reading of the same repository, decided after the same
  starting point was set, whose outcome was `reviewed` and whose head commit is on this head's first-parent line.
  Which such reading it counts from, if any, is its choice: counting from an older one, or from the starting point,
  only checks more commits. Those earlier readings form a chain that ends at the starting point. Each link was judged
  once, as the git host stood when it was read: a later reading does not judge again the commits an earlier one
  covered, so a decision made at the git host after a reading does not change what that reading judged. Iltero
  Platform keeps every reading of a chain as long as any record rests on it. More than 100 commits since the reading
  counted from is still `too_many_commits`.

**Limit:** who pushed to a pull request's branch is not checked. The reading keeps the repository's branch rules as
the git host reports them, including whether the most recent push needs another person's approval.

Every outcome has these fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `outcome` | string | One of the eight outcomes below. |
| `host_reading_id`, `host_reading_digest` | UUID, digest | The reading of the git host the outcome was decided from, and a digest of what the decision rests on. The reading keeps when the host was read. With no review starting point the host is not called, and the reading is Iltero Platform's record of that. |
| `decided_at` | timestamp | When Iltero decided the outcome from that reading. |
| `repository` | object | The repository, as its git host names it (see [Git repository](#git-repository)). |
| `head_commit` | commit | The commit the change is from, where the line starts. |

`head_commit` and `repository` are what Iltero Platform verified, never what the input names. For an `iac_change`,
they are the commit and repository it verified from the identity the CI system gave the job that opened the run. For
an `image_deploy`, they are the accepted build's `verified_commit` and `repository` (see
[The `image_deploy` body](#the-image_deploy-body)).

| `outcome` | Meaning | Further fields |
| --- | --- | --- |
| `reviewed` | Every commit on the line was reviewed. | `review_starting_point`, `counted_since`, `commits_counted` |
| `not_reviewed` | Some commits on the line were not reviewed. | `review_starting_point`, `counted_since`, `commits_counted`, `commits_not_reviewed`, `commits_not_reviewed_list_complete` |
| `too_many_commits` | The line holds more commits than Iltero Platform checks. | `review_starting_point`, `counted_since`, `commits_counted` |
| `no_review_starting_point` | No administrator recorded a review starting point for the repository. | none |
| `review_starting_point_not_in_history` | The review starting point is not in the head commit's history, so there is no line to check. | `review_starting_point` |
| `head_commit_before_review_starting_point` | The head commit is in the review starting point's history, older than it, so the review never covered it. | `review_starting_point` |
| `source_commit_not_verified_commit` | The input's source commit is not the commit Iltero Platform verified for the job that opened the run, so a review of the verified commit says nothing about the change. `head_commit` is the verified commit. Only for an `iac_change`. | none |
| `build_commit_not_verified_commit` | The image's build names no commit, or another commit than the one Iltero verified for its build, so a review of the verified commit says nothing about the image. Only for an `image_deploy`. | none |

`source_commit_not_verified_commit` and `build_commit_not_verified_commit` come before every other outcome: when one
holds, nothing else is decided.

| Field | Type | Meaning |
| --- | --- | --- |
| `review_starting_point` | object | The commit an administrator recorded (`commit`), who set it (`set_by`: `provider` and `id`, as an approval's `actor`), when (`set_at`, a timestamp) and why (`reason`, text of 1 to 1024 characters). |
| `counted_since` | object | The commit the count starts after, not counted (`commit`), and the earlier reading whose head commit it is (`earlier_reading`): that reading's own `host_reading_id` (UUID) and `host_reading_digest` (digest), and when its outcome was decided (`decided_at`, a timestamp). `earlier_reading` is `null` for a count since the review starting point. |
| `commits_counted` | integer | The commits on the line since `counted_since.commit`, from 0. At most 100 (`MAX_COMMITS_CHECKED`) for `reviewed` and `not_reviewed`. For `too_many_commits`, more than 100, and the line holds at least this many. |
| `commits_not_reviewed` | list | Each commit not reviewed (`commit`) and why (`reason`): 1 to 50 entries (`MAX_COMMITS_NOT_REVIEWED`), the first found walking back from the head commit, each listed once, sorted. |
| `commits_not_reviewed_list_complete` | boolean | Whether the list holds every commit not reviewed. Iltero Platform stops listing after 50. |

Each commit not reviewed has one reason, Iltero Platform's word, backed by the reading: the first of these that holds,
in this order (`NotReviewedReason`).

| `reason` | Meaning |
| --- | --- |
| `no_pull_request` | No pull request could have put the commit on the line. |
| `pull_request_not_merged` | The pull request was not merged. |
| `pull_request_not_read_in_full` | The git host would not list all of the pull request's commits, approvals or changed files. |
| `merged_commits_not_one_line` | The commits the merge put on the line are not one first-parent line. |
| `no_qualifying_approval` | No approval qualified for the pull request's final head. |
| `approved_after_merge` | The qualifying approval came after the merge. |
| `changed_after_approval` | A file the merge changed, from the first parent of the earliest commit it put on the branch to its merge commit, is one the pull request did not change (its final head holds it as at the merge base), or has another mode or content than in the approved final head. |

Of several pull requests that could have put a commit on the line, one that reviewed it is enough. Otherwise the
commit takes the reason of the one that met the most conditions, the one with the lowest id on a tie.

Iltero Platform serves the unknown marker `{"__unknown": true, "reason": "server_facts_unavailable"}` in place of the
part when it could not read the git host or has no adapter for it, when no server opened the run, and when an image
deploy has no accepted build.

Rules:

| Rule | Refused with |
| --- | --- |
| `commits_not_reviewed` lists each commit once, sorted. | "commit_review lists each commit not reviewed once, sorted" |
| The list is incomplete only when it holds 50 entries, the most it may, and more commits were counted. | "commit_review's list of commits not reviewed is incomplete only when it holds 50, the most it may, of more commits counted" |
| The list holds no more commits than `commits_counted`. | "commit_review lists no more commits not reviewed than it counted" |
| The list never names `counted_since.commit`, which is the review starting point when the count starts there. | "commit_review never lists the commit it counts since as not reviewed" |
| With no earlier reading, `counted_since.commit` is the review starting point. | "commit_review counts since the review starting point when it names no earlier reading" |
| With an earlier reading, `counted_since.commit` is not the review starting point. | "commit_review counts since an earlier reading only of a commit after the review starting point" |
| The earlier reading is not the outcome's own: its `host_reading_id` is not the outcome's `host_reading_id`. | "commit_review counts since an earlier reading, not its own" |
| The earlier reading's `decided_at` is later than the review starting point's `set_at`. | "commit_review counts since a reading decided after its review starting point was set" |
| The earlier reading's `decided_at` is earlier than the outcome's `decided_at`. | "commit_review counts since a reading decided before its own outcome" |
| The count is 0 exactly when `head_commit` is `counted_since.commit`. | "commit_review counts no commits exactly when the head commit is the one it counts since" |
| `reviewed` and `not_reviewed` count at most 100 commits. | "commit_review checks at most 100 commits; more is too_many_commits" |
| `too_many_commits` counts more than 100. | "commit_review is too_many_commits only for more than 100 commits" |
| The review starting point's `set_at` is no later than `decided_at`. | "commit_review's review starting point was set no later than the outcome was decided" |
| For `review_starting_point_not_in_history`, the starting point is not `head_commit`. | "a review starting point that is the head commit is in its history" |
| For `head_commit_before_review_starting_point`, the starting point is not `head_commit`. | "a head commit that is the review starting point is not before it" |
| `iac_change`: the part is the unknown marker when `organization_scope.environment` is `null` or its `production` is the marker. | "commit_review holds the unknown marker when the input names no environment or its production flag is the marker: only a server that opened the run reviews its commits" |
| `iac_change`: the outcome is never `build_commit_not_verified_commit`. | "an infrastructure change's commit_review is not about an image's build" |
| `iac_change`: `head_commit` is `source.commit.sha`, except for `source_commit_not_verified_commit`, where it is not. | "commit_review.head_commit is source.commit.sha, unless the outcome is source_commit_not_verified_commit, which names the verified commit" |
| `image_deploy`: the outcome is never `source_commit_not_verified_commit`. | "an image deploy's commit_review is not about an infrastructure change's source commit" |
| `image_deploy`: the part is the unknown marker unless `change.build` is an accepted build. | "commit_review holds the unknown marker when the deploy has no accepted build" |
| `image_deploy`: `head_commit` and `repository` are `change.build.verified_commit` and `change.build.repository`. | "commit_review.head_commit and repository are the accepted build's verified_commit and repository" |
| `image_deploy`: the outcome is `build_commit_not_verified_commit` exactly when `change.build.build_commit` is not `change.build.verified_commit`, `null` included. | "commit_review is build_commit_not_verified_commit exactly when the accepted build's build_commit is not its verified_commit" |

The starter assertion `ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED` reads the part. It is about any change
(`change_type: null`), at `pre_deploy`, about the `change` target:

| Assertion | Title | Passes when |
| --- | --- | --- |
| `ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED` | Every commit the change ships since its review starting point was merged through a pull request with a qualifying approval | `commit_review.outcome` is `reviewed`. It fails for every other outcome, and is `unknown` with `server_facts_unavailable` when the part is the unknown marker. In a run the tool opened it is never `pass`, `fail` or `not_applicable`, and when it is `unknown` its reason is `server_facts_unavailable`, so a `pre_deploy` stage that evaluates it is at best indeterminate (exit code `3`); see the record rule for such a run in [Change Assurance Record (CAR)](#change-assurance-record-car). Not built in: a project adds it, and an exception may name it. Its remediation: "Merge every commit through a pull request approved on its final head, before the merge, by a person who can write to the repository and wrote none of it; run the change from, or build the image from, the commit Iltero verified; have an administrator set a review starting point when none fits." |

#### Git repository

A repository as its git host names it (`iltero_schemas.models.git.GitRepository`). A git host's ids are unique only
within one instance of it, so the id is read with the host and instance.

| Field | Type | Meaning |
| --- | --- | --- |
| `host` | string | The git host: `github` (`iltero_schemas.models.git.GIT_HOSTS`). Any other is refused. |
| `instance` | identifier | The instance of the git host, by its host name, such as `github.com`. |
| `repository_id` | identifier | The repository's id at the git host, which does not change when the repository is renamed. |

### Apply with the state not read

The state is the IaC tool's record of the resources it manages. When the pipeline says the tool could not read the
state after the apply, the post-deploy stage is still recorded, from the apply log alone. That the state was not read
is the pipeline's word; nothing corroborates it. `deployment.apply.state` is then the unknown marker
`{"__unknown": true, "reason": "state_not_read"}` (`iltero_schemas.models.iac.markers.StateNotRead`), with no other
key, and `deployment.apply.outcomes_from` is `apply_log_alone`.

Such a deployment shows that an apply was invoked, which plan the pipeline says it applied, by its digest, and what
the log says happened to each change. When the apply has a `timing`, it started no earlier than the plan stage was
observed, by the clocks that wrote them; an apply whose every operation is unknown may have no `timing`. The
deployment does not show which resources the state holds, and no outcome of the apply was held to the state. The
record does not show why the state was not read, nor whether the apply failed.

Each change says how its outcome is known (`outcome_from`):

| `outcome_from` | Meaning |
| --- | --- |
| `apply_log` | The log's word, held to the applied plan by address, action and operation, and to which resources the state holds. |
| `apply_log_alone` | The log's word, held to the applied plan only, since the state was not read. |
| `state` | The log lost what happened to the change, and the state settled which operations completed. Only a `create`, `delete` or `replace`, as `applied`, `errored` or unknown. |
| `none` | Nothing settles it. `outcome` is an unknown marker, and so is `completed` for a change that needs an operation: `deployment_log_incomplete` for an update the log lost, which the state never settles, or `state_not_read` where only the state would have settled it. |

Rules:

- `outcomes_from` is `apply_log_alone` exactly when `state` is the marker: "outcomes_from is apply_log_alone exactly
  when the state after the apply was not read".
- With the state not read, every change is `apply_log_alone`, or `none`: "with the state not read, a change is known
  from the log alone or not at all". A change is `none`, with the `state_not_read` marker as its `outcome`, where only
  the state would have settled it: a `create`, `delete` or `replace` whose end the log lost, with the marker as
  `completed` too, and every change that needs no operation (a rename, an import or a `forget`), whose `completed` is
  `[]`. A change that needs no operation is never `no_operation` or `not_attempted` without the state: "only the
  state after the apply shows whether a change that needs no operation was done". Any other use of the marker is
  refused: "a change stays unknown for want of the state only when the state would have settled it: a create, delete
  or replace whose end the log lost, or a change that needs no operation".
- With the state read, no change is `apply_log_alone`, and no change or deposed object's delete holds the
  `state_not_read` marker: "a change stays unknown for want of the state only when the state was not read".
- The log and the state are held to one IaC tool only when the state was read.
- When the log lost messages, whether or not the state was read, no change that needs an operation is `not_attempted`; a
  change that needs no operation is not affected. The log cannot show that a change it never names was not started, and
  the state never shows that a change was not attempted. "a log that lost messages never shows that a change with
  operations was not attempted: it is unknown". For `terraform`, the log lost messages when `damaged_messages` or
  `interrupted_operations` is above 0, or when its `summary` is the `deployment_log_incomplete` marker, and no deposed
  object's delete is then `not_attempted` either: "a log that lost messages never shows that a deposed object's delete
  was not attempted: it is unknown".
- For `terraform`: Terraform 1.14 ends an apply log with its counts when the apply ran to its end, and with its errors
  when it stopped. `errors_reported` counts the error diagnostics the log holds, each counted whether or not the
  record keeps it; a warning is not counted, and a damaged line is counted in `damaged_messages` instead. The `summary`
  is `null` exactly when `errors_reported` is above 0: "an apply log that reports an error holds no counts: its
  summary is null". A log that holds neither its counts nor an error was cut short: its `summary` is the
  `deployment_log_incomplete` marker, "an apply log that holds neither its counts nor an error was cut: its summary is
  unknown", and the log counts as having lost messages, so no change with operations and no deposed object's delete
  is `not_attempted`.
- A change that needs no operation, left unknown, is not an operation that may have run: an apply whose only unknown
  changes need no operation has a `timing` only when an operation ran.
- For `terraform`: with the state not read, every deposed object's delete is the `state_not_read` marker: "with the
  state not read, every deposed object's delete is unknown". A change that needs an operation left `none` needs a
  log that lost messages: "only a log that lost messages leaves a change to the state or unknown". The one
  exception: with the state not read, a `delete`, or a `replace` that deletes, at an address that also holds deposed
  objects may be `none` with the `state_not_read` marker even when the log lost no messages, since the log names every
  delete at that address alike and only the state shows which was the current object's. A change that needs no
  operation, left unknown, still allows the `summary`; an import among them is still counted in `imported`. The
  summary's `removed` count may include the deposed deletes left unknown.
- A `post_verify` input whose deployment's state was not read is refused: "post-verify needs the identities the state
  after the apply gives, and the state after the apply was not read".

An assertion that reads a change's outcome decides on the log's word alone. One that reads a `state_not_read` marker,
such as `deployment.apply.state.tool`, is `unknown` with reason `state_not_read`.
`ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN` reads only the applied plan, so it still decides. A
`not_equal` or `not_in` over `outcomes_from` also matches `apply_log_alone`: `not_equal: apply_log_and_state` holds when
the state was not read. The same holds for each change's `outcome_from`, which has four values (`apply_log`,
`apply_log_alone`, `state`, `none`): `not_equal: state` matches `apply_log_alone`.

## AssuranceEvent

An assurance event is one verdict: the result of one assertion about one subject, with the provenance needed to say
who produced it and to reproduce it.

- **apiVersion:** none. An event travels inside a [CAR](#change-assurance-record-car), and in the events file of its
  stage.
- **Model:** `iltero_schemas.models.event.AssuranceEvent`

| Field | Type | Meaning |
| --- | --- | --- |
| `assertion` | object | The assertion's `id`, `version` and the `digest` of its document as it was read. |
| `subject` | object | The subject's `kind`, `key` and `identities`, in the same shape as on the evaluation input, with at most 2 identities. `key` is `null`, and `identities` empty, exactly when no subject was in scope. |
| `evaluation` | object | The [`activity`](#change-types-and-activities) and `stage` the evaluation belongs to, the `status`, the runner's `status_reason` and `status_detail`, and the policy's own reason (`policy_reason`) and `observations`. |
| `provenance` | object | Where the verdict came from (see below). |
| `observed_at` | timestamp | The run's timestamp. Every event of one run carries the same value. |

| `provenance` field | Meaning |
| --- | --- |
| `run` | The run `id` and the `unit`. A unit is the part of a project the IaC tool plans and applies as one. |
| `source_commit`, `checked_content` | The commit and the [checked content](#checked-content) the evaluation is about. |
| `input_digest` | The digest of the assurance context the evaluator received. |
| `evaluator` | The engine that produced the verdict. For `opa`: its `version`, binary `digest` and the `limits` applied: `timeout_seconds`, `memory_limit`, `max_output_bytes`, `evaluations_per_process`, `capabilities_digest` and `platform`. For a scanner (`checkov` or `trivy`): the `version` the scanner wrote into its report (`null` for a required scanner that gave no report), `digest: null`, `reason: not_executed_by_cli`, and what its verdict rests on (see [Evaluations from a scanner's results](#evaluations-from-a-scanners-results)). A scanner digest is refused: "a scanner's version is named, not its digest". |
| `bundle` | The bundle the program came from: `kind` (`server` or `local_bundle`), `tarball_digest`, the SHA-256 of the bytes of the bundle tarball the evaluator loaded, `content_digest` and `key_id`. For `server`, they are the served [descriptor](#assertionbundledescriptor)'s `tarball_digest`, `content_digest` and `key_id`. For `local_bundle`, `tarball_digest` is the digest of the tarball the tool built, and `content_digest` and `key_id` are `null`, because a bundle the tool built has no descriptor. Any other combination is refused: "a bundle names its content digest and signing key exactly when its kind is server". The writer's claim: nothing compares these values with a descriptor. Present exactly when the evaluator is `opa`. An evaluation whose `assertion_source` is `server_bundle` and that ran over a bundle names a bundle of kind `server`; otherwise it is refused: "an assertion from the server's bundle is evaluated over the server's bundle". |
| `evaluator_binding` | The scanner evaluator of an [evaluator binding](#evaluatorbindingset) whose checks decided the evaluation, by its `digest` alone (`EvaluatorBindingRef`). Present exactly when the evaluator is a scanner; otherwise it is refused: "an evaluator binding is named exactly when a scanner's result was read for this evaluation". |
| `assertion_source`, `assertion_source_digest` | Where the assertion came from, and its source digest. `server_bundle`: an assertion bundle Iltero Platform served. `local`: the project's own files; `custom_rego` when hand-written in Rego. `contract_starter`: a starter assertion this package ships, added to a local run. The writer's claim. |
| `compiled_digest`, `compiler` | The compiled program's digest, and the compiler's `version`, `contract_version`, `contract_digest` and `install` (`wheel` or `editable`). Absent for a scanner. |
| `executor` | Who ran the evaluation: `type` (`human` or `workload`), `provider` (`local`, `ci` or a CI system such as `github_actions`) and the CI system's run id (`ci_run_id`). |
| `facts_source` | For an evaluation whose input may carry Iltero Platform facts (approvals, exceptions, earlier evaluations, the commit review, the verified source, the verified attestation: an `iac_change` input at `pre_deploy` or `runtime`, an `image_build` input at `plan`, and an `image_deploy` input at `pre_deploy`), where they came from: `server` or `none`. `null` for every other input (`iltero_schemas.profiles.reads_server_facts`). It names where the facts document came from: the parts only Iltero Platform holds (`SERVER_FACTS`: `evaluations`, `approvals`, `exceptions`, `commit_review`, `verified_source`, `attestation_outcome`). A value Iltero Platform supplies inside another part is not counted: the environment's production flag (`organization_scope.environment.production`) in every input, and the accepted build (`change.build`) in an `image_deploy` input. In a run the tool opened, such a value holds the unknown marker (`server_facts_unavailable`), so it follows `governance.run_opened_by`. The `post_deploy` and `post_verify` inputs of an `image_deploy` name no `facts_source`. |

Key rules:

- `status` is one of six values. Only `pass` and `fail` may omit `status_reason`, and a reason must belong to its
  status:

  | Status | Reasons |
  | --- | --- |
  | `pass` | none |
  | `fail` | none: a failure's reason is the policy's `policy_reason` |
  | `unknown` | `known_after_deploy`, `redacted`, `path_missing`, `not_a_list`, `unspecified`, `server_facts_unavailable`, `not_reported_by_tool`, `reference_time_untrusted`, `deployment_log_incomplete`, `state_not_read`, `kind_unmapped`, `scanner_result_unresolved`, `scanner_report_incomplete` |
  | `not_applicable` | `when_guard_excluded`, `no_subject_in_scope` |
  | `not_evaluated` | `scanner_not_run`, `credential_denied`, `resource_type_unsupported`, `scanner_version_not_allowed`, `timeout`, `subject_unresolved`, `evaluator_unavailable`, `identity_unverified`, `stage_not_run`, `suppressed_in_source`, `tool_reports_only_failures`, `no_scanner_report` |
  | `error` | `evaluator_crash`, `evaluator_timeout`, `evaluator_memory_limit`, `output_overflow`, `output_contract_violation`, `adapter_parse_failure`, `bundle_verification_failed`, `compile_failure` |

- An event is checked on its own against its activity. Its activity, stage and subject kind have a profile
  (`iltero_schemas.profiles.profile_for`); otherwise it is refused, such as "stage 'plan' is not valid for target kind
  'artifact' in an iac_change input". Its `provenance.checked_content.kind` is the activity's
  (`CHECKED_CONTENT_KIND_OF`: `plan` for `iac_change`, `container_image` for `image_build` and `image_deploy`): "an
  image_build evaluation names the container_image it checked".
- An event's assertion id sits in the namespace its `provenance.assertion_source` allows:

  | Rule | Refused with |
  | --- | --- |
  | Whatever its source, an event's assertion has the namespace `ILT` or one that does not start with `ILT`. | "an assertion's namespace is ILT or one not starting ILT" |
  | An assertion from the project's own files (`local` or `custom_rego`, `iltero_schemas.models.event.PROJECT_ASSERTION_SOURCES`) has an id whose namespace does not start with `ILT`. | "an assertion from a project's own files has an id outside ILT" |
  | An assertion named as a starter (`contract_starter`) is one this package ships, at its version and document digest (`iltero_schemas.assertions.SHIPPED_ASSERTIONS`, each a `ShippedAssertion` with its `version`, document `digest` and `compiled_digest`). | "an assertion named as this package's starter is the document this package ships" |

- A built-in assertion's id is reserved. `iltero_schemas.assertions.BUILT_INS`, the built-ins among
  `SHIPPED_ASSERTIONS`, gives each built-in (`ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN`, `ILT.IAC.DEPLOYMENT.DRIFT.NO_DRIFT_AFTER_APPLY`,
  `ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT`,
  `ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT`,
  `ILT.IMAGE.DEPLOYMENT.CONTENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE` and
  `ILT.IMAGE.DEPLOYMENT.DRIFT.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE`) as shipped; `BUILT_IN_IDS` is the set of their
  ids. An event that names a built-in is evaluated as shipped, and each rule is refused with its message, where the
  id stands for the built-in's:

  | Rule | Refused with |
  | --- | --- |
  | `assertion.version` and `assertion.digest` are the shipped ones. | "ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT is a built-in assertion: it names the document this package ships" |
  | `provenance.assertion_source` is `contract_starter` or `server_bundle` (`iltero_schemas.models.event.BUILT_IN_SOURCES`). | "ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT is evaluated from this package or the server's bundle" |
  | `provenance.compiled_digest` is the shipped module's. It is `null` only when no evaluator ran (`evaluator` is `null`). | "ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT runs the module compiled from the document this package ships" |

- No scanner's result decides an assertion in `iltero_schemas.assertions.NOT_DECIDED_BY_SCANNERS`: the built-in
  assertions, and the starters that read a fact only Iltero Platform holds (`ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED`,
  `ILT.COMMON.CHANGE.APPROVAL.PRODUCTION_APPROVED`, `ILT.IAC.CHANGE.APPROVAL.SENSITIVE_CHANGE_APPROVED` and
  `ILT.IMAGE.ARTIFACT.PROVENANCE.SIGNED_PROVENANCE_MATCHES_RUN`). An event that names one with an `evaluator_binding` is
  refused, with its id: "ILT.COMMON.CHANGE.APPROVAL.PRODUCTION_APPROVED is never decided by a scanner's result".
- An evaluation from a scanner's results is one whose `provenance.evaluator` is a scanner. Its rules:

  | Rule | Refused with |
  | --- | --- |
  | It is about a resource (`subject.kind: resource`). | "an evaluation from a scanner's result is about a resource" |
  | Its `status` and `status_reason` are one of the pairs in `iltero_schemas.models.scanner_evaluator.SCANNER_OUTCOMES` (see below). | "an evaluation from a scanner's results is one of: fail, not_evaluated/scanner_not_run, not_evaluated/scanner_version_not_allowed, not_evaluated/suppressed_in_source, not_evaluated/tool_reports_only_failures, pass, unknown/known_after_deploy, unknown/not_reported_by_tool, unknown/scanner_report_incomplete, unknown/scanner_result_unresolved" |
  | It reads no facts from Iltero Platform: `provenance.facts_source` is not `server`. | "an evaluation from a scanner's result reads no facts from the server" |
  | Only such an evaluation gives `scanner_version_not_allowed`, `suppressed_in_source`, `tool_reports_only_failures`, `scanner_result_unresolved`, `scanner_report_incomplete` or `scanner_not_run` (`SCANNER_ONLY_REASONS`). | "only an evaluation from a scanner's results is scanner_version_not_allowed" (with the reason) |
  | It names a project's exception (`local_exception`) only when it is `suppressed_in_source`. | "a scanner's evaluation names a project's exception only for a suppressed check" |
  | It names no compiled module and no compiler. | "a scanner's result was not compiled here, so it names no module and no compiler" |
  | Its evaluator's `version` and its `provenance.input_digest` are `null` exactly when it is `scanner_not_run`. | "a scanner's evaluation names no version and no input exactly when the scanner gave no report" |
  | A `scanner_not_run` evaluation has empty `result_addresses`, `unknown_paths` and `failed_rule_ids`, and its `undecided_rule_ids` are its `rule_ids`. | "a scanner that gave no report decided none of its bound checks and read no resource" |

  A scanner `evaluator` (`iltero_schemas.models.scanner_evaluator.ScannerEvaluator`) also names what the verdict
  rests on. Each list is sorted, each item once ("rule_ids is sorted, each once", with the field's name):

  | Field | Meaning |
  | --- | --- |
  | `rule_ids` | The checks its binding bound, 1 to 16. |
  | `subject_match` | How their results found the subject: `exact_address` or `plan_configures`. |
  | `result_addresses` | The plan addresses of the resources the results it rests on were about, at most 16. Empty when no result of a bound check was about the subject. |
  | `unknown_paths` | The paths, at most 512, that the plan marks known only after the deployment on those resources and that a key the result read, or a path of the binding's `paths_read`, reaches. |
  | `failed_rule_ids`, `undecided_rule_ids` | The bound checks that failed for the subject, and those that decided nothing about it. Each names bound checks, and no check is in both: "failed_rule_ids and undecided_rule_ids name bound checks, each in one of them". |
  | `local_exception` | The project's own exception the source's suppression rests on (`LocalExceptionRef`: its `id` and the `file_digest` of the [LocalExceptions](#localexceptions) file it is in), or `null`. A record of a run Iltero Platform opened names none: "a record of a run the server opened names no exception from a project's own files". |

  A record ties each one to the scanner report its stage kept and to the binding set, among those its stage applied,
  that holds its evaluator (see [Evaluations from a scanner's
  results](#evaluations-from-a-scanners-results)).
- A policy can return `pass`, `fail`, `unknown` or `not_applicable`. Only the runner sets `not_evaluated` and
  `error`.
- A policy verdict names its `input_digest`. When no subject was in scope, the event's subject has no `key` and no
  `identities`, and the event has no `input_digest`.
- `evaluator` is `null` only for `evaluator_unavailable`, `no_subject_in_scope` and `no_scanner_report` (an
  assertion that only scanners decide, when no report the stage was given has checks bound to it). A
  `scanner_not_run` evaluation names its scanner, with `version: null`.
- From worst to best, statuses rank `not_evaluated`, `error`, `unknown`, `fail`, `not_applicable`, `pass`
  (`iltero_schemas.models.event.STATUS_SEVERITY`).
- A policy's `policy_reason` is at most 2 KiB. Its `observations` are at most 512 KiB of canonical JSON, nested at
  most 4 levels.

### How evaluators combine

A stage may evaluate one assertion about one subject with several evaluators: its own rule, which OPA runs, and each
scanner whose report the stage was given and whose checks are bound to the assertion. Each gives its own event. The
stage's verdict for that assertion and subject is their combined verdict (`iltero_schemas.models.verdicts`); verdicts
of different stages never combine. The status that comes first in `COMBINING_ORDER` wins:

| Order | Status | Why |
| --- | --- | --- |
| 1 | `fail` | One evaluator's failure is never outweighed. |
| 2 | `unknown` | A value one evaluator could not settle keeps a pass from standing. |
| 3 | `pass` | Stands only where no evaluator failed or could not settle the value. |
| 4 | `not_applicable` | |
| 5 | `error` | Not a decision: it never hides another evaluator's decision. |
| 6 | `not_evaluated` | Not a decision. |

A scanner the run requires (`scanners.required_scanners`) that gave no report (`scanner_not_run`, see [Evaluations
from a scanner's results](#evaluations-from-a-scanners-results)), or whose report came from a version its binding does
not allow (`scanner_version_not_allowed`), is a gap no pass fills (`REQUIRED_SCANNER_GAP_REASONS`): it cancels every
`pass` and `not_applicable` (`CANCELLED_BY_A_REQUIRED_SCANNERS_GAP`), and the order above applies to what is left. A
`fail` or `unknown` still stands, and so does another evaluator's `error`. A pass beside the gap gives
`not_evaluated`, decided by that scanner. A scanner the run does not require cancels nothing: its
`scanner_version_not_allowed` is an evaluation that could not decide, like any other. `combined_verdict` and
`stage_verdicts` take the scanners the run requires (`required_scanners`, which `stage_required_scanners` reads from a
stage record).

The combined verdict names, in `decided_by`, the engine of every evaluator whose own status is the one it reached
(`combined_verdict`, `stage_verdicts`). A stage's coverage counts combined verdicts, not events. An evaluation that
could not decide and that its combined verdict does not count is listed as an [`evaluator_did_not_decide`
gap](#change-assurance-record-car).

## Change Assurance Record (CAR)

A Change Assurance Record (CAR) is the record of one attempted change, for one unit of one run: an infrastructure
change, the build of an artifact, such as a container image, or the deployment of a built image to one environment.
It holds the evaluations, what the deployment did and the evidence each part cites. It exists whatever the outcome:
deployed, failed, stopped, refused before deployment, or a plan that changes nothing.

A CAR records technical and process assurance facts. It does not, by itself, establish certification or compliance
with a regulatory framework.

- **apiVersion:** `iltero.com/v1`, with `kind: ChangeAssuranceRecord`
- **Model:** `iltero_schemas.models.car.CAR`

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion`, `kind` | string | `iltero.com/v1` and `ChangeAssuranceRecord`. |
| `metadata` | object | The record's `uuid`, its id, and its `issuer`: `type: local` and `identity_verified: false`. The `uuid` is derived from the run and the unit (`iltero_schemas.canonical.record_uuid(run_id, unit)`): a version 5 UUID, in the namespace `RECORD_UUID_NAMESPACE`, of the text `iltero-car:<run.id>:<unit>`. Every stage of the run that reports on the unit writes the same record under the same id, and a reader recomputes it. |
| `run` | object | The run's `id` (UUID). |
| `unit` | identifier | The unit the record covers. |
| `trust_level` | string | How far the record's facts were established (see below). Always `self_attested` in this version. |
| `compliance_determination` | null | Always `null`. |
| `governance` | object | `run_opened_by`: `server` when the writer says Iltero Platform opened the run, `local` when the tool opened it on its own. Only Iltero Platform confirms that it opened a run, by its `run.id`. |
| `subject` | object | `kind: change`, the `environment`, the `unit` and the `source`: the code the change comes from, in the shape of an [AssuranceContext](#assurancecontext)'s `source`. |
| `change` | object | The change the record is about: the body of its [activity](#change-types-and-activities), named by `change.activity` (see [The `iac_change` body](#the-iac_change-body), [The `image_build` body](#the-image_build-body) and [The `image_deploy` body](#the-image_deploy-body)). |
| `units_file` | object or null | The project's [units file](#units-file) as the writer read it. `null` for a project that declares none. |
| `stages` | object | One entry per stage that reported, keyed by stage (see below). Every stage is one the record expects. |
| `events` | list | Every [event](#assuranceevent), grouped in stage order. At most 100,000. |
| `coverage` | object | The stages' coverage combined: subjects in scope and evaluated, assertions expected and evaluated, counts per status, the number of `evaluations`, gaps, truncation and sampling, and the inputs replaced with placeholders (`substituted_inputs`), each naming its stage. |
| `verdict` | object | `value` (`pass`, `fail` or `indeterminate`), `exit_code`, `computed_from` (`status_counts` for a stage, `stage_precedence` for the record) and the deciding `stage`. |
| `assurance_status` | object | `complete` or `incomplete`, with a `reason`: `required_policy_evaluation_failed` (an evaluation ended in an evaluator error, even one another evaluator's verdict outweighed), `state_not_read` (the state after the apply was not read), `checks_postponed_until_after_the_deployment` (a record only: checks its plan stage postponed were not settled), `plan_not_complete` (the plan said it is incomplete, or did not say it is complete) or `upstream_state_unavailable` (the stage read placeholders for an input). The `reason` is the leading cause, in that order (`iltero_schemas.models.coverage.INCOMPLETE_REASON_PRECEDENCE`), within a stage; a record's reason is the stage reason that comes first in that order, taken from the earliest stage incomplete for it; every cause stays in the stage's `coverage`: its gaps, substituted inputs and error count. A record that is `complete` (every expected stage reported) can still be `incomplete` here. A record whose plan stage postponed checks and that has no `post_verify` stage yet is `incomplete` with reason `checks_postponed_until_after_the_deployment` (`iltero_schemas.models.coverage.OPEN_CHECKS_REASON`) and the `detail` `1 check postponed until after the deployment was not settled`, or `<count> checks postponed until after the deployment were not settled` for more, unless its stages give a reason that comes earlier, which it keeps (`iltero_schemas.models.iac.postponed_checks.open_checks_status`). |
| `complete` | boolean | Whether every expected stage has reported. |
| `expected_stages` | list | The stages the record expects. |
| `out_of_scope` | list | Each stage of the activity the record does not expect, with a `reason` and `declared_in` (see below). |
| `evidence_refs` | list | The evidence register: every file the record cites (see below). At most 501,024 (`iltero_schemas.models.car.MAX_EVIDENCE_REFS`): five files for each event, its input and the four files its assertion was compiled into, and 256 more for each of a record's four stages. |
| `integrity` | object | `scheme: file_digests` (the record is bound together by its files' digests only) and `signature: null`. |
| `expires_at`, `retention_class` | null | Always `null`. |
| `retention_reason` | string | `no_server_scope`. |

Trust levels, from weakest to strongest:

| Level | Meaning |
| --- | --- |
| `self_attested` | The tool that wrote the record is its only source. The file digests show the files are the ones the record names. They do not show who wrote the record, and no other party confirms what it says. |
| `source_authenticated` | A service other than the writer authenticated the repository, the CI system and the identities named in the record. |
| `governed` | Iltero Platform enforced a declared assurance profile and verified the evidence chain. |

Every level above `self_attested` requires a signature. This version of the record carries none, so the model
accepts only `self_attested`.

Each `stages` entry says what one stage did:

| Field | Type | Meaning |
| --- | --- | --- |
| `stage` | stage | The stage, the same as the entry's key. |
| `observed_at` | timestamp | When the stage observed the change. |
| `reference_time` | object | The shape and rules of an [AssuranceContext](#assurancecontext)'s `reference_time`. Read from the runner's clock (`source: runner_clock`), its `value` is the same instant as `observed_at`. |
| `execution` | object | What ran the evaluations: the `evaluator` (`engine: opa`, `version`, binary `digest`) and the `bundle` (`kind`, `tarball_digest`, `content_digest` and `key_id`, with the rules of an event's `bundle`, and the `capabilities_digest` its programs were built under), or, when nothing ran, both `null` and a `reason` (identifier) with an optional `detail`. `reason` is `null` when something ran. The bundle is the writer's claim: nothing compares it with a descriptor. A `local_bundle` has no descriptor. The stage's compiled index (`assertions`) and `coverage.assertions_expected.required_assertion_digest` describe what it held; both are the writer's claims, and nothing compares them with the tarball. |
| `enforcement_mode` | string | The mode the stage's gate ran in: `enforcing` or `advisory` (see the key rules). |
| `approvals` | list, marker or null | The approvals the stage's evaluations read, in the shape of the [approval item](#assurancecontext), whatever their source, at most 256, each listed once and of the record's change or run, or the unknown marker `{"__unknown": true, "reason": "server_facts_unavailable"}` the input held in their place, or the marker `{"__unknown": true, "reason": "not_read_by_the_stage"}` (`iltero_schemas.models.facts.NotReadByTheStage`) when none of the stage's evaluations read an input that carries them (an event with a `provenance.facts_source` and an `input_digest`), so the stage keeps no copy. Present exactly at a stage whose input carries approvals (the `pre_deploy` stage of an `iac_change` or an `image_deploy`), `null` at every other: "the post_deploy stage keeps approvals, or the unknown marker, exactly where its input carries them". A stage keeps the `not_read_by_the_stage` marker exactly then: "the pre_deploy stage keeps the marker that it read no approvals exactly when none of its evaluations read an input that carries them". Otherwise, a stage none of whose events read its facts from Iltero Platform (`provenance.facts_source: server`) keeps the unknown marker: "the pre_deploy stage keeps the unknown marker for its approvals when its results read no facts from the server". One whose events did keeps the list or the unknown marker its input held. `StageRecord.listed_approvals` gives the list, empty for a marker or `null`. |
| `commit_review` | object, marker or null | The [commit review](#commit-review) the stage's evaluations read, as the input carried it (`iltero_schemas.models.commit_review.CommitReview`, one shape per outcome), the unknown marker `{"__unknown": true, "reason": "server_facts_unavailable"}` the input held in its place, or the `not_read_by_the_stage` marker (see below). `null` at every other stage. |
| `compiler` | object | The compiler, in the shape of an event's `compiler`: `version`, `contract_version`, `contract_digest` and `install`. |
| `redaction` | object | The stage's redaction report (see below). |
| `events` | object | The file of the stage's events: its `path`, `digest` and `count`, the number of the stage's events. The file is `{"apiVersion": "iltero.com/v1", "kind": "AssuranceEvents", "events": [...]}` (`iltero_schemas.models.event.EVENTS_FILE_KIND`), with the stage's events in the order the record lists them, written as its RFC 8785 canonical JSON (`iltero_schemas.models.event.events_file_bytes(events)`); `digest` is the digest of those bytes. Its evidence register entry has that digest, the bytes' `size_bytes` and `canonicalization: RFC8785`. `coverage.evaluations` counts their [combined verdicts](#how-evaluators-combine), one per assertion and subject, so it is at most `count`. |
| `assertions` | object | The index of the assertions the stage compiled: its path (`index`), `digest` and `count`. |
| `scanners` | object or null | The scanner reports the stage was given, and the binding sets it read their results with (see below). `null` for a stage given no scanner report. |
| `values_known_after_deployment` | string or null | What the plan stage's gate does with a check that read a value the plan knows only after the deployment: `block` on it, or `postpone` it (see [Checks postponed until after the deployment](#checks-postponed-until-after-the-deployment)). `null` at every other stage. |
| `postponed_checks` | list or null | The checks the plan stage postponed: a list exactly when it postpones, `null` otherwise. |
| `resource_redaction` | object or null | A redaction report, of kind `post_apply_resources`, of the values after the apply that the post-verify stage's settling checks read. `null` at every other stage, and at a post-verify stage that settles none. |
| `coverage`, `verdict`, `assurance_status` | object | The stage's own, in the shape of the record's. |

A stage keeps a commit review, or a marker, exactly where its input carries one, the `pre_deploy` stage of an
`iac_change` or an `image_deploy`. It keeps the `not_read_by_the_stage` marker exactly when none of its evaluations read
an input that carries a commit review. Otherwise it keeps the unknown marker when none of its events read its facts from
Iltero Platform, and when its `ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED` check could not read a commit review. It keeps
the review when that check passed or failed. Whether a stage whose events read facts from Iltero Platform kept the
review or the marker its input held is decided by replaying that input. The rules are in `iltero_schemas.models.stages`:

| Rule | Refused with |
| --- | --- |
| The stage keeps a commit review or the marker exactly where its input carries one. | "the post_deploy stage keeps a commit review, or the unknown marker, exactly where its input carries one" (with the stage) |
| The stage evaluates `ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED` at most once. | "the pre_deploy stage evaluates ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED at most once, so it keeps one reading" |
| A stage keeps the `not_read_by_the_stage` marker exactly when none of its evaluations read an input that carries a commit review. | "the pre_deploy stage keeps the marker that it read no commit review exactly when none of its evaluations read an input that carries it" |
| Otherwise, a stage whose events read no facts from Iltero Platform keeps the unknown marker. | "the pre_deploy stage keeps the unknown marker for its commit review when its results read no facts from the server" |
| When an `ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED` event of the stage is `pass` or `fail`, the stage keeps the commit review it was decided from, not the marker. | "the pre_deploy stage keeps the commit review its ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED check decided from" |
| When that event is `unknown` with `server_facts_unavailable`, as for an image deploy with no accepted build, the stage keeps the marker. | "the pre_deploy stage keeps the unknown marker when its ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED check could not read a commit review" |
| The kept outcome is `reviewed` exactly when that event is `pass`. | "the pre_deploy stage's commit review is reviewed exactly when its ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED check passed" |
| A record of an `iac_change` keeps no `build_commit_not_verified_commit`, and one of an `image_deploy` no `source_commit_not_verified_commit`. | "a record of image_deploy keeps no commit review that is source_commit_not_verified_commit" (with the activity and outcome) |
| The review was decided no later than the stage's `observed_at`. | "the pre_deploy stage's commit review was decided no later than the stage observed it" |
| `iac_change`: `head_commit` is the record's `subject.source.commit.sha`, except for `source_commit_not_verified_commit`, where it is not. | "the pre_deploy stage's commit review is of the record's source commit, unless it is source_commit_not_verified_commit, which names the verified commit" |
| `image_deploy`: the record has an accepted build, and the review's `head_commit` and `repository` are its `verified_commit` and `repository`. | "the pre_deploy stage's commit review is of the accepted build's verified commit and repository" |
| `image_deploy`: the outcome is `build_commit_not_verified_commit` exactly when `change.build.build_commit` is not `change.build.verified_commit`, `null` included. | "the pre_deploy stage's commit review is build_commit_not_verified_commit exactly when the accepted build's build_commit is not its verified_commit" |

A kept review is a `CommitReview`, so the [commit review](#commit-review)'s rules on its own fields hold for it too,
such as where it counts since and how many it counts.

A stage's `scanners` names the scanner reports it was given and the binding sets it read their results with. Each
verdict a scanner's results gave is an event of the stage (see [Evaluations from a scanner's
results](#evaluations-from-a-scanners-results)):

| Field | Type | Meaning |
| --- | --- | --- |
| `evaluator_binding_sets` | list | The [evaluator binding sets](#evaluatorbindingset) the stage applied: one or two (see below). |
| `required_scanners` | list | The scanners whose report the run requires, as the record states them (a reader does not check them against any configuration): `checkov` or `trivy`, sorted, each once ("required_scanners is sorted, each once"), at most 16. |
| `reports` | list | Each scanner report the stage was given, 0 to 16, one per scanner: "one report per tool per stage" (see below). |
| `local_exceptions` | object or null | The project's own exceptions file the stage applied to the results the scanned source suppressed: its `file_path`, `digest` and `copy_path` (see [A stage that applies the file](#a-stage-that-applies-the-file)). `null` when the project gave none. |

`scanners` keeps a report or names a required scanner: "a stage's scanners keep a report or name a required scanner".
`required_scanners` is the writer's claim: a record that leaves a scanner out of the list, together with its
evaluations and gaps, still holds together. A reader compares the list with the scanners its own policy requires.
It is `null` for a stage given no report and requiring none. Only a stage that reads scanner reports keeps
`scanners`: the `plan` stage of an `iac_change` record (`stages_that_read_scanner_reports` of the record's
[activity](#change-types-and-activities)). Every other stage keeps `null`: "the post_deploy stage of an iac_change
record keeps no scanner report".

A binding set says which scanner checks decide which assertion. A stage that reads scanner reports always applies
the binding set Iltero ships (`origin: shipped`). It may also apply one binding set read from the project's own file
(`origin: file`), and that set is then listed first. The list therefore holds either the shipped set alone, or the
project's set followed by the shipped set. Any other list is refused: "a stage always applies the binding set Iltero
ships, and at most one binding set of the project's own, listed first".

The project's set can decide only the project's own assertions, and the shipped set can decide only Iltero's starter
assertions, so no assertion is decided by both. As a result, the `provenance.evaluator_binding.digest` of each scanner
verdict matches exactly one binding across all of the stage's sets. That is how a reader finds the set that decided a
verdict.

Each entry of `evaluator_binding_sets` (`EvaluatorBindingSetUsed`) names one binding set by:

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | The binding set's `metadata.id`: upper-case segments joined by dots, at least two, at most 96 characters. A set read from a file (`origin: file`) has an id of its own namespace, not `ILT` or one starting `ILT` (`check_project_id`): "a project's own id has a namespace of its own, not ILT or one starting so". |
| `version` | string | The binding set's `metadata.version`: a semantic version `X.Y.Z`. |
| `origin` | string | `shipped` for the set this package ships, `file` for one read from a file. The writer sets it, not the binding set; in a self-attested record it is the writer's claim. Only the shipped set has the id `ILT.BINDINGS.STARTER`: "only the shipped binding set is ILT.BINDINGS.STARTER". |
| `file_name` | string or null | The name of the file the set was read from, without its directories. It follows the same rule as the plan's `artifact_file_name`. Present exactly when `origin` is `file`: "a binding set read from a file names it, and the shipped set names none". |
| `digest` | digest | The digest of the binding set's canonical JSON as parsed, not of the file's bytes. A reader recomputes it from the copy at `copy_path`. |
| `copy_path` | string | Where the stage kept its copy of the binding set's canonical JSON, in the record's directory. The copy is an entry of the evidence register by this path and `digest`. |
| `assertions_bound` | integer | How many assertions the set binds, the length of its `spec.bindings`, for every scanner and stage, from 0. |

Each `reports` entry (`ScannerReport`):

| Field | Type | Meaning |
| --- | --- | --- |
| `tool` | string | `checkov` or `trivy`. |
| `tool_version` | identifier | The version the scanner wrote into its report. |
| `supplied_by` | string | Who ran the scanner: always `pipeline`, which supplied the report. |
| `input_kinds` | list | What the scanner read, in the contract's words (`plan`, `deployed_resources`): sorted, each once ("input_kinds is sorted, each kind once"), at most 16 (`iltero_schemas.models.car.MAX_INPUT_KINDS`). |
| `report_digest` | digest | The digest of the report as the stage kept it, redacted and canonical, the digest of an entry of the evidence register. That entry's `source` is the report as the pipeline gave it. Every evaluation from the report names it as its `input_digest`. |
| `observations` | string | Where the stage kept the [ScannerObservations](#scannerobservations) it read from the report, in the record's directory, the path of an entry of the evidence register. |
| `results_read` | integer | The results the observations hold, from 0. |
| `unreadable_results` | integer | Results of the report the stage could not read, from 0. Each decides nothing. |
| `written_configuration_results` | integer | Results about the configuration as written, which no stage reads, from 0. They are left out of the observations' `results`. |
| `tool_parsing_errors` | integer or null | Files the scanner itself says it could not parse, from 0, or `null` when the scanner does not say. A value above 0 means the scanner did not cover everything it was given; 0 does not show that everything was parsed. |
| `redacted_values` | object | For each reason, how many redaction markers that stand for a value (`present: true`) the report holds as the stage kept it; `{}` when it holds none. Each key is a reason token (`iltero_schemas.models.redaction.RedactionReason`), each count is at least 1, and at most 64 reasons are listed (`MAX_REDACTION_REASONS`). |

`redacted_values` says what the kept report file holds, not what the redaction policy did. A marker in a field the
[kept form](#the-report-a-stage-keeps) drops is not in the file, so it is not counted. A reader counts with
`iltero_schemas.models.redaction.redacted_value_counts`, which walks the object values and list items of the kept
report, never its keys and never the inside of a marker. A marker at a field the reader reads, such as a rule id or an
address, makes that result unreadable, so it is also counted in `unreadable_results`.

A stage's redaction report (`redaction`) says what the stage's redaction hid, left unknown or allowed, by
path. It holds no value.

| Field | Type | Meaning |
| --- | --- | --- |
| `policy` | object | The redaction policy that ran: `id`, `version` (identifiers) and `digest`. |
| `input` | object | What was redacted: `kind` and the `digest` of the redacted tree. The `kind` is what the stage reads: `observation` at `plan`, `facts` at `pre_deploy`, `deployment` at `post_deploy`, `drift_check` at `post_verify` (`iltero_schemas.models.stages.REDACTED_INPUT_KIND`): "the pre_deploy stage's redaction report is of the facts it read". A post-verify stage's `resource_redaction` is of kind `post_apply_resources`: "the post-verify stage's resource redaction is of the values after the apply". |
| `redacted` | list | Each path the policy hid: `path`, and `reason`, a token of a lowercase letter followed by up to 63 lowercase letters, digits or `_`. |
| `unknown` | list | The paths left unknown. |
| `allowed` | list | Each path the project allowed through: `path`, and `reason`, the project configuration's own words: one line of plain text, at most 1024 characters. |

At `post_deploy` and `post_verify` the record keeps the part the stage counts as it is, so the redaction report is of
that part and redacts nothing (`iltero_schemas.models.stages.STAGES_THAT_REDACT_NOTHING`). Its `input.digest` is the
stage's `coverage.subjects_in_scope.source_digest`, the digest of the record's `change.deployment` at `post_deploy` and
of its `change.drift_check` at `post_verify`: "the post_deploy stage's redaction report is of the part it counts".
Its `redacted`, `unknown` and `allowed` lists are empty: "the post_verify stage redacts nothing: the part it counts is
kept as it is".

A path is a path in the redacted tree. Map keys are part of it, so it is kept as written: any characters, at most
64 KiB of UTF-8 (`iltero_schemas.models.fields.RAW_TEXT_MAX_BYTES`). A reader escapes it to show it, control,
bidirectional and invisible characters included. Each list holds at most 1,000,000 entries.

Each `evidence_refs` entry names one file in the record's directory:

| Field | Type | Meaning |
| --- | --- | --- |
| `ref_id` | identifier | The entry's id. |
| `media_type` | identifier | The file's media type, such as `application/json`. |
| `digest` | digest | The SHA-256 of the file's bytes. |
| `size_bytes` | integer | The file's size, from 0. |
| `path` | string | Where the file sits in the record's directory. |
| `storage_uri`, `retention_until` | null | Always `null`. |
| `collected_at` | timestamp | When the file was collected. |
| `collector` | object | The `tool` that produced the file and its `version` (identifiers). |
| `source` | object or null | The file as the pipeline gave it, before the record kept it (`EvidenceSource`): its `name`, a file name without directories, and its `digest`. Its `digest` differs from the entry's `digest` when redaction changed the file. `null` for a file the tool wrote itself. |
| `canonicalization` | identifier or null | The canonical form the file's bytes are in, such as `RFC8785`, or `null`. |
| `redaction_policy` | object or null | The redaction policy that redacted the file's content, in the shape of a redaction report's `policy`: `id`, `version` and `digest`. `null` when no redaction policy ran over the file. A tool names the policy for every file it ran over, even when the policy hid nothing. For a file kept from the pipeline in an `image_build` or `image_deploy` record, `null` means the stored copy is the file as given: its `digest` equals `source.digest`. |

A redacted file can be a tool's output, such as the plan kept after redaction, or a file the record wrote, such as an
evaluation context. An entry's `digest` is of the file's bytes; a stage's `redaction.input.digest` is of the redacted
tree the report describes. The two are equal when the file holds that tree's canonical JSON, as the plan stage's
redacted plan does, which the evidence register finds by that digest.

A stage's `coverage.subjects_in_scope.excluded` lists the plan resources left out of the subjects in scope, at most
100,000:

| Field | Type | Meaning |
| --- | --- | --- |
| `plan_index` | integer | The resource's index in the plan's resource list, from 0. |
| `id` | string or null | The resource's address as the plan wrote it, kept as written whatever its characters, at most 64 KiB of UTF-8. `null` when it was redacted. |
| `reason` | string | `not_managed` (not managed by the configuration), `deposed` (an old copy a replacement set aside), `identity_redacted` or `identity_unnameable` (an identity redacted, or one that cannot be named). |

The contract decides each reason from the resource's own entry in the plan the stage kept
(`iltero_schemas.models.iac.plan_exclusions.exclusion_reason`). The reason is the first of these that holds:

| Order | `reason` | When |
| --- | --- | --- |
| 1 | `identity_redacted` | Any naming field holds a whole redaction marker (`__redacted: true`, `reason`, `present`, `type`; `iltero_schemas.models.redaction.RedactedMarker`), whatever the other naming fields hold. |
| 2 | `identity_unnameable` | A naming field is empty text, is longer than its limit, or holds a control character. |
| 3 | `not_managed` | The resource's `mode` is not `managed`. |
| 4 | `deposed` | The resource's `deposed` holds a value. |
| 5 | `identity_unnameable` | The resource's provider has no short name an assertion can target. |

When none holds, the plan gives no reason to leave the resource out. A naming field that is absent or `null` is not
checked. A naming field that holds any other value that is not text, such as a number, a list, an object or part of a
marker, means the plan is not one a stage keeps: `exclusion_reason` raises `ValueError`, and a reader reports the
stage as one that "names a plan its reader cannot read".

Each IaC tool names its own naming fields (`iltero_schemas.models.iac.tools.variants.PLAN_NAMING`). For
`terraform`, the naming fields are `address` and `module_address`, at most 2,048 characters each, and `type` and
`provider_name`, at most 256 characters each. The provider's short name is the last segment of `provider_name`, such
as `aws` for `registry.terraform.io/hashicorp/aws`; it must match `^[a-z][a-z0-9_-]*$` and be at most 32 characters.

A resource excluded for its identity is also a gap whose `kind` is the exclusion's `reason` and whose `plan_index` is
the resource's, listed once, and every identity gap names such a resource: "the identity gaps name, once each, the
resources the scope excludes for their identity, by the same reason". A plan resource is excluded at most once: "a
plan resource is excluded once, for one reason".

A stage's `coverage.gaps` lists what is missing from what the stage evaluated. Each gap has one of five shapes,
chosen by its `kind`:

| `kind` | Other field | Meaning |
| --- | --- | --- |
| `plan_incomplete`, `plan_not_applyable` | `value`: `false` or the `not_reported_by_tool` marker | A plan flag that is not `true`. The kind names the flag (`plan_incomplete` for `complete`, `plan_not_applyable` for `applyable`) and `value` carries what the plan said: `false` means the plan said so, the marker means it did not say. |
| `identity_redacted`, `identity_unnameable` | `plan_index`: integer from 0 | A plan resource whose identity was redacted or cannot be named, by its index in the plan's resource list. |
| `deferred_changes`, `related_copies_omitted`, `unresolved_references`, `checked_after_deployment`, or a `not_evaluated` or `error` [status reason](#assuranceevent) | `count`: integer from 1 | How many of one thing are missing: what the plan left out, checks the plan stage [postponed until after the deployment](#checks-postponed-until-after-the-deployment), or combined verdicts the reason left undecided (see below). |
| `state_not_read` | none | The state after the apply was not read, so no outcome of the apply was held to it (`StateNotReadGap`; see [When the state after the apply was not read](#apply-with-the-state-not-read)). |
| `evaluator_did_not_decide` | `engine`, `reason`, `count`: integer from 1 | How many of the stage's evaluations by one evaluator (`engine`, as its events name it) could not decide an assertion about a subject, where the subject's combined verdict does not count them, and why (`reason`, a `not_evaluated` or `error` [status reason](#assuranceevent)) (`EvaluatorDidNotDecideGap`; see below). |

A gap in a stage's own `coverage` names no `stage`: the field is left out or `null`. The record's combined `coverage`
names the stage each gap came from.

A stage lists, for each `not_evaluated` or `error` reason (`iltero_schemas.models.coverage.UNDECIDED_REASON_GAP_KINDS`),
one count gap whose `count` is the number of its [combined verdicts](#how-evaluators-combine) that are
`not_evaluated` or `error` and that the reason gave: the reasons of the evaluations that reached the verdict (an
engine in `decided_by`, with the verdict's status), each counted once per verdict
(`iltero_schemas.models.verdicts.undecided_reason_counts`). A reason that left nothing undecided is not listed. The
integrity checks recompute the counts from the events: "does not count, for each reason, the verdicts of the stage it
left undecided", at `stages.<stage>.coverage`.

A combined verdict can rest on an evaluation that could not decide and that the verdict does not count: OPA could not
run the assertion's rule while Checkov decided it, Trivy names no resource for a passing check, or a scanner did not
evaluate a check while OPA ended in error. The verdict stands, and the stage lists, for each evaluator and reason, one
`evaluator_did_not_decide` gap. Its `count` is the number of the stage's evaluations by that evaluator that are
`not_evaluated` or `error` with that reason, less those the subject's combined verdict counts: a verdict of the same
status, reached by that evaluator (its engine in `decided_by`). An evaluation beside a decided verdict, beside an
undecided verdict another evaluator reached, or beside one with another status is counted in the gap
(`iltero_schemas.models.verdicts.evaluator_did_not_decide_counts`; a writer builds the gaps, sorted by evaluator and
reason, with `evaluator_did_not_decide_gaps`). An evaluator and reason that left nothing undecided are not listed.

| Rule | Refused with |
| --- | --- |
| A stage lists each evaluator and reason once. | "a stage lists each evaluator and reason that did not decide once" |
| `reason` is a `not_evaluated` or `error` status reason (`UNDECIDED_REASON_GAP_KINDS`). | "reason is a reason an evaluation is not evaluated or in error" |
| The gaps are the counts the stage's events give, an integrity check at `stages.<stage>.coverage`. | "does not count, for each evaluator and reason, the evaluations that could not decide and that no undecided verdict of the stage counts" |

A gap whose `reason` is an `error` reason marks the stage `incomplete` with reason `required_policy_evaluation_failed`
and the `detail` `evaluator errors outweighed by another evaluator's verdict on the same assertion: <count>`, with the
sum of those gaps' counts. A stage with a combined verdict that is `error` keeps that verdict's detail instead,
`<n> of <evaluations> evaluations ended in an evaluator error`. A gap whose `reason` is a `not_evaluated` reason is
listed only: it changes neither the verdict nor the status.

The kinds a count gap may name are
`iltero_schemas.models.coverage.COUNT_GAP_KINDS`. A coverage lists at most
`iltero_schemas.models.coverage.MAX_GAPS` gaps.

The `state_not_read` gap:

- The `post_deploy` stage of an `iac_change` record lists it exactly when `change.deployment.apply.state` is the
  `state_not_read` marker, an integrity check: "does not match change.deployment.apply.state: one state-not-read gap
  exactly when the state after the apply was not read".
- A stage lists it at most once: "a stage lists the state not read once". No other stage lists it: "the plan stage
  lists the state not read, which only the post-deploy stage lists".
- A record of an activity whose `reads_a_state_after_the_apply` is `False` (see [Change types and
  activities](#change-types-and-activities)) refuses it: "the post_deploy stage lists the state not read, which a
  record of image_deploy never has".
- A stage that lists it is a coverage gap, exit code `6`, whatever its checks found, and `incomplete` with reason
  `state_not_read` and the `detail` `the state after the apply was not read, so no outcome of the apply was held to
  it`. Within the stage, an evaluator error's reason wins over it.

Each `out_of_scope` entry names a `stage`, a `reason` and `declared_in`. The stages each reason can leave out are
the record's activity's (see [Change types and activities](#change-types-and-activities)). An `image_build` record
leaves out no stage. An `image_deploy` record can leave out only `post_verify`, for any of the three reasons; it may
call it `not_supported` whatever the workload, since the workload may be of a kind no reader reads. For
`iac_change`:

| `reason` | Meaning | Stage it can leave out | `declared_in` |
| --- | --- | --- | --- |
| `project_config` | The project declared the stage out of scope. | `pre_deploy` or `post_verify` | The project file that says so, by its `path` and its `digest`. |
| `environment_policy` | The environment policy of the environment Iltero Platform opened the run for does not require the stage. Iltero Platform holds the policy; the record does not name it. | `post_verify`, in a record whose `governance.run_opened_by` is `server` | `null` |
| `not_supported` | The record's IaC tool cannot run the stage. | `post_verify`, for a tool with no drift reader (`iltero_schemas.change_types.not_supported_by(tool)` gives the stages a tool cannot run). A tool with a drift reader (`iltero_schemas.models.iac.drift_check.TOOLS_WITH_DRIFT_READER`: `terraform`) runs every stage, so none. | `null` |

A record's `change.drift_check` says what two readings of the unit's deployed resources found. After the apply, the
pipeline asks the IaC tool to read every resource its state holds back from the cloud, twice, through a
refresh-only plan: a plan that reads the resources and changes nothing. A resource has drifted when a reading finds
it changed or gone since the apply wrote it. The second reading, the latest, is taken at least
`minimum_interval_seconds` after the first, and what differs in it has drifted. A resource that differed in the first
reading but not in the latest is listed apart, and the check does not say why. Neither reading writes the state, so
both compare the resources with the state the apply wrote.

| Field | Type | Meaning |
| --- | --- | --- |
| `run_id` | UUID | The run the readings were taken for: the record's `run.id`. |
| `change_digest` | digest | The change the readings were taken for: the record's `change.digest`. A drift check of another change is an integrity failure: "change.drift_check.change_digest is not change.digest". |
| `tool`, `tool_version` | string, identifier | The IaC tool that took the readings, the one that applied the deployment, and its version. |
| `resources_read` | integer | The managed resources of the state, which each reading read, from 0 to 100,000. |
| `first_reading_at`, `second_reading_at` | timestamp | When each reading was taken, by the time the tool wrote into it. |
| `first_reading_digest`, `second_reading_digest` | digest | The SHA-256 of each refresh-only plan's bytes as the tool wrote them, so a kept copy can be matched to its reading. The two differ. |
| `minimum_interval_seconds` | integer | The least time the readings had to be apart, from 1 to 86,400 (a day). |
| `differences` | list | Each resource that differed from the apply in the second reading: its `address` and its `difference`, `changed` (its values changed) or `deleted` (it is no longer there). Sorted by address, each once, at most 100,000. |
| `differences_count` | integer | The number of `differences`, which an assertion compares. |
| `first_reading_only_differences` | list | Each resource that differed in the first reading but not in the latest, for a reason the check does not give: its `address` and its `difference` as the first reading found it. Sorted by address, each once, at most 100,000. No address is also in `differences`. |

The drift check keeps addresses only: no attribute value, and no copy of either reading. It reports what the
pipeline that ran the apply saw, and nothing about resources outside the state or attributes the tool does not read
back.

Key rules:

- Every path in the record is relative to the record's directory, except `units_file.path`,
  `out_of_scope[].declared_in.path` and `scanners.local_exceptions.file_path`, which are relative to the project and
  hold no `.` or `..` part and no `:` (a Windows drive or file stream). A path in the record's directory is plain
  names joined by `/`, at most 6 deep and 1024 characters, each name using only letters, digits, `.`, `_`, `@` and
  `-`, and never `.` or `..`. No two `evidence_refs` entries share a `path` or a `ref_id`.
- These files that a record's stages and events name are entries of its evidence register
  (`iltero_schemas.models.register.check_register`):

  | File | Matched by | Refused with |
  | --- | --- | --- |
  | Each stage's events file | Its `path` and `digest`, on an entry with `canonicalization: RFC8785` | "the plan stage's events file is an entry of the evidence register", or "the plan stage's events file is kept as canonical JSON (RFC8785)" |
  | Each stage's assertion index | Its `index` and `digest` | "the plan stage's assertion index is an entry of the evidence register" |
  | Each stage's copy of each binding set it applied | Each `scanners.evaluator_binding_sets` entry's `copy_path` and `digest` | "the evidence register lists the copy of each binding set the plan stage applied" |
  | What a stage read from each scanner report | The report's `observations` path | "the observations the plan stage read from its checkov report are an entry of the evidence register" |
  | Each scanner report as the stage kept it | The report's `report_digest`, on an entry that names a `source` and a `redaction_policy` and was collected as that scanner's report (`collector.tool` is the report's `tool`). Every such entry was redacted from the same pipeline file (one `source.digest`). | "the checkov report the plan stage kept is an entry of the evidence register, redacted from the file the pipeline gave" |
  | The input every event was evaluated over | Its `provenance.input_digest` | "the input every event was evaluated over is an entry of the evidence register" |
  | What the plan stage redacted | Its `redaction.input.digest`, on an entry that names a `redaction_policy` | "what the plan stage redacted is an entry of the evidence register that names the redaction policy" |
  | Each stage's copy of the project's exceptions file | `scanners.local_exceptions.copy_path` and `digest`, on an entry that names the file as its `source` (`source.name` is the file name of `file_path`, without its directories, and `source.digest` is `digest`) and have no `redaction_policy` and no `canonicalization`: the copy is the file's bytes, unredacted and as the project wrote them | "the plan stage's copy of the project's exceptions file is an entry of the evidence register, copied byte for byte from the file it names" |

  The scanner files are tied to where they came from:

  | Rule | Refused with |
  | --- | --- |
  | The register entry of the copy of a project's binding set names the file the set was read from as its `source`, with `source.name` equal to that entry's `file_name`. The register entry of the copy of the shipped set has no `source`. | "in the evidence register, the copy of a project's binding set names the file it was read from, and the copy of the shipped set names no file" |
  | Each scanner file a stage keeps (each binding set copy, its observations, the entry of each kept report, and the copy of the project's exceptions file) is an entry of its own: never another scanner file, nor any stage's events file or assertion index. The digest of a kept report or of its observations is never the `input_digest` of an evaluation that stands on no scanner's result. | "each scanner file a stage keeps is an entry of its own, not a file the record names for another part" |
  | The observations were read from the file the report was kept from: the `source.digest` of the observations entry is that of the kept report. | "the observations the plan stage read from its checkov report were read from the file that report was kept from" |

  In an `iac_change` record whose post-deploy stage has reported, the apply log the deployment was read from is an
  entry too, by its `source.digest`, which is `change.deployment.apply.source.digest`: "the apply log the deployment
  was read from is an entry of the evidence register".
- A record redacts under one policy: every stage's `redaction.policy`, every `resource_redaction.policy` and every
  `evidence_refs[].redaction_policy` that is not `null` name the same `id`, `version` and `digest`, whatever the
  validation context. The digest tells apart two policies that share an `id` and `version`.
- The first expected stage is the activity's first stage (`plan` for `iac_change` and `image_build`, `pre_deploy`
  for `image_deploy`): "a record starts at its plan stage", or "a record starts at its pre_deploy stage". `runtime` is
  never a stage of a record. Every stage of the activity is either expected or listed once in `out_of_scope`, with a
  reason that can leave it out, so an `iac_change` record always expects `plan` and `post_deploy`, and an
  `image_deploy` record `pre_deploy` and `post_deploy`. A stage left
  out by `project_config` names the declaring file in `declared_in`; any other stage is refused: "a project can leave
  out only the pre-deploy and post-verify stages". A stage that is not one the activity's `not_supported(record)`
  names is refused as `not_supported`, in a record of any activity: "the post-verify stage is supported for this
  record: expect it, or say who leaves it out", naming the first such stage. A stage left out by
  `environment_policy` other than `post_verify` is refused: "an environment's policy can leave out only the
  post-verify stage"; and only a record of a run Iltero Platform opened may name that reason: "only a run the server
  opened has an environment policy that leaves a stage out".
- A stage's verdict follows from its own counts. Exit code `6` (coverage gap), `4` (evaluator error), `3`
  (indeterminate), `1` (assertion failed) or `0` applies, and the stage takes the first in the order
  `2, 5, 9, 10, 7, 8, 6, 4, 3, 1, 0`. The record's verdict is the stage verdict that comes first in that order, and
  it names that stage. Code `3` applies only when the stage leaves more checks `unknown` than its
  `checked_after_deployment` gaps count: a postponed check is decided later, not undecided. A stage counts no more
  checks as postponed than it left unknown: "a stage counts no more checks as checked_after_deployment than it left
  unknown".
- A stage's evaluations are about one kind of subject, one its assertions can target, and the stage counts its subjects
  by that kind (`iltero_schemas.models.stages.scope_counted_from`): the plan stage enumerates the plan's resources
  (`counted_from: plan_resource_enumeration`); a change counts as its one unit (`change_unit`, with the record's
  `change.digest` as its `source_digest`); a deployment counts as its one unit (`deployment_unit`), with the digest of
  the record's `change.deployment` as its `source_digest` at `post_deploy`, and of its `change.drift_check` at
  `post_verify`; a build's artifact counts as its one unit (`artifact_unit`), with the digest of the record's
  `change` as its `source_digest`. Only the plan stage enumerates the plan's resources. A `post_verify` stage's
  evaluations about a resource settle postponed checks and are not counted as its subject kind: it still counts the
  deployment. A stage with no evaluations
  counts by the one kind its change type's assertions can target, so a `post_verify` stage with none counts the
  deployment. A stage that counts a change, a deployment or an artifact has exactly one subject in scope, none
  removed by the plan and none excluded. The record's combined coverage counts what its first stage counts: the
  plan's resources, a build's one artifact, or an image deploy's one change.
- A stage evaluates each assertion once per subject and evaluator: no two events share a stage, an `assertion.id`,
  a `subject.key` and an evaluator engine. Otherwise the record is refused: "a stage evaluates an assertion once per
  subject and evaluator". An assertion is evaluated by one stage only ("an assertion is evaluated by one stage
  only"), except that the `post_verify` stage evaluates again the plan-stage assertions whose checks it settles.
- `enforcement_mode` is the mode the stage's gate ran in. Under `enforcing`, every
  non-zero exit code stopped the pipeline. Under `advisory`, a verdict with exit code `1` or `3` did not stop it; every
  other non-zero code did. A waiver happened when a stage is `advisory` and its exit code is `1` or `3`. Only the plan
  and pre-deploy stages can be `advisory`. In a run Iltero Platform opened, Iltero Platform's policy sets it; otherwise
  it is the tool's choice. It is the writer's claim; only the CI job's own result shows what the pipeline did.
- A stage that could not read an input, such as the state of a unit it reads from, lists each replaced input once in
  `coverage.substituted_inputs`: `kind: upstream_state` and the input's `source`, the tool's address of the input (for
  a Terraform configuration, its module path and data source, with no instance key). A stage lists at most 256, sorted
  by `source` by Unicode code point; a record lists at most 256 across its stages. Its verdict still follows its
  evaluations, and it is `incomplete` with reason `upstream_state_unavailable`; an evaluator error's, a state not
  read's or the plan's reason wins when there is one.
- A `pass` or exit code `0` on a stage that lists `substituted_inputs` is a verdict on the placeholder plan, not on
  the change: a gate reads `assurance_status` with the verdict. Any other reason of any stage leads the record's
  reason over `upstream_state_unavailable`, so readers find placeholder use by `coverage.substituted_inputs`, not by
  the reason.
- The plan stage lists one plan-flag gap for each plan flag that is not `true`, with the plan's flag as its `value`,
  in kind order: `plan_incomplete` before `plan_not_applyable`. A plan-flag gap in any other stage is refused.
- A plan stage with a `plan_incomplete` gap is `incomplete` with reason `plan_not_complete`, and its verdict still
  follows its evaluations. The `detail` is `the plan says it is incomplete` (`value: false`) or `the plan does not say
  it is complete` (the marker). An evaluator error's reason wins over it; it wins over
  `upstream_state_unavailable`. A `plan_not_applyable` gap leaves the status as it is: Terraform marks a plan that
  changes nothing as not applyable.
- A record whose state after the apply was not read has no `drift_check` and no `post_verify` stage: "post-verify
  needs the identities the state after the apply gives, and the state after the apply was not read". Its `complete`
  field is `true` only when `post_verify` is out of scope, and its `assurance_status` stays `incomplete`. The record's
  `assurance_status.reason` is `state_not_read` unless a stage is incomplete for an evaluator error
  (`required_policy_evaluation_failed`), which leads it. Readers find a state not read by the post-deploy stage's
  `state_not_read` gap, or by `change.deployment.apply.state`, not by the record's reason alone.
- A record's `change.drift_check` names the record's run (`run_id`) and the IaC tool that applied the deployment
  (`change.deployment.apply.source.tool`). Its first reading is no earlier than the `post_deploy` stage's
  `observed_at`, nor than the end of the apply (`change.deployment.apply.timing.ended_at`, when the apply's timing
  is known). A first reading written without a fraction of a second (`2026-10-29T02:28:13Z`) is compared with the
  whole second each of these fell in; one written with a fraction, even `.000`, is compared exactly. The `post_verify`
  stage's `observed_at` is no earlier than its second reading, and the second reading is at least
  `minimum_interval_seconds` after the first, to the nanosecond.
- `resources_read` equals the number of managed resources the record's identities list (`change.identity.resolved` and
  `change.identity.unresolved`), and every `differences[].address` and `first_reading_only_differences[].address` is one
  of their addresses. `differences_count` equals the number of `differences`, no address is in both lists, and the two
  lists together hold at most `resources_read` entries. `first_reading_digest` and `second_reading_digest` differ.
- The model runs the integrity checks: it recomputes every value a reader can recompute and refuses a record whose value
  differs. They cover the change digest and the digests bound to it (the pre-deploy stage's
  `coverage.subjects_in_scope.source_digest`, each approval of a change and `change.drift_check.change_digest`), the
  counts from events, each stage's verdict and status, the plan stage's plan-flag gaps, the post-deploy stage's
  `state_not_read` gap (see the gap's rules above), the status each built-in check must have, the combined top level and
  the record's id. The record's `metadata.uuid` is the one its `run.id` and `unit` give, or "is not the id of the
  record's run and unit" at `metadata.uuid`. A stage's `events.count` is the number of its events, or "does not count
  the stage's events" at `stages.<stage>.events`. A stage's `events.digest` is the digest of the bytes
  `events_file_bytes` gives for its events, or "is not the digest of the stage's events" at
  `stages.<stage>.events.digest`; when it is, the register entry of the events file has their size, or "is kept in the
  register at another size than its events" at `stages.<stage>.events`. These events-file problems are listed after
  every other. A stage's `coverage.evaluations` is the number of its [combined
  verdicts](#how-evaluators-combine), or "does not count one evaluation per assertion and subject of the stage", and its
  `coverage.status_counts` count their statuses, or "does not count the combined statuses of the stage's evaluations",
  and its undecided-reason count gaps and its `evaluator_did_not_decide` gaps (see the gaps above), all at
  `stages.<stage>.coverage`. An event's `status_reason`
  is `state_not_read` only in an `iac_change` record whose state was not read, at `post_deploy`; otherwise it is an
  integrity failure at `events.<index>.evaluation.status_reason`: "names a state not read the record does not". In an
  `iac_change` record, `ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN` must be `pass` exactly when
  `change.deployment.plan` has the evaluated plan's `digest`, `artifact_digest` and `artifact_digest_source`, and `fail`
  otherwise; `ILT.IAC.DEPLOYMENT.DRIFT.NO_DRIFT_AFTER_APPLY` must be `pass` exactly when
  `change.drift_check.differences_count` is 0, and `fail` otherwise. An event of either check whose status is one a
  policy answers with (`pass`, `fail`, `unknown` or `not_applicable`, `iltero_schemas.models.event.POLICY_STATUSES`) and
  not the recomputed one is an integrity failure at `events.<index>.evaluation.status`: "is not fail, what the record's
  change gives". An event that is `not_evaluated` or `error` decides nothing and is not compared. The `image_deploy`
  checks are recomputed the same way (see [The `image_deploy` body](#the-image_deploy-body)). The change digest problems
  come first, so a forged `change.digest` is refused as
  `change.digest is not the digest of the change type, unit, environment and plan`. A reader that reports integrity
  failures itself sets `SKIP_INTEGRITY_CHECKS` (`iltero_schemas.models.car`) to `True` in the validation context (any
  other value is ignored), then calls `iltero_schemas.models.stages.integrity_problems`, which returns every problem as
  a `(where, what)` pair. An approval of another run is refused whatever the context. A reader must also call
  [`scanner_evidence_problems`](#the-check-a-reader-runs) on every record that holds an evaluation from a scanner's
  results: the model alone does not check these evaluations.
- A record of a run the tool opened (`governance.run_opened_by: local`) names no Iltero Platform bundle, no
  evaluation from one, no facts from Iltero Platform, and no stage `reference_time` from it (`source: server`). Every
  stage's `coverage.assertions_expected.origin` is `server_pinned` exactly when Iltero Platform opened the run
  (`governance.run_opened_by: server`): "stages.plan: counts its assertions as server_pinned exactly when the server
  opened the run". In a record of a run Iltero Platform opened for an activity whose run is a change
  run (`run_type: change`), `subject.environment` names the environment the run was opened for. A build run belongs
  to no environment, whoever opened it. Either way the record is the writer's own: only Iltero Platform can confirm a
  run it opened, by its `run.id`.
- In a record of a run the tool opened, an `ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED` event is never `pass`, `fail` or
  `not_applicable`, and when it is `unknown` its `status_reason` is `server_facts_unavailable`. An event that was not
  evaluated or that ended in `error` is accepted. Otherwise the record is refused:
  "ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED is unknown with reason server_facts_unavailable, never pass, fail or
  not_applicable, on a run the tool opened: only a server that opened the run reviews its commits".
- In a record of a run Iltero Platform opened, an `ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED` event that is `pass` or
  `fail` read its facts from Iltero Platform (`provenance.facts_source: server`):
  "ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED passes or fails only on facts read from the server".
- Every event's `provenance.checked_content` is the record's [checked content](#checked-content): "every event names
  the content the record's change checked". Every event's `evaluation.activity` is the record's `change.activity`:
  "every event names the record's activity".
- In an `iac_change` or `image_deploy` record, `change.digest` is the [change digest](#the-change-digest) of the
  record's change type, its `unit`, its `subject.environment` and its checked content. Approvals bind to it. An
  `image_build` record has no change digest.
- A record's `subject.unit` is its `unit`. When `units_file` is set, the record's `unit` is one of its units' names:
  "the record's unit is one of the units its units file declares".
- Across records: the records of one run share `run.id`, and every one of them names the same `units_file`, or
  every one names `null`. The run has a record for each declared unit when the records' units are the names in
  `units_file.units`. The units file is the writer's copy: records cannot show a run with no record at all, or a
  units file the writer left out or shortened. Only the file at the record's commit can, by its digest.
- A stage's `coverage.assertions_expected.required_assertion_digest` is the digest of the assertions it owed, whether
  or not each was evaluated: as the project's files gave them (`origin: project_files`), or as Iltero Platform set
  them for the run (`origin: server_pinned`). The integrity checks recompute it: `assertions_expected.value` is the
  stage's assertion index count (`assertions.count`), or "is not the count the stage gives its assertion index";
  and, for a stage not cut short (`coverage.truncated.value: false`), the count and the digest are those of the
  `(id, version, digest)` set of the stage's events, or "does not describe the assertions of the stage's events", both
  at `stages.<stage>.coverage.assertions_expected`. The digest and count describe the stage's events and its assertion
  index; a writer that leaves out an owed assertion and its events still agrees with itself. A check the plan stage
  postponed is owed by the plan stage: the `post_verify` stage's set leaves out the assertions it evaluates to settle
  one. What a stage owed is shown
  only against the project's assertion files at `source_commit`, or the set Iltero Platform pinned for the run.
- These rules establish consistency only. An unsigned record cannot prove that Iltero Platform opened its run. Only
  Iltero Platform can confirm a run, by its `run.id`.
- `compiler.contract_digest` is the SHA-256 over the sorted `path,hash` lines of the wheel's `RECORD` entries for the
  package's own files. `iltero_schemas.distribution.installed_identity()` returns it for the installed package. An
  editable install has none.

### Evaluations from a scanner's results

A scanner, such as Checkov or Trivy, runs in the pipeline, outside the tool that writes the record. The plan stage of an
`iac_change` keeps, for each scanner report it was given, the report in the contract's kept form (see [The report a
stage keeps](#the-report-a-stage-keeps)), the [ScannerObservations](#scannerobservations) it read from it, and the plan
it evaluated, and it keeps a copy of each [evaluator binding set](#evaluatorbindingset) it applied. For each assertion a
set binds that the stage evaluates, and each scanner evaluator of that binding whose tool's report the stage kept, the
stage gives every subject in scope one evaluation from that scanner's results, beside the assertion's own evaluation
when it has a rule. The stage's verdict for the assertion and subject [combines](#how-evaluators-combine) them. The
subjects in scope are the ones the stage's events name and, for an assertion that only scanners decide, every managed
resource of the plan of one of the target's resource types that the plan does not delete or forget and that the stage's
coverage does not exclude for its identity (`identity_redacted` or `identity_unnameable` in
`coverage.subjects_in_scope.excluded`, matched by `plan_index`; `iltero_schemas.models.iac.scanner_scope.plan_scope`).
A [deposed object](#deposed-objects-terraform) shares the address of the live resource that replaces it, so only the
live resource gives the paths the plan knows only after the deployment.

By default a binding is a lookup table, never a requirement: a scanner whose report the stage was not given adds no
evaluation, and a check bound nowhere is kept in the observations as evidence, never turned into a verdict. An
assertion that only scanners decide, for which no report the stage was given has bound checks, is `not_evaluated`
with `no_scanner_report`.

Requiring a scanner (`scanners.required_scanners`) makes a missing report a gap. A required scanner whose report the
stage was not given gives each subject its bound checks cover, the same subjects in scope as for a kept report, one
evaluation: `not_evaluated` with `scanner_not_run` (`iltero_schemas.models.scanner_evaluator.SCANNER_NOT_RUN`). Its
evaluator names the scanner with `version: null`, its `provenance.input_digest` is `null`, it names no result address,
unknown path or failed check, all its `rule_ids` are undecided, and it names its `evaluator_binding`. It
[combines](#how-evaluators-combine) as a gap no pass fills.

#### The report a stage keeps

A stage keeps each scanner report in the contract's kept form: a new document that holds only the fields the tool's
reader reads, plus each check's title and severity and, for Checkov, the reason the scanned source gives for skipping
a check. `iltero_schemas.models.iac.scanner_reports.readers.kept_report(tool, report)` gives it, through the tool's
`kept_checkov` or `kept_trivy`, which `SCANNER_REPORT_READERS` registers beside the tool's reader. The kept form reads
into the same observations as the whole report. It keeps no field that holds the plan's values, file paths, source
lines, secrets or rendered source.

| Tool | Fields kept |
| --- | --- |
| `checkov` | For each framework (the report, or each entry of a list of them): `check_type`, `summary.checkov_version`, `summary.parsing_errors`, and, of `results`, only `passed_checks`, `failed_checks` and `skipped_checks`. For each of their results: `check_id`, `check_name`, `severity`, `resource_address`, `resource`, `check_result.result`, `check_result.evaluated_keys`, `check_result.suppress_comment` and `connected_node.resource_address`. |
| `trivy` | `Trivy.Version`, and for each entry of `Results`: `Type`, and for each entry of its `Misconfigurations`: `ID`, `Title`, `Severity`, `Status` and `CauseMetadata.Resource`. |

A kept field holds its value only when the value has the kind the reader reads:

- A string or `null` is kept as written, and so is an integer for `summary.parsing_errors` and a list of strings for
  `evaluated_keys`.
- A whole redaction marker (`iltero_schemas.models.redaction.RedactedMarker`, checked by `is_redaction_marker`) is kept
  as written, wherever it stands in place of a kept value, an object, a list or a name in `evaluated_keys`. A stage
  keeps a report in its kept form and then redacts it, so a kept and redacted report is its own kept form. The reader
  refuses most markers in place of an object or a list (see [Hidden objects, lists and
  counts](#hidden-objects-lists-and-counts)).
- A value the reader reads only for its shape, a list or Trivy's `Trivy` object, that is not of that shape is kept as
  `null` when it is `null`, and otherwise as `true` or `false`, its truth, never as text. These are each of Checkov's
  result lists, and Trivy's `Trivy`, `Results` and `Misconfigurations`, and a whole Trivy report that is not an
  object. An `evaluated_keys` that is not a list of strings and redaction markers is kept the same way.
- An object the reader reads that is `null` is kept as `null`. Any other value there that is not an object is kept as
  its truth, never as `null`, so the reader never reads it as absent. This holds for a list entry, a Checkov framework,
  `summary`, `results`, `check_result` or `connected_node`, and a Trivy `CauseMetadata`.
- Any other value is kept as its truth. The reader reads it the same way, and it holds none of the tool's text.
- A field the report leaves out stays out of the kept form.

The reader only counts the results of a Checkov framework whose `check_type` is the word for the configuration as
written (`terraform`), is not text, or names no input a binding reads, such as a secrets or Dockerfile scan. Each such
result keeps only its `check_result` and `connected_node`, each as written when it is `null` or a redaction marker
and as its truth when it is not an object. An object `check_result` keeps only its `evaluated_keys`, as its truth; an
object `connected_node` is kept as `{}`. A result that is not an object is kept as `null` when it is `null` and as its
truth otherwise. That is just enough for the kept framework to be counted, and read, the same way as the one given.

The evidence register entry of a kept report names, in `source.digest`, the file the pipeline gave, whole.

#### How a scanner's results decide a subject

A result is about a resource only when its address names exactly one resource of the plan the stage evaluated. Each
tool writes addresses its own way, and the rule for each is exact, never a guess by name
(`iltero_schemas.models.iac.scanner_addresses`). Results are resolved against every managed resource instance of the
plan, whatever its action (`plan_resource_addresses`).

| Tool | Address it writes | Resolves when |
| --- | --- | --- |
| `checkov` | The plan's own address, such as `module.db.aws_db_instance.main`. | The plan has that address. |
| `trivy` | The resource's type and name without its instance key; inside a module, followed by `_` and the MD5 digest of the module path, such as `aws_db_instance.main_<MD5 of "module.db">`. | Exactly one resource of the plan is written that way. Resources made by `count` or `for_each` share one address, so a result about one of them is `ambiguous`. |

A result that resolves to no resource gives the reason: `not_in_plan`, `ambiguous`, or `no_address` when the tool
wrote none.

A result is about the subject when its plan address is the subject's own (`subject_match: exact_address`), or the
address of a resource whose configuration refers to the subject in the same module instance (`plan_configures`, such
as an S3 bucket's public access block, read from the plan's own configuration by
`iltero_schemas.models.iac.plan_relations.plan_configures`). Only results of the evaluator's `input_kind` count. For a
scanner version the evaluator's `tool_version_constraint` does not admit, every subject is `not_evaluated` with
`scanner_version_not_allowed`.

Otherwise the first row that holds gives the verdict (`iltero_schemas.models.iac.scanner_verdicts.scanner_verdicts`):

| Status | `status_reason` | When |
| --- | --- | --- |
| `fail` | none | A bound check failed for the subject. |
| `unknown` | `scanner_result_unresolved` | A bound check failed for an `ambiguous` address the tool writes for the subject: the failure may be about it. |
| `unknown` | `scanner_result_unresolved` | A bound check failed for no resource of the plan at all: the tool wrote no address (`no_address`), or one the plan does not hold (`not_in_plan`). The failure may be about the subject, so neither a suppression nor a tool's silence explains it. |
| `not_evaluated` | `suppressed_in_source` | The scanned source asked the tool to skip a bound check for the subject, and nothing else is left open: the stage read the whole report (no `unreadable_results` and no `tool_parsing_errors`), no other result about the subject is a word that is not a decision, and every bound check without a decision is suppressed too or, for a tool that names a resource only when a check fails (`trivy`), has no result. Otherwise the rows below decide. |
| `unknown` | `scanner_report_incomplete` | A bound check gave a word that is not a decision for the subject. |
| `unknown` | `scanner_report_incomplete` | The report holds results the stage could not read (`unreadable_results`), or the tool says it could not parse files (`tool_parsing_errors`): the missing result may be a failure. This holds for every tool, before the rows about a check with no result. |
| `not_evaluated` | `tool_reports_only_failures` | A bound check has no result for the subject, from a tool that names a resource only when a check fails (`trivy`). |
| `unknown` | `not_reported_by_tool` | A bound check has no result for the subject, from a tool that reports passes. |
| `unknown` | `known_after_deploy` | Every bound check passed, but a key a result read, or a path of the binding's `paths_read`, reaches a value the plan knows only after the deployment. |
| `unknown` | `scanner_result_unresolved` | Every bound check passed, but a bound check failed for an `ambiguous` address the tool writes only for other resources, or a passing result about two resources names a second one the stage could not find. |
| `pass` | none | Every bound check passed for the subject. |

A tool's word is a decision only as `TOOL_DECISIONS` lists it, and a suppressed result is never one.

#### What the record holds

The model refuses a record that breaks one of these rules
(`iltero_schemas.models.scanner_results.check_scanner_results`):

| Rule | Refused with |
| --- | --- |
| The stage kept a report of the evaluation's scanner, unless the evaluation is `scanner_not_run`. | "the plan stage kept the trivy report an evaluation from trivy's results reads" |
| Only a scanner the stage requires, and kept no report of, is `scanner_not_run`. | "only a scanner the plan stage requires and kept no report of is scanner_not_run" |
| The evaluation names that report's `report_digest` as its `input_digest`. | "an evaluation from trivy's results names as its input the trivy report the plan stage kept" |
| The evaluator's `version` is the report's `tool_version`. | "an evaluation from trivy's results names the version of trivy that wrote the report the plan stage kept" |
| The entry named as shipped (`origin: shipped`) is the set this package ships, `iltero_schemas.bindings.SHIPPED_SET`: the same `id`, `version`, `digest` (`SHIPPED_SET_DIGEST`) and `assertions_bound`. | "the plan stage's binding set named as shipped is the one this package ships" |
| A scanner verdict on an Iltero starter assertion (`assertion_source: contract_starter`) names an evaluator of the shipped set (`SHIPPED_SET_EVALUATORS`), and the shipped set binds that assertion (`SHIPPED_SET_ASSERTIONS`). | "a scanner verdict on an Iltero starter assertion comes from a binding in the set Iltero ships" |
| Every other scanner verdict is on one of the project's own assertions: its `assertion_source` is `local` or `custom_rego`, and its id's namespace does not start with `ILT`. | "a scanner verdict is about an Iltero starter assertion or one of the project's own assertions" |
| A scanner verdict on one of the project's own assertions needs a project's set among the stage's binding sets, and names no evaluator of the shipped set. | "a scanner verdict on one of the project's own assertions comes from a binding in the project's own binding set" |

#### The check a reader runs

The binding sets, the observations, the report, the plan and the assertion documents are files the record keeps, not
part of the record, so the model cannot check them alone.
`iltero_schemas.models.scanner_results.scanner_evidence_problems(car, files)` does. Every reader of a record that
holds an evaluation from a scanner's results must call it, on a record whose structure holds, and must not trust the
record while it returns any problem. `files` is a `KeptFiles` (`iltero_schemas.models.kept_files`), each file as read
from its JSON or YAML, except the exceptions files, which are given as their bytes, unparsed, so the contract checks
their digest and reads them one way for every reader:

| Field | Keyed by |
| --- | --- |
| `binding_sets` | The `copy_path` of each entry of the stage's `scanners.evaluator_binding_sets`. |
| `observations` | Each report's `observations` path. |
| `reports` | Each report's `report_digest`. |
| `plans` | The digest of the plan as the stage kept it, redacted (`ScannerObservations.plan_digest`, the digest of the one plan of the evidence register). |
| `assertions` | The digest of each assertion document (`AssertionRef.digest`). |
| `exceptions` | The `digest` of each stage's `scanners.local_exceptions`; each value is the bytes of the stage's copy. |

For each stage that keeps `scanners`, it reads the copy of each binding set, then each report's observations, rebuilt
from the kept report and plan by the tool's reader, then every evaluation the sets and those observations give, and the
`scanner_not_run` evaluation of each required scanner that gave no report. When the stage kept no report, it reads
the subjects in scope from the one plan of the evidence register. It returns `(where, what)` pairs. Among them:

| Where | What | Meaning |
| --- | --- | --- |
| `stages.<stage>.scanners.evaluator_binding_sets.<n>` | "is not given", "is not a binding set", "does not name its copy's digest", "does not name the copy's id, version and number of assertions bound", "is a project's set in Iltero's namespace, or one that decides an assertion of it" | The copy of the set at position `<n>` of the list, counted from 0, does not hold. Every copy that does not hold is listed, and no other problem of the stage. |
| `stages.<stage>.scanners` | "keeps no one plan its scanner reports can be read against" | The evidence register does not hold exactly one plan collected for the stage's IaC tool (`collector.tool: terraform_plan`, `iltero_schemas.models.iac.tool_names.PLAN_COLLECTORS`). |
| `stages.<stage>.scanners.reports.<index>` | "names observations that are not the ones its report and plan give", "does not count what its observations hold" (`results_read`, `unreadable_results`, `written_configuration_results` or `tool_parsing_errors`), and the other report problems | The observations, the report or the plan do not hold. The report's evaluations are not checked further. |
| `stages.<stage>.scanners.reports.<index>` | "keeps more of its scanner's report than the contract keeps" | The kept report is not its own [kept form](#the-report-a-stage-keeps): the canonical bytes of what `kept_report` gives for it are not the report's. |
| `stages.<stage>.scanners.reports.<index>` | "does not count, for each reason, the redacted values the report the stage kept holds" | `redacted_values` is not what `redacted_value_counts` gives for the kept report. It is checked wherever the kept report is checked, after its kept form. |
| `stages.<stage>.coverage.subjects_in_scope.excluded.<n>` | "leaves out a resource for a reason the plan the stage kept does not give" | The plan does not say of the resource at the exclusion's `plan_index` what the exclusion says (`iltero_schemas.models.iac.scanner_scope.exclusion_holds`): the plan has no resource there; the exclusion's `id` is not the address the plan wrote there, when that address is text, or is not `null`, when it is not; or the exclusion's `reason` is not exactly the one the plan gives for that resource (see the order of reasons under `coverage.subjects_in_scope.excluded` in [Change Assurance Record (CAR)](#change-assurance-record-car)). Every exclusion is checked, against the plan the stage kept, for a stage that keeps a scanner report or requires a scanner. |
| `stages.<stage>.scanners` | "requires a scanner but the plan it kept is not given" | The stage kept no report, requires a scanner, and its plan is not among the files. |
| `stages.<stage>.scanners` | "keeps a checkov report that gives an evaluation the record lacks" | A subject in scope has no evaluation from that scanner. |
| `stages.<stage>.scanners` | "requires trivy, whose missing report gives an evaluation the record lacks" | A subject in scope has no `scanner_not_run` evaluation from a required scanner that gave no report. |
| `stages.<stage>.scanners` | "binds an assertion at a stage it is not evaluated at" | The evaluator's stage is not one of the assertion's stages. |
| `events.<index>.evaluation` | "is not the verdict its scanner's results give" | The status or reason differs from the verdict above. |
| `events.<index>.evaluation` | "is not evaluated although a kept report decides it" | A `no_scanner_report` evaluation where a kept report has bound checks. |
| `events.<index>.evaluation` | "is no_scanner_report although its stage requires trivy" | A `no_scanner_report` evaluation beside a required scanner's `scanner_not_run` gap. |
| `events.<index>.provenance.evaluator` | "does not name the checks, resources and unknown paths its verdict rests on" | `result_addresses`, `unknown_paths`, `failed_rule_ids` or `undecided_rule_ids` differ. |
| `events.<index>.provenance.evaluator` | "names other checks, or another match, than its binding" | `rule_ids` or `subject_match` differ from the binding's. |
| `events.<index>.provenance.evaluator_binding` | "names no evaluator of its stage's binding sets", "names a binding of another assertion", "names a binding of another tool or stage", "names another evaluator than its binding sets give it" | The evaluator digest does not lead to the binding, in any of the stage's binding sets, that decides this assertion, tool and stage. |
| `events.<index>.assertion` | "names an assertion document that is not given" | No valid document with the event's digest, id and version was given. |
| `stages.<stage>.scanners.local_exceptions` | "the record does not keep an exceptions file with the digest the stage names" | No bytes are given under the stage's `digest`, or their SHA-256 is not that digest. The stage's suppressed results are not checked further. |
| `stages.<stage>.scanners.local_exceptions` | "is not a project's exceptions file the contract can read" | `read_local_exceptions` refuses the copy (see [Reading the file](#reading-the-file)). The stage's suppressed results are not checked further. |
| `events.<index>.provenance.evaluator.local_exception` | "names an exception the kept exceptions file does not give this result" | A `suppressed_in_source` evaluation names an exception, but the kept file gives the result none, or another one. |
| `events.<index>.provenance.evaluator.local_exception` | "names no exception, but the kept exceptions file gives this result one" | A `suppressed_in_source` evaluation names no exception, but the kept file gives the result one. |

The vectors in `scanner_evidence/iac/local_run_scanned/` give the complete list of cases.

#### What these checks establish

Together, the record's rules and `scanner_evidence_problems` establish that each evaluation from a scanner's results
is the verdict the kept report, read against the kept plan, gives the subject under the binding its stage kept, and
that every subject in scope has one. They do not establish:

- that the scanner ran, or that the kept report is what the scanner wrote: the pipeline supplies the report
  (`supplied_by: pipeline`), and the writer redacts and keeps it;
- that the scanner read the plan the record names: a report the pipeline supplied is its own claim;
- that the scanner version is genuine: it is the version the report states;
- that the bound checks of a binding set read from a file decide the assertion they are bound to: such a set is the
  project's own word, not this package's;
- that anyone outside the project approved an exception: the exceptions file is the project's own word, naming who
  the project says approved each one;
- that an exception was in force when the scanner ran: it is judged at the stage's `reference_time`, which is only as
  trustworthy as its `source`.

In a self-attested record, all of this is the writer's claim.

### Checks postponed until after the deployment

A plan-stage check that read a value the plan knows only after the deployment is `unknown` with `known_after_deploy`.
The plan stage's `values_known_after_deployment` says what its gate does with such a check: `block` on it, or
`postpone` it (`iltero_schemas.models.iac.postponed_checks`). A postponed check is settled at `post_verify`, where the
same assertion is evaluated for the same subject over the resource's values after the apply, as Terraform's state
holds them, with `plan` naming the plan it was postponed from. Those values are the IaC tool's own knowledge after the
apply, not a reading of the cloud: a settled check never stands for a running state.

A check may be postponed only when its verdict at plan is unknown for that reason alone: the assertion's own rule,
which OPA runs, left a value of `resource.after` unsettled, its `when` guard settled, and every other evaluator of it
passed or left it unknown for the same reason. Its assertion has a rule, is about a resource at `plan`, and reads only
what a `post_verify` input about a resource holds (`postponable`).

Each `postponed_checks` item:

| Field | Type | Meaning |
| --- | --- | --- |
| `assertion` | object | The assertion's `id`, `version` and document `digest`. |
| `subject_key` | digest | The subject's key. |
| `path` | string | The path the rule could not settle, as the rule names it, such as `resource.after.storage_encrypted`: `resource.after.` and then letters, digits, `_`, `.` and `-`, at most 1,024 characters. |
| `plan_digest` | digest | The plan the check was evaluated over: the plan stage's checked content. |

The rules (`check_postponed_checks`):

| Rule | Refused with |
| --- | --- |
| The plan stage, and only it, names `values_known_after_deployment`. | "the plan stage, and only it, says what its gate does with a value known after deployment" |
| A stage lists `postponed_checks` exactly when it postpones. | "a stage lists postponed checks exactly when it postpones them" |
| Only the plan stage counts `checked_after_deployment` gaps. | "only the plan stage counts checks as checked_after_deployment" |
| The plan stage lists only checks it may postpone, each once. It may list fewer: a check left off the list stays `unknown` at plan and holds its gate. | "the plan stage lists, once each, only checks it may postpone" |
| A postponed check names the plan and path of the evaluation it postpones. | "a postponed check names the plan and the path of the evaluation it postpones" |
| A check is postponed only in a record that expects `post_verify`. | "a check is postponed only in a run that includes post-verify, which settles it" |
| The plan stage's `checked_after_deployment` gaps count its postponed checks. | "the plan stage counts its postponed checks as checked_after_deployment" |
| Each evaluation about a resource at `post_verify` (`settles_a_postponed_check`) settles one postponed check of the same assertion and subject, once, over the plan it was postponed from: the assertion's own rule, which OPA runs, decides it, or, when no evaluator could run, it is `not_evaluated` with no evaluator (`provenance.evaluator: null`). | "a resource evaluation at post-verify settles, once, a check the plan stage postponed" and "a postponed check is settled over the plan it was postponed from" |
| A record whose `post_verify` stage reported settles every postponed check. | "a record that reached post-verify settles every check its plan stage postponed" |
| A record with postponed checks and no `post_verify` stage is `incomplete` with reason `checks_postponed_until_after_the_deployment` (`open_postponed_checks`), an integrity check. | "is not the record's stages combined" at `assurance_status` |
| Only `post_verify` keeps a `resource_redaction`, and it keeps one exactly when it settles a check. | "only the post-verify stage redacts values after the apply" and "the post-verify stage reports what it redacted of the values its settling checks read" |

The plan stage's exit code treats its postponed checks as decided later (see the stage verdict rule above). A reader
that holds the files the plan stage kept calls `postponed_check_problems(car, files)`, with a `KeptFiles`: it lists, at
`stages.plan.postponed_checks.<index>`, each postponed check whose assertion document is not given ("names an assertion
document that is not given") or may not be postponed ("postpones a check whose condition reads what post-verify does
not hold"), and each whose path the kept plan does not leave unknown on the subject's resource ("postpones a check on a
value the plan it kept does not leave unknown"). It needs the one plan the evidence register keeps: without it, it
returns "names checks of a plan the record does not keep" at `stages.plan.postponed_checks`.

### Change types and activities

A change type is the kind of thing a change changes. An activity is one kind of work a single record describes; a
change type is made of one or more activities. A record's `change` is the body of its activity, named by
`change.activity`, and a record of any other activity is refused. The contract knows two change types:

| Change type | What it changes | Activities |
| --- | --- | --- |
| `iac_change` | Infrastructure, through an IaC tool, whichever tool. | `iac_change` |
| `image_release` | A container image, built once and released to environments. | `image_build`: the build of the image. `image_deploy`: the deployment of a built image to one environment. |

`iltero_schemas.models.change_type` names them (`IAC_CHANGE_TYPE`, `IAC_CHANGE_ACTIVITY`, `IMAGE_RELEASE_TYPE`,
`IMAGE_BUILD_ACTIVITY`, `IMAGE_DEPLOY_ACTIVITY`), and `CHANGE_TYPE_OF` gives the change type of each activity. Each
activity declares how its records are checked (`iltero_schemas.change_types.ACTIVITIES`, and the change types in
`CHANGE_TYPES`):

| Declaration | `iac_change` (`iltero_schemas.change_types.IAC_CHANGE`) | `image_build` (`iltero_schemas.change_types.IMAGE_BUILD`) | `image_deploy` (`iltero_schemas.change_types.IMAGE_DEPLOY`) |
| --- | --- | --- | --- |
| `run_type` | `change`: a run of a project's unit in an environment. | `build`: a run that builds an artifact, in no environment. | `change`. |
| `stages` | `plan`, `pre_deploy`, `post_deploy`, `post_verify`, in the order they run. A record starts at the first. | `plan` only: the image is produced and checked before any deployment uses it. | `pre_deploy`, `post_deploy`, `post_verify`: the image was checked when it was built, so the record starts where the change is approved. |
| `project_may_leave_out` | `pre_deploy`, `post_verify`. | None. | `post_verify`. |
| `environment_policy_may_leave_out` | `post_verify`. | None. | `post_verify`. |
| `not_supported(record)` | `post_verify` when the record's IaC tool has no drift reader; none for `terraform`. | None. | `post_verify`, whatever the record: the workload may be of a kind no reader reads, such as one a cloud's own service runs. |
| `required_documents` | The record at every stage, and the [resource identities](#resourceidentities) document (`resource_identities`) at `post_deploy` as well. A record whose state after the apply was not read names no identities; the document stays owed at `post_deploy`. | The record at `plan`. | The record at every stage. |
| `named_documents(record)` | None. | At `plan`, `image_index`, the raw index, only when the change's `index_evidence_ref` names one, by its `ref_id` in `evidence_refs`. The build tool's metadata file and the reports are never owed. | None. |
| `checked_content` | The record's plan (see [Checked content](#checked-content)). | The record's image. | The record's image. |
| `carried_out_matches_checked` | `ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN` at `post_deploy`. | `ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT` at `plan`. | `ILT.IMAGE.DEPLOYMENT.CONTENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE` at `post_deploy`. |
| `always_evaluated` | `ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN` at `post_deploy`, `ILT.IAC.DEPLOYMENT.DRIFT.NO_DRIFT_AFTER_APPLY` at `post_verify`. | `ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT` at `plan`. | `ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT` at `pre_deploy`, `ILT.IMAGE.DEPLOYMENT.CONTENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE` at `post_deploy`, `ILT.IMAGE.DEPLOYMENT.DRIFT.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE` at `post_verify`. |
| `reads_a_state_after_the_apply` | `True`: its records read the IaC tool's state after the apply, which can go unread (see [When the state after the apply was not read](#apply-with-the-state-not-read)). | `False`. | `False`. |

`carried_out_matches_checked` is the built-in assertion that checks that what the pipeline carried out matches what was
checked, with the stage it is evaluated at: it ties a record's evaluations to its checked content. No policy leaves it
out. `always_evaluated` lists every built-in assertion of the activity by the stage it belongs to,
`carried_out_matches_checked` among them. Once that stage has reported, the record evaluates the assertion exactly once,
at that stage only, and never as `not_applicable`, since it always has the stage's one subject:
"ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN is evaluated once, at the post_deploy stage, once it has
reported" and "ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT always applies to the plan stage's one
subject" (the id and stage are the assertion's). A record evaluates no built-in assertion of another activity:
"ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN is a built-in assertion of another activity, not of
image_deploy" (the id and activity are the record's).

### The `iac_change` body

The `change` of a record whose activity is `iac_change`: one unit's plan and, once applied, what the deployment did.

- **Model:** `iltero_schemas.change_types.IacChange`

| Field | Type | Meaning |
| --- | --- | --- |
| `activity` | string | `iac_change`. |
| `digest` | digest | The [change digest](#the-change-digest). Approvals bind to it. |
| `plan` | object | The plan the record is about (see below). |
| `deployment` | object or null | What the apply did, in the shape of an [AssuranceContext](#assurancecontext)'s `deployment`. Present exactly when the `post_deploy` stage has reported. |
| `identity` | object or null | The unit's [resource identities](#resourceidentities) after the apply. Present exactly when `deployment` is and its state was read: a record whose state after the apply was not read names none ("a record names no identities when the state after the apply was not read"). Read from the state file the apply left (`sources.read_from: state_file`), with the deployment's applied plan as `sources.plan` and its state as `sources.state`. |
| `drift_check` | object or null | What two readings of the deployed resources, taken after the apply, found (see the drift check above). Present exactly when the `post_verify` stage has reported. |

`plan` (`iltero_schemas.change_types.PlanRecord`):

| Field | Type | Meaning |
| --- | --- | --- |
| `digest`, `digest_version` | digest, identifier | The plan's digest by its tool's rule, and that rule's version. Any other version is refused. |
| `artifact_digest_source` | string | `saved_plan` when the plan was read from a saved plan file, `not_provided` otherwise. |
| `artifact_digest`, `artifact_file_name` | digest, string | The saved plan file's digest, and its file name without its directories. Present exactly when `artifact_digest_source` is `saved_plan`, and `null` when it is `not_provided`. The record keeps the file's digest and name, not the file. |
| `context_digest` | digest | The plan as kept after redaction. The plan stage counts its resources by it, and its redaction report describes it: the plan stage's `redaction.input.digest` is `context_digest`, "the plan stage's redaction report is of the plan the record names". |
| `tool`, `format_version` | string, identifier | The IaC tool that wrote the plan, which is the tool the whole record is about, and the plan's format version. |
| `tool_version`, `complete`, `applyable` | identifier, boolean | What the tool's plan says: its version, and whether the plan is complete and can be applied. Each holds the unknown marker `{"__unknown": true, "reason": "not_reported_by_tool"}` when the plan does not say; `null` is refused. |

A file name that holds `/`, `\`, `:` or a character that looks like a slash or backslash (fullwidth and small forms
included), or that consists only of dots and spaces, is refused: "must be a file name without its directories". The
name is at most 255 UTF-8 bytes as written, with no control character; only the separator and dots-and-spaces checks
use its NFKC (Unicode compatibility) form.

#### Deposed objects (Terraform)

A deposed object is an old copy of a resource that a replacement set aside, which the plan lists for deletion. When
the applied plan is the evaluated plan (`deployment.plan.digest` is `plan.digest`), the apply's deposed objects
(`deployment.apply.tool_data.deposed`) are held to what the plan stage excluded
(`coverage.subjects_in_scope.excluded`). The plan names no deposed object's key, so objects at one address are matched
by their count only.

| Rule | Refused with |
| --- | --- |
| At each address, the apply names at least as many deposed objects as the plan stage excluded there as `deposed`. The deposed objects it names beyond those, over all addresses together, number at least the plan stage's `deposed` exclusions whose address was redacted (`id: null`). | "the apply names every deposed object the plan stage left out as deposed" |
| Any more at an address are allowed only up to the plan stage's exclusions for identity (`identity_redacted` or `identity_unnameable`) at that address. The rest, over all addresses together, are allowed only up to the number of its exclusions whose address was redacted (`id: null`) and whose reason is `deposed`, `identity_redacted` or `identity_unnameable`; a `not_managed` exclusion never counts. | "the apply names no deposed object beyond those the plan stage left out as deposed or for its identity" |

### The `image_build` body

The `change` of a record whose activity is `image_build`: the container image one build of a unit pushed, the commit the
build tool's own provenance names, when it names one, and the files that describe it. An image is identified by its
digest, the SHA-256 of its manifest. An image built for several platforms is pushed as an index, the manifest that lists
one image per platform, and is identified by the index's digest. A tag is only a name a registry points at an image and
can be moved, so the record commits to the digest and keeps a tag for reading only.

The record keeps what the pipeline reported. A tag is tied to the digest by the build tool's metadata file, the platform
digests are read from the raw index the pipeline gave, the build's commit is read from the build tool's metadata file
(see [The build's commit](#the-builds-commit)), and an attestation, a signed statement about how the image was built, is
named by its digest and not verified by the record. When it was sent to Iltero Platform, Iltero Platform checks its
signature (see [The build's attestation](#the-builds-attestation)). A build belongs to no environment and deploys
nothing, so it has no change digest and nothing to approve. The commit the run's checkout was at stays in the record's
`subject.source`; it says nothing of the image.

- **Model:** `iltero_schemas.change_types.ImageBuild`

| Field | Type | Meaning |
| --- | --- | --- |
| `activity` | string | `image_build`. |
| `image` | object | The image (`ImageRef`): its `repository`, its `digest` (the index digest for an image of several platforms) and `tag_resolution`, the tag the pipeline gave, or `null` when it gave none. |
| `platform_digests` | list | The digest of each platform's image the index lists, without the build's attestation manifests: at most 64, sorted, each once, and never the image's own digest. Empty exactly for an image pushed as a single manifest. |
| `index_evidence_ref` | identifier or null | The raw index the pipeline pushed, by its `ref_id` in `evidence_refs`. `null` exactly when `platform_digests` is empty. |
| `reports` | list | The test and scan reports the build was given (`ReportRef`, see below): at most 128, sorted by `evidence_ref`, each once. Empty for a build given no reports. |
| `build_commit` | object or null | The commit the build tool's provenance names (`BuildCommit`, see [The build's commit](#the-builds-commit)). `null` when it names none. |
| `attestation` | object or null | The build's attestation file (`AttestationRef`): its `evidence_ref` (a `ref_id` in `evidence_refs`, which holds the file's digest, not its bytes), `verification: not_verified`, and `sent_to_server`, `true` when the file was sent to Iltero Platform for checking, whatever its answer, and `false` when it was never sent, as on a run the tool opened. `null` when the pipeline gave none. |

`reports` entry (`ReportRef`):

| Field | Type | Meaning |
| --- | --- | --- |
| `evidence_ref` | identifier | The report file, by its `ref_id` in `evidence_refs`. |
| `format` | string | `junit` (a JUnit XML test report), `trivy_json` or `grype_json` (a Trivy or Grype JSON scan report). |
| `image_digest` | digest | The image the report is about: the image's `digest` or one of its `platform_digests`. |
| `image_digest_source` | string | Where the tie to the image comes from: `report`, the report itself names the image's digest; or `pipeline`, only the pipeline says so. `report` is the claim of the tool that read the report: the contract does not read report contents. Always `pipeline` for a `junit` report, which names no image. A report of a scan made before the image was pushed names no pushed digest; a scan of the pushed image, read from its registry, names it. |

Each report the build's evaluations read (a `tests` or `scans` item of their [input](#assurancecontext)) is one of the
files `reports` names, matched by its `file_digest` against the entry's `source.digest`, the digest of the file as the
pipeline gave it, never against the entry's `digest`, which is of the stored copy and changes when the copy is
redacted. The record does not hold the evaluation inputs, so it cannot check this match itself; a reader that holds
them does.

`iltero_schemas.models.image.naming.platform_digests_of(index)` reads the platform digests from the bytes of a raw
index: each manifest the index lists, by its digest, sorted and each once, without a build's attestation manifests. A
manifest is skipped only when it is annotated as one (`vnd.docker.reference.type: attestation-manifest`) and its
platform is `unknown/unknown` (`os` and `architecture` both `unknown`); a manifest with a real platform counts,
whatever its annotations say. It raises `ValueError` for bytes that are not an image index as plain JSON in UTF-8: a
byte order mark, bytes that are not UTF-8, `NaN` or `Infinity`, nesting deeper than the reader can follow, a key
written twice, no `manifests` list, or a manifest not named by a `sha256` digest.
It raises `ValueError` before parsing for an index over 4,194,304 bytes (`MAX_INDEX_BYTES`): "an image index is at
most 4194304 bytes". It raises `ValueError` for an index that lists more than 64 distinct platform images
(`MAX_PLATFORM_DIGESTS`), the most a record keeps: "an image index lists at most 64 platform images". It is a pure
function, so every reader of the kept index computes the same list. The record model does not read the file: a reader
compares `platform_digests` with the function's result. The plan stage owes the raw index as its `image_index`
document, and Iltero Platform checks it with `platform_digests_of` and then discards it.

Two files of a build reach Iltero Platform: the raw index, which it checks and discards, and, when it was sent
(`sent_to_server: true`), the attestation, which it verifies and keeps by its digest so the signature can be checked
again (see [The build's attestation](#the-builds-attestation)). Iltero never reads the pipeline's own store. The
pipeline keeps the files in the run's artifact store, and the record keeps each file's digest in `evidence_refs`. The
build tool's metadata file and the test and scan reports are never sent to Iltero Platform.

`image.tag_resolution` (`TagResolution`):

| Field | Type | Meaning |
| --- | --- | --- |
| `tag` | string | The tag, as a registry accepts it: 1 to 128 characters, letters, digits, `_`, `.` and `-`, not starting with `.` or `-`. |
| `read_from` | string | `pipeline_metadata_file`: the build tool's metadata file tied the tag to the digest. |
| `read_from_evidence_ref` | identifier | That metadata file, by its `ref_id` in `evidence_refs`. No registry was asked. |

#### The build's commit

`build_commit` (`BuildCommit`) is the commit the build tool's own provenance says the image was built from. It is the
one commit the record ties to the image. `ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT` compares it
with the commit Iltero Platform verified for the run.

| Field | Type | Meaning |
| --- | --- | --- |
| `commit` | commit | The commit: 40 lower-case hexadecimal characters, or 64 for a repository that uses SHA-256. |
| `read_from` | string | `buildx_provenance`: the provenance summary in the Docker Buildx metadata file. |
| `evidence_ref` | identifier | That metadata file, by its `ref_id` in `evidence_refs`. |
| `verification` | string | `not_verified`. |

**Where it comes from.** The pipeline builds the image with `docker buildx build --metadata-file <file>` and gives the
file to the Iltero CLI. Buildx writes there the digest of the image it pushed (`containerimage.digest`), the names it
pushed it under (`image.name`) and, unless provenance is turned off, a summary of the build's provenance
(`buildx.build.provenance`). The commit is read from one place only:
`buildx.build.provenance.invocation.configSource.digest.sha1`. BuildKit, the engine behind Buildx, writes it there only
when the build context is a Git repository URL, so that BuildKit fetched the commit itself.

A build from a local directory, such as the common `context: .` after a checkout, gets a metadata file that names no
commit, whether provenance is in `mode=min` or `mode=max`. BuildKit keeps the local checkout's revision only in the
full provenance it pushes with the image, which this record does not read. For such a build `build_commit` is `null`.
An image label, such as `org.opencontainers.image.revision`, is never read as the commit: it is text the pipeline
wrote.

**How a reader reads it.** `iltero_schemas.models.image.buildx.build_metadata_of(metadata)` takes the bytes of the file
and returns a `BuildMetadata`: `image_digest`; `image_names`, the value of `image.name` split on commas; and `commit`,
or `None` when the file names no commit. It reads the file strictly (`iltero_schemas.models.strict_json`), as
`platform_digests_of` reads an index: UTF-8 with no byte order mark, each key once, and no `NaN` or other constant. It
raises `ValueError` for a file over 1,048,576 bytes (`MAX_METADATA_BYTES`), checked before the file is parsed: "a
Buildx metadata file is at most 1048576 bytes"; and for a file that is not a JSON object, that names no image digest
in `containerimage.digest`, whose `containerimage.descriptor` names another digest ("a Buildx metadata file's
containerimage.descriptor names the digest it names in containerimage.digest"), whose `image.name` is not text, or
whose commit is not a commit. It is a pure function, so
every reader computes the same result.

**How the record and the file are compared.** The record model does not read the file, so it cannot compare the two.
`iltero_schemas.change_types.check_build_metadata(build, metadata)` does. The tool that writes the record runs it, and
so can any reader later given the file from the pipeline's store: the record's digest of the file shows it is the same
file. Iltero Platform never receives the file, so it never runs the function. The function raises `ValueError` unless
the file:

| Rule | Refused with |
| --- | --- |
| Names the image's `digest` in `containerimage.digest`. | "the build tool's metadata file names the image's digest" |
| Names the image's `repository` with the record's tag, when there is one: one of its `image_names`, read without any `@digest` suffix and with its repository put in its one spelling, is the image's `repository` followed by `:<tag>`. | "the build tool's metadata file names the image's repository with its tag" |
| Names exactly the record's `build_commit.commit`, or no commit when `build_commit` is `null`. | "the build commit is the one the build tool's metadata file names, and only that" |

A name is put in its one spelling by `iltero_schemas.models.image.naming.in_one_spelling(repository)`, the way a tool
may have been given it: Docker Hub's host and `library` namespace are added where left out (`nginx` is
`docker.io/library/nginx`, `acme/api` is `docker.io/acme/api`), Docker Hub's other host names are written `docker.io`,
and the default port 443 is left out. A name with no tag, or one that is still not a repository, matches nothing.

**Which provenance mode to use.** Build with `--provenance=mode=min`. The commit is the same in `mode=min` and
`mode=max`: the `buildx/` conformance vectors read alike in both. `mode=max` also writes the build's arguments
(`invocation.parameters.args`) into the metadata file, and a build argument can hold a secret value.

**How strong it is.**

- The metadata file is unsigned and the pipeline's own. The commit is what BuildKit wrote there, not a commit anyone
  verified, so `verification` is always `not_verified`. The record names the file by the digest of the bytes the
  pipeline gave, so a reader given the file can read the commit again.
- On a run Iltero Platform opened, `ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT` compares the commit
  the record names, which the tool read from the pipeline's metadata file, with the commit Iltero Platform verified for
  the run. Iltero Platform does not check that commit against the file, which it never receives. The record's file
  digests let anyone given the pipeline's files run the checks again later.
- Only the commit is compared. The repository it names (`configSource.uri`) is not compared with the run's repository.
- A build given additional named build contexts may use files from more than that one commit.
- A record that names no tag and no build commit names no metadata file, and may keep none.

**What the check shows.** `ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT` reads `artifact.build_commit`
from its input: the commit, or the unknown marker `{"__unknown": true, "reason": "not_reported_by_tool"}` when the build
named none. The record holds the status to what it can be (see the last row of the key rules below):

| Run opened by | Build commit | Status | What it shows |
| --- | --- | --- | --- |
| Iltero Platform | Equals the verified commit | `pass` | The commit BuildKit wrote in its provenance is the commit Iltero Platform verified for the run. |
| Iltero Platform | Differs from the verified commit | `fail` | BuildKit names another commit. The record is kept. |
| Iltero Platform or the tool | None named (`build_commit: null`) | `unknown`, `not_reported_by_tool`; never `pass` or `fail` | Nothing: the build's provenance names no commit, as for a build from a local directory. |
| The tool | Named | `unknown`, `server_facts_unavailable`; never `pass` or `fail` | Nothing: only Iltero Platform verifies the run's commit. |

In every case an event that was not evaluated (`not_evaluated`) or that ended in `error` is also accepted. A `pass`
does not show that the image holds only what that commit holds: the check compares two commits, not the image's
contents.

```json
{
  "build_commit": {
    "commit": "c84e7a1000000000000000000000000000000000",
    "read_from": "buildx_provenance",
    "evidence_ref": "plan/build-metadata.json",
    "verification": "not_verified"
  }
}
```

The metadata file it is read from, in part, as Buildx wrote it for a build of a Git repository URL:

```json
{
  "buildx.build.provenance": {
    "invocation": {
      "configSource": {
        "uri": "https://github.com/docker-library/hello-world.git#master:amd64",
        "digest": {"sha1": "522bcd2faf422c60b9d20e64d7cd6d56600aec97"}
      }
    }
  },
  "containerimage.digest": "sha256:e4b3653f84a41453bb7d64680a12fddfcd00ebda7ec7323642a7773608891bdc",
  "image.name": "127.0.0.1:5000/acme/hello:min"
}
```

An image repository is written in one spelling, so that one image is never named two ways, in at most 255
characters (`iltero_schemas.models.image.naming.ImageRepository`):

| Rule | Refused with |
| --- | --- |
| It starts with its registry host: a lower-case host name holding a `.`, a host with a port, or `localhost`. Each label of the host name is at most 63 characters. An IPv6 address is not accepted. `docker.io/library/nginx`, never `nginx` or `library/nginx`. | "an image repository starts with its registry host, such as docker.io/library/nginx" |
| A port is a number from 1 to 65535, without leading zeros. | "an image repository's port is a number from 1 to 65535, without leading zeros" |
| The default port, 443, is never written. | "an image repository leaves out the default port 443" |
| Its path is lower case, with no tag or digest in it. | "an image repository is lower case, with no tag or digest" |
| Docker Hub is written `docker.io`, with no port, never `index.docker.io`, `registry-1.docker.io` or `registry.hub.docker.com`. | "an image repository on Docker Hub is written with the host docker.io" |
| On Docker Hub it names its namespace, `library` for the official images. | "an image repository on Docker Hub names its namespace, such as docker.io/library/nginx" |

Key rules:

| Rule | Refused with |
| --- | --- |
| The record's `subject.environment` is `null`, whoever opened the run. | "a build belongs to no environment" |
| `platform_digests` are sorted, each once. | "platform_digests are named once each, in order" |
| No platform digest is the image's digest. | "platform_digests are the index's children, never the index digest itself" |
| `index_evidence_ref` is set exactly when `platform_digests` is not empty. | "an image pushed as an index names both its raw index and its platform digests; an image pushed as one manifest names neither" |
| Every `ref_id` the body names is in `evidence_refs`. | "change.index_evidence_ref names a file of the record's evidence register", and the same for `attestation.evidence_ref`, `image.tag_resolution.read_from_evidence_ref` and `build_commit.evidence_ref` |
| Every report is in `evidence_refs`. | "change.reports names files of the record's evidence register" |
| `reports` are sorted by `evidence_ref`, each once. | "reports names each report once, sorted by its evidence_ref" |
| Each report's `image_digest` is the image's `digest` or one of its `platform_digests`. | "a report is about the image or one of its platform images" |
| When `platform_digests` is not empty, each `trivy_json` and `grype_json` report names one of them, never the image's own digest: a scanner given an image index reads one of its platforms. | "a scan of an image built for several platforms names the platform it scanned" |
| A `junit` report's `image_digest_source` is `pipeline`. | "a JUnit report names no image, so only the pipeline ties it to one" |
| A report's `media_type` is the type of its format (`iltero_schemas.models.image.build_reports.REPORT_MEDIA_TYPES_OF`): `application/xml` or `text/xml` for `junit`, `application/json` for `trivy_json` and `grype_json`. | "a junit report is a file of type application/xml or text/xml", or the same for the other formats |
| Every report's `evidence_refs` entry has a `source` (not `null`): the file as the pipeline gave it. A `source.digest` that is not a `sha256:` digest is refused by the entry's model. | "a report names the digest of the file as the pipeline gave it, in its source" |
| A report nothing redacted (`redaction_policy: null`) is stored as given: its `source.digest` is its `digest`. | "a report, when nothing redacted it, is stored as the pipeline gave it" |
| No two reports share a `source.digest`. | "each report is a different file as the pipeline gave it" |
| When the record has both a tag and a build commit, both are read from the same metadata file. One file may give both. | "the tag and the build's commit are read from one build tool's metadata file" |
| The raw index, the attestation, the metadata file and each report are different `evidence_refs` entries. | "the raw index, the attestation, the build tool's metadata file and each report are different files" |
| The raw index's `media_type` is an image index type (`INDEX_MEDIA_TYPES`): `application/vnd.oci.image.index.v1+json` or `application/vnd.docker.distribution.manifest.list.v2+json`. | "the raw index is a file of type application/vnd.docker.distribution.manifest.list.v2+json or application/vnd.oci.image.index.v1+json" |
| The attestation's `media_type` is a Sigstore bundle type (`ATTESTATION_MEDIA_TYPES`): `application/vnd.dev.sigstore.bundle+json;version=0.1`, `;version=0.2` or `;version=0.3`, or `application/vnd.dev.sigstore.bundle.v0.3+json`. Versions 0.1 and 0.2 are named only with the `version` parameter; 0.3 is named either way. | "the attestation is a file of type ..." with the accepted types |
| The metadata file the tag or the build commit is read from is of type `application/json`. | "the build tool's metadata file is a file of type application/json" |
| That file is kept as the pipeline gave it: no redaction (`redaction_policy: null`), and its `source.digest` equals its `digest`. | A redacted file: "the build tool's metadata file is kept as the pipeline gave it". No `source` (`null`): "the build tool's metadata file names the digest of the file as the pipeline gave it, in its source". An unredacted file whose `source.digest` is not its `digest`: "the build tool's metadata file, when nothing redacted it, is stored as the pipeline gave it" |
| The attestation is kept the same way: no redaction, and a `source.digest` equal to its `digest`. | A redacted attestation: "the attestation is kept as the pipeline gave it, so its signature can be checked again". No `source` (`null`): "the attestation names the digest of the file as the pipeline gave it, in its source". An unredacted file whose `source.digest` is not its `digest`: "the attestation, when nothing redacted it, is stored as the pipeline gave it" |
| The raw index's `evidence_refs` digest is the image's `digest`. | "the raw index's digest is the image's digest" |
| The `plan` stage counts the one image (`counted_from: artifact_unit`), with the digest of the record's `change` as its `source_digest`. | "the plan stage counts the one image the build describes, by its digest" |
| The `plan` stage evaluates `ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT`, the activity's `carried_out_matches_checked`, exactly once (see `always_evaluated` above). | "ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT is evaluated once, at the plan stage, once it has reported" |
| Every event's `facts_source` is `server` when Iltero Platform opened the run (`governance.run_opened_by: server`), and `none` when the tool opened it (`local`). The verified source comes only from Iltero Platform, so in a run the tool opened it is the unknown marker. | "every evaluation of a build whose run was opened by local reads its facts from none", or "... opened by server reads its facts from server" |
| With no build commit (`build_commit: null`), on any run, the `ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT` event is never `pass` or `fail`, and when it is `unknown` its `status_reason` is `not_reported_by_tool`. With a build commit, on a run the tool opened, the same holds with `server_facts_unavailable`. An event that was not evaluated (`not_evaluated`, such as with `evaluator_unavailable`) or that ended in `error` is accepted. | "ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT is unknown with reason not_reported_by_tool, never pass or fail, when the build names no commit", or "ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT is unknown with reason server_facts_unavailable, never pass or fail, on a run the tool opened: only the server verifies the commit" |
| On a run the tool opened, an `ILT.IMAGE.ARTIFACT.PROVENANCE.SIGNED_PROVENANCE_MATCHES_RUN` event is never `pass`, `fail` or `not_applicable`, and when it is `unknown` its `status_reason` is `server_facts_unavailable`. An event that was not evaluated or that ended in `error` is accepted. | "ILT.IMAGE.ARTIFACT.PROVENANCE.SIGNED_PROVENANCE_MATCHES_RUN is unknown with reason server_facts_unavailable, never pass, fail or not_applicable, on a run the tool opened: only the server checks an attestation" |
| On a run the tool opened, a kept attestation has `sent_to_server: false`. | "a run the tool opened sent the server no attestation" |
| An `ILT.IMAGE.ARTIFACT.PROVENANCE.SIGNED_PROVENANCE_MATCHES_RUN` event passes only when the record keeps an attestation with `sent_to_server: true`. | "ILT.IMAGE.ARTIFACT.PROVENANCE.SIGNED_PROVENANCE_MATCHES_RUN passes only for a build whose record keeps the attestation it sent the server" |

The record does not compare any commit with the commit of the run's checkout (`subject.source.commit.sha`).

```json
{
  "activity": "image_build",
  "image": {
    "repository": "ghcr.io/acme/api",
    "digest": "sha256:798f8e3fdc1ef9c987695b91a932470cec284ec0a94ebde96ffe70c0209196ae",
    "tag_resolution": {
      "tag": "1.4.2",
      "read_from": "pipeline_metadata_file",
      "read_from_evidence_ref": "plan/build-metadata.json"
    }
  },
  "platform_digests": [
    "sha256:2b6eef8cba36a744a903bbceaac9f97f85bc4d2a00e5ff7243c2f0441e5fc1d7",
    "sha256:69ee8b80f453ff0a8ea48c870a35316d4574dc35332036c6ce4a2db79c3531d9"
  ],
  "index_evidence_ref": "plan/image-index.json",
  "reports": [
    {
      "evidence_ref": "plan/reports/junit.xml",
      "format": "junit",
      "image_digest": "sha256:798f8e3fdc1ef9c987695b91a932470cec284ec0a94ebde96ffe70c0209196ae",
      "image_digest_source": "pipeline"
    },
    {
      "evidence_ref": "plan/reports/trivy.json",
      "format": "trivy_json",
      "image_digest": "sha256:798f8e3fdc1ef9c987695b91a932470cec284ec0a94ebde96ffe70c0209196ae",
      "image_digest_source": "report"
    }
  ],
  "build_commit": {
    "commit": "c84e7a1000000000000000000000000000000000",
    "read_from": "buildx_provenance",
    "evidence_ref": "plan/build-metadata.json",
    "verification": "not_verified"
  },
  "attestation": {
    "evidence_ref": "plan/attestation.sigstore.json",
    "verification": "not_verified",
    "sent_to_server": false
  }
}
```

Four starter assertions check a build at its `plan` stage, each about the `artifact` target:

| Assertion | Title | Passes when |
| --- | --- | --- |
| `ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT` | The commit the build tool's provenance names is the commit the server verified for the run | `artifact.build_commit` equals `verified_source.commit`. Its remediation: "Build the image with Buildx provenance, from the commit the run was opened for." Built in: a runner evaluates it at every build's `plan` stage (`iltero_schemas.assertions.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT`), whatever a project's own assertions are. When no verified source was supplied, or the build names no commit (`not_reported_by_tool`), it is `unknown`; see [The build's commit](#the-builds-commit). |
| `ILT.IMAGE.ARTIFACT.CHECKS.TESTS_RAN` | The pipeline gave a test report for the built image, and at least one test in it ran | Some `tests` report has more tests than skipped tests (`counts.tests` greater than `counts.skipped`) and names the image's digest or one of its platform digests. |
| `ILT.IMAGE.ARTIFACT.CHECKS.SCAN_RAN` | A vulnerability scan ran whose report names the built image or at least one of its platform images | Some `scans` report is an `image_vulnerability` scan whose report itself names the image (`image_digest_source: report`), by one of its platform digests, or by its own digest for an image pushed as a single manifest. One scanned platform image is enough: [scan coverage](#scan-coverage) says how many there are. |
| `ILT.IMAGE.ARTIFACT.PROVENANCE.SIGNED_PROVENANCE_MATCHES_RUN` | Signed build provenance names the built image and this run's repository, commit and run | `attestation_outcome.outcome` is `verified`, its `image_digest` is `artifact.digest`, and its `ci_provider`, `ci_instance`, `repository_id`, `commit`, `ci_run_id` and `ci_run_attempt` equal `verified_source`'s. `fail` when no attestation was sent (`outcome: not_sent`) or Iltero Platform refused it; `unknown` when the fact is the unknown marker. Not built in: a project adds it. See [The build's attestation](#the-builds-attestation). |

#### Scan coverage

Scan coverage says which of an image's platform images the build's scan reports name.
`iltero_schemas.change_types.scan_coverage(build)` returns a `ScanCoverage` with two sorted tuples of digests:
`platforms_scanned` and `platforms_not_scanned`. It counts the reports `ILT.IMAGE.ARTIFACT.CHECKS.SCAN_RAN` counts:
a `trivy_json` or `grype_json` report whose `image_digest_source` is `report`. An image pushed as a single manifest is
its own one platform image. A report's tie to a platform image is the report's own word, so a reader writes "scan
reports name 1 of 2 platform images", not "scanned", and shows the count even when it is 0. It is a pure function, so
every reader computes the same result from the record.

A scan of a local image, built with `--load` before the push, covers only the platform it loaded and names no pushed
digest. Scan each platform image from its registry by its digest.

#### The build's attestation

A build-provenance attestation is a Sigstore bundle. Sigstore is an open-source service and file format for signing
software. The bundle holds a signed envelope (DSSE, Dead Simple Signing Envelope) that carries an in-toto statement, a
standard JSON statement about software artifacts. The statement names its subjects, each an artifact by its digest, and
a predicate about them. A build's provenance is the statement whose predicate is SLSA provenance (Supply-chain Levels
for Software Artifacts), such as the one GitHub's artifact attestations write. The record names the file in
`change.attestation` by its digest, of the file as the pipeline gave it; it does not hold the file's bytes. The pipeline
keeps the file. `sent_to_server` says whether the file was sent to Iltero Platform for checking, whatever its answer; it
is `false` when the file was never sent, as on a run the tool opened. `verification: not_verified` is the tool's own
view: the tool never checks the signature. Iltero Platform's answer is the build's `attestation_outcome`, in its
evaluation input, and its verdict is in the `ILT.IMAGE.ARTIFACT.PROVENANCE.SIGNED_PROVENANCE_MATCHES_RUN` event.

**How a reader reads it.** `iltero_schemas.models.image.attestation.attestation_statement_of(bundle)` takes the bytes of
the bundle and returns an `UnverifiedAttestationStatement`: `subject_digests`, each subject's SHA-256 digest written
`sha256:<hex>`, sorted and once each, and `predicate_type`. A subject named only by another algorithm is left out.
`attestation_statement_of_payload(payload)` reads the same from the envelope's payload, the bytes its signature
covers. Neither checks the signature, the signing certificate or a transparency log (a public, append-only log of
signatures). A caller reads at most `MAX_ATTESTATION_BYTES` from the file before calling them. Each reads strictly
and raises `ValueError` for:

| Input | Refused with |
| --- | --- |
| More than 1,048,576 bytes (`MAX_ATTESTATION_BYTES`), checked before parsing. | "an attestation is at most 1048576 bytes", or "an in-toto statement is at most 1048576 bytes" for a payload |
| Not plain JSON: a key named twice, `NaN` or another constant, a byte order mark, or bytes that are not UTF-8. | The message of `iltero_schemas.models.strict_json`, with "an attestation" or "an in-toto statement" as its subject |
| A `mediaType` that is not a Sigstore bundle type (`iltero_schemas.models.image.naming.ATTESTATION_MEDIA_TYPES`, listed under the key rules below). | "an attestation is a Sigstore bundle that names its media type" |
| The signature of a file (`messageSignature`) instead of a signed statement. | "an attestation is a signed in-toto statement, not the signature of a file" |
| No signed envelope (`dsseEnvelope`). | "an attestation carries its statement in a signed envelope (dsseEnvelope)" |
| A plain image signature (payload type `application/vnd.dev.cosign.simplesigning.v1+json`). | "an attestation says how the image was built; a signature of the image alone says nothing" |
| Another payload type than `application/vnd.in-toto+json`. | "an attestation's envelope carries an in-toto statement (application/vnd.in-toto+json)" |
| No signature, or more than one. | "an attestation's envelope carries exactly one signature" |
| A payload that is not standard, padded base64. | "an attestation's envelope payload is base64 text" |
| A statement whose `_type` is not `https://in-toto.io/Statement/v1` or `https://in-toto.io/Statement/v0.1`. | "an attestation carries an in-toto statement of type `https://in-toto.io/Statement/v0.1` or `https://in-toto.io/Statement/v1`" |
| A predicate other than SLSA provenance (`https://slsa.dev/provenance/v1` or `https://slsa.dev/provenance/v0.2`), such as a software bill of materials. | "an attestation of a build is its SLSA provenance" |
| No subjects, or more than 1,024 (`MAX_SUBJECTS`). | "an in-toto statement names 1 to 1024 subjects" |
| A subject with no `digest` object. | "each subject of an in-toto statement names its digests" |
| A `sha256` value, even `null`, that is not 64 lower-case hexadecimal characters. | "a subject's sha256 digest is 64 lower-case hexadecimal characters" |
| No subject named by its `sha256` digest. | "an in-toto statement names at least one subject by its sha256 digest" |

**The subject.** `check_attestation_subject(image_digest, statement)` raises `ValueError` unless one subject is the
image's own digest: "the attestation names the image's own digest". For an image built for several platforms that is
the index digest, which covers every platform image. An attestation of one platform image alone does not cover the
image.

**What Iltero Platform found.** In a run Iltero Platform opened, the build's input carries `attestation_outcome`,
Iltero Platform's answer once it checked the attestation's signature. In a run the tool opened, it is the unknown
marker. `outcome` says which answer it is:

| `outcome` | Fields | Meaning |
| --- | --- | --- |
| `verified` | See below. | The signature holds, the certificate names the run's own CI identity, the statement names the image's own digest, and it is SLSA provenance. |
| `refused` | `attestation_digest`, `trust_root`, `verifier`, `verified_at` (as below), and `reason`: `not_an_attestation`, `signature_invalid`, `identity_mismatch`, `subject_mismatch` or `predicate_not_provenance` | Iltero Platform refused the attestation, for that reason. `not_an_attestation` is a file `attestation_statement_of` refuses; `identity_mismatch` is a certificate naming another CI identity than the run's. |
| `not_sent` | none | No attestation was sent with the build: the record keeps none, or keeps one with `sent_to_server: false`. |

When Iltero Platform could not check the attestation at all, such as when its trust root could not be read, the part
is the unknown marker, never `signature_invalid`.

A `verified` answer (`iltero_schemas.models.server_facts.VerifiedAttestation`) reads its commit, repository and run
from the certificate the CI system's identity was issued, never from the statement, which the job wrote:

| Field | Meaning |
| --- | --- |
| `commit`, `ci_provider`, `ci_instance`, `repository_id`, `ci_run_id`, `ci_run_attempt` | The commit and CI run the certificate names, in the shape of the verified source, without the repository's name: a repository is compared by its id only. |
| `attestation_digest` | The digest of the attestation file Iltero Platform verified: Iltero Platform's word that it is the record's attestation file. A reader that holds the record and the input compares them with `iltero_schemas.change_types.check_attestation_outcome(car, outcome)`: "the server checked the attestation the build's record keeps", or "the server was sent an attestation exactly when the build's record says it sent the one it keeps". The outcome is `not_sent` exactly when the record keeps no attestation or keeps one with `sent_to_server: false`; otherwise its `attestation_digest` is the kept file's digest. |
| `image_digest` | The subject it matched: the image's own digest. |
| `predicate_type` | `https://slsa.dev/provenance/v1` or `https://slsa.dev/provenance/v0.2`. |
| `issuer` | Who issued the CI system's identity token, such as `https://token.actions.githubusercontent.com`. |
| `source_ref` | The Git reference the run was for, such as `refs/heads/main`. |
| `signer_identity`, `signer_commit` | The workflow that signed, by its path and reference, and the commit that workflow file was at. |
| `build_config` | The workflow the run started from. |
| `signed_by_same_job` | `true` when the job's own workflow signed, `false` when a workflow separate from the job did. |
| `runner_environment` | `ci_hosted`, a runner the CI system runs, or `self_hosted`, one the CI system's user runs on their own machine. |
| `signed_at`, `timestamp_source`, `log_entry` | When it was signed, and who says so: `transparency_log`, with the log's `log_entry` (`log_id`, `log_index`), or `timestamp_authority`, with no log entry. A timestamp authority is a service that signs the time a signature was made. `log_entry` is set exactly for `transparency_log`: "an attestation names its transparency log entry exactly when the log timed its signature". `signed_at` is no later than `verified_at`: "an attestation was signed no later than the server verified it". |
| `trust_root` | The trust root, the certificates and keys the signature was checked against: its `name` and the `digest` of its contents. |
| `verifier`, `verified_at` | What verified it (`name`, `version`), and when. |

**What a pass shows and what it does not.**

- A pass shows that a job holding the run's CI identity signed the image's own digest. A signature made in the job's
  own workflow (`signed_by_same_job: true`) does not show which image the job meant to sign. A workflow separate from
  the job, such as a reusable workflow, ties the digest to the build only when it builds the image or computes the
  digest itself, rather than signing a digest the job gives it.
- `ILT.IMAGE.ARTIFACT.PROVENANCE.SIGNED_PROVENANCE_MATCHES_RUN` compares the CI run and its attempt as well as the
  commit, so an attestation from another run of the same commit fails, and a build that sends none fails.
- It does not read `signed_by_same_job`, `runner_environment` or `signer_identity`. A project that needs a separate
  signer or a hosted runner writes its own assertion on them.
- A `self_hosted` runner is a machine the CI system's user runs, a weaker guarantee than a runner the CI system runs.
- A signature made with a key, not a CI identity, names no repository or commit, so it never gives a `verified`
  answer.
- A pass shows who signed the image's digest, not what the image holds.
- A private repository's build signed with the public Sigstore service writes its repository and workflow names to
  a public transparency log.

### The `image_deploy` body

The `change` of a record whose activity is `image_deploy`: one deployment of a built container image to one
environment, in one unit. The image was checked when it was built, so the record starts at the `pre_deploy` stage,
where the change is approved. Its change digest names the image, by its repository and digest, in the record's unit
and environment.

The record keeps what each party reported:

- **The build.** Iltero Platform finds the build of the image by its digest and accepts it against the environment's
  accepted build sources. The record copies the build as Iltero Platform served it (`build`), and never names a build a
  pipeline chose. A record of a run the tool opened names none. At `pre_deploy`,
  `ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT` checks that there is one (see the built-in assertions below).
- **The deployment.** The Iltero CLI talks to no cluster and no deploy tool. The pipeline declares the repository
  and digest it deployed. The deployment, and when it happened, are the pipeline's word: the record names no time for
  it, and the `post_deploy` stage was observed no earlier than the pipeline reported it.
- **The reading of the workload.** After the deployment, the pipeline reads the workload that runs the image and writes
  what it found to files the Iltero CLI reads. The record names no time for the reading: the `post_verify` stage's
  `observed_at` is the latest it can have happened. It copies the state of the
  workload's rollout, lists every container of the workload's pod template and says which ones it compares, and lists
  what every container of every pod of the workload runs. The record keeps the files the reading was taken from as JSON
  files in its evidence register: the workload object read before and after the pods were listed, the pod list and, for
  a Deployment, its ReplicaSets, redacted under the record's redaction policy. A workload is a Kubernetes Deployment,
  StatefulSet or DaemonSet: a controller that rolls out the pods running the image. An OpenShift DeploymentConfig is not
  accepted.
- **The pods a reading lists.** A reading lists the pods the workload controls, found by their controller owner
  reference: the reference Kubernetes sets on an object to name the controller that manages it. A StatefulSet's or
  DaemonSet's pods name the workload itself; a Deployment's pods name one of its ReplicaSets, which names the
  Deployment. A pod with any other controller, or with none, is not listed.
- **The containers a reading compares.** A container is compared by its image reference's repository, in its one
  spelling: one that names the deployed repository is always compared, in the template or in a pod, and so is a pod's
  container whose template container is compared. A container that only the pods have, not the template, such as a
  sidecar added to the pods when they were created or a debugging container, is recorded with its digest; when its
  image reference names another repository, it is not compared, so its image does not decide
  `ILT.IMAGE.DEPLOYMENT.DRIFT.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE`.

- **Model:** `iltero_schemas.change_types.ImageDeploy`, with its parts in `iltero_schemas.models.image.deploy`

| Field | Type | Meaning |
| --- | --- | --- |
| `activity` | string | `image_deploy`. |
| `digest` | digest | The [change digest](#the-change-digest). Approvals bind to it. |
| `image` | object | The image the change deploys, in the shape of an `image_build` record's `image` (`ImageRef`): its `repository`, its `digest` (the index digest for an image of several platforms) and `tag_resolution`, the tag the pipeline gave, or `null`. |
| `build` | object or null | The build Iltero Platform accepted for the environment (`AcceptedBuild`, see below). `null` in a run the tool opened, and when Iltero Platform accepted no build of the image. In the evaluation input of a run the tool opened, `build` is the unknown marker with reason `server_facts_unavailable`. |
| `deployment` | object or null | The image the pipeline reports it deployed (`ImageDeployment`, see below). Present exactly when the `post_deploy` stage has reported. |
| `drift_check` | object or null | What one reading of the workload found (`ImageDriftCheck`, see below). Present exactly when the `post_verify` stage has reported. |

`build` (`AcceptedBuild`):

| Field | Type | Meaning |
| --- | --- | --- |
| `run_id` | UUID | The run that built the image. |
| `record_digest` | digest | The digest of that build's record. |
| `platform_digests` | list | The digest of each platform's image the build's index lists: at most 64, sorted, each once, and never the image's own digest. |
| `verified_commit` | commit | The commit Iltero Platform verified for the build: the `verified_source.commit` it served in the build's evaluation input. |
| `build_commit` | commit or null | The commit the image's build metadata names, `null` when it names none. Accepting a build does not require it to be `verified_commit`, so a review of the verified commit speaks for the image only when the two agree (see [Commit review](#commit-review)). |
| `repository` | object | The repository the build's verified source names, as its git host names it (see [Git repository](#git-repository)). Iltero Platform maps the CI system's repository to the git host's. |

`deployment` (`ImageDeployment`):

| Field | Type | Meaning |
| --- | --- | --- |
| `repository`, `digest` | string, digest | The image the pipeline reports it deployed, the repository in its one spelling. |
| `reported_by` | string | `pipeline`. |

`drift_check` (`ImageDriftCheck`):

| Field | Type | Meaning |
| --- | --- | --- |
| `run_id` | UUID | The run the reading was taken for: the record's `run.id`. |
| `change_digest` | digest | The change the reading was taken for: the record's `change.digest`. |
| `workload` | object | The workload read, in the shape of the platform that runs it (see below). |
| `rollout` | object | The state of the workload's rollout when it was read, in the shape of the workload's kind (see below). |
| `template_containers` | list | Every container of the workload's pod template (`TemplateContainer`, see below): from 1 to 256, sorted by `name`, each once. Containers the reading does not compare are listed too. |
| `containers_read` | list | What the containers of the pods listed ran (`ContainerRead`, see below): at most 1,024 entries, naming at most 10,000 pods and at most 100,000 containers of pods (a pod counted once for each of its containers). Pods whose container shares its name, role, image reference, comparison, digest, pod state and revision share one entry. Empty when the reading listed no pod. |
| `live_pods_read` | integer | The number of pods `containers_read` lists whose `pod_state` is `live`. |
| `pods_resource_version` | identifier | The version the cluster gave the pod list read (its resource version). |
| `workload_before_pods_listing_evidence_ref` | identifier | The workload object as read before the pods were listed, by its `ref_id` in `evidence_refs`. |
| `workload_after_pods_listing_evidence_ref` | identifier | The workload object as read after the pods were listed, by its `ref_id` in `evidence_refs`. |
| `pods_evidence_ref` | identifier | The pod list read, by its `ref_id` in `evidence_refs`. |
| `pod_owners_evidence_ref` | identifier or null | The objects that own the pods, by their `ref_id` in `evidence_refs`: a Deployment's ReplicaSets. `null` for a workload that owns its pods itself, a StatefulSet or a DaemonSet. |

These are the files the reading was taken from (`ImageDriftCheck.files_read`), each a different file. The contract
checks each file's place in the evidence register, as the rules below say. It does not read their contents: it does
not check that the two workload reads agree, or that the pod owners lead to the workload.

`workload` (`KubernetesWorkload`, in `iltero_schemas.models.image.kubernetes`, the one shape of `Workload` in this
version; another platform adds its own):

| Field | Type | Meaning |
| --- | --- | --- |
| `platform` | string | `kubernetes`. |
| `cluster_id` | identifier | The cluster read, by the id of its `kube-system` namespace. |
| `kind` | string | `deployment`, `stateful_set` or `daemon_set`. Any other kind is refused, such as `deployment_config`. |
| `namespace`, `name` | identifier | The workload's namespace and name in the cluster. |
| `uid` | UUID | The workload object's own id. A workload deleted and created again under the same name has another. |

`rollout` (`KubernetesRollout`, in `iltero_schemas.models.image.kubernetes`, the one shape of `Rollout` in this
version): one shape per workload kind, told apart by `kind`, which is the workload's `kind`. The reading copies the
counts the workload's status reported, each read in the same request as its pod template; a count the status left out is
written as 0. `complete` and `expected_live_pods` are worked out from the counts, and a reading whose values differ is
refused. Every kind carries:

| Field | Type | Meaning |
| --- | --- | --- |
| `kind` | string | `deployment`, `stateful_set` or `daemon_set`. |
| `resource_version` | identifier | The version the cluster gave the workload object read (its resource version), so the reading names the state it was taken from. |
| `generation` | integer | The generation of the workload's spec: Kubernetes raises it on every change to the spec. |
| `observed_generation` | integer | The generation the workload's controller last acted on. |
| `complete` | boolean | Whether the rollout had finished when it was read: `observed_generation` is at least `generation`, and the kind's counts show it finished, as the table below says. This is the test `kubectl rollout status` applies. |
| `expected_live_pods` | integer | The live pods the workload has once its rollout has finished, as the table below says. |

Each kind adds its own counts and settings, all integers from 0 unless the table says otherwise:

| `kind` | Fields it adds | Finished when | `expected_live_pods` |
| --- | --- | --- | --- |
| `deployment` (`DeploymentRollout`) | `desired_replicas`, `replicas`, `updated_replicas`, `available_replicas`; `paused` (boolean); `strategy` (`rolling_update` or `recreate`) | `paused` is `false`, and `updated_replicas`, `replicas` and `available_replicas` all equal `desired_replicas`. A paused rollout never finishes. | `desired_replicas` |
| `stateful_set` (`StatefulSetRollout`) | `desired_replicas`, `replicas`, `updated_replicas`, `available_replicas`; `current_revision`, `update_revision` (identifiers, or null while the status names none); `strategy` (`rolling_update` or `on_delete`); `partition` | `strategy` is `rolling_update`, `partition` is 0, `updated_replicas` and `available_replicas` equal `desired_replicas`, and `update_revision` is not null and equals `current_revision`. A partitioned or `on_delete` rollout leaves pods on the old revision on purpose, so it never finishes. | `desired_replicas` |
| `daemon_set` (`DaemonSetRollout`) | `desired_number_scheduled`, `current_number_scheduled`, `updated_number_scheduled`, `number_available`, `number_misscheduled`; `strategy` (`rolling_update` or `on_delete`) | `strategy` is `rolling_update`, `updated_number_scheduled` and `number_available` equal `desired_number_scheduled`, and `number_misscheduled` is 0: no pod runs on a node the daemon set no longer selects. An `on_delete` rollout never finishes. | `desired_number_scheduled` |

`template_containers` entry (`TemplateContainer`):

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | identifier | The container's name in the pod template. |
| `role` | string | What the container is to its pod: `app`, one of its containers; `init`, an init container that runs to completion before them; or `sidecar`, an init container that keeps running beside them. |
| `image_reference` | string | The image the pod template names for the container, with its repository in its one fully qualified spelling (`ImageReference`, in `iltero_schemas.models.image.naming`): the repository under the image repository rules of the [`image_build` body](#the-image_build-body), then, optionally, a `:tag`, an `@digest`, or both, such as `ghcr.io/acme/api:1.4.2@sha256:…`. The reader rewrites the pod template's reference into that spelling: a name with no registry host is on `docker.io`, and a name of one path segment is under `docker.io/library/`, so `nginx:1.25` is written `docker.io/library/nginx:1.25` and `fluent/fluent-bit:3.1.4` is written `docker.io/fluent/fluent-bit:3.1.4`; a Docker Hub alias (`index.docker.io`, `registry-1.docker.io`, `registry.hub.docker.com`) is written `docker.io`; and the default port `:443` is left out. A reference in any other spelling is refused. A bare repository, with no tag or digest, is accepted. The repository is at most 255 characters, and the whole reference at most 456 (`REFERENCE_MAX_LENGTH`). |
| `compared` | boolean | Whether the reading compares the image the container runs. A container whose `image_reference` names the deployed repository (`change.image.repository`), in its one spelling, is always compared. |

`containers_read` entry (`ContainerRead`): one container as the pods listed ran it.

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | identifier | The container's name in the pod. |
| `role` | string | `app`, `init` or `sidecar`, as in `template_containers`, or `ephemeral`: a debugging container added to the running pod. |
| `image_reference` | string | The image the pod names for the container, in the spelling of `template_containers`. It is the pod's own, which can differ from the template's. |
| `compared` | boolean | Whether the reading compares the image the container runs. A container whose `image_reference` names the deployed repository is always compared, and so is one whose template container of the same name is compared. |
| `digest` | digest or marker | The digest of the image the container runs, from the container's status. The unknown marker `{"__unknown": true, "reason": "not_reported_by_tool"}` when the status names no registry digest. |
| `pod_state` | string | `terminating` for a pod being deleted, `finished` for a pod whose containers have all stopped, and `live` for any other. |
| `revision` | identifier or null | The pod's template revision: its `pod-template-hash` or `controller-revision-hash` label. `null` for a pod with neither label. |
| `pods` | list | The pods that ran the container this way, by name: from 1 to 10,000, sorted, each once. |

Entries are sorted by their fields in the order the table gives them: `name`, `role`, `image_reference`, `compared`,
`digest`, `pod_state`, then `revision` (`ContainerRead.sort_key`), and no two entries share all seven. In that order
`compared` sorts `false` before `true`, and a `digest` that is the unknown marker and a `null` revision sort first.

A container's running digest is the one the container runtime reports. Depending on the runtime, that is the index
digest or the digest of the platform's image, so either one stands for the deployed image.

Key rules:

| Rule | Refused with |
| --- | --- |
| A record of a run the tool opened (`governance.run_opened_by: local`) has `build: null`. | "a run the tool opened names no build: only the server accepts one for the environment" |
| `build.platform_digests` are sorted, each once, and none is the image's digest. | "platform_digests are named once each, in order", "platform_digests are the index's children, never the index digest itself" |
| `image.repository` and `deployment.repository` follow the image repository rules of the [`image_build` body](#the-image_build-body). | "an image repository starts with its registry host, such as docker.io/library/nginx", and the other messages of that table |
| A tag's metadata file is in `evidence_refs`. | "change.image.tag_resolution.read_from_evidence_ref names a file of the record's evidence register" |
| `deployment` is set exactly when the `post_deploy` stage has reported. | "a record describes the deployment exactly when its post-deploy stage has reported" |
| The `post_deploy` stage counts the one deployment, with the digest of `change.deployment` as its `source_digest`. | "the post_deploy stage must count the one deployment by its digest" |
| `drift_check` is set exactly when the `post_verify` stage has reported. | "a record carries its drift check exactly when its post-verify stage has reported" |
| `drift_check.run_id` is the record's `run.id`. | "the drift check names the record's run" |
| The `post_verify` stage counts the one deployment, with the digest of `change.drift_check` as its `source_digest`. | "the post_verify stage must count the one deployment by the drift check that read it" |
| `drift_check.rollout.kind` is `drift_check.workload.kind`. | "rollout is the state of the workload's kind of rollout" |
| `rollout.complete` is what the counts give, as the `rollout` tables say. | "rollout.complete is whether the rollout's counts show it finished" |
| `rollout.expected_live_pods` is what the counts give, as the `rollout` tables say. | "rollout.expected_live_pods is the live pods the rollout's counts call for" |
| `drift_check.template_containers` lists at least one container, and names each once, sorted by `name`. | "template_containers lists each container of the pod template once, sorted by name"; an empty list is refused as too short |
| `drift_check.containers_read` is sorted, and no two entries share name, role, image reference, comparison, digest, pod state and revision. | "containers_read lists each group once, sorted" |
| Each entry's `pods` are sorted, each once. | "pods names each pod once, sorted" |
| No pod is listed twice for the same container name. | "a pod lists each of its containers once" |
| Every entry that lists a pod gives it the same `pod_state` and `revision`. | "each pod has one state and one revision" |
| `containers_read` lists at most 100,000 containers of pods, counting each entry once for each pod it names. | "a reading lists at most 100000 containers of pods" |
| `containers_read` names at most 10,000 different pods. | "a reading lists at most 10000 pods" |
| `live_pods_read` is the number of different pods `containers_read` lists as `live`. | "live_pods_read is the number of live pods containers_read lists" |
| A pod's container is `compared` when the template container of the same name is. | "a pod's container is compared when its template container is" |
| When `rollout.complete` is `true`, every live pod lists every template container, each in its template `role`. | "once the rollout has finished, every live pod lists every template container" |
| When `rollout.complete` is `true`, every live pod has one and the same `revision`; for a stateful set, it is `rollout.update_revision`. | "once the rollout has finished, every live pod is of its current revision" |
| `pod_owners_evidence_ref` is set exactly when `workload.kind` is `deployment`. | "pod_owners_evidence_ref names a deployment's replica sets, and only a deployment's" |
| The files the reading was taken from are each a different file. | "the files a reading was taken from are each a different file" |
| Each file is in `evidence_refs`. | "change.drift_check.workload_before_pods_listing_evidence_ref names a file of the record's evidence register", or the same for the file's other field |
| Each file is of type `application/json`. | "the workload read before the pods were listed is a file of type application/json", or the same for "the workload read after the pods were listed", "the pod list read" or "the pod owners read" |
| Each file's `evidence_refs` entry has a `source`, whose `digest` is the digest of the file as the pipeline gave it, before redaction, which differs from the stored `digest` when redaction changed the file. | "the pod list read names the digest of the file as the pipeline gave it, in its source", or the same for each other file |
| Each file names the redaction policy that ran over it (`redaction_policy` is not `null`). The rule that a record redacts under one policy makes it the record's policy. | "the workload read before the pods were listed names the redaction policy that ran over it", or the same for each other file; a file redacted under another policy: "every stage and every redacted evidence file name the same redaction policy" |
| No file is the tag's metadata file (`image.tag_resolution.read_from_evidence_ref`). | "the workload read before the pods were listed is not the tag's metadata file", or the same for each other file |
| Every container, in `template_containers` or in `containers_read`, whose `image_reference` names `change.image.repository`, in its one spelling, is `compared`. | "a reading compares every container whose image is from the deployed repository" |
| An `image_reference`'s digest is `sha256:` and 64 lower-case hexadecimal characters, its tag is one a registry accepts, and its repository is at most 255 characters and follows the image repository rules. | "an image reference's digest is sha256: and 64 lower-case hexadecimal characters", "an image reference's tag is one a registry accepts", "an image reference's repository is at most 255 characters", or a message of the image repository rules |
| The `pre_deploy` stage evaluates `ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT`, the `post_deploy` stage `ILT.IMAGE.DEPLOYMENT.CONTENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE`, and the `post_verify` stage `ILT.IMAGE.DEPLOYMENT.DRIFT.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE`, each exactly once and never as `not_applicable` (see `always_evaluated` above). | "ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT is evaluated once, at the pre_deploy stage, once it has reported", or the same for the others; a `not_applicable` event: "ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT always applies to the pre_deploy stage's one subject" |
| An `ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT` event that was not evaluated, or that ended in `error`, gives a fault of the evaluator as its reason: `timeout` or `evaluator_unavailable` for `not_evaluated`; `evaluator_crash`, `evaluator_timeout`, `evaluator_memory_limit`, `output_overflow`, `output_contract_violation`, `bundle_verification_failed` or `compile_failure` for `error`, never `adapter_parse_failure` (`iltero_schemas.models.event.EVALUATOR_FAULT_REASONS`). | "ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT is not_evaluated only for a fault of the evaluator, never for want of the change or its facts", or the same with `error` |
| On a run the tool opened, any other `ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT` event is `unknown` with `server_facts_unavailable`. | "ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT is unknown with reason server_facts_unavailable on a run the tool opened: only the server accepts a build for the environment" |

The `post_verify` stage's redaction report (`redaction`) describes one input, the drift check (`input.kind:
drift_check`); it does not list what redaction hid in the files the reading was taken from. For each of those files the
record keeps the redaction policy that ran (`redaction_policy`) and the digest of the file as read (`source.digest`),
not a list of what was hidden.

An evaluation input's `drift_check` is read with the same model, so the rules on the reading itself hold there too:
the rollout, the two container lists, the pods, the finished-rollout rules, the different files and the compared
containers. The rules on the record's run, stages and evidence register hold only in a record.

The integrity checks recompute `change.digest` from the record's change type, unit, environment and image, and hold the
`pre_deploy` stage's `coverage.subjects_in_scope.source_digest`, each approval of a change and
`change.drift_check.change_digest` to it. Each one that differs is an integrity failure, such as "change.digest is not
the digest of the change type, unit, environment and image" and "change.drift_check.change_digest is not change.digest".
They also recompute the status each built-in check must have from the record's own image, deployment, reading and build,
with the rules of the three assertions below: on a run Iltero Platform opened,
`ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT` passes with a `build` and fails without one;
`ILT.IMAGE.DEPLOYMENT.CONTENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE` passes or fails; and
`ILT.IMAGE.DEPLOYMENT.DRIFT.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE` passes, fails or is `unknown` as its row in the table
below says. An event of any of them whose status is `pass`, `fail`, `unknown` or `not_applicable` and not the recomputed
one is an integrity failure at `events.<index>.evaluation.status`: "is not fail, what the record's change gives". An
event that is `not_evaluated` or `error` is not compared. On a run the tool opened,
`ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT` is not recomputed: the key rules above refuse an event that is
neither `unknown` with `server_facts_unavailable` nor `not_evaluated` or `error` for a fault of the evaluator, even when
the integrity checks are skipped.

```json
{
  "activity": "image_deploy",
  "digest": "sha256:4edd32ab77cfd06df324ec6e843e6b8cd9bfd3a30d530ff3ec9e93555a21e8f2",
  "image": {
    "repository": "ghcr.io/acme/api",
    "digest": "sha256:9555f244c96cff1d2aaeec43cc6bb226d166a5642c92c485570cd0c73a3487fb",
    "tag_resolution": null
  },
  "build": null,
  "deployment": {
    "repository": "ghcr.io/acme/api",
    "digest": "sha256:9555f244c96cff1d2aaeec43cc6bb226d166a5642c92c485570cd0c73a3487fb",
    "reported_by": "pipeline"
  },
  "drift_check": {
    "run_id": "7a2d3c4b-5e6f-5071-8b9c-1d2e3f4a5b6c",
    "change_digest": "sha256:4edd32ab77cfd06df324ec6e843e6b8cd9bfd3a30d530ff3ec9e93555a21e8f2",
    "workload": {
      "platform": "kubernetes",
      "cluster_id": "5f0c1d1f-1f6c-4e5b-8b4a-7c2e3d9a8b7c",
      "kind": "deployment",
      "namespace": "payments",
      "name": "api",
      "uid": "3e1f0a2b-7c4d-4e5f-8a6b-9c0d1e2f3a4b"
    },
    "rollout": {
      "resource_version": "48213",
      "generation": 4,
      "observed_generation": 4,
      "complete": true,
      "expected_live_pods": 2,
      "kind": "deployment",
      "desired_replicas": 2,
      "replicas": 2,
      "updated_replicas": 2,
      "available_replicas": 2,
      "paused": false,
      "strategy": "rolling_update"
    },
    "template_containers": [
      {
        "name": "api",
        "role": "app",
        "image_reference": "ghcr.io/acme/api@sha256:9555f244c96cff1d2aaeec43cc6bb226d166a5642c92c485570cd0c73a3487fb",
        "compared": true
      },
      {
        "name": "log-shipper",
        "role": "sidecar",
        "image_reference": "docker.io/fluent/fluent-bit:3.1.4",
        "compared": false
      }
    ],
    "containers_read": [
      {
        "name": "api",
        "role": "app",
        "image_reference": "ghcr.io/acme/api@sha256:9555f244c96cff1d2aaeec43cc6bb226d166a5642c92c485570cd0c73a3487fb",
        "compared": true,
        "digest": "sha256:9555f244c96cff1d2aaeec43cc6bb226d166a5642c92c485570cd0c73a3487fb",
        "pod_state": "live",
        "revision": "7d9f8b6c5",
        "pods": [
          "api-7d9f8b6c5-abcde",
          "api-7d9f8b6c5-fghij"
        ]
      },
      {
        "name": "log-shipper",
        "role": "sidecar",
        "image_reference": "docker.io/fluent/fluent-bit:3.1.4",
        "compared": false,
        "digest": "sha256:6e2c192007955e140b45a9f70dfe9d04d2a6f269328b6a69f7da4af044e55fc5",
        "pod_state": "live",
        "revision": "7d9f8b6c5",
        "pods": [
          "api-7d9f8b6c5-abcde",
          "api-7d9f8b6c5-fghij"
        ]
      }
    ],
    "live_pods_read": 2,
    "pods_resource_version": "48217",
    "workload_before_pods_listing_evidence_ref": "post_verify/workload-before-pods-listing.json",
    "workload_after_pods_listing_evidence_ref": "post_verify/workload-after-pods-listing.json",
    "pods_evidence_ref": "post_verify/pods.json",
    "pod_owners_evidence_ref": "post_verify/pod-owners.json"
  }
}
```

The evaluation input of a deploy carries the `change` (its `digest`, the `image` by `repository` and `digest`, and the
`build`, without a tag; in a run the tool opened, `build` is the unknown marker
`{"__unknown": true, "reason": "server_facts_unavailable"}`, where the record has `null`), and from `post_deploy` on the
`deployment`, and at `post_verify` the `drift_check`, in the shapes above. At `pre_deploy`, an assertion about any
change, such as `ILT.COMMON.CHANGE.APPROVAL.PRODUCTION_APPROVED`, reads only what both the `iac_change` and the
`image_deploy` input carry, so it never reads `plan`.

Three built-in assertions check a deploy: the first about the `change` target, the other two about the `deployment`
target.

| Assertion | Title | Passes when |
| --- | --- | --- |
| `ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT` | The server accepted a build of the image for the environment | At `pre_deploy` (`iltero_schemas.assertions.BUILD_ACCEPTED_FOR_ENVIRONMENT`): `change.build` is not `null`. It fails when Iltero Platform opened the run and accepted no build of the image for the environment (`build: null`), and is `unknown` with `server_facts_unavailable` in a run the tool opened, where `build` is the unknown marker. So the `pre_deploy` stage of an image deploy in a run the tool opened never passes: at best it is indeterminate (exit code `3`). Its remediation: "Deploy an image built by a run the server recorded, from a source the environment accepts." |
| `ILT.IMAGE.DEPLOYMENT.CONTENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE` | The image the pipeline reports it deployed is the image the deploy checked | At `post_deploy`: `deployment.repository` equals `change.image.repository`, and `deployment.digest` equals `change.image.digest`. The activity's `carried_out_matches_checked` check (`iltero_schemas.assertions.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE`). |
| `ILT.IMAGE.DEPLOYMENT.DRIFT.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE` | After its rollout finished, every live pod of the workload runs the deployed image, or one of its platform images, in every compared container | At `post_verify` (`iltero_schemas.assertions.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE`): `drift_check.rollout.complete` is `true`; `drift_check.live_pods_read` equals `drift_check.rollout.expected_live_pods`; at least one `template_containers` entry is compared; at least one `containers_read` entry is a compared container of a live pod; and every compared container of a live pod runs `change.image.digest` or one of `change.build.platform_digests`. It fails when the rollout had not finished, when the live pods read are not the number the rollout calls for, when the template compares no container, when no live pod has a compared container (so a workload scaled to zero fails, having no live pod to check), or when the change names an accepted build and a compared container of a live pod runs a digest that is neither the image's nor one of that build's platform digests. It is `unknown` when such a container's `digest` is the `not_reported_by_tool` marker, or when the change names no accepted build (`build` is `null`, or the unknown marker in a run the tool opened) and such a container runs a digest other than the image's, since there is no platform digest to compare it with. A failure decides before an unknown. Iltero Platform recomputes the same status from a record (`iltero_schemas.change_types.image.deploy.running_image_status`). Terminating and finished pods, and containers not compared, never decide it. |

### Checked content

The checked content is what a record's change is about and its evaluations ran on, named by its digest. Every event
names it in `provenance.checked_content`, and an earlier evaluation in `checked_content`, so an evaluation of other
content cannot stand in a record. It has one shape per `kind`: for `iac_change` the plan, for `image_build` and
`image_deploy` the image (`iltero_schemas.models.change_type.CHECKED_CONTENT_KIND_OF`).

- **Model:** `iltero_schemas.models.checked_content.CheckedContent`, one of `CheckedPlan` and `CheckedImage`

`kind: plan` (`CheckedPlan`):

| Field | Type | Meaning |
| --- | --- | --- |
| `kind` | string | `plan`. |
| `digest` | digest | The plan's digest by its tool's rule (`iltero_schemas.canonical.plan_digest`). |
| `digest_version` | identifier | The version of that rule. Any other version is refused. |
| `tool` | string | The IaC tool that wrote the plan. |

In a record, it is `change.plan`'s `digest`, `digest_version` and `tool`.

`kind: container_image` (`CheckedImage`):

| Field | Type | Meaning |
| --- | --- | --- |
| `kind` | string | `container_image`. |
| `repository` | string | The image's repository, in its one spelling (see [The `image_build` body](#the-image_build-body)). |
| `digest` | digest | The image's digest: the index digest for an image of several platforms. |

In a record of either image activity, it is `change.image`'s `repository` and `digest`. The image a build checked
and the same image deployed are the same checked content, and so is the same image released to several
environments.

### The change digest

The change digest names one change: one checked content, of one change type, in one unit, deployed to one environment.
An `iac_change` or `image_deploy` record names it in `change.digest`. An `image_build` record deploys nothing and has
none. `iltero_schemas.canonical.change_digest(change_type, unit, environment_key, checked_content)` is the SHA-256 of
the RFC 8785 canonical JSON of the following, where `checked_content` is the [checked content](#checked-content) as
every evaluation names it:

```json
{
  "change_type": "iac_change",
  "checked_content": {
    "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "digest_version": "1",
    "kind": "plan",
    "tool": "terraform"
  },
  "environment_key": "production",
  "unit": "root"
}
```

| Input | In an `iac_change` record | In an `iac_change` evaluation input | In an `image_deploy` record | In an `image_deploy` evaluation input |
| --- | --- | --- | --- | --- |
| `change_type` | `iac_change` | `iac_change` | `image_release` | `image_release` |
| `unit` | `unit` | The subject's unit | `unit` | The subject's unit |
| `environment_key` | `subject.environment` | `organization_scope.environment.name` | `subject.environment` | `organization_scope.environment.name` |
| `checked_content` | `change.plan`'s `digest`, `digest_version` and `tool`, with `kind: plan` | `plan`'s `digest`, `digest_version` and `tool`, with `kind: plan` | `change.image`'s `repository` and `digest`, with `kind: container_image` | `change.image`'s `repository` and `digest`, with `kind: container_image` |

`environment_key` is `null` for a change made outside any environment; a record of a run Iltero Platform opened
always names its environment. An approval of a change binds to this digest, so it counts for that content, in that
unit and environment: a plan that does something else, or the same plan deployed to another environment, is another
change. The digest names no project or organization; Iltero Platform holds an approval to the project it was given
in. A record whose change digest is not this one is an integrity failure: "change.digest is not the digest of the
change type, unit, environment and plan", or "... and image" in an `image_deploy` record. A record that lists an
approval of another change is one too, naming the approval: "stages.pre_deploy.approvals lists approval apr_0001 of
another change: another change type, unit, environment or checked content".

### Units file

A units file is the file in which a project declares its units, in the order they deploy. A record names it as the
writer read it.

- **Model:** `iltero_schemas.models.units_file.UnitsFile`

| Field | Type | Meaning |
| --- | --- | --- |
| `path` | string | The file's path in the project. |
| `digest` | digest | The SHA-256 of the file's bytes. |
| `units` | list | 1 to 64 units in deploy order, each a `name` and the units it `depends_on` (`DeclaredUnit`). |

A unit name is 1 to 64 lowercase letters, digits, `_` and `-`, not starting with `-`. Rules:

| Rule | Refused with |
| --- | --- |
| Each unit is named once. | "a units file names each unit once" |
| `depends_on` lists at most 64 names, sorted by Unicode code point, each once. | "a unit's dependencies are sorted by name and name each unit once" |
| A unit does not depend on itself. | "a unit does not depend on itself" |
| A unit depends only on units the file declares. | "a unit depends only on units the units file declares" |
| A unit comes after every unit it depends on. | "a unit comes after every unit it depends on, in deploy order" |

```json
{
  "path": ".iltero/units.json",
  "digest": "sha256:7777777777777777777777777777777777777777777777777777777777777777",
  "units": [
    {"name": "network", "depends_on": []},
    {"name": "app", "depends_on": ["network"]}
  ]
}
```

## VerificationReport

A verification report states what a verifier found about one CAR, one property at a time. It is a separate document,
never part of the record.

- **apiVersion:** `iltero.com/v1`, with `kind: VerificationReport`
- **Model:** `iltero_schemas.models.verification.VerificationReport`

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion`, `kind` | string | `iltero.com/v1` and `VerificationReport`. |
| `metadata` | object | The `verifier`: `name: iltero` and the verifier's `version`; and `verified_at` (timestamp), when the verifier wrote the report, by its own clock. A result such as a stage still pending holds at that time. |
| `record` | object | The record's `uuid` (its `metadata.uuid`), and the `digest` of the record's canonical JSON as the verifier read it: its document digest. |
| `properties` | object | Ten properties, each with a `state` and a `reason`: a short name for why the property has its state, or `null`. |

| Property | What `verified` would mean |
| --- | --- |
| `integrity` | The record's structure and signature are valid, and the evidence it cites is unchanged. |
| `source_identity` | The repository, commit and pipeline came from an authenticated source. |
| `approval_identity` | Every approval came from an authenticated identity. |
| `bundle_provenance` | The evaluations ran from a bundle signed by an authorized key that was not revoked. |
| `stage_completeness` | Every required stage is present, and every evaluation owed has a result or is listed as not evaluated. |
| `plan_apply_match` | The approved plan is the applied plan. |
| `runtime_verification` | A verification after the deployment ran. |
| `deployment_coverage` | No deployment visible to the verifier is missing a record. |
| `exceptions` | Every exception used was approved and valid at deployment time. |
| `commit_review` | Every commit the change ships was reviewed. |

| State | Meaning |
| --- | --- |
| `verified` | Checked, and it holds. |
| `failed` | Checked, and it does not hold. |
| `not_determined` | Examined, but not decidable. |
| `not_assessed` | Not assessed for this record. |
| `not_performed` | The record shows the step did not happen. |
| `client_asserted` | The only evidence is the record's own claim. |

Key rules:

- No property of an unsigned record is `verified`: only a signature could verify a record's integrity, or anything
  that rests on it, and no record carries one. Matching digests give `client_asserted` with the reason
  `file_digests`. Any `verified` is refused: "no property of an unsigned record is verified".
- When `integrity` is `failed` with the reason `file_digests`, every other property is `not_determined` with the
  reason `integrity_failed`: a record that does not hold together says nothing a verifier can take about itself.
  Any other is refused: "when a record's integrity is not established, every other property is not_determined with
  the reason integrity_failed".
- Otherwise each property has one of the results a verifier gives it
  (`iltero_schemas.models.verification.PROPERTY_RESULTS`), each a state and a reason, and any other is refused:
  "`<property>` is one of the results a verifier gives that property". For a commit review the pre-deploy stage kept,
  a verifier gives `commit_review` the result `iltero_schemas.models.verification.COMMIT_REVIEW_RESULTS` names for its
  outcome, with the outcome as the reason.

  | Property | State | Reason | Meaning |
  | --- | --- | --- | --- |
  | `integrity` | `client_asserted` | `file_digests` | The files the record cites hold the digests it names, which anyone who can edit them can recompute. |
  | `source_identity` | `not_assessed` | `ci_job_held_by_server` | Iltero Platform, which opened the run, verifies its CI jobs; the record does not carry them. |
  | `source_identity` | `not_performed` | `run_opened_locally` | The tool opened the run, so no CI job was verified. |
  | `approval_identity` | `client_asserted` | `approvals_listed` | The pre-deploy stage lists approvals: its writer's claim. |
  | `approval_identity` | `not_performed` | `no_approval_served` | Iltero Platform opened the run, and the pre-deploy stage keeps an empty list of approvals. |
  | `approval_identity`, `exceptions`, `commit_review` | `not_assessed` | `not_in_activity` | The record's activity has no pre-deploy stage, as an image build has none. |
  | `approval_identity` | `not_performed` | `server_facts_unavailable` | The pre-deploy stage ran and keeps a marker in place of its approvals, or lists none in a run the tool opened. |
  | `commit_review` | `not_performed` | `server_facts_unavailable` | The pre-deploy stage ran and keeps a marker in place of its commit review, or keeps no commit review. |
  | `exceptions` | `not_performed` | `server_facts_unavailable` | The pre-deploy stage ran in a run the tool opened, so no exception came from Iltero Platform. |
  | `approval_identity`, `exceptions`, `commit_review` | `not_assessed` | `pre_deploy_pending` | The record expects the pre-deploy stage, and the run that would report it is still in progress. |
  | `approval_identity`, `exceptions`, `commit_review` | `not_assessed` | `pre_deploy_out_of_scope` | The record leaves the pre-deploy stage out of scope. |
  | `exceptions` | `not_assessed` | `exceptions_not_listed` | A record lists no exception, so the exceptions Iltero Platform may have served are not assessed. |
  | `bundle_provenance` | `client_asserted` | `server_bundle_named` | A stage names an assertion bundle Iltero Platform served. |
  | `bundle_provenance` | `not_performed` | `local_assertions` | The checks were the project's own. |
  | `stage_completeness` | `client_asserted` | `expected_stages` | Every stage the record expects reported. |
  | `stage_completeness` | `not_assessed` | `stages_pending` | The run is still in progress. |
  | `stage_completeness` | `failed` | `stage_not_reported` | The record is finished, and a stage it expects was never reported. |
  | `plan_apply_match` | `not_assessed` | `not_in_activity` | The record's activity applies no plan. |
  | `plan_apply_match` | `not_performed` | `no_post_deploy_stage` | No stage compared the applied plan. |
  | `plan_apply_match` | `client_asserted` | `plan_files_supplied` | The plan files given to the verifier match. |
  | `plan_apply_match` | `failed` | `plan_files_supplied` | The plan files given to the verifier do not match. |
  | `plan_apply_match` | `not_determined` | `binding_undecided` | The plan files given to the verifier could not be compared. |
  | `runtime_verification` | `client_asserted` | `reported_by_pipeline` | The pipeline reported the `post_verify` stage, which only the pipeline's word supports. |
  | `runtime_verification` | `not_assessed` | `stage_pending` | The record expects the stage, and the run that would report it is still in progress. |
  | `runtime_verification` | `not_performed` | `stage_not_reported` | The record expects the stage, and it was never reported. |
  | `runtime_verification` | `not_assessed` | `project_config`, `environment_policy` or `not_supported` | The record leaves the stage out of scope for that reason. |
  | `runtime_verification` | `not_assessed` | `not_in_activity` | The record's activity has no stage after deployment, as an image build has none. |
  | `deployment_coverage` | `not_assessed` | `null` | No reader of one record knows of a deployment that left no record. |
  | `commit_review` | `client_asserted` | `reviewed` | The pre-deploy stage kept a commit review whose outcome is `reviewed`: its writer's claim. |
  | `commit_review` | `failed` | `not_reviewed`, `review_starting_point_not_in_history`, `head_commit_before_review_starting_point`, `source_commit_not_verified_commit` or `build_commit_not_verified_commit` | The kept outcome, which shows that a commit the change ships was not reviewed. |
  | `commit_review` | `not_determined` | `too_many_commits` | The kept outcome: more commits than Iltero Platform checks, so it was not decided. |
  | `commit_review` | `not_performed` | `no_review_starting_point` | The kept outcome: no review starting point, so no commit was checked. |

- The report has no overall verdict, and no report establishes certification or compliance with a regulatory
  framework.

## ResourceIdentities

A resource identities document lists, for one unit after an apply, the resolved identity of each resource of its
IaC configuration: the resource tied to the cloud resource it created. A resource is resolved only by a resolver
verified for its type, and otherwise listed as unresolved with a reason. A resolver is the part of a tool that reads
identifiers for one cloud provider.

- **apiVersion:** `iltero.com/v1`, with `kind: ResourceIdentities`
- **Model:** `iltero_schemas.models.iac.resource_identities.ResourceIdentities`

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion`, `kind` | string | `iltero.com/v1` and `ResourceIdentities`. |
| `metadata` | object | The `generator`: `name: iltero` and the writer's `version`. |
| `unit` | identifier | The unit. |
| `sources` | object | The `state` read (its `digest`, IaC `tool` and `tool_version`); where it was read from (`read_from`: `state_file`, the state file the apply left, or `refresh_plan`, the state a refresh-only plan read back after the deployment, as the plan records it); and the applied `plan` (`digest`, `digest_version`), or `null` when no applied plan was read. `state.digest` is the digest of the bytes read: the state file or the refresh-only plan. |
| `resolvers` | list | One resolver per cloud provider, sorted by provider, at most 16. Each names its `provider`, `version` and the resource types verified for it (`supported_resource_types`). |
| `resolved` | list | Each managed resource in the state after the apply that was resolved (`ResolvedIdentity`): `iac` (`tool`, `unit`, `address`), `cloud` (per provider) and `resolution: resolved`. |
| `unresolved` | list | Each managed resource that was not resolved: `address` and `reason`. |
| `removed`, `removed_unresolved` | list or null | Each object that left the state during the apply, by its identity before the apply (`RemovedIdentity`, or `RemovedUnresolved` when it was not resolved), with its `removal` (`deleted` or `forgotten`). |
| `tool_data` | object | What only the state's IaC tool says, keyed by `tool`, which must be `sources.state.tool`. For `terraform`: `deposed_deleted` (integer or null), how many deposed objects the apply deleted, and `deposed_remaining`, how many the state still holds. |

Key rules:

- `resolved` and `unresolved` are sorted by address and name each resource once: "resolved and unresolved are sorted
  by address and name each resource once". A resource is in one of them only: "a resource is resolved or unresolved,
  never both". The same holds for `removed` and `removed_unresolved`.
- No two entries of `resolved` name the same cloud identity: the same `provider`, `identifier.scheme` and
  `identifier.value`, compared exactly as written: "no two entries of resolved name the same cloud identity". The same
  holds within `removed`. The two lists are not compared with
  each other: for example, a resource destroyed and created again under the same name in one apply appears in both.
  The removed entry's `removal` says whether the old object was deleted or only forgotten.
- A resource is resolved only for a resource type its provider's resolver lists in `supported_resource_types`.
- Every entry of `resolved` and `removed` names the tool in `sources.state.tool` in `iac.tool` ("every resolved
  identity names the tool that wrote the state it was read from"), and the document's `unit` in `iac.unit` ("every
  resolved identity belongs to the unit").
- An unresolved `reason` is the first that holds, in this order: `no_resolver`, `provider_untrusted`,
  `resolver_unverified`, `identifier_sensitive`, `identifier_invalid`, `identifier_missing`,
  `identifier_ambiguous`.
- For `aws`, `cloud` holds the `resource_type` (`s3_bucket`, `rds_instance`, `security_group`, `iam_role` or
  `kms_key`) and the `identifier` (`scheme: aws_arn`, `value`). Each ARN must match its type's published
  naming rule, holds no wildcard and is at most 2048 characters. An S3 bucket name and an RDS instance identifier are
  lowercase, as AWS stores them.
- `removed`, `removed_unresolved` and `tool_data.deposed_deleted` are `null` exactly when `sources.plan` is
  `null`.
- Identities read from a refresh-only plan (`read_from: refresh_plan`), a plan that reads the resources back and
  changes nothing, name no applied plan: `sources.plan` is `null`, and so are the removed lists. Otherwise the
  document is refused: "identities read from a refresh-only plan name no applied plan".
- `sources.plan.digest_version` is the version of the plan digest rule for `sources.state.tool`, since the tool that
  wrote the state wrote the applied plan. Any other version is refused.
- The document carries identifiers only. The state file it was read from never leaves the machine that read it.

## EvaluatorBindingSet

An evaluator binding set says which scanner checks decide which assertion. Each binding names one assertion and lists
its scanner evaluators. An evaluator says: these checks of this tool, at a version the constraint admits, read from
this kind of input, together decide the assertion at this stage. Nothing is run for a bound check: the scanner already
ran in the pipeline, and its results become one evaluation of the assertion, beside the assertion's own rule when it
has one (see [How evaluators combine](#how-evaluators-combine)).

A binding is a lookup table, never a requirement: a stage uses the reports it was given, and a scanner with no report
adds nothing unless the run requires it (see [Evaluations from a scanner's
results](#evaluations-from-a-scanners-results)). A check bound nowhere is not an error: its result is kept as
evidence, never turned into a verdict.

- **apiVersion:** `iltero.com/v1`, with `kind: EvaluatorBindingSet`
- **Model:** `iltero_schemas.models.binding.EvaluatorBindingSet`

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion`, `kind` | string | `iltero.com/v1` and `EvaluatorBindingSet`. |
| `metadata` | object | The binding set's `id` and `version`. |
| `spec.bindings` | list | 1 to 10,000 bindings, sorted by assertion id, each assertion once. |

Each binding (`AssertionBinding`):

| Field | Type | Meaning |
| --- | --- | --- |
| `assertion` | object | The assertion it decides: its `id`, `version` and the `digest` of its document. |
| `evaluators` | list | 1 to 32 scanner evaluators, sorted by stage in lifecycle order, then by tool, one per tool and stage. |

Each evaluator (`ScannerBinding`):

| Field | Type | Meaning |
| --- | --- | --- |
| `tool` | string | `checkov` or `trivy`. |
| `stage` | stage | The stage at which the checks decide the assertion. |
| `rule_ids` | list | The tool's own check ids, such as `CKV_AWS_16`, 1 to 16, sorted, each once, compared exactly as the tool writes them. All of them decide together: any that fails fails the assertion, and all of them must pass for it to pass. |
| `tool_version_constraint` | string | A PEP 440 (Python's version specification) specifier with an upper bound, such as `>=3,<4`. A result from a version outside it decides nothing. |
| `input_kind` | string | What the scanner read, in the contract's words: `plan` (the values the plan settled on) or `deployed_resources`. |
| `subject_match` | string | How a result finds the subject it decides: `exact_address` (the result's resource is the subject) or `plan_configures` (the result is about a resource whose configuration refers to the subject, such as an S3 bucket's public access block). |
| `paths_read` | list | The attribute paths the checks read on the resources their results are about, 1 to 32, with `/` between names and `*` for any list element (`ingress/*/cidr_blocks`), sorted, each once. A result that passes while one of these values is known only after the deployment does not pass. |

Key rules:

| Rule | Refused with |
| --- | --- |
| An evaluator reads the input its stage stands for (`STAGE_INPUT_KINDS`): `plan` at `plan`, `deployed_resources` at `runtime`. No other stage reads scanner input. | "a scanner binding at plan reads plan input", "a scanner binding at pre_deploy reads no scanner input" |
| `tool_version_constraint` is a version specifier, bounded from above. | "is not a version specifier", "bounds the version from above, such as <4" |
| `rule_ids` and `paths_read` are sorted, each once. | "rule_ids is sorted, each check once", "paths_read is sorted, each path once" |
| A binding's evaluators are one per tool and stage, in order. | "evaluators are in lifecycle order of their stage, then by tool, one per tool and stage" |
| Each assertion is bound once, in id order. | "bindings are sorted by assertion id, each assertion once" |
| A tool's check is used once per stage across the whole set. | "two bindings use the same check of the same tool at the same stage" |
| No binding decides an assertion in `iltero_schemas.assertions.NOT_DECIDED_BY_SCANNERS` (see [AssuranceEvent](#assuranceevent)). | "no binding decides ILT.COMMON.CHANGE.APPROVAL.PRODUCTION_APPROVED: a scanner's result never decides it" |

- A tool's word is a decision only as `iltero_schemas.models.binding.TOOL_DECISIONS` lists it:

  | `tool` | Words |
  | --- | --- |
  | `checkov` | `PASSED` is `pass`, `FAILED` is `fail` |
  | `trivy` | `PASS` is `pass`, `FAIL` is `fail` |

- A pre-release version, a local build (`3.2.1+patched`) or a version string not written as the tool releases it
  (`v3.2.1`) satisfies no constraint (`constraint_met`).
- An event decided through an evaluator names it by `AssertionBinding.evaluator_digest(evaluator)`: the digest of
  `{"assertion": <the binding's assertion>, "evaluator": <the evaluator>}`, each as the model dumps it, so an edit to
  either is visible. `EvaluatorBindingSet.by_digest` finds an evaluator by that digest.
- That an evaluator's stage is one of the assertion's stages needs the assertion's document, so a reader checks it
  with the document (see [The check a reader runs](#the-check-a-reader-runs)).
- A set read from a project's own file decides only the project's own assertions
  (`iltero_schemas.models.binding.check_project_set`): its id's namespace is not `ILT` and does not start with `ILT`
  ("a project's own id has a namespace of its own, not ILT or one starting so"), and no binding decides an assertion
  whose namespace starts with `ILT`, since Iltero's are bound only by the sets Iltero ships ("a project's binding set
  decides only the project's own assertions, not ILT.IAC.RESOURCE.AWS.RDS.STORAGE_ENCRYPTED", with the id).
- The package ships one set, `ILT.BINDINGS.STARTER` (`iltero_schemas.bindings.SHIPPED_SET`). It binds nine starter
  assertions about AWS resources to checks of Checkov (`>=3,<4`), Trivy (`>=0.72,<1`) or both. A record names it with
  `origin: shipped`, and its digest is `SHIPPED_SET_DIGEST`. `SHIPPED_SET_EVALUATORS` gives the digest of each of its
  evaluators, and `SHIPPED_SET_ASSERTIONS` the version and document digest each binding cites.
- `iltero_schemas.bindings.load_binding_set` reads a set from YAML text with the loader of a
  [TechnicalAssertion](#technicalassertion), under the same rules: one document of at most 256 KiB, nested at most 32
  levels, with no anchors, aliases, tags, merge keys or duplicate keys, and no value written other than as `null`.

```yaml
apiVersion: iltero.com/v1
kind: EvaluatorBindingSet
metadata:
  id: ACME.BINDINGS.PAYMENTS
  version: "1.0.0"
spec:
  bindings:
    - assertion:
        id: ACME.IAC.RESOURCE.AWS.RDS.STORAGE_ENCRYPTED
        version: "1.0.0"
        digest: "sha256:<digest of the assertion's document>"
      evaluators:
        - tool: checkov
          stage: plan
          rule_ids: [CKV_AWS_16]
          tool_version_constraint: ">=3,<4"
          input_kind: plan
          subject_match: exact_address
          paths_read: [storage_encrypted]
```

## ScannerObservations

Scanner observations are what a stage read from one scanner's report, in one shape for every tool. The Iltero CLI
reads the report once and keeps what a verdict can rest on: for each result, the check, the tool's own word for its
outcome and the decision that word names, what the tool read, the resource address the tool wrote, and the plan
address it resolves to, or why it resolves to none. Titles, severities and source locations are not kept.

- **apiVersion:** `iltero.com/v1`, with `kind: ScannerObservations`
- **Model:** `iltero_schemas.models.iac.scanner_observations.ScannerObservations`. The readers
  `iltero_schemas.models.iac.scanner_reports.checkov.read_checkov` (a `checkov -o json` report) and
  `iltero_schemas.models.iac.scanner_reports.trivy.read_trivy` (a `trivy config --format json` report) build it from
  a report and the plan's resource addresses (`plan_resource_addresses`).

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion`, `kind` | string | `iltero.com/v1` and `ScannerObservations`. |
| `tool`, `tool_version` | string, identifier | The scanner and the version it wrote into its report. |
| `supplied_by` | string | Always `pipeline`, which supplied the report. |
| `rules_digest`, `configuration_digest` | digest or null | The digests of the tool's separately downloaded checks (Trivy's checks bundle) and of its configuration and ignore files. `null` means the stage was not given them, never that none was used. |
| `report_digest` | digest | The report as the stage kept it, in the contract's [kept form](#the-report-a-stage-keeps). |
| `plan_digest` | digest | The plan the stage evaluated, as it kept it, redacted. |
| `input_kinds` | list | What the tool read, translated into the contract's words (`TOOL_INPUT_KINDS`), sorted, each once. |
| `unreadable_results` | integer | Results of the report the reader could not read, which decide nothing. |
| `written_configuration_results` | integer | Results about the IaC configuration as written (not the tool's own settings, which `configuration_digest` covers), which no stage reads, counted and left out of `results`. |
| `tool_parsing_errors` | integer or null | Files the tool says it could not parse, or `null` when the tool does not say. |
| `results` | list | At most 200,000 results, sorted by check, then input kind, then the tool's address (a result with none first), each once. |

Each result (`ScannerResult`):

| Field | Type | Meaning |
| --- | --- | --- |
| `rule_id` | string | The check, as the tool names it. |
| `tool_status`, `decision` | identifier, string or null | The tool's own word, and the decision it names (`pass` or `fail`), or `null` for a word that is not a decision. |
| `suppressed` | boolean | The tool skipped the check because the scanned source asked it to. A suppressed result is no decision. |
| `input_kind` | string | What the tool read for this result. |
| `scanner_address`, `plan_address`, `unresolved_reason` | string or null | The address the tool wrote, the plan address it resolves to, or `null` with `not_in_plan`, `ambiguous` or `no_address` (see [How a scanner's results decide a subject](#how-a-scanners-results-decide-a-subject)). |
| `connected_scanner_address`, `connected_plan_address` | string or null | For a check about two resources, such as a recorder status and its recorder, the other resource's address as the tool wrote it and as it resolves. |
| `evaluated_keys` | list | The attribute paths the tool says it read, sorted, each once, at most 32. |

Each tool's words for what it read (`TOOL_INPUT_KINDS` for `plan`, `TOOL_CONFIGURATION_WORDS` for the configuration
as written):

| `tool` | `plan` | Configuration as written, counted in `written_configuration_results` |
| --- | --- | --- |
| `checkov` | `terraform_plan` | `terraform` |
| `trivy` | `terraformplan` | `terraform` |

A result whose tool word is not listed, whose word for what it read is not a string, or that cannot otherwise be read,
is counted in `unreadable_results`. A report
that gives one check twice for one address, from a tool that writes each resource once per check (Checkov), covers
more than one plan and is refused.

A Trivy `CauseMetadata` or a Checkov `connected_node` that is present but neither an object nor `null` makes its result
unreadable: the reader cannot tell which resource the result is about, and never reads it as absent.

Checkov writes `summary.parsing_errors` for each framework. `tool_parsing_errors` is their sum, or `null` when no
framework gives one. A report in which some frameworks give it and others do not, or one gives anything but a whole
number from 0, is refused: "the checkov report gives the count of files it could not parse for some frameworks but
not for others, or gives one that is not a count". One framework that does not say never hides the files another
could not parse. A framework's `summary` that is present but neither an object nor `null` is refused too: "the checkov
report gives a framework a summary that is not an object".

### Hidden objects, lists and counts

A redaction marker where a reader expects an object, a list or a count makes the report unreadable as a whole, and
the reader refuses it (`iltero_schemas.models.iac.scanner_reports.common.opened` raises `ReportError`), whatever the
marker's `present` says: read as empty or absent, a hidden list could hide a failure. The message names the place and
what the reader expects there, such as "the report hides the list of results, where its reader expects a list". A
marker whose `type` is `null` (`HIDDEN_NULL_TYPE`) and whose `present` is `false` is the one exception: it reads as
the `null` it stands for. A marker of type `null` whose `present` is `true` claims a value that was never there, and
is refused like any other. A
marker in place of a value the reader reads, such as a rule id or an address, makes only that result unreadable.

| Tool | Places where a marker other than a hidden `null` refuses the report |
| --- | --- |
| `checkov` | The whole report (an object or a list); each framework of a list of them; a framework's `results` and `summary`; `summary.parsing_errors` (a count); each of the `passed_checks`, `failed_checks` and `skipped_checks` lists; each result in them; a result's `check_result` and `connected_node`; `check_result.evaluated_keys` (a list). |
| `trivy` | The whole report; `Trivy`; `Results`; each element of `Results`; its `Misconfigurations`; each misconfiguration; its `CauseMetadata`. |

A record whose kept report its reader refuses is refused with "names a report its reader cannot read".

Key rules:

| Rule | Refused with |
| --- | --- |
| A result resolves to a plan address, or names why it resolves to none. | "a result resolves to a plan address, or names why it resolves to none" |
| It resolves to no address exactly when the tool wrote none. | "a result resolves to no address exactly when the tool wrote none" |
| A suppressed result is no decision. | "a suppressed result is no decision" |
| Its decision is the one the tool's word names. | "a result's decision is the one checkov's word for it names, or none" |
| Its input kind is one the observations name. | "a result is of an input kind the observations name" |
| Results are sorted, each once. | "results are sorted by check, input kind and address, each once" |

A report the pipeline supplied is the pipeline's own claim: nothing in the observations shows that the tool read the
plan they name.

## LocalExceptions

A local exceptions document holds the exceptions a project writes in its own files, for a run the tool opened. Each
exception says that an assertion is excused for an environment and the resources it names, between two times, why,
and who the project says approved it. It is the project's own word: nothing outside the project approved it. A stage
applies the file only to the scanner results the scanned source suppressed, to name the exception each suppression
rests on; such a result stays `not_evaluated` with `suppressed_in_source`. An exception explains a gap, it never
fills it.

- **apiVersion:** `iltero.com/v1`, with `kind: LocalExceptions`
- **Model:** `iltero_schemas.models.local_exceptions.LocalExceptions`. `read_local_exceptions(data, file_path)` reads
  the file's bytes (see [Reading the file](#reading-the-file)).

```yaml
apiVersion: iltero.com/v1
kind: LocalExceptions
metadata:
  name: payments-exceptions
spec:
  exceptions:
    - id: exc_0001
      status: approved
      scope:
        assertion:
          id: ILT.IAC.RESOURCE.AWS.RDS.NOT_PUBLIC
        environment: production
        resources:
          - scheme: terraform_address
            scope:
              unit: root
            value: aws_db_instance.payments
      valid_from: "2026-09-01T00:00:00Z"
      expires_at: "2026-12-01T00:00:00Z"
      approved_by:
        provider: github
        id: u_1
      reason: The database is reached only through a private network link.
```

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion`, `kind` | string | `iltero.com/v1` and `LocalExceptions`. |
| `metadata.name` | string | The name the project gives the document: 1 to 63 lowercase letters, digits and hyphens, starting and ending with a letter or a digit. |
| `spec.exceptions` | list | 1 to 256 exceptions, in the shape of the Exception item of an [AssuranceContext](#assurancecontext): `id`, `status` (always `approved`), `scope` (`assertion.id`, `environment` and `resources`), `valid_from`, `expires_at`, `approved_by` and `reason`. In this file, `status` and `approved_by` are what the project says: nothing checks them. |

| Rule | Refused with |
| --- | --- |
| Each exception has an id of its own. | "each exception has an id of its own" |
| Each resource is named by its address in the IaC tool's configuration (`scheme: terraform_address`), with `scope` exactly `{"unit": <its unit>}`. A cloud identity is not accepted: a resource being created has none, and one that is replaced gets a new one. | "an exception in a project's own files names each resource by its address, scoped by its unit and nothing else" |
| No two exceptions cover the same assertion, environment and resource at overlapping times, so the exception that covers a result is never a choice. Two periods overlap when each starts no later than the other expires. | "no two exceptions cover the same assertion, environment and resource at the same time" |
| An exception lasts at most 365 days of 24 hours from its `valid_from` (`MAX_EXCEPTION_DAYS`), compared to the nanosecond. A calendar year that holds 29 February is 366 days, longer than this limit. | "an exception in a project's own files lasts at most 365 days from when it starts" |
| An exception expires after it starts, and never names a built-in assertion, as for the Exception item. | "an exception expires after it starts", "an exception never covers a built-in assertion: what it records is never waived" |

### Reading the file

`read_local_exceptions` reads the file as its name's suffix says, then validates it with the model. It raises
`ValueError` with the message below.

| Rule | Refused with |
| --- | --- |
| The file is named `.json`, read as JSON, or `.yaml` or `.yml`, read as YAML (`EXCEPTIONS_FILE_SUFFIXES`). | "a project's exceptions file is JSON or YAML, named .json, .yaml or .yml" |
| The file is at most 256 KiB (262,144 bytes, `iltero_schemas.ast.document.MAX_DOCUMENT_BYTES`), the limit of a [TechnicalAssertion](#technicalassertion). | "a project's exceptions file is at most 262144 bytes" |
| JSON is UTF-8 with no byte order mark, names each key once and holds no constant such as `NaN`. | "a project's exceptions file names each key once", or the message that names the other problem |
| YAML is UTF-8 text, read by the loader of a TechnicalAssertion under the same rules: one mapping, with no anchors, aliases, tags, merge keys or duplicate keys. | "a project's exceptions file is UTF-8 text", or the loader's message |

In YAML, write each time in quotes. An unquoted time is read as a YAML date and time, not as text, and the file is
refused.

### When an exception covers a result

`exception_in_force(grants, assertion_id, identity, environment, at)` gives the exception that covers one result, or
`null` when none does. An exception covers it when all of these hold:

- its `scope.assertion.id` is the assertion's id, at any version;
- one of its `resources` is the result's subject: the same `scheme`, `value` and `scope`, the subject's identity in
  the address scheme of the plan's IaC tool;
- its `scope.environment` is the record's `subject.environment`. A run that names no environment has no exception in
  force;
- it is in force at the stage's `reference_time.value`: from `valid_from` up to and including `expires_at`, compared
  to the nanosecond (`iltero_schemas.models.server_facts.in_force`).

At most one exception can cover a result. `why_no_exception` gives the reason none does, the first that holds, or
`null` when one does:

| Reason | When |
| --- | --- |
| `no_exception_for_the_assertion_and_resource` | No exception is about the assertion and the resource. |
| `run_names_no_environment` | Some are, but the run names no environment. |
| `for_another_environment` | Every one that is names another environment. |
| `expired` | Every one for the run's environment expired before the reference time. |
| `not_yet_in_force` | None for the run's environment is in force, and one starts after the reference time: before the only one starts, or between two. |

### A stage that applies the file

A stage that applied the project's exceptions file names it in `scanners.local_exceptions`
(`LocalExceptionsUsed`) and keeps a byte copy of it:

| Field | Type | Meaning |
| --- | --- | --- |
| `file_path` | string | Where the file is in the project, relative to the project's directory: no `.`, `..` or empty part, no `:`, no `\` and no leading `/`. Its suffix is `.json`, `.yaml` or `.yml`: "a project's exceptions file is JSON or YAML, named .json, .yaml or .yml". |
| `digest` | digest | The SHA-256 of the file's raw bytes as the project wrote them, comments included, not of its canonical JSON. A reader can compare the copy with the file at the record's commit. |
| `copy_path` | string | Where the stage kept its byte copy, in the record's directory. It has the suffix of `file_path`: "the copy of a project's exceptions file has the file's own suffix". The copy is an entry of the evidence register, copied byte for byte from the file (see the register rules in [Change Assurance Record (CAR)](#change-assurance-record-car)). |

A scanner evaluation names an exception in `provenance.evaluator.local_exception` (`LocalExceptionRef`): its `id` and
the `file_digest` of the file it is in, which repeats the stage's `digest` so each event stands on its own. The model
refuses a record that breaks one of these rules:

| Rule | Refused with |
| --- | --- |
| Only a `suppressed_in_source` evaluation names an exception. | "a scanner's evaluation names a project's exception only for a suppressed check" |
| An evaluation names an exception only from the file its stage applied: its `file_digest` is that stage's `scanners.local_exceptions.digest`. | "a scanner result names an exception only from the project's exceptions file its stage applied" |
| A record of a run Iltero Platform opened (`governance.run_opened_by: server`) names no exception from a project's files. | "a record of a run the server opened names no exception from a project's own files" |
| A record of a run Iltero Platform opened applies no exceptions file: every stage's `scanners.local_exceptions` is `null`. | "a record of a run the server opened applies no exceptions file of the project's own" |

The model does not read the copy. A reader does, with
[`scanner_evidence_problems`](#the-check-a-reader-runs), given the copy's bytes in `KeptFiles.exceptions`: for each
suppressed result of the stage it works out again which exception covers it, and the record must name that one, or
none when none covers it.

## PolicySource

A policy source describes a directory of hand-written Rego policies, for rules the assertion language
cannot express. Each entry names the assertion a policy decides, the stage, the target and the one `.rego` file it
is written in.

- **apiVersion:** `iltero.com/v1`, with `kind: PolicySource`
- **Model:** `iltero_schemas.models.policy_source.PolicySource`

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion`, `kind` | string | `iltero.com/v1` and `PolicySource`. |
| `metadata.name` | string | The name the project gives the document: 1 to 63 lowercase letters, digits and hyphens, starting and ending with a letter or a digit. |
| `spec.policies` | list | 1 to 512 entries, each described below. |

Each entry:

| Field | Type | Meaning |
| --- | --- | --- |
| `title` | string | What the policy claims, at most 200 characters. |
| `assertion` | object | The `id` and `version` of the assertion the policy decides. |
| `stage` | stage | When the policy is evaluated. |
| `target` | object | The same shape as a TechnicalAssertion's `spec.target`. |
| `file` | string | A plain `.rego` file name inside the directory, with no directory part. |

Key rules:

- The entry's `assertion.id` is an [assertion id](#assertion-ids), checked against the entry's `target` as an
  assertion's id is against its `spec`. A policy names no change type of its own: it is read from the id's second
  segment (`iltero_schemas.models.assertion_id.change_type_of_id`), and any other segment is refused: "an assertion
  id's second segment names its change type: one of IAC, IMAGE, COMMON". The stage and the target kind form a
  combination that change type allows, or, for `COMMON`, one some change type allows (`VALID_COMBINATIONS`).
- The entry's assertion is the project's own: its namespace is not `ILT` and does not start with `ILT`
  (`check_project_id`): "a project's own id has a namespace of its own, not ILT or one starting so".
- One policy decides an assertion at a stage. Two policies are never written in the same file.
- Each file declares the package `iltero.assertions["<id>"]` of the assertion it decides.
- A record that ran a hand-written policy says so, and a replay runs the retained code, because nothing can derive
  it again.

## AssertionBundleDescriptor

A bundle descriptor is how Iltero Platform serves a signed assertion bundle. It carries the signed Open Policy Agent
(OPA) bundle tarball and each assertion's source, so a tool can recompile every assertion and compare the result
with the module in the tarball before it runs anything.

- **apiVersion:** `iltero.com/v1`, with `kind: AssertionBundleDescriptor`
- **Model:** `iltero_schemas.models.bundle.BundleDescriptor`

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion`, `kind` | string | `iltero.com/v1` and `AssertionBundleDescriptor`. |
| `content_digest` | digest | The digest of the bundle's content: the `metadata.iltero` object of its `.manifest` file, which holds the `apiVersion`, `kind: AssertionBundle`, `compiler_version`, `capabilities_digest`, `minimum_cli_version`, `assertion_set_digest` and `assertions` (each without its `source`). The `.manifest` file carries the same value under OPA's key `revision`. |
| `tarball_digest` | digest | The SHA-256 of the decoded tarball bytes, signature included, never of their base64 text. |
| `key_id` | identifier | The key that signed the bundle. |
| `algorithm` | string | `ES256`. |
| `compiler_version` | identifier | The compiler version the modules were built with. |
| `capabilities_digest` | digest | The digest of the evaluator's allowlist of built-in functions the modules were built under. |
| `minimum_cli_version` | string | The oldest CLI version able to evaluate the bundle, such as `1.2.3`. |
| `assertion_set_digest` | digest | The digest of every assertion in the bundle, by id, version and document digest. |
| `assertions` | list | 1 to 1,024 assertions, sorted by id: `id`, `version`, `digest`, `source_digest`, `compiled_digest` and the YAML `source`. |
| `tarball` | string | The signed tarball, standard base64 with padding, at most 16 MiB decoded. |

Key rules:

- A bundle is identified by `content_digest` and `tarball_digest` together. Content has one `content_digest` but can
  have several `tarball_digest` values, because an ES256 signature can differ on each signing, under the same key or
  another.
- `content_digest` is recomputed from the assertions' sources (`iltero_schemas.bundle.check_descriptor`); a
  descriptor whose value differs is refused.
- `tarball_digest` is taken over the bytes served, because compression libraries can write different bytes for the
  same files. A descriptor whose `tarball_digest` is not the SHA-256 of its decoded `tarball` is refused.
- `assertion_set_digest` names everything in the bundle.
- `check_descriptor` refuses a descriptor whose `compiler_version` is not `iltero_schemas.compiler.COMPILER_VERSION`:
  `the bundle was compiled by another compiler version; this package's is <version>`.
- `check_descriptor` refuses a descriptor whose `capabilities_digest` is not `iltero_schemas.opa.CAPABILITIES_DIGEST`:
  `the bundle was built under another allowlist; this package's is <digest>`. The content digest covers the
  allowlist, so the same assertions built under another allowlist have another `content_digest`.
- The signing key must be in the trusted keys and must not be revoked.
- A descriptor is at most 64 MiB as canonical JSON (`iltero_schemas.models.bundle.MAX_DESCRIPTOR_BYTES`); a larger
  one is refused. The limit is applied to the parsed descriptor, so a tool also caps the bytes it reads before parsing.

## BundleSigningKeys

The trusted bundle keys file lists the public keys that may sign an assertion bundle. It ships inside the package
as `iltero_schemas/trust/bundle-keys.json`, so a tool that pins one package version also pins the keys it trusts.

- **apiVersion:** `iltero.com/v1`, with `kind: BundleSigningKeys`
- **Reader:** `iltero_schemas.trust.parse_bundle_keys`, with the shipped set in `iltero_schemas.trust.BUNDLE_KEYS`,
  the digest of the file's bytes in `iltero_schemas.trust.TRUST_FILE_DIGEST` and its `kind` in
  `iltero_schemas.trust.TRUST_FILE_KIND`

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion`, `kind` | string | `iltero.com/v1` and `BundleSigningKeys`. |
| `keys` | list | Each key's `key_id`, `algorithm` (`ES256`), `public_key` (an uncompressed P-256 SubjectPublicKeyInfo, base64), `spki_sha256`, `status`, `valid_from`, `retired_at`, `revoked_at` and `revocation_reason`. |

Key rules:

- The file has exactly the fields `apiVersion`, `kind` and `keys` ("must have exactly the fields apiVersion, kind
  and keys"), with this `apiVersion` ("apiVersion: must be iltero.com/v1") and this `kind` ("kind: must be
  BundleSigningKeys").
- `active` keys sign and verify. `retired` keys only verify. `revoked` keys never verify again, whenever the
  signature was made.
- Keys are never removed. A status only moves forward: `active` to `retired` or `revoked`, `retired` to `revoked`.
- A key id starting with `dev-` (`iltero_schemas.trust.DEVELOPMENT_KEY_PREFIX`) is a development key. The reader
  refuses it, unless it is called with `development=True`, for a development tool's own local file; then every key
  must be a development key.
- Any change to the keys requires a new package version.
