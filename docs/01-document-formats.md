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
- [ScannerCheckMapping](#scannercheckmapping)
- [ScannerObservations](#scannerobservations)
- [LocalExceptions](#localexceptions)
- [ServedExceptions](#servedexceptions)
- [PolicySource](#policysource)
- [AssertionBundleDescriptor](#assertionbundledescriptor)
- [ScannerCheckMappingDescriptor](#scannercheckmappingdescriptor)
- [SigningKeys](#signingkeys)

## Conventions

Every document names itself by two top-level fields: `apiVersion`, which is `iltero.com/v1` for every document
(`iltero_schemas.models.common.base.API_VERSION`), and `kind`, which names the document type. A reader accepts exactly its
own pair. A document with any other `apiVersion`, with no `kind`, or with the `kind` of another document is refused.
A `kind` nested inside a document, such as a target's, a subject's or a gap's, is an ordinary field described with
its parent.

| `kind` | Document | Read by |
| --- | --- | --- |
| `TechnicalAssertion` | [An assertion](#technicalassertion) | `iltero_schemas.models.common.assertion.TechnicalAssertion` |
| `AssuranceContext` | [An evaluation input](#assurancecontext) | `iltero_schemas.models.common.context.AssuranceContext` |
| `AssuranceEvents` | The events file a stage keeps (see the stage's [`events`](#change-assurance-record-car)) | No model: `iltero_schemas.models.common.event.events_file_bytes` writes it, and a record names it by path and digest |
| `ChangeAssuranceRecord` | [A record](#change-assurance-record-car) | `iltero_schemas.models.common.car.CAR` |
| `VerificationReport` | [A verification report](#verificationreport) | `iltero_schemas.models.common.verification.VerificationReport` |
| `ResourceIdentities` | [A resource identities document](#resourceidentities) | `iltero_schemas.models.iac.resource_identities.ResourceIdentities` |
| `ScannerCheckMapping` | [A scanner check mapping](#scannercheckmapping) | `iltero_schemas.models.iac.scanner_check_mapping.ScannerCheckMapping` |
| `ScannerObservations` | [What a stage read from a scanner's report](#scannerobservations) | `iltero_schemas.models.iac.scanner_observations.ScannerObservations` |
| `LocalExceptions` | [A project's own exceptions](#localexceptions) | `iltero_schemas.models.common.local_exceptions.LocalExceptions` |
| `ServedExceptions` | [The exceptions Iltero Platform serves one stage of a run](#servedexceptions) | `iltero_schemas.models.common.served_exceptions.ServedExceptions` |
| `PolicySource` | [A directory of hand-written policies](#policysource) | `iltero_schemas.models.common.policy_source.PolicySource` |
| `AssertionBundleDescriptor` | [How Iltero Platform serves a signed assertion bundle](#assertionbundledescriptor) | `iltero_schemas.models.common.bundle.BundleDescriptor` |
| `ScannerCheckMappingDescriptor` | [How Iltero Platform serves a signed scanner check mapping](#scannercheckmappingdescriptor) | `iltero_schemas.models.iac.scanner_check_mapping_descriptor.ScannerCheckMappingDescriptor` |
| `AssertionBundle` | The assertion bundle's own description, in its `.manifest` file (`iltero_schemas.models.common.bundle.BUNDLE_KIND`) | `iltero_schemas.bundle.check_descriptor`, which rebuilds it |
| `SigningKeys` | [The trusted signing keys](#signingkeys) | `iltero_schemas.trust.parse_signing_keys` |

Documents take one of two shapes:

- A document Iltero writes as evidence keeps its content at the top level. Facts about the document itself sit in a
  `metadata` object where the document has any: a record's `metadata` holds its `uuid` and `issuer`, a verification
  report's its `verifier` and `verified_at`, and a resource identities document's its `generator`. An evaluation input,
  a bundle descriptor, a scanner check mapping descriptor, scanner observations and the trust file have no
  `metadata`.
- A document a person writes has four top-level fields: `apiVersion`, `kind`, `metadata`, which says which document
  it is, and `spec`, which holds what it says. A TechnicalAssertion and a ScannerCheckMapping name themselves by
  `metadata.id` and `metadata.version`. LocalExceptions and PolicySource name themselves by `metadata.name`, a
  name the project chooses: 1 to 63 lowercase letters, digits and hyphens, starting and ending with a letter or a
  digit (`iltero_schemas.models.common.fields.PROJECT_DOCUMENT_NAME_PATTERN`).

A document's digest covers the whole document, `apiVersion`, `kind` and `metadata` included.

Every model applies the same rules:

- A key the model does not define is refused.
- No value is converted. The string `"true"` is not a boolean, and `"7"` is not a number.
- A text field the model types (a name, an identifier, an address, a title) never contains a control character,
  a zero-width character, a bidirectional formatting character or another character that shows as nothing: a soft
  hyphen, the combining grapheme joiner, the Arabic letter mark, the Mongolian vowel separator or a Hangul filler.
  The refused characters are listed by code point (`iltero_schemas.models.common.assertion.CONTROL_CHARACTERS`), so every
  reader refuses the same ones whatever its Unicode version: U+0000–U+001F, U+007F–U+009F, U+00AD, U+034F,
  U+0600–U+0605, U+061C, U+06DD, U+070F, U+0890–U+0891, U+08E2, U+115F–U+1160, U+180E, U+200B–U+200F,
  U+2028–U+202E, U+2060–U+2064, U+2066–U+206F, U+3164, U+FEFF, U+FFA0, U+FFF9–U+FFFB, U+110BD, U+110CD,
  U+13430–U+1343F, U+1BCA0–U+1BCA3, U+1D173–U+1D17A, and the tag characters U+E0000–U+E007F, which spell text a
  reader does not see. The message is "must not contain control characters". Variation selectors, which follow
  ordinary emoji, are accepted.
  Fields that carry data as another tool wrote it, such as a resource's planned values in an AssuranceContext,
  accept any JSON value.
- A list of names that the model keeps sorted is sorted by Unicode code point, with no name twice.
- A count (`iltero_schemas.models.common.fields.Count`) is an integer from 0 to 2^53 − 1
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
| commit | A full git object id: 40 lowercase hexadecimal digits (SHA-1) or 64 (SHA-256). |
| git object id | The id of any other git object, such as a tree, in the same form as a commit (`iltero_schemas.models.common.fields.GitObjectId`). |
| identifier | Text of 1 to 256 characters. |
| stage | `plan`, `pre_deploy`, `post_deploy`, `post_verify` or `runtime` (see below). |

A stage is a point in a change's life at which assertions are checked:

| Stage | What is checked |
| --- | --- |
| `plan` | The change to deploy, once it is produced and before anyone approves it. For an IaC (infrastructure-as-code) change, the IaC tool's plan. For a container image build, the image the build pushed, before any deployment uses it. |
| `pre_deploy` | The change, at the gate before it is deployed: approvals, earlier evaluations and whether its commits were reviewed. |
| `post_deploy` | What the deployment did. |
| `post_verify` | What runs after the deployment: the deployed resources, read back, or the workload that runs a deployed image. |
| `runtime` | Resources as they run, outside any change. No record has a `runtime` stage. |

## TechnicalAssertion

A technical assertion is a rule about infrastructure or a built artifact, written in YAML. It states what must be
true, at which stage of a change it is checked, and what kind of thing it is about. The compiler turns it into one
OPA program.

- **apiVersion:** `iltero.com/v1`, with `kind: TechnicalAssertion`
- **Model:** `iltero_schemas.models.common.assertion.TechnicalAssertion`. `iltero_schemas.ast.parse` reads the YAML text,
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
| `spec.evidence.stages` | list | The stages whose scanner results may decide an assertion that has no rule of its own. The only such stage is `plan`, since Iltero reads scanner results at no other stage (`iltero_schemas.models.common.assertion.STAGES_WITH_SCANNER_RESULTS`). Stages are in lifecycle order, each once ("stages are in lifecycle order, each stage once"). Present exactly when `spec.assert` is `null`. |
| `spec.target` | object | What the assertion is about. `kind` is `resource`, `change`, `deployment`, `assurance` or `artifact` (the artifact a build produced, such as a container image). `resources` lists resource selectors: a `resource` target names exactly one; a `change` or `deployment` target may name up to 16, and is then in scope only when the change touches a resource one of them picks. Only an assertion about an `iac_change` names them on a `change` or `deployment` target: "a change target names resources only in an assertion about an iac_change". An `assurance` or `artifact` target names none: "an artifact target names no resources: it has no change to scope". |
| `spec.when` | object | Optional condition. When it is false, the result is `not_applicable`. |
| `spec.assert` | object or null | Required. The rule, or `null` for an assertion that only scanners decide (see below). |

Key rules:

- Each change type allows its own stage and target pairs (`iltero_schemas.models.common.assertion.COMBINATIONS`). Any
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

An assertion with `assert: null` has no rule of its own: only the scanner checks a
[scanner check mapping](#scannercheckmapping) maps to it decide it, and its `metadata.description` says exactly what they
check. Its rules (`iltero_schemas.models.common.assertion.Spec`):

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
fixed place (`iltero_schemas.models.common.assertion_id`):

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

The segments come from `iltero_schemas.models.common.change_type.CHANGE_TYPE_SEGMENT` and `COMMON_SEGMENT`.

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
| `APPROVAL` | `ILT.COMMON.CHANGE.APPROVAL.PRODUCTION_APPROVED`, `ILT.IAC.CHANGE.APPROVAL.SENSITIVE_CHANGE_APPROVED`, `ILT.IAC.CHANGE.APPROVAL.APPROVED_AFTER_PLAN_STAGE_RECORD_ACCEPTED` |
| `SOURCE` | `ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED`, `ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT` |
| `CONTENT` | `ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN`, `ILT.IMAGE.DEPLOYMENT.CONTENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE`, `ILT.IAC.CHANGE.CONTENT.RECEIVED_PLAN_FILE_MATCHES_EVALUATED_PLAN_FILE`, `ILT.IAC.CHANGE.CONTENT.RENDERED_PLAN_MATCHES_EVALUATED_PLAN`, `ILT.IAC.CHANGE.CONTENT.EVALUATED_PLAN_IS_PINNED_PLAN` |
| `DRIFT` | `ILT.IAC.DEPLOYMENT.DRIFT.NO_DRIFT_AFTER_APPLY`, `ILT.IMAGE.DEPLOYMENT.DRIFT.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE` |
| `BUILD` | `ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT` |
| `CHECKS` | `ILT.IMAGE.ARTIFACT.CHECKS.TESTS_RAN`, `ILT.IMAGE.ARTIFACT.CHECKS.SCAN_RAN` |
| `PROVENANCE` | `ILT.IMAGE.ARTIFACT.PROVENANCE.SIGNED_PROVENANCE_MATCHES_RUN` |
| `HISTORY` | None |
| `TIMING` | `ILT.IAC.CHANGE.TIMING.PLAN_AGE_WITHIN_LIMIT` |

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

`ILT` is Iltero's alone (`iltero_schemas.models.common.assertion_id.ILTERO_NAMESPACE`). No other namespace starts with
`ILT`. Where an id is a project's own, `ILT` itself is refused too (`check_project_id`): the assertion of
an event from the project's own files (see [AssuranceEvent](#assuranceevent)), a policy source entry's assertion (see
[PolicySource](#policysource)), and a scanner check mapping read from a file, with each assertion it maps (see
[ScannerCheckMapping](#scannercheckmapping)). `check_project_id` refuses with "a project's own id has a namespace of
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
| An `ILT` process assertion's area is one of `ASSERTION_AREAS`. | "an Iltero process assertion's area must be one of APPROVAL, BUILD, CHECKS, CONTENT, DRIFT, HISTORY, PROVENANCE, SOURCE, TIMING" |

A new change type, provider, target kind or area adds a value to its list and changes no existing id.

An id that refers to an assertion, in an event, a record, an assertion mapping or a bundle, keeps only the general
shape: upper-case segments joined by dots, at least two, at most 96 characters
(`iltero_schemas.models.common.assertion.ID_PATTERN` and `ID_MAX_LENGTH`, which is `ASSERTION_ID_MAX_LENGTH`). A scanner
check mapping's id, such as `ILT.SCANNER_CHECKS.STARTER`, is not an assertion id and keeps the same general shape.

## AssuranceContext

The assurance context is the evaluation input: the one JSON document OPA receives for one assertion about one
subject. The tool that runs OPA records the context's digest in the event as `input_digest`, and the stage keeps the
context, as canonical JSON, for a reader to check against the record (see [Checking the kept evaluation
inputs](#checking-the-kept-evaluation-inputs)).

- **apiVersion:** `iltero.com/v1`, with `kind: AssuranceContext`
- **Model:** `iltero_schemas.models.common.context.AssuranceContext`.
  `iltero_schemas.profiles.profile_for(activity, stage, kind)` gives the parts an input of an activity carries at a
  stage, for a target kind.

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion`, `kind` | string | `iltero.com/v1` and `AssuranceContext`. |
| `evaluation` | object | This evaluation: its `id`, the [`activity`](#change-types-and-activities) it belongs to (`iac_change`, `image_build` or `image_deploy`), its `stage`, the runner's `timestamp`, and the `assertion` (`id`, `version`). |
| `organization_scope` | object | The `organization`, `workspace` and `environment`, each `null` when the run has none. The `environment` has its `name` and `production`: whether Iltero Platform's environment policy treats it as production, or the unknown marker in a run Iltero Platform did not open. |
| `reference_time` | object | The time every expiry and ordering comparison uses (`iltero_schemas.models.common.reference_time.ReferenceTime`): its `value` (timestamp) and its `source`, `server` for the time Iltero Platform gave the run or `runner_clock` for the runner's own clock. Any other source is refused: "Input should be 'server' or 'runner_clock'". The document states the source; a [verification report](#verificationreport) judges how far it can be trusted. Read from the runner's clock, its `value` is the same instant as `evaluation.timestamp`: "an input that reads its runner's clock uses the time of its evaluation". |
| `source` | object | The code the change comes from: `vcs` (`git`) and the `commit` (`sha`); the `repository` (`name`), `null` for a checkout with no remote; the `ref` (`type`: `branch` or `tag`, and `name`), `null` for a detached head; and the `pull_request` (`id`), `null` for a run outside a pull request. A run on a developer's machine is never a pull request. |
| `change` | object | The resources the plan changes (`id`, `provider`, `type`, `kind`, `action`, `module`), and the change `digest`: the [change digest](#the-change-digest) of `iac_change`, the subject's unit, the environment key `organization_scope.environment.name` (`null` when the environment is `null`) and `plan.digest`. A context with any other `digest` is refused: "change.digest is the digest of the change type, unit, environment and plan". `provider` is the provider's short name: lower-case letters, digits, `_` and `-`, starting with a letter (`aws`, `google-beta`). `kind` is the kind the plan tool's table gives the type, or the unknown marker `{"__unknown": true, "reason": "kind_unmapped"}` when the table lacks it; it is `null` exactly for a provider with no kinds. A context whose kinds differ from the table's is refused. In an `image_deploy` input, the change is the deployed image instead: its `digest`, the change digest of `image_release`, the subject's unit, the environment key and the image; the `image` (`repository`, `digest`); and the `build` Iltero Platform accepted, `null` when it accepted none, or the unknown marker `{"__unknown": true, "reason": "server_facts_unavailable"}` in a run the tool opened (see [The `image_deploy` body](#the-image_deploy-body)). An `image_deploy` input names its environment ("a deploy's input names its environment: a deploy is to one"), and `build` holds the marker exactly when `organization_scope.environment.production` does: "change.build holds the unknown marker exactly when the environment's production flag does: both hold it only in a run no server opened". A context with any other `digest` is refused: "change.digest is the digest of the change type, unit, environment and image". |
| `plan` | object | The IaC `tool` and `tool_version`, the plan `format_version`, the plan's digests, `source_commit`, whether the plan is `complete` and `applyable`, and the same table of contents for every resource the plan covers. `tool_version`, `complete` and `applyable` hold the unknown marker `{"__unknown": true, "reason": "not_reported_by_tool"}` when the tool's plan does not say; `null` is refused. |
| `subject` | object | The subject's `kind`, its `key` and its `identities` (`scheme`, `value`, `scope`): one or two, its local identity and, at runtime, its cloud identity (at most `iltero_schemas.models.common.fields.MAX_SUBJECT_IDENTITIES`, 2). An identity's `scope` holds at most 8 keys (`MAX_SCOPE_KEYS`). |
| `resource` | object | For a resource subject, the resource as planned: `id`, `provider`, `type`, `kind`, `name`, `module`, `action`, `before`, `after`, the resources that refer to it (`related`), and `tool_data`. |
| `deployment` | object | What the apply did: the applied `plan`, and `apply` with its `source` log (its tool and its given file digest, see [Given file digests](#given-file-digests)), the `state` after it (its tool and its state digest, see [State digests](#state-digests)), or the `state_not_read` marker when it was not read (see [When the state after the apply was not read](#apply-with-the-state-not-read)), `outcomes_from` (`apply_log`; `apply_log_and_state` when the log lost messages and the state settled what it could; `apply_log_alone` when the state was not read), each change of the applied plan once (`changes`, each saying where its outcome came from in `outcome_from`: `apply_log`, `apply_log_alone`, `state` or `none`), `timing`, and `tool_data`: what only the IaC tool says, keyed by `tool`, which must be `apply.source.tool`. For `terraform`: the `summary` counts it reported, `errors_reported`, the number of error diagnostics the log holds (see [When the state after the apply was not read](#apply-with-the-state-not-read) for the rules on both), the `log_lines` it could not read (`other_output_lines`, `damaged_messages`, `interrupted_operations`), and the delete of each `deposed` object (an old copy a replacement set aside), settled by the state, or the `state_not_read` marker when it was not read. `superseded_by` is `{"reason": "dependency_replanned"}` when the pipeline says it applied a re-plan, which must differ from the evaluated plan, and `null` otherwise. In an `image_deploy` input, the image the pipeline reports it deployed (see [The `image_deploy` body](#the-image_deploy-body)). |
| `evaluations`, `approvals` | list or marker | Facts only Iltero Platform holds, as the items below (`iltero_schemas.models.common.server_facts`). |
| `run` | object | The run the input belongs to, by Iltero's run `id`; an approval of a run names it. |
| `drift_check` | object | What two readings of the unit's deployed resources, taken after the apply, found: the shape of a record's [`drift_check`](#change-assurance-record-car). In an `image_deploy` input, what one reading of the workload found (see [The `image_deploy` body](#the-image_deploy-body)); its `change_digest` is `change.digest`: "drift_check.change_digest is change.digest", and it compares every container, of the pod template or of a pod, whose image is from `change.image.repository`: "a reading compares every container whose image is from the deployed repository". |
| `assurance` | object | An assertion's results about one subject over time (`iltero_schemas.models.common.assurance.Assurance`): the `assertion` (`id`, `version`), the `subject` (`kind`, `key`), the `current` result and the `previous` one (each a `status`, the `stage` that reached it and `observed_at`), and what happened in between (`since_previous`: the `deployments` recorded for the subject's unit, each its `record` UUID, `change_digest` and `deployed_at`). `previous` and `since_previous` are both `null` for a subject with no earlier result: "what happened since the previous result is given exactly when there is one". The previous result is no later than the current one ("the previous result comes before the current one"), and every deployment falls between them ("a deployment since the previous result comes between it and the current one"). |
| `artifact` | object | The image a build produced: its `repository`, its `digest`, the digest of each platform's image (`platform_digests`) and `build_commit`: the commit the build tool's provenance names, or the unknown marker `{"__unknown": true, "reason": "not_reported_by_tool"}` when the build named none (see [The build's commit](#the-builds-commit)), with the rules of the [`image_build` body](#the-image_build-body). |
| `tests` | list | Each test report the build was given, at most 64 (see below). |
| `scans` | list | Each scan report the build was given, at most 64 (see below). |
| `verified_source` | object or marker | The commit Iltero Platform verified from the identity the continuous integration (CI) system gave the job that opened the run, not the commit the tool reads from its checkout, with what that identity named (see the Verified source item below). A fact only Iltero Platform holds. |
| `attestation_outcome` | object or marker | What Iltero Platform found when it checked the signature of the build's attestation: verified, refused or not sent (see [The build's attestation](#the-builds-attestation)). A fact only Iltero Platform holds. |
| `commit_review` | object or marker | Whether every commit the change ships since its review starting point was reviewed (see [Commit review](#commit-review)). A fact only Iltero Platform holds. |
| `apply_job_facts` | object or marker | What Iltero Platform says about the job that applies an infrastructure change (see [The apply job's facts](#the-apply-jobs-facts)). A fact only Iltero Platform holds. |
| `apply_job_timing` | object | The plan's age and the counts of the apply job's approvals, worked out from `apply_job_facts` and `approvals` (see [The apply job's facts](#the-apply-jobs-facts)). |
| `replan_check` | object | The re-plan check the apply job made: a comparison, or `{"outcome": "not_compared"}` (see [The re-plan check](#the-re-plan-check)). Present exactly when `apply_job_facts` are of a later job, and maybe when they are the unknown marker. |

Key rules:

- The parts present are exactly those the profile of the evaluation's activity, stage and target kind provides. A
  part outside the profile is written as `null` and reads as absent, as does one left out. A missing required part
  or an extra part is refused, and the error names it. `evaluation`, `organization_scope` and `reference_time` are
  always required. A resource target also requires `resource`.

  | Activity | Stage | Required | Optional |
  | --- | --- | --- | --- |
  | `iac_change` | `plan` | `source`, `change`, `plan`, `subject` | none |
  | `iac_change` | `pre_deploy` | `source`, `change`, `plan`, `subject`, `evaluations`, `approvals`, `commit_review`, `run`, `apply_job_facts`, `apply_job_timing` | `replan_check` |
  | `iac_change` | `post_deploy` | `source`, `change`, `plan`, `subject`, `deployment` | none |
  | `iac_change` | `post_verify` | `subject`, `deployment`, `drift_check` | `source`, `assurance` |
  | `iac_change` | `post_verify`, about a resource (a [postponed check](#checks-postponed-until-after-the-deployment)) | `subject`, `resource`, `plan`, `deployment` | `source` |
  | `iac_change` | `runtime` | `subject` | `source`, `deployment`, `assurance` |
  | `image_build` | `plan` | `source`, `subject`, `artifact`, `tests`, `scans`, `verified_source`, `attestation_outcome` | none |
  | `image_deploy` | `pre_deploy` | `source`, `change`, `subject`, `evaluations`, `approvals`, `commit_review`, `run` | none |
  | `image_deploy` | `post_deploy` | `source`, `change`, `subject`, `deployment` | none |
  | `image_deploy` | `post_verify` | `change`, `subject`, `deployment`, `drift_check` | `source` |

- An input is at most 16 MiB (`iltero_schemas.models.common.context.MAX_INPUT_BYTES`, 16,777,216 bytes) of canonical JSON,
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
  | `file_digest` | The SHA-256 of the report file's bytes as the pipeline gave it, which the record keeps as given. |
  | `image_digest`, `image_digest_source` | The image the report is about, and where that tie comes from. Always `pipeline`: "a JUnit report names no image, so only the pipeline ties it to one". |
  | `counts` | `tests`, `failures`, `errors` and `skipped`, each from 0. `failures`, `errors` and `skipped` together are at most `tests`. |

  | `scans` item field | Meaning |
  | --- | --- |
  | `kind` | `image_vulnerability`: a scan for known vulnerabilities in an image's packages. |
  | `format` | `trivy_json` or `grype_json`. |
  | `tool_version` | The version the report names (identifier). |
  | `file_digest` | The SHA-256 of the report file's bytes as the pipeline gave it, which the record keeps as given. |
  | `image_digest`, `image_digest_source` | The image the report is about, and where that tie comes from. |
  | `reported_at` | When the report says it was written (timestamp). |
  | `finding_counts` | How many findings the report lists by the severity the scanner gave: `critical`, `high`, `medium`, `low`, `negligible` and `unknown`, each from 0. |

- A subject's `key` is `sha256:` and the hex SHA-256 of the canonical bytes of `{"kind": <kind>, "identity": {"scheme":
  ..., "value": ..., "scope": ...}}`, the local identity with all three fields, `scope` as `null` when it has none,
  computed by `iltero_schemas.models.common.subjects.subject_key`. Every document is checked against it. The key is over
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
- `plan.digest` is the plan's digest by the rule for the plan's `tool`, keyed or of the redacted plan (see
  [Plan digests](#plan-digests)), and `digest_version` is the version of the rule its form names. A context with any
  other `digest_version` is refused. `deployment.plan.digest_version` is held to the rule of
  `deployment.apply.source.tool` in the same way: the applied plan may be a re-plan, so it follows its own tool's rule.
  `artifact_digest` is the digest of the saved plan file. It is
  present exactly when `artifact_digest_source` is `saved_plan`, and `null` when it is `not_provided`.
  `ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN` compares `plan.digest`, `plan.artifact_digest` and
  `plan.artifact_digest_source` with the same fields of `deployment.plan`. When neither side was given the saved plan
  file, both artifact digests are `null` and both sources `not_provided`: the assertion passes, and the event's
  observations show `not_provided`. Such a pass shows that the applied plan's digest equals the evaluated plan's, not
  that the applied plan file is the evaluated one byte for byte. When only one side has the saved plan file, it fails.
- `plan.source_commit` equals `source.commit.sha`.
- A value removed by redaction is a marker, `{"__redacted": true, "reason": ..., "present": true, "type": ...}`
  (`iltero_schemas.models.common.redaction.RedactedMarker`). Its `reason` is one of the
  [redaction reasons](#redaction-reasons), and its `type` is the JSON type of the hidden value: `object`, `array`,
  `string`, `number`, `boolean` or `null`. `present` is `false` only for a hidden `null`. Only the JSON value `true`
  marks a value redacted, never `1` or `1.0`, as in the evaluator's runtime. A value not yet known is
  `{"__unknown": true, "reason": ..., "present": true}`; redaction writes `"reason": "known_after_deploy"`
  (`UnknownMarker`). A predicate that reaches either is `unknown`. A tool writes a value known only after
  the deploy as the `known_after_deploy` marker, never as `null`; the context does not check this, since
  `resource.after` is the tool's data. An `equal: null` check on the marker is `unknown`.
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
served. No input carries an exception: no assertion reads one. Iltero Platform serves exceptions in a
[ServedExceptions](#servedexceptions) document.

| Item | Fields |
| --- | --- |
| Approval | `id`, `actor` (`provider`, and `id`: the provider's stable account id, never a login, a name or an address), `roles`, `status` (`approved`), `subject`, `method` (`ci_deployment_review` or `iltero_review`), `independence` (`independent` when the approver neither started the run nor triggered the attempt; `self_permitted_by_policy` otherwise, with the permitting `policy_version`, `null` when independent), `timestamp`: when Iltero received the approval, by its own clock, and `bound_to`: the CI job a CI deployment review approved (`ci_run_id`, `ci_run_attempt`, an integer from 1, and `ci_job_id`, `iltero_schemas.models.common.ci.CiJob`), `null` for a review in Iltero. An approval from a CI deployment review names no role, since none is verified. An approval names its job exactly when a CI deployment review gave it: "an approval names the CI job it approved exactly when a CI deployment review gave it". |
| Earlier evaluation | `id`, `assertion` (`id`, `version`), `stage`, `subject` (`kind`, `key`), `result`, `checked_content` (the [checked content](#checked-content) it read, or `null`: its kind, or `null`, is one an activity's input carries at that stage (`iltero_schemas.profiles.reads_checked_content`, one kind per activity, `None` for an activity whose input carries none). So `plan` and `container_image` are accepted at `plan`, `pre_deploy` and `post_deploy`; `container_image` or `null` at `post_verify`, where an `image_deploy` input carries the image and an `iac_change` input nothing; and only `null` at `runtime`. Any other is refused: "an earlier evaluation names the content it checked exactly when its stage reads that content"), `observed_at`. One earlier evaluation is the [combined verdict](#how-evaluators-combine) of a stage's evaluations of one assertion about one subject: `result.status` is that verdict, and `result.decided_by` names the engine of each evaluator that reached it (`opa`, `checkov`, `trivy` or `none`), sorted, each once ("decided_by is sorted, each engine once"). |
| Verified source | `commit`: the commit Iltero Platform verified from the identity the CI system gave the job that opened the run. What that identity named: `ci_provider`, the CI system (`github_actions`, from `iltero_schemas.models.common.ci.CI_SYSTEMS`); `ci_instance`, the instance of it by its host name, such as `github.com`; `repository_id`, the repository's id at the CI system, which does not change when the repository is renamed, and `repository`, its name; `ci_run_id` and `ci_run_attempt` (an integer from 1), the CI run and its attempt. A CI system's ids are unique only within one instance of it, so each id is read with `ci_provider` and `ci_instance`. |

- An approval's `subject` names what it approves: `{kind: change, digest}`, that plan and no other, or `{kind: run,
  id}`, Iltero's run, never a CI run. An approval of a run approves the run, not a plan's content: a CI deployment
  review approves the deploy job when it starts, whether or not that run has planned yet.
- `ILT.COMMON.CHANGE.APPROVAL.PRODUCTION_APPROVED` and `ILT.IAC.CHANGE.APPROVAL.SENSITIVE_CHANGE_APPROVED` pass on an
  approved, independent approval of the change by its digest from the `security` role, or on an approval of the run
  whose `subject.id` is the input's `run.id`. Each is its own `exists`, so the observations show which one held. An
  approval of the run may be a self-approval the policy permitted; an approval of the change may not. For an approval of
  the run, both assertions read the same CI environment approval: there is no separate security sign-off behind it.

### The apply job's facts

What Iltero Platform says, at the `pre_deploy` stage of an `iac_change` run it opened, about the job that applies the
change. A run may plan in one job and apply in a later one, after a person reviewed the plan; these facts say which
job asked for them, the plan-stage record that counts and when Iltero Platform received it, when it issued the
facts, the plan age limit, the saved plan file the job sent, the plan the job reports it rendered from
that file, and the plan the run is held to. The input carries them as `apply_job_facts`, or the unknown marker
`{"__unknown": true, "reason": "server_facts_unavailable"}` when Iltero Platform could not supply them.

- **Model:** `iltero_schemas.models.iac.apply_job_facts.ApplyJobFacts`

| Field | Type | Meaning |
| --- | --- | --- |
| `flow` | string | How the run applies its change: `plan_and_apply_in_one_job`, `apply_in_a_later_job`, or `job_not_identified` for a job Iltero Platform could not identify, held to the rules of a job that applies later (`ApplyJobFlow`; the constants `ONE_JOB_FLOW`, `LATER_JOB_FLOW` and `JOB_NOT_IDENTIFIED_FLOW`). |
| `apply_job` | object | The job that asked for the facts: `ci_run_id`, `ci_run_attempt` (an integer from 1) and `ci_job_id` (`iltero_schemas.models.common.ci.CiJob`). |
| `accepted_plan_stage_record` | object | The plan-stage record Iltero Platform accepted for the plan the run applies. When the plan job ran more than once (several CI run attempts), it is the record from the latest attempt that sent one, and within that attempt the earliest record of the change that Iltero Platform kept. It names its `run_id`, `change_digest`, `plan_digest` (a keyed digest, see [Plan digests](#plan-digests)), and `artifact_digest`, the saved plan file the plan stage evaluated, `null` when it was given none. |
| `plan_stage_record_accepted_at`, `facts_issued_at` | timestamp | `plan_stage_record_accepted_at` is when Iltero Platform received that record; `facts_issued_at` is when it issued these facts. Both are on Iltero Platform's own clock. |
| `plan_age_limit` | object | The longest plan age (`apply_job_timing.plan_age_seconds`) the facts accept: `seconds`, from 1 to `MAX_PLAN_AGE_SECONDS` (604,800, seven days); `source`, `environment_policy` or `server_default` (`PolicySource`; the constants `ENVIRONMENT_POLICY_SOURCE` and `SERVER_DEFAULT_SOURCE`); and `policy_version`, the id of the environment policy version that set the limit, present exactly when that policy set it. |
| `approval_requirement` | object | Whether an approval of the apply job is required, and what set that: `required`; `source`, `environment_policy` or `server_default` (`PolicySource`); and `policy_version`, the id of the environment policy version that set it, present exactly when that policy set it. Only an environment's policy can require none. |
| `received_plan_file_digest` | digest, object or null | The digest the pipeline reported for the saved plan file the apply job holds; `{"outcome": "not_sent"}` (`PlanFileNotSent`) when a later apply job sent none; `null` exactly when the run plans and applies in one job. |
| `rendered_plan` | object or null | The apply job's report, which Iltero Platform passes on (`RenderedPlan`). The job renders its saved plan file, that is, turns it back into the tool's plan document, and reports that plan's `digest`, a keyed digest (see [Plan digests](#plan-digests)), with `digest_version`, the version of the keyed plan digest rule that computed it, and `tool`, the IaC tool. `{"outcome": "not_sent"}` (`RenderedPlanNotSent`) when a later apply job reported none; `null` exactly when the run plans and applies in one job. |
| `pinned_plan_digest` | keyed digest | The plan the run is held to, by its keyed digest (see [Plan digests](#plan-digests)). |

The model refuses:

- facts issued before `plan_stage_record_accepted_at`: "the apply job's facts are issued no earlier than the
  plan-stage record was accepted";
- a saved plan file named, or not, against the flow: "the apply job's facts name the saved plan file it sent, or that
  it sent none, exactly when the run does not plan and apply in one job";
- a rendered plan named, or not, against the flow: "the apply job's facts name the plan it rendered from its saved
  plan file, or that it sent none, exactly when the run does not plan and apply in one job";
- a rendered plan whose `digest_version` is not the version of its tool's keyed plan digest rule
  (`KEYED_PLAN_DIGEST_VERSIONS`): "a keyed plan digest names the version of the terraform keyed plan digest rule";
- a limit that names its policy version when the server's default set it, or names none when a policy did: "a plan
  age limit names its policy version exactly when the environment's policy set it";
- an approval requirement that names its policy version, or not, against its source: "an approval requirement names
  its policy version exactly when the environment's policy set it";
- an approval requirement that requires no approval unless an environment's policy said so: "only an environment's
  policy leaves the apply job without a required approval".

The approvals a stage reads are timed when Iltero Platform received them, by its own clock.

`apply_job_timing` is what `iltero_schemas.models.iac.apply_job_facts.apply_job_timing(facts, approvals)` works out
from `apply_job_facts` and `approvals`, so that a check can compare it: the evaluator cannot subtract one time from
another. Every reader works it out the same way.

| Field | Type | Meaning |
| --- | --- | --- |
| `plan_age_seconds` | integer or marker | The plan age in whole seconds, from `plan_stage_record_accepted_at` to `facts_issued_at`: the time since Iltero Platform received `accepted_plan_stage_record`, not the time since the IaC tool wrote the plan file. It is measured to the nanosecond and rounded up, so an age a fraction of a second over the limit is over it. |
| `approvals_given_before_plan_stage_record_accepted` | integer or marker | The approvals of the apply job timed before `plan_stage_record_accepted_at`. |
| `approvals_given_after_plan_stage_record_accepted` | integer or marker | The approvals of the apply job timed at or after `plan_stage_record_accepted_at` and no later than `facts_issued_at`. |

An approval of the apply job is one a CI deployment review gave for that job: its `bound_to` equals `apply_job`. Every
field is the unknown marker when `apply_job_facts` is; the two counts are when `approvals` is, beside facts Iltero
Platform did supply. A pre-deploy input of an `iac_change` carries both parts (its profile requires them:
"pre_deploy_change: missing apply_job_timing"). Its facts are about its own run, change and plan: their
`accepted_plan_stage_record` equals the input's `run.id`, `change.digest`, `plan.digest` and `plan.artifact_digest`,
"the apply job's facts name the accepted plan-stage record of this run, change, plan and saved plan file". A run that
does not plan and apply in one job evaluated a saved plan file: "a run that does not plan and apply in one job evaluated
a saved plan file". No approval is timed after the facts were issued: "no approval is timed after the apply job's facts
were issued". Its `apply_job_timing` is what the function gives for its facts and approvals, and any other value is
refused: "the input's apply_job_timing is what the function apply_job_timing gives for its apply job's facts and
approvals".

### Commit review

`commit_review` says whether every commit a change ships since its review starting point was reviewed. At the
change's `pre_deploy` stage, Iltero Platform reads the repository's history at its git host, the service that keeps
the repository and its pull requests, and serves the outcome. It is a fact only Iltero Platform holds, carried by the
`pre_deploy` input of an `iac_change` and of an `image_deploy`.

- **Model:** `iltero_schemas.models.common.commit_review.CommitReview`, one shape per `outcome`. The input checks it against
  its other parts with `iltero_schemas.models.common.commit_review.check_commit_review`.

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
| `ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED` | Every commit the change ships since its review starting point was merged through a pull request with a qualifying approval | `commit_review.outcome` is `reviewed`. It fails for every other outcome, and is `unknown` with `server_facts_unavailable` when the part is the unknown marker. In a run the tool opened it is never `pass`, `fail` or `not_applicable`, and when it is `unknown` its reason is `server_facts_unavailable`, so a `pre_deploy` stage that evaluates it is never `met`, and is `undecided` when nothing else is wrong; see the record rule for such a run in [Change Assurance Record (CAR)](#change-assurance-record-car). Not built in: a project adds it, and an exception may name it. Its remediation: "Merge every commit through a pull request approved on its final head, before the merge, by a person who can write to the repository and wrote none of it; run the change from, or build the image from, the commit Iltero verified; have an administrator set a review starting point when none fits." |

#### Git repository

A repository as its git host names it (`iltero_schemas.models.common.git.GitRepository`). A git host's ids are unique only
within one instance of it, so the id is read with the host and instance.

| Field | Type | Meaning |
| --- | --- | --- |
| `host` | string | The git host: `github` (`iltero_schemas.models.common.git.GIT_HOSTS`). Any other is refused. |
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
- **Model:** `iltero_schemas.models.common.event.AssuranceEvent`

| Field | Type | Meaning |
| --- | --- | --- |
| `assertion` | object | The assertion's `id`, `version` and the `digest` of its document as it was read. |
| `subject` | object | The subject's `kind`, `key` and `identities`, in the same shape as on the evaluation input, with at most 2 identities. `key` is `null`, and `identities` empty, exactly when no subject was in scope. |
| `evaluation` | object | The [`activity`](#change-types-and-activities) and `stage` the evaluation belongs to, the `status`, the runner's `status_reason` and `status_detail`, and the policy's own reason (`policy_reason`) and `observations`. |
| `provenance` | object | Where the verdict came from (see below). |
| `observed_at` | timestamp | The run's timestamp. Every event of one run carries the same value. |

`iltero_schemas.models.common.event.event_digest(event)` gives an event's digest: the digest of its canonical JSON (RFC
8785), the same whether the event is read from its stage's events file or sent on its own.

| `provenance` field | Meaning |
| --- | --- |
| `run` | The run `id` and the `unit`. A unit is the part of a project the IaC tool plans and applies as one. |
| `source_commit`, `checked_content` | The commit and the [checked content](#checked-content) the evaluation is about. |
| `input_digest` | The digest of the assurance context the evaluator received. |
| `evaluator` | The engine that produced the verdict. For `opa`: its `version`, binary `digest` and the `limits` applied: `timeout_seconds`, `memory_limit`, `max_output_bytes`, `evaluations_per_process`, `capabilities_digest` and `platform`. For a scanner (`checkov` or `trivy`): the `version` the scanner wrote into its report (`null` for a member of a scanner requirement that gave no report) and what its verdict rests on (see below). What ran, and where, is named once on the scanner's report (`ScannerReport`, in the [CAR](#change-assurance-record-car)'s `scanners`), which the evaluation names by its `input_digest` (see [Evaluations from a scanner's results](#evaluations-from-a-scanners-results)). |
| `bundle` | The bundle the program came from: `kind` (`server` or `local_bundle`), `tarball_digest`, the SHA-256 of the bytes of the bundle tarball the evaluator loaded, `content_digest` and `key_id`. For `server`, they are the served [descriptor](#assertionbundledescriptor)'s `tarball_digest`, `content_digest` and `key_id`. For `local_bundle`, `tarball_digest` is the digest of the tarball the tool built, and `content_digest` and `key_id` are `null`, because a bundle the tool built has no descriptor. Any other combination is refused: "a bundle names its content digest and signing key exactly when its kind is server". The writer's claim: nothing compares these values with a descriptor. Present exactly when the evaluator is `opa`. An evaluation whose `assertion_source` is `server_bundle` and that ran over a bundle names a bundle of kind `server`; otherwise it is refused: "an assertion from the server's bundle is evaluated over the server's bundle". |
| `scanner_checks` | The scanner checks entry of a [scanner check mapping](#scannercheckmapping) whose checks decided the evaluation, by its `digest` alone (`ScannerChecksRef`). Present exactly when the evaluator is a scanner; otherwise it is refused: "a scanner checks entry is named exactly when a scanner's result was read for this evaluation". |
| `assertion_source`, `assertion_source_digest` | Where the assertion came from, and its source digest. `server_bundle`: an assertion bundle Iltero Platform served. `local`: the project's own files; `custom_rego` when hand-written in Rego. A record of a run Iltero Platform opened has only `server_bundle`. `contract_starter`: a starter assertion this package ships, added to a local run. The writer's claim. |
| `compiled_digest`, `compiler` | The compiled program's digest, and the compiler's `version`, `contract_version`, `contract_digest` and `install` (`wheel` or `editable`). Absent for a scanner. |
| `executor` | Who ran the evaluation: `type` (`human` or `workload`), `provider` (`local`, `ci` or a CI system such as `github_actions`) and the CI system's run id (`ci_run_id`). |
| `facts_source` | For an evaluation whose input may carry Iltero Platform facts (approvals, earlier evaluations, the commit review, the verified source, the verified attestation: an `iac_change` input at `pre_deploy`, an `image_build` input at `plan`, and an `image_deploy` input at `pre_deploy`), where they came from: `server` or `none`. `null` for every other input (`iltero_schemas.profiles.reads_server_facts`). It names where the facts document came from: the parts only Iltero Platform holds (`SERVER_FACTS`: `evaluations`, `approvals`, `commit_review`, `verified_source`, `attestation_outcome`, `apply_job_facts`). A value Iltero Platform supplies inside another part is not counted: the environment's production flag (`organization_scope.environment.production`) in every input, and the accepted build (`change.build`) in an `image_deploy` input. In a run the tool opened, such a value holds the unknown marker (`server_facts_unavailable`), so it follows `governance.run_opened_by`. The `post_deploy` and `post_verify` inputs of an `image_deploy` name no `facts_source`. |

Key rules:

- `status` is one of six values. Only `pass` and `fail` may omit `status_reason`, and a reason must belong to its
  status:

  | Status | Reasons |
  | --- | --- |
  | `pass` | none |
  | `fail` | none: a failure's reason is the policy's `policy_reason` |
  | `unknown` | `known_after_deploy`, `redacted`, `path_missing`, `not_a_list`, `unspecified`, `server_facts_unavailable`, `not_reported_by_tool`, `deployment_log_incomplete`, `state_not_read`, `kind_unmapped`, `rendered_plan_not_sent`, `replan_not_compared`, `scanner_result_unresolved`, `scanner_report_incomplete` |
  | `not_applicable` | `when_guard_excluded`, `no_subject_in_scope` |
  | `not_evaluated` | `scanner_not_run`, `credential_denied`, `resource_type_unsupported`, `scanner_version_not_allowed`, `timeout`, `subject_unresolved`, `evaluator_unavailable`, `identity_unverified`, `stage_not_run`, `suppressed_in_source`, `tool_reports_only_failures`, `no_result_of_the_mapped_checks`, `no_result_in_the_report`, `no_scanner_report` |
  | `error` | `evaluator_crash`, `evaluator_timeout`, `evaluator_memory_limit`, `output_overflow`, `output_contract_violation`, `adapter_parse_failure`, `bundle_verification_failed`, `compile_failure` |

- Only an evaluation of `ILT.IAC.CHANGE.CONTENT.RENDERED_PLAN_MATCHES_EVALUATED_PLAN` gives `rendered_plan_not_sent`
  (`iltero_schemas.models.common.event.RENDERED_PLAN_NOT_SENT`), and only an evaluation of
  `ILT.IAC.CHANGE.CONTENT.REPLAN_HAS_SAME_ACTIONS_AS_EVALUATED_PLAN` gives `replan_not_compared` (`REPLAN_NOT_COMPARED`;
  both in `REASONS_OF_ONE_CHECK`): "only an evaluation of ILT.IAC.CHANGE.CONTENT.RENDERED_PLAN_MATCHES_EVALUATED_PLAN
  gives the reason rendered_plan_not_sent", and the same for the re-plan check's reason.
- An event is checked on its own against its activity. Its activity, stage and subject kind have a profile
  (`iltero_schemas.profiles.profile_for`); otherwise it is refused, such as "stage 'plan' is not valid for target kind
  'artifact' in an iac_change input". Its `provenance.checked_content.kind` is the activity's
  (`CHECKED_CONTENT_KIND_OF`: `plan` for `iac_change`, `container_image` for `image_build` and `image_deploy`): "an
  image_build evaluation names the container_image it checked".
- An event's assertion id sits in the namespace its `provenance.assertion_source` allows:

  | Rule | Refused with |
  | --- | --- |
  | Whatever its source, an event's assertion has the namespace `ILT` or one that does not start with `ILT`. | "an assertion's namespace is ILT or one not starting ILT" |
  | An assertion from the project's own files (`local` or `custom_rego`, `iltero_schemas.models.common.event.PROJECT_ASSERTION_SOURCES`) has an id whose namespace does not start with `ILT`. | "an assertion from a project's own files has an id outside ILT" |
  | An assertion named as a starter (`contract_starter`) is one this package ships, at its version and document digest (`iltero_schemas.assertions.SHIPPED_ASSERTIONS`, each a `ShippedAssertion` with its `version`, document `digest` and `compiled_digest`). | "an assertion named as this package's starter is the document this package ships" |

- A built-in assertion's id is reserved. `iltero_schemas.assertions.BUILT_INS`, the built-ins among
  `SHIPPED_ASSERTIONS`, gives each built-in (`ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN`, `ILT.IAC.DEPLOYMENT.DRIFT.NO_DRIFT_AFTER_APPLY`,
  the five [checks of the apply job](#the-checks-of-the-apply-job),
  `ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT`,
  `ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT`,
  `ILT.IMAGE.DEPLOYMENT.CONTENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE` and
  `ILT.IMAGE.DEPLOYMENT.DRIFT.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE`) as shipped; `BUILT_IN_IDS` is the set of their
  ids. An event that names a built-in is evaluated as shipped, and each rule is refused with its message, where the
  id stands for the built-in's:

  | Rule | Refused with |
  | --- | --- |
  | `assertion.version` and `assertion.digest` are the shipped ones. | "ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT is a built-in assertion: it names the document this package ships" |
  | `provenance.assertion_source` is `contract_starter` or `server_bundle` (`iltero_schemas.models.common.event.BUILT_IN_SOURCES`). | "ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT is evaluated from this package or the server's bundle" |
  | `provenance.compiled_digest` is the shipped module's. It is `null` only when no evaluator ran (`evaluator` is `null`). | "ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT runs the module compiled from the document this package ships" |

- No scanner's result decides an assertion in `iltero_schemas.assertions.NOT_DECIDED_BY_SCANNERS`: the built-in
  assertions, and the starters that read a fact only Iltero Platform holds (`ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED`,
  `ILT.COMMON.CHANGE.APPROVAL.PRODUCTION_APPROVED`, `ILT.IAC.CHANGE.APPROVAL.SENSITIVE_CHANGE_APPROVED` and
  `ILT.IMAGE.ARTIFACT.PROVENANCE.SIGNED_PROVENANCE_MATCHES_RUN`). An event that names one with
  `provenance.scanner_checks` is refused, with its id: "ILT.COMMON.CHANGE.APPROVAL.PRODUCTION_APPROVED is never decided
  by a scanner's result".
- An evaluation from a scanner's results is one whose `provenance.evaluator` is a scanner. Its rules:

  | Rule | Refused with |
  | --- | --- |
  | It is about a resource (`subject.kind: resource`). | "an evaluation from a scanner's result is about a resource" |
  | Its `status` and `status_reason` are one of the pairs in `iltero_schemas.models.common.scanner_evaluator.SCANNER_OUTCOMES` (see below). | "an evaluation from a scanner's results is one of: fail, not_evaluated/no_result_in_the_report, not_evaluated/no_result_of_the_mapped_checks, not_evaluated/scanner_not_run, not_evaluated/scanner_version_not_allowed, not_evaluated/suppressed_in_source, not_evaluated/tool_reports_only_failures, pass, unknown/known_after_deploy, unknown/not_reported_by_tool, unknown/scanner_report_incomplete, unknown/scanner_result_unresolved" |
  | It reads no facts from Iltero Platform: `provenance.facts_source` is not `server`. | "an evaluation from a scanner's result reads no facts from the server" |
  | Only such an evaluation gives `scanner_version_not_allowed`, `suppressed_in_source`, `tool_reports_only_failures`, `scanner_result_unresolved`, `scanner_report_incomplete`, `no_result_in_the_report`, `no_result_of_the_mapped_checks` or `scanner_not_run` (`SCANNER_ONLY_REASONS`). | "only an evaluation from a scanner's results is scanner_version_not_allowed" (with the reason) |
  | It names a project's exception (`local_exception`) only when it is `suppressed_in_source`. | "a scanner's evaluation names a project's exception only for a suppressed check" |
  | It names no compiled module and no compiler. | "a scanner's result was not compiled here, so it names no module and no compiler" |
  | Its evaluator's `version` and its `provenance.input_digest` are `null` exactly when it is `scanner_not_run`. | "a scanner's evaluation names no version and no input exactly when the scanner gave no report" |
  | A `scanner_not_run` evaluation has empty `result_addresses`, `unknown_paths` and `failed_rule_ids`, and its `undecided_rule_ids` are its `rule_ids`. | "a scanner that gave no report decided none of its mapped checks and read no resource" |
  | A `no_result_of_the_mapped_checks` evaluation has the same empty lists, and its `undecided_rule_ids` are its `rule_ids`. Unlike `scanner_not_run`, it names its scanner's `version` and its `provenance.input_digest`. | "a scanner whose report holds no result of its mapped checks decided none of them and read no resource" |
  | A `no_result_in_the_report` evaluation has the same empty lists, and its `undecided_rule_ids` are its `rule_ids`; it also names its scanner's `version` and its `provenance.input_digest`. | "a scanner whose report holds no result at all decided none of its checks and read no resource" |

  A scanner `evaluator` (`iltero_schemas.models.common.scanner_evaluator.ScannerEvaluator`) also names what the verdict
  rests on. Each list is sorted, each item once ("rule_ids is sorted, each once", with the field's name):

  | Field | Meaning |
  | --- | --- |
  | `rule_ids` | The checks its scanner checks entry lists, 1 to 16. |
  | `subject_match` | How their results found the subject: `exact_address` or `plan_configures`. |
  | `result_addresses` | The plan addresses of the resources the results it rests on were about, at most 16. Empty when no result of a mapped check was about the subject. |
  | `unknown_paths` | The paths, at most 512, that the plan marks known only after the deployment on those resources and that a key the result read, or a path of the entry's `paths_read`, reaches. |
  | `failed_rule_ids`, `undecided_rule_ids` | The mapped checks that failed for the subject, and those that decided nothing about it. Each names mapped checks, and no check is in both: "failed_rule_ids and undecided_rule_ids name mapped checks, each in one of them". |
  | `local_exception` | The project's own exception the source's suppression rests on (`LocalExceptionRef`: its `id` and the `file_digest` of the [LocalExceptions](#localexceptions) file it is in), or `null`. A record of a run Iltero Platform opened names none: "a record of a run the server opened names no exception from a project's own files". |

  A record ties each one to the scanner report its stage kept and to the scanner checks entry, in one of the scanner
  check mappings its stage applied, that decided it (see [Evaluations from a scanner's
  results](#evaluations-from-a-scanners-results)).
- A policy can return `pass`, `fail`, `unknown` or `not_applicable`. Only the runner sets `not_evaluated` and
  `error`.
- A policy verdict names its `input_digest`. When no subject was in scope, the event's subject has no `key` and no
  `identities`, and the event has no `input_digest`.
- `evaluator` is `null` only for `evaluator_unavailable`, `no_subject_in_scope` and `no_scanner_report` (an
  assertion that only scanners decide, when no report the stage was given has checks mapped to it). A
  `scanner_not_run` evaluation names its scanner, with `version: null`.
- Reading an event or a record does not compare its OPA evaluator with the [pinned OPA
  release](02-conformance-vectors.md#the-pinned-opa-release). A verifier that checks it calls
  `iltero_schemas.models.common.pinned_evaluator.pinned_evaluator_problems(events)`, which returns every problem as a
  `(where, what)` pair, such as `("events.0.provenance.evaluator.digest", "is not the digest of the pinned OPA binary
  for its platform")`. A scanner's evaluation, and one no evaluator ran, names no OPA binary and is not compared. The
  check compares the binary the record states with the pin; it cannot show which binary ran.

  | `where` | `what` |
  | --- | --- |
  | `events.<index>.provenance.evaluator.version` | "is not the pinned OPA release `<version>`" |
  | `events.<index>.provenance.evaluator.limits.platform` | "is not a platform the pinned OPA release has a binary for" |
  | `events.<index>.provenance.evaluator.digest` | "is not the digest of the pinned OPA binary for its platform" |

  `iltero_schemas.models.common.pinned_evaluator.evaluator_binary_result(events)` turns these problems into a
  verification report's [`evaluator_binary`](#verificationreport) result.
- From worst to best, statuses rank `not_evaluated`, `error`, `unknown`, `fail`, `not_applicable`, `pass`
  (`iltero_schemas.models.common.event.STATUS_SEVERITY`).
- A policy's `policy_reason` is at most 2 KiB. Its `observations` are at most 512 KiB of canonical JSON, nested at
  most 4 levels.

### How evaluators combine

A stage may evaluate one assertion about one subject with several evaluators: its own rule, which OPA runs, and each
scanner whose report the stage was given and whose checks are mapped to the assertion. Each gives its own event. The
stage's verdict for that assertion and subject is their combined verdict (`iltero_schemas.models.common.verdicts`); verdicts
of different stages never combine. The status that comes first in `COMBINING_ORDER` wins:

| Order | Status | Why |
| --- | --- | --- |
| 1 | `fail` | One evaluator's failure is never outweighed. |
| 2 | `unknown` | A value one evaluator could not settle keeps a pass from standing. |
| 3 | `pass` | Stands only where no evaluator failed or could not settle the value. |
| 4 | `not_applicable` | |
| 5 | `error` | Not a decision: it never hides another evaluator's decision. |
| 6 | `not_evaluated` | Not a decision. |

A run can require groups of scanners, one scanner of each group (`scanners.scanner_requirements`, see
[Change Assurance Record (CAR)](#change-assurance-record-car)). A group of one requires that scanner. A member of a
group gives a gap for an assertion and subject when it gave no report (`scanner_not_run`, see [Evaluations from a
scanner's results](#evaluations-from-a-scanners-results)), when its report came from a version its scanner checks entry
does not allow (`scanner_version_not_allowed`), or when its report holds no result of the entry's checks
(`no_result_of_the_mapped_checks`) or no result at all (`no_result_in_the_report`) (`SCANNER_REQUIREMENT_GAP_REASONS`).

Only the members whose checks are mapped to the assertion count for a check. A group is unmet for an assertion and
subject when at least one member that counts evaluated it and each one that did gave a gap. When no member counts, the
group places nothing on that check. An unmet group is a gap no pass fills: it cancels every `pass` and `not_applicable`
(`CANCELLED_BY_AN_UNMET_SCANNER_REQUIREMENT`), and the order above applies to what is left. A `fail` or `unknown` still
stands, and so does another evaluator's `error`. A pass beside the gap gives `not_evaluated`, decided by the members
that gave it. A group one of whose members read the input cancels nothing, and neither does a scanner no group names:
its `scanner_version_not_allowed`, `no_result_of_the_mapped_checks` or `no_result_in_the_report` is an evaluation that
could not decide, like any other. The members of a group need not check the same things, so a group is only as strong as
its weakest member. `combined_verdict` and `stage_verdicts` take the groups (`scanner_requirements`, which
`stage_scanner_requirements` reads from a stage record, each group as the set of its members).

For example, the plan stage of `records/iac/local_run_scanner_required.json` names two groups of one, Checkov and
Trivy, and was given only Checkov's report. Its five checks give ten events. OPA and Checkov both pass
`ILT.IAC.RESOURCE.AWS.RDS.NOT_PUBLIC` and `ILT.IAC.RESOURCE.AWS.RDS.STORAGE_ENCRYPTED`, and Trivy's `scanner_not_run`
leaves its group unmet, which cancels both passes:

| Counts | `pass` | `fail` | `unknown` | `not_evaluated` |
| --- | --- | --- | --- | --- |
| OPA's own (`evaluator_status_counts.opa`) | 2 | 2 | 1 | 0 |
| Checkov's own (`evaluator_status_counts.checkov`) | 2 | 1 | 0 | 0 |
| Trivy's own (`evaluator_status_counts.trivy`) | 0 | 0 | 0 | 2 |
| Combined (`status_counts`) | 0 | 2 | 1 | 2 |

So an evaluator's own passes can sit beside a combined `pass` count of 0. The verdict reads only the combined counts.

The same stage with one group of both scanners (`{"any_of": ["checkov", "trivy"]}`, the `records_valid/` case
`iac_record_whose_group_of_two_scanners_is_met_by_the_one_that_read_the_plan`) is met by Checkov, which read the plan.
Both passes stand, so the combined counts are 2 `pass`, 2 `fail` and 1 `unknown`. Trivy still gives its two
`scanner_not_run` evaluations, since every member that gave no report gives one. They are listed as an
`evaluator_did_not_decide` gap (count 2), which leaves the stage's evidence `whole`.

The combined verdict names, in `decided_by`, the engine of every evaluator whose own status is the one it reached
(`combined_verdict`, `stage_verdicts`). A stage's `status_counts` and `evaluations` count combined verdicts, not events;
its [`evaluator_status_counts`](#each-evaluators-own-counts) count events. An evaluation that could not decide and that
its combined verdict does not count is listed as an [`evaluator_did_not_decide` gap](#change-assurance-record-car).

## Change Assurance Record (CAR)

A Change Assurance Record (CAR) is the record of one attempted change, for one unit of one run: an infrastructure
change, the build of an artifact, such as a container image, or the deployment of a built image to one environment.
It holds the evaluations, what the deployment did and the evidence each part cites. It exists whatever the outcome:
deployed, failed, stopped, refused before deployment, or a plan that changes nothing.

A CAR records technical and process assurance facts. It does not, by itself, establish certification or compliance
with a regulatory framework.

- **apiVersion:** `iltero.com/v1`, with `kind: ChangeAssuranceRecord`
- **Model:** `iltero_schemas.models.common.car.CAR`

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion`, `kind` | string | `iltero.com/v1` and `ChangeAssuranceRecord`. |
| `metadata` | object | The record's `uuid`, its id, and its `issuer`: `type: local` and `identity_verified: false`. The `uuid` is derived from the run and the unit (`iltero_schemas.canonical.record_uuid(run_id, unit)`): a version 5 UUID, in the namespace `RECORD_UUID_NAMESPACE`, of the text `iltero-car:<run.id>:<unit>`. Every stage of the run that reports on the unit writes the same record under the same id, and a reader recomputes it. |
| `run` | object | The run's `id` (UUID). |
| `unit` | identifier | The unit the record covers. |
| `trust_level` | string | How far the record's facts were established (see below). Always `self_attested` in this version. |
| `compliance_determination` | null | Always `null`. |
| `governance` | object | `run_opened_by`: `server` when the writer says Iltero Platform opened the run, `local` when the tool opened it on its own. Only Iltero Platform confirms that it opened a run (see [What checking offline establishes](#what-checking-offline-establishes)). |
| `subject` | object | What the record is about (`iltero_schemas.models.common.record_subject.RecordSubject`): `kind: change`, the `environment`: the environment the change is for, in the shape of an [AssuranceContext](#assurancecontext)'s `organization_scope.environment` (`iltero_schemas.models.common.context_parts.Environment`), with its `name` and `production`, whether Iltero Platform's environment policy treats it as production, or the unknown marker in a run the tool opened (see the rules below), and every evaluation input a stage kept names the same environment, name and `production` value (see [Checking the kept evaluation inputs](#checking-the-kept-evaluation-inputs)); `null` when the change is for no environment, such as an image build (`RecordSubject.environment_name` gives the name, or `null`), the `unit`, the `source`: the code the change comes from, in the shape of an [AssuranceContext](#assurancecontext)'s `source`, the `project_directory`: the project's directory relative to the repository's root, `.` for the root (`iltero_schemas.models.common.fields.DirectoryPath`), and the `project_tree`: that directory's git tree at the record's commit (see the project tree rule below). Every project path the record names is relative to it, and a reader can follow one to the repository only with the record's repository and commit; a record of a local run may name no repository. `project_directory` and `project_tree` are not part of `source`, which an evaluation reads, so they change no evaluation input. `project_tree` is `{"id": <git object id>}` (`ProjectTree`), required: git's id of the names, file modes and contents of every file git tracks under the project directory at the commit, the commit's root tree for `.`. It covers no uncommitted, untracked or ignored file, no file outside the directory, a submodule only by the commit it points at, and no variable, state or tool version. Its `id` uses the same hash as `source.commit.sha`, both 40 characters or both 64: "the project tree's id and the commit's id use the same hash: both are 40 or both 64 characters long". `project_directory` follows the directory rule below: a bad value is refused with "must be '.' or a relative path with no '..', '.', empty part, ':' or leading '/'", or "must name each part plainly: not only dots and spaces, and with no character that looks like a separator or a colon". |
| `change` | object | The change the record is about: the body of its [activity](#change-types-and-activities), named by `change.activity` (see [The `iac_change` body](#the-iac_change-body), [The `image_build` body](#the-image_build-body) and [The `image_deploy` body](#the-image_deploy-body)). |
| `units_file` | object or null | The project's [units file](#units-file) as the writer read it. `null` for a project that declares none. |
| `redaction_policy` | object | The [redaction policy](#redaction-policy) every stage ran, written out so a reader rebuilds it and its digest: `id`, `version`, `additional_paths` and `exempt_paths`. Every stage's redaction report and every redacted evidence file names it by its digest. |
| `stages` | object | One entry per stage that reported, keyed by stage (see below). Every stage is one the record expects. |
| `events` | list | Every [event](#assuranceevent), grouped in stage order. At most 100,000. |
| `coverage` | object | The stages' coverage combined: subjects in scope and evaluated, assertions required and evaluated, the subjects each required assertion was evaluated about (`subjects_per_assertion`), counts per status, the failed checks served exceptions cover in full summed over the stages (`failed_checks_excepted`), each evaluator's own counts per status summed over the stages that name it (`evaluator_status_counts`), the number of `evaluations`, gaps, truncation and sampling, and the inputs replaced with placeholders (`substituted_inputs`), each naming its stage. |
| `verdict` | object | What the stages' required checks came to: `value` (`met`, `not_met`, `undecided` or `incomplete`), `reason` (`not_evaluated` or `evaluator_failed` for an `incomplete` verdict, `every_failure_excepted` for a `not_met` verdict whose every failure a served exception covers, `null` otherwise), `computed_from` (`stage_precedence`) and the deciding `stage`. See [Verdict and evidence status](#verdict-and-evidence-status). |
| `evidence_status` | object | Whether the evidence behind the verdict is whole: `value` (`whole` or `has_gaps`) and `reasons`, every reason it has gaps, each with its `stage` and a `detail`, empty when it is whole. See [Verdict and evidence status](#verdict-and-evidence-status). |
| `all_expected_stages_reported` | boolean | Whether every expected stage has reported: "all_expected_stages_reported is true exactly when every expected stage has reported". |
| `expected_stages` | list | The stages the record expects. |
| `out_of_scope` | list | Each stage of the activity the record does not expect, with a `reason` and `declared_in` (see below). |
| `evidence_refs` | list | The evidence register: every file the record cites (see below). At most 501,024 (`iltero_schemas.models.common.car.MAX_EVIDENCE_REFS`): five files for each event, its input and the four files its assertion was compiled into, and 256 more for each of a record's four stages. |
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
| `execution` | object | What ran the evaluations: the `evaluator` (`engine: opa`, `version`, binary `digest`) and the `bundle` (`kind`, `tarball_digest`, `content_digest` and `key_id`, with the rules of an event's `bundle`, and the `capabilities_digest` its programs were built under), or, when nothing ran, both `null` and a `reason` (identifier) with an optional `detail`. `reason` is `null` when something ran. The bundle is the writer's claim: nothing compares it with a descriptor. A `local_bundle` has no descriptor. The stage's compiled index (`assertions`) and `coverage.assertions_required.required_assertion_digest` describe what it held; both are the writer's claims, and nothing compares them with the tarball. |
| `enforcement_mode` | string | The mode the stage's gate ran in: `enforcing` or `advisory` (see the key rules). |
| `approvals` | list, marker or null | The approvals the stage's evaluations read, in the shape of the [approval item](#assurancecontext), whatever their source, at most 256, each listed once and of the record's change or run, or the unknown marker `{"__unknown": true, "reason": "server_facts_unavailable"}` the input held in their place, or the marker `{"__unknown": true, "reason": "not_read_by_the_stage"}` (`iltero_schemas.models.common.facts.NotReadByTheStage`) when none of the stage's evaluations read an input that carries them (an event with a `provenance.facts_source` and an `input_digest`), so the stage keeps no copy. Present exactly at a stage whose input carries approvals (the `pre_deploy` stage of an `iac_change` or an `image_deploy`), `null` at every other: "the post_deploy stage keeps approvals, or the unknown marker, exactly where its input carries them". A stage keeps the `not_read_by_the_stage` marker exactly then: "the pre_deploy stage keeps the marker that it read no approvals exactly when none of its evaluations read an input that carries them". Otherwise, a stage none of whose events read its facts from Iltero Platform (`provenance.facts_source: server`) keeps the unknown marker: "the pre_deploy stage keeps the unknown marker for its approvals when its results read no facts from the server". One whose events did keeps the list or the unknown marker its input held. `StageRecord.listed_approvals` gives the list, empty for a marker or `null`. |
| `commit_review` | object, marker or null | The [commit review](#commit-review) the stage's evaluations read, as the input carried it (`iltero_schemas.models.common.commit_review.CommitReview`, one shape per outcome), the unknown marker `{"__unknown": true, "reason": "server_facts_unavailable"}` the input held in its place, or the `not_read_by_the_stage` marker (see below). `null` at every other stage. |
| `apply_job_facts` | object, marker or null | [The apply job's facts](#the-apply-jobs-facts) the stage's input carried, or the unknown marker `{"__unknown": true, "reason": "server_facts_unavailable"}` it held in their place; never the `not_read_by_the_stage` marker. Present exactly at the `pre_deploy` stage of an `iac_change` record of a run Iltero Platform opened, `null` at every other stage: "the plan stage keeps the apply job's facts, or the unknown marker, exactly where its input carries them: at the pre-deploy stage of an infrastructure change in a run the server opened". |
| `compiler` | object | The compiler, in the shape of an event's `compiler`: `version`, `contract_version`, `contract_digest` and `install`. |
| `redaction` | object | The stage's redaction report (see below). |
| `events` | object | The file of the stage's events: its `path`, `digest` and `count`, the number of the stage's events. The file is `{"apiVersion": "iltero.com/v1", "kind": "AssuranceEvents", "events": [...]}` (`iltero_schemas.models.common.event.EVENTS_FILE_KIND`), with the stage's events in the order the record lists them, written as its RFC 8785 canonical JSON (`iltero_schemas.models.common.event.events_file_bytes(events)`); `digest` is the digest of those bytes. Its evidence register entry has that digest, the bytes' `size_bytes` and `canonicalization: RFC8785`. `coverage.evaluations` counts their [combined verdicts](#how-evaluators-combine), one per assertion and subject, so it is at most `count`. |
| `assertions` | object | The index of the assertions the stage compiled: its path (`index`), `digest` and `count`. |
| `scanners` | object or null | The scanner reports the stage was given, and the scanner check mappings it read their results with (see below). `null` for a stage given no scanner report. |
| `served_exceptions` | object or null | The exceptions Iltero Platform served the stage, and the failed results they cover (see [A stage that applies served exceptions](#a-stage-that-applies-served-exceptions)). Set exactly at the `plan` stage of an `iac_change` run Iltero Platform opened, even when it served none; `null` at every other stage and in a run the tool opened. |
| `values_known_after_deployment` | string or null | What the plan stage's gate does with a check that read a value the plan knows only after the deployment: `block` on it, or `postpone` it (see [Checks postponed until after the deployment](#checks-postponed-until-after-the-deployment)). Always `block` in a record of a run Iltero Platform opened. `null` at every other stage. |
| `postponed_checks` | list or null | The checks the plan stage postponed: a list exactly when it postpones, `null` otherwise. |
| `resource_redaction` | object or null | A redaction report, of kind `post_apply_resources`, of the values after the apply that the post-verify stage's settling checks read. `null` at every other stage, and at a post-verify stage that settles none. |
| `coverage`, `verdict`, `evidence_status` | object | The stage's own, in the shape of the record's. A stage's verdict has `computed_from: status_counts` and `stage: null`. |

A stage keeps a commit review, or a marker, exactly where its input carries one, the `pre_deploy` stage of an
`iac_change` or an `image_deploy`. It keeps the `not_read_by_the_stage` marker exactly when none of its evaluations read
an input that carries a commit review. Otherwise it keeps the unknown marker when none of its events read its facts from
Iltero Platform, and when its `ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED` check could not read a commit review. It keeps
the review when that check passed or failed. Whether a stage whose events read facts from Iltero Platform kept the
review or the marker its input held is decided by replaying that input. The rules are in `iltero_schemas.models.common.stages`:

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
| The review was decided no later than the stage's `reference_time`. | "the pre_deploy stage's commit review was decided no later than the stage's reference time" |
| `iac_change`: `head_commit` is the record's `subject.source.commit.sha`, except for `source_commit_not_verified_commit`, where it is not. | "the pre_deploy stage's commit review is of the record's source commit, unless it is source_commit_not_verified_commit, which names the verified commit" |
| `image_deploy`: the record has an accepted build, and the review's `head_commit` and `repository` are its `verified_commit` and `repository`. | "the pre_deploy stage's commit review is of the accepted build's verified commit and repository" |
| `image_deploy`: the outcome is `build_commit_not_verified_commit` exactly when `change.build.build_commit` is not `change.build.verified_commit`, `null` included. | "the pre_deploy stage's commit review is build_commit_not_verified_commit exactly when the accepted build's build_commit is not its verified_commit" |

A kept review is a `CommitReview`, so the [commit review](#commit-review)'s rules on its own fields hold for it too,
such as where it counts since and how many it counts.

A stage's `scanners` names the scanner reports it was given and the scanner check mappings it read their results
with. Each verdict a scanner's results gave is an event of the stage (see [Evaluations from a scanner's
results](#evaluations-from-a-scanners-results)):

| Field | Type | Meaning |
| --- | --- | --- |
| `scanner_check_mappings` | list | The [scanner check mappings](#scannercheckmapping) the stage applied: one or two (see below). |
| `scanner_requirements` | list | The groups of scanners the run requires, one scanner of each, as the record states them (a reader does not check them against any configuration), at most one group per scanner (see [How evaluators combine](#how-evaluators-combine)). Each group is a `ScannerRequirement` (`iltero_schemas.models.common.scanners`). |
| `reports` | list | Each scanner report the stage was given, 0 to 16, one per scanner: "one report per tool per stage" (see below). |
| `redacted_plan` | string | Where the stage kept the redacted plan its reports were read against, in the record's directory: the `path` of an entry of the evidence register that the plan's collector wrote (see [The files a stage sends with its record](#the-files-a-stage-sends-with-its-record)). A later stage may keep another plan beside it, such as the one it applied. |
| `local_exceptions` | object or null | The project's own exceptions file the stage applied to the results the scanned source suppressed: its `file_path`, `digest` and `copy_path` (see [A stage that applies the file](#a-stage-that-applies-the-file)). `null` when the project gave none. |

A `ScannerRequirement` has one field:

| Field | Type | Meaning |
| --- | --- | --- |
| `any_of` | list | The group's members: one or two of `checkov` and `trivy`, sorted, each once ("a scanner requirement names its scanners sorted, each once"). The group is met for a check when one of them whose checks are mapped to the assertion read the input. |

For example, `"scanner_requirements": [{"any_of": ["checkov", "trivy"]}]` requires Checkov or Trivy, and
`[{"any_of": ["checkov"]}, {"any_of": ["trivy"]}]` requires both.

| Rule | Refused with |
| --- | --- |
| The groups are sorted by their members. | "the scanner requirements are sorted by their members" |
| A scanner is a member of one group at most. | "a scanner is a member of one scanner requirement at most" |
| `scanners` keeps a report or names a group. | "a stage's scanners keep a report or name a scanner requirement" |

`Scanners.required_members` is every scanner a group names. Each one the stage was given no report of gives a
`scanner_not_run` evaluation. `scanner_requirements` is the writer's claim: a record that leaves a group out, together
with its evaluations and gaps, still holds together. A reader compares the groups with the ones its own policy
requires. `scanners` is `null` for a stage given no report and requiring none. Only a stage that reads scanner reports
keeps `scanners`: the `plan` stage of an `iac_change` record (`stages_that_read_scanner_reports` of the record's
[activity](#change-types-and-activities)). Every other stage keeps `null`: "the post_deploy stage of an iac_change
record keeps no scanner report".

Whether each group can ever be met is a check of a policy, not of a record:
`iltero_schemas.models.iac.scanner_requirements.scanner_requirement_problems(requirements, assertions, mappings)` lists
every group that can never be met, given the run's assertions and the scanner check mappings it applies (only the
mapping entries of the run's assertions count), as
`(where, what)` pairs at `scanner_requirements.<index>`. It is written for a server to apply when it saves an
environment's policy and when it opens a run, and for a tool to apply when it reads a project's settings. A record is
not refused for a group it lists, such as a group of Trivy alone.

The two problems weigh differently. A group mapped to nothing (`MAPS_NOTHING`) is a reason to refuse the policy or the
settings. A group that can never be met for an assertion is a warning for whoever sets the policy to confirm: the run
still goes ahead, and the record shows that check as not evaluated unless another scanner decides it.

| What | When |
| --- | --- |
| "names no scanner whose checks are mapped to any assertion of the run, so it requires nothing" (`MAPS_NOTHING`) | No member's checks are mapped to any assertion of the run. |
| "can never be met for `<assertion>` at the `<stage>` stage: every member mapped to it names resources only when they fail" | The assertion only scanners decide (`assert: null`), and every member mapped to it at that stage names resources only when they fail (`trivy`, `REPORTS_ONLY_FAILURES`), so it never gives a pass. One pair for each such assertion and stage. |

A scanner check mapping says which scanner checks decide which assertion. A stage that reads scanner reports applies
one of three lists:

| `origin` of each entry, in order | When |
| --- | --- |
| `[shipped]` | The mapping Iltero ships alone. |
| `[file, shipped]` | One mapping read from the project's own file, then the mapping Iltero ships. |
| `[served]` | The mapping Iltero Platform served the run alone. |

Any other list is refused: "a stage applies the scanner check mapping Iltero ships, with at most one of the project's
own listed first, or only the one the server served".

The project's mapping can decide only the project's own assertions, and the shipped mapping can decide only Iltero's
starter assertions, so no assertion is decided by both. A served mapping is applied alone. As a result, the
`provenance.scanner_checks.digest` of each scanner verdict matches exactly one scanner checks entry across the stage's
mappings. That is how a reader finds the entry, and the mapping, that decided a verdict.

Each entry of `scanner_check_mappings` (`ScannerCheckMappingUsed`) names one scanner check mapping by:

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | The scanner check mapping's `metadata.id`: upper-case segments joined by dots, at least two, at most 96 characters. A mapping read from a file (`origin: file`) has an id of its own namespace, not `ILT` or one starting `ILT` (`check_project_id`): "a project's own id has a namespace of its own, not ILT or one starting so". |
| `version` | string | The scanner check mapping's `metadata.version`: a semantic version `X.Y.Z`. |
| `origin` | string | `shipped` for the mapping this package ships, `file` for one read from a file, `served` for the mapping Iltero Platform served the run it opened. The writer sets it, not the scanner check mapping; in a self-attested record it is the writer's claim. No mapping but the shipped one has the id `ILT.SCANNER_CHECKS.STARTER`: "only the shipped scanner check mapping is ILT.SCANNER_CHECKS.STARTER". |
| `file_path` | string or null | The path, in the project, of the file the mapping was read from, relative to the record's `subject.project_directory`, such as `payments.json` or `config/scanner-check-mapping.yaml`. It follows the project path rule, so a path outside the project, such as `../config/scanner-check-mapping.yaml`, is refused. Present exactly when `origin` is `file`: "a scanner check mapping read from a file names it, and no other mapping names one". |
| `digest` | digest | The digest of the scanner check mapping's canonical JSON as parsed, not of the file's bytes. A reader recomputes it from the copy at `copy_path`. |
| `copy_path` | string | Where the stage kept its copy of the scanner check mapping's canonical JSON, in the record's directory. The copy is an entry of the evidence register by this path and `digest`. |
| `assertions_mapped` | integer | How many assertions the mapping maps, the length of its `spec.assertion_mappings`, for every scanner and stage, from 0. |
| `descriptor_digest` | digest or null | The digest of the [signed descriptor](#scannercheckmappingdescriptor) Iltero Platform served the mapping in. |
| `key_id` | identifier or null | The key that signed that descriptor: its [`key_id`](#scannercheckmappingdescriptor). |
| `signature` | string or null | The descriptor's [`signature`](#scannercheckmappingdescriptor), the same value: the ES256 signature in base64url with no padding, 86 characters. |

`descriptor_digest`, `key_id` and `signature` are present exactly when `origin` is `served`: "a scanner check mapping
names its descriptor, signing key and signature exactly when it was served". A run applies only the scanner check
mapping fixed when Iltero Platform opened the run. A served mapping's `key_id` is the `key_id` of its stage's
`execution.bundle`: "a served scanner check mapping is signed by the key that signed its stage's bundle".

The key signs only the mapping's digest, the key id and the signing scope, so the kept copy of a served mapping, its
`key_id` and its `signature` rebuild the descriptor byte for byte. A reader with the kept files rebuilds it and checks
that its digest is `descriptor_digest`: "does not name the digest of the descriptor its copy, key id and signature
rebuild". A reader can then verify the signature offline, without asking Iltero Platform:

1. `iltero_schemas.scanner_check_mappings.iac.descriptor.kept_descriptor(copy, key_id=..., signature=...)` rebuilds
   the descriptor. `descriptor_digest(descriptor)`, in the same module, gives its digest.
2. [`read_scanner_check_mapping_descriptor(descriptor, key_id=..., keys=...)`](#reading-a-pinned-mapping-back), with
   the trust set as `keys`, gives the signed bytes (`signed`), the raw signature (`signature`) and the key (`key`).
3. The reader verifies the ES256 signature over `signed` with `key.public_key_der`. The package does not do the
   signature's mathematics.

A reader also checks that each scanner verdict's entry is in the stage's copy of the served mapping. The contract does
not compare the mapping's `key_id` with the stage bundle's, or check that its id is in Iltero's namespace: a run
applies only the mapping fixed when Iltero Platform opened it.

Each `reports` entry (`ScannerReport`):

| Field | Type | Meaning |
| --- | --- | --- |
| `tool` | string | `checkov` or `trivy`. |
| `tool_version` | identifier | The version the scanner wrote into its report. |
| `ran_by` | string | Who ran the scanner: `pipeline`, which gave the stage the report, or `iltero_cli`, the Iltero CLI, which ran the scanner itself on the runner (`iltero_schemas.models.common.scanners.PIPELINE` and `ILTERO_CLI`). It is the record's own claim: nothing in the record shows which program ran. A record of a run Iltero Platform opened keeps only reports the Iltero CLI ran: "a record of a run the server opened keeps only scanner reports the Iltero CLI ran". |
| `scanner_digest` | digest or null | The digest of the scanner the Iltero CLI ran: the scanner's program for Trivy, or the hash lock of its Python packages for Checkov. |
| `platform` | identifier or null | The platform the Iltero CLI ran the scanner on, in the words of the OPA evaluator's `limits.platform`, such as `linux-x86_64` or `linux-aarch64`. |
| `python_version` | string or null | For a scanner installed as Python packages (`iltero_schemas.models.common.scanners.INSTALLED_AS_PYTHON_PACKAGES`: Checkov), the interpreter tag its packages were locked for: `cp`, the major and minor version, and `t` for a free-threaded build, such as `cp312` or `cp313t`. |
| `outbound_network` | string or null | Whether the scanner process could reach the network (`OutboundNetwork`). `blocked`: the operating system or a sandbox stopped every outbound connection of the scanner process and of every process it starts, name lookups and connections to the machine itself included. `not_blocked`: otherwise, even when the scanner's own options told it not to connect. The record's own claim; no rule refuses `not_blocked`. |
| `configuration_digest` | digest or null | The configuration digest of the [pinned run](02-conformance-vectors.md#the-pinned-scanner-runs) the Iltero CLI ran the scanner with: its arguments, its whole environment and the files it wrote, every path left as a placeholder. Its kept observations name the same. |
| `input_kinds` | list | What the scanner read, in the contract's words (`plan`, `deployed_resources`): sorted, each once ("input_kinds is sorted, each kind once"), at most 16 (`iltero_schemas.models.common.stage_scanners.MAX_INPUT_KINDS`). When the Iltero CLI ran the scanner, the one input it gave the scanner, even when the scanner found nothing: "a report of a scanner the Iltero CLI ran names the one input it gave the scanner". When the pipeline ran it, the inputs its results cover. |
| `report_digest` | digest | The digest of the report as the stage kept it, redacted and canonical, the digest of an entry of the evidence register. That entry's `source` is the report as the pipeline gave it. Every evaluation from the report names it as its `input_digest`. |
| `observations` | string | Where the stage kept the [ScannerObservations](#scannerobservations) it read from the report, in the record's directory, the path of an entry of the evidence register. |
| `results_read` | integer | The results the observations hold, from 0. |
| `unreadable_results` | integer | Results of the report the stage could not read, from 0. Each decides nothing. |
| `written_configuration_results` | integer | Results about the configuration as written, which no stage reads, from 0. They are left out of the observations' `results`. |
| `tool_parsing_errors` | integer or null | Files the scanner itself says it could not parse, from 0, or `null` when the scanner does not say (Trivy). A value above 0 means the scanner did not cover everything it was given; 0 does not show that everything was parsed. |
| `results_not_listed` | integer or null | Results the scanner's own summary counts that its report does not list, from 0, such as the passes Checkov leaves out when run with `--quiet`; `null` when the scanner writes no counts (Trivy). A value above 0 means the report is not read in full; 0 does not show that every check ran, only that every result the scanner counts is listed. |
| `redacted_values` | object | For each reason, how many redaction markers that stand for a value (`present: true`) the report holds as the stage kept it; `{}` when it holds none. Each key is a [redaction reason](#redaction-reasons) (`iltero_schemas.models.common.redaction.RedactionReason`), each count is at least 1, and at most 64 reasons are listed (`MAX_REDACTION_REASONS`). |

`scanner_digest`, `platform`, `outbound_network` and `configuration_digest` are present exactly when `ran_by` is
`iltero_cli`, and `python_version` exactly when the Iltero CLI ran a scanner installed as Python packages; each is
`null` otherwise: "a scanner report names the digest, platform and configuration of what ran and whether it could reach
the network exactly when the Iltero CLI ran the scanner, and the Python version as well only for a scanner installed as
Python packages". Like `ran_by`, they are the record's own claim.

A verifier compares each report the Iltero CLI ran with the [pinned scanner
releases](02-conformance-vectors.md#the-pinned-scanner-releases) and
[runs](02-conformance-vectors.md#the-pinned-scanner-runs), using
`iltero_schemas.models.common.pinned_scanner.pinned_scanner_problems(car)`. It returns `(where, what)` pairs and refuses
nothing. Only a report that names a `scanner_digest` and a `platform` is compared, whether or not an evaluation reads
it; a report the pipeline ran names neither. The check compares what the record states with the pin; it cannot show
which program ran or how, neither digest covers the Python interpreter, the operating system nor the Iltero CLI, and in
a run the tool opened a report the Iltero CLI ran claims no more than one the pipeline ran.

| `where` | `what` |
| --- | --- |
| `stages.<stage>.scanners.reports.<index>.tool_version` | "is not the pinned `<tool>` release `<version>`" |
| `stages.<stage>.scanners.reports.<index>.platform` | "is not a platform the pinned trivy release covers", or for Checkov "is not a platform and Python version the pinned checkov release covers" |
| `stages.<stage>.scanners.reports.<index>.scanner_digest` | "is not a digest the pinned trivy release gives for its platform", or for Checkov "is not a digest the pinned checkov release gives for its platform and Python version" |
| `stages.<stage>.scanners.reports.<index>.input_kinds` | "is not one input kind a pinned `<tool>` run reads: ['plan']" |
| `stages.<stage>.scanners.reports.<index>.configuration_digest` | "is not the digest of the pinned `<tool>` run over what it read" |

`redacted_values` says what the kept report file holds, not what the redaction policy did. A marker in a field the
[kept form](#the-report-a-stage-keeps) drops is not in the file, so it is not counted. A reader counts with
`iltero_schemas.models.common.redaction.redacted_value_counts`, which walks the object values and list items of the kept
report, never its keys and never the inside of a marker. A marker at a field the reader reads, such as a rule id or an
address, makes that result unreadable, so it is also counted in `unreadable_results`.

A stage's redaction report (`redaction`, `iltero_schemas.models.common.redaction.RedactionReport`) says what the
stage's redaction hid, left unknown or exempted, by path. It holds no value.

| Field | Type | Meaning |
| --- | --- | --- |
| `policy` | object | The redaction policy that ran: `id`, `version` (identifiers) and `digest`. It is the record's `redaction_policy`, named by its digest (see [Redaction policy](#redaction-policy)). |
| `input` | object | What was redacted: `kind` and the `digest` of the redacted tree. The `kind` is what the stage reads: `observation` at `plan`, `facts` at `pre_deploy`, `deployment` at `post_deploy`, `drift_check` at `post_verify` (`iltero_schemas.models.common.stages.REDACTED_INPUT_KIND`): "the pre_deploy stage's redaction report is of the facts it read". A post-verify stage's `resource_redaction` is of kind `post_apply_resources`: "the post-verify stage's resource redaction is of the values after the apply". |
| `redacted` | list | Each path the policy hid (`RedactedPath`): `path`; `reason`, one of the [redaction reasons](#redaction-reasons); and `value_change` (see Value changes below): `changed`, `unchanged` or `unknown` on a path under a resource change's `after` in the plan stage's report, and `null` on every other entry. |
| `unknown` | list | The paths of the values the tool knows only after the deployment, each written as the `known_after_deploy` marker. |
| `exempted` | list | Each path the project exempted from the policy (`ExemptedPath`): `path`, and `reason`, the project configuration's own words: one line of plain text, at most 1024 characters. |

At `post_deploy` and `post_verify` the record keeps the part the stage counts as it is, so the redaction report is of
that part and redacts nothing (`iltero_schemas.models.common.stages.STAGES_THAT_REDACT_NOTHING`). Its `input.digest` is
the stage's `coverage.subjects_in_scope.source_digest`, the digest of the record's `change.deployment` at `post_deploy`
and of its `change.drift_check` at `post_verify`: "the post_deploy stage's redaction report is of the part it counts".
Its `redacted`, `unknown` and `exempted` lists are empty: "the post_verify stage redacts nothing: the part it counts is
kept as it is".

**Value changes.** In the plan stage's report, of what the plan stage observed, each `redacted` entry whose path lies
under a resource change's `after` names whether the value there changed (`value_change`,
`iltero_schemas.redaction.common.value_change`). A resource change is each item of `resources` and each related
resource's copy at `resources[i].related[k].resource`. The path is paired with the same relative path under that
change's `before` (`paired_before`): a list item is paired with the item at the same position under `before`, so an item
that moved reads as changed. Redaction (`iltero_schemas.redaction.common.apply.redact` with subject
`observation`) writes:

| `value_change` | When |
| --- | --- |
| `changed` | The paired path is hidden too, both values are present, and they differ. |
| `unchanged` | The paired path is hidden too, both values are present, and they are equal (RFC 8785 bytes). |
| `unknown` | The paired path is not hidden, either side is absent (a create, a delete, a list whose shape changed), the value is known only after the deployment, or the values have no canonical form. |

Every entry of one path names the same value change, and every other entry names `null`. The value change is the
statement of the program that redacted the plan stage's input: the record keeps neither value, so no reader can check
it later. Pairing is by path. `check_value_changes(report)` (`iltero_schemas.models.common.redaction`), which
the record's model calls for each stage's report and the post-verify stage's resource redaction, refuses any other use:

| Refused | Message |
| --- | --- |
| A value change in a report of anything but what the plan stage observed. | "only the redaction report of what the plan stage observed names a value change" |
| A value change off a path under a resource change's `after`, or none on such a path, in the plan stage's report. | "the redaction report of what the plan stage observed names a value change exactly on the paths under a resource change's after" |
| Two entries of one path naming different value changes. | "every entry of one path of a redaction report names the same value change" |
| `changed` or `unchanged` where the report does not list the paired path under `before`, or a path above it, as hidden. | "a redaction report says whether a value changed only where the paired value under before is hidden too" |
| `changed` or `unchanged` on a path the report's `unknown` list holds. | "a redaction report says whether a value changed only for a value known before the deployment" |

A path is a list of the object keys and list indexes from the redacted tree's root to one value, as the tree writes
them: `["resource_changes", 0, "change", "after", "password"]`. A key is text, kept as written: any characters, even
none, at most 64 KiB of UTF-8 (`iltero_schemas.models.common.fields.RawKey`). A reader escapes it to show it, control,
bidirectional and invisible characters included. An index is an integer from 0. A path is at most 64 steps long
(`MAX_REPORTED_PATH_DEPTH`), and each list holds at most 1,000,000 entries (`MAX_REPORTED_PATHS`).

| Rule | Refused with |
| --- | --- |
| Each list is in path order, then by reason, with no entry twice. Path order compares two paths step by step: at the first step where they differ, a list index comes before an object key, indexes compare as numbers and keys by Unicode code point; a path comes before the longer paths it starts (`iltero_schemas.models.common.redaction.path_order`). | "a redaction report lists each path in path order, then by reason, once" |
| No key on a listed path is [shaped like a credential](#keys-shaped-like-a-credential). | "a redaction report lists no path through a key shaped like a credential" |
| Each `reason` of `redacted` is a redaction reason. | Pydantic's message for a value outside the set, such as "Input should be 'declared_sensitive', ..." |

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
| `source` | object or null | The file as the pipeline gave it, before the record kept it (`EvidenceSource`): its `name`, a file name without directories, and its `digest`, a given file digest (see [Given file digests](#given-file-digests)). For a file kept as the pipeline gave it, `digest` is the entry's own `digest`. For a file kept redacted, it is keyed in a record of a run the server opened and `null` in a record of a run the tool opened. `source` is `null` for a file the tool wrote itself. |
| `canonicalization` | identifier or null | The canonical form the file's bytes are in, such as `RFC8785`, or `null`. |
| `redaction_policy` | object or null | The redaction policy that redacted the file's content, in the shape of a redaction report's `policy`: `id`, `version` and `digest`, those of the record's `redaction_policy`. `null` when no redaction policy ran over the file. A tool names the policy for every file it ran over, even when the policy hid nothing. For a file kept from the pipeline in an `image_build` or `image_deploy` record, `null` means the stored copy is the file as given: its `digest` equals `source.digest`. |

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
| `reason` | string | `not_managed` (not managed by the configuration), `deposed` (an old copy a replacement set aside), `makes_no_outside_object` (creates nothing outside the IaC tool, such as a random value), `identity_redacted` or `identity_unnameable` (an identity redacted, or one that cannot be named). |

The contract decides each reason from the resource's own entry in the plan the stage kept, from the resources the
plan's configuration gives a provisioner, a command the IaC tool runs when it creates the resource, and from the
resource types the stage's assertions name (see below)
(`iltero_schemas.models.iac.plan_exclusions.exclusion_reason(tool, change, provisioners, named_types)`).
`iltero_schemas.models.iac.plan_coverage.plan_exclusions(tool, plan, named_types)` gives every exclusion of a plan, in
the plan's order. The reason is the first of these that holds:

| Order | `reason` | When |
| --- | --- | --- |
| 1 | `identity_redacted` | Any naming field holds a whole redaction marker (`__redacted: true`, `reason`, `present`, `type`; `iltero_schemas.models.common.redaction.RedactedMarker`), whatever the other naming fields hold. |
| 2 | `identity_unnameable` | A naming field is empty text, is longer than its limit, or holds a control character. |
| 3 | `not_managed` | The resource's `mode` is not `managed`. |
| 4 | `deposed` | The resource's `deposed` holds a value. |
| 5 | `identity_unnameable` | The resource's provider has no short name an assertion can target. |
| 6 | `makes_no_outside_object` | The resource's type creates no object outside the IaC tool, and no assertion of the stage names that type (see below). |

When none holds, the plan gives no reason to leave the resource out. A naming field that is absent or `null` is not
checked. A naming field that holds any other value that is not text, such as a number, a list, an object or part of a
marker, means the plan is not one a stage keeps: `exclusion_reason` raises `ValueError`, and a reader reports the
stage as one that "names a plan its reader cannot read".

Each IaC tool names its own naming fields (`iltero_schemas.models.iac.tools.variants.PLAN_NAMING`). For
`terraform`, the naming fields are `address` and `module_address`, at most 2,048 characters each, and `type` and
`provider_name`, at most 256 characters each. `provider_name` is the provider's source address: a host, a namespace
and a type, such as `registry.terraform.io/hashicorp/aws`. The provider's short name is the type, the last of the three
parts, such as `aws`; it must match `^[a-z][a-z0-9_-]*$` and be at most 32 characters. A source address that is not
three non-empty parts gives no short name, so the resource is `identity_unnameable`: the bare `aws` that Terraform 0.12
wrote, or `hashicorp/aws`, does not say whose provider it is.

A Terraform resource creates no object outside the tool when its provider's source address and its type are one of
these, and the configuration declares it with no provisioner
(`iltero_schemas.models.iac.tools.terraform.makes_no_outside_object`):

| Provider source address | Types |
| --- | --- |
| `registry.terraform.io/hashicorp/random`, `registry.opentofu.org/hashicorp/random` | Every type that starts with `random_`, such as `random_id` and `random_password` |
| `registry.terraform.io/hashicorp/time`, `registry.opentofu.org/hashicorp/time` | Every type that starts with `time_`, such as `time_rotating` |
| `registry.terraform.io/hashicorp/null`, `registry.opentofu.org/hashicorp/null` | `null_resource` |
| `terraform.io/builtin/terraform` | `terraform_data` |

The source address must match exactly: a `random_id` from `example.com/acme/random` stays in scope. Any resource can
carry a provisioner, and a provisioner can run any command, so a resource of these types is left out only when the
plan's `configuration` declares it with no provisioner: one with a provisioner, one in a module the configuration
leaves out, or one whose provisioner list is of another shape stays in scope. The contract reads the root module and
every module it calls, by the address the configuration writes, without instance keys (`configured_provisioners(plan)`).
A provisioner of a `removed` block is not read.

Such a resource stays in scope when one of the stage's assertions names its type: the type appears, with the
resource's provider short name, in the `resource_types` of a `{tool, provider, resource_types}` selector of the
assertion's target (see [TechnicalAssertion](#technicalassertion)). The assertions are every one the stage evaluates,
whatever result it reached, built-ins, rules written by hand in Rego and assertions an exception covers included. A
rule written by hand (`assertion_source: custom_rego`) names the target its [policy source](#policysource) entry
declares. `iltero_schemas.models.iac.plan_exclusions.named_resource_types_of_targets(tool, targets)` gives these
`named_types` from the targets, as (provider short name, type) pairs such as `("random", "random_password")`. An
assertion about `random_password` evaluates each such resource instead of finding no subject.

A resource left out as `makes_no_outside_object` is not checked. A `random_password`'s length or a `time_rotating`'s
schedule can still matter to the resources that use it; only an assertion that names its type reads it.

A resource excluded for its identity is also a gap whose `kind` is the exclusion's `reason` and whose `plan_index` is
the resource's, listed once, and every identity gap names such a resource: "the identity gaps name, once each, the
resources the scope excludes for their identity, by the same reason". A plan resource is excluded at most once: "a
plan resource is excluded once, for one reason".

A stage's `coverage.gaps` lists what is missing from what the stage evaluated. Each gap has one of six shapes,
chosen by its `kind`:

| `kind` | Other field | Meaning |
| --- | --- | --- |
| `plan_incomplete`, `plan_not_applyable` | `value`: `false` or the `not_reported_by_tool` marker | A plan flag that is not `true`. The kind names the flag (`plan_incomplete` for `complete`, `plan_not_applyable` for `applyable`) and `value` carries what the plan said: `false` means the plan said so, the marker means it did not say. |
| `identity_redacted`, `identity_unnameable` | `plan_index`: integer from 0 | A plan resource whose identity was redacted or cannot be named, by its index in the plan's resource list. |
| `deferred_changes`, `related_copies_omitted`, `unresolved_references`, `checked_after_deployment`, or a `not_evaluated` or `error` [status reason](#assuranceevent) | `count`: integer from 1 | How many of one thing are missing: what the plan left out, checks the plan stage [postponed until after the deployment](#checks-postponed-until-after-the-deployment), or combined verdicts the reason left without a decision (see below). |
| `state_not_read` | none | The state after the apply was not read, so no outcome of the apply was held to it (`StateNotReadGap`; see [When the state after the apply was not read](#apply-with-the-state-not-read)). |
| `evaluator_did_not_decide` | `engine`, `reason`, `count`: integer from 1 | How many of the stage's evaluations by one evaluator (`engine`, as its events name it) could not decide an assertion about a subject, where the subject's combined verdict does not count them, and why (`reason`, a `not_evaluated` or `error` [status reason](#assuranceevent)) (`EvaluatorDidNotDecideGap`; see below). |
| `provider_has_no_resource_kinds`, `provider_source_not_reviewed` | `provider_source`: identifier; `count`: integer from 1 | How many of the plan's resources in scope come from one provider source address, as the plan wrote it, that no check reaches as reviewed (`ProviderSourceGap`; see below). A resource the plan deletes or forgets is not counted, nor, in a `provider_has_no_resource_kinds` gap, one whose type an assertion of the stage names. |

A gap in a stage's own `coverage` names no `stage`: the field is left out or `null`. The record's combined `coverage`
names the stage each gap came from.

A stage lists, for each `not_evaluated` or `error` reason (`iltero_schemas.models.common.coverage.NO_DECISION_REASON_GAP_KINDS`),
one count gap whose `count` is the number of its [combined verdicts](#how-evaluators-combine) that are
`not_evaluated` or `error` and that the reason gave: the reasons of the evaluations that reached the verdict (an
engine in `decided_by`, with the verdict's status), each counted once per verdict
(`iltero_schemas.models.common.verdicts.no_decision_reason_counts`). A reason behind no such verdict is not listed.
The integrity checks recompute the counts from the events: "does not count, for each reason, the verdicts of the stage
that the reason left without a decision", at `stages.<stage>.coverage`.

A combined verdict can rest on an evaluation that could not decide and that the verdict does not count: OPA could not
run the assertion's rule while Checkov decided it, Trivy names no resource for a passing check, or a scanner did not
evaluate a check while OPA ended in error. The verdict stands, and the stage lists, for each evaluator and reason, one
`evaluator_did_not_decide` gap. Its `count` is the number of the stage's evaluations by that evaluator that are
`not_evaluated` or `error` with that reason, less those the subject's combined verdict counts: a verdict of the same
status, reached by that evaluator (its engine in `decided_by`). An evaluation beside a decided verdict, beside a
verdict without a decision that another evaluator reached, or beside one with another status is counted in the gap
(`iltero_schemas.models.common.verdicts.evaluator_did_not_decide_counts`; a writer builds the gaps, sorted by evaluator
and reason, with `evaluator_did_not_decide_gaps`). An evaluator and reason behind no such evaluation are not listed.

| Rule | Refused with |
| --- | --- |
| A stage lists each evaluator and reason once. | "a stage lists each evaluator and reason that did not decide once" |
| `reason` is a `not_evaluated` or `error` status reason (`NO_DECISION_REASON_GAP_KINDS`). | "reason is a reason an evaluation is not evaluated or in error" |
| The gaps are the counts the stage's events give, an integrity check at `stages.<stage>.coverage`. | "does not count, for each evaluator and reason, the evaluations that could not decide where the stage's verdict about the same assertion and subject reached a decision or decided nothing for another reason" |

A gap whose `reason` is an `error` reason gives the stage's evidence gaps: its evidence status `has_gaps` with
reason `required_policy_evaluation_failed` and the `detail`
`evaluator errors outweighed by another evaluator's verdict on the same assertion: <count>`, with the sum of those
gaps' counts. A stage with a combined verdict that is `error` keeps that verdict's detail instead,
`<n> of <evaluations> evaluations ended in an evaluator error`. A gap whose `reason` is a `not_evaluated` reason is
listed only: it changes neither the verdict nor the evidence status.

The kinds a count gap may name are
`iltero_schemas.models.common.coverage.COUNT_GAP_KINDS`. A coverage lists at most
`iltero_schemas.models.common.coverage.MAX_GAPS` gaps.

A provider source gap counts plan resources that no kind-scoped check reaches as reviewed. A kind-scoped check, one on
a `change` or `deployment` target, names resources by kind, from a provider's list of resource kinds
(`iltero_schemas.kinds.RESOURCE_KINDS`), and each IaC tool's kind table gives the provider's resource types their
kinds. A stage that counted the plan's resources (`counted_from: plan_resource_enumeration`) reads the provider source
address of each resource in scope and lists one gap for each kind and source address that has at least one resource
(`iltero_schemas.models.iac.plan_coverage.provider_source_gap_kind(tool, source)` gives the kind). The resources in
scope leave out the excluded ones and the ones the plan deletes or forgets (actions `["delete"]` or `["forget"]`,
`iltero_schemas.models.iac.plan_exclusions.leaves_scope`): a removed resource is no subject, so no check misses it.
A `provider_has_no_resource_kinds` gap also leaves out each resource whose type one of the stage's assertions names
(`named_types`, see above): the assertion that names it reaches it. A `provider_source_not_reviewed` gap still counts
such a resource, because checks that select by kind read it through a table that may not describe it. A replaced
resource, deleted and created again, is counted:

| `kind` | When | Example `provider_source` |
| --- | --- | --- |
| `provider_has_no_resource_kinds` | The provider's short name has no list of resource kinds, so no kind-scoped check can name its resources. | `registry.terraform.io/hashicorp/awscc` |
| `provider_source_not_reviewed` | The provider's short name has a list, but the source address is not one the kind table was reviewed against, such as a fork of the same name. Checks still reach its resources through the table, which may not describe them. | `example.com/acme/aws` |

The sources each kind table was reviewed against are
`iltero_schemas.models.iac.tools.terraform.REVIEWED_PROVIDER_SOURCES`: for `aws`,
`registry.terraform.io/hashicorp/aws` and `registry.opentofu.org/hashicorp/aws`. A writer builds the gaps with
`provider_source_gaps(tool, plan, excluded, named_types)`, sorted by `kind` and then by `provider_source`.

A source address names a publisher's namespace, not the program that ran: a provider mirror or a local override can
install any program under it. A provider source gap makes resources no check reaches as reviewed visible; it does not
change the verdict.

A reader recounts a stage's exclusions and provider source gaps from the redacted plan the stage kept, together with
the target of each rule the stage evaluated, when the stage keeps a scanner report or names a scanner requirement (see
[Evaluations from a scanner's results](#evaluations-from-a-scanners-results)). It reads each target from the kept
files' `assertions`: the assertion document the event names, or for a rule written by hand, the policy entry whose
digest is the event's assertion digest and whose assertion id, version and stage are the event's
(`iltero_schemas.models.iac.stage_assertions.stage_targets`). The targets decide which types stay in scope, so when the
kept files do not give one, the reader lists each such event as one that "names an assertion document that is not
given" and does not check or recount the stage's exclusions and gaps. For any other stage they are the writer's claim,
held only to the rules above.

| Rule | Refused with |
| --- | --- |
| A stage lists each `kind` and `provider_source` once, sorted by `kind` and then by `provider_source`. | "a stage lists each provider source once for each kind of gap, sorted by kind and source" |
| Only a stage that counted the plan's resources lists one. | "only a stage that counted the plan's resources lists a provider source gap" |
| A stage's provider source gaps count, together, at most its `subjects_in_scope.value`. | "a stage's provider source gaps count no more resources than it has in scope" |
| Each gap's `kind` is the one its `provider_source` gives (`check_provider_source_gaps`). | "the plan stage lists registry.terraform.io/hashicorp/aws as a provider with no resource kinds, which its source address does not give" |

A stage with a provider source gap has the evidence status `has_gaps`, with the reason the gap's `kind` names (see
[Verdict and evidence status](#verdict-and-evidence-status)).

The `state_not_read` gap:

- The `post_deploy` stage of an `iac_change` record lists it exactly when `change.deployment.apply.state` is the
  `state_not_read` marker, an integrity check: "does not match change.deployment.apply.state: one state-not-read gap
  exactly when the state after the apply was not read".
- A stage lists it at most once: "a stage lists the state not read once". No other stage lists it: "the plan stage
  lists the state not read, which only the post-deploy stage lists".
- A record of an activity whose `reads_a_state_after_the_apply` is `False` (see [Change types and
  activities](#change-types-and-activities)) refuses it: "the post_deploy stage lists the state not read, which a
  record of image_deploy never has".
- A stage that lists it has the verdict `incomplete` with reason `not_evaluated`, unless a required check failed, which
  makes it `not_met`. Its evidence status `has_gaps` with reason `state_not_read` and the `detail` `the state after the
  apply was not read, so no outcome of the apply was held to it`. Within the stage, an evaluator error's reason is
  listed before it.

Each `out_of_scope` entry names a `stage`, a `reason` and `declared_in`. The stages each reason can leave out are the
record's activity's (see [Change types and activities](#change-types-and-activities)). An `image_build` record leaves
out no stage. An `image_deploy` record can leave out only `post_verify`, for `project_config`, `environment_policy` or
`not_supported`; it may call it `not_supported` whatever the workload, since the workload may be of a kind no reader
reads. For `iac_change`:

| `reason` | Meaning | Stage it can leave out | `declared_in` |
| --- | --- | --- | --- |
| `project_config` | The project declared the stage out of scope. | `post_verify` | The project file that says so, by its `path` and its `digest`. |
| `environment_policy` | The environment policy of the environment Iltero Platform opened the run for does not require the stage. Iltero Platform holds the policy; the record does not name it. | `pre_deploy` or `post_verify`, in a record whose `governance.run_opened_by` is `server`; never `pre_deploy` for a production environment | `null` |
| `needs_the_server` | The stage reads what only Iltero Platform supplies, and the tool opened the run on its own. | `pre_deploy`, in a record whose `governance.run_opened_by` is `local`, which must leave that stage out for this reason | `null` |
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
| `first_reading_digest`, `second_reading_digest` | given file digest or null | Each refresh-only plan's bytes as the tool wrote them, which the record never keeps: keyed in a record of a run the server opened, `null` in a record of a run the tool opened (see [Given file digests](#given-file-digests)). Both are named or neither is: "the drift check names the digests of both readings, or of neither". When named, the two differ: "the two readings are two refresh-only plans, so their digests differ". |
| `minimum_interval_seconds` | integer | The least time the readings had to be apart, from 1 to 86,400 (a day). |
| `differences` | list | Each resource that differed from the apply in the second reading: its `address` and its `difference`, `changed` (its values changed) or `deleted` (it is no longer there). Sorted by address, each once, at most 100,000. |
| `differences_count` | integer | The number of `differences`, which an assertion compares. |
| `first_reading_only_differences` | list | Each resource that differed in the first reading but not in the latest, for a reason the check does not give: its `address` and its `difference` as the first reading found it. Sorted by address, each once, at most 100,000. No address is also in `differences`. |

The drift check keeps addresses only: no attribute value, and no copy of either reading. It reports what the
pipeline that ran the apply saw, and nothing about resources outside the state or attributes the tool does not read
back.

Key rules:

- Every path in the record is relative to the record's directory, except the project paths: `units_file.path`, each
  unit's `directory` in it, `out_of_scope[].declared_in.path`, `scanners.local_exceptions.file_path` and a scanner check
  mapping's `file_path`. These are relative to the project's directory, `subject.project_directory`, so following one
  never leaves the project. Paths to files the record keeps stay inside the record's directory. A project path
  (`ProjectPath`) holds no `.` or `..` part, no empty part, no `\`, no leading `/` and no `:` (a Windows drive or file
  stream), at most 1024 characters: "must be a relative path inside the project, with no '..', '.', empty part, ':' or
  leading '/'". A directory (`DirectoryPath`), `subject.project_directory` or a unit's `directory`, is exactly `.` for
  the directory it is relative to, or a path by the same rule, so never one with a leading `./` or a trailing `/`: "must
  be '.' or a relative path with no '..', '.', empty part, ':' or leading '/'". An empty value is refused with "at least
  1 character". In both, each part, in its compatibility form (NFKC), holds no separator or colon, look-alike ones
  included, and is not only dots and spaces, which Windows drops from the end of a name: "must name each part plainly:
  not only dots and spaces, and with no character that looks like a separator or a colon". A path in the record's
  directory is plain names joined by `/`, at most 6 deep and 1024 characters, each name using only letters, digits,
  `.`, `_`, `@` and `-`, and never `.` or `..`. No two `evidence_refs` entries share a `path` or a `ref_id`.
- `subject.project_tree.id` is the git tree id of `subject.project_directory` at `subject.source.commit.sha`: git's
  id of the names, file modes and contents of every file git tracks under that directory, so a record is written only
  for a project directory git tracks at the commit. It is the writer's reading: the contract cannot check it, and a
  reader with the repository reads it again with `git rev-parse <commit>:<project_directory>/` (the trailing `/` makes
  git refuse a path that names a file), or `git rev-parse <commit>^{tree}` when the project directory is `.`. It covers
  only the files git tracks under the directory at the commit:

  | Not covered | Such as |
  | --- | --- |
  | Files not committed | Uncommitted changes, untracked files and ignored files. A run from a checkout with uncommitted changes still names the commit's tree, not what was on disk. |
  | Files outside the directory | A shared module referenced by a relative path such as `../modules`, a remote or registry module, the target of a symbolic link. |
  | Anything that is not a project file | Variables, state and tool versions. |
  | The files of a submodule | A submodule inside the project directory is covered only by the commit it points at. |

  Two records of the same repository and project directory that name the same tree come from commits whose project
  files are the same. That says nothing about the files on disk when each run ran, and does not make their changes the
  same: what a record checks is its change, by its [checked content](#checked-content). Tree ids compare only between
  records of the same repository and project directory.
- Each entry of the evidence register has its own name (`ref_id`): "no two entries of the evidence register share a
  name". Two entries may name one `path` only when they name one file, as a record package, which keeps each file by
  its digest, writes them: the same `digest` ("no two entries of the evidence register name one file by different
  digests"), and the same `size_bytes`, `media_type` and `canonicalization` ("two entries of the evidence register
  that name one file name it by the same size, media type and canonicalization"); their `source`, `collected_at` and
  `redaction_policy` may differ. A record package rewrites every path field of the record to where it keeps the file:
  each entry's `path`, each stage's `events.path` and `assertions.index`, and the `copy_path`, `observations` and
  `redacted_plan` of its scanner files and its copies of the exceptions it applied. It keeps each entry's `ref_id`,
  `digest` and every other field, so a packaged record passes every reader check the record it was packaged from
  passes.
- These files that a record's stages and events name are entries of its evidence register
  (`iltero_schemas.models.common.register.check_register`):

  | File | Matched by | Refused with |
  | --- | --- | --- |
  | Each stage's events file | Its `path` and `digest`, on an entry with `canonicalization: RFC8785` | "the plan stage's events file is an entry of the evidence register", or "the plan stage's events file is kept as canonical JSON (RFC8785)" |
  | Each stage's assertion index | Its `index` and `digest` | "the plan stage's assertion index is an entry of the evidence register" |
  | Each stage's copy of each scanner check mapping it applied | Each `scanners.scanner_check_mappings` entry's `copy_path` and `digest` | "the evidence register lists the copy of each scanner check mapping the plan stage applied" |
  | What a stage read from each scanner report | The report's `observations` path | "the observations the plan stage read from its checkov report are an entry of the evidence register" |
  | Each scanner report as the stage kept it | The report's `report_digest`, on an entry that names a `source` and a `redaction_policy` and was collected as that scanner's report (`collector.tool` is the report's `tool`). Every such entry names one pipeline file by its `source.name`. In a record of a run the server opened, every such entry names one keyed `source.digest`. In one the tool opened, none names a digest. | "the checkov report the plan stage kept is an entry of the evidence register, redacted from the file the pipeline gave" |
  | The input every event was evaluated over | Its `provenance.input_digest` | "the input every event was evaluated over is an entry of the evidence register" |
  | What the plan stage redacted | Its `redaction.input.digest`, on an entry that names a `redaction_policy` | "what the plan stage redacted is an entry of the evidence register that names the redaction policy" |
  | Each stage's copy of the project's exceptions file | `scanners.local_exceptions.copy_path` and `digest`, on an entry that names the file as its `source` (`source.name` is the file name of `file_path`, without its directories, and `source.digest` is `digest`) and have no `redaction_policy` and no `canonicalization`: the copy is the file's bytes, unredacted and as the project wrote them | "the plan stage's copy of the project's exceptions file is an entry of the evidence register, copied byte for byte from the file it names" |
  | Each stage's copy of the exceptions Iltero Platform served it | `served_exceptions.copy_path` and `digest`, on an entry of its own (no events file, assertion index or scanner file) with `canonicalization: RFC8785`, `source: null` and no `redaction_policy` | "the plan stage's copy of the exceptions the server served it is an entry of the evidence register of its own, kept as canonical JSON (RFC8785) and not copied from a file the pipeline gave" |

  The scanner files are tied to where they came from:

  | Rule | Refused with |
  | --- | --- |
  | The register entry of the copy of a project's scanner check mapping names the file the mapping was read from as its `source`, with `source.name` equal to the last part of that entry's `file_path`, the file's name. The register entry of the copy of the shipped or the served mapping has no `source`. | "in the evidence register, the copy of a project's scanner check mapping names the file it was read from, and the copy of the shipped or the served mapping names no file" |
  | Each scanner file a stage keeps (each scanner check mapping copy, its observations, the entry of each kept report, and the copy of the project's exceptions file) is an entry of its own: never another scanner file, nor any stage's events file or assertion index. The digest of a kept report or of its observations is never the `input_digest` of an evaluation that stands on no scanner's result. | "each scanner file a stage keeps is an entry of its own, not a file the record names for another part" |
  | The observations were read from the file the report was kept from: every observations entry names a `source` with the kept report's `source.name`. In a record of a run the server opened, its `source.digest` is the kept report's too, and neither is `null`. In a record of a run the tool opened, the observations also name their report by its `report_digest`. | "the observations the plan stage read from its checkov report were read from the file that report was kept from" |

  In an `iac_change` record whose post-deploy stage has reported, the apply log the deployment was read from is an
  entry too: exactly one entry collected by the apply tool's apply log reader
  (`iltero_schemas.models.iac.tool_names.APPLY_COLLECTORS`: `terraform_apply` for `terraform`), with a `source` and a
  `redaction_policy`. Otherwise: "the apply log the deployment was read from is one entry of the evidence register,
  collected by terraform_apply and kept redacted". In a record of a run the server opened, that entry's `source.digest`
  is `change.deployment.apply.source.digest`, and neither is `null`: "in a record of a run the server opened, the apply
  log's entry of the evidence register names the keyed digest the deployment names".
- A record redacts under one policy, the one it writes out in `redaction_policy`
  (`iltero_schemas.models.common.stages.check_structure`, whatever the validation context). The record rebuilds that
  policy (see [Redaction policy](#redaction-policy)), and every stage's `redaction.policy`, every
  `resource_redaction.policy` and every `evidence_refs[].redaction_policy` that is not `null` names its `id`, `version`
  and `digest`: "every stage and every redacted evidence file name the redaction policy the record writes out, by its
  digest". The digest tells apart two policies that share an `id` and `version`.
- The first expected stage is the activity's first stage (`plan` for `iac_change` and `image_build`, `pre_deploy` for
  `image_deploy`): "a record starts at its plan stage", or "a record starts at its pre_deploy stage". `runtime` is never
  a stage of a record. Every stage of the activity is either expected or listed once in `out_of_scope`, with a reason
  that can leave it out, so an `iac_change` record always expects `plan` and `post_deploy`, and an `image_deploy` record
  `pre_deploy` and `post_deploy`. A stage left out by `project_config` names the declaring file in `declared_in`; any
  other stage is refused: "a project can leave out only the post-verify stage", for an `iac_change` or an `image_deploy`
  record alike. A stage that is not one the activity's `not_supported(record)` names is refused as `not_supported`, in a
  record of any activity: "the post-verify stage is supported for this record: expect it, or say who leaves it out",
  naming the first such stage. A stage left out by `environment_policy` that the activity's policy may not leave out is
  refused: "an environment's policy can leave out only the pre-deploy and post-verify stages" for `iac_change`, "an
  environment's policy can leave out only the post-verify stage" for `image_deploy`; and only a record of a run Iltero
  Platform opened may name that reason: "only a run the server opened has an environment policy that leaves a stage
  out". A record of a run Iltero Platform opened for a production environment (`subject.environment.production` is
  `true`) expects its `pre_deploy` stage, for an infrastructure change where approvals are read: "a record for a
  production environment expects its pre-deploy stage".
- A record of a run the tool opened leaves out, as `needs_the_server`, every stage its activity says needs the server
  (`stages_that_need_the_server`: `pre_deploy` for `iac_change`, whose approvals and commit review only Iltero Platform
  supplies; none for `image_build` and `image_deploy`): "a run the tool opened leaves the pre-deploy stage out of scope
  as needing the server: only the server supplies what that stage reads". No other stage is left out for that reason:
  "only the pre-deploy stage needs the server", or "no stage of this activity needs the server". A record of a run
  Iltero Platform opened leaves no stage out as `needs_the_server`: "only a run the tool opened leaves a stage out as
  needing the server: a run the server opened supplies what every stage reads".
- A stage's verdict follows from its own counts, and the record's is the stage verdict that wins by a fixed order (see
  [Verdict and evidence status](#verdict-and-evidence-status)). A stage counts no more checks as postponed than it
  left unknown: "a stage counts no more checks as checked_after_deployment than it left unknown".
- A stage's evaluations are about one kind of subject, one its assertions can target, and the stage counts its subjects
  by that kind (`iltero_schemas.models.common.stages.scope_counted_from`): the plan stage enumerates the plan's resources
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
- `enforcement_mode` is the mode the stage's gate ran in. With `advisory` enforcement, a failed or undecided check does
  not stop the pipeline; a missing check, or a check whose evaluator failed, always does. The Iltero CLI also exits with
  a failure on any result other than `pass` or `not_applicable` of a check the activity enforces in advisory mode
  (`enforced_in_advisory_mode`: the five [checks of the apply job](#the-checks-of-the-apply-job)). Only the plan and
  pre-deploy stages can be `advisory`; a stage after the deployment is always `enforcing`. In a run Iltero Platform
  opened, Iltero Platform's policy sets it; otherwise it is the tool's choice. It is the writer's claim; only the CI
  job's own result shows what the pipeline did.
- A stage that could not read an input, such as the state of a unit it reads from, lists each replaced input once in
  `coverage.substituted_inputs`: `kind: upstream_state` and the input's `source`, the tool's address of the input (for
  a Terraform configuration, its module path and data source, with no instance key). A stage lists at most 256, sorted
  by `source` by Unicode code point; a record lists at most 256 across its stages. Its verdict still follows its
  evaluations, and its evidence status lists `upstream_state_unavailable`, after any reason that comes earlier in
  `GAP_REASON_PRECEDENCE`.
- A `met` verdict on a stage that lists `substituted_inputs` is a verdict on the placeholder plan, not on the change:
  a gate reads `evidence_status` with the verdict.
- The plan stage lists one plan-flag gap for each plan flag that is not `true`, with the plan's flag as its `value`,
  in kind order: `plan_incomplete` before `plan_not_applyable`. A plan-flag gap in any other stage is refused.
- A plan stage with a `plan_incomplete` gap has an evidence status that `has_gaps` with reason `plan_not_complete`,
  and its verdict still follows its evaluations. The `detail` is `the plan says it is incomplete` (`value: false`) or
  `the plan does not say it is complete` (the marker). It is listed after an evaluator error's reason and before
  `upstream_state_unavailable`. A `plan_not_applyable` gap leaves the evidence status as it is: Terraform marks a plan
  that changes nothing as not applyable.
- A record whose state after the apply was not read has no `drift_check` and no `post_verify` stage: "post-verify
  needs the identities the state after the apply gives, and the state after the apply was not read". Its
  `all_expected_stages_reported` field is `true` only when `post_verify` is out of scope, and its `evidence_status`
  stays `has_gaps`, listing `state_not_read` for `post_deploy`. Only `required_policy_evaluation_failed` comes before
  it. The post-deploy stage's `state_not_read` gap and `change.deployment.apply.state` show it too.
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
  lists together hold at most `resources_read` entries. `first_reading_digest` and `second_reading_digest`, when named,
  differ.
- The model runs the integrity checks: it recomputes every value a reader can recompute and refuses a record whose value
  differs. They cover the change digest and the digests bound to it (the pre-deploy stage's
  `coverage.subjects_in_scope.source_digest`, each approval of a change and `change.drift_check.change_digest`), the
  counts from events, each stage's verdict and evidence status, the plan stage's plan-flag gaps, the post-deploy stage's
  `state_not_read` gap (see the gap's rules above), the status each built-in check must have, the combined top level and
  the record's id. The record's `metadata.uuid` is the one its `run.id` and `unit` give, or "is not the id of the
  record's run and unit" at `metadata.uuid`. A stage's `events.count` is the number of its events, or "does not count
  the stage's events" at `stages.<stage>.events`. A stage's `events.digest` is the digest of the bytes
  `events_file_bytes` gives for its events, or "is not the digest of the stage's events" at
  `stages.<stage>.events.digest`; when it is, the register entry of the events file has their size, or "is kept in the
  register at another size than its events" at `stages.<stage>.events`. These events-file problems are listed after
  every other. A stage's `coverage.evaluations` is the number of its [combined verdicts](#how-evaluators-combine), or
  "does not count one evaluation per assertion and subject of the stage", and its `coverage.status_counts` count their
  statuses, or "does not count the combined statuses of the stage's evaluations", and its
  `coverage.failed_checks_excepted` counts the failed checks its served exceptions cover in full (see [Verdict and
  evidence status](#verdict-and-evidence-status)), or "does not count the failed checks the exceptions the stage names
  cover in full", and its `coverage.evaluator_status_counts` count each evaluator's own statuses, or "does not count,
  for each evaluator, the statuses of the evaluations it gave", and its count gaps of the reasons verdicts were left
  without a decision and its `evaluator_did_not_decide` gaps (see the gaps above), all at `stages.<stage>.coverage`. An
  event's `status_reason` is `state_not_read` only in an `iac_change` record whose state was not read, at `post_deploy`;
  otherwise it is an integrity failure at `events.<index>.evaluation.status_reason`: "names a state not read the record
  does not". In an `iac_change` record, an `unknown` `ILT.IAC.CHANGE.CONTENT.RENDERED_PLAN_MATCHES_EVALUATED_PLAN`
  event's `status_reason` is `rendered_plan_not_sent` exactly when the `pre_deploy` stage's apply job's facts hold
  `{"outcome": "not_sent"}` as `rendered_plan`; otherwise it is an integrity failure at
  `events.<index>.evaluation.status_reason`: "is not rendered_plan_not_sent, what the apply job's facts give", or "is
  rendered_plan_not_sent, but the apply job's facts name a rendered plan" ("…, but the stage kept no apply job's facts"
  when the stage kept the unknown marker). An `unknown` `ILT.IAC.CHANGE.CONTENT.REPLAN_HAS_SAME_ACTIONS_AS_EVALUATED_PLAN`
  event's `status_reason` is `replan_not_compared` exactly when `change.replan_check` is `{"outcome": "not_compared"}`;
  otherwise it is an integrity failure at `events.<index>.evaluation.status_reason`: "is not replan_not_compared, what
  the record's re-plan check gives", or "is replan_not_compared, but the record names a re-plan it compared" ("…, but
  the record names no re-plan" when it names none). In an `iac_change` record,
  `ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN` must be `pass` exactly when `change.deployment.plan`
  has the evaluated plan's `digest`, `artifact_digest` and `artifact_digest_source`, and `fail` otherwise;
  `ILT.IAC.DEPLOYMENT.DRIFT.NO_DRIFT_AFTER_APPLY` must be `pass` exactly when `change.drift_check.differences_count` is
  0, and `fail` otherwise; each of the five [checks of the apply job](#the-checks-of-the-apply-job) must have the status
  `apply_job_check_statuses` gives for the facts and approvals the `pre_deploy` stage kept, and the [re-plan
  check](#the-re-plan-check) the status `replan_check_status` gives. An event of any of these
  checks whose status is one a policy answers with (`pass`, `fail`, `unknown` or `not_applicable`,
  `iltero_schemas.models.common.event.POLICY_STATUSES`) and not the recomputed one is an integrity failure at
  `events.<index>.evaluation.status`: "is not fail, what the record's change gives". An event that is `not_evaluated` or
  `error` decides nothing and is not compared. The `image_deploy` checks are recomputed the same way (see [The
  `image_deploy` body](#the-image_deploy-body)). The change digest problems come first, so a forged `change.digest` is
  refused as `change.digest is not the digest of the change type, unit, environment and plan`. A reader that reports
  integrity failures itself sets `SKIP_INTEGRITY_CHECKS` (`iltero_schemas.models.common.car`) to `True` in the
  validation context (any other value is ignored), then calls `iltero_schemas.models.common.stages.integrity_problems`,
  which returns every problem as a `(where, what)` pair. An approval of another run is refused whatever the context.
  Every reader of a record, with or without that key, calls
  [`kept_file_problems`](#checking-a-record-against-its-kept-files), which makes these checks and the checks of the
  files the stages kept: the model alone does not check those files.
- A record of a run the tool opened (`governance.run_opened_by: local`) names no Iltero Platform bundle, no
  evaluation from one, no facts from Iltero Platform, and no stage `reference_time` from it (`source: server`). It
  applies no scanner check mapping Iltero Platform served (`origin: served`): "a record of a run the tool opened
  applies no scanner check mapping the server served". Every
  stage's `coverage.assertions_required.origin` is `server_pinned` exactly when Iltero Platform opened the run
  (`governance.run_opened_by: server`): "stages.plan: counts its assertions as server_pinned exactly when the server
  opened the run". In a record of a run Iltero Platform opened for an activity whose run is a change
  run (`run_type: change`), `subject.environment` names the environment the run was opened for. A build run belongs
  to no environment, whoever opened it. Either way the record is the writer's own (see
  [What checking offline establishes](#what-checking-offline-establishes)).
- A record that names an environment says whether it is production, as `true` or `false`, exactly when Iltero
  Platform opened its run, and holds the unknown marker `{"__unknown": true, "reason": "server_facts_unavailable"}`
  when the tool opened it: a tool cannot know Iltero Platform's environment policy. Otherwise the record is refused:
  "a record names whether its environment is production exactly when the server opened its run, and holds the
  unknown marker when the tool opened it". In a record of a run Iltero Platform opened, the value can be compared
  with the production flag of the environment Iltero Platform opened the run for.
- In a record of a run the tool opened, an `ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED` event is never `pass`, `fail` or
  `not_applicable`, and when it is `unknown` its `status_reason` is `server_facts_unavailable`. An event that was not
  evaluated or that ended in `error` is accepted. Otherwise the record is refused:
  "ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED is unknown with reason server_facts_unavailable, never pass, fail or
  not_applicable, on a run the tool opened: only a server that opened the run reviews its commits".
- In a record of a run Iltero Platform opened, an `ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED` event that is `pass` or
  `fail` read its facts from Iltero Platform (`provenance.facts_source: server`):
  "ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED passes or fails only on facts read from the server".
- A record of a run Iltero Platform opened evaluates only assertions from Iltero Platform's bundle: every event's
  `provenance.assertion_source` is `server_bundle`, so it evaluates no hand-written Rego, no assertion of the
  project's own and no copy of this package's starter assertions. Otherwise the record is refused: "a record of a run
  the server opened evaluates only assertions from the server's bundle: no hand-written Rego, no project's own
  assertion and no copy of this package's".
- Every stage of a record of a run Iltero Platform opened that reads scanner reports applies only the scanner check
  mapping Iltero Platform served (`[served]`): "a record of a run the server opened applies only the scanner check
  mapping it served".
- A record of a run Iltero Platform opened postpones no check until after the deployment: no stage's
  `values_known_after_deployment` is `postpone`, so its plan stage blocks on a value the plan knows only after the
  deployment. Otherwise the record is refused: "a record of a run the server opened postpones no check until after the
  deployment: its plan stage blocks on a value known only after the deployment".
- Every event's `provenance.checked_content` is the record's [checked content](#checked-content): "every event names
  the content the record's change checked". Every event's `evaluation.activity` is the record's `change.activity`:
  "every event names the record's activity".
- In an `iac_change` or `image_deploy` record, `change.digest` is the [change digest](#the-change-digest) of the
  record's change type, its `unit`, its environment's name (`subject.environment.name`, `null` when
  `subject.environment` is `null`) and its checked content. Approvals bind to it. An
  `image_build` record has no change digest.
- A record's `subject.unit` is its `unit`. When `units_file` is set, the record's `unit` is one of its units' names:
  "the record's unit is one of the units its units file declares".
- Across records, which the contract does not check and a reader does: the records of one run share `run.id`, name the
  same `subject.project_directory` and `subject.source.commit`, and every one of them names the same `units_file`, or
  every one names `null`. The run has a record for each declared unit when the records' units are the names in
  `units_file.units`. The units file is the writer's copy: records cannot show a run with no record at all, or a units
  file the writer left out or shortened. A reader can compare the record's digest with the file at the record's
  commit. The digests also differ when the writer read uncommitted changes or git converted the file on checkout, so
  a mismatch alone does not show the record is wrong.
- A stage's `coverage.assertions_required.required_assertion_digest` is the digest of the assertions it was required to
  evaluate, whether or not each was evaluated: as the project's files gave them (`origin: project_files`), or as Iltero
  Platform set them for the run (`origin: server_pinned`). The integrity checks recompute it:
  `assertions_required.value` is the stage's assertion index count (`assertions.count`), or "is not the count the stage
  gives its assertion index"; and, for a stage not cut short (`coverage.truncated.value: false`), the count and the
  digest are those of the `(id, version, digest)` set of the stage's events, or "does not describe the assertions of the
  stage's events", both at `stages.<stage>.coverage.assertions_required`. The digest and count describe the stage's
  events and its assertion index; a writer that leaves out a required assertion and its events still agrees with itself.
  A check the plan stage postponed is required of the plan stage: the `post_verify` stage's set leaves out the
  assertions it evaluates to settle one. What a stage was required to evaluate is shown only against the project's
  assertion files at `source_commit`, or the set Iltero Platform pinned for the run.
- These rules establish consistency only: an unsigned record cannot prove that Iltero Platform opened its run (see
  [What checking offline establishes](#what-checking-offline-establishes)).
- `compiler.contract_digest` is the SHA-256 over the sorted `path,hash` lines of the wheel's `RECORD` entries for the
  package's own files. `iltero_schemas.distribution.installed_identity()` returns it for the installed package. An
  editable install has none.

### Verdict and evidence status

Each stage, and the record, gives two separate answers. The verdict says what the stage's required checks came to.
The evidence status lists every reason the evidence behind that verdict has gaps. A required check is one assertion
the stage was required to evaluate about one subject in scope. An assertion that ran and found no subject in scope
counts as evaluated: it had no check to make. A stage's verdict is about all of its required checks; an event's
status, and the [combined verdict](#how-evaluators-combine) for one assertion and subject, are about one check.

The verdict words describe the stage's required checks only. They never say that a framework control is met or that
anything is compliant: a record's `compliance_determination` is always `null`.

- **Models:** `iltero_schemas.models.common.coverage.Verdict`; `iltero_schemas.models.common.evidence_status.EvidenceStatus`
  and its `GapReason` items, with the reason constants and `GAP_REASON_PRECEDENCE`
- **Functions:** `iltero_schemas.models.common.coverage.stage_outcome(coverage)` gives a stage's verdict and evidence
  status; `iltero_schemas.models.common.stages.record_outcome(car)` gives the record's.
  `iltero_schemas.models.common.coverage.required_checks_missing(coverage)` says why a stage did not make every
  required check, and `every_required_check_made(coverage)` is false when it did not or when it lists the
  `state_not_read` gap.

The rule reads these coverage counts. A combined verdict reached a result when it is neither `not_evaluated` nor
`error`.

| Field | Type | Meaning |
| --- | --- | --- |
| `assertions_required` | object | `value`, how many assertions the stage was required to evaluate; `origin` (`project_files` or `server_pinned`); and `required_assertion_digest`, the digest of that set (see the key rules). |
| `assertions_evaluated` | integer | How many required assertions reached a result, including one that ran and found no subject in scope (`not_applicable`). |
| `subjects_evaluated` | integer | How many distinct subjects some required assertion reached a result about. |
| `subjects_per_assertion` | object | For each required assertion the stage has events for, keyed `<id>@<version>`, how many distinct subjects it was evaluated about: 0 when it found no subject in scope. A required assertion with no event has no entry. A stage counts subjects only for the assertions it was required to evaluate, so a post-verify stage counts none for the checks it settles: "the plan stage counts subjects only for the assertions it was required to evaluate" (with the stage). |
| `failed_checks_excepted` | integer | How many failed checks, each one assertion about one subject, a [served exception](#a-stage-that-applies-served-exceptions) covers in full: every `fail` event of the check is one of the stage's `served_exceptions.excepted_failures`, and every other event of it is `pass` or `not_applicable`. At most the `fail` count of `status_counts`. 0 at a stage that applies no served exceptions. |

The integrity checks recompute the three counts from the stage's events, where a stage's required assertions are its
assertions less those a `post_verify` stage evaluates to settle [postponed
checks](#checks-postponed-until-after-the-deployment) (`iltero_schemas.models.common.stage_counts.evaluated_counts`). A
count that differs is reported at `stages.<stage>.coverage`: "does not count the assertions and subjects the stage's
evaluations reached a result for, or the subjects each required assertion was evaluated about".

A verdict has these fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `value` | string | `met`, `not_met`, `undecided` or `incomplete` (see the table below). |
| `reason` | string or null | For an `incomplete` verdict, why the stage could not make every required check: `not_evaluated` or `evaluator_failed`. For a `not_met` verdict whose every failed check a served exception covers in full, `every_failure_excepted`. `null` otherwise. |
| `computed_from` | string | `status_counts` for a stage's verdict, taken from its own counts. `stage_precedence` for the record's, taken from one of its stages. |
| `stage` | stage or null | The stage the record's verdict was taken from. `null` for a stage's own verdict. |

A stage's verdict follows from its own coverage. The first row that holds gives it:

| `value` | `reason` | When |
| --- | --- | --- |
| `not_met` | `null` | A required check failed that no served exception covers in full: the `fail` count of `status_counts` is more than `failed_checks_excepted`. |
| `incomplete` | `not_evaluated` | The stage did not make every required check: a required assertion has no evaluation, a required check is `not_evaluated`, or the list of evaluations was cut short (`truncated.value` is `true`). Or it lists the `state_not_read` gap. |
| `incomplete` | `evaluator_failed` | An evaluation ended in an evaluator error: `status_counts` counts at least one `error`. |
| `undecided` | `null` | A required check could not be decided: the stage left more checks `unknown` than its `checked_after_deployment` gaps count. |
| `not_met` | `every_failure_excepted` | Required checks failed, and served exceptions cover every one in full: `status_counts` counts at least one `fail`, and `failed_checks_excepted` counts them all. |
| `met` | `null` | Every required check passed, did not apply, or was postponed until after the deployment. |

A `met` stage includes three cases a reader should know about. A stage none of whose required assertions found a subject
in scope, and a stage that was required to evaluate no assertion, are `met`, and each lists its own evidence reason
(`no_resource_in_scope_for_any_check`, `no_assertion_required`). The first is listed only when no required assertion
found a subject: one assertion that does not apply to the plan, beside others that do, is not a gap. A check postponed
until after the deployment counts as decided later, not undecided: the plan stage lists it in `postponed_checks`, and
the record lists `checks_postponed_until_after_the_deployment` until a `post_verify` stage settles it.

A `not_met` verdict with `every_failure_excepted` means the failed checks did not pass: their events stay `fail`, and
the stage names each failed result in `served_exceptions.excepted_failures`. A stage gives this reason only when
nothing else is open, so a stage whose failures are all excepted but which left a check undecided, or did not make
every required check, is `undecided` or `incomplete`. These failures are never excepted:

- a failure about a subject with no resource address in the plan, or of a [built-in assertion](#assuranceevent): no
  served exception covers it;
- a failed check that another evaluator left `unknown`, ended in `error` or did not evaluate: it is not covered in
  full, so the stage stays `not_met` with no reason;
- a check postponed until after the deployment that fails at `post_verify`: only the plan stage applies served
  exceptions.

A project's own exception never gives this reason: the result it names stays `not_evaluated` with
`suppressed_in_source` (see [LocalExceptions](#localexceptions)). The reason says nothing about whether an exception
was justified, or about compliance. A tool may let a gate proceed on it; that is the tool's own policy, not a pass.

The record's verdict is the stage verdict that comes first in this ranking (`VERDICT_RANKING`):

1. `not_met`, with no reason;
2. `incomplete`, `not_evaluated`;
3. `incomplete`, `evaluator_failed`;
4. `undecided`;
5. `not_met`, `every_failure_excepted`;
6. `met`.

A failure no exception covers, a check not made and a check not decided, at any stage, are never hidden by another
stage's excepted failures. On a tie, the earliest stage in `expected_stages` wins. The record's verdict keeps that stage's
`value` and `reason`, with `computed_from: stage_precedence` and the stage's name in `stage`. For example, a record
whose plan stage is `met`, whose `pre_deploy` stage is `undecided` and whose `post_deploy` stage is `incomplete` is
`incomplete`, naming `post_deploy`.

A failed check no exception covers is never hidden by a check that was not made, and a check that was not made is
never hidden by a failure. Failures served exceptions cover stay visible whatever the verdict: in the `fail` count of
`status_counts`, in `coverage.failed_checks_excepted` and in `served_exceptions.excepted_failures`. A plan stage with
three failures and one required check not evaluated is `not_met`, and its evidence lists `required_checks_not_evaluated`
with the detail `1 of 15 required checks were not evaluated`.

`VERDICT_RANKING` puts a missing check before an evaluator error, while `GAP_REASON_PRECEDENCE` puts an evaluator
error first. They do different jobs: the first picks the one reason an `incomplete` verdict carries, and the second
only orders the reasons the evidence status lists. Both causes stay visible.

The Iltero CLI turns a verdict into its own process exit code; the record holds no exit code.

An evidence status has these fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `value` | string | `whole`, or `has_gaps` exactly when `reasons` lists at least one reason. |
| `reasons` | list | Every reason the evidence has gaps, at most 60 (`MAX_GAP_REASONS`): sorted by `GAP_REASON_PRECEDENCE`, then, for one reason, in stage order. Each reason and stage is listed once. The first is the leading reason (`EvidenceStatus.leading_reason`); none is hidden behind it. |

Each `reasons` item has these fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `reason` | string | One of the reasons in the table below. |
| `stage` | stage or null | The stage the reason holds for. `null` in a stage's own status. In a record's status, every reason names its stage, except `checks_postponed_until_after_the_deployment`, which holds for the record and names none. |
| `detail` | string | One plain sentence about what was found, 1 to 1,024 characters. |

The reasons, in the order of `GAP_REASON_PRECEDENCE`:

| `reason` | Holds when | `detail` |
| --- | --- | --- |
| `required_policy_evaluation_failed` | An evaluation ended in an evaluator error, even one another evaluator's verdict on the same assertion and subject outweighed. | `<n> of <evaluations> evaluations ended in an evaluator error`, or, when only outweighed errors hold, `evaluator errors outweighed by another evaluator's verdict on the same assertion: <count>` |
| `state_not_read` | The stage lists the `state_not_read` gap: the state after the apply was not read. | `the state after the apply was not read, so no outcome of the apply was held to it` |
| `expected_stage_not_reported` | A record only: an expected stage did not report, though a later expected stage did, such as an approval stage that never ran before the deployment. A stage the run has not reached yet is not listed. | `the <stage> stage did not report, though a later stage did` |
| `required_checks_not_evaluated` | The stage did not make every required check, whatever its verdict. The first that holds gives the detail. | `<n> of <m> required assertions have no evaluation` (fewer `subjects_per_assertion` entries than `assertions_required.value`); `<n> of <m> required checks were not evaluated` (the `not_evaluated` count of the stage's `evaluations`); `the list of evaluations was cut short` |
| `checks_postponed_until_after_the_deployment` | A record only: checks its plan stage postponed were not settled, since no `post_verify` stage has reported. | `1 check postponed until after the deployment was not settled`, or `<count> checks postponed until after the deployment were not settled` |
| `plan_not_complete` | The plan stage lists a `plan_incomplete` gap. | `the plan says it is incomplete` (`value: false`), or `the plan does not say it is complete` (the `not_reported_by_tool` marker) |
| `upstream_state_unavailable` | The stage lists `coverage.substituted_inputs`: it read placeholders for inputs it could not read. | `upstream inputs replaced with placeholders: <count>` |
| `plan_resources_excluded_for_their_identity` | The coverage lists identity gaps: plan resources left out of scope because their identity was redacted or cannot be named (`identity_redacted`, `identity_unnameable`). It does not change the verdict. | `1 plan resource was left out of scope for its identity`, or `<n> plan resources were left out of scope for their identity` |
| `provider_has_no_resource_kinds` | The coverage lists a `provider_has_no_resource_kinds` gap: resources in scope come from a provider with no list of resource kinds, so no kind-scoped check reaches them. It does not change the verdict. | `<count> plan <resource or resources> in scope from <sources> provider <source or sources> with no resource kinds a check can name`, with the sum of the gaps' counts and the number of gaps, such as `3 plan resources in scope from 2 provider sources with no resource kinds a check can name` |
| `provider_source_not_reviewed` | The coverage lists a `provider_source_not_reviewed` gap: resources in scope come from a source other than those the provider's kind table was reviewed against. It does not change the verdict. | `<count> plan <resource or resources> in scope from <sources> provider <source or sources> no reviewed kind table describes`, such as `1 plan resource in scope from 1 provider source no reviewed kind table describes` |
| `no_resource_in_scope_for_any_check` | No required assertion had a subject in scope: every `subjects_per_assertion` entry is 0. Listed only when none had one. | `no required assertion had a subject in scope` |
| `no_assertion_required` | The stage was required to evaluate no assertion: `assertions_required.value` is 0. | `the stage was required to evaluate no assertion` |

A record's evidence status lists every reason of every stage, each naming its stage, and the two reasons only a record
holds (`iltero_schemas.models.common.record_coverage.record_evidence_status`). For example, a record of a run Iltero
Platform opened whose `plan`, `post_deploy` and `post_verify` stages reported without its `pre_deploy` stage is
`has_gaps` with `expected_stage_not_reported` for `pre_deploy`. Every cause also stays in the stage's `coverage`: its
gaps, its substituted inputs and its counts.

A reader reads the verdict and the evidence status together. Only an evaluator error, a state not read and a required
check not made can change the verdict, and the evidence status lists them even when a failure makes the verdict
`not_met`. Every other reason leaves the verdict as the checks gave it: a stage that read placeholders can be `met`,
which is a verdict on the placeholder plan, not on the change, and its evidence lists `upstream_state_unavailable`. A
record whose evidence is `whole` can still be waiting for later stages (`all_expected_stages_reported` is `false`).

| Rule | Refused with |
| --- | --- |
| A verdict names a `reason` exactly when its `value` is `incomplete`, or `not_met` with every failure excepted: its `value` and `reason` are one row of `VERDICT_RANKING`. | "a verdict names its reason exactly when it is incomplete, or not_met with every failure excepted" |
| `failed_checks_excepted` is at most the `fail` count of `status_counts`. | "a stage counts no more failed checks as excepted than it has failed checks" |
| A stage that applies no served exceptions (`served_exceptions: null`) counts no failure as excepted. | "a stage that applies no served exceptions counts no failure as excepted" |
| A stage's `failed_checks_excepted` is what `iltero_schemas.models.common.verdicts.excepted_failure_count` gives for its events and its `excepted_failures`, an integrity check. | "does not count the failed checks the exceptions the stage names cover in full" at `stages.<stage>.coverage` |
| A verdict names a `stage` exactly when `computed_from` is `stage_precedence`. | "a verdict names its stage exactly when it was taken from a stage" |
| The evidence `has_gaps` exactly when `reasons` is not empty. | "the evidence has gaps exactly when the status lists a reason" |
| `reasons` follow `GAP_REASON_PRECEDENCE`. | "the reasons are in the order of GAP_REASON_PRECEDENCE" |
| Each reason is listed once per stage. | "each reason is listed once for each stage it holds for" |
| A stage's verdict is the one its counts give, an integrity check. | "is not the verdict the stage's counts give" at `stages.<stage>.verdict` |
| A stage's evidence status is the one its counts give, an integrity check. | "is not the status the stage's counts give" at `stages.<stage>.evidence_status` |
| The record's `coverage`, `verdict` and `evidence_status` are what `record_outcome` gives, an integrity check. | "is not the record's stages combined" at the field |
| `all_expected_stages_reported` is `true` exactly when the stages that reported are the expected stages. | "all_expected_stages_reported is true exactly when every expected stage has reported" |

### Each evaluator's own counts

A stage's `coverage.evaluator_status_counts` counts each evaluator's own results before they
[combine](#how-evaluators-combine), keyed by engine: `opa`, `checkov`, `trivy`, or `none` for evaluations no evaluator
ran, such as `no_subject_in_scope`, `evaluator_unavailable` and `no_scanner_report`. `none` is not an evaluator. Each
value names every status with a count, one per assertion and subject the evaluator evaluated, so the counts add up to
the stage's events (`events.count`), not to `evaluations`. A member of a scanner requirement that gave no report is
counted under its own name, as `not_evaluated` (`scanner_not_run`). An engine that gave no evaluation is not listed,
and a stage with no events has `{}`. The record's coverage sums each evaluator over the stages that name it.

- **Model:** `iltero_schemas.models.common.coverage.Coverage`
- **Function:** `iltero_schemas.models.common.stage_counts.evaluator_status_counts(events)` gives the counts for a
  stage's events. A writer uses it, and the integrity checks recompute the counts with it.

Read these counts with care:

- The verdict reads only `status_counts`. These counts decide nothing.
- An unmet scanner requirement cancels other evaluators' passes, so an evaluator's own passes can sit beside a combined
  `pass` count of 0 (see the example in [How evaluators combine](#how-evaluators-combine)).
- A scanner's counts are the results of its report as the stage kept it, not Iltero's own finding.
- In a stage whose list of evaluations was cut short (`truncated.value: true`), an evaluator that is not listed may
  still have run.
- The `not_evaluated` and `error` counts include the evaluations behind the stage's `evaluator_did_not_decide` gaps.
  Do not add the two together.

| Rule | Refused with |
| --- | --- |
| Each evaluator's counts name every status. | "each evaluator's status counts name every status: pass, fail, unknown, not_applicable, not_evaluated, error" |
| An evaluator is listed only when it gave an evaluation. | "an evaluator's status counts are listed only for an evaluator that gave an evaluation" |
| Each key is a known engine. | The key's type, with a message that contains "Input should be 'opa' or 'none'" |
| A stage's counts are what `evaluator_status_counts` gives for its events, an integrity check. | "does not count, for each evaluator, the statuses of the evaluations it gave" at `stages.<stage>.coverage` |
| The record's counts are each evaluator's summed over the stages that name it, an integrity check. | "is not the record's stages combined" at `coverage` |

### Evaluations from a scanner's results

A scanner, such as Checkov or Trivy, is a program of its own: the pipeline runs it, or the Iltero CLI runs it on the
runner (the report's `ran_by`). The plan stage of
an `iac_change` keeps, for each scanner report it was given, the report in the contract's kept form (see [The report a
stage keeps](#the-report-a-stage-keeps)), the [ScannerObservations](#scannerobservations) it read from it, and the plan
it evaluated, and it keeps a copy of each [scanner check mapping](#scannercheckmapping) it applied. For each assertion a
mapping maps that the stage evaluates, and each of that assertion's scanner checks entries whose tool's report the stage
kept, the stage gives every subject in scope one evaluation from that scanner's results, beside the assertion's own
evaluation when it has a rule. The stage's verdict for the assertion and subject [combines](#how-evaluators-combine)
them. The subjects in scope are the ones the stage's events name and, for an assertion that only scanners decide, every
managed resource of the plan of one of the target's resource types that the plan does not delete or forget and that the
stage's coverage does not exclude for its identity or as one that creates no object outside the tool
(`identity_redacted`, `identity_unnameable` or `makes_no_outside_object` in `coverage.subjects_in_scope.excluded`,
matched by `plan_index`; `iltero_schemas.models.iac.scanner_scope.plan_scope`). A
[deposed object](#deposed-objects-terraform) shares the address of the live resource that replaces it, so only the live
resource gives the paths the plan knows only after the deployment.

By default a scanner check mapping is a lookup table, never a requirement: a scanner whose report the stage was not
given adds no evaluation, and a check mapped nowhere is kept in the observations as evidence, never turned into a
verdict. An assertion that only scanners decide, for which no report the stage was given has mapped checks, is
`not_evaluated` with `no_scanner_report`.

A scanner requirement (`scanners.scanner_requirements`) makes a missing report a gap. Each member of a scanner
requirement whose report the stage was not given gives each subject its mapped checks cover, the same subjects in scope
as for a kept report, one evaluation: `not_evaluated` with `scanner_not_run`
(`iltero_schemas.models.common.scanner_evaluator.SCANNER_NOT_RUN`), even when another member of its group met it. Its
evaluator names the scanner with `version: null`, its `provenance.input_digest` is `null`, it names no result address,
unknown path or failed check, all its `rule_ids` are undecided, and it names its `scanner_checks`. It is that member's
gap when its group [combines](#how-evaluators-combine). Beside a group another member met, it is an evaluation that
could not decide, like any other, listed as an `evaluator_did_not_decide` gap where the combined verdict does not
already count it.

#### The report a stage keeps

A stage keeps each scanner report in the contract's kept form: a new document that holds only the fields the tool's
reader reads, plus each check's title and severity and, for Checkov, the reason the scanned source gives for skipping
a check. `iltero_schemas.models.iac.scanner_reports.readers.kept_report(tool, report)` gives it, through the tool's
`kept_checkov` or `kept_trivy`, which `SCANNER_REPORT_READERS` registers beside the tool's reader. The kept form reads
into the same observations as the whole report. It keeps no field that holds the plan's values, file paths, source
lines, secrets or rendered source.

| Tool | Fields kept |
| --- | --- |
| `checkov` | For each framework (the report, or each entry of a list of them): `check_type`; of `summary`, only `checkov_version` and the counts `parsing_errors`, `passed`, `failed` and `skipped` (not `resource_count`); and, of `results`, only `passed_checks`, `failed_checks` and `skipped_checks`. For each of their results: `check_id`, `check_name`, `severity`, `resource_address`, `resource`, `check_result.result`, `check_result.evaluated_keys`, `check_result.suppress_comment` and `connected_node.resource_address`. A summary with no framework (see [ScannerObservations](#scannerobservations)) is kept as it is: its five counts and `checkov_version`. |
| `trivy` | `Trivy.Version`, and for each entry of `Results`: `Type`, and for each entry of its `Misconfigurations`: `ID`, `Title`, `Severity`, `Status` and `CauseMetadata.Resource`. |

A kept field holds its value only when the value has the kind the reader reads:

- A string or `null` is kept as written, and so is an integer for each count of a Checkov `summary` and a list of
  strings for `evaluated_keys`.
- A whole redaction marker (`iltero_schemas.models.common.redaction.RedactedMarker`, checked by `is_redaction_marker`)
  is kept as written, wherever it stands in place of a kept value, an object, a list or a name in `evaluated_keys`. A
  stage keeps a report in its kept form and then redacts it, so a kept and redacted report is its own kept form. The
  reader refuses most markers in place of an object or a list (see [Hidden objects, lists and
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
written (`terraform`), is not text, or names no input a scanner checks entry reads, such as a secrets or Dockerfile
scan. Each such result keeps only its `check_result` and `connected_node`, each as written when it is `null` or a
redaction marker and as its truth when it is not an object. An object `check_result` keeps only its `evaluated_keys`, as
its truth; an object `connected_node` is kept as `{}`. A result that is not an object is kept as `null` when it is
`null` and as its truth otherwise. That is just enough for the kept framework to be counted, and read, the same way as
the one given.

The evidence register entry of a kept report names, in `source`, the file the pipeline gave, whole: by its keyed digest
in a run the server opened, and by its name alone in a run the tool opened (see [Given file digests](#given-file-digests)).

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
`iltero_schemas.models.iac.plan_relations.plan_configures`). Only results of the entry's `input_kind` count. For a
scanner version the entry's `tool_version_constraint` does not admit, every subject is `not_evaluated` with
`scanner_version_not_allowed`.

Next, the stage asks whether the report says anything about the entry's checks, for a report it read in full: no
`unreadable_results`, no `tool_parsing_errors` and no `results_not_listed`
([`ScannerObservations.read_in_full`](#scannerobservations)). A report the stage could not read in full falls to the
rows below, which give `unknown` with `scanner_report_incomplete`.

- For a tool that names a resource only when a check fails (`trivy`, `REPORTS_ONLY_FAILURES`), a report that holds no
  result, passed, failed or skipped, of any check the entry names, of the entry's `input_kind`, says nothing about any
  subject of the entry. Every subject is `not_evaluated` with `no_result_of_the_mapped_checks`
  (`iltero_schemas.models.common.scanner_evaluator.NO_RESULT_OF_THE_MAPPED_CHECKS`). When this leaves Trivy's scanner
  requirement unmet, since no other member read the input, it cancels every pass and `not_applicable` beside it, so a
  check no other evaluator failed or left unknown is not evaluated, and the stage's evidence lists
  `required_checks_not_evaluated`. Trivy's silence about one subject
  therefore depends on the rest of the report: when it holds any result of the entry's checks, even a pass about no
  resource, the subject is `not_evaluated` with `tool_reports_only_failures`, which cancels nothing.
- For a tool that reports passes (`checkov`), a report read in full that holds no result at all (no `results` and no
  `written_configuration_results`, such as Checkov's summary with no framework) shows the tool checked nothing. Every
  subject is `not_evaluated` with `no_result_in_the_report`
  (`iltero_schemas.models.common.scanner_evaluator.NO_RESULT_IN_THE_REPORT`), with all its checks undecided. When this
  leaves Checkov's scanner requirement unmet, it cancels every pass and `not_applicable` beside it, as for Trivy above;
  for a Checkov no group names, or whose group another member met, it cancels nothing, so another evaluator's pass
  stands and the stage lists an [`evaluator_did_not_decide` gap](#change-assurance-record-car) for `checkov` with
  `no_result_in_the_report`. A Checkov report that holds results about other resources leaves a subject it is silent
  about `unknown` with `not_reported_by_tool`. A Checkov report run with `--quiet` whose checks all passed lists no
  result but counts its passes, so it is not read in full: every subject is `unknown` with `scanner_report_incomplete`,
  not `no_result_in_the_report`. That reason is not a member's gap, so it cancels nothing, even for a Checkov a scanner
  requirement names: like any `unknown`, it keeps every other evaluator's pass from standing, and a required check it
  leaves `unknown` makes the stage `undecided`, not `incomplete`, unless another check makes it `not_met` or
  `incomplete`.

Otherwise the first row that holds gives the verdict (`iltero_schemas.models.iac.scanner_verdicts.scanner_verdicts`):

| Status | `status_reason` | When |
| --- | --- | --- |
| `fail` | none | A mapped check failed for the subject. |
| `unknown` | `scanner_result_unresolved` | A mapped check failed for an `ambiguous` address the tool writes for the subject: the failure may be about it. |
| `unknown` | `scanner_result_unresolved` | A mapped check failed for no resource of the plan at all: the tool wrote no address (`no_address`), or one the plan does not hold (`not_in_plan`). The failure may be about the subject, so neither a suppression nor a tool's silence explains it. |
| `not_evaluated` | `suppressed_in_source` | The scanned source asked the tool to skip a mapped check for the subject, and nothing else is left open: the stage read the whole report (no `unreadable_results`, `tool_parsing_errors` or `results_not_listed`), no other result about the subject is a word that is not a decision, and every mapped check without a decision is suppressed too or, for a tool that names a resource only when a check fails (`trivy`), has no result. Otherwise the rows below decide. |
| `unknown` | `scanner_report_incomplete` | A mapped check gave a word that is not a decision for the subject. |
| `unknown` | `scanner_report_incomplete` | The report holds results the stage could not read (`unreadable_results`), the tool says it could not parse files (`tool_parsing_errors`), or the tool's summary counts results the report does not list (`results_not_listed`, such as Checkov run with `--quiet`). An unreadable result or an unparsed file may hide a failure; a result counted but not listed is about no resource the report names, so a subject with no listed failure may have passed, been skipped or not been checked. This holds for every tool, before the rows about a check with no result. A failure the report lists still fails its subject, by the first row. |
| `not_evaluated` | `tool_reports_only_failures` | A mapped check has no result for the subject, from a tool that names a resource only when a check fails (`trivy`), and the report holds at least one result of a mapped check. A pass of such a tool that names the subject's resource counts as no result for it. |
| `unknown` | `not_reported_by_tool` | A mapped check has no result for the subject, from a tool that reports passes. |
| `unknown` | `known_after_deploy` | Every mapped check passed, but a key a result read, or a path of the entry's `paths_read`, reaches a value the plan knows only after the deployment. |
| `unknown` | `scanner_result_unresolved` | Every mapped check passed, but a mapped check failed for an `ambiguous` address the tool writes only for other resources, or a passing result about two resources names a second one the stage could not find. |
| `pass` | none | Every mapped check passed for the subject. |

A tool's word is a decision only as `TOOL_DECISIONS` lists it, and a suppressed result is never one.

##### Trivy

Trivy 0.72.0 reads any JSON file with a `format_version` and a `terraform_version` as a plan (`{"Target": ".", "Type":
"terraformplan"}`), and the `terraform show -json` output of an applied state has both. Without
`--include-non-failures`, Trivy lists only failures, so a clean plan leaves no result even when Trivy checked every
resource: its evaluations under the shipped mapping (`ILT.SCANNER_CHECKS.STARTER`, whose Trivy checks are `AWS-0014`,
`AWS-0016`, `AWS-0080`, `AWS-0107` and `AWS-0180`) are then `no_result_of_the_mapped_checks`. With it, Trivy also lists
some checks as passed, about no resource, even when it read no resource: an empty plan and a state file each give the
same 51 such checks, such as `AWS-0019`, `AWS-0056`, `AWS-0123` and `AWS-0140`, and `AZU-` and `GCP-` checks, none of
them in the shipped mapping. No Trivy release up to 0.76.2 writes a passed check with the resource it passed: it writes
one pass per check per input file, about no resource, and a single failure of the check removes that pass. A Trivy pass,
even one that names a resource (an edited report, or a release that changed its output), never decides a subject. It
counts as a result of the entry's check, so the report is not `no_result_of_the_mapped_checks`, and it counts as no
result about the resource it names: a subject Trivy names no failure for is `not_evaluated` with
`tool_reports_only_failures`, with empty `result_addresses`, and a failure about it still fails it. An entry that names
one of those always-listed checks never gets `no_result_of_the_mapped_checks`, so for such an entry the rule shows
nothing about what Trivy read, and a scanner requirement of Trivy then leaves another evaluator's pass standing. For
the shipped mapping, a result of the entry's checks shows that Trivy read a plan with resources those checks cover,
not that it read this plan.

A scanner requirement of Trivy alone (`{"any_of": ["trivy"]}`) means a report from a version the entry allows was given,
holding results of the entry's checks. It never means Trivy passed each resource. Trivy's silence
(`tool_reports_only_failures`) is not a gap. For an assertion only scanners decide, such a group never gives a pass, so
`scanner_requirement_problems` lists the group for each such assertion (see [Change Assurance Record
(CAR)](#change-assurance-record-car)).

The contract reads only Trivy's JSON report (`trivy config --format json`): an object with `Trivy.Version` and a
`Results` list. It does not read SARIF, which writes passes as error-level results, or CycloneDX, which carries no
misconfigurations. Neither has a `Trivy` object, so `read_trivy` refuses both: "the trivy report names no version of
the tool".

#### What the record holds

The model refuses a record that breaks one of these rules
(`iltero_schemas.models.iac.scanner_results.check_scanner_results`):

| Rule | Refused with |
| --- | --- |
| The stage kept a report of the evaluation's scanner, unless the evaluation is `scanner_not_run`. | "the plan stage kept the trivy report an evaluation from trivy's results reads" |
| Only a member of one of the stage's scanner requirements that the stage kept no report of is `scanner_not_run`. | "only a member of a scanner requirement of the plan stage that kept no report of it is scanner_not_run" |
| The evaluation names that report's `report_digest` as its `input_digest`. | "an evaluation from trivy's results names as its input the trivy report the plan stage kept" |
| The evaluator's `version` is the report's `tool_version`. | "an evaluation from trivy's results names the version of trivy that wrote the report the plan stage kept" |
| In a stage where a scanner report names the `platform` it ran on, every report that names a platform and every policy evaluator's `limits.platform` name the same one (`iltero_schemas.models.common.stage_platform.check_one_platform_per_stage`). | "every scanner report and evaluation of the plan stage that names the platform it ran on names the same one" |
| The mapping named as shipped (`origin: shipped`), when the stage applies it, is the one this package ships, `iltero_schemas.scanner_check_mappings.SHIPPED_MAPPING`: the same `id`, `version`, `digest` (`SHIPPED_MAPPING_DIGEST`) and `assertions_mapped`. | "the plan stage's scanner check mapping named as shipped is the one this package ships" |
| A scanner verdict on an assertion from Iltero Platform's bundle (`assertion_source: server_bundle`) needs the served mapping among the stage's scanner check mappings. A reader with the kept files works out the entry that decided it from the stage's kept copy of that mapping. | "a scanner verdict on an assertion from the server's bundle comes from the scanner check mapping the server served" |
| A scanner verdict on an Iltero starter assertion (`assertion_source: contract_starter`) names a scanner checks entry of the shipped mapping (`SHIPPED_SCANNER_CHECKS`), and the shipped mapping maps that assertion (`SHIPPED_MAPPING_ASSERTIONS`). | "a scanner verdict on an Iltero starter assertion comes from a scanner checks entry in the mapping Iltero ships" |
| A scanner verdict on one of the project's own assertions needs a project's mapping among the stage's scanner check mappings, and names no scanner checks entry of the shipped mapping. | "a scanner verdict on one of the project's own assertions comes from a scanner checks entry in the project's own mapping" |

#### The check a reader runs

The scanner check mappings, the observations, the report, the plan, the assertion documents and the policy entries of
rules written by hand are files the record keeps, not part of the record, so the model cannot check them alone.
`iltero_schemas.models.iac.scanner_results.scanner_evidence_problems(car, files)` does, on a record whose structure
holds; a reader calls it through [`kept_file_problems`](#checking-a-record-against-its-kept-files). `files` is a
`KeptFiles` (`iltero_schemas.models.iac.kept_files`), each file as read from its JSON or YAML, except the exceptions
files, the evaluation inputs, the post-verify stage's resource identities document and the served bundle tarballs,
which are given as their bytes, unparsed, so the contract checks their digest and reads them one way for every reader:

| Field | Keyed by |
| --- | --- |
| `scanner_check_mappings` | The `copy_path` of each entry of the stage's `scanners.scanner_check_mappings`. |
| `observations` | Each report's `observations` path. |
| `reports` | Each report's `report_digest`. |
| `plans` | The digest of the plan as the stage kept it, redacted (`ScannerObservations.kept_plan_digest`, the digest of the one plan of the evidence register). |
| `assertions` | The digest of each assertion document (`AssertionRef.digest`), or for a rule written by hand in Rego, of its policy source entry (`digest_of(entry)`). |
| `local_exceptions` | The `digest` of each stage's `scanners.local_exceptions`; each value is the bytes of the stage's copy. Read by [`local_exception_problems`](#a-stage-that-applies-the-file). |
| `served_exceptions` | The `digest` of each stage's `served_exceptions`; each value is the bytes of the stage's copy. Read by [`served_exception_problems`](#checking-the-kept-copy). |
| `inputs` | The digest each evaluation names its input by (`provenance.input_digest`); each value is the bytes of the stage's copy. Read by [`kept_input_problems`](#checking-the-kept-evaluation-inputs). |
| `identities` | The `digest` of the register entry of the resource identities document the post-verify stage kept; each value is the bytes of the stage's copy. Read by [`post_verify_identities_problems`](#checking-the-kept-post-verify-identities). |
| `served_bundles` | The `digest` of the register entry of each served bundle tarball a stage kept; each value is the tarball's bytes. Read by [`served_bundle_problems`](#checking-the-kept-served-bundles). |

For each stage that keeps `scanners`, it reads the copy of each scanner check mapping, then each report's observations,
rebuilt from the kept report and plan by the tool's reader, then every evaluation the mappings and those observations
give, and the `scanner_not_run` evaluation of each member of a scanner requirement that gave no report. When the stage
kept no report, it reads the subjects in scope from the redacted plan its `scanners.redacted_plan` names. It returns
`(where, what)` pairs. Among them:

| Where | What | Meaning |
| --- | --- | --- |
| `stages.<stage>.scanners.scanner_check_mappings.<n>` | "is not given", "is not a scanner check mapping", "does not name its copy's digest", "does not name the copy's id, version and number of assertions mapped", "is a project's mapping in Iltero's namespace, or one that decides an assertion of it" | The copy of the mapping at position `<n>` of the list, counted from 0, does not hold. Every copy that does not hold is listed, and no other problem of the stage. |
| `stages.<stage>.scanners` | "keeps no one plan its scanner reports can be read against" | The evidence register holds no entry at the path `scanners.redacted_plan` names. Reports are read against that entry only. |
| `stages.<stage>.scanners.reports.<index>` | "names observations that are not the ones its report and plan give", "does not count what its observations hold" (`results_read`, `unreadable_results`, `written_configuration_results`, `tool_parsing_errors` or `results_not_listed`), and the other report problems | The observations, the report or the plan do not hold. The report's evaluations are not checked further. |
| `stages.<stage>.scanners.reports.<index>` | "names observations of another report" | The kept observations name another `tool`, `tool_version`, `ran_by`, `configuration_digest`, `report_digest` or `input_kinds` than the report entry. The report's evaluations are not checked further. |
| `stages.<stage>.scanners.reports.<index>` | "keeps more of its scanner's report than the contract keeps" | The kept report is not its own [kept form](#the-report-a-stage-keeps): the canonical bytes of what `kept_report` gives for it are not the report's. |
| `stages.<stage>.scanners.reports.<index>` | "does not count, for each reason, the redacted values the report the stage kept holds" | `redacted_values` is not what `redacted_value_counts` gives for the kept report. It is checked wherever the kept report is checked, after its kept form. |
| `stages.<stage>.coverage.subjects_in_scope.excluded.<n>` | "leaves out a resource for a reason the plan the stage kept does not give" | The plan does not say of the resource at the exclusion's `plan_index` what the exclusion says (`iltero_schemas.models.iac.scanner_scope.exclusion_holds`): the plan has no resource there; the exclusion's `id` is not the address the plan wrote there, when that address is text, or is not `null`, when it is not; or the exclusion's `reason` is not exactly the one the plan gives for that resource, with the types the stage's assertions name (see the order of reasons under `coverage.subjects_in_scope.excluded` in [Change Assurance Record (CAR)](#change-assurance-record-car)). Every exclusion is checked, against the plan the stage kept, for a stage that keeps a scanner report or names a scanner requirement and whose kept files give the document or policy entry of every rule it evaluated. |
| `stages.<stage>.coverage.subjects_in_scope.excluded` | "is not what the plan it counted leaves out" | Every exclusion holds, but the list is not the one `plan_exclusions` gives for the plan the stage kept and the types the stage's assertions name, for example because a resource the plan leaves out is missing. |
| `stages.<stage>.coverage.gaps` | "does not list the provider source gaps the plan it counted gives" | Every exclusion holds, but the stage's provider source gaps are not the ones `provider_source_gaps` gives for the plan the stage kept and the types the stage's assertions name (`iltero_schemas.models.iac.plan_coverage.plan_coverage_problems`). |
| `stages.<stage>.scanners` | "names in a scanner requirement a scanner that gave no report, but the plan it kept is not given" | The stage kept no report, a member of one of its scanner requirements gave none, and its plan is not among the files. |
| `stages.<stage>.scanners` | "keeps a checkov report that gives an evaluation the record lacks" | A subject in scope has no evaluation from that scanner. |
| `stages.<stage>.scanners` | "names trivy in a scanner requirement, and trivy's missing report gives an evaluation the record lacks" | A subject in scope has no `scanner_not_run` evaluation from a member of a scanner requirement that gave no report. |
| `stages.<stage>.scanners` | "maps an assertion at a stage it is not evaluated at" | A scanner checks entry's stage is not one of the assertion's stages. |
| `events.<index>.evaluation` | "is not the verdict its scanner's results give" | The status or reason differs from the verdict above. |
| `events.<index>.evaluation` | "is not evaluated although a kept report decides it" | A `no_scanner_report` evaluation where a kept report has mapped checks. |
| `events.<index>.evaluation` | "is no_scanner_report although its stage names trivy in a scanner requirement" | A `no_scanner_report` evaluation of an assertion to which a member of a scanner requirement that gave no report has mapped checks. |
| `events.<index>.provenance.evaluator` | "does not name the checks, resources and unknown paths its verdict rests on" | `result_addresses`, `unknown_paths`, `failed_rule_ids` or `undecided_rule_ids` differ. |
| `events.<index>.provenance.evaluator` | "names other checks, or another match, than its scanner checks entry" | `rule_ids` or `subject_match` differ from the entry's. |
| `events.<index>.provenance.scanner_checks` | "names no scanner checks entry of its stage's scanner check mappings", "names a scanner checks entry of another assertion", "names a scanner checks entry of another tool or stage", "names another scanner checks entry than its scanner check mappings give it" | The digest does not lead to the scanner checks entry, in any of the stage's scanner check mappings, that decides this assertion, tool and stage. |
| `events.<index>.assertion` | "names an assertion document that is not given" | No valid document with the event's digest, id and version was given, or for a rule written by hand, no policy entry with the event's digest, assertion id, version and stage. Listed for every event of the stage, whatever its result; the stage's exclusions and gaps are then not checked. |
| `events.<index>.assertion` | "is a rule written by hand, which no scanner check mapping maps" | A scanner check mapping maps the event's assertion, but the document the kept files give for it is the policy entry of a rule written by hand in Rego. Listed for each such event of the stage whose document is given. |

The vectors in `scanner_evidence/iac/local_run_scanned/` give the complete list of cases.

#### What these checks establish

Together, the record's rules, `scanner_evidence_problems` and `local_exception_problems` establish that each
evaluation from a scanner's results is the verdict the kept report, read against the kept plan, gives the subject
under the scanner checks entry its stage kept, that every subject in scope has one, and that each suppressed result
names the exception the kept exceptions file gives it. They do not establish:

- that the scanner ran, or that the kept report is what the scanner wrote: the record says who ran it (`ran_by`), and
  the writer redacts and keeps the report;
- that the Iltero CLI ran the scanner, or which program it ran: `ran_by` and the report's `scanner_digest`,
  `platform` and `outbound_network` are the record's own claim, and no reader verifies them. Like the OPA evaluator's
  pinned binary, they are at best claimed by the record. In a run the tool opened, `iltero_cli` claims no more than
  `pipeline`;
- that the scanner read the plan the record names: the report is the record's own claim. Under the shipped
  mapping, a Trivy report with a result of an entry's checks shows only that Trivy read some plan with resources those
  checks cover; for an entry that names a check Trivy lists whatever it read, it shows nothing (see
  [Trivy](#trivy));
- that the scanner version is genuine: it is the version the report states;
- that a Checkov report that checked nothing came from a plan that changes nothing: the summary does not say why
  nothing was checked, so it may come from a run set up wrongly;
- that every check ran: `results_not_listed` is Checkov's own count, and 0 shows only that every result its summary
  counts is listed. A check left out of the run by a command-line filter, such as `--skip-check`, is in neither the
  counts nor the lists;
- that the mapped checks of a scanner check mapping read from a file decide the assertion they are mapped to: such a
  mapping is the project's own word, not this package's;
- that anyone outside the project approved an exception: the exceptions file is the project's own word, naming who
  the project says approved each one;
- that an exception was in force when the scanner ran: it is judged at the stage's `reference_time`, which is only as
  trustworthy as its `source` (a [verification report](#verificationreport)'s `reference_time` property).

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
| A record with postponed checks and no `post_verify` stage has an evidence status that lists `checks_postponed_until_after_the_deployment`, with no stage (`open_postponed_checks` counts them), an integrity check. | "is not the record's stages combined" at `evidence_status` |
| Only `post_verify` keeps a `resource_redaction`, and it keeps one exactly when it settles a check. | "only the post-verify stage redacts values after the apply" and "the post-verify stage reports what it redacted of the values its settling checks read" |

The plan stage's verdict treats its postponed checks as decided later (see [Verdict and evidence
status](#verdict-and-evidence-status)): a postponed check does not make the stage `undecided`.
`postponed_check_problems(car, files)`, with a `KeptFiles`, checks the list against the files the plan stage kept; a
reader calls it through [`kept_file_problems`](#checking-a-record-against-its-kept-files). It lists, at
`stages.plan.postponed_checks.<index>`, each postponed check whose assertion document is not given ("names an assertion
document that is not given") or may not be postponed ("postpones a check whose condition reads what post-verify does
not hold"), and each whose path the kept plan does not leave unknown on the subject's resource ("postpones a check on a
value the plan it kept does not leave unknown"). It needs the one plan the evidence register keeps: without it, it
returns "names checks of a plan the record does not keep" at `stages.plan.postponed_checks`.

### Checking the kept evaluation inputs

An evaluation input is the [AssuranceContext](#assurancecontext) the policy evaluator read for one evaluation. Each
stage keeps every input it evaluated, and each evaluation names its input by `provenance.input_digest`. The model does
not read the inputs. `kept_input_problems(car, inputs)` (`iltero_schemas.models.common.kept_inputs`) does: `inputs`
holds the bytes of each kept input, unparsed, keyed by its digest (`KeptFiles.inputs`). A reader of an `iac_change`
record calls it through [`kept_file_problems`](#checking-a-record-against-its-kept-files). A reader of an
`image_build` or `image_deploy` record calls it directly with the inputs its stages kept, as well as
`iltero_schemas.models.common.stages.integrity_problems`.

For every evaluation that names an input and is not a scanner's (`provenance.scanner_checks` is `null`), it checks that
the input:

- is at most 16 MiB (`MAX_INPUT_BYTES`, 16,777,216 bytes), checked before its digest;
- is kept: given by its digest, and its bytes have that digest;
- is canonical JSON;
- is a valid `AssuranceContext`;
- is about the record's environment: its `organization_scope.environment` equals the record's `subject.environment`,
  the same name and `production` value, or `null` for both;
- is about the record's change: where the input's `change` carries a `digest`, it is the record's `change.digest`;
- carries the apply job's facts its stage kept: where the input carries `apply_job_facts`, its `apply_job_facts` and
  `approvals` equal the stage's `apply_job_facts` and `approvals`;
- names the files the record keeps redacted, or never keeps, in the form of who opened the record's run: the apply
  log's digest in its `deployment`, and the two readings' digests in its `drift_check`, are keyed in a record of a run
  the server opened and `null` in one the tool opened (see [Given file digests](#given-file-digests));
- names the state in the form of who opened the record's run: the state's digest in its `deployment` is keyed in a
  record of a run the server opened, and the digest of the redacted state in one the tool opened (see
  [State digests](#state-digests));
- is about the record's deployment: where the input carries a `deployment`, it equals the record's
  `change.deployment`;
- is about the drift check the post-verify stage counts: where the input carries a `drift_check`, its digest
  (`iltero_schemas.canonical.digest_of`) is the post-verify stage's `coverage.subjects_in_scope.source_digest`;
- names only reports the record's build names: each `tests` and `scans` item matches a `change.reports` entry by
  `file_digest`, the `source.digest` of that entry's file, and by `format`, `image_digest` and `image_digest_source`.

It reads each distinct input once, and returns one `(where, what)` pair at `events.<index>.provenance.input_digest`
for each evaluation whose input fails a check, with the message of the first check it fails:

| What | Constant |
| --- | --- |
| "names an evaluation input larger than an input may be (16777216 bytes)" | `INPUT_TOO_LARGE` |
| "names an evaluation input the stage did not keep, or one whose bytes have another digest" | `INPUT_NOT_GIVEN` |
| "names an evaluation input not kept as canonical JSON" | `INPUT_NOT_CANONICAL` |
| "names a kept file that is not an evaluation input" | `NOT_AN_INPUT` |
| "names an evaluation input about another environment than the record's" | `ANOTHER_ENVIRONMENT` |
| "names an evaluation input about another change than the record's" | `ANOTHER_CHANGE` |
| "names an evaluation input whose apply job's facts or approvals are not the ones its stage kept" | `ANOTHER_APPLY_JOB` |
| "names an evaluation input whose digests of files the record keeps redacted, or never keeps, do not have the form of who opened the run" | `GIVEN_FILE_DIGESTS_OF_ANOTHER_RUN` |
| "names an evaluation input whose state digest does not have the form of who opened the run" | `STATE_DIGEST_OF_ANOTHER_RUN` |
| "names an evaluation input about another deployment than the record's" | `ANOTHER_DEPLOYMENT` |
| "names an evaluation input whose drift check is not the one the post-verify stage counts" | `ANOTHER_DRIFT_CHECK` |
| "names an evaluation input whose re-plan check is not the record's" (a `pre_deploy` input whose `replan_check` is not `change.replan_check`) | `ANOTHER_REPLAN_CHECK` |
| "names an evaluation input that names a test or scan report the record's build does not name" | `REPORT_NOT_KEPT` |

For example, a record of a run Iltero Platform opened whose `subject.environment` is
`{"name": "production", "production": false}` fails `ANOTHER_ENVIRONMENT` at every evaluation whose kept input holds
`{"name": "production", "production": true}`.

### Checking the kept post-verify identities

After the deployment, the post-verify stage of an `iac_change` record reads the deployment's resources back with a
refresh-only plan, the drift check's second reading. It may keep the [resource identities](#resourceidentities) it read
from that plan beside the record. It keeps them only as the evidence register entry named
`post_verify/resource-identities.json` (its `ref_id`, `POST_VERIFY_IDENTITIES_REF_ID`), wherever that entry's path is,
and only a record whose post-verify stage has reported holds an entry of that name. The model refuses any other record
that holds one (`check_post_verify_identities_entry`): "only a record whose post-verify stage has reported keeps a file
where that stage keeps its resource identities". The record never keeps the refresh-only plan, so the document names
the state it read by a [state digest](#state-digests): in a record of a run Iltero Platform opened, the keyed digest of
the plan's bytes; in a record of a run the tool opened, the digest of the plan's `prior_state`, the state the plan read,
as the record's redaction policy leaves it. The model does not read the document.
`post_verify_identities_problems(car, change, files)` (`iltero_schemas.models.iac.post_verify_identities`) does,
with the document's bytes, unparsed, keyed by its register entry's digest (`KeptFiles.identities`). A reader calls it
through [`kept_file_problems`](#checking-a-record-against-its-kept-files). A record whose register holds no such entry
has no problem here.

It checks that the document:

- is kept: given by its register entry's digest, and its bytes have that digest;
- is a JSON document that reads as a valid `ResourceIdentities`;
- is about the record's unit: its `unit` is the record's `unit`;
- was read from a refresh-only plan: `sources.read_from` is `refresh_plan`;
- names no applied plan: `sources.plan` is `null`;
- was read by the tool that applied the deployment: `sources.state.tool` is the record's
  `change.deployment.apply.source.tool`;
- names the state it read in the form of who opened the record's run: `sources.state.digest` is not keyed in a record
  of a run the tool opened, and keyed in one Iltero Platform opened. In a record of a run the tool opened, nothing
  compares `sources.state.digest` with the record: the record keeps neither the refresh-only plan nor a digest of
  either reading;
- in a record of a run Iltero Platform opened, names the drift check's second reading: `sources.state.digest` equals
  `change.drift_check.second_reading_digest`.

It returns one `(where, what)` pair at `evidence_refs.<index>`, the document's register entry, for each check the
document fails. A document that is not given or cannot be read is not checked further, and the second reading is
compared only when the digest has the run's form:

| What | Constant |
| --- | --- |
| "is the post-verify stage's resource identities document, and the files given do not hold it with the digest the entry names" | `IDENTITIES_NOT_GIVEN` |
| "is the post-verify stage's resource identities document, and it is not a resource identities document the contract can read" | `IDENTITIES_NOT_READABLE` |
| "is the post-verify stage's resource identities document, and it is about a unit other than the record's" | `ANOTHER_UNIT` |
| "is the post-verify stage's resource identities document, and it does not say it was read from a refresh-only plan" | `NOT_READ_FROM_A_REFRESH_ONLY_PLAN` |
| "is the post-verify stage's resource identities document, and it names an applied plan, which identities read from a refresh-only plan never name" | `APPLIED_PLAN_NAMED` |
| "is the post-verify stage's resource identities document, and it names a tool other than the one that applied the deployment" | `ANOTHER_TOOL` |
| "is the post-verify stage's resource identities document, and it names the state it read by a keyed digest, where a record of a run the tool opened names it by the digest of the state as its redaction policy leaves it" | `STATE_NAMED_BY_A_KEYED_DIGEST_IN_A_TOOL_RUN` |
| "is the post-verify stage's resource identities document, and it does not name the refresh-only plan it was read from by its keyed digest, as a record of a run the server opened does" | `REFRESH_ONLY_PLAN_NOT_NAMED_BY_A_KEYED_DIGEST` |
| "is the post-verify stage's resource identities document, and the refresh-only plan it names is not the drift check's second reading" | `NOT_THE_SECOND_READING` |

### Checking the kept served bundles

A stage that ran over the bundle Iltero Platform served (`execution.bundle.kind: server`) keeps the bundle's tarball as
an entry of the evidence register. A reader finds the entry by the stage's `execution.bundle.tarball_digest`, taking the
stage's own entry, named `<stage>/bundle.tar.gz` (`SERVED_BUNDLE_REF_ID`), first when stages share one tarball; that
entry, when the register holds one, names the stage's tarball. No check reads the entry's path.
`served_bundle_results(car, bundles, keys, verify)` (`iltero_schemas.models.common.kept_bundles`) checks it, for a
record of any change type, given:

- the kept tarballs, by their register entry's digest (`KeptFiles.served_bundles`);
- the trust set `keys`: `iltero_schemas.trust.SIGNING_KEYS` for a real reader; the conformance vectors use their
  development keys, `iltero_schemas.vectors.vector_signing_keys.vector_signing_keys()`, which no shipped trust set
  holds;
- `verify`, the reader's signature check (`SignatureCheck`): called with a key's SubjectPublicKeyInfo DER bytes, the
  signed bytes and the raw 64-byte `r‖s` signature, it returns whether the ES256 signature verifies. This package holds
  no cryptography, so the reader supplies it, for example over the Python `cryptography` library.

It reads each tarball back with [`read_signed_bundle`](#reading-a-pinned-bundle-back), under the key the stage names. A
tarball it refuses is a problem, never an error. It returns a `ServedBundleResults`: its `problems`, and
`verified_stages`, the stages whose bundle read back under a key the trust set holds and has not revoked, with its
signature verified, its content and allowlist digests the stage's, and every module its events ran held. A reader calls
`served_bundle_problems(car, bundles, keys, verify)`, its problems alone, through
[`kept_file_problems`](#checking-a-record-against-its-kept-files), which takes the same `keys` and `verify`.

It checks that:

- each stage that ran over the served bundle keeps its tarball as an entry with the stage's
  `execution.bundle.tarball_digest`, and the tarball is given with that digest;
- the tarball reads back under the stage's `key_id`: the trust set holds that key, the tarball holds its manifest,
  signatures file and assertion modules only, the manifest's revision is the digest of its metadata, and the signed
  bytes cover exactly its files under that key;
- the key is not revoked (`SigningKey.can_verify`), the signature verifies under it (`verify`), and the content digest
  and the allowlist digest (`execution.bundle.capabilities_digest`) the stage names are the ones the signed manifest
  gives (its `revision`, and `metadata.iltero.capabilities_digest`);
- each event that ran over a served bundle (`provenance.bundle.kind: server`) names its stage's: the same
  `tarball_digest`, `content_digest` and `key_id`, in a stage that ran over a served bundle;
- each such event's assertion is a module of the stage's kept tarball (`<id>.rego`), whose digest is the event's
  `provenance.compiled_digest`. The event model requires an event of a built-in assertion that the policy engine
  evaluated to name its compiled digest; any event here that names none is listed, since no module digest matches it.

It returns one `(where, what)` pair for each check that fails. A tarball that is not kept, not given or not read back
is not checked further:

| Where | What | Constant |
| --- | --- | --- |
| `evidence_refs.<index>` | "is the stage's served bundle entry, and its digest is not the tarball digest the stage names" (the entry named `<stage>/bundle.tar.gz`) | `ANOTHER_TARBALL` |
| `stages.<stage>.execution.bundle` | "names a served bundle, and the evidence register holds no entry with the digest of its tarball" | `BUNDLE_NOT_IN_THE_REGISTER` |
| `evidence_refs.<index>` | "is the stage's served bundle tarball, and the files given do not hold it with the digest the entry names" | `TARBALL_NOT_GIVEN` |
| `evidence_refs.<index>` | "is the stage's served bundle tarball, and the trust set given holds no key with the id the stage names" | `KEY_NOT_IN_THE_TRUST_SET` |
| `evidence_refs.<index>` | "is the stage's served bundle tarball, and the revision its manifest names is not the digest of its metadata" | `REVISION_NOT_THE_METADATA` |
| `evidence_refs.<index>` | "is the stage's served bundle tarball, and the key the stage names is revoked" | `KEY_REVOKED` |
| `evidence_refs.<index>` | "is the stage's served bundle tarball, and its signature does not verify under the key the stage names" | `SIGNATURE_NOT_VALID` |
| `evidence_refs.<index>` | "is the stage's served bundle tarball, and the content digest the stage names is not the one its signed manifest gives" | `ANOTHER_CONTENT_DIGEST` |
| `evidence_refs.<index>` | "is the stage's served bundle tarball, and the allowlist digest the stage names is not the one its signed manifest gives" | `ANOTHER_CAPABILITIES_DIGEST` |
| `evidence_refs.<index>` | "is the stage's served bundle tarball, and the bytes it signed do not cover exactly its files under the key the stage names" | `SIGNATURE_NOT_COVERING_THE_FILES` |
| `evidence_refs.<index>` | "is the stage's served bundle tarball, and it is not a bundle tarball the contract can read" (any other refusal of the bundle reader) | `TARBALL_NOT_READABLE` |
| `events.<index>.provenance.bundle` | "is not the served bundle the stage ran over" | `ANOTHER_BUNDLE` |
| `events.<index>.assertion.id` | "names an assertion that has no module in the stage's kept bundle" | `MODULE_NOT_IN_THE_BUNDLE` |
| `events.<index>.provenance.compiled_digest` | "is not the digest of the module the stage's kept bundle holds for the event's assertion" | `ANOTHER_MODULE` |

### Checking a record against its kept files

The model checks a record's structure and, unless `SKIP_INTEGRITY_CHECKS` is set, every value it can recompute from
the record alone. The rest of what a record claims rests on the files its stages kept.
`kept_file_problems(car, files, keys, verify)` (`iltero_schemas.models.iac.kept_file_problems`) makes every check a
reader makes of a record of any change type, given its kept files, the trust set `keys` its served bundles are read
back under and the reader's signature check `verify` (see [Checking the kept served
bundles](#checking-the-kept-served-bundles)), and returns the `(where, what)` pairs of each, in this order. The plan
digest check, the post-verify identities check and the re-plan recount run for an `iac_change` record only:

| Function | What it works out again |
| --- | --- |
| `iltero_schemas.models.common.stages.integrity_problems(car)` | Every value the record can recompute from itself, such as its digests, counts, verdicts and evidence statuses. |
| `iltero_schemas.models.iac.scanner_results.scanner_evidence_problems(car, files)` | Each scanner verdict (see [The check a reader runs](#the-check-a-reader-runs)). |
| `iltero_schemas.models.iac.exception_evidence.local_exception_problems(car, files)` | Each project exception a suppressed result names (see [A stage that applies the file](#a-stage-that-applies-the-file)). |
| `iltero_schemas.models.iac.exception_evidence.served_exception_problems(car, files)` | The failed results the exceptions Iltero Platform served cover (see [Checking the kept copy](#checking-the-kept-copy)). |
| `iltero_schemas.models.iac.postponed_checks.postponed_check_problems(car, files)` | The checks the plan stage postponed (see [Checks postponed until after the deployment](#checks-postponed-until-after-the-deployment)). |
| `iltero_schemas.models.common.kept_inputs.kept_input_problems(car, files.inputs)` | Each evaluation input, against the record's environment and change (see [Checking the kept evaluation inputs](#checking-the-kept-evaluation-inputs)). |
| `iltero_schemas.models.iac.plan_digests.kept_plan_digest_problems(car, change, files)` | In a record of a change made with an IaC tool, of a run the tool opened, the evaluated plan's and the applied plan's digests, against the redacted plans the record keeps (see [Plan digests](#plan-digests)). |
| `iltero_schemas.models.iac.post_verify_identities.post_verify_identities_problems(car, change, files)` | In a record of a change made with an IaC tool, the resource identities document the post-verify stage kept, against the run and its drift check (see [Checking the kept post-verify identities](#checking-the-kept-post-verify-identities)). |
| `iltero_schemas.models.iac.replan_recount.replan_recount_problems(car, change, files)` | In a record of a change made with an IaC tool, the evaluated side of its re-plan check, against the redacted plan the plan stage kept (see [Recounting the re-plan check](#recounting-the-re-plan-check)). |
| `iltero_schemas.models.common.kept_bundles.served_bundle_problems(car, files.served_bundles, keys, verify)` | The served bundle each stage kept, against the trust set, its signature, the stage and its events (see [Checking the kept served bundles](#checking-the-kept-served-bundles)). |
| `iltero_schemas.redaction.iac.sent_documents.kept_document_redaction_problems(car, files)` | Each document a stage sends with its record, against the record's redaction policy (see [Checking a redacted document](#checking-a-redacted-document)). |

Every reader of a record calls it, on a record whose structure holds
(`iltero_schemas.models.common.stages.check_structure`), read with or without `SKIP_INTEGRITY_CHECKS`, with the
[`KeptFiles`](#the-check-a-reader-runs) its stages kept, its trust set and its signature check. It must not trust the
record while the list holds any problem. An empty list means every check a reader can make holds, a verdict whose every
failure is excepted and the signature of each kept served bundle included. What only
Iltero Platform confirms, such as whether a kept copy is what it served, stays unchecked (see
[What checking offline establishes](#what-checking-offline-establishes)).

`iltero_schemas.models.iac.scanner_event_digests.scanner_event_digests(car, files, stage)` gives the scanner verdicts
one stage decided from files that hold, by event digest. It decides only `stage`, from the files that stage kept: it
returns the problems of `scanner_evidence_problems` and `served_exception_problems` for that stage alone (each takes an
optional `only` stage), and, only when there is none, a `frozenset` of the [`event_digest`](#assuranceevent) of each
event of the stage a scanner decided. Problems in other stages do not affect it. When the stage has any problem it gives
no digest at all, so no scanner verdict of a stage whose files do not hold can be matched. A digest names an event's
content only, not its run: a reader matches it only against events of the same run, unit, stage and attempt as the
record, and counts each digest once. Exceptions from a project's own files are not checked here, since a record of a run
Iltero Platform opened names none. Call it on a record whose structure holds.

### Redaction policy

Redaction hides credentials and other sensitive values in everything a record keeps, such as a plan, a scanner report
or an evaluation input, before the record keeps it. A redaction policy is the set of rules that decides what is
hidden. Each hidden value becomes a [redaction marker](#assurancecontext) that says why it was hidden and what type it
had, so an assertion that reads it is `unknown` rather than silently false. The record writes the policy out in
`redaction_policy` (`iltero_schemas.models.common.redaction.RedactionPolicyDocument`), so a reader rebuilds it and its
digest:

```json
{
  "id": "iltero.redaction",
  "version": "1",
  "additional_paths": ["tags.owner"],
  "exempt_paths": [{"path": "ingress[*].cidr_blocks", "reason": "The network checks read the allowed ranges."}]
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | identifier | `iltero.redaction` (`iltero_schemas.redaction.common.policy.POLICY_ID`). |
| `version` | identifier | `1` (`POLICY_VERSION`): the version of the policy's rules and of `redact`, the function that applies them. |
| `additional_paths` | list | The paths the project hides beyond the built-in rules, each a configured path (see below). At most 64 (`MAX_POLICY_PATHS`), in Unicode code point order, each once. |
| `exempt_paths` | list | The paths the project keeps (`ExemptPathRule`): `path`, a configured path, and `reason`, the project configuration's own words: one line of plain text, 1 to 1024 characters. At most 64, in code point order of their `path`, each path once. |

A configured path names an attribute of a resource, such as `tags.owner` or `ingress[*].cidr_blocks`: names of letters,
digits, `_` and `-`, joined by dots, each optionally followed by `[*]` (any list index) or `[n]` (index `n`), at most
256 characters (`MAX_POLICY_PATH_LENGTH`, `CONFIGURED_PATH_PATTERN`). It applies under each anchor: a path where a
tool's output starts a resource's values, such as a resource's values before and after the change in a plan, or a
value the tool declared sensitive whole, such as a sensitive output's or root variable's value. It matches
a value whose path from the anchor has exactly its steps, and applies nowhere else, such as a plan's configuration
block.

The built-in policy (`iltero_schemas.redaction.common.policy.BUILT_IN_REDACTION_POLICY`) is the rules with no
additional and no exempt path. A project's policy is the built-in policy with its own paths.

The policy's digest is the digest of its whole rule set: every word list, pattern and number its rules read, and its
additional and exempt paths (`RedactionPolicy.as_dict()`, `RedactionPolicy.digest`). The record's `redaction_policy`
holds only the paths; the contract supplies the rest for the record's `version`. Two policies with the same paths have
the same digest, whatever order the project's configuration wrote them in.

| Rule | Refused with |
| --- | --- |
| The record names the policy this contract defines: `id` `iltero.redaction`, `version` `1`. | "the record names a redaction policy this contract does not define: it defines iltero.redaction version 1" |
| Each list is in code point order, each path once. | "the record's redaction policy lists each additional and each exempt path once, in order" |
| Every stage's report and every redacted evidence file names the rebuilt policy's `id`, `version` and `digest`. | "every stage and every redacted evidence file name the redaction policy the record writes out, by its digest" |
| A record of a run Iltero Platform opened (`governance.run_opened_by: server`) exempts no path. | "a record of a run the server opened exempts no path from its redaction policy" |

A record of a run Iltero Platform opened therefore names a policy that holds at least the built-in rules. The
additional paths are the ones the pipeline wrote.

`iltero_schemas.redaction.common.policy` gives the policy in code:

| Name | What it does |
| --- | --- |
| `RedactionPolicy(additional_paths, exempt_paths)` | A policy. It sorts both lists into code point order, and raises `ValueError` when a path is named twice ("a redaction policy names each additional and each exempt path once") or past the limits above. |
| `policy_from_document(document)` | Rebuilds the policy a record writes out, with the first two refusals above. |
| `RedactionPolicy.document()` | The policy as a record writes it out. |
| `RedactionPolicy.identity()` | The `id`, `version` and `digest` a stage's report and an evidence file name. |
| `RedactionPolicy.exempt_reason(path)` | The reason of the first exempt path, in code point order, that matches a path from where a resource's values start, or `None`. |
| `RedactionPolicy.also_exempting(paths)` | The policy with more exempt paths. A build tool uses it for its own metadata file, to keep a list that holds only the ids of the build's secrets, and still checks each id. Those paths hide nothing, so they are never part of the policy a record names. |

`iltero_schemas.redaction.common.apply.redact(tree, marks, policy, *, subject, anchors, known_sensitive)` applies a
policy to a tree and returns a copy of it with its report (`Redacted`); the tree itself is not changed. `marks` are
what the tool itself says about a value (`iltero_schemas.redaction.common.marks.Mark`): that it is sensitive, or known
only after the deployment. `anchors` are the paths where each resource's values start. `known_sensitive` are strings
the tool marked sensitive elsewhere in its output. For a Terraform or OpenTofu plan,
`iltero_schemas.redaction.iac.terraform.plan_marks_and_anchors(plan)` reads the marks and anchors from the plan
itself (see [Terraform marks and anchors](#terraform-marks-and-anchors)).

#### Redaction reasons

A hidden value's reason is one of nine (`iltero_schemas.models.common.redaction.RedactionReason`). The first five are
the tool's own marks (`SensitiveMarkReason`); the last four are the policy's rules (`PolicyRuleReason`).

| Reason | The value |
| --- | --- |
| `declared_sensitive` | The tool declared it sensitive. |
| `provider_configuration` | A setting of a provider's configuration, hidden whatever it looks like. |
| `provisioner_configuration` | A provisioner's settings, hidden whatever they look like. |
| `unplanned_configuration` | The configuration of a resource with no instance in the plan, which has no flags to say which of its values are sensitive. |
| `field_not_read` | A field the reading of a workload does not use, which can hold a container's environment values, its arguments, or text another tool or the container wrote. |
| `sensitive_value_reuse` | A string that equals or holds a string of at least 8 characters (`REUSE_MIN_CHARS`) the tool declared sensitive. Providers copy values, such as a sensitive tag into `tags_all`, without copying the mark. |
| `configured_path` | A value at one of the policy's additional paths. |
| `deny_key` | A value whose key, or the name written beside it, looks like a credential's, or text that assigns one, such as `DB_PASSWORD=...`. |
| `value_shape` | A string with a credential's shape, whatever its key. |

#### The order the rules apply in

`redact` reads the tree from its root. At each value, the first rule that applies decides, and a hidden object or list
is replaced whole:

| Order | When | What redaction does |
| --- | --- | --- |
| 1 | The value is a whole redaction marker or `known_after_deploy` marker. | Keeps it as it is, and never looks inside it. An object that only resembles a marker is read like any other. |
| 2 | The tool marks the value as known only after the deployment. | Writes the `known_after_deploy` marker and lists the path in `unknown`, adding the marker where the tree leaves the value out. A sensitive mark at the same path is still listed in `redacted`. |
| 3 | The tool marks the value as sensitive. | Hides it, with the mark's reason. |
| 4 | The value is a string that holds a string the tool declared sensitive. | Hides it: `sensitive_value_reuse`. |
| 5 | The value sits at an exempt path. | Keeps it and lists the path in `exempted`, with the reason of the first matching exempt path in code point order. The rules below do not apply to it; the values inside an exempted object or list still go through every rule. |
| 6 | The value sits at an additional path. | Hides it: `configured_path`. |
| 7 | Its key, or a name written beside it, looks like a credential's, and the value is a string or holds one; or it is a string that holds `NAME=...` where `NAME` looks like a credential's key. | Hides it: `deny_key`. A number, a boolean or `null` under such a key is kept. |
| 8 | The value is a string with a credential's shape. | Hides it: `value_shape`. |

Nothing a project configures overrides the tool's marks or the reuse of a marked value. When a parent is hidden, the
tool's marks on values inside it are still listed in `redacted`, each with its own reason.

A key looks like a credential's when its words hold a credential word (`password`, `secret`, `token` and the others in
`CREDENTIAL_WORDS`), end in `key` after a word that says whose key it is (`access_key`, `api_key`), or hold `key`
before a word that says how it is written (`key_pem`). A key is split into words at separators and where a lowercase
letter or digit meets an uppercase one; each word is lowercased, loses a trailing number and is made singular. A key
whose last word names something about a credential is not one: `password_length`, `secret_arn`, `token_ttl`
(`IDENTIFIER_WORDS`). A name written beside a value is the name in an object such as
`{"name": "DB_PASSWORD", "value": "..."}`: the pairs are `name` and `value`, `key` and `value`, `optionname` and
`value`, and `parameterkey` and `parametervalue`, compared in lower case (`NAMED_VALUE_PAIRS`). The lists are in
`iltero_schemas.redaction.common.credentials`, and `iltero_schemas.redaction.common.words` gives the tests:
`key_is_denied`, `names_by_value_key`, `assigns_a_credential` and `matching_shape`.

The credential shapes (`VALUE_SHAPES`), found anywhere inside a string:

| Shape | What it matches |
| --- | --- |
| `aws_access_key_id` | `AKIA`, `ASIA`, `ABIA` or `ACCA` followed by 16 uppercase letters or digits. |
| `private_key_block` | `-----BEGIN ... PRIVATE KEY-----`. |
| `jwt` | A JSON Web Token: `eyJ` and three parts of at least 10 token characters joined by dots, where no token character comes before it. |
| `url_credentials` | A URL with a user name and password, `scheme://user:password@`. |
| `github_token` | A GitHub token: `ghp_`, `gho_`, `ghu_`, `ghs_` or `ghr_` and 36 letters or digits, or `github_pat_` and at least 22 more characters. |
| `slack_token` | `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-` or `xoxs-` and at least 10 more characters. |
| `google_api_key` | `AIza` and 35 more characters. |
| `authorization_header` | `Bearer` or `Basic`, in any case, white space and at least 16 token characters. |
| `iltero_token` | `ilt_`, `itk_` or `irt_` and at least 16 more characters. |
| `embedded_assignment` | A credential word, such as `password`, `secret`, `token` or `api_key`, followed by `=` or `:` and a value. |

Every test takes time in proportion to the length of the text it reads. The vector `redaction/policy.json` holds the
built-in policy's whole rule set as canonical bytes, every list and pattern included (see
[Conformance vectors](02-conformance-vectors.md#vector-folders)).

#### Keys shaped like a credential

A marker can stand for a value, never for a key. So an object key that is itself shaped like a credential cannot be
hidden: one that holds a credential shape, or `NAME=...` where `NAME` looks like a credential's key. A key's words
alone never count: `password` is a name, not a secret
(`iltero_schemas.redaction.common.words.key_is_shaped_like_a_credential`).

`redact` refuses such a tree, and a mark on a path through such a key, with `RedactionError`. The message names only
the path to the object that holds the key, never the key: "an object key at tags is shaped like a credential, and no
marker can stand for a key" (`the root` for a key of the tree's root). An object hidden whole is not looked inside, so a
key under it is not refused. `redact` also raises `RedactionError` when one of its lists would pass 1,000,000 paths:
"redaction touched more than the 1000000 paths one report lists".

#### Terraform marks and anchors

`plan_marks_and_anchors(plan)` reads a plan as `terraform show -json` writes it, or as redaction left it: redaction keeps
every flag, key and address it does not hide, so both give the same marks. A section of the wrong shape is read as
absent. A resource of `planned_values` or `prior_state`, child modules included, that names no `sensitive_values` is
refused with `RedactionError`, since Terraform writes the key for every resource: "every resource names its sensitive
values, as the tool writes them; the resource at planned_values.root_module.resources[0] names none". So is one whose
`sensitive_values` holds anything but objects, lists and booleans: "the sensitive values of the resource at
planned_values.root_module.resources[0] hold only objects, lists and booleans". The plan's reader stays lenient about
the other sections, as every reader reads a kept plan again; the state's reader below is strict, since the record keeps
no copy of the state.

`redact_plan` refuses a plan as the tool wrote it, before reading it, when it already holds what only redaction writes:
a digest of the redacted plan could not tell that object from a value redaction hid. A kept, redacted plan holds the
markers redaction wrote and is never checked this way: its readers (`plan_marks_and_anchors`,
`redacted_plan_digest_of_kept`, the check of a redacted document) read it as it is.

| Refused | Message |
| --- | --- |
| An object anywhere in the plan with a `__redacted` or `__unknown` key, whole marker or lookalike (`iltero_schemas.redaction.common.planted_markers.refuse_planted_markers`). | "the plan holds an object at resource_changes[0].change.after.input that a reader could take for a redaction or unknown marker, which only redaction writes"; a path is named up to its first key shaped like a credential ("at or under …"), each key cut to its first 256 characters (`MAX_LISTED_KEY_LENGTH`) |

- **Marks.** `true` in a tree of flags (`before_sensitive`, `after_sensitive`, `sensitive_values`,
  `config_sensitive`) marks the value at that path and everything under it `declared_sensitive`; `after_unknown` and
  `config_unknown` mark it known only after the deployment. Sensitive variables, outputs and module inputs, and the
  configuration's expressions of an attribute the plan flags sensitive in any instance, are `declared_sensitive`.
  Every provider setting is `provider_configuration`, every provisioner's expressions `provisioner_configuration`, and
  every expression of a configured resource with no instance in the plan (`count = 0`, or left out by `-target`)
  `unplanned_configuration`.
- **Anchors.** The `before` and `after` of each entry of `resource_changes`, `resource_drift` and `deferred_changes`,
  each action invocation's `config_values`, and each resource's `values` in `planned_values` and `prior_state`, child
  modules included. Also the `value` of each sensitive output in `planned_values` and `prior_state`, the `before` or
  `after` of an entry of `output_changes` its flags mark in whole or in part, and the `value` of each sensitive root
  variable. Every string inside a value the tool declared sensitive under an anchor, whatever its type, is hidden
  wherever else it appears.

`state_marks_and_anchors(state)` reads a state as `terraform show -json` prints it, with the same walk as a plan's
`prior_state`: each resource's `sensitive_values` marks its `values`, a deposed object (an entry with a `deposed_key`)
by its own flags, child modules included, and each output with `sensitive: true` marks its `value`. The anchors are
each resource's `values` and each sensitive output's `value`. A state is read only in the shape Terraform writes, and
any other is refused with `RedactionError`:

| Refused | Message |
| --- | --- |
| A state that is not an object. | "a state is a JSON object" |
| Another top-level key, named in the message when it is letters, digits and `_`, at most 64 characters, and not shaped like a credential. | "a state holds no top-level key other than format_version, terraform_version, values and checks; it holds resource_changes" |
| `values` not an object, or holding another key, named as a top-level key is. | "the values of a state are an object", "the values of a state hold no key other than root_module and outputs; they hold checks" |
| `outputs` not an object of objects. | "the outputs of a state are an object of outputs, each an object" |
| An output whose `sensitive` is missing or not a boolean. | "every output of a state says whether it is sensitive, true or false" |
| A module that is not an object, `resources` that are not a list of objects, `child_modules` that are not a list. | "the module at values.root_module of the state is an object", "the resources of the module at values.root_module of the state are a list of objects", "the child modules of the module at values.root_module of the state are a list" |
| `sensitive_values` holding anything but objects, lists and booleans, at any depth. | "the sensitive values of the resource at values.root_module.resources[0] hold only objects, lists and booleans" |
| Modules nested deeper than the reader's walk reads. | "the state nests deeper than its reader reads" |
| A resource with no `sensitive_values`. | "every resource names its sensitive values, as the tool writes them; the resource at values.root_module.resources[0] names none" |
| An object anywhere in the state with a `__redacted` or `__unknown` key, whole marker or lookalike, before redaction (`iltero_schemas.redaction.common.planted_markers.refuse_planted_markers`). | "the state holds an object at values.root_module.resources[0].values.input that a reader could take for a redaction or unknown marker, which only redaction writes"; a path is named up to its first key shaped like a credential ("at or under …"), each key cut to its first 256 characters (`MAX_LISTED_KEY_LENGTH`) |

A state with no `values`, or no `terraform_version`, holds nothing and is read as empty. A top-level `checks` is accepted
with any value and never read: `redact_state` drops it before the reader runs (`STATE_KEYS_NOT_READ`), and a key of the
same name deeper in the state is content.

`iltero_schemas.models.iac.tools.terraform.configured_address(address)` gives an address as the configuration writes
it, without instance keys:
`module.a["k"].aws_x.y[0]` gives `module.a.aws_x.y`.

### Checking a redacted document

A reader that receives a redacted document, such as a kept plan or a scanner report, can apply the policy's rules to it
again. `iltero_schemas.redaction.common.problems.redaction_problems(policy, document, *, marks, anchors)` lists each
value a rule would still hide, and each object that holds a key shaped like a credential. A whole redaction or unknown
marker is never looked inside; any other value is read, including one left where the tool flags a value known only after
the deployment, since the unknown marker is what belongs there. It returns `RedactionProblems`:

| Field | Meaning |
| --- | --- |
| `problems` | The first 100 problems (`MAX_LISTED_PROBLEMS`), in path order, then by `at` and `rule`. Each is a `RedactionProblem`: `path`, `at` and `rule`. |
| `count` | How many problems it found in all. |

| `RedactionProblem` field | Meaning |
| --- | --- |
| `path` | The path of the value, or of the object that holds the key. A key on it longer than 256 characters is cut to its first 256 (`MAX_LISTED_KEY_LENGTH`). |
| `at` | `value`: the value at `path` would be hidden. `key`: the object at `path` holds a key shaped like a credential, whose text is never given. |
| `rule` | The reason redaction would give, or `credential_shaped_key` for `at: key`. |

The check never looks inside a whole marker. It lists an object that holds a key shaped like a credential once, and
does not read the values under that key. It raises `RedactionError` for a document nested deeper than 64 levels: "the
tree nests deeper than the 64 levels a check reads".

It applies again the rules that read the document alone (`RECHECKED_RULES`): `configured_path`, `deny_key`,
`value_shape` and `credential_shaped_key`, and the tool's marks the reader of the document's kind gives:
`declared_sensitive`, `provider_configuration`, `provisioner_configuration` and `unplanned_configuration`. It cannot
apply again (`NOT_RECHECKED_REASONS`):

- `sensitive_value_reuse`: a copy of a value the tool marked sensitive. The marked value is no longer in the document,
  so the check cannot know what to look for.
- `field_not_read`: no reader of these documents gives that mark.

It cannot find a key whose text is a secret without a credential's shape, nor a secret no rule recognizes. An empty
result says only that these rules find nothing to hide; it does not prove that the document holds no secret.

For an `iac_change` record, `iltero_schemas.redaction.iac.sent_documents` checks each of the
[files a stage sends with its record](#the-files-a-stage-sends-with-its-record) against the record's
`redaction_policy`, with the marks and anchors the stage redacted it with, read from the document itself
(`document_marks_and_anchors(name, tool, document)`):

| Document | Marks | Anchors |
| --- | --- | --- |
| `redacted_plan` | Those the plan reader of the record's IaC tool gives (`plan_marks_and_anchors` for `terraform`). | Those the same reader gives. |
| `scanner_report` | None. | The report's root, or each item of a report that is a list, as a tool that ran several times writes, such as Checkov once for each framework. |
| `scanner_observations` | None. | None: the observations were read from a report already redacted, so a configured path does not apply to them. |

| Function | What it does |
| --- | --- |
| `sent_document_problems(car, stage, entry, data)` | Checks `data`, received as the register `entry` that `stage` sends. It reads the bytes with [`read_sent_document`](#reading-a-sent-document) and raises its `SentDocumentError`, or "the document is not one the stage sends with its record" for any other entry. It raises `RedactionError` for a document nested too deep, or a plan its tool's reader refuses. Returns `RedactionProblems`. |
| `kept_document_redaction_problems(car, files)` | Checks each sent document `files` holds, and returns `("evidence_refs.<index>", "holds a value or a key the record's redaction policy would hide")` for each one with a problem, `("evidence_refs.<index>", "nests deeper than a check of what its redaction policy would hide reads")` (`NESTS_TOO_DEEP`) for one nested too deep to check or for its tool's reader to read, and `("evidence_refs.<index>", "is a plan whose flags for sensitive values its tool's reader refuses to read")` (`MARKS_NOT_READ`) for a plan its tool's reader refuses, such as one with a resource that names no `sensitive_values`. [`kept_file_problems`](#checking-a-record-against-its-kept-files) calls it. A document `files` does not hold is a problem of the checks that read it. |

Call both on a record whose structure holds (`check_structure`).

### Comparing a re-plan

`iltero_schemas.redaction.iac.replan.replan_differences(tool, evaluated_plan, replan, policy)` compares a re-plan with
the plan the plan stage evaluated, both as the tool wrote them, by the resources each would act on. It is a pure
function and returns `ReplanDifferences`.

What it compares. The tool's reader (`iltero_schemas.models.iac.tools.variants.PLANNED_RESOURCE_READERS`; for
`terraform`, `planned_resources` over `resource_changes`) lists every managed resource change (`mode: managed`)
whose actions are not only `no-op`, and every one that imports (`change.importing` set) or moves (`previous_address`
set) a resource, including resources the plan stage left out of scope. Each is keyed by its address and, for a deposed
object, its deposed key, and compared on the tool's ordered action words (`["delete", "create"]` is not
`["create", "delete"]`), whether it imports and whether it moves. Nothing else is compared: no data source, no output,
no attribute value. A pass says nothing about attribute values, plain or hidden.

| Field | Meaning |
| --- | --- |
| `evaluated_plan_resources`, `replan_resources` | How many resources each plan lists for the comparison. |
| `differences` | Each resource object the two plans do not act on alike (`ReplanDifference`): its `address`, its `deposed_key` (`null` for a current object) and its `difference`: `added`, the re-plan changes a resource the evaluated plan did not change; `removed`, the reverse; `actions_changed`, its actions, its import or its move differ. |
| `evaluated_plan_timestamp`, `replan_timestamp` | The top-level `timestamp` the tool wrote into each plan. |

The differences are sorted: plain addresses first, by address and deposed key (`""` for none); markers after them, by
`difference`, then deposed key, then the position of the resource change in the plan that lists it (the re-plan for
`added`, the evaluated plan otherwise). The first three are the order a re-plan check lists its differences in
(`iltero_schemas.models.iac.replan_check.difference_sort_key`); the position only orders markers that tie on them.
Each difference is the model `ReplanDifference` of the [re-plan check](#the-re-plan-check). Both plans are redacted
by `policy` with `redact_plan`.
An address is the redaction marker when that side's redacted plan hides it, or hides the resource change or the whole
list that holds it, whole (either side for `actions_changed`), or when it holds a string a tool declared sensitive in
either plan (reason `sensitive_value_reuse`; a sensitive string shorter than 8 characters, `REUSE_MIN_CHARS`, is not
looked for). No value, action list or plan copy is
kept, and no redaction report is written for the re-plan.

Refused with `ValueError`:

| Refused | Message |
| --- | --- |
| A tool with no reader. | "no reader of the resource changes a plan would act on for this tool" |
| A plan with no `timestamp`. | "a plan names the time the tool wrote it in its timestamp" |
| `resource_changes` that is not a list. | "the resource changes of a plan are a list" |
| An entry, or its `change`, that is not an object. | "each resource change of a plan, and its change, is an object" |
| An address, mode, previous address, deposed key or action word that is not text. | "a resource change names its address, mode, previous address, deposed key and actions as text" |
| A deposed key other than eight lowercase hexadecimal characters. | "a deposed key is eight lowercase hexadecimal characters" |
| One key twice in one plan. | "a plan names each resource object once" |
| More than 100,000 compared resources in one plan (`MAX_RESOURCES`). | "a plan lists at most 100000 resources it acts on" |
| A plan `redact_plan` refuses, such as one that already holds a redaction or unknown marker. | Its message (see [Terraform marks and anchors](#terraform-marks-and-anchors)) |

### Change types and activities

A change type is the kind of thing a change changes. An activity is one kind of work a single record describes; a
change type is made of one or more activities. A record's `change` is the body of its activity, named by
`change.activity`, and a record of any other activity is refused. The contract knows two change types:

| Change type | What it changes | Activities |
| --- | --- | --- |
| `iac_change` | Infrastructure, through an IaC tool, whichever tool. | `iac_change` |
| `image_release` | A container image, built once and released to environments. | `image_build`: the build of the image. `image_deploy`: the deployment of a built image to one environment. |

`iltero_schemas.models.common.change_type` names them (`IAC_CHANGE_TYPE`, `IAC_CHANGE_ACTIVITY`, `IMAGE_RELEASE_TYPE`,
`IMAGE_BUILD_ACTIVITY`, `IMAGE_DEPLOY_ACTIVITY`), and `CHANGE_TYPE_OF` gives the change type of each activity. Each
activity declares how its records are checked (`iltero_schemas.change_types.ACTIVITIES`, and the change types in
`CHANGE_TYPES`):

| Declaration | `iac_change` (`iltero_schemas.change_types.IAC_CHANGE`) | `image_build` (`iltero_schemas.change_types.IMAGE_BUILD`) | `image_deploy` (`iltero_schemas.change_types.IMAGE_DEPLOY`) |
| --- | --- | --- | --- |
| `run_type` | `change`: a run of a project's unit in an environment. | `build`: a run that builds an artifact, in no environment. | `change`. |
| `stages` | `plan`, `pre_deploy`, `post_deploy`, `post_verify`, in the order they run. A record starts at the first. | `plan` only: the image is produced and checked before any deployment uses it. | `pre_deploy`, `post_deploy`, `post_verify`: the image was checked when it was built, so the record starts where the change is approved. |
| `project_may_leave_out` | `post_verify`: whether a change is approved before its apply is the environment's policy, never the project's. | None. | `post_verify`. |
| `environment_policy_may_leave_out` | `pre_deploy`, `post_verify`. | None. | `post_verify`. |
| `stages_that_need_the_server` | `pre_deploy`: the approvals and the commit review it reads come only from Iltero Platform. | None. | None. |
| `not_supported(record)` | `post_verify` when the record's IaC tool has no drift reader; none for `terraform`. | None. | `post_verify`, whatever the record: the workload may be of a kind no reader reads, such as one a cloud's own service runs. |
| `required_documents` | The record at every stage, and the [resource identities](#resourceidentities) document (`resource_identities`) at `post_deploy` as well. A record whose state after the apply was not read names no identities; the `post_deploy` stage must still keep the document. | The record at `plan`. | The record at every stage. |
| `named_documents(record)` | In a run Iltero Platform opened, for each stage that reads scanner reports, the [files it sends with its record](#the-files-a-stage-sends-with-its-record): `redacted_plan`, `scanner_report` and `scanner_observations`. None for a run the tool opened, or for a record whose stages read no scanner report. | At `plan`, `image_index`, the raw index, only when the change's `index_evidence_ref` names one, by its `ref_id` in `evidence_refs`. A stage never has to keep the build tool's metadata file or the reports. | None. |
| `checked_content` | The record's plan (see [Checked content](#checked-content)). | The record's image. | The record's image. |
| `input_parts_of_the_record(record, stage)` | At `pre_deploy`, `replan_check`: each kept input carries the record's `change.replan_check` (see [Checking the kept evaluation inputs](#checking-the-kept-evaluation-inputs)). | None. | None. |
| `carried_out_matches_checked` | `ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN` at `post_deploy`. | `ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT` at `plan`. | `ILT.IMAGE.DEPLOYMENT.CONTENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE` at `post_deploy`. |
| `always_evaluated` | The five [checks of the apply job](#the-checks-of-the-apply-job) and the [re-plan check](#the-re-plan-check) at `pre_deploy` (`PRE_DEPLOY_BUILT_INS`), `ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN` at `post_deploy`, `ILT.IAC.DEPLOYMENT.DRIFT.NO_DRIFT_AFTER_APPLY` at `post_verify`. | `ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT` at `plan`. | `ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT` at `pre_deploy`, `ILT.IMAGE.DEPLOYMENT.CONTENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE` at `post_deploy`, `ILT.IMAGE.DEPLOYMENT.DRIFT.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE` at `post_verify`. |
| `expected_statuses(record)` | The status each built-in check must have: the five checks of the apply job from the facts the `pre_deploy` stage kept, the re-plan check from those facts and `change.replan_check`, `APPLIED_PLAN_MATCHES_EVALUATED_PLAN` from the deployment, `NO_DRIFT_AFTER_APPLY` from the drift check. | None. | `BUILD_ACCEPTED_FOR_ENVIRONMENT`, `REPORTED_IMAGE_MATCHES_CHECKED_IMAGE` and `RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE` from the record's build, deployment and reading. |
| `enforced_in_advisory_mode` | The five checks of the apply job and the re-plan check. | None. | None. |
| `reads_a_state_after_the_apply` | `True`: its records read the IaC tool's state after the apply, which can go unread (see [When the state after the apply was not read](#apply-with-the-state-not-read)). | `False`. | `False`. |

`required_documents` and `named_documents` name the documents a stage sends Iltero Platform with its record
(`iltero_schemas.change_types.common.activity.DocumentName`): `record`, `resource_identities`, `image_index`,
`redacted_plan`, `scanner_report` and `scanner_observations`. `named_documents` gives, by stage and document, the
`ref_id` of each entry of the evidence register a stage sends beyond the required documents. Every other file a record
names stays in the pipeline's own store, and the record keeps its digest.

`carried_out_matches_checked` is the built-in assertion that checks that what the pipeline carried out matches what was
checked, with the stage it is evaluated at: it ties a record's evaluations to its checked content. No policy leaves it
out. `always_evaluated` lists every built-in assertion of the activity by the stage it belongs to,
`carried_out_matches_checked` among them. Once that stage has reported, as a stage the record expects, the record
evaluates each assertion exactly once, at that stage only, and never as `not_applicable`, since it always has the
stage's one subject, unless `expected_statuses` gives it `not_applicable`:
"ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN is evaluated once, at the post_deploy stage, once it has
reported" and "ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT always applies to the plan stage's one
subject" (the id and stage are the assertion's). A record evaluates no built-in assertion of another activity:
"ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN is a built-in assertion of another activity, not of
image_deploy" (the id and activity are the record's).

#### The files a stage sends with its record

In an `iac_change` record of a run Iltero Platform opened, a stage that reads scanner reports sends, with its record,
the redacted plan the reports were read against, each report as it kept it and the observations it read from each, in
the order the stage lists its reports, each by the `ref_id` of its entry in the evidence register. A run the tool
opened sends none. A later record of the run still names a stage's files; they are sent with the record of that stage.

`iltero_schemas.models.iac.stage_files` finds them in the register: `redacted_plan_entry(car, stage)` gives the entry
at the path the stage's `scanners.redacted_plan` names, or `None`, and `stage_file_entries(car, stage)` gives that
redacted plan, then each report and its observations. The record check calls `check_stage_files(car, tool)` on every
`iac_change` record, whoever opened the run. It refuses a record unless each stage that reads scanner reports names its
redacted plan, keeps one entry of each report, names each file once, and keeps every file as canonical JSON, so a
reader can check the bytes it receives against the entry's digest. A later stage may keep another plan with the same
collector, such as the plan it applied; only the entry `scanners.redacted_plan` names is the stage's redacted plan:

| Rule | Refusal |
| --- | --- |
| The entry `scanners.redacted_plan` names is in the register and was written by the collector of the plan of the record's IaC tool (`collector.tool: terraform_plan`, `iltero_schemas.models.iac.tool_names.PLAN_COLLECTORS`). | "the redacted plan the `<stage>` stage's scanner reports were read against is an entry of the evidence register that the plan's collector wrote" |
| That entry names the `redaction_policy` that ran over it. | "the redacted plan the `<stage>` stage's scanner reports were read against names the redaction policy that ran over it" |
| The register holds one entry of each report the stage kept. | "the `<stage>` stage keeps one entry of its `<tool>` report" |
| No entry is among the stage's files twice, under two names. | "the `<stage>` stage sends each file with its record once, under one name" |
| In a run Iltero Platform opened, the stage's redaction report (`redaction`) lists no `exempted` path, since the files it sends were redacted under that policy. | "the `<stage>` stage of a run the server opened, which reads scanner reports, exempts no path from its redaction policy" |
| The redacted plan, each report and each observations entry are kept as canonical JSON (`canonicalization: RFC8785`). | "the `<stage>` stage keeps the files it sends with its record as canonical JSON (RFC8785)" |

The rule on exempted paths reads only what the record lists: it cannot show that the writer applied the redaction
policy it names. A reader that receives the files checks each one against the record's policy with
[`sent_document_problems`](#checking-a-redacted-document). `resource_redaction` is not checked: only the `post_verify`
stage has one, and that stage reads no scanner report.

#### Reading a sent document

`iltero_schemas.models.common.sent_documents.read_sent_document(data, *, size_bytes, named_digest, limits)` reads the
bytes of a document a stage sends with its record, given the size and digest of the register entry it is sent as and the
limits of its kind (`SentDocumentLimits`: `max_bytes` and `max_values`). It returns the parsed document only if it is
exactly that entry and within its limits. The record a stage sends is read the same way, as its canonical bytes, within
`RECORD_LIMITS`, so a record not in canonical form is refused. It checks, in this order, and raises `SentDocumentError`
with a fixed sentence that never repeats the input:

| Rule | Refused with |
| --- | --- |
| The document is no larger than `max_bytes`. | "the document is larger than documents of its kind may be" |
| Its size and digest are the entry's `size_bytes` and `digest`. | "the document is not the file its register entry names" |
| It nests at most 64 arrays and objects deep (`MAX_JSON_DEPTH`), and its value count is at most `max_values`. Both are read from the bytes before anything is parsed (see below). | "the document nests deeper or holds more values than documents of its kind may" |
| It is strict JSON (each key once, no `NaN`) with a canonical form: no number or string without one, such as an integer of too many digits or a lone surrogate in a key. | "the document is not strict JSON with a canonical form" |
| Its bytes are its own canonical form (RFC 8785). | "the document is not kept as canonical JSON (RFC 8785)" |

The value count is, outside strings, one, plus one for each opening bracket (`[` or `{`) and each comma. It is at
least the number of values, and every reader counts the same: `[[],[]]` counts 5. Reading costs memory by the value,
not by the byte: measured, from about 40 bytes a value for nested lists to about 220 for an object of distinct keys,
against about 20 to 26 bytes a value in the files a stage keeps. The value limit bounds the memory a hostile file can
take.

The limits of the documents a scanning stage sends (`iltero_schemas.models.iac.kept_files.SENT_DOCUMENT_LIMITS`), by
document name, and of the record a stage sends (`iltero_schemas.models.common.sent_documents.RECORD_LIMITS`):

| Document | `max_bytes` | `max_values` |
| --- | --- | --- |
| `redacted_plan` | 6 MiB | 400,000 |
| `scanner_report` | 2 MiB | 120,000 |
| `scanner_observations` | 2 MiB | 120,000 |
| the record | 5 MiB | 300,000 |

All the documents one stage sends besides its record are at most 12 MiB together (`MAX_STAGE_SENT_DOCUMENT_BYTES`). A
record holds about 24 to 29 bytes a value, so a record of 5 MiB holds about 220,000 values. The whole plan of a change
of about a thousand resources, at about 5 KiB and 20 bytes a value per resource, fits the plan's limits; a larger
change's plan is over them. A scanner's report and its observations, at about 24 bytes a value, fill 2 MiB at about
90,000 values.

`iltero_schemas.models.iac.stage_files.sent_documents_within_limits(car, stage)` gives `(sent, over_limit)`: the
`ref_id` of each document the stage sends, in send order (the redacted plan, then each report and its observations),
split into those within the limits and those over one. It decides from the sizes the register names only, so the
writer and every reader decide the same. A document is over when it is larger than its own limit, or when it would take
the documents sent before it past the stage's total. Values are counted only when a document is read
(`read_sent_document`), so a writer reads each document it sends that way first. The stage's scanner verdicts rest on
every file it names, so a document over a limit leaves them resting on a file a reader was not sent. Call it on a
record whose stage files hold (`check_stage_files`).

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
| `replan_check` | object or null | The re-plan check the apply job made (see [The re-plan check](#the-re-plan-check)). Named exactly when the `pre_deploy` stage has reported and its apply job's facts are of a later job; either way when the facts are the unknown marker; `null` otherwise. |

`plan` (`iltero_schemas.change_types.PlanRecord`):

| Field | Type | Meaning |
| --- | --- | --- |
| `digest`, `digest_version` | plan digest, identifier | The plan's digest by its tool's rule, keyed or of the redacted plan (see [Plan digests](#plan-digests)), and the version of the rule its form names. Any other version is refused. |
| `artifact_digest_source` | string | `saved_plan` when the plan was read from a saved plan file, `not_provided` otherwise. |
| `artifact_digest`, `artifact_file_name` | digest, string | The saved plan file's digest, and its file name without its directories. Present exactly when `artifact_digest_source` is `saved_plan`, and `null` when it is `not_provided`. The record keeps the file's digest and name, not the file. |
| `context_digest` | digest | The plan as kept after redaction. The plan stage counts its resources by it, and its redaction report describes it: the plan stage's `redaction.input.digest` is `context_digest`, "the plan stage's redaction report is of the plan the record names". |
| `tool`, `format_version` | string, identifier | The IaC tool that wrote the plan, which is the tool the whole record is about, and the plan's format version. |
| `tool_version`, `complete`, `applyable` | identifier, boolean | What the tool's plan says: its version, and whether the plan is complete and can be applied. Each holds the unknown marker `{"__unknown": true, "reason": "not_reported_by_tool"}` when the plan does not say; `null` is refused. |

A file name that holds `/`, `\`, `:` or a character that looks like a slash or backslash (fullwidth and small forms
included), or that consists only of dots and spaces, is refused: "must be a file name without its directories". The
name is at most 255 UTF-8 bytes as written, with no control character; only the separator and dots-and-spaces checks
use its NFKC (Unicode compatibility) form.

#### The apply job's facts in a record

The `pre_deploy` stage of a record of a run Iltero Platform opened keeps [the apply job's facts](#the-apply-jobs-facts)
its input carried (`iltero_schemas.change_types.iac.apply_job`). When it keeps them, and not the unknown marker:

- A record for a production environment (`subject.environment.production` is `true`) requires an approval of the apply
  job: "a production environment's policy requires an approval of the apply job". An input for a production environment
  is refused the same way.
- They are about the record's run, plan and saved plan file, with the messages of the input's rules above. Which change
  they name is an integrity check: an `accepted_plan_stage_record.change_digest` other than the record's is listed as
  `stages.pre_deploy.apply_job_facts.accepted_plan_stage_record.change_digest`, "is not change.digest".
- The stage keeps the approvals they are counted from, a list or the unknown marker: "the pre-deploy stage that keeps
  the apply job's facts keeps the approvals they are counted from".
- The plan and `pre_deploy` stages take their reference time from Iltero Platform: "a record that keeps the apply job's
  facts takes its plan and pre-deploy times from the server". The plan stage's time is no later than
  `plan_stage_record_accepted_at`: "the plan stage's reference time is no later than the server accepted its record".
  The `pre_deploy` stage's time is no later than `facts_issued_at`: "the pre-deploy stage's reference time is no later
  than the apply job's facts were issued". The plan's age is measured from `plan_stage_record_accepted_at` to
  `facts_issued_at`, the server's two times, not from either reference time.
- Every `pre_deploy` evaluation ran in the CI run of the apply job: its `provenance.executor.ci_run_id` is
  `apply_job.ci_run_id`, "every pre-deploy evaluation ran in the CI run of the apply job the facts name".
- A run that does not plan and apply in one job applies no re-plan: its deployment's `superseded_by` is `null`, "a run
  that does not plan and apply in one job applies no re-plan". An applied plan other than the evaluated one stays a failed
  check of the applied plan.
- The record does not keep `apply_job_timing`. A reader works it out with
  `apply_job_timing(stage.apply_job_facts, stage.approvals)`, the value the stage's kept inputs carried (see [Checking
  the kept evaluation inputs](#checking-the-kept-evaluation-inputs)).

#### The checks of the apply job

Five built-in assertions read [the apply job's facts](#the-apply-jobs-facts) at the `pre_deploy` stage of an
`iac_change` record of a run Iltero Platform opened, each about the stage's change. A record evaluates each exactly once
there (`always_evaluated`), and no exception covers one.

| Assertion | Applies | Passes when |
| --- | --- | --- |
| `ILT.IAC.CHANGE.TIMING.PLAN_AGE_WITHIN_LIMIT` | Always. | `apply_job_timing.plan_age_seconds` is no more than `apply_job_facts.plan_age_limit.seconds`. The age is not measured from either stage's reference time. |
| `ILT.IAC.CHANGE.APPROVAL.APPROVED_AFTER_PLAN_STAGE_RECORD_ACCEPTED` | Unless the run plans and applies in one job, or `approval_requirement.required` is `false`. | No approval of the apply job was given before `plan_stage_record_accepted_at`, and at least one was given at or after it. Only an approval of the apply job itself is counted. |
| `ILT.IAC.CHANGE.CONTENT.RECEIVED_PLAN_FILE_MATCHES_EVALUATED_PLAN_FILE` | Unless the run plans and applies in one job. | The apply job reported the saved plan file the plan stage evaluated, by its digest: `apply_job_facts.received_plan_file_digest`, the digest the pipeline reported, is the evaluated plan's `artifact_digest`. A job that reported none fails. Iltero Platform receives only that digest, never the file: the post-deploy check `ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN` is what shows the file was applied. |
| `ILT.IAC.CHANGE.CONTENT.RENDERED_PLAN_MATCHES_EVALUATED_PLAN` | Unless the run plans and applies in one job. | The plan the apply job reports it rendered from its saved plan file is the evaluated plan: `apply_job_facts.rendered_plan` has the evaluated plan's `digest`, `digest_version` and `tool`. Any difference fails. A job that reported no rendered plan leaves the check `unknown`, with the reason `rendered_plan_not_sent`. |
| `ILT.IAC.CHANGE.CONTENT.EVALUATED_PLAN_IS_PINNED_PLAN` | Always. | `apply_job_facts.pinned_plan_digest` is the evaluated plan's `digest`. |

The order check says only that the apply job was approved at or after `plan_stage_record_accepted_at`, and not before: it
says nothing about the approvals other checks read, such as an approval of the change's digest. Where it is
`not_applicable` because the environment's policy requires no approval of the apply job, the order was not checked, and
the record does not say the job was approved; the facts name the policy version that requires none. A job Iltero
Platform could not identify (`job_not_identified`) is held to every check a later job is.

The rendered-plan check and the saved-plan-file check differ on a job that reported nothing: a saved plan file not
sent fails the saved-plan-file check, while a rendered plan not sent leaves the rendered-plan check `unknown`. The
evaluator answers `unknown` with `path_missing` at `apply_job_facts.rendered_plan.digest`; the program that runs the
evaluation records the reason `rendered_plan_not_sent` from the facts.

`iltero_schemas.change_types.iac.apply_job.apply_job_check_statuses(facts, approvals, plan, artifact_digest)` gives
the status each check has, without an evaluator, and the record holds each event to it (see the integrity checks
above). `plan` is the evaluated plan as a `CheckedPlan`
(`iltero_schemas.models.common.checked_content.checked_plan(digest, digest_version, tool)`): its digest, the version of
the rule that computed it, and its IaC tool. `artifact_digest` is the digest of the saved plan file the plan stage
evaluated, or `None`.

- facts Iltero Platform could not supply make every check `unknown`, and approvals it could not supply make the order
  check `unknown`;
- a rendered plan not sent makes the rendered-plan check `unknown`;
- in a run that plans and applies in one job, the order, saved-plan-file and rendered-plan checks are
  `not_applicable`, and the order check is too where the environment's policy requires no approval of the apply job;
  only then may they be;
- otherwise each check is `pass` or `fail`, as the table says.

An evaluation that ended in an `error` is not compared. The Iltero CLI exits with a failure on any result of these five,
or of the re-plan check, other than `pass` or `not_applicable`, also when the stage runs in `advisory` mode
(`enforced_in_advisory_mode`); the record still accepts the stages after it. As with `enforcement_mode`, the record
states the mode; only the CI job's own result shows what the pipeline did.

#### The re-plan check

In a run Iltero Platform opened that applies in a later job, the pipeline gives the apply job's `pre_deploy` stage a
re-plan it reports it made there against the current state, and the stage compares it with the evaluated plan by the
resources each acts on (see [Comparing a re-plan](#comparing-a-re-plan)). The record names the result as
`change.replan_check` (`ReplanCheck`, in `iltero_schemas.models.iac.replan_check`), or `{"outcome": "not_compared"}`
(`ReplanNotCompared`) when the job compared none: the re-plan or the rendered plan was not given. The `pre_deploy`
inputs carry the same value as `replan_check`.

The comparison is the pipeline's claim. The record keeps neither the re-plan nor the comparison, only this result:
nothing in the record shows the re-plan was made in the apply job, after the approval, or from the current state, and
the re-plan is not tied in time to the approval. The only part a reader can check offline is the evaluated side,
recounted from the redacted plan the plan stage kept (see [Recounting the re-plan
check](#recounting-the-re-plan-check)). A difference whose address the redaction policy hides leaves only its kind and
the count.

| Field | Type | Meaning |
| --- | --- | --- |
| `run_id` | UUID | The record's run. |
| `change_digest` | digest | The record's `change.digest`. |
| `tool`, `tool_version` | string | The IaC tool and the version the re-plan names. |
| `replanned_at` | timestamp | The time the tool wrote into the re-plan, by the clock of the machine that made it. The record compares it only with the `pre_deploy` observation and the apply log, which it takes to be the same machine's clock. |
| `evaluated_plan_resources`, `replan_resources` | integer | How many resources each plan acts on, as `replan_differences` counts them. |
| `differences` | list | The resource objects the two plans do not act on alike (`ReplanDifference`): `address` (or the redaction marker), `deposed_key` (`null` for a current object) and `difference`, `added`, `removed` or `actions_changed`. |
| `differences_count` | integer | The number of `differences`, which an assertion can compare. |

The model refuses:

- differences out of order: "the re-plan's differences list plain addresses first, by address and deposed key, each
  once, and redacted addresses after them, by the kind of difference and deposed key";
- a count other than the list's: "differences_count is the number of differences";
- differences that do not fit the totals: "the re-plan's differences fit its totals: no more added than the re-plan
  acts on, no more removed than the evaluated plan acts on, no more changed than both act on, and both act on the same
  rest";
- a deposed key not in its tool's shape (eight lowercase hexadecimal characters for `terraform`): "a deposed key in
  the re-plan check has its tool's shape".

A record (`iltero_schemas.change_types.iac.replan.check_replan`) refuses:

| Rule | Refused with |
| --- | --- |
| A record names no re-plan check before its `pre_deploy` stage has reported. | "a record names no re-plan check before its pre-deploy stage has reported" |
| A run that does not plan and apply in one job names its re-plan check; one that does names none. Facts that are the unknown marker allow either. | "a run that does not plan and apply in one job names its re-plan check", "a run that plans and applies in one job names no re-plan check" |
| A comparison is of the record's run and its plan's IaC tool. | "the re-plan check is for the record's run and its plan's IaC tool" |
| A comparison was made against the plan the apply job rendered from its saved plan file, and that is the evaluated plan: `apply_job_facts.rendered_plan` has the plan's `digest`, `digest_version` and `tool`. | "a re-plan is compared with the plan the apply job rendered from its saved plan file, which is the evaluated plan" |
| `replanned_at` is no later than the second the `pre_deploy` stage was observed in (at its own precision, as `read_no_later_than` reads it). | "the re-plan was made no later than the second the pre-deploy stage was observed in" |
| At `post_deploy`, `replanned_at` is no later than the apply log's first time. | "the re-plan was made no later than the apply log's first time" |

`replanned_at` is the time the tool wrote into the re-plan, by the clock of the machine that made it. The record
compares it only with the `pre_deploy` observation and the apply log, which it takes to be the same machine's clock, and
never with a time of Iltero Platform's. These two rules bound it from above. Its lower bound, later than the time the
tool wrote into the evaluated plan, is a rule a reader of the record alone never sees: only the
[recount](#recounting-the-re-plan-check) checks it, from the kept plan. A comparison whose
`change_digest` is not `change.digest` is an integrity failure at `change.replan_check.change_digest`: "is not
change.digest". An input that carries a re-plan check is refused unless it is for the input's run, change and IaC tool:
"the input's re-plan check is for its run, its change and its plan's IaC tool".

The built-in assertion `ILT.IAC.CHANGE.CONTENT.REPLAN_HAS_SAME_ACTIONS_AS_EVALUATED_PLAN` reads it, once, at the
`pre_deploy` stage, and no exception covers it:

| Assertion | Applies | Passes when |
| --- | --- | --- |
| `ILT.IAC.CHANGE.CONTENT.REPLAN_HAS_SAME_ACTIONS_AS_EVALUATED_PLAN` | Unless the run plans and applies in one job. | `replan_check.differences_count` is 0. A re-plan not compared leaves it `unknown`, with the reason `replan_not_compared`; facts Iltero Platform could not supply leave it `unknown`. |

The evaluator answers a re-plan not compared with `unknown` and `path_missing` at `replan_check.differences_count`;
the program that runs the evaluation records the reason `replan_not_compared`.
`iltero_schemas.change_types.iac.apply_job.replan_check_status(facts, replan_check)` gives the status without an
evaluator, and the record holds the event to it.

#### Recounting the re-plan check

`iltero_schemas.models.iac.replan_recount.replan_recount_problems(car, change, files)` works out again, from the
redacted plan the plan stage kept (`files.plans`, by its register entry's digest), what a comparison says of the
evaluated side, and returns `(where, what)` pairs. A record that names no comparison has none. In a run the tool
opened, the plan stage's copy is found by value: the copy, of an entry its tool's plan collector wrote naming a
redaction policy, that is the entry's file and whose redacted plan digest is `change.plan.digest`, whatever the
register names it. In a run Iltero Platform opened, whose keyed plan digest no reader recomputes, the recount reads the
plan stage's copy by its register name: the entry the plan collector wrote under the name of its digest (`ref_id`
`sha256-<hex>`, `content_name`), where a plan a later stage keeps is named by its role, such as
`post_deploy/applied-plan`. That name is the only tie to the plan stage.

| Problem | At | What |
| --- | --- | --- |
| The files hold no copy of the plan stage's own, or more than one, or its tool's reader refuses it, such as one with no `timestamp`. | `change.replan_check` | "names a re-plan compared with the evaluated plan, and the files given hold no redacted plan the plan stage kept that a reader can recount it from, so the recount was not made" |
| `replanned_at` is not later than the `timestamp` the tool wrote into the kept plan. | `change.replan_check.replanned_at` | "is not later than the time the tool wrote into the evaluated plan the plan stage kept" |
| `evaluated_plan_resources` is not a count the kept plan allows. | `change.replan_check.evaluated_plan_resources` | "is not the number of resources the evaluated plan the plan stage kept acts on" |
| A plain address named as `removed` or `actions_changed` that the kept plan does not act on. | `change.replan_check.differences.<index>` | "names a resource as removed or changed that the evaluated plan the plan stage kept does not act on" |
| A plain address named as `added` that the kept plan acts on. | `change.replan_check.differences.<index>` | "names a resource as added that the evaluated plan the plan stage kept acts on" |

A resource change whose address, deposed key, mode, actions, import or move a marker stands for may be any of the
resources counted: the count must lie between the changes the kept plan surely acts on and those plus the open ones,
and an address may be one of the open ones. A redaction policy that hides action lists narrows what the recount shows.

#### Deposed objects (Terraform)

A deposed object is an old copy of a resource that a replacement set aside, which the plan lists for deletion. When
the applied plan is the evaluated plan (`deployment.plan.digest` is `plan.digest`), the apply's deposed objects
(`deployment.apply.tool_data.deposed`) are held to what the plan stage excluded
(`coverage.subjects_in_scope.excluded`). The plan names no deposed object's key, so objects at one address are matched
by their count only.

| Rule | Refused with |
| --- | --- |
| At each address, the apply names at least as many deposed objects as the plan stage excluded there as `deposed`. The deposed objects it names beyond those, over all addresses together, number at least the plan stage's `deposed` exclusions whose address was redacted (`id: null`). | "the apply names every deposed object the plan stage left out as deposed" |
| Any more at an address are allowed only up to the plan stage's exclusions for identity (`identity_redacted` or `identity_unnameable`) at that address. The rest, over all addresses together, are allowed only up to the number of its exclusions whose address was redacted (`id: null`) and whose reason is `deposed`, `identity_redacted` or `identity_unnameable`; a `not_managed` or `makes_no_outside_object` exclusion never counts. | "the apply names no deposed object beyond those the plan stage left out as deposed or for its identity" |

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
compares `platform_digests` with the function's result. The plan stage must keep the raw index as its `image_index`
document.

The pipeline keeps a build's files in the run's artifact store, and the record keeps each file's digest in
`evidence_refs`. Iltero never reads the pipeline's own store. The build tool's metadata file and the test and scan
reports are never sent to Iltero Platform; for the attestation, see [The build's attestation](#the-builds-attestation).

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
or `None` when the file names no commit. It reads the file strictly (`iltero_schemas.models.common.strict_json`), as
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
| Every report's `evidence_refs` entry has a `source` (not `null`): the file as the pipeline gave it. A `source.digest` that is neither a `sha256:` nor an `hmac-sha256:` digest is refused by the entry's model. | "a report names the file as the pipeline gave it, in its source" |
| A report is kept as the pipeline gave it, with nothing redacted (`redaction_policy: null`). | "a test or scan report is kept as the pipeline gave it, with nothing redacted" |
| The raw index is kept as the pipeline gave it, with nothing redacted. | "the raw index is kept as the pipeline gave it, so its digest is the image's own" |
| A report nothing redacted is stored as given: its `source.digest` is its `digest`. | "a report, when nothing redacted it, is stored as the pipeline gave it" |
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
| Not plain JSON: a key named twice, `NaN` or another constant, a byte order mark, or bytes that are not UTF-8. | The message of `iltero_schemas.models.common.strict_json`, with "an attestation" or "an in-toto statement" as its subject |
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

A `verified` answer (`iltero_schemas.models.common.server_facts.VerifiedAttestation`) reads its commit, repository and run
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
| Each file's `evidence_refs` entry has a `source`: the file as the pipeline gave it, before redaction. Its `digest` is keyed in a record of a run the server opened and `null` in a record of a run the tool opened (see [Given file digests](#given-file-digests)). | "the pod list read names the file as the pipeline gave it, in its source", or the same for each other file |
| Each file names the redaction policy that ran over it (`redaction_policy` is not `null`). The rule that a record redacts under one policy makes it the record's policy. | "the workload read before the pods were listed names the redaction policy that ran over it", or the same for each other file; a file redacted under another policy: "every stage and every redacted evidence file name the redaction policy the record writes out, by its digest" |
| No file is the tag's metadata file (`image.tag_resolution.read_from_evidence_ref`). | "the workload read before the pods were listed is not the tag's metadata file", or the same for each other file |
| Every container, in `template_containers` or in `containers_read`, whose `image_reference` names `change.image.repository`, in its one spelling, is `compared`. | "a reading compares every container whose image is from the deployed repository" |
| An `image_reference`'s digest is `sha256:` and 64 lower-case hexadecimal characters, its tag is one a registry accepts, and its repository is at most 255 characters and follows the image repository rules. | "an image reference's digest is sha256: and 64 lower-case hexadecimal characters", "an image reference's tag is one a registry accepts", "an image reference's repository is at most 255 characters", or a message of the image repository rules |
| The `pre_deploy` stage evaluates `ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT`, the `post_deploy` stage `ILT.IMAGE.DEPLOYMENT.CONTENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE`, and the `post_verify` stage `ILT.IMAGE.DEPLOYMENT.DRIFT.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE`, each exactly once and never as `not_applicable` (see `always_evaluated` above). | "ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT is evaluated once, at the pre_deploy stage, once it has reported", or the same for the others; a `not_applicable` event: "ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT always applies to the pre_deploy stage's one subject" |
| An `ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT` event that was not evaluated, or that ended in `error`, gives a fault of the evaluator as its reason: `timeout` or `evaluator_unavailable` for `not_evaluated`; `evaluator_crash`, `evaluator_timeout`, `evaluator_memory_limit`, `output_overflow`, `output_contract_violation`, `bundle_verification_failed` or `compile_failure` for `error`, never `adapter_parse_failure` (`iltero_schemas.models.common.event.EVALUATOR_FAULT_REASONS`). | "ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT is not_evaluated only for a fault of the evaluator, never for want of the change or its facts", or the same with `error` |
| On a run the tool opened, any other `ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT` event is `unknown` with `server_facts_unavailable`. | "ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT is unknown with reason server_facts_unavailable on a run the tool opened: only the server accepts a build for the environment" |

The `post_verify` stage's redaction report (`redaction`) describes one input, the drift check (`input.kind:
drift_check`); it does not list what redaction hid in the files the reading was taken from. For each of those files the
record keeps the redaction policy that ran (`redaction_policy`) and the file as read (`source`, with its keyed digest
in a run the server opened), not a list of what was hidden.

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
| `ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT` | The server accepted a build of the image for the environment | At `pre_deploy` (`iltero_schemas.assertions.BUILD_ACCEPTED_FOR_ENVIRONMENT`): `change.build` is not `null`. It fails when Iltero Platform opened the run and accepted no build of the image for the environment (`build: null`), and is `unknown` with `server_facts_unavailable` in a run the tool opened, where `build` is the unknown marker. So the `pre_deploy` stage of an image deploy in a run the tool opened is never `met`: with nothing else wrong, it is `undecided`. Its remediation: "Deploy an image built by a run the server recorded, from a source the environment accepts." |
| `ILT.IMAGE.DEPLOYMENT.CONTENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE` | The image the pipeline reports it deployed is the image the deploy checked | At `post_deploy`: `deployment.repository` equals `change.image.repository`, and `deployment.digest` equals `change.image.digest`. The activity's `carried_out_matches_checked` check (`iltero_schemas.assertions.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE`). |
| `ILT.IMAGE.DEPLOYMENT.DRIFT.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE` | After its rollout finished, every live pod of the workload runs the deployed image, or one of its platform images, in every compared container | At `post_verify` (`iltero_schemas.assertions.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE`): `drift_check.rollout.complete` is `true`; `drift_check.live_pods_read` equals `drift_check.rollout.expected_live_pods`; at least one `template_containers` entry is compared; at least one `containers_read` entry is a compared container of a live pod; and every compared container of a live pod runs `change.image.digest` or one of `change.build.platform_digests`. It fails when the rollout had not finished, when the live pods read are not the number the rollout calls for, when the template compares no container, when no live pod has a compared container (so a workload scaled to zero fails, having no live pod to check), or when the change names an accepted build and a compared container of a live pod runs a digest that is neither the image's nor one of that build's platform digests. It is `unknown` when such a container's `digest` is the `not_reported_by_tool` marker, or when the change names no accepted build (`build` is `null`, or the unknown marker in a run the tool opened) and such a container runs a digest other than the image's, since there is no platform digest to compare it with. A failure decides before an unknown. Iltero Platform recomputes the same status from a record (`iltero_schemas.change_types.image.deploy.running_image_status`). Terminating and finished pods, and containers not compared, never decide it. |

### Checked content

The checked content is what a record's change is about and its evaluations ran on, named by its digest. Every event
names it in `provenance.checked_content`, and an earlier evaluation in `checked_content`, so an evaluation of other
content cannot stand in a record. It has one shape per `kind`: for `iac_change` the plan, for `image_build` and
`image_deploy` the image (`iltero_schemas.models.common.change_type.CHECKED_CONTENT_KIND_OF`).

- **Model:** `iltero_schemas.models.common.checked_content.CheckedContent`, one of `CheckedPlan` and `CheckedImage`

`kind: plan` (`CheckedPlan`):

| Field | Type | Meaning |
| --- | --- | --- |
| `kind` | string | `plan`. |
| `digest` | plan digest | The plan's digest by its tool's rule, keyed or of the redacted plan (see [Plan digests](#plan-digests)). |
| `digest_version` | identifier | The version of the rule the digest's form names. Any other version is refused. |
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

### Plan digests

Plan digests are keyed per run. A plan digest names a plan by a rule for its IaC tool, in one of two forms. The form
follows who opened the run (`governance.run_opened_by`):

| Run opened by | Form | Value | `terraform` `digest_version` | Who computes it |
| --- | --- | --- | --- | --- |
| `server` | Keyed | `hmac-sha256:` and 64 lowercase hex digits: HMAC-SHA-256, under the run's digest key, of the RFC 8785 bytes of `{"rule": "iltero.plan_digest", "tool", "digest_version", "plan"}` (`iltero_schemas.canonical.keyed_plan_digest(tool, plan, key)`). | `1` (`KEYED_PLAN_DIGEST_VERSIONS`) | The Iltero CLI, with the run's digest key. No reader recomputes it, and the same plan has a different digest in each run. |
| `local` | Of the redacted plan | `sha256:` and 64 lowercase hex digits: SHA-256 of the RFC 8785 bytes of `{"rule": "iltero.redacted_plan_digest", "tool", "digest_version", "plan"}`, where `plan` is the plan as the record keeps it, redacted (`iltero_schemas.canonical.redacted_plan_digest_of_kept(tool, kept_plan)`). | `redacted-1` (`REDACTED_PLAN_DIGEST_VERSIONS`) | Any reader, from the redacted plan the record keeps. |

In both forms, `plan` leaves out the tool's top-level keys that describe the rendering rather than the change
(`PLAN_EXCLUDED_TOP_LEVEL_KEYS`). For `terraform`, the plan is as `terraform show -json` prints it, without
`timestamp`, `terraform_version`, `format_version`, `prior_state`, `resource_drift` and `relevant_attributes`. A tool
with no rule is refused. The two tables give distinct versions, so a tool and a version name one rule.

- **The run's digest key.** The server that opened the run gives each stage of the run the same key: `irk_` and 43
  base64url characters, no padding, naming 32 bytes (`RUN_DIGEST_KEY_PATTERN`, `RUN_DIGEST_KEY_BYTES`,
  `RUN_DIGEST_KEY_TEXT_LENGTH`), read with `iltero_schemas.canonical.RunDigestKey.from_text`. Any other text is
  refused: "a run digest key is irk_ and 43 base64url characters naming 32 bytes". No record, evaluation input, event
  or report names the key. The key text is shaped like an Iltero token, so redaction hides it wherever it appears.
- **What a keyed digest shows.** Two keyed digests the Iltero CLI made in one run are equal exactly when their plans,
  without the keys the rule leaves out, are equal. A reader cannot tell which plan a keyed digest names: that it is the
  digest of the plan a stage evaluated is the record's claim. A keyed digest is not a signature. In a run the server
  opened, the saved plan file's `artifact_digest`, when the record names one, is the one plan digest a holder of the
  file recomputes.
- **Redacting a plan.** `iltero_schemas.redaction.iac.plan.redacted_plan_digest(tool, plan, policy)` redacts the plan as
  the tool wrote it and digests the result. Redaction (`redact_plan`) applies the redaction policy and the plan's own
  marks, and hides every copy of a sensitive string. A holder of the plan as `terraform show -json` printed it, with
  the policy the record writes out in `redaction_policy`, computes `redacted_plan_digest` and compares it with
  `change.plan.digest` in a record of a run the tool opened. The kept copy's own bytes match only for the same
  rendering, since it keeps the keys the digest leaves out, such as `timestamp`. A run the tool opened that names no
  saved plan file binds the evaluated and the applied plan by their redacted plans only: two plans that differ only in
  a hidden value have the same digest.
- **Record rules.** Every plan digest a record names (`change.plan.digest`, `change.deployment.plan.digest`,
  `change.identity.sources.plan.digest` and each event's `checked_content` of kind `plan`) is keyed in a record of a
  run the server opened, or the record is refused: "a record of a run the server opened names every plan by its keyed
  digest". In a record of a run the tool opened, none is keyed: "a record of a run the tool opened names every plan by
  the digest of its redacted plan". Each `digest_version` is the version of the rule its digest's form names: "a keyed
  plan digest names the version of the terraform keyed plan digest rule", or "a plan digest that is not keyed names the
  version of the terraform redacted plan digest rule". The apply job's facts name keyed digests only.
- **Checked against the kept plan.** In a record of a run the tool opened, `change.plan.digest` and
  `change.deployment.plan.digest` are each the digest of a redacted plan the record keeps: an entry of the evidence
  register that the plan's collector wrote and that names the redaction policy. Otherwise
  [`kept_file_problems`](#checking-a-record-against-its-kept-files) reports "is not the digest of a redacted plan the
  record keeps, among the files given".

### State digests

A state digest names a state (`StateSource.digest`, a `StateDigest`), as the IaC tool printed it, that the record never
keeps: the state the deployment was held to (`change.deployment.apply.state`, and an input's `deployment`) and the
state the identities were read from (`change.identity.sources.state`, and a [ResourceIdentities](#resourceidentities)
document). It is never `null`. Its form follows who opened the run (`governance.run_opened_by`), and its
`digest_version` names the rule it was made under, read from the table its form selects:

| Run opened by | Form | Value | `terraform` `digest_version` |
| --- | --- | --- | --- |
| `server` | Keyed | The keyed digest of the bytes read (`keyed_given_file_digest`, see [Given file digests](#given-file-digests)): the state, or, for identities read from a refresh-only plan, that plan. | `1` (`KEYED_STATE_DIGEST_VERSIONS`) |
| `local` | Of the redacted state | `sha256:` and 64 lowercase hex digits: SHA-256 of the RFC 8785 bytes of `{"rule": "iltero.redacted_state_digest", "tool", "digest_version", "state"}`, where `state` is the state as the record's redaction policy leaves it, without the tool's excluded top-level keys (`STATE_EXCLUDED_TOP_LEVEL_KEYS`; for `terraform`, `format_version`, `terraform_version` and `checks`). For identities read from a refresh-only plan, the state is that plan's `prior_state`. | `redacted-1` (`REDACTED_STATE_DIGEST_VERSIONS`) |

`iltero_schemas.redaction.iac.state.redacted_state_digest(tool, state, policy)` redacts the state as `terraform show
-json` prints it and digests the result; `redact_state(tool, state, policy)` gives the redacted state, and
`iltero_schemas.canonical.redacted_state_digest_of_kept(tool, redacted_state)` and `canonical_redacted_state_bytes`
the digest and the bytes it is taken of. Redaction applies the policy and the state's own marks
(`STATE_MARK_READERS`, see [Terraform marks and anchors](#terraform-marks-and-anchors)), and hides every copy of a
sensitive string, under the redaction subject `state`. The record keeps neither the state nor a redaction report for
it, so only a holder of the state, with the policy the record writes out, computes the digest again. A state with no
canonical form, such as one holding an integer beyond 2^53 or a number that is not finite, has no digest:
`redact_state` and `redacted_state_digest` raise `CanonicalizationError` ("an integer is outside the range JSON numbers
hold exactly").

- **Version.** A keyed digest names the keyed version, and any other the redacted version, or the state is refused:
  "a keyed state digest names the version of the terraform keyed state digest rule", or "a state digest that is not
  keyed names the version of the terraform redacted state digest rule"
  (`iltero_schemas.canonical.check_state_digest_version(tool, version, state_digest)`).
- **Record rules.** `iltero_schemas.models.iac.state_digests.check_change_state_digest_form(car, change)`, which the
  record's model calls: in a record of a run the server opened, every state is named by its keyed digest, or the
  record is refused: "a record of a run the server opened names every state by its keyed digest". In a record of a run
  the tool opened, none is keyed: "a record of a run the tool opened names every state by the digest of the state as
  its redaction policy leaves it".
- **The identities.** The identities' `sources.state` equals the deployment's `apply.state`, digest and version
  included: "the identities are read from the state the deployment was held to".

### Given file digests

A given file digest (`GivenFileDigest`) names a file the pipeline gave, before the record kept it. Its form follows how
the record keeps the file and who opened the run (`governance.run_opened_by`), and is checked by
`iltero_schemas.models.common.given_file_digests.check_given_file_digest_form(car)`, which the record's model calls.
The digests the change of an infrastructure change names are checked by
`iltero_schemas.models.iac.given_file_digests.check_change_given_file_digest_form(car, change)`. The state, which the
record never keeps, is named by a [state digest](#state-digests) instead:

| How the record keeps the file | Run opened by `server` | Run opened by `local` |
| --- | --- | --- |
| As the pipeline gave it (no `redaction_policy`) | `sha256:`, the entry's own `digest` | The same |
| Redacted (a `redaction_policy`), or never | Keyed: `hmac-sha256:` and 64 lowercase hex digits | `null` |

A keyed given file digest is HMAC-SHA-256, under the run's digest key (see [Plan digests](#plan-digests)), of the RFC
8785 bytes of `{"rule": "iltero.given_file_digest", "sha256": <hex>}`, where `<hex>` is the 64 hex digits of the file's
plain SHA-256 digest (`iltero_schemas.canonical.keyed_given_file_digest(plain_digest, key)`). A plain digest in any
other form is refused: "a given file's plain digest is sha256: and 64 lowercase hexadecimal digits". Only a holder of
the key computes one; a keyed digest shows that two files named in the same run are the same file.

The fields that take a given file digest (`GivenFileDigest`, `sha256:` or `hmac-sha256:`, or `null`):

| Field | Where | The file |
| --- | --- | --- |
| `source.digest` | Each `evidence_refs` entry | The file the entry was kept from |
| `apply.source.digest` | `change.deployment`, and an input's `deployment` | The apply log |
| `first_reading_digest`, `second_reading_digest` | `change.drift_check`, and an input's `drift_check` | Each refresh-only plan of the drift check |

The rules, each refused with its message:

| Rule | Refused with |
| --- | --- |
| In a record of a run the server opened, every given file digest of a file kept redacted, or never kept, is keyed. | "a record of a run the server opened names every file it keeps redacted, or never keeps, by its keyed digest" |
| In a record of a run the tool opened, none of these given file digests is named. | "a record of a run the tool opened names no given file digest of a file it keeps redacted, or never keeps" |
| A file kept with no `redaction_policy` is named by its own `digest`. This holds for the raw index of an image build too. | "a file the record keeps as the pipeline gave it is named by its own digest" |
| The one exception: the copy of a project's scanner check mapping (the entry at a `scanners.scanner_check_mappings[].copy_path` whose `file_path` is set), kept as canonical JSON, is named by the plain digest of the project's file. | "the copy of a project's scanner check mapping is named by the plain digest of the project's file" |

The rules that bind these files, by who opened the run. In a record of a run the server opened, no binding rests on a
`null` digest:

| Binding | Run opened by `server` | Run opened by `local` |
| --- | --- | --- |
| The apply log | The register keeps one entry collected by the apply tool's reader (`APPLY_COLLECTORS`), redacted, whose `source.digest` is `change.deployment.apply.source.digest` | The register keeps that one entry |
| A scanner report and its observations | The report's entries and the observations entry name one file by its `source.name` and one keyed `source.digest` | The report's entries and the observations entry name one file by its `source.name`, and the observations name their report by `report_digest` |
| The drift check's readings | Both keyed, and different | Both `null` |
| An image build's test and scan reports and its raw index | Kept as given, so each named by its own digest; the reports are different files | The same |

A record of a run the tool opened names none of these given file digests. For each file it holds:

| File | What the record holds of it |
| --- | --- |
| The raw plan | The plan redacted, whose digest is the plan digest (see [Plan digests](#plan-digests)) |
| The apply log | The log redacted, in its one apply log entry |
| A scanner report | The report redacted, and the observations read from it, which name it by `report_digest` |
| A Kubernetes reading of an image deploy | The reading redacted |
| The state | The digest of the state as the record's redaction policy leaves it, without the tool's excluded top-level keys (see [State digests](#state-digests)), and the identities read from it. Post-verify compares the resources' addresses, and each resolved resource's cloud identifier, read from the state, with the record's identities. |
| The drift check's readings | Their times (`first_reading_at`, `second_reading_at`, at least `minimum_interval_seconds` apart) and the run they were taken for (`run_id`) |

A drift check names both readings' digests or neither: "the drift check names the digests of both readings, or of
neither". An evaluation input names no `run_opened_by`, so an input on its own takes either form; checked against its
record (see [Checking the kept evaluation inputs](#checking-the-kept-evaluation-inputs)), it takes the record's form.

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
    "digest": "hmac-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
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
| `environment_key` | `subject.environment.name` | `organization_scope.environment.name` | `subject.environment.name` | `organization_scope.environment.name` |
| `checked_content` | `change.plan`'s `digest`, `digest_version` and `tool`, with `kind: plan` | `plan`'s `digest`, `digest_version` and `tool`, with `kind: plan` | `change.image`'s `repository` and `digest`, with `kind: container_image` | `change.image`'s `repository` and `digest`, with `kind: container_image` |

`environment_key` is `null` for a change made outside any environment; a record of a run Iltero Platform opened
always names its environment. An approval of a change binds to this digest, so it counts for that content, in that
unit and environment: a plan that does something else, or the same plan deployed to another environment, is another
change. In a run the server opened, the plan digest is keyed per run, so the change digest is unique to the run.
The digest names no project or organization; Iltero Platform holds an approval to the project it was given
in. A record whose change digest is not this one is an integrity failure: "change.digest is not the digest of the
change type, unit, environment and plan", or "... and image" in an `image_deploy` record. A record that lists an
approval of another change is one too, naming the approval: "stages.pre_deploy.approvals lists approval apr_0001 of
another change: another change type, unit, environment or checked content".

### Units file

A units file is the file in which a project declares its units, in the order they deploy. A record names it as the
writer read it.

- **Model:** `iltero_schemas.models.common.units_file.UnitsFile`

| Field | Type | Meaning |
| --- | --- | --- |
| `path` | string | The file's path in the project. |
| `digest` | digest | The SHA-256 of the file's bytes. |
| `units` | list | 1 to 64 units in deploy order, each a `name`, its `directory` relative to the project's directory (`.` for the project's own directory, `DirectoryPath`), and the units it `depends_on` (`DeclaredUnit`). |

The record's unit's code is in its entry's `directory`. A record with no units file is about the one unit in the
project's own directory. Two units may share a directory, deployed with different settings. Each directory is the
writer's reading of the units file: the contract has no reader of a project's units file, so a reader can only
compare the record's `digest` with the file at the record's commit. The digests also differ when the writer read
uncommitted changes or git converted the file on checkout, such as its line endings, so a mismatch alone does not show
the record is wrong.

A unit name is 1 to 64 lowercase letters, digits, `_` and `-`, not starting with `-`. Rules:

| Rule | Refused with |
| --- | --- |
| Each unit is named once. | "a units file names each unit once" |
| `depends_on` lists at most 64 names, sorted by Unicode code point, each once. | "a unit's dependencies are sorted by name and name each unit once" |
| A unit does not depend on itself. | "a unit does not depend on itself" |
| A unit depends only on units the file declares. | "a unit depends only on units the units file declares" |
| A unit comes after every unit it depends on. | "a unit comes after every unit it depends on, in deploy order" |
| Each unit names its `directory`, by the directory rule (see [Change Assurance Record](#change-assurance-record-car)). | "Field required", or the directory rule's message |

```json
{
  "path": ".iltero/units.json",
  "digest": "sha256:7777777777777777777777777777777777777777777777777777777777777777",
  "units": [
    {"name": "network", "directory": "network", "depends_on": []},
    {"name": "app", "directory": "app", "depends_on": ["network"]}
  ]
}
```

## VerificationReport

A verification report states what a verifier found about one CAR, one property at a time. It is a separate document,
never part of the record.

- **apiVersion:** `iltero.com/v1`, with `kind: VerificationReport`
- **Model:** `iltero_schemas.models.common.verification.VerificationReport`

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion`, `kind` | string | `iltero.com/v1` and `VerificationReport`. |
| `metadata` | object | The `verifier`: `name: iltero` and the verifier's `version`; and `verified_at` (timestamp), when the verifier wrote the report, by its own clock. A result such as a stage still pending holds at that time. |
| `record` | object | The record's `uuid` (its `metadata.uuid`), and the `digest` of the record's canonical JSON as the verifier read it: its document digest. |
| `properties` | object | Nineteen properties, each a result (`PropertyResult`) with a `state`, a `reason` and a `detail`. |

Each result has three fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `state` | string | One of the six states below. |
| `reason` | string or null | A short name for why the property has its state, or `null` when there is nothing to name. |
| `detail` | string or null | A plain sentence about what the verifier found, 1 to 1024 characters (`RESULT_DETAIL_MAX_LENGTH`), with no control character, or `null` when there is nothing to add. |

A `detail` never changes what a state means and never makes a result stronger than its state. It is for people to read:
a reader must not parse it.

| Property | What `verified` would mean |
| --- | --- |
| `integrity` | The record's structure and signature are valid, and the evidence it cites is unchanged. |
| `source_identity` | The repository, commit and pipeline came from an authenticated source. |
| `approval_identity` | Every approval came from an authenticated identity. |
| `bundle_provenance` | The evaluations ran from a bundle signed by an authorized key that was not revoked. |
| `stage_completeness` | Every required stage is present, and every required evaluation has a result or is listed as not evaluated. |
| `plan_apply_match` | The plan the record says was evaluated is the plan it says was applied. |
| `runtime_verification` | A verification after the deployment ran. |
| `deployment_coverage` | No deployment visible to the verifier is missing a record. |
| `exceptions` | Every exception relied on was approved and in force at the reference time of the stage that relied on it. |
| `commit_review` | Every commit the change ships was reviewed. |
| `reference_time` | Every stage took its reference time, which every expiry and ordering comparison uses, from a source a verifier can trust. |
| `evaluator_binary` | Every evaluation ran on the binary of the Open Policy Agent (OPA) release this contract pins, for its platform. |
| `scanner_reports` | Every scanner result the record states comes from a report of the pinned scanner Iltero Platform required, run on the plan the record evaluated. |
| `plan_age` | No more than the limit passed between Iltero Platform receiving the plan-stage record that counts and issuing the apply job's facts. |
| `apply_job_approval_order` | The apply job was approved at or after `plan_stage_record_accepted_at`, when Iltero Platform received the plan-stage record that counts, and not before. |
| `received_plan_file` | The apply job reported, by its digest, the saved plan file the plan stage evaluated. |
| `rendered_plan` | The plan the apply job reports it rendered from its saved plan file is the evaluated plan. |
| `pinned_plan` | The evaluated plan is the plan Iltero Platform holds the run to. |
| `replan_resource_actions` | The re-plan the pipeline reports from the apply job acts on the same resources, with the same actions, as the evaluated plan. |

For the last six, about the job that applies an infrastructure change, no result is `verified` or can be: the facts are
Iltero Platform's word as the pre-deploy stage kept them, and the re-plan is the pipeline's. The best result is
`claimed_by_record`.

| State | Meaning |
| --- | --- |
| `verified` | Checked, and it holds. |
| `failed` | Checked, and it does not hold. |
| `could_not_decide` | Examined, but the verifier could not decide. |
| `not_assessed` | Not assessed for this record. |
| `not_performed` | The record shows the step did not happen. |
| `claimed_by_record` | The only evidence is the record's own claim. |

Key rules:

- No property of an unsigned record is `verified`: only a signature could verify a record's integrity, or anything
  that rests on it, and no record carries one. Matching digests give `claimed_by_record` with the reason
  `file_digests`. Any `verified` is refused: "no property of an unsigned record is verified".
- When `integrity` is `failed` with the reason `file_digests`, every other property is `could_not_decide` with the
  reason `integrity_failed`: a record that does not hold together says nothing a verifier can take about itself.
  Any other is refused: "when a record's integrity is not established, every other property is could_not_decide with
  the reason integrity_failed".
- Otherwise each property has one of the results a verifier gives it
  (`iltero_schemas.models.common.verification.PROPERTY_RESULTS`), each a state and a reason, and any other is refused:
  "`<property>` is one of the results a verifier gives that property". The model checks that the pair is one of these;
  it does not read the record, so which result a record gets is set by the rules below and the
  [`reports_expected/`](02-conformance-vectors.md#vector-folders) vectors.

  | Property | State | Reason | Meaning |
  | --- | --- | --- | --- |
  | `integrity` | `claimed_by_record` | `file_digests` | The files the record cites hold the digests it names, which anyone who can edit them can recompute. |
  | `source_identity` | `not_assessed` | `ci_job_held_by_server` | Iltero Platform, which opened the run, verifies its CI jobs; the record does not carry them. |
  | `source_identity` | `not_performed` | `run_opened_locally` | The tool opened the run, so no CI job was verified. |
  | `approval_identity` | `claimed_by_record` | `approvals_listed` | The pre-deploy stage lists approvals: its writer's claim. |
  | `approval_identity` | `not_performed` | `no_approval_served` | Iltero Platform opened the run, and the pre-deploy stage keeps an empty list of approvals. |
  | `approval_identity`, `commit_review` | `not_assessed` | `not_in_activity` | The record's activity has no pre-deploy stage, as an image build has none. |
  | `exceptions` | `not_assessed` | `not_in_activity` | The record's activity applies no exception at any stage, Iltero Platform's or the project's own, as an image build or deploy applies none. |
  | `approval_identity`, `exceptions`, `commit_review` | `not_assessed` | `pre_deploy_out_of_scope` | The record leaves the pre-deploy stage out of scope for a reason other than `needs_the_server`. |
  | `approval_identity`, `exceptions`, `commit_review` | `not_performed` | `run_opened_locally` | The tool opened the run, so Iltero Platform served no approval, exception or commit review, and no check of one happened. |
  | `approval_identity`, `exceptions`, `commit_review` | `not_assessed` | `pre_deploy_pending` | The record expects the pre-deploy stage, and the run that would report it is still in progress. |
  | `approval_identity`, `commit_review` | `could_not_decide` | `server_facts_unavailable` | Iltero Platform opened the run, a check needed the fact, and the pre-deploy stage kept the unknown marker in its place. |
  | `approval_identity`, `commit_review` | `not_assessed` | `not_read_by_the_stage` | None of the pre-deploy stage's results read the fact, so the stage kept the `not_read_by_the_stage` marker. |
  | `exceptions` | `failed` | `kept_exceptions_do_not_hold` | An exceptions file a stage kept, the project's own or the [one Iltero Platform served](#servedexceptions), does not give the exceptions the record names, or was served to another run, stage or environment. |
  | `exceptions` | `claimed_by_record` | `served_exception_approved_by_run_starter` | As `served_exception_relied_on`, and the kept copy says the person who approved one of those exceptions [started the run](#the-runs-starter). |
  | `exceptions` | `claimed_by_record` | `served_exception_relied_on` | The plan stage names a failed result that an exception Iltero Platform served covers, and the kept copy gives that exception. Only Iltero Platform confirms that it served that copy, who approved each exception, and whether one was revoked later. Whether an exception was in force rests on the stage's reference time, itself the record's claim. |
  | `exceptions` | `claimed_by_record` | `served_exceptions_not_relied_on` | The plan stage applied the exceptions Iltero Platform served, and names no failed result they cover. |
  | `exceptions` | `claimed_by_record` | `project_exception_relied_on` | An event names an exception from the [project's own exceptions file](#localexceptions): the project's own word. |
  | `exceptions` | `claimed_by_record` | `project_exceptions_file_not_relied_on` | A stage applied the project's own exceptions file, and no event relied on an exception from it. |
  | `bundle_provenance` | `claimed_by_record` | `server_bundle_named` | A stage names an assertion bundle Iltero Platform served. |
  | `bundle_provenance` | `not_performed` | `local_assertions` | The checks were the project's own. |
  | `stage_completeness` | `claimed_by_record` | `expected_stages` | Every stage the record expects reported. |
  | `stage_completeness` | `not_assessed` | `stages_pending` | The run is still in progress. |
  | `stage_completeness` | `failed` | `stage_not_reported` | The record is finished, and a stage it expects was never reported. |
  | `plan_apply_match` | `not_assessed` | `not_in_activity` | The record's activity applies no plan. |
  | `plan_apply_match` | `not_performed` | `no_post_deploy_stage` | No stage compared the applied plan. |
  | `plan_apply_match` | `claimed_by_record` | `plan_digests_compared` | The digests the record names of the evaluated plan and the applied plan match. |
  | `plan_apply_match` | `claimed_by_record` | `redacted_plan_only` | In a run the tool opened that names no saved plan file, the digests of the redacted plans match; hidden values were not compared. When the digests match, a verifier gives this reason exactly when `governance.run_opened_by` is `local` and `change.plan.artifact_digest_source` is `not_provided`, and `plan_digests_compared` otherwise. A failed comparison gives `plan_digests_compared`: redacted plans that differ already show the plans differ. |
  | `plan_apply_match` | `failed` | `plan_digests_compared` | The digests the record names of the evaluated plan and the applied plan do not match. |
  | `plan_apply_match` | `could_not_decide` | `binding_undecided` | The record's plan digests could not be compared. |
  | `runtime_verification` | `claimed_by_record` | `reported_by_pipeline` | The pipeline reported the `post_verify` stage, which only the pipeline's word supports. |
  | `runtime_verification` | `not_assessed` | `stage_pending` | The record expects the stage, and the run that would report it is still in progress. |
  | `runtime_verification` | `not_performed` | `stage_not_reported` | The record expects the stage, and it was never reported. |
  | `runtime_verification` | `not_assessed` | `project_config`, `environment_policy` or `not_supported` | The record leaves the stage out of scope for that reason. |
  | `runtime_verification` | `not_assessed` | `not_in_activity` | The record's activity has no stage after deployment, as an image build has none. |
  | `deployment_coverage` | `not_assessed` | `null` | No reader of one record knows of a deployment that left no record. |
  | `commit_review` | `claimed_by_record` | `reviewed` | The pre-deploy stage kept a commit review whose outcome is `reviewed`: its writer's claim. |
  | `commit_review` | `failed` | `not_reviewed`, `review_starting_point_not_in_history`, `head_commit_before_review_starting_point`, `source_commit_not_verified_commit` or `build_commit_not_verified_commit` | The kept outcome, which shows that a commit the change ships was not reviewed. |
  | `commit_review` | `could_not_decide` | `too_many_commits` | The kept outcome: more commits than Iltero Platform checks, so it was not decided. |
  | `commit_review` | `not_performed` | `no_review_starting_point` | The kept outcome: no review starting point, so no commit was checked. |
  | `reference_time` | `not_performed` | `runner_clock` | At least one stage took its reference time from the runner's own clock, so no trusted time source was used. |
  | `reference_time` | `claimed_by_record` | `server` | Every stage took its reference time from Iltero Platform: the record's own claim, since no signature binds the time to the record. |
  | `evaluator_binary` | `claimed_by_record` | `pinned_binary_named` | Every OPA evaluation names the pinned binary for its platform. |
  | `evaluator_binary` | `failed` | `other_binary_named` | An OPA evaluation names another release, a platform the pin has no binary for, or another binary. |
  | `evaluator_binary` | `not_assessed` | `no_opa_evaluation` | No evaluation of the record ran on OPA. |
  | `scanner_reports` | `failed` | `kept_files_do_not_give_the_verdicts` | A scanner evaluation does not follow from the files its stage kept. |
  | `scanner_reports` | `failed` | `other_scanner_named` | A report of a scanner the Iltero CLI ran names a release, platform or digest the [scanner pin](02-conformance-vectors.md#the-pinned-scanner-releases) does not give, or another input kind or configuration than its [pinned run](02-conformance-vectors.md#the-pinned-scanner-runs). |
  | `scanner_reports` | `not_performed` | `scanner_requirement_not_met` | A group of scanners a stage requires is [unmet](#how-evaluators-combine) for a check and subject: each member that evaluated it gave a gap. |
  | `scanner_reports` | `claimed_by_record` | `ran_by_pipeline` | A kept scanner report says the pipeline ran it: the pipeline's word. |
  | `scanner_reports` | `claimed_by_record` | `ran_by_iltero_cli` | Every kept scanner report says the Iltero CLI ran it, each naming the pinned release: the record's word. |
  | `scanner_reports` | `not_assessed` | `not_in_activity` | The record's activity reads no scanner report, as an image build reads none. |
  | `scanner_reports` | `not_assessed` | `no_scanner_report` | No stage read a scanner report, and none requires one. In a run Iltero Platform opened, only Iltero Platform confirms that its stages required none. |

- For the six properties about the job that applies an infrastructure change,
  `iltero_schemas.models.iac.apply_job_results.apply_job_results(car)` gives every result, by property name. It takes
  each property's pass, fail, unknown or not applicable from the status its built-in check must have (see
  [The checks of the apply job](#the-checks-of-the-apply-job)), worked out from the apply job's facts the pre-deploy
  stage kept, the approvals beside them, the evaluated plan and `change.replan_check`, and adds only the reason that
  tells two failures or two unknowns apart, and a detail. It never reads an evaluation: an evaluation that ended in
  `error` decides nothing, and the detail says so ("the check's evaluation ended in error, which decides nothing; this
  result is read from the facts kept"). The first result that holds, in this order, is the property's:
  `not_in_activity` (an activity other than `iac_change`, an image deploy included, though it has a pre-deploy stage),
  `pre_deploy_out_of_scope`, `run_opened_locally`, `pre_deploy_pending`, `server_facts_unavailable` (the facts are the
  unknown marker; for `apply_job_approval_order`, also the approvals, after the two results that do not need them),
  then the property's own results in the order of
  `iltero_schemas.models.common.verification.APPLY_JOB_RESULT_ORDER`:

  | Property | State | Reason | When |
  | --- | --- | --- | --- |
  | `plan_age` | `failed` | `plan_older_than_limit` | More than `plan_age_limit.seconds` passed between Iltero Platform receiving the plan-stage record and issuing the facts (`apply_job_timing`). The detail gives both. |
  | `plan_age` | `claimed_by_record` | `plan_age_within_limit` | Otherwise. |
  | `apply_job_approval_order` | `not_performed` | `plan_and_apply_in_one_job` | The run plans and applies in one job. |
  | `apply_job_approval_order` | `not_performed` | `approval_not_required` | The environment's policy requires no approval of the apply job. The detail names the policy version. |
  | `apply_job_approval_order` | `failed` | `approved_before_plan_stage_record_accepted` | An approval of the apply job was received before `plan_stage_record_accepted_at`. When no approval came at or after it as well, the detail says so. |
  | `apply_job_approval_order` | `failed` | `no_approval_after_plan_stage_record_accepted` | No approval of the apply job was received at or after it. |
  | `apply_job_approval_order` | `claimed_by_record` | `approved_after_plan_stage_record_accepted` | Otherwise. The detail names each counted approval by its id and time. |
  | `received_plan_file` | `not_performed` | `plan_and_apply_in_one_job` | The run plans and applies in one job. |
  | `received_plan_file` | `failed` | `plan_file_not_sent` | The later apply job sent no saved plan file. |
  | `received_plan_file` | `failed` | `received_plan_file_differs` | `received_plan_file_digest` is not `change.plan.artifact_digest`. |
  | `received_plan_file` | `claimed_by_record` | `received_plan_file_matches` | Otherwise. |
  | `rendered_plan` | `not_performed` | `plan_and_apply_in_one_job` | The run plans and applies in one job. |
  | `rendered_plan` | `failed` | `rendered_plan_differs` | The rendered plan's digest, version or tool is not the evaluated plan's. |
  | `rendered_plan` | `could_not_decide` | `rendered_plan_not_sent` | The apply job reported no rendered plan. |
  | `rendered_plan` | `claimed_by_record` | `rendered_plan_matches` | Otherwise. |
  | `pinned_plan` | `failed` | `plan_differs_from_pinned_plan` | `pinned_plan_digest` is not `change.plan.digest`. |
  | `pinned_plan` | `claimed_by_record` | `evaluated_plan_is_pinned_plan` | Otherwise. |
  | `replan_resource_actions` | `not_performed` | `plan_and_apply_in_one_job` | The run plans and applies in one job. |
  | `replan_resource_actions` | `failed` | `rendered_plan_differs` | The rendered plan is not the evaluated plan, which decides it before the comparison. |
  | `replan_resource_actions` | `failed` | `resource_actions_differ` | `change.replan_check` names differences. The detail gives their count and the first address as the record keeps it, a marker named as "an address the record keeps redacted". |
  | `replan_resource_actions` | `could_not_decide` | `replan_not_compared` | The apply job compared no re-plan. |
  | `replan_resource_actions` | `claimed_by_record` | `same_resource_actions` | Otherwise. |

  A detail names at most three approvals (`MAX_NAMED_APPROVALS`), each id cut to 64 characters
  (`MAX_NAMED_ID_LENGTH`), with their times and how many more there are, or a count of differences and the first
  address as the record keeps it, cut to 256 characters (`MAX_NAMED_ADDRESS_LENGTH`), never a value. The order reasons
  keep the name of the field `plan_stage_record_accepted_at`, whose time is Iltero Platform's receipt of the
  plan-stage record that counts. A report's results are checked against its record only by computing them again from
  the record.
- One record gives one report. For `approval_identity`, `exceptions` and `commit_review`, a verifier takes the first
  result in this order that holds for the record
  (`iltero_schemas.models.common.verification.PRE_DEPLOY_RESULT_ORDER`, with `first_that_holds`). When none holds,
  the result is the pre-deploy stage's own: `approvals_listed`, `no_approval_served`, `not_read_by_the_stage`,
  or `server_facts_unavailable`, or, for a commit review the stage kept, the result
  `iltero_schemas.models.common.verification.COMMIT_REVIEW_RESULTS` names for its outcome, with the outcome as the
  reason.

  | Order | State | Reason | Properties |
  | --- | --- | --- | --- |
  | 1 | `failed` | `kept_exceptions_do_not_hold` | `exceptions` |
  | 2 | `claimed_by_record` | `served_exception_approved_by_run_starter` | `exceptions` |
  | 3 | `claimed_by_record` | `served_exception_relied_on` | `exceptions` |
  | 4 | `claimed_by_record` | `project_exception_relied_on` | `exceptions` |
  | 5 | `claimed_by_record` | `served_exceptions_not_relied_on` | `exceptions` |
  | 6 | `claimed_by_record` | `project_exceptions_file_not_relied_on` | `exceptions` |
  | 7 | `not_assessed` | `not_in_activity` | `approval_identity`, `exceptions`, `commit_review` |
  | 8 | `not_assessed` | `pre_deploy_out_of_scope` | `approval_identity`, `exceptions`, `commit_review` |
  | 9 | `not_performed` | `run_opened_locally` | `approval_identity`, `exceptions`, `commit_review` |
  | 10 | `not_assessed` | `pre_deploy_pending` | `approval_identity`, `exceptions`, `commit_review` |

  The exception results come first, and a kept exceptions file that does not hold comes before any of them. The plan
  stage applies exceptions, so a pre-deploy stage that is not in the activity, is out of scope or is still pending does
  not hide an exception the record relied on. A run the tool opened that leaves its pre-deploy stage out as
  `needs_the_server` gets `run_opened_locally`, not `pre_deploy_out_of_scope`: no server will serve that run its
  approvals. A verifier passes `first_that_holds` only results the property can take: an exception result given for
  `approval_identity` is refused when the report is read.
- `iltero_schemas.models.iac.report_results.exception_results(car, files)` gives each exception result that holds for
  a record, with its detail, from the record and the files its stages kept (a
  [`KeptFiles`](#the-check-a-reader-runs)). A verifier passes these, with the pre-deploy results that hold, to
  `first_that_holds`. The served results apply only to a run Iltero Platform opened. `not_in_activity` holds when
  the record's activity applies no exception at any stage, as for an image build or deploy, whoever opened the run;
  it comes before `run_opened_locally`.
- `server_facts_unavailable` applies only to a run Iltero Platform opened. Neither `server_facts_unavailable` nor
  `not_read_by_the_stage` is ever an `exceptions` result.
- The `reference_time` result follows the weakest source any stage took its time from.
- `iltero_schemas.models.common.pinned_evaluator.evaluator_binary_result(events)` gives the `evaluator_binary` result.
  For `other_binary_named`, its `detail` is the first problem
  [`pinned_evaluator_problems`](#assuranceevent) lists, as `<where> <what>`, such as
  "events.0.provenance.evaluator.digest is not the digest of the pinned OPA binary for its platform". When the
  evaluations have more problems, the detail ends with their count, such as " (4 more problems)". The property
  compares the binary the record states with this contract release's pin; it cannot show which binary ran.
- `iltero_schemas.models.iac.report_results.scanner_reports_result(car, files)` gives the `scanner_reports` result:
  the first of `iltero_schemas.models.common.verification.SCANNER_REPORTS_RESULT_ORDER` that holds, in the order of
  the table above. It applies to a record of any change type: an image record gets `not_in_activity`. Who ran the
  reports is judged per kept report: any kept report the pipeline ran gives `ran_by_pipeline`, even beside reports the
  Iltero CLI ran. The `other_scanner_named` detail is the first problem `pinned_scanner_problems` lists, as
  `<where> <what>`, followed by the count of the rest, as for `kept_files_do_not_give_the_verdicts`.
- The `kept_exceptions_do_not_hold` detail is the first problem
  [`local_exception_problems`](#a-stage-that-applies-the-file) and
  [`served_exception_problems`](#checking-the-kept-copy) list, and the `kept_files_do_not_give_the_verdicts` detail the
  first problem [`scanner_evidence_problems`](#the-check-a-reader-runs) lists, as `<where> <what>`, followed by the
  count of the rest, such as " (and 1 more problem)" or " (and 2 more problems)". The `served_exception_relied_on`
  detail is the fixed sentence `report_results.SERVED_EXCEPTION_RELIED_ON`: "the kept copy gives each failure the record
  names as excepted; only the server that opened the run confirms that it served that copy, who approved each exception
  and whether one was revoked, and whether an exception was in force rests on the stage's reference time". The
  `served_exception_approved_by_run_starter` detail is `report_results.APPROVED_BY_RUN_STARTER`: "the kept copy says the
  person who approved an exception the record relies on started the run; " followed by that sentence. Both stand only
  beside kept copies that hold: when `local_exception_problems` or `served_exception_problems` list a problem, these
  results carry no detail, and `kept_exceptions_do_not_hold` comes first anyway. The `scanner_requirement_not_met`
  detail names the stage and the group's scanners, sorted, such as "in the plan stage, the required group of checkov,
  trivy gave only gaps for a check". A detail never holds a value from a kept file.
- Call both functions on a record whose integrity holds: when it does not, every other property is
  `could_not_decide`.
- The report has no overall verdict, and no report establishes certification or compliance with a regulatory
  framework.

### What checking offline establishes

A reader checks a record offline: from the record, the files its stages kept, this package and its trust set. That
shows the record agrees with itself and with its kept files. It does not show who wrote them. A record is unsigned and
`self_attested`, so anyone who can edit the record and its files can make them agree, and no property is `verified`.

Some facts rest on what Iltero Platform holds for a run it opened. Iltero Platform confirms them to the organization's
users. What an organization keeps on Iltero Platform is private to that organization, and there is no public lookup of
a record. The first such fact is that Iltero Platform opened the run at all: `governance.run_opened_by: server` is the
writer's claim, and Iltero Platform confirms it to the organization's users by the record's `run.id`.

| Property | What a reader recomputes offline | What only Iltero Platform confirms, to the organization's users |
| --- | --- | --- |
| `integrity` | Every value the record derives from itself, such as its digests, counts, verdicts and evidence statuses, and that each file it cites holds the digest it names ([`kept_file_problems`](#checking-a-record-against-its-kept-files)). | That a record with this document digest is the one it accepted for the run, unit and stage. It cannot say who wrote the record. |
| `source_identity` | The repository, commit and project tree the record names, against the repository when the reader holds it. | The CI job that opened the run, and the commit it verified from that job's identity. |
| `approval_identity` | The approvals the pre-deploy stage lists, and the change digest they bind to. | Who approved, and that each approval was given. |
| `bundle_provenance` | The bundle each evaluation names, by its digests and key; with the tarball, the bundle's signature ([`read_signed_bundle`](#reading-a-pinned-bundle-back)). | That it served that bundle to the run. |
| `stage_completeness` | Which expected stages reported, and that the assertions each stage counts as required are those of its events; for the project's own assertions, against its files at the record's commit. | The assertions it set for each stage of the run. |
| `plan_apply_match` | Whether the plan digests the record names match. In a run the tool opened, also that each is the digest of a redacted plan the record keeps ([`kept_plan_digest_problems`](#plan-digests)), and, with the plan as the tool printed it and the record's policy, that the kept copy is that plan redacted, for the same rendering. In a run the server opened, only that the keyed digests are equal: which plan they name is the record's claim. The saved plan file's `artifact_digest`, when the record names one, against a held file. | That the plan each accepted record evaluated and applied is the plan the run was fixed to before the deployment. |
| `runtime_verification` | Whether the stage after the deployment reported, and what it recorded. | Nothing beyond whether it accepted the record of the stage after the deployment, which `stage_completeness` covers. The stage is the pipeline's word. |
| `deployment_coverage` | Nothing: one record cannot show a deployment that left no record. | For the runs it opened only: each run of the project and environment, and each record a unit should have sent and never did. A deployment made outside any run Iltero Platform opened stays invisible to it. |
| `exceptions` | That each excepted failure is what the kept exceptions file or served copy gives it ([`served_exception_problems`](#checking-the-kept-copy), [`local_exception_problems`](#a-stage-that-applies-the-file)). | That it served the kept copy, who approved each exception, and whether one was revoked later. A project's own exceptions are the project's word. |
| `commit_review` | The outcome the pre-deploy stage kept. | The review itself: which commits it read and how each was reviewed. |
| `reference_time` | The source each stage names for its reference time. | The time it served each stage of a run it opened. It does not compare that time with the record. |
| `evaluator_binary` | That each OPA evaluation names the pinned binary for its platform. | Nothing: which binary ran is the record's claim. |
| `scanner_reports` | That each scanner verdict follows from the kept report, plan and mapping ([`scanner_evidence_problems`](#the-check-a-reader-runs)), that each report the Iltero CLI ran names the pinned scanner, and the served mapping's signature. | That the kept mapping is the one fixed for the run, and, in a run it opened, that its stages required no scanner when none reported. Who ran each scanner and which program ran stay the record's claim (see [What these checks establish](#what-these-checks-establish)). |
| `plan_age`, `apply_job_approval_order`, `received_plan_file`, `rendered_plan`, `pinned_plan` | What the apply job's facts and approvals the pre-deploy stage kept give, against the record's plan ([`apply_job_results`](#verificationreport)). | That it issued those facts and received those approvals. |
| `replan_resource_actions` | What `change.replan_check` says, and that the record's other rules on it hold. | Nothing: the re-plan and its comparison are the pipeline's word. |

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
| `sources` | object | The `state` read (its `digest`, `digest_version`, IaC `tool` and `tool_version`); where it was read from (`read_from`: `state_file`, the state file the apply left, or `refresh_plan`, the state a refresh-only plan read back after the deployment, as the plan records it); and the applied `plan` (`digest`, `digest_version`), or `null` when no applied plan was read. `state.digest` is the [state digest](#state-digests) of what was read: in a run the server opened, the keyed digest of the bytes read, the state file or the refresh-only plan; in a run the tool opened, the digest of the state, or of the refresh-only plan's `prior_state`, as the record's redaction policy leaves it. A document on its own takes either form; in a record's `change.identity`, the identities' state is the deployment's; the post-verify stage's document is checked as [Checking the kept post-verify identities](#checking-the-kept-post-verify-identities) says. |
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
- `sources.plan.digest_version` is the version of the plan digest rule for `sources.state.tool` that the digest's form
  names (see [Plan digests](#plan-digests)), since the tool that wrote the state wrote the applied plan. Any other
  version is refused.
- The document carries identifiers only. The state file it was read from never leaves the machine that read it.

A document the post-verify stage of a record keeps is checked against the record's run and drift check (see
[Checking the kept post-verify identities](#checking-the-kept-post-verify-identities)).

## ScannerCheckMapping

A scanner check mapping says which scanner checks decide which assertion. It lists assertion mappings: each names one
assertion and lists its scanner checks entries. A scanner checks entry says: these checks of this tool, at a version
the constraint admits, read from this kind of input, together decide the assertion at this stage. Nothing is run for
a mapped check: the scanner already ran in the pipeline, and its results become one evaluation of the assertion,
beside the assertion's own rule when it has one (see [How evaluators combine](#how-evaluators-combine)).

A scanner check mapping is a lookup table, never a requirement: a stage uses the reports it was given, and a scanner
with no report adds nothing unless a scanner requirement names it (see [Evaluations from a scanner's
results](#evaluations-from-a-scanners-results)). A check mapped nowhere is not an error: its result is kept as
evidence, never turned into a verdict.

- **apiVersion:** `iltero.com/v1`, with `kind: ScannerCheckMapping`
- **Model:** `iltero_schemas.models.iac.scanner_check_mapping.ScannerCheckMapping`

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion`, `kind` | string | `iltero.com/v1` and `ScannerCheckMapping`. |
| `metadata` | object | The mapping's `id` and `version` (`MappingMetadata`). |
| `spec.assertion_mappings` | list | 1 to 10,000 assertion mappings (`MAX_ASSERTION_MAPPINGS`), sorted by assertion id, each assertion once. |

Each assertion mapping (`AssertionMapping`):

| Field | Type | Meaning |
| --- | --- | --- |
| `assertion` | object | The assertion it decides: its `id`, `version` and the `digest` of its document. |
| `scanner_checks` | list | 1 to 32 scanner checks entries (`MAX_SCANNER_CHECKS`), sorted by stage in lifecycle order, then by tool, one per tool and stage. |

Each scanner checks entry (`ScannerChecks`):

| Field | Type | Meaning |
| --- | --- | --- |
| `tool` | string | `checkov` or `trivy`. |
| `stage` | stage | The stage at which the checks decide the assertion. |
| `rule_ids` | list | The tool's own check ids, such as `CKV_AWS_16`, 1 to 16 (`MAX_RULE_IDS`), sorted, each once, compared exactly as the tool writes them. All of them decide together: any that fails fails the assertion, and all of them must pass for it to pass. |
| `tool_version_constraint` | string | A PEP 440 (Python's version specification) specifier with an upper bound, such as `>=3,<4`. A result from a version outside it decides nothing. |
| `input_kind` | string | What the scanner read, in the contract's words: `plan` (the values the plan settled on) or `deployed_resources`. |
| `subject_match` | string | How a result finds the subject it decides: `exact_address` (the result's resource is the subject) or `plan_configures` (the result is about a resource whose configuration refers to the subject, such as an S3 bucket's public access block). |
| `paths_read` | list | The attribute paths the checks read on the resources their results are about, 1 to 32, with `/` between names and `*` for any list element (`ingress/*/cidr_blocks`), sorted, each once. A result that passes while one of these values is known only after the deployment does not pass. |

Key rules:

| Rule | Refused with |
| --- | --- |
| A scanner checks entry reads the input its stage stands for (`STAGE_INPUT_KINDS`): `plan` at `plan`, `deployed_resources` at `runtime`. No other stage reads scanner input. | "a scanner checks entry at plan reads plan input", "a scanner checks entry at pre_deploy reads no scanner input" |
| `tool_version_constraint` is a version specifier, bounded from above. | "is not a version specifier", "bounds the version from above, such as <4" |
| `rule_ids` and `paths_read` are sorted, each once. | "rule_ids is sorted, each check once", "paths_read is sorted, each path once" |
| An assertion mapping's scanner checks entries are one per tool and stage, in order. | "scanner_checks are in lifecycle order of their stage, then by tool, one per tool and stage" |
| Each assertion is mapped once, in id order. | "assertion_mappings are sorted by assertion id, each assertion once" |
| A tool's check is used once per stage across the whole mapping. | "two assertion mappings use the same check of the same tool at the same stage" |
| No assertion mapping decides an assertion in `iltero_schemas.assertions.NOT_DECIDED_BY_SCANNERS` (see [AssuranceEvent](#assuranceevent)). | "no scanner checks decide ILT.COMMON.CHANGE.APPROVAL.PRODUCTION_APPROVED: a scanner's result never decides it" |

- A tool's word is a decision only as `iltero_schemas.models.iac.scanner_check_mapping.TOOL_DECISIONS` lists it:

  | `tool` | Words |
  | --- | --- |
  | `checkov` | `PASSED` is `pass`, `FAILED` is `fail` |
  | `trivy` | `PASS` is `pass`, `FAIL` is `fail` |

- A pre-release version, a local build (`3.2.1+patched`) or a version string not written as the tool releases it
  (`v3.2.1`) satisfies no constraint (`constraint_met`).
- An event decided through a scanner checks entry names it in `provenance.scanner_checks` by
  `AssertionMapping.scanner_checks_digest(entry)`: the digest of
  `{"assertion": <the assertion mapping's assertion>, "scanner_checks": <the entry>}`, each as the model dumps it, so
  an edit to either is visible. `ScannerCheckMapping.by_digest` finds an entry, with its assertion mapping, by that
  digest.
- That an entry's stage is one of the assertion's stages needs the assertion's document, so a reader checks it with
  the document (see [The check a reader runs](#the-check-a-reader-runs)).
- A mapping read from a project's own file decides only the project's own assertions
  (`iltero_schemas.models.iac.scanner_check_mapping.check_project_mapping`). Its id's namespace is not `ILT` and does
  not start with `ILT` ("a project's own id has a namespace of its own, not ILT or one starting so"). No assertion
  mapping in it decides an assertion whose namespace starts with `ILT`, since only the mappings Iltero ships map
  Iltero's assertions ("a project's scanner check mapping decides only the project's own assertions, not
  ILT.IAC.RESOURCE.AWS.RDS.STORAGE_ENCRYPTED", with the id).
- The package ships one mapping, `ILT.SCANNER_CHECKS.STARTER`
  (`iltero_schemas.scanner_check_mappings.SHIPPED_MAPPING`). It maps nine starter assertions about AWS resources to
  checks of Checkov (`>=3,<4`), Trivy (`>=0.72,<1`) or both. A record names it with `origin: shipped`, and its digest
  is `SHIPPED_MAPPING_DIGEST`. `SHIPPED_SCANNER_CHECKS` gives the digest of each of its scanner checks entries, and
  `SHIPPED_MAPPING_ASSERTIONS` the version and document digest each of its assertion mappings cites.
- `iltero_schemas.scanner_check_mappings.load_scanner_check_mapping` reads a mapping from YAML text with the loader of
  a [TechnicalAssertion](#technicalassertion), under the same rules: one document of at most 256 KiB, nested at most
  32 levels, with no anchors, aliases, tags, merge keys or duplicate keys, and no value written other than as `null`.

```yaml
apiVersion: iltero.com/v1
kind: ScannerCheckMapping
metadata:
  id: ACME.SCANNER_CHECKS.PAYMENTS
  version: "1.0.0"
spec:
  assertion_mappings:
    - assertion:
        id: ACME.IAC.RESOURCE.AWS.RDS.STORAGE_ENCRYPTED
        version: "1.0.0"
        digest: "sha256:<digest of the assertion's document>"
      scanner_checks:
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
  a report, the plan's resource addresses (`plan_resource_addresses`) and an
  `iltero_schemas.models.iac.scanner_reports.common.Source`: the report, plan, rules and configuration digests, who ran
  the tool, and `input_kind`, the input the Iltero CLI gave the tool, given exactly when the Iltero CLI ran it (`None`
  when the pipeline ran it): "a reader is given the input the tool read exactly when the Iltero CLI ran it". When
  `input_kind` is set, the observations name exactly it; the kept-file check rebuilds the observations of a report the
  Iltero CLI ran with it.

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion`, `kind` | string | `iltero.com/v1` and `ScannerObservations`. |
| `tool`, `tool_version` | string, identifier | The scanner and the version it wrote into its report. |
| `ran_by` | string | Who ran the tool: `pipeline` or `iltero_cli`, as the report entry's `ran_by` says. |
| `rules_digest` | digest or null | The digest of the tool's separately downloaded checks (Trivy's checks bundle). When the pipeline ran the tool, `null` means the stage was not given it, never that none was used. When the Iltero CLI ran it, `null`: only the checks built into the pinned release ran. |
| `configuration_digest` | digest or null | The configuration digest of the [pinned run](02-conformance-vectors.md#the-pinned-scanner-runs) the Iltero CLI ran the tool with, the one its report entry names; `null` when the pipeline ran the tool. |
| `report_digest` | digest | The report as the stage kept it, in the contract's [kept form](#the-report-a-stage-keeps). |
| `kept_plan_digest` | digest | The plan the stage evaluated, by the digest of the copy it kept, redacted: the digest of an entry of the evidence register, not a [plan digest](#plan-digests). |
| `input_kinds` | list | What the tool read, translated into the contract's words (`TOOL_INPUT_KINDS`), sorted, each once. When the Iltero CLI ran the tool, the one input it gave the tool, even when the tool found nothing: "observations of a scanner the Iltero CLI ran name the one input it gave the scanner". When the pipeline ran it, the inputs its results cover. |
| `unreadable_results` | integer | Results of the report the reader could not read, which decide nothing. |
| `written_configuration_results` | integer | Results about the IaC configuration as written (not the tool's own settings), which no stage reads, counted and left out of `results`. |
| `tool_parsing_errors` | integer or null | Files the tool says it could not parse, or `null` when the tool does not say (Trivy). |
| `results_not_listed` | integer or null | Results the tool's own summary counts that its report does not list, or `null` when the tool writes no counts (Trivy). It is the tool's own word: 0 does not show that every check ran, only that every result the tool counts is listed. |
| `results` | list | At most 200,000 results, sorted by check, then input kind, then the tool's address (a result with none first), each once. |

Observations name a `configuration_digest` exactly when the Iltero CLI ran the scanner, and then no `rules_digest`:
"observations name the configuration a scanner ran with exactly when the Iltero CLI ran it, and then no separately
downloaded checks".

The property `read_in_full` is true when `unreadable_results`, `tool_parsing_errors` and `results_not_listed` are each
0 or `null`: the stage read every result the report holds or counts. A report not read in full leaves a subject with
no listed failure `unknown` with `scanner_report_incomplete`, unless an earlier rule decides it (see [How a scanner's
results decide a subject](#how-a-scanners-results-decide-a-subject)). `tool_parsing_errors` and `results_not_listed`
are `null` exactly when the tool writes no counts (`TOOLS_THAT_WRITE_NO_COUNTS`, Trivy): "the counts of unparsed files
and of results not listed are given exactly when the tool writes counts".

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

Checkov writes a `summary` for each framework, and the reader requires it. Each summary gives four counts, each a
whole number from 0: `parsing_errors`, the files Checkov could not parse, and `passed`, `failed` and `skipped`, the
results Checkov holds in each list. `tool_parsing_errors` is the sum of `parsing_errors` over every framework, so for
Checkov it is never `null`. Run with `--quiet`, Checkov writes only `failed_checks`, while its summary still counts the
passed and skipped results. For each framework and each of its three lists, the count less the list's length is a
result the summary counts and the report does not list; `results_not_listed` is their sum over every framework and
list. Each list is compared with its own count, so a surplus in one list never hides a shortfall in another.

For example, Checkov 3.3.8 run with `--quiet` on the RDS plan of the conformance vectors
(`scanner_reports/iac/rds_quiet_checkov.json`) lists 47 failures and counts 37 passes it does not list, so
`results_not_listed` is 37. The stage did not read that report in full, so each subject it lists no failure for is
`unknown` with `scanner_report_incomplete`, and a skip the scanned source asked for, which the report does not list,
never gives `suppressed_in_source`.

Run Checkov without `--quiet`. A quiet report passes no subject: each subject of a mapped assertion that it lists no
failure for stays `unknown`, so the stage cannot be `met` while such a subject is in scope. The reader accepts the
report so that the record states what it holds, not so that a stage relies on it.

| Framework summary | Refused with |
| --- | --- |
| Left out, `null`, a hidden `null`, or not an object. | "the checkov report gives a framework no summary, or one that is not an object" |
| A count left out, `null`, a hidden `null`, below 0, or a truth or text in place of a count. | "the checkov report's summary gives no count of files it could not parse, or one that is not a count", or the same for its count of passed checks, of failed checks or of skipped checks |
| A redaction marker other than a hidden `null` in place of the summary or a count. | "the report hides a framework's summary, where its reader expects an object", or "the report hides the summary's count of passed checks, where its reader expects a count", or the same for its other counts |
| A count lower than the length of its list. | "the checkov report's summary counts fewer passed results than the report lists", or the same for failed or skipped results |

When no framework has a result and no file failed to parse, Checkov writes one summary object with no framework:
exactly `passed`, `failed`, `skipped`, `parsing_errors` and `resource_count`, each the count 0, and `checkov_version`.
Checkov 3.3.8 writes it for an empty plan, for `{}`, for `[]`, for a file that is not JSON, for an unknown check id, and
for a `--check` or `--skip-check` filter that matches nothing on a plan with resources. A missing file is different:
Checkov writes a whole framework with `parsing_errors` 1, which reads as `scanner_report_incomplete`. The reader reads
the summary as a report with no result, whose `tool_version` is `checkov_version` and whose `tool_parsing_errors` and
`results_not_listed` are 0,
so a plan that changes nothing can be given a Checkov report. Every subject of such a report is `not_evaluated` with
`no_result_in_the_report` (see [How a scanner's results decide a subject](#how-a-scanners-results-decide-a-subject)).
The summary does not say why nothing was checked, so a record cannot tell a plan that changes nothing from a run set
up wrongly, such as one given a file that is not the plan or a check filter that matches nothing.

| Summary with no framework | Refused with |
| --- | --- |
| A count other than 0, or a truth or text in place of a count. | "the checkov report is a summary with no framework, whose counts are not all the number 0" |
| A key left out, or a key added. | "the checkov report is not one or more framework objects with results" |
| A redaction marker in place of a count. | "the report hides the summary's count of resources, where its reader expects a count", or the same for its count of passed, failed or skipped checks or of files it could not parse |

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
| `checkov` | The whole report (an object or a list); each framework of a list of them; a framework's `results` and `summary`; each count of a framework's `summary` (`parsing_errors`, `passed`, `failed` and `skipped`); each of the `passed_checks`, `failed_checks` and `skipped_checks` lists; each result in them; a result's `check_result` and `connected_node`; `check_result.evaluated_keys` (a list); each count of a summary with no framework. |
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

Whoever ran the tool (`ran_by`), the report is the record's own claim: nothing in the observations shows that the tool
read the plan they name.

## LocalExceptions

A local exceptions document holds the exceptions a project writes in its own files, for a run the tool opened. Each
exception says that an assertion does not have to hold for an environment and the resources it names, between two times,
why, and who the project says approved it. It is the project's own word: nothing outside the project approved it. A
stage applies the file only to the scanner results the scanned source suppressed, to name the exception each suppression
rests on; such a result stays `not_evaluated` with `suppressed_in_source`. An exception explains a gap, it never fills
it.

- **apiVersion:** `iltero.com/v1`, with `kind: LocalExceptions`
- **Model:** `iltero_schemas.models.common.local_exceptions.LocalExceptions`. `read_local_exceptions(data, file_path)` reads
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
| `spec.exceptions` | list | 0 to 256 exceptions (`LocalException`), each with the fields below. An empty list is valid: a project with no exception keeps `exceptions: []`. |

| Exception field | Type | Meaning |
| --- | --- | --- |
| `id` | identifier | The exception's id, unique in the file. |
| `status` | string | Always `approved`. |
| `scope.assertion.id` | string | The assertion the exception is about, by its id: the exception covers every version of it. |
| `scope.environment` | identifier | The Iltero environment the exception holds in. |
| `scope.resources` | list | 1 to 256 resources, each by its identity (`scheme`, `value`, `scope`). |
| `valid_from`, `expires_at` | timestamp | When the exception starts and when it expires. |
| `approved_by` | object | Who the project says approved it: `provider` and `id`, each an identifier. |
| `reason` | string | Why the exception was granted: 1 to 1,024 characters. |

In this file, `status` and `approved_by` are what the project says: nothing checks them.

The rules below hold for every exception, a project's or one Iltero Platform serves
(`iltero_schemas.models.common.exception_terms.check_exception` and `check_exception_list`):

| Rule | Refused with |
| --- | --- |
| Each exception has an id of its own. | "each exception has an id of its own" |
| Each resource is named by its address in the IaC tool's configuration (`scheme: terraform_address`), with `scope` exactly `{"unit": <its unit>}`. A cloud identity is not accepted: a resource being created has none, and one that is replaced gets a new one. | "an exception names each resource by its address, scoped by its unit and nothing else" |
| No two exceptions cover the same assertion, environment and resource at overlapping times, so the exception that covers a result is never a choice. Two periods overlap when each starts no later than the other expires. | "no two exceptions cover the same assertion, environment and resource at the same time" |
| An exception lasts at most 365 days of 24 hours from its `valid_from` (`MAX_EXCEPTION_DAYS`), compared to the nanosecond. A calendar year that holds 29 February is 366 days, longer than this limit. | "an exception lasts at most 365 days from when it starts" |
| An exception expires after it starts. | "an exception expires after it starts" |
| An exception never names a [built-in assertion](#assuranceevent) in `scope.assertion.id`. | "an exception never covers a built-in assertion: what it records is never waived" |

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

`exception_in_force(exceptions, assertion_id, identity, environment, at)`
(`iltero_schemas.models.common.exception_terms`) gives the exception that covers one result, or `null` when none does.
An exception covers it when all of these hold:

- its `scope.assertion.id` is the assertion's id, at any version;
- one of its `resources` is the result's subject: the same `scheme`, `value` and `scope`, the subject's identity in
  the address scheme of the plan's IaC tool;
- its `scope.environment` is the name of the record's `subject.environment`. A run that names no environment has no
  exception in force;
- it is in force at the stage's `reference_time.value`: from `valid_from` up to and including `expires_at`, compared
  to the nanosecond (`iltero_schemas.models.common.exception_terms.in_force`).

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
`iltero_schemas.models.iac.exception_evidence.local_exception_problems(car, files)` (through
[`kept_file_problems`](#checking-a-record-against-its-kept-files)), given the copy's bytes in
[`KeptFiles`](#the-check-a-reader-runs)`.local_exceptions`: for each suppressed result of the stage it works out again
which exception covers it, and the record must name that one, or none when none covers it. It returns `(where, what)`
pairs:

| Where | What | Meaning |
| --- | --- | --- |
| `stages.<stage>.scanners.local_exceptions` | "the record does not keep an exceptions file with the digest the stage names" | No bytes are given under the stage's `digest`, or their SHA-256 is not that digest. The stage's suppressed results are not checked further. |
| `stages.<stage>.scanners.local_exceptions` | "is not a project's exceptions file the contract can read" | `read_local_exceptions` refuses the copy (see [Reading the file](#reading-the-file)). The stage's suppressed results are not checked further. |
| `events.<index>.provenance.evaluator.local_exception` | "names an exception the kept exceptions file does not give this result" | A `suppressed_in_source` evaluation names an exception, but the kept file gives the result none, or another one. |
| `events.<index>.provenance.evaluator.local_exception` | "names no exception, but the kept exceptions file gives this result one" | A `suppressed_in_source` evaluation names no exception, but the kept file gives the result one. |

## ServedExceptions

A served exceptions document holds the exceptions Iltero Platform served one stage of a run it opened. Each exception
(`ServedException`) says that an assertion does not have to hold for an environment and the resources it names,
between two times, why, who asked for it, who approved it in Iltero Platform, and when. It names the assertion
document it was approved for by its id, version and digest. The list is empty when no exception is in force.

A served exception covers a failed result only of the assertion document it was approved for: the same id, version
and digest (see [When a served exception covers a failed result](#when-a-served-exception-covers-a-failed-result)).
The result stays `fail`: the exception is recorded beside it, never in its place. A stage whose every failed check
served exceptions cover in full, with nothing else open, is `not_met` with the reason `every_failure_excepted` (see
[Verdict and evidence status](#verdict-and-evidence-status)).

- **apiVersion:** `iltero.com/v1`, with `kind: ServedExceptions`
- **Model:** `iltero_schemas.models.common.served_exceptions.ServedExceptions`

```json
{
  "apiVersion": "iltero.com/v1",
  "kind": "ServedExceptions",
  "metadata": {
    "run_id": "be477ff2-92cb-561b-ae23-45f44dfb71de",
    "stage": "plan"
  },
  "spec": {
    "exceptions": [
      {
        "id": "exc_0001",
        "status": "approved",
        "scope": {
          "kind": "resources",
          "assertion": {
            "id": "ILT.IAC.RESOURCE.AWS.RDS.NOT_PUBLIC",
            "version": "1.0.0",
            "digest": "sha256:363672bedffd12abcb8ca4dde27fc253ea5d6180994c4a781a7ab382d2e5000e"
          },
          "environment": "production",
          "resources": [
            {
              "scheme": "terraform_address",
              "scope": {"unit": "root"},
              "value": "aws_db_instance.payments"
            }
          ]
        },
        "valid_from": "2026-11-01T00:00:00Z",
        "expires_at": "2027-02-01T00:00:00Z",
        "requested_by": {"provider": "iltero_pseudonym", "id": "1f2e3d4c-5b6a-4978-8a9b-0c1d2e3f4a5b"},
        "approved_by": {"provider": "iltero_pseudonym", "id": "3a9e2b7c-1d4f-4c6a-8e5b-9d0c1f2e3a4b"},
        "approved_at": "2026-10-30T14:12:00Z",
        "requester_and_run_starter": "different_users",
        "approver_and_run_starter": "different_users",
        "reason": "The database is reached through a private link added in the next change."
      }
    ]
  }
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion`, `kind` | string | `iltero.com/v1` and `ServedExceptions`. |
| `metadata.run_id` | UUID | Iltero's id of the run the exceptions were served to. |
| `metadata.stage` | stage | The stage they were served to. |
| `spec.exceptions` | list | 0 to 256 exceptions (`ServedException`), each with the fields below. |

Iltero Platform serves no document larger than 16 MiB (16,777,216 bytes) of canonical JSON
(`iltero_schemas.models.common.served_exceptions.MAX_SERVED_EXCEPTIONS_BYTES`). The model does not check the size; a
reader of a kept copy does (see [Checking the kept copy](#checking-the-kept-copy)).

| Exception field | Type | Meaning |
| --- | --- | --- |
| `id` | identifier | The exception's id, unique in the document. |
| `status` | string | Always `approved`. |
| `scope.kind` | string | Always `resources`: an exception about the resources it names (`ResourcesScope`). Any other value is refused: "Input should be 'resources'". |
| `scope.assertion` | object | The assertion the exception was approved for: its `id`, its `version` and the `digest` of its document. All three are required. |
| `scope.environment` | identifier | The Iltero environment the exception holds in. |
| `scope.resources` | list | 1 to 256 resources, each by its identity (`scheme`, `value`, `scope`). |
| `valid_from`, `expires_at` | timestamp | When the exception starts and when it expires. |
| `requested_by` | object | Who asked for the exception, by the pseudonym Iltero issued their Iltero user for the organization (`Pseudonym`): `provider`, always `iltero_pseudonym`, and `id`, a UUID. |
| `approved_by` | object | Who approved it, in the same form. |
| `approved_at` | timestamp | When it was approved. |
| `requester_and_run_starter` | string | Whether the requester is the [run's starter](#the-runs-starter), as Iltero Platform found: `same_user`, when Iltero Platform links the starter's account to this Iltero user; `different_users`, only when Iltero Platform linked both to Iltero users and they differ, which shows two Iltero users, not two people; or `could_not_tell`, when it could not link them. `could_not_tell` never means they are different people, so no reader treats it as a sign that the two are independent. Any other value, `true` and `false` included, is refused: "Input should be 'same_user', 'different_users' or 'could_not_tell'". |
| `approver_and_run_starter` | string | Whether the approver is the run's starter, with the same values, meaning and refusal as `requester_and_run_starter`. |
| `reason` | string | Why the exception was granted: 1 to 1,024 characters. |

A served exception follows every rule of a [project's exception](#localexceptions): an id of its own, each resource by
its address scoped by its unit, no two covering the same assertion, environment and resource at the same time, at most
365 days long, ending after it starts, and never about a built-in assertion. It also follows these rules:

| Rule | Refused with |
| --- | --- |
| An exception is approved no later than it expires. | "an exception is approved no later than it expires" |
| `requested_by` and `approved_by` are pseudonyms: `provider` is `iltero_pseudonym`. An account at an identity provider is refused. | "Input should be 'iltero_pseudonym'" |
| `requested_by` and `approved_by` name different `id`s. | "an exception is approved by someone other than who asked for it" |
| In one document, one Iltero user (one pseudonym `id`), as requester or approver, has one finding about the run's starter: every `requester_and_run_starter` and `approver_and_run_starter` about them has the same value. | "a run has one starter, so one Iltero user is found to be them, or not, in every exception" |
| In one document, at most one Iltero user is found to be the run's starter (`same_user`). | "a run has one starter, so at most one Iltero user is found to be them" |

A pseudonym is the one Iltero issued the user for the organization: the same for one Iltero user in every exception of
that organization, and unrelated to the same person's pseudonym in another, so records of two organizations cannot be
linked through their pseudonyms. Iltero keeps which user each pseudonym stands for, and erasing that removes Iltero's
link only. The person may still be identified without it: a pseudonym stays the same across the organization's
exceptions, and the record names the run's own CI facts. The free-text `reason` can name a person too, and erasing the
link does not remove that.

Two different pseudonyms show two Iltero users, not two people; the model checks only that they differ.

### The run's starter

The run's starter is the account of the continuous integration (CI) system that triggered the run, not necessarily
the author of the change. Iltero Platform states in `requester_and_run_starter` and `approver_and_run_starter` whether
the requester and the approver are each the run's starter, or that it could not tell: `same_user` means Iltero
Platform links that account to this Iltero user. The fields do not cover who triggered a later attempt of the run; the
record's CI facts show who triggered each attempt.

A requester or an approver found to be the run's starter (`same_user`) is recorded, not refused; a reader judges it.
Separation of duties rests on Iltero Platform and on a reader that checks these fields. The model reads the fields as
Iltero Platform's claims and does not check them.

### A stage that applies served exceptions

The stage that applies served exceptions is the `plan` stage of an `iac_change`
(`iltero_schemas.change_types.common.activity.Activity.stage_that_applies_served_exceptions`). An `image_build` or an
`image_deploy` applies none. In a record of a run Iltero Platform opened, that stage names what it applied in
`served_exceptions` (`ServedExceptionsUsed`), even when no exception was served:

| Field | Type | Meaning |
| --- | --- | --- |
| `digest` | digest | The digest of the served exceptions document's canonical JSON (RFC 8785). |
| `copy_path` | string | Where the stage kept those canonical bytes, in the record's directory. The copy is an entry of the evidence register (see the register rules in [Change Assurance Record (CAR)](#change-assurance-record-car)). |
| `excepted_failures` | list | Each failed result of the stage a served exception covers (`ExceptedFailure`), each once, at most 100,000 (`MAX_EXCEPTED_FAILURES`), one per failed event of the stage, so no more than a record holds events. Sorted by assertion `id`, then the resource by `scheme`, `value` and unit, then `engine`, each string compared by Unicode code point: a writer orders them with `iltero_schemas.models.common.served_exceptions.sorted_excepted_failures(failures)` rather than repeating the order. Empty when none is covered. |

| Excepted failure field | Type | Meaning |
| --- | --- | --- |
| `assertion` | object | The failed result's assertion: `id`, `version` and `digest`. |
| `resource` | object | The resource, by its address in the IaC tool's configuration (`scheme: terraform_address`), with `scope` exactly `{"unit": <its unit>}`, as an exception names it. |
| `engine` | string | The evaluator that gave the result, such as `opa` or `checkov`. |
| `exception_id` | identifier | The `id` of the served exception that covers it. |

The copy names the requester and the approver of each exception by the pseudonym Iltero issued their Iltero users for
the organization, and gives each exception's `reason`, so a record of a run Iltero Platform opened keeps those
pseudonyms and reasons among its files. Erasing which user a pseudonym stands for removes Iltero's link only (see
[ServedExceptions](#servedexceptions)).

The model refuses a record that breaks one of these rules (`iltero_schemas.models.common.provenance`,
`ServedExceptionsUsed`):

| Rule | Refused with |
| --- | --- |
| A record of a run the tool opened applies no served exceptions: every stage's `served_exceptions` is `null`. | "a record of a run the tool opened applies no exceptions the server served" |
| In a record of a run Iltero Platform opened, `served_exceptions` is set at the stage that applies served exceptions, and at no other stage. | "the served exceptions a run the server opened applies are named at the stage its activity applies them at, and only there" |
| That stage's `reference_time.source` is `server`. | "a stage that applies served exceptions reads its time from the server" |
| Each excepted failure is a `fail` event of the stage with that assertion, an identity of its subject equal to `resource`, and that `engine`. | "each failed result a served exception covers is a failed result of the stage, by its assertion, resource and engine" |
| `excepted_failures` is sorted by assertion id, resource and engine, each once. | "excepted_failures is sorted by assertion id, resource and engine, each once" |
| An excepted failure names its resource by its address, scoped by its unit and nothing else (`ExceptedFailure`). | "an excepted failed result names its resource by its address, scoped by its unit" |

### When a served exception covers a failed result

`served_exception_for(exceptions, assertion, identity, environment, at)`
(`iltero_schemas.models.common.served_exceptions`) gives the served exception that covers one failed result, or the
reason none does. A served exception covers it when it covers the result as any exception does, by the assertion's
id, the resource, the environment and the stage's reference time (see
[When an exception covers a result](#when-an-exception-covers-a-result)), and also:

- its `scope.assertion` is the result's assertion: the same `id`, `version` and `digest`;
- its `approved_at` is no later than the stage's `reference_time.value`.

The reason is the first that holds: one of the reasons `why_no_exception` gives, then these
(`NoServedExceptionReason`):

| Reason | When |
| --- | --- |
| `approved_for_another_document_of_the_assertion` | The exception in force was approved for another version or digest of the assertion. |
| `approved_after_the_reference_time` | The exception in force was approved after the stage's reference time. |

### Checking the kept copy

The model does not read the copy. `served_exception_problems(car, files)`
(`iltero_schemas.models.iac.exception_evidence`) does, on a record whose structure holds; a reader calls it through
[`kept_file_problems`](#checking-a-record-against-its-kept-files). `files` is a [`KeptFiles`](#the-check-a-reader-runs)
whose `served_exceptions` holds the bytes of each copy. For each such stage it checks that:

- the copy is kept and has the stage's `digest`;
- the copy is at most 16 MiB (`MAX_SERVED_EXCEPTIONS_BYTES`), checked before it is parsed: a larger copy is
  `SERVED_NOT_READABLE`;
- the copy is canonical JSON and a valid `ServedExceptions` document;
- its `metadata.run_id` is the record's `run.id`, its `metadata.stage` is the stage, and every exception's
  `scope.environment` is the name of the record's `subject.environment`;
- `excepted_failures` is exactly what `served_exception_for` gives each `fail` event of the stage whose subject has an
  identity in the address scheme of the plan's IaC tool, at the stage's reference time.

It returns `(where, what)` pairs:

| Where | What |
| --- | --- |
| `stages.<stage>.served_exceptions` | "the record does not keep, as canonical JSON, the served exceptions with the digest the stage names" (`SERVED_NOT_KEPT`) |
| `stages.<stage>.served_exceptions` | "is not a served exceptions document the contract can read" (`SERVED_NOT_READABLE`) |
| `stages.<stage>.served_exceptions` | "holds exceptions served to another run or stage, or for another environment" (`SERVED_ELSEWHERE`) |
| `stages.<stage>.served_exceptions.excepted_failures` | "names a failed result the kept served exceptions do not cover, or not with that exception" (`SERVED_NOT_GIVEN`) |
| `stages.<stage>.served_exceptions.excepted_failures` | "leaves out a failed result the kept served exceptions cover" (`SERVED_LEFT_OUT`) |

This shows that the record agrees with the copy it kept. It does not show that Iltero Platform served that copy, or
that Iltero approved the exceptions in it (see [What checking offline establishes](#what-checking-offline-establishes)).

## PolicySource

A policy source describes a directory of hand-written Rego policies, for rules the assertion language
cannot express. Each entry names the assertion a policy decides, the stage, the target and the one `.rego` file it
is written in.

- **apiVersion:** `iltero.com/v1`, with `kind: PolicySource`
- **Model:** `iltero_schemas.models.common.policy_source.PolicySource`

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
  segment (`iltero_schemas.models.common.assertion_id.change_type_of_id`), and any other segment is refused: "an assertion
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
- **Model:** `iltero_schemas.models.common.bundle.BundleDescriptor`

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
- A descriptor is at most 64 MiB as canonical JSON (`iltero_schemas.models.common.bundle.MAX_DESCRIPTOR_BYTES`); a larger
  one is refused. The limit is applied to the parsed descriptor, so a tool also caps the bytes it reads before parsing.

The bytes a key signs for a bundle are `iltero_schemas.bundle.files_signing_input(files, *, key_id)`: each file's name
and SHA-256 digest, by name, every file but the signature, under `key_id` and the bundle signing scope.
`signing_input(bundle, *, key_id)` gives the same for a built bundle. `signature_in(files)` gives the signed bytes and
the raw signature of the `.signatures.json` among a tarball's files.

### Reading a pinned bundle back

A run pins its bundle by `tarball_digest` and `key_id`. That key may later be retired or revoked.
`iltero_schemas.bundle.read_signed_bundle(tarball, *, tarball_digest, key_id, keys)` reads the bundle back under any
status of its key, for showing a run's bundle, and compiles nothing. It raises `BundleError` naming the first rule that
fails, in this order:

| Rule | Refused with |
| --- | --- |
| The tarball's SHA-256 is `tarball_digest`. | "the tarball is not the one the run pinned" |
| `key_id` names a key in the trust set `keys`, whatever its status. | "the pinned key_id names a key the trust set never held" |
| The tarball and its `.signatures.json` read as `check_descriptor` reads them, and the signature is in its low-S form. | The refusals `check_descriptor` gives for the tarball and its `.signatures.json`, such as "the tarball holds no .signatures.json", and "an ES256 signature is written in its low-S form: s at most half the curve order" |
| The tarball holds `.manifest`, `.signatures.json` and assertion modules (`.rego` files), and nothing else. | "the tarball must hold .manifest, .signatures.json and assertion modules, nothing else" |
| The `revision` of `.manifest` is the digest of its `metadata.iltero` object. | "the revision .manifest names is not the digest of its metadata" |
| The signature covers exactly the tarball's files under `key_id` (`files_signing_input`). | "the signature does not cover exactly this tarball's files under the pinned key_id" |

It returns a `ReadBackBundle`: the `key` the trust set holds, the `signed` bytes, the raw `signature`, the
tarball's `files` and the `content_digest`, the manifest's `revision`. The caller verifies the signature over `signed`
with `key.public_key_der`. Nothing in the result may be evaluated: a bundle is evaluated only through
`check_descriptor`, which recompiles every assertion and refuses a key that may not verify.

A record keeps the tarball of the served bundle each stage ran over. A reader reads the kept tarball back, verifies its
signature and checks it against the stage and its events with
[`served_bundle_problems`](#checking-the-kept-served-bundles).

## ScannerCheckMappingDescriptor

A scanner check mapping descriptor is how Iltero Platform serves a signed [scanner check
mapping](#scannercheckmapping). In a run Iltero Platform opens, a stage applies only the mapping served this way. The
descriptor carries the mapping, its digest, the key that signed it and the signature. A tool checks the descriptor and
verifies the signature before it reads any scanner result with the mapping.

- **apiVersion:** `iltero.com/v1`, with `kind: ScannerCheckMappingDescriptor`
- **Model:** `iltero_schemas.models.iac.scanner_check_mapping_descriptor.ScannerCheckMappingDescriptor`
- **Check:** `iltero_schemas.scanner_check_mappings.check_scanner_check_mapping_descriptor`

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion`, `kind` | string | `iltero.com/v1` and `ScannerCheckMappingDescriptor`. |
| `mapping` | object | The ScannerCheckMapping document, as a JSON object. At most 8 MiB of canonical JSON (see below). |
| `digest` | digest | The digest of `mapping`'s canonical JSON. |
| `key_id` | identifier | The key that signed the mapping. |
| `algorithm` | string | `ES256`. |
| `signature` | string | The ES256 signature over the signing input: the raw 64 bytes `r` then `s`, in base64url with no padding (86 characters), in its low-S form. |

ES256 is ECDSA (the Elliptic Curve Digital Signature Algorithm) on the P-256 curve with SHA-256. The signature form
and the bytes a key signs are shared with assertion bundles (`iltero_schemas.signing`).

The model refuses a `mapping` larger than 8 MiB as canonical JSON (`MAX_SERVED_SCANNER_CHECK_MAPPING_BYTES`): "the
mapping is at most 8388608 bytes of canonical JSON". It refuses a mapping that has no canonical form, such as one
nested too deeply to encode: "the mapping is a JSON object that has a canonical form". The limit is applied to the
parsed descriptor, so a tool also caps the bytes it reads before parsing.

### What the key signs

The signing input (`iltero_schemas.scanner_check_mappings.iac.descriptor.signing_input(mapping, key_id=...)`) is a
JSON Web Signature (JWS) header and payload, each written as canonical JSON in base64url with no padding, joined by a
dot:

| Part | Value |
| --- | --- |
| Header | `{"alg": "ES256", "kid": <key_id>, "typ": "JWT"}` |
| Payload | `{"digest": <the mapping's digest>, "keyid": <key_id>, "scope": "iltero-scanner-check-mappings"}` |

The signer computes SHA-256 over these bytes and signs that digest. The scope names the kind of document signed: a
verifier asks for exactly the scope of the document it checks, `iltero-scanner-check-mappings` for a mapping and
`iltero-assertions` for a bundle, so a signature over one is never accepted for the other.
`iltero_schemas.scanner_check_mappings.iac.descriptor.descriptor` writes the descriptor, with the signature in its
low-S form whichever form the signer returned.

### Checking a served descriptor

`check_scanner_check_mapping_descriptor(served, keys)` takes the descriptor, read with its model, and the trust set:
`iltero_schemas.trust.SIGNING_KEYS`, or a development tool's own set. It checks everything but the signature's
mathematics and raises `ScannerCheckMappingDescriptorError` naming the first rule that fails, in this order:

| Rule | Refused with |
| --- | --- |
| `key_id` names a key in the trust set that is not revoked. | "the descriptor's key_id names a key that is not trusted, or is revoked" |
| `mapping` is a valid ScannerCheckMapping. | "the descriptor's mapping is not a scanner check mapping" |
| The mapping's id starts `ILT.SCANNER_CHECKS.` and is not `ILT.SCANNER_CHECKS.STARTER`, the mapping the package ships. | "a served scanner check mapping's id starts ILT.SCANNER_CHECKS. and is not ILT.SCANNER_CHECKS.STARTER" |
| `digest` is the digest of `mapping`. | "the descriptor's digest is not the digest of its mapping" |
| `signature` decodes as base64url with no padding. | "a signature is base64url text with no padding" |
| `signature` is spelled the one way this package writes its bytes: no padding, and the unused bits of its last character zero. A last character with an unused bit set spells the same bytes another way. | "a signature is written in its one base64url spelling: no padding, and the unused bits of its last character zero" |
| `signature` is 64 bytes, its `r` and `s` each between 0 and the curve order, in its low-S form (`s` at most half the curve order). | "an ES256 signature's r and s each lie between 0 and the curve order", "an ES256 signature is written in its low-S form: s at most half the curve order" |

The model refuses a `signature` that is not 86 characters long or holds a character outside base64url, such as the
padding `=`. Its message names the field, `signature`.

The check returns an `UnverifiedScannerCheckMapping`:

| Field | Meaning |
| --- | --- |
| `key` | The trusted key `key_id` names. |
| `signed` | The signing input, the bytes the signature is over. |
| `signature` | The raw 64-byte signature. |
| `mapping` | The mapping, read with its model. |
| `descriptor_digest` | The SHA-256 of the RFC 8785 canonical JSON of the descriptor object as served, signature included, written `sha256:<hex>`. A record's `scanners.scanner_check_mappings` entry for the served mapping names this value as its [`descriptor_digest`](#change-assurance-record-car), with the descriptor's `key_id` and `signature`. `iltero_schemas.scanner_check_mappings.iac.descriptor.descriptor_digest(served)` computes it. |

The tool then verifies the ES256 signature over `signed` with `key`. No scanner result is read with the mapping until
it verifies.

`check_scanner_check_mapping_descriptor` first refuses a key that is not trusted or is revoked, then reads the
descriptor with `read_scanner_check_mapping_descriptor`.

### Reading a pinned mapping back

`iltero_schemas.scanner_check_mappings.read_scanner_check_mapping_descriptor(served, *, key_id, keys)` reads a
descriptor back as the mapping a run pinned under `key_id`, under any status of that key, for showing a run's mapping,
not for applying one. It raises `ScannerCheckMappingDescriptorError` naming the first rule that fails. It first refuses
a descriptor whose `key_id` is not `key_id`, or names a key the trust set `keys` never held: "the descriptor's key_id is
not the pinned one, or names a key the trust set never held". It then applies the mapping, digest and signature-form
rules of the table above, in that order, and returns the same `UnverifiedScannerCheckMapping`. The caller still
verifies the signature with the key's public key.

### Starter assertions in a served mapping

A stage of a run Iltero Platform opened applies only the served mapping, so the starter assertions this package ships
(`iltero_schemas.assertions.SHIPPED_ASSERTIONS`) are decided by scanner checks only when the served mapping carries
their entries. Those entries have one source, the [shipped mapping](#scannercheckmapping): for each starter assertion
the shipped mapping decides, the served mapping holds that entry unchanged, and it decides no other starter assertion.
An entry for an assertion that is not a starter is the served mapping's own and is not compared.

`iltero_schemas.scanner_check_mappings.served_mapping_problems(mapping)` takes a ScannerCheckMapping, read with its
model, and returns `(where, what)` pairs. It refuses nothing. A publisher can call it before signing a mapping to serve,
and a reader can call it on the mapping a checked descriptor carries.

| `where` | `what` |
| --- | --- |
| `spec.assertion_mappings` | "leaves out the shipped entry for `<id>`": a starter assertion the shipped mapping decides has no entry. |
| `spec.assertion_mappings.<index>` | "is not the shipped entry for its starter assertion": the entry differs from the shipped mapping's. |
| `spec.assertion_mappings.<index>` | "decides a starter assertion the shipped mapping does not decide". |

Problems are listed with the left-out entries first, sorted by assertion id, then the others by index. The list is
empty for a mapping built from the shipped one, such as the vector `scanner_check_mappings/iac/served_catalog.json`;
the [conformance vectors](02-conformance-vectors.md#vector-folders) in `scanner_check_mappings_served_invalid/` give
the list for changed copies of it.

## SigningKeys

The trusted signing keys file lists the public keys that sign what Iltero Platform serves: assertion bundles and
[scanner check mappings](#scannercheckmappingdescriptor). It ships inside the package
as `iltero_schemas/trust/signing-keys.json`, so a tool that pins one package version also pins the keys it trusts.

- **apiVersion:** `iltero.com/v1`, with `kind: SigningKeys`
- **Reader:** `iltero_schemas.trust.parse_signing_keys`, with the shipped mapping in `iltero_schemas.trust.SIGNING_KEYS`,
  the digest of the file's bytes in `iltero_schemas.trust.TRUST_FILE_DIGEST` and its `kind` in
  `iltero_schemas.trust.TRUST_FILE_KIND`

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion`, `kind` | string | `iltero.com/v1` and `SigningKeys`. |
| `keys` | list | Each key's `key_id`, `algorithm` (`ES256`), `public_key` (an uncompressed P-256 SubjectPublicKeyInfo, base64), `spki_sha256`, `status`, `valid_from`, `retired_at`, `revoked_at` and `revocation_reason`. |

Key rules:

- The file has exactly the fields `apiVersion`, `kind` and `keys` ("must have exactly the fields apiVersion, kind
  and keys"), with this `apiVersion` ("apiVersion: must be iltero.com/v1") and this `kind` ("kind: must be
  SigningKeys").
- A key id is 1 to 128 characters of lower-case letters, digits, `.`, `_` and `-`, starting with a letter or a digit.
  The pattern is `iltero_schemas.trust.KEY_ID_PATTERN`, for any program that names a key id.
- `active` keys sign and verify. `retired` keys only verify. `revoked` keys never verify again, whenever the
  signature was made.
- Keys are never removed. A status only moves forward: `active` to `retired` or `revoked`, `retired` to `revoked`.
- A key id starting with `dev-` (`iltero_schemas.trust.DEVELOPMENT_KEY_PREFIX`) is a development key. The reader
  refuses it, unless it is called with `development=True`, for a development tool's own local file; then every key
  must be a development key.
- Any change to the keys requires a new package version.
