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
- [BundleSigningKeys](#bundlesigningkeys)

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
| `BundleSigningKeys` | [The trusted bundle keys](#bundlesigningkeys) | `iltero_schemas.trust.parse_bundle_keys` |

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
| `APPROVAL` | `ILT.COMMON.CHANGE.APPROVAL.PRODUCTION_APPROVED`, `ILT.IAC.CHANGE.APPROVAL.SENSITIVE_CHANGE_APPROVED` |
| `SOURCE` | `ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED`, `ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT` |
| `CONTENT` | `ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN`, `ILT.IMAGE.DEPLOYMENT.CONTENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE` |
| `DRIFT` | `ILT.IAC.DEPLOYMENT.DRIFT.NO_DRIFT_AFTER_APPLY`, `ILT.IMAGE.DEPLOYMENT.DRIFT.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE` |
| `BUILD` | `ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT` |
| `CHECKS` | `ILT.IMAGE.ARTIFACT.CHECKS.TESTS_RAN`, `ILT.IMAGE.ARTIFACT.CHECKS.SCAN_RAN` |
| `PROVENANCE` | `ILT.IMAGE.ARTIFACT.PROVENANCE.SIGNED_PROVENANCE_MATCHES_RUN` |
| `HISTORY` | None |

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
| An `ILT` process assertion's area is one of `ASSERTION_AREAS`. | "an Iltero process assertion's area must be one of APPROVAL, BUILD, CHECKS, CONTENT, DRIFT, HISTORY, PROVENANCE, SOURCE" |

A new change type, provider, target kind or area adds a value to its list and changes no existing id.

An id that refers to an assertion, in an event, a record, an assertion mapping or a bundle, keeps only the general
shape: upper-case segments joined by dots, at least two, at most 96 characters
(`iltero_schemas.models.common.assertion.ID_PATTERN` and `ID_MAX_LENGTH`, which is `ASSERTION_ID_MAX_LENGTH`). A scanner
check mapping's id, such as `ILT.SCANNER_CHECKS.STARTER`, is not an assertion id and keeps the same general shape.

## AssuranceContext

The assurance context is the evaluation input: the one JSON document OPA receives for one assertion about one
subject. The tool that runs OPA records the context's digest in the event as `input_digest`.

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
| `deployment` | object | What the apply did: the applied `plan`, and `apply` with its `source` log, the `state` after it, or the `state_not_read` marker when it was not read (see [When the state after the apply was not read](#apply-with-the-state-not-read)), `outcomes_from` (`apply_log`; `apply_log_and_state` when the log lost messages and the state settled what it could; `apply_log_alone` when the state was not read), each change of the applied plan once (`changes`, each saying where its outcome came from in `outcome_from`: `apply_log`, `apply_log_alone`, `state` or `none`), `timing`, and `tool_data`: what only the IaC tool says, keyed by `tool`, which must be `apply.source.tool`. For `terraform`: the `summary` counts it reported, `errors_reported`, the number of error diagnostics the log holds (see [When the state after the apply was not read](#apply-with-the-state-not-read) for the rules on both), the `log_lines` it could not read (`other_output_lines`, `damaged_messages`, `interrupted_operations`), and the delete of each `deposed` object (an old copy a replacement set aside), settled by the state, or the `state_not_read` marker when it was not read. `superseded_by` is `{"reason": "dependency_replanned"}` when the pipeline says it applied a re-plan, which must differ from the evaluated plan, and `null` otherwise. In an `image_deploy` input, the image the pipeline reports it deployed (see [The `image_deploy` body](#the-image_deploy-body)). |
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

Key rules:

- The parts present are exactly those the profile of the evaluation's activity, stage and target kind provides. A
  part outside the profile is written as `null` and reads as absent, as does one left out. A missing required part
  or an extra part is refused, and the error names it. `evaluation`, `organization_scope` and `reference_time` are
  always required. A resource target also requires `resource`.

  | Activity | Stage | Required | Optional |
  | --- | --- | --- | --- |
  | `iac_change` | `plan` | `source`, `change`, `plan`, `subject` | none |
  | `iac_change` | `pre_deploy` | `source`, `change`, `plan`, `subject`, `evaluations`, `approvals`, `commit_review`, `run` | none |
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
served. No input carries an exception: no assertion reads one. Iltero Platform serves exceptions in a
[ServedExceptions](#servedexceptions) document.

| Item | Fields |
| --- | --- |
| Approval | `id`, `actor` (`provider`, and `id`: the provider's stable account id, never a login, a name or an address), `roles`, `status` (`approved`), `subject`, `method` (`ci_deployment_review` or `iltero_review`), `independence` (`independent` when the approver neither started the run nor triggered the attempt; `self_permitted_by_policy` otherwise, with the permitting `policy_version`, `null` when independent), `timestamp`. An approval from a CI deployment review names no role, since none is verified. |
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

| `provenance` field | Meaning |
| --- | --- |
| `run` | The run `id` and the `unit`. A unit is the part of a project the IaC tool plans and applies as one. |
| `source_commit`, `checked_content` | The commit and the [checked content](#checked-content) the evaluation is about. |
| `input_digest` | The digest of the assurance context the evaluator received. |
| `evaluator` | The engine that produced the verdict. For `opa`: its `version`, binary `digest` and the `limits` applied: `timeout_seconds`, `memory_limit`, `max_output_bytes`, `evaluations_per_process`, `capabilities_digest` and `platform`. For a scanner (`checkov` or `trivy`): the `version` the scanner wrote into its report (`null` for a member of a scanner requirement that gave no report), the `digest`, `platform` and `python_version` of what the Iltero CLI ran, `null` unless it ran the scanner itself (see below), and what its verdict rests on (see [Evaluations from a scanner's results](#evaluations-from-a-scanners-results)). |
| `bundle` | The bundle the program came from: `kind` (`server` or `local_bundle`), `tarball_digest`, the SHA-256 of the bytes of the bundle tarball the evaluator loaded, `content_digest` and `key_id`. For `server`, they are the served [descriptor](#assertionbundledescriptor)'s `tarball_digest`, `content_digest` and `key_id`. For `local_bundle`, `tarball_digest` is the digest of the tarball the tool built, and `content_digest` and `key_id` are `null`, because a bundle the tool built has no descriptor. Any other combination is refused: "a bundle names its content digest and signing key exactly when its kind is server". The writer's claim: nothing compares these values with a descriptor. Present exactly when the evaluator is `opa`. An evaluation whose `assertion_source` is `server_bundle` and that ran over a bundle names a bundle of kind `server`; otherwise it is refused: "an assertion from the server's bundle is evaluated over the server's bundle". |
| `scanner_checks` | The scanner checks entry of a [scanner check mapping](#scannercheckmapping) whose checks decided the evaluation, by its `digest` alone (`ScannerChecksRef`). Present exactly when the evaluator is a scanner; otherwise it is refused: "a scanner checks entry is named exactly when a scanner's result was read for this evaluation". |
| `assertion_source`, `assertion_source_digest` | Where the assertion came from, and its source digest. `server_bundle`: an assertion bundle Iltero Platform served. `local`: the project's own files; `custom_rego` when hand-written in Rego. A record of a run Iltero Platform opened has only `server_bundle`. `contract_starter`: a starter assertion this package ships, added to a local run. The writer's claim. |
| `compiled_digest`, `compiler` | The compiled program's digest, and the compiler's `version`, `contract_version`, `contract_digest` and `install` (`wheel` or `editable`). Absent for a scanner. |
| `executor` | Who ran the evaluation: `type` (`human` or `workload`), `provider` (`local`, `ci` or a CI system such as `github_actions`) and the CI system's run id (`ci_run_id`). |
| `facts_source` | For an evaluation whose input may carry Iltero Platform facts (approvals, earlier evaluations, the commit review, the verified source, the verified attestation: an `iac_change` input at `pre_deploy`, an `image_build` input at `plan`, and an `image_deploy` input at `pre_deploy`), where they came from: `server` or `none`. `null` for every other input (`iltero_schemas.profiles.reads_server_facts`). It names where the facts document came from: the parts only Iltero Platform holds (`SERVER_FACTS`: `evaluations`, `approvals`, `commit_review`, `verified_source`, `attestation_outcome`). A value Iltero Platform supplies inside another part is not counted: the environment's production flag (`organization_scope.environment.production`) in every input, and the accepted build (`change.build`) in an `image_deploy` input. In a run the tool opened, such a value holds the unknown marker (`server_facts_unavailable`), so it follows `governance.run_opened_by`. The `post_deploy` and `post_verify` inputs of an `image_deploy` name no `facts_source`. |

Key rules:

- `status` is one of six values. Only `pass` and `fail` may omit `status_reason`, and a reason must belong to its
  status:

  | Status | Reasons |
  | --- | --- |
  | `pass` | none |
  | `fail` | none: a failure's reason is the policy's `policy_reason` |
  | `unknown` | `known_after_deploy`, `redacted`, `path_missing`, `not_a_list`, `unspecified`, `server_facts_unavailable`, `not_reported_by_tool`, `deployment_log_incomplete`, `state_not_read`, `kind_unmapped`, `scanner_result_unresolved`, `scanner_report_incomplete` |
  | `not_applicable` | `when_guard_excluded`, `no_subject_in_scope` |
  | `not_evaluated` | `scanner_not_run`, `credential_denied`, `resource_type_unsupported`, `scanner_version_not_allowed`, `timeout`, `subject_unresolved`, `evaluator_unavailable`, `identity_unverified`, `stage_not_run`, `suppressed_in_source`, `tool_reports_only_failures`, `no_result_of_the_mapped_checks`, `no_result_in_the_report`, `no_scanner_report` |
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
  | An assertion from the project's own files (`local` or `custom_rego`, `iltero_schemas.models.common.event.PROJECT_ASSERTION_SOURCES`) has an id whose namespace does not start with `ILT`. | "an assertion from a project's own files has an id outside ILT" |
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
  | A `scanner_not_run` evaluation names no `digest`, `platform` or `python_version`. | "a scanner that gave no report names no digest or platform of a program that ran, since none did" |
  | A `scanner_not_run` evaluation has empty `result_addresses`, `unknown_paths` and `failed_rule_ids`, and its `undecided_rule_ids` are its `rule_ids`. | "a scanner that gave no report decided none of its mapped checks and read no resource" |
  | A `no_result_of_the_mapped_checks` evaluation has the same empty lists, and its `undecided_rule_ids` are its `rule_ids`. Unlike `scanner_not_run`, it names its scanner's `version` and its `provenance.input_digest`. | "a scanner whose report holds no result of its mapped checks decided none of them and read no resource" |
  | A `no_result_in_the_report` evaluation has the same empty lists, and its `undecided_rule_ids` are its `rule_ids`; it also names its scanner's `version` and its `provenance.input_digest`. | "a scanner whose report holds no result at all decided none of its checks and read no resource" |

  A scanner `evaluator` (`iltero_schemas.models.common.scanner_evaluator.ScannerEvaluator`) also names what the verdict
  rests on. Each list is sorted, each item once ("rule_ids is sorted, each once", with the field's name):

  | Field | Meaning |
  | --- | --- |
  | `digest`, `platform`, `python_version` | What the Iltero CLI ran, when it ran the scanner itself (its report's `ran_by: iltero_cli`); otherwise each is `null`. `digest` is the digest of the scanner's program, or of the hash lock of its Python packages. `platform` is in the words of the OPA evaluator's `limits.platform`, such as `linux-x86_64` or `linux-aarch64`. `python_version` is the interpreter tag the packages were locked for: `cp`, the major and minor version, and `t` for a free-threaded build, such as `cp312` or `cp313t`. `digest` and `platform` are named together, and `python_version` only with them: "a scanner's digest and platform are named together, and its Python version only with them". |
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
| `governance` | object | `run_opened_by`: `server` when the writer says Iltero Platform opened the run, `local` when the tool opened it on its own. Only Iltero Platform confirms that it opened a run, by its `run.id`. |
| `subject` | object | What the record is about (`iltero_schemas.models.common.record_subject.RecordSubject`): `kind: change`, the `environment`, the `unit`, the `source`: the code the change comes from, in the shape of an [AssuranceContext](#assurancecontext)'s `source`, the `project_directory`: the project's directory relative to the repository's root, `.` for the root (`iltero_schemas.models.common.fields.DirectoryPath`), and the `project_tree`: that directory's git tree at the record's commit (see the project tree rule below). Every project path the record names is relative to it, and a reader can follow one to the repository only with the record's repository and commit; a record of a local run may name no repository. `project_directory` and `project_tree` are not part of `source`, which an evaluation reads, so they change no evaluation input. `project_tree` is `{"id": <git object id>}` (`ProjectTree`), required: git's id of the names, file modes and contents of every file git tracks under the project directory at the commit, the commit's root tree for `.`. It covers no uncommitted, untracked or ignored file, no file outside the directory, a submodule only by the commit it points at, and no variable, state or tool version. Its `id` uses the same hash as `source.commit.sha`, both 40 characters or both 64: "the project tree's id and the commit's id use the same hash: both are 40 or both 64 characters long". `project_directory` follows the directory rule below: a bad value is refused with "must be '.' or a relative path with no '..', '.', empty part, ':' or leading '/'", or "must name each part plainly: not only dots and spaces, and with no character that looks like a separator or a colon". |
| `change` | object | The change the record is about: the body of its [activity](#change-types-and-activities), named by `change.activity` (see [The `iac_change` body](#the-iac_change-body), [The `image_build` body](#the-image_build-body) and [The `image_deploy` body](#the-image_deploy-body)). |
| `units_file` | object or null | The project's [units file](#units-file) as the writer read it. `null` for a project that declares none. |
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
| The review was decided no later than the stage's `observed_at`. | "the pre_deploy stage's commit review was decided no later than the stage observed it" |
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

`descriptor_digest` and `key_id` are present exactly when `origin` is `served`: "a scanner check mapping names its
descriptor and signing key exactly when it was served". Iltero Platform compares the mapping's `digest`,
`descriptor_digest` and `key_id` with the values it pinned when it opened the run.
For a served mapping, a reader with the kept files checks only that each scanner verdict's entry is in the stage's
copy of it. The contract does not compare its `key_id` with the stage bundle's, or check that its id is in Iltero's
namespace: Iltero Platform's comparison with the pinned values covers the served mapping.

Each `reports` entry (`ScannerReport`):

| Field | Type | Meaning |
| --- | --- | --- |
| `tool` | string | `checkov` or `trivy`. |
| `tool_version` | identifier | The version the scanner wrote into its report. |
| `ran_by` | string | Who ran the scanner: `pipeline`, which gave the stage the report, or `iltero_cli`, the Iltero CLI, which ran the scanner itself on the runner (`iltero_schemas.models.common.scanners.PIPELINE` and `ILTERO_CLI`). It is the record's own claim: nothing in the record shows which program ran. A record of a run Iltero Platform opened keeps only reports the Iltero CLI ran: "a record of a run the server opened keeps only scanner reports the Iltero CLI ran". |
| `input_kinds` | list | What the scanner read, in the contract's words (`plan`, `deployed_resources`): sorted, each once ("input_kinds is sorted, each kind once"), at most 16 (`iltero_schemas.models.common.car.MAX_INPUT_KINDS`). |
| `report_digest` | digest | The digest of the report as the stage kept it, redacted and canonical, the digest of an entry of the evidence register. That entry's `source` is the report as the pipeline gave it. Every evaluation from the report names it as its `input_digest`. |
| `observations` | string | Where the stage kept the [ScannerObservations](#scannerobservations) it read from the report, in the record's directory, the path of an entry of the evidence register. |
| `results_read` | integer | The results the observations hold, from 0. |
| `unreadable_results` | integer | Results of the report the stage could not read, from 0. Each decides nothing. |
| `written_configuration_results` | integer | Results about the configuration as written, which no stage reads, from 0. They are left out of the observations' `results`. |
| `tool_parsing_errors` | integer or null | Files the scanner itself says it could not parse, from 0, or `null` when the scanner does not say (Trivy). A value above 0 means the scanner did not cover everything it was given; 0 does not show that everything was parsed. |
| `results_not_listed` | integer or null | Results the scanner's own summary counts that its report does not list, from 0, such as the passes Checkov leaves out when run with `--quiet`; `null` when the scanner writes no counts (Trivy). A value above 0 means the report is not read in full; 0 does not show that every check ran, only that every result the scanner counts is listed. |
| `redacted_values` | object | For each reason, how many redaction markers that stand for a value (`present: true`) the report holds as the stage kept it; `{}` when it holds none. Each key is a reason token (`iltero_schemas.models.common.redaction.RedactionReason`), each count is at least 1, and at most 64 reasons are listed (`MAX_REDACTION_REASONS`). |

`redacted_values` says what the kept report file holds, not what the redaction policy did. A marker in a field the
[kept form](#the-report-a-stage-keeps) drops is not in the file, so it is not counted. A reader counts with
`iltero_schemas.models.common.redaction.redacted_value_counts`, which walks the object values and list items of the kept
report, never its keys and never the inside of a marker. A marker at a field the reader reads, such as a rule id or an
address, makes that result unreadable, so it is also counted in `unreadable_results`.

A stage's redaction report (`redaction`) says what the stage's redaction hid, left unknown or allowed, by
path. It holds no value.

| Field | Type | Meaning |
| --- | --- | --- |
| `policy` | object | The redaction policy that ran: `id`, `version` (identifiers) and `digest`. |
| `input` | object | What was redacted: `kind` and the `digest` of the redacted tree. The `kind` is what the stage reads: `observation` at `plan`, `facts` at `pre_deploy`, `deployment` at `post_deploy`, `drift_check` at `post_verify` (`iltero_schemas.models.common.stages.REDACTED_INPUT_KIND`): "the pre_deploy stage's redaction report is of the facts it read". A post-verify stage's `resource_redaction` is of kind `post_apply_resources`: "the post-verify stage's resource redaction is of the values after the apply". |
| `redacted` | list | Each path the policy hid: `path`, and `reason`, a token of a lowercase letter followed by up to 63 lowercase letters, digits or `_`. |
| `unknown` | list | The paths left unknown. |
| `allowed` | list | Each path the project allowed through: `path`, and `reason`, the project configuration's own words: one line of plain text, at most 1024 characters. |

At `post_deploy` and `post_verify` the record keeps the part the stage counts as it is, so the redaction report is of
that part and redacts nothing (`iltero_schemas.models.common.stages.STAGES_THAT_REDACT_NOTHING`). Its `input.digest` is
the stage's `coverage.subjects_in_scope.source_digest`, the digest of the record's `change.deployment` at `post_deploy`
and of its `change.drift_check` at `post_verify`: "the post_deploy stage's redaction report is of the part it counts".
Its `redacted`, `unknown` and `allowed` lists are empty: "the post_verify stage redacts nothing: the part it counts is
kept as it is".

A path is a path in the redacted tree. Map keys are part of it, so it is kept as written: any characters, at most
64 KiB of UTF-8 (`iltero_schemas.models.common.fields.RAW_TEXT_MAX_BYTES`). A reader escapes it to show it, control,
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
| 1 | `identity_redacted` | Any naming field holds a whole redaction marker (`__redacted: true`, `reason`, `present`, `type`; `iltero_schemas.models.common.redaction.RedactedMarker`), whatever the other naming fields hold. |
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
| `deferred_changes`, `related_copies_omitted`, `unresolved_references`, `checked_after_deployment`, or a `not_evaluated` or `error` [status reason](#assuranceevent) | `count`: integer from 1 | How many of one thing are missing: what the plan left out, checks the plan stage [postponed until after the deployment](#checks-postponed-until-after-the-deployment), or combined verdicts the reason left without a decision (see below). |
| `state_not_read` | none | The state after the apply was not read, so no outcome of the apply was held to it (`StateNotReadGap`; see [When the state after the apply was not read](#apply-with-the-state-not-read)). |
| `evaluator_did_not_decide` | `engine`, `reason`, `count`: integer from 1 | How many of the stage's evaluations by one evaluator (`engine`, as its events name it) could not decide an assertion about a subject, where the subject's combined verdict does not count them, and why (`reason`, a `not_evaluated` or `error` [status reason](#assuranceevent)) (`EvaluatorDidNotDecideGap`; see below). |

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
- These files that a record's stages and events name are entries of its evidence register
  (`iltero_schemas.models.common.register.check_register`):

  | File | Matched by | Refused with |
  | --- | --- | --- |
  | Each stage's events file | Its `path` and `digest`, on an entry with `canonicalization: RFC8785` | "the plan stage's events file is an entry of the evidence register", or "the plan stage's events file is kept as canonical JSON (RFC8785)" |
  | Each stage's assertion index | Its `index` and `digest` | "the plan stage's assertion index is an entry of the evidence register" |
  | Each stage's copy of each scanner check mapping it applied | Each `scanners.scanner_check_mappings` entry's `copy_path` and `digest` | "the evidence register lists the copy of each scanner check mapping the plan stage applied" |
  | What a stage read from each scanner report | The report's `observations` path | "the observations the plan stage read from its checkov report are an entry of the evidence register" |
  | Each scanner report as the stage kept it | The report's `report_digest`, on an entry that names a `source` and a `redaction_policy` and was collected as that scanner's report (`collector.tool` is the report's `tool`). Every such entry was redacted from the same pipeline file (one `source.digest`). | "the checkov report the plan stage kept is an entry of the evidence register, redacted from the file the pipeline gave" |
  | The input every event was evaluated over | Its `provenance.input_digest` | "the input every event was evaluated over is an entry of the evidence register" |
  | What the plan stage redacted | Its `redaction.input.digest`, on an entry that names a `redaction_policy` | "what the plan stage redacted is an entry of the evidence register that names the redaction policy" |
  | Each stage's copy of the project's exceptions file | `scanners.local_exceptions.copy_path` and `digest`, on an entry that names the file as its `source` (`source.name` is the file name of `file_path`, without its directories, and `source.digest` is `digest`) and have no `redaction_policy` and no `canonicalization`: the copy is the file's bytes, unredacted and as the project wrote them | "the plan stage's copy of the project's exceptions file is an entry of the evidence register, copied byte for byte from the file it names" |
  | Each stage's copy of the exceptions Iltero Platform served it | `served_exceptions.copy_path` and `digest`, on an entry of its own (no events file, assertion index or scanner file) with `canonicalization: RFC8785`, `source: null` and no `redaction_policy` | "the plan stage's copy of the exceptions the server served it is an entry of the evidence register of its own, kept as canonical JSON (RFC8785) and not copied from a file the pipeline gave" |

  The scanner files are tied to where they came from:

  | Rule | Refused with |
  | --- | --- |
  | The register entry of the copy of a project's scanner check mapping names the file the mapping was read from as its `source`, with `source.name` equal to the last part of that entry's `file_path`, the file's name. The register entry of the copy of the shipped or the served mapping has no `source`. | "in the evidence register, the copy of a project's scanner check mapping names the file it was read from, and the copy of the shipped or the served mapping names no file" |
  | Each scanner file a stage keeps (each scanner check mapping copy, its observations, the entry of each kept report, and the copy of the project's exceptions file) is an entry of its own: never another scanner file, nor any stage's events file or assertion index. The digest of a kept report or of its observations is never the `input_digest` of an evaluation that stands on no scanner's result. | "each scanner file a stage keeps is an entry of its own, not a file the record names for another part" |
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
  not stop the pipeline; a missing check, or a check whose evaluator failed, always does. Only the plan and pre-deploy
  stages can be `advisory`; a stage after the deployment is always `enforcing`. In a run Iltero Platform opened, Iltero
  Platform's policy sets it; otherwise it is the tool's choice. It is the writer's claim; only the CI job's own result
  shows what the pipeline did.
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
  lists together hold at most `resources_read` entries. `first_reading_digest` and `second_reading_digest` differ.
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
  does not". In an `iac_change` record, `ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN` must be `pass`
  exactly when `change.deployment.plan` has the evaluated plan's `digest`, `artifact_digest` and
  `artifact_digest_source`, and `fail` otherwise; `ILT.IAC.DEPLOYMENT.DRIFT.NO_DRIFT_AFTER_APPLY` must be `pass` exactly
  when `change.drift_check.differences_count` is 0, and `fail` otherwise. An event of either check whose status is one a
  policy answers with (`pass`, `fail`, `unknown` or `not_applicable`,
  `iltero_schemas.models.common.event.POLICY_STATUSES`) and not the recomputed one is an integrity failure at
  `events.<index>.evaluation.status`: "is not fail, what the record's change gives". An event that is `not_evaluated` or
  `error` decides nothing and is not compared. The `image_deploy` checks are recomputed the same way (see [The
  `image_deploy` body](#the-image_deploy-body)). The change digest problems come first, so a forged `change.digest` is
  refused as `change.digest is not the digest of the change type, unit, environment and plan`. A reader that reports
  integrity failures itself sets `SKIP_INTEGRITY_CHECKS` (`iltero_schemas.models.common.car`) to `True` in the
  validation context (any other value is ignored), then calls `iltero_schemas.models.common.stages.integrity_problems`,
  which returns every problem as a `(where, what)` pair. An approval of another run is refused whatever the context.
  Every reader of an `iac_change` record, with or without that key, calls
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
  record's change type, its `unit`, its `subject.environment` and its checked content. Approvals bind to it. An
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
- These rules establish consistency only. An unsigned record cannot prove that Iltero Platform opened its run. Only
  Iltero Platform can confirm a run, by its `run.id`.
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
| `no_resource_in_scope_for_any_check` | No required assertion had a subject in scope: every `subjects_per_assertion` entry is 0. Listed only when none had one. | `no required assertion had a subject in scope` |
| `no_assertion_required` | The stage was required to evaluate no assertion: `assertions_required.value` is 0. | `the stage was required to evaluate no assertion` |

A record's evidence status lists every reason of every stage, each naming its stage, and the two reasons only a record
holds (`iltero_schemas.models.common.record_coverage.record_evidence_status`). For example, a record whose `plan`,
`post_deploy` and `post_verify` stages reported without its `pre_deploy` stage is `has_gaps` with
`expected_stage_not_reported` for `pre_deploy`. Every cause also stays in the stage's `coverage`: its gaps, its
substituted inputs and its counts.

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
stage's coverage does not exclude for its identity (`identity_redacted` or `identity_unnameable` in
`coverage.subjects_in_scope.excluded`, matched by `plan_index`; `iltero_schemas.models.iac.scanner_scope.plan_scope`). A
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
| The evaluator names `digest` and `platform` exactly when its report's `ran_by` is `iltero_cli`, and `python_version` as well exactly when that scanner is installed as Python packages (`INSTALLED_AS_PYTHON_PACKAGES`: Checkov). | "an evaluation from a scanner's results names the digest and platform of what ran exactly when the Iltero CLI ran the scanner, and the Python version only for a scanner installed as Python packages" |
| The mapping named as shipped (`origin: shipped`), when the stage applies it, is the one this package ships, `iltero_schemas.scanner_check_mappings.SHIPPED_MAPPING`: the same `id`, `version`, `digest` (`SHIPPED_MAPPING_DIGEST`) and `assertions_mapped`. | "the plan stage's scanner check mapping named as shipped is the one this package ships" |
| A scanner verdict on an assertion from Iltero Platform's bundle (`assertion_source: server_bundle`) needs the served mapping among the stage's scanner check mappings. A reader with the kept files works out the entry that decided it from the stage's kept copy of that mapping. | "a scanner verdict on an assertion from the server's bundle comes from the scanner check mapping the server served" |
| A scanner verdict on an Iltero starter assertion (`assertion_source: contract_starter`) names a scanner checks entry of the shipped mapping (`SHIPPED_SCANNER_CHECKS`), and the shipped mapping maps that assertion (`SHIPPED_MAPPING_ASSERTIONS`). | "a scanner verdict on an Iltero starter assertion comes from a scanner checks entry in the mapping Iltero ships" |
| A scanner verdict on one of the project's own assertions needs a project's mapping among the stage's scanner check mappings, and names no scanner checks entry of the shipped mapping. | "a scanner verdict on one of the project's own assertions comes from a scanner checks entry in the project's own mapping" |

#### The check a reader runs

The scanner check mappings, the observations, the report, the plan and the assertion documents are files the record
keeps, not part of the record, so the model cannot check them alone.
`iltero_schemas.models.iac.scanner_results.scanner_evidence_problems(car, files)` does, on a record whose structure
holds; a reader calls it through [`kept_file_problems`](#checking-a-record-against-its-kept-files). `files` is a
`KeptFiles` (`iltero_schemas.models.iac.kept_files`), each file as read from its JSON or YAML, except the exceptions
files, which are given as their bytes, unparsed, so the contract checks their digest and reads them one way for every
reader:

| Field | Keyed by |
| --- | --- |
| `scanner_check_mappings` | The `copy_path` of each entry of the stage's `scanners.scanner_check_mappings`. |
| `observations` | Each report's `observations` path. |
| `reports` | Each report's `report_digest`. |
| `plans` | The digest of the plan as the stage kept it, redacted (`ScannerObservations.plan_digest`, the digest of the one plan of the evidence register). |
| `assertions` | The digest of each assertion document (`AssertionRef.digest`). |
| `local_exceptions` | The `digest` of each stage's `scanners.local_exceptions`; each value is the bytes of the stage's copy. |
| `served_exceptions` | The `digest` of each stage's `served_exceptions`; each value is the bytes of the stage's copy. Read by [`served_exception_problems`](#checking-the-kept-copy). |

For each stage that keeps `scanners`, it reads the copy of each scanner check mapping, then each report's
observations, rebuilt from the kept report and plan by the tool's reader, then every evaluation the mappings and those
observations give, and the `scanner_not_run` evaluation of each member of a scanner requirement that gave no report.
When the stage kept no report, it reads the subjects in scope from the one plan of the evidence register. It returns
`(where, what)` pairs. Among them:

| Where | What | Meaning |
| --- | --- | --- |
| `stages.<stage>.scanners.scanner_check_mappings.<n>` | "is not given", "is not a scanner check mapping", "does not name its copy's digest", "does not name the copy's id, version and number of assertions mapped", "is a project's mapping in Iltero's namespace, or one that decides an assertion of it" | The copy of the mapping at position `<n>` of the list, counted from 0, does not hold. Every copy that does not hold is listed, and no other problem of the stage. |
| `stages.<stage>.scanners` | "keeps no one plan its scanner reports can be read against" | The evidence register does not hold exactly one plan collected for the stage's IaC tool (`collector.tool: terraform_plan`, `iltero_schemas.models.iac.tool_names.PLAN_COLLECTORS`). |
| `stages.<stage>.scanners.reports.<index>` | "names observations that are not the ones its report and plan give", "does not count what its observations hold" (`results_read`, `unreadable_results`, `written_configuration_results`, `tool_parsing_errors` or `results_not_listed`), and the other report problems | The observations, the report or the plan do not hold. The report's evaluations are not checked further. |
| `stages.<stage>.scanners.reports.<index>` | "names observations of another report" | The kept observations name another `tool`, `tool_version`, `ran_by`, `report_digest` or `input_kinds` than the report entry. The report's evaluations are not checked further. |
| `stages.<stage>.scanners.reports.<index>` | "keeps more of its scanner's report than the contract keeps" | The kept report is not its own [kept form](#the-report-a-stage-keeps): the canonical bytes of what `kept_report` gives for it are not the report's. |
| `stages.<stage>.scanners.reports.<index>` | "does not count, for each reason, the redacted values the report the stage kept holds" | `redacted_values` is not what `redacted_value_counts` gives for the kept report. It is checked wherever the kept report is checked, after its kept form. |
| `stages.<stage>.coverage.subjects_in_scope.excluded.<n>` | "leaves out a resource for a reason the plan the stage kept does not give" | The plan does not say of the resource at the exclusion's `plan_index` what the exclusion says (`iltero_schemas.models.iac.scanner_scope.exclusion_holds`): the plan has no resource there; the exclusion's `id` is not the address the plan wrote there, when that address is text, or is not `null`, when it is not; or the exclusion's `reason` is not exactly the one the plan gives for that resource (see the order of reasons under `coverage.subjects_in_scope.excluded` in [Change Assurance Record (CAR)](#change-assurance-record-car)). Every exclusion is checked, against the plan the stage kept, for a stage that keeps a scanner report or names a scanner requirement. |
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
| `events.<index>.assertion` | "names an assertion document that is not given" | No valid document with the event's digest, id and version was given. |
| `stages.<stage>.scanners.local_exceptions` | "the record does not keep an exceptions file with the digest the stage names" | No bytes are given under the stage's `digest`, or their SHA-256 is not that digest. The stage's suppressed results are not checked further. |
| `stages.<stage>.scanners.local_exceptions` | "is not a project's exceptions file the contract can read" | `read_local_exceptions` refuses the copy (see [Reading the file](#reading-the-file)). The stage's suppressed results are not checked further. |
| `events.<index>.provenance.evaluator.local_exception` | "names an exception the kept exceptions file does not give this result" | A `suppressed_in_source` evaluation names an exception, but the kept file gives the result none, or another one. |
| `events.<index>.provenance.evaluator.local_exception` | "names no exception, but the kept exceptions file gives this result one" | A `suppressed_in_source` evaluation names no exception, but the kept file gives the result one. |

The vectors in `scanner_evidence/iac/local_run_scanned/` give the complete list of cases.

#### What these checks establish

Together, the record's rules and `scanner_evidence_problems` establish that each evaluation from a scanner's results
is the verdict the kept report, read against the kept plan, gives the subject under the scanner checks entry its stage
kept, and that every subject in scope has one. They do not establish:

- that the scanner ran, or that the kept report is what the scanner wrote: the record says who ran it (`ran_by`), and
  the writer redacts and keeps the report;
- that the Iltero CLI ran the scanner, or which program it ran: `ran_by` and the evaluator's `digest` and `platform`
  are the record's own claim, and copying the pinned values into a record is all it takes. Like the OPA evaluator's
  pinned binary, they are at best claimed by the record, never verified. In a run the tool opened, `iltero_cli` claims
  no more than `pipeline`;
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

### Checking a record against its kept files

The model checks a record's structure and, unless `SKIP_INTEGRITY_CHECKS` is set, every value it can recompute from
the record alone. The rest of what an `iac_change` record claims rests on the files its stages kept.
`kept_file_problems(car, files)` (`iltero_schemas.models.iac.kept_file_problems`) makes every check a reader makes of
such a record, and returns the `(where, what)` pairs of each, in this order:

| Function | What it works out again |
| --- | --- |
| `iltero_schemas.models.common.stages.integrity_problems(car)` | Every value the record can recompute from itself, such as its digests, counts, verdicts and evidence statuses. |
| `iltero_schemas.models.iac.scanner_results.scanner_evidence_problems(car, files)` | Each scanner verdict, and each project exception a suppressed result names (see [The check a reader runs](#the-check-a-reader-runs)). |
| `iltero_schemas.models.iac.exception_evidence.served_exception_problems(car, files)` | The failed results the exceptions Iltero Platform served cover (see [Checking the kept copy](#checking-the-kept-copy)). |
| `iltero_schemas.models.iac.postponed_checks.postponed_check_problems(car, files)` | The checks the plan stage postponed (see [Checks postponed until after the deployment](#checks-postponed-until-after-the-deployment)). |

Every reader of an `iac_change` record calls it, on a record whose structure holds
(`iltero_schemas.models.common.stages.check_structure`), read with or without `SKIP_INTEGRITY_CHECKS`, with the
[`KeptFiles`](#the-check-a-reader-runs) its stages kept. It must not trust the record while the list holds any problem.
An empty list means every check a reader can make holds, a verdict whose every failure is excepted included. What only
Iltero Platform can check, such as whether a kept copy is what it served, stays unchecked.

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
| `project_may_leave_out` | `pre_deploy`, `post_verify`. | None. | `post_verify`. |
| `environment_policy_may_leave_out` | `post_verify`. | None. | `post_verify`. |
| `not_supported(record)` | `post_verify` when the record's IaC tool has no drift reader; none for `terraform`. | None. | `post_verify`, whatever the record: the workload may be of a kind no reader reads, such as one a cloud's own service runs. |
| `required_documents` | The record at every stage, and the [resource identities](#resourceidentities) document (`resource_identities`) at `post_deploy` as well. A record whose state after the apply was not read names no identities; the `post_deploy` stage must still keep the document. | The record at `plan`. | The record at every stage. |
| `named_documents(record)` | None. | At `plan`, `image_index`, the raw index, only when the change's `index_evidence_ref` names one, by its `ref_id` in `evidence_refs`. A stage never has to keep the build tool's metadata file or the reports. | None. |
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
compares `platform_digests` with the function's result. The plan stage must keep the raw index as its `image_index`
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
| Each file's `evidence_refs` entry has a `source`, whose `digest` is the digest of the file as the pipeline gave it, before redaction, which differs from the stored `digest` when redaction changed the file. | "the pod list read names the digest of the file as the pipeline gave it, in its source", or the same for each other file |
| Each file names the redaction policy that ran over it (`redaction_policy` is not `null`). The rule that a record redacts under one policy makes it the record's policy. | "the workload read before the pods were listed names the redaction policy that ran over it", or the same for each other file; a file redacted under another policy: "every stage and every redacted evidence file name the same redaction policy" |
| No file is the tag's metadata file (`image.tag_resolution.read_from_evidence_ref`). | "the workload read before the pods were listed is not the tag's metadata file", or the same for each other file |
| Every container, in `template_containers` or in `containers_read`, whose `image_reference` names `change.image.repository`, in its one spelling, is `compared`. | "a reading compares every container whose image is from the deployed repository" |
| An `image_reference`'s digest is `sha256:` and 64 lower-case hexadecimal characters, its tag is one a registry accepts, and its repository is at most 255 characters and follows the image repository rules. | "an image reference's digest is sha256: and 64 lower-case hexadecimal characters", "an image reference's tag is one a registry accepts", "an image reference's repository is at most 255 characters", or a message of the image repository rules |
| The `pre_deploy` stage evaluates `ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT`, the `post_deploy` stage `ILT.IMAGE.DEPLOYMENT.CONTENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE`, and the `post_verify` stage `ILT.IMAGE.DEPLOYMENT.DRIFT.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE`, each exactly once and never as `not_applicable` (see `always_evaluated` above). | "ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT is evaluated once, at the pre_deploy stage, once it has reported", or the same for the others; a `not_applicable` event: "ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT always applies to the pre_deploy stage's one subject" |
| An `ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT` event that was not evaluated, or that ended in `error`, gives a fault of the evaluator as its reason: `timeout` or `evaluator_unavailable` for `not_evaluated`; `evaluator_crash`, `evaluator_timeout`, `evaluator_memory_limit`, `output_overflow`, `output_contract_violation`, `bundle_verification_failed` or `compile_failure` for `error`, never `adapter_parse_failure` (`iltero_schemas.models.common.event.EVALUATOR_FAULT_REASONS`). | "ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT is not_evaluated only for a fault of the evaluator, never for want of the change or its facts", or the same with `error` |
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
| `properties` | object | Twelve properties, each a result (`PropertyResult`) with a `state`, a `reason` and a `detail`. |

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
| `plan_apply_match` | The approved plan is the applied plan. |
| `runtime_verification` | A verification after the deployment ran. |
| `deployment_coverage` | No deployment visible to the verifier is missing a record. |
| `exceptions` | Every exception relied on was approved and in force at the reference time of the stage that relied on it. |
| `commit_review` | Every commit the change ships was reviewed. |
| `reference_time` | Every stage took its reference time, which every expiry and ordering comparison uses, from a source a verifier can trust. |
| `evaluator_binary` | Every evaluation ran on the binary of the Open Policy Agent (OPA) release this contract pins, for its platform. |

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
  | `approval_identity`, `exceptions`, `commit_review` | `not_assessed` | `not_in_activity` | The record's activity has no pre-deploy stage, as an image build has none. |
  | `approval_identity`, `exceptions`, `commit_review` | `not_assessed` | `pre_deploy_out_of_scope` | The record leaves the pre-deploy stage out of scope. |
  | `approval_identity`, `exceptions`, `commit_review` | `not_performed` | `run_opened_locally` | The tool opened the run, so Iltero Platform served no approval, exception or commit review, and no check of one happened. |
  | `approval_identity`, `exceptions`, `commit_review` | `not_assessed` | `pre_deploy_pending` | The record expects the pre-deploy stage, and the run that would report it is still in progress. |
  | `approval_identity`, `commit_review` | `could_not_decide` | `server_facts_unavailable` | Iltero Platform opened the run, a check needed the fact, and the pre-deploy stage kept the unknown marker in its place. |
  | `approval_identity`, `commit_review` | `not_assessed` | `not_read_by_the_stage` | None of the pre-deploy stage's results read the fact, so the stage kept the `not_read_by_the_stage` marker. |
  | `exceptions` | `claimed_by_record` | `project_exception_relied_on` | An event names an exception from the [project's own exceptions file](#localexceptions): the project's own word. |
  | `exceptions` | `claimed_by_record` | `project_exceptions_file_not_relied_on` | A stage applied the project's own exceptions file, and no event relied on an exception from it. |
  | `exceptions` | `not_assessed` | `served_exceptions_not_assessed` | Iltero Platform opened the run, the record relies on no exception of the project's own, and a verifier does not assess the exceptions Iltero Platform served. |
  | `bundle_provenance` | `claimed_by_record` | `server_bundle_named` | A stage names an assertion bundle Iltero Platform served. |
  | `bundle_provenance` | `not_performed` | `local_assertions` | The checks were the project's own. |
  | `stage_completeness` | `claimed_by_record` | `expected_stages` | Every stage the record expects reported. |
  | `stage_completeness` | `not_assessed` | `stages_pending` | The run is still in progress. |
  | `stage_completeness` | `failed` | `stage_not_reported` | The record is finished, and a stage it expects was never reported. |
  | `plan_apply_match` | `not_assessed` | `not_in_activity` | The record's activity applies no plan. |
  | `plan_apply_match` | `not_performed` | `no_post_deploy_stage` | No stage compared the applied plan. |
  | `plan_apply_match` | `claimed_by_record` | `plan_files_supplied` | The plan files given to the verifier match. |
  | `plan_apply_match` | `failed` | `plan_files_supplied` | The plan files given to the verifier do not match. |
  | `plan_apply_match` | `could_not_decide` | `binding_undecided` | The plan files given to the verifier could not be compared. |
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

- One record gives one report. For `approval_identity`, `exceptions` and `commit_review`, a verifier takes the first
  result in this order that holds for the record
  (`iltero_schemas.models.common.verification.PRE_DEPLOY_RESULT_ORDER`, with `first_that_holds`). When none holds,
  the result is the pre-deploy stage's own: `approvals_listed`, `no_approval_served`, `not_read_by_the_stage`,
  `server_facts_unavailable` or `served_exceptions_not_assessed`, or, for a commit review the stage kept, the result
  `iltero_schemas.models.common.verification.COMMIT_REVIEW_RESULTS` names for its outcome, with the outcome as the
  reason.

  | Order | State | Reason | Properties |
  | --- | --- | --- | --- |
  | 1 | `claimed_by_record` | `project_exception_relied_on` | `exceptions` |
  | 2 | `claimed_by_record` | `project_exceptions_file_not_relied_on` | `exceptions` |
  | 3 | `not_assessed` | `not_in_activity` | `approval_identity`, `exceptions`, `commit_review` |
  | 4 | `not_assessed` | `pre_deploy_out_of_scope` | `approval_identity`, `exceptions`, `commit_review` |
  | 5 | `not_performed` | `run_opened_locally` | `approval_identity`, `exceptions`, `commit_review` |
  | 6 | `not_assessed` | `pre_deploy_pending` | `approval_identity`, `exceptions`, `commit_review` |

  The project's own exceptions come first because a stage other than the pre-deploy stage may rely on one, so a
  pre-deploy stage that is not in the activity or is out of scope does not hide it. A run the tool opened whose
  pre-deploy stage has not reported gets `run_opened_locally`, not `pre_deploy_pending`: no server will serve that run
  its approvals. A verifier passes `first_that_holds` only results the property can take: an exception result given
  for `approval_identity` is refused when the report is read.
- `server_facts_unavailable` and `served_exceptions_not_assessed` apply only to a run Iltero Platform opened. Neither
  `server_facts_unavailable` nor `not_read_by_the_stage` is ever an `exceptions` result.
- The `reference_time` result follows the weakest source any stage took its time from.
- `iltero_schemas.models.common.pinned_evaluator.evaluator_binary_result(events)` gives the `evaluator_binary` result.
  For `other_binary_named`, its `detail` is the first problem
  [`pinned_evaluator_problems`](#assuranceevent) lists, as `<where> <what>`, such as
  "events.0.provenance.evaluator.digest is not the digest of the pinned OPA binary for its platform". When the
  evaluations have more problems, the detail ends with their count, such as " (4 more problems)". The property
  compares the binary the record states with this contract release's pin; it cannot show which binary ran.
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
  a report and the plan's resource addresses (`plan_resource_addresses`).

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion`, `kind` | string | `iltero.com/v1` and `ScannerObservations`. |
| `tool`, `tool_version` | string, identifier | The scanner and the version it wrote into its report. |
| `ran_by` | string | Who ran the tool: `pipeline` or `iltero_cli`, as the report entry's `ran_by` says. |
| `rules_digest`, `configuration_digest` | digest or null | The digests of the tool's separately downloaded checks (Trivy's checks bundle) and of its configuration and ignore files. `null` means the stage was not given them, never that none was used. |
| `report_digest` | digest | The report as the stage kept it, in the contract's [kept form](#the-report-a-stage-keeps). |
| `plan_digest` | digest | The plan the stage evaluated, as it kept it, redacted. |
| `input_kinds` | list | What the tool read, translated into the contract's words (`TOOL_INPUT_KINDS`), sorted, each once. |
| `unreadable_results` | integer | Results of the report the reader could not read, which decide nothing. |
| `written_configuration_results` | integer | Results about the IaC configuration as written (not the tool's own settings, which `configuration_digest` covers), which no stage reads, counted and left out of `results`. |
| `tool_parsing_errors` | integer or null | Files the tool says it could not parse, or `null` when the tool does not say (Trivy). |
| `results_not_listed` | integer or null | Results the tool's own summary counts that its report does not list, or `null` when the tool writes no counts (Trivy). It is the tool's own word: 0 does not show that every check ran, only that every result the tool counts is listed. |
| `results` | list | At most 200,000 results, sorted by check, then input kind, then the tool's address (a result with none first), each once. |

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
- its `scope.environment` is the record's `subject.environment`. A run that names no environment has no exception in
  force;
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
[`scanner_evidence_problems`](#the-check-a-reader-runs) (through
[`kept_file_problems`](#checking-a-record-against-its-kept-files)), given the copy's bytes in
`KeptFiles.local_exceptions`: for each suppressed result of the stage it works out again which exception covers it,
and the record must name that one, or none when none covers it.

## ServedExceptions

A served exceptions document holds the exceptions Iltero Platform serves one stage of a run it opened: those in force
for that stage. Each exception (`ServedException`) says that an assertion does not have to hold for an environment and
the resources it names, between two times, why, who asked for it, who approved it in Iltero Platform, and when. It names
the assertion document it was approved for by its id, version and digest. The list is empty when no exception is in
force.

Iltero Platform reads the exceptions in force when it opens a run, and serves that one document to every plan stage of
the run, re-runs of the run's plan stage included. An exception approved after the run opened applies from a new run of
the pipeline. Each plan stage still holds an exception to its own reference time.

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
    "run_id": "99b4f87b-c9e7-5eeb-a02b-9849b7f6a5fb",
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
| In one document, at most one Iltero user is found to be the run's starter (`same_user`): Iltero Platform links a CI account to at most one Iltero user of the organization. | "a run has one starter, and the server links its account to one Iltero user at most, so no two are found to be them" |

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

A requester or an approver found to be the run's starter (`same_user`) is recorded, not refused, because the exception
was approved before the run opened; a reader judges it. Separation of duties rests on Iltero Platform and on a reader
that checks these fields. The model reads the fields as Iltero Platform's claims and does not check them.

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
  `scope.environment` is the record's `subject.environment`;
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
that Iltero approved the exceptions in it: only Iltero Platform can check that.

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
`iltero_schemas.trust.BUNDLE_KEYS`, or a development tool's own set. It checks everything but the signature's
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
| `descriptor_digest` | The SHA-256 of the RFC 8785 canonical JSON of the descriptor object as served, signature included, written `sha256:<hex>`. A record's `scanners.scanner_check_mappings` entry for the served mapping names this value as its [`descriptor_digest`](#change-assurance-record-car). |

The tool then verifies the ES256 signature over `signed` with `key`. No scanner result is read with the mapping until
it verifies.

## BundleSigningKeys

The trusted bundle keys file lists the public keys that may sign an assertion bundle or a [scanner check
mapping Iltero Platform serves](#scannercheckmappingdescriptor). It ships inside the package
as `iltero_schemas/trust/bundle-keys.json`, so a tool that pins one package version also pins the keys it trusts.

- **apiVersion:** `iltero.com/v1`, with `kind: BundleSigningKeys`
- **Reader:** `iltero_schemas.trust.parse_bundle_keys`, with the shipped mapping in `iltero_schemas.trust.BUNDLE_KEYS`,
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
