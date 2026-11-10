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
- [PolicySourceManifest](#policysourcemanifest)
- [BundleDescriptor](#bundledescriptor)
- [Trusted bundle keys](#trusted-bundle-keys)

## Conventions

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
| `pre_deploy` | The change, at the gate before it is deployed: approvals, exceptions and earlier evaluations. |
| `post_deploy` | What the deployment did. |
| `post_verify` | What runs after the deployment: the deployed resources, read back, or the workload that runs a deployed image. |
| `runtime` | Resources as they run, outside any change. No record has a `runtime` stage. |

## TechnicalAssertion

A technical assertion is a rule about infrastructure or a built artifact, written in YAML. It states what must be
true, at which stage of a change it is checked, and what kind of thing it is about. The compiler turns it into one
OPA program.

- **apiVersion:** `iltero.io/v1`, with `kind: TechnicalAssertion`
- **Model:** `iltero_schemas.models.assertion.TechnicalAssertion`. `iltero_schemas.ast.parse` reads the YAML text,
  applies the limits below and validates the rule's grammar.

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion`, `kind` | string | `iltero.io/v1` and `TechnicalAssertion`. |
| `metadata.id` | string | Upper-case segments joined by dots, at least two, at most 128 characters. `ILT.` is reserved for assertions Iltero maintains. The first segment must not be a Windows device name (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`). |
| `metadata.version` | string | A semantic version `X.Y.Z`. Evidence cites the assertion's digest, not this version. |
| `metadata.title` | string | One line, at most 200 characters. |
| `metadata.remediation` | string | Optional; when absent, the key is left out, never `null`. What a person does to make a failing subject meet the assertion. One line, at most 300 characters. |
| `spec.change_type` | string or null | Required. The [change type](#change-types-and-activities) the assertion is about: `iac_change` or `image_release`. `null` for an assertion about any change, which reads only what every change type's input shares. Left out, it is refused: "change_type is missing: give iac_change or image_release, or null for an assertion about any change". |
| `spec.stage` | stage | When the assertion is checked. |
| `spec.target` | object | What the assertion is about. `kind` is `resource`, `change`, `deployment`, `assurance` or `artifact` (the artifact a build produced, such as a container image). `resources` lists resource selectors: a `resource` target names exactly one; a `change` or `deployment` target may name up to 16, and is then in scope only when the change touches a resource one of them picks. Only an assertion about an `iac_change` names them on a `change` or `deployment` target: "a change target names resources only in an assertion about an iac_change". An `assurance` or `artifact` target names none: "an artifact target names no resources: it has no change to scope". |
| `spec.when` | object | Optional condition. When it is false, the result is `not_applicable`. |
| `spec.assert` | object | The rule. |

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
- Limits: a document of at most 256 KiB, nested at most 32 levels; at most 128 expressions (predicates and
  combinators), nested at most 8 levels, and 64 in one `all` or `any`; a path of at most 16 segments of 64 characters;
  at most 256 values in an `in` list; text values of at most 1024 characters; integers within ±(2^53 − 1). YAML
  anchors, aliases, tags, merge keys and duplicate keys are refused. The document is read as YAML 1.1, so unquoted
  `yes`, `no`, `on` and `off` are booleans.
- No value is written only as the word `null`. YAML also reads an empty value, `~`, `Null` and `NULL` as null, so the
  loader refuses them, as a value or as a key, and a forgotten value is never read as a comparison with null. For
  such a value on line 4: "line 4: no value is written as null, never as an empty value, ~, Null or NULL".
- `iltero_schemas.ast.source_digest` gives the assertion's source digest. It covers the id, version, type, change
  type, stage, target, `when` and `assert`, and not the title or the remediation. The compiler ignores both. The
  assertion's digest, the one evidence cites, is taken over the whole document and covers both.

```yaml
apiVersion: iltero.io/v1
kind: TechnicalAssertion
metadata:
  id: ACME.AWS.RDS.PRODUCTION_BASELINE
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

## AssuranceContext

The assurance context is the evaluation input: the one JSON document OPA receives for one assertion about one
subject. The tool that runs OPA records the context's digest in the event as `input_digest`.

- **apiVersion:** `iltero.io/assurance-context/v1`
- **Model:** `iltero_schemas.models.context.AssuranceContext`.
  `iltero_schemas.profiles.profile_for(activity, stage, kind)` gives the parts an input of an activity carries at a
  stage, for a target kind.

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion` | string | `iltero.io/assurance-context/v1`. |
| `evaluation` | object | This evaluation: its `id`, the [`activity`](#change-types-and-activities) it belongs to (`iac_change`, `image_build` or `image_deploy`), its `stage`, the runner's `timestamp`, and the `assertion` (`id`, `version`). |
| `organization_scope` | object | The `organization`, `workspace` and `environment`, each `null` when the run has none. The `environment` has its `name` and `production`: whether Iltero Platform's environment policy treats it as production, or the unknown marker in a run Iltero Platform did not open. |
| `reference_time` | object | The time every expiry and ordering comparison uses: `value`, `source` (`server`, `timestamp_authority`, `rekor` or `runner_clock`), `trust` (`attested`, `corroborated` or `asserted`; always `asserted` for `runner_clock`), and `time_window`: the two timestamps the evaluation sits between (`not_before`, `not_after`) and a `nonce_digest`, present exactly when `source` is `timestamp_authority`, otherwise left out or `null`. `not_before` ≤ `value` ≤ `not_after`. Read from the runner's clock, its `value` is the same instant as `evaluation.timestamp`: "an input that reads its runner's clock uses the time of its evaluation". |
| `source` | object | The code the change comes from: `vcs` (`git`) and the `commit` (`sha`); the `repository` (`name`), `null` for a checkout with no remote; the `ref` (`type`: `branch` or `tag`, and `name`), `null` for a detached head; and the `pull_request` (`id`), `null` for a run outside a pull request. A run on a developer's machine is never a pull request. |
| `change` | object | The resources the plan changes (`id`, `provider`, `type`, `kind`, `action`, `module`), and the change `digest`: the [change digest](#the-change-digest) of `iac_change`, the subject's unit, the environment key `organization_scope.environment.name` (`null` when the environment is `null`) and `plan.digest`. A context with any other `digest` is refused: "change.digest is the digest of the change type, unit, environment and plan". `provider` is the provider's short name: lower-case letters, digits, `_` and `-`, starting with a letter (`aws`, `google-beta`). `kind` is the kind the plan tool's table gives the type, or the unknown marker `{"__unknown": true, "reason": "kind_unmapped"}` when the table lacks it; it is `null` exactly for a provider with no kinds. A context whose kinds differ from the table's is refused. In an `image_deploy` input, the change is the deployed image instead: its `digest`, the change digest of `image_release`, the subject's unit, the environment key and the image; the `image` (`repository`, `digest`); and the `build` Iltero Platform accepted, `null` when it accepted none, or the unknown marker `{"__unknown": true, "reason": "server_facts_unavailable"}` in a run the tool opened (see [The `image_deploy` body](#the-image_deploy-body)). An `image_deploy` input names its environment ("a deploy's input names its environment: a deploy is to one"), and `build` holds the marker exactly when `organization_scope.environment.production` does: "change.build holds the unknown marker exactly when the environment's production flag does: both hold it only in a run no server opened". A context with any other `digest` is refused: "change.digest is the digest of the change type, unit, environment and image". |
| `plan` | object | The IaC `tool` and `tool_version`, the plan `format_version`, the plan's digests, `source_commit`, whether the plan is `complete` and `applyable`, and the same table of contents for every resource the plan covers. `tool_version`, `complete` and `applyable` hold the unknown marker `{"__unknown": true, "reason": "not_reported_by_tool"}` when the tool's plan does not say; `null` is refused. |
| `subject` | object | The subject's `kind`, its `key` and its `identities` (`scheme`, `value`, `scope`): one or two, its local identity and, at runtime, its cloud identity (at most `iltero_schemas.models.fields.MAX_SUBJECT_IDENTITIES`, 2). An identity's `scope` holds at most 8 keys (`MAX_SCOPE_KEYS`). |
| `resource` | object | For a resource subject, the resource as planned: `id`, `provider`, `type`, `kind`, `name`, `module`, `action`, `before`, `after`, the resources that refer to it (`related`), and `tool_data`. |
| `deployment` | object | What the apply did: the applied `plan`, and `apply` with its `source` log, the `state` after it, or the `state_not_read` marker when it was not read (see [When the state after the apply was not read](#apply-with-the-state-not-read)), `outcomes_from` (`apply_log`; `apply_log_and_state` when the log lost messages and the state settled what it could; `apply_log_alone` when the state was not read), each change of the applied plan once (`changes`, each saying where its outcome came from in `outcome_from`: `apply_log`, `apply_log_alone`, `state` or `none`), `timing`, and `tool_data`: what only the IaC tool says, keyed by `tool`, which must be `apply.source.tool`. For `terraform`: the `summary` counts it reported, the `log_lines` it could not read (`other_output_lines`, `damaged_messages`, `interrupted_operations`), and the delete of each `deposed` object (an old copy a replacement set aside), settled by the state, or the `state_not_read` marker when it was not read. `superseded_by` is `{"reason": "dependency_replanned"}` when the pipeline says it applied a re-plan, which must differ from the evaluated plan, and `null` otherwise. In an `image_deploy` input, the image the pipeline reports it deployed (see [The `image_deploy` body](#the-image_deploy-body)). |
| `evaluations`, `approvals`, `exceptions` | list or marker | Facts only Iltero Platform holds, as the items below (`iltero_schemas.models.server_facts`). |
| `run` | object | The run the input belongs to, by Iltero's run `id`; an approval of a run names it. |
| `drift_check` | object | What two readings of the unit's deployed resources, taken after the apply, found: the shape of a record's [`drift_check`](#change-assurance-record-car). In an `image_deploy` input, what one reading of the workload found (see [The `image_deploy` body](#the-image_deploy-body)); its `change_digest` is `change.digest`: "drift_check.change_digest is change.digest", and it compares every container, of the pod template or of a pod, whose image is from `change.image.repository`: "a reading compares every container whose image is from the deployed repository". |
| `assurance` | object | Facts after deployment. This version gives it no shape: any object, held to the bounds of an event's `observations` (at most 512 KiB in canonical form, nested at most 4 levels, and no refused character in any string). |
| `artifact` | object | The image a build produced: its `repository`, its `digest`, the digest of each platform's image (`platform_digests`) and `build_commit`: the commit the build tool's provenance names, or the unknown marker `{"__unknown": true, "reason": "not_reported_by_tool"}` when the build named none (see [The build's commit](#the-builds-commit)), with the rules of the [`image_build` body](#the-image_build-body). |
| `tests` | list | Each test report the build was given, at most 64 (see below). |
| `scans` | list | Each scan report the build was given, at most 64 (see below). |
| `verified_source` | object or marker | The commit Iltero Platform verified from the identity the continuous integration (CI) system gave the job that opened the run, not the commit the tool reads from its checkout, with what that identity named (see the Verified source item below). A fact only Iltero Platform holds. |
| `attestation_outcome` | object or marker | What Iltero Platform found when it checked the signature of the build's attestation: verified, refused or not sent (see [The build's attestation](#the-builds-attestation)). A fact only Iltero Platform holds. |

Key rules:

- The parts present are exactly those the profile of the evaluation's activity, stage and target kind provides. A
  part outside the profile is written as `null` and reads as absent, as does one left out. A missing required part
  or an extra part is refused, and the error names it. `evaluation`, `organization_scope` and `reference_time` are
  always required. A resource target also requires `resource`.

  | Activity | Stage | Required | Optional |
  | --- | --- | --- | --- |
  | `iac_change` | `plan` | `source`, `change`, `plan`, `subject` | none |
  | `iac_change` | `pre_deploy` | `source`, `change`, `plan`, `subject`, `evaluations`, `approvals`, `exceptions`, `run` | none |
  | `iac_change` | `post_deploy` | `source`, `change`, `plan`, `subject`, `deployment` | none |
  | `iac_change` | `post_verify` | `subject`, `deployment`, `drift_check` | `source`, `assurance` |
  | `iac_change` | `runtime` | `subject` | `source`, `deployment`, `assurance`, `exceptions` |
  | `image_build` | `plan` | `source`, `subject`, `artifact`, `tests`, `scans`, `verified_source`, `attestation_outcome` | none |
  | `image_deploy` | `pre_deploy` | `source`, `change`, `subject`, `evaluations`, `approvals`, `exceptions`, `run` | none |
  | `image_deploy` | `post_deploy` | `source`, `change`, `subject`, `deployment` | none |
  | `image_deploy` | `post_verify` | `change`, `subject`, `deployment`, `drift_check` | `source` |

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
  `ILT.DEPLOYMENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN` compares `plan.digest`, `plan.artifact_digest` and
  `plan.artifact_digest_source` with the same fields of `deployment.plan`. When neither side was given the saved plan
  file, both artifact digests are `null` and both sources `not_provided`: the assertion passes, and the event's
  observations show `not_provided`. Such a pass shows that the applied plan's digest equals the evaluated plan's, not
  that the applied plan file is the evaluated one byte for byte. When only one side has the saved plan file, it fails.
- `plan.source_commit` equals `source.commit.sha`.
- A value removed by redaction is a marker, `{"__redacted": true, "reason": ..., "present": true, "type": ...}`. A
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
| Earlier evaluation | `id`, `assertion` (`id`, `version`), `stage`, `subject` (`kind`, `key`), `result.status`, `checked_content` (the [checked content](#checked-content) it read, or `null`: its kind, or `null`, is one an activity's input carries at that stage (`iltero_schemas.profiles.reads_checked_content`, one kind per activity, `None` for an activity whose input carries none). So `plan` and `container_image` are accepted at `plan`, `pre_deploy` and `post_deploy`; `container_image` or `null` at `post_verify`, where an `image_deploy` input carries the image and an `iac_change` input nothing; and only `null` at `runtime`. Any other is refused: "an earlier evaluation names the content it checked exactly when its stage reads that content"), `observed_at`. |
| Verified source | `commit`: the commit Iltero Platform verified from the identity the CI system gave the job that opened the run. What that identity named: `ci_provider`, the CI system (`github_actions`, from `iltero_schemas.models.ci.CI_SYSTEMS`); `ci_instance`, the instance of it by its host name, such as `github.com`; `repository_id`, the repository's id at the CI system, which does not change when the repository is renamed, and `repository`, its name; `ci_run_id` and `ci_run_attempt` (an integer from 1), the CI run and its attempt. A CI system's ids are unique only within one instance of it, so each id is read with `ci_provider` and `ci_instance`. |

- An approval's `subject` names what it approves: `{kind: change, digest}`, that plan and no other, or `{kind: run,
  id}`, Iltero's run, never a CI run. An approval of a run approves the run, not a plan's content: a CI deployment
  review approves the deploy job when it starts, whether or not that run has planned yet.
- `ILT.CHANGE.PRODUCTION_APPROVED` and `ILT.CHANGE.SENSITIVE_CHANGE_APPROVED` pass on an approved, independent
  approval of the change by its digest from the `security` role, or on an approval of the run whose `subject.id` is
  the input's `run.id`. Each is its own `exists`, so the observations show which one held. An approval of the run may
  be a self-approval the policy permitted; an approval of the change may not. For an approval of the run, both
  assertions read the same CI environment approval: there is no separate security sign-off behind it.

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
- A change that needs no operation, left unknown, is not an operation that may have run: an apply whose only unknown
  changes need no operation has a `timing` only when an operation ran.
- For `terraform`: with the state not read, every deposed object's delete is the `state_not_read` marker: "with the
  state not read, every deposed object's delete is unknown". A `summary` that is the `deployment_log_incomplete`
  marker, and a change that needs an operation left `none`, need a log that lost messages (`damaged_messages` or
  `interrupted_operations` above 0): "only a log that lost messages leaves a change to the state or unknown". The one
  exception: with the state not read, a `delete`, or a `replace` that deletes, at an address that also holds deposed
  objects may be `none` with the `state_not_read` marker even when the log lost no messages, since the log names every
  delete at that address alike and only the state shows which was the current object's. When the log lost messages, a change
  that needs an operation is never `not_attempted` from the log alone: "with the state not read and the log missing
  messages, a change the log never names is unknown". A change that needs no operation, left
  unknown, still allows the `summary`; an import among them is still counted in `imported`. The summary's `removed`
  count may include the deposed deletes left unknown.
- A `post_verify` input whose deployment's state was not read is refused: "post-verify needs the identities the state
  after the apply gives, and the state after the apply was not read".

An assertion that reads a change's outcome decides on the log's word alone. One that reads a `state_not_read` marker,
such as `deployment.apply.state.tool`, is `unknown` with reason `state_not_read`.
`ILT.DEPLOYMENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN` reads only the applied plan, so it still decides. A `not_equal`
or `not_in` over `outcomes_from` also matches `apply_log_alone`: `not_equal: apply_log_and_state` holds when the state
was not read. The same holds for each change's `outcome_from`, which has four values (`apply_log`, `apply_log_alone`,
`state`, `none`): `not_equal: state` matches `apply_log_alone`.

## AssuranceEvent

An assurance event is one verdict: the result of one assertion about one subject, with the provenance needed to say
who produced it and to reproduce it.

- **apiVersion:** none. An event travels inside a [CAR](#change-assurance-record-car).
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
| `evaluator` | The engine that produced the verdict. For `opa`: its `version`, binary `digest` and the `limits` applied: `timeout_seconds`, `memory_limit`, `max_output_bytes`, `evaluations_per_process`, `capabilities_digest` and `platform`. For a scanner (`checkov` or `trivy`): its reported `version`, a `digest` when known, and `reason: not_executed_by_cli`. |
| `bundle` | The bundle the program came from: `kind` (`server` or `local_bundle`), `tarball_digest`, the SHA-256 of the bytes of the bundle tarball the evaluator loaded, `content_digest` and `key_id`. For `server`, they are the served [descriptor](#bundledescriptor)'s `tarball_digest`, `content_digest` and `key_id`. For `local_bundle`, `tarball_digest` is the digest of the tarball the tool built, and `content_digest` and `key_id` are `null`, because a bundle the tool built has no descriptor. Any other combination is refused: "a bundle names its content digest and signing key exactly when its kind is server". The writer's claim: nothing compares these values with a descriptor. Present exactly when the evaluator is `opa`. An evaluation whose `assertion_source` is `server_bundle` and that ran over a bundle names a bundle of kind `server`; otherwise it is refused: "an assertion from the server's bundle is evaluated over the server's bundle". |
| `evaluator_binding` | The [evaluator binding](#evaluatorbindingset) that let a scanner's result stand for the assertion. Present exactly when the evaluator is a scanner; otherwise it is refused: "an evaluator binding is named exactly when a scanner's result was read for this evaluation". |
| `assertion_source`, `assertion_source_digest` | Where the assertion came from, and its source digest. `server_bundle`: an assertion bundle Iltero Platform served. `local`: the project's own files; `custom_rego` when hand-written in Rego. `contract_starter`: a starter assertion this package ships, added to a local run. The writer's claim. |
| `compiled_digest`, `compiler` | The compiled program's digest, and the compiler's `version`, `contract_version`, `contract_digest` and `install` (`wheel` or `editable`). Absent for a scanner. |
| `executor` | Who ran the evaluation: `type` (`human` or `workload`), `provider` (`local`, `ci` or a CI system such as `github_actions`) and the CI system's run id (`ci_run_id`). |
| `facts_source` | For an evaluation whose input may carry Iltero Platform facts (approvals, exceptions, earlier evaluations, the verified source, the verified attestation: an `iac_change` input at `pre_deploy` or `runtime`, an `image_build` input at `plan`, and an `image_deploy` input at `pre_deploy`), where they came from: `server` or `none`. `null` for every other input (`iltero_schemas.profiles.reads_server_facts`). An `image_deploy` input's accepted build (`change.build`) also comes from Iltero Platform, but `reads_server_facts` does not count it: `change` is not one of the parts it lists (`SERVER_FACTS`). So the `pre_deploy` input names its `facts_source` for its approvals, exceptions and earlier evaluations, and the `post_deploy` and `post_verify` inputs, which carry `change.build` too, name none. |

Key rules:

- `status` is one of six values. Only `pass` and `fail` may omit `status_reason`, and a reason must belong to its
  status:

  | Status | Reasons |
  | --- | --- |
  | `pass` | none |
  | `fail` | none: a failure's reason is the policy's `policy_reason` |
  | `unknown` | `known_after_deploy`, `redacted`, `path_missing`, `not_a_list`, `unspecified`, `server_facts_unavailable`, `not_reported_by_tool`, `reference_time_untrusted`, `deployment_log_incomplete`, `state_not_read`, `kind_unmapped` |
  | `not_applicable` | `when_guard_excluded`, `no_subject_in_scope` |
  | `not_evaluated` | `scanner_not_run`, `credential_denied`, `resource_type_unsupported`, `scanner_version_not_allowed`, `timeout`, `subject_unresolved`, `evaluator_unavailable`, `identity_unverified`, `stage_not_run` |
  | `error` | `evaluator_crash`, `evaluator_timeout`, `evaluator_memory_limit`, `output_overflow`, `output_contract_violation`, `adapter_parse_failure`, `bundle_verification_failed`, `compile_failure` |

- An event is checked on its own against its activity. Its activity, stage and subject kind have a profile
  (`iltero_schemas.profiles.profile_for`); otherwise it is refused, such as "stage 'plan' is not valid for target kind
  'artifact' in an iac_change input". Its `provenance.checked_content.kind` is the activity's
  (`CHECKED_CONTENT_KIND_OF`: `plan` for `iac_change`, `container_image` for `image_build` and `image_deploy`): "an
  image_build evaluation names the container_image it checked".
- A built-in assertion's id is reserved. `iltero_schemas.assertions.BUILT_INS` gives each built-in
  (`ILT.DEPLOYMENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN`, `ILT.IAC.NO_DRIFT_AFTER_APPLY`,
  `ILT.IMAGE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT`, `ILT.IMAGE.BUILD_ACCEPTED_FOR_ENVIRONMENT`,
  `ILT.DEPLOYMENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE` and `ILT.IMAGE.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE`) as
  shipped: a `BuiltIn` with its `version`, its document `digest` and its `compiled_digest`; `BUILT_IN_IDS` is the set
  of their ids. An event that names a built-in is evaluated as shipped, and each rule is refused with its message,
  where the id stands for the built-in's:

  | Rule | Refused with |
  | --- | --- |
  | `assertion.version` and `assertion.digest` are the shipped ones. | "ILT.IMAGE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT is a built-in assertion: it names the document this package ships" |
  | `provenance.assertion_source` is `contract_starter` or `server_bundle` (`iltero_schemas.models.event.BUILT_IN_SOURCES`), and `provenance.evaluator_binding` is `null`: no scanner result stands for it. | "ILT.IMAGE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT is evaluated from this package or the server's bundle, never a scanner" |
  | `provenance.compiled_digest` is the shipped module's. It is `null` only when no evaluator ran (`evaluator` is `null`). | "ILT.IMAGE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT runs the module compiled from the document this package ships" |

- A policy can return `pass`, `fail`, `unknown` or `not_applicable`. Only the runner sets `not_evaluated` and
  `error`.
- A policy verdict names its `input_digest`. When no subject was in scope, the event's subject has no `key` and no
  `identities`, and the event has no `input_digest`.
- `evaluator` is `null` only for `evaluator_unavailable` and `no_subject_in_scope`.
- From worst to best, statuses rank `not_evaluated`, `error`, `unknown`, `fail`, `not_applicable`, `pass`
  (`iltero_schemas.models.event.STATUS_SEVERITY`).
- A policy's `policy_reason` is at most 2 KiB. Its `observations` are at most 512 KiB of canonical JSON, nested at
  most 4 levels.

## Change Assurance Record (CAR)

A Change Assurance Record (CAR) is the record of one attempted change, for one unit of one run: an infrastructure
change, the build of an artifact, such as a container image, or the deployment of a built image to one environment.
It holds the evaluations, what the deployment did and the evidence each part cites. It exists whatever the outcome:
deployed, failed, stopped, refused before deployment, or a plan that changes nothing.

A CAR records technical and process assurance facts. It does not, by itself, establish certification or compliance
with a regulatory framework.

- **apiVersion:** `iltero.io/car/v1`
- **Model:** `iltero_schemas.models.car.CAR`

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion` | string | `iltero.io/car/v1`. |
| `uuid` | UUID | The record's id. |
| `run` | object | The run's `id` (UUID). |
| `unit` | identifier | The unit the record covers. |
| `trust_level` | string | How far the record's facts were established (see below). Always `self_attested` in this version. |
| `compliance_determination` | null | Always `null`. |
| `issuer` | object | `type: local` and `identity_verified: false`. |
| `governance` | object | `run_opened_by`: `server` when the writer says Iltero Platform opened the run, `local` when the tool opened it on its own. Only Iltero Platform confirms that it opened a run, by its `run.id`. |
| `subject` | object | `kind: change`, the `environment`, the `unit` and the `source`: the code the change comes from, in the shape of an [AssuranceContext](#assurancecontext)'s `source`. |
| `change` | object | The change the record is about: the body of its [activity](#change-types-and-activities), named by `change.activity` (see [The `iac_change` body](#the-iac_change-body), [The `image_build` body](#the-image_build-body) and [The `image_deploy` body](#the-image_deploy-body)). |
| `units_file` | object or null | The project's [units file](#units-file) as the writer read it. `null` for a project that declares none. |
| `stages` | object | One entry per stage that reported, keyed by stage (see below). Every stage is one the record expects. |
| `events` | list | Every [event](#assuranceevent), grouped in stage order. At most 100,000. |
| `coverage` | object | The stages' coverage combined: subjects in scope and evaluated, assertions expected and evaluated, counts per status, the number of `evaluations`, gaps, truncation and sampling, and the inputs replaced with placeholders (`substituted_inputs`), each naming its stage. |
| `verdict` | object | `value` (`pass`, `fail` or `indeterminate`), `exit_code`, `computed_from` (`status_counts` for a stage, `stage_precedence` for the record) and the deciding `stage`. |
| `assurance_status` | object | `complete` or `incomplete`, with a `reason`: `required_policy_evaluation_failed` (an evaluation ended in an evaluator error), `state_not_read` (the state after the apply was not read), `plan_not_complete` (the plan said it is incomplete, or did not say it is complete) or `upstream_state_unavailable` (the stage read placeholders for an input). The `reason` is the leading cause, in that order, within a stage; a record's reason is its first incomplete stage's, with an evaluator error first; every cause stays in the stage's `coverage`: its gaps, substituted inputs and error count. A record that is `complete` (every expected stage reported) can still be `incomplete` here. |
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
| `approvals` | list or null | The approvals the stage's evaluations read, in the shape of the [approval item](#assurancecontext), whatever their source, at most 256, each listed once and of the record's change or run. A list exactly at a stage whose input carries approvals (the `pre_deploy` stage of an `iac_change` or an `image_deploy`), `null` at every other. A stage lists approvals only when one of its events read its facts from Iltero Platform (`provenance.facts_source: server`): "the pre_deploy stage lists approvals only when its results read facts from the server". |
| `compiler` | object | The compiler, in the shape of an event's `compiler`: `version`, `contract_version`, `contract_digest` and `install`. |
| `redaction` | object | The stage's redaction report (see below). |
| `events` | object | The file of the stage's events: its `path`, `digest` and `count`, which equals the stage's `coverage.evaluations`. |
| `assertions` | object | The index of the assertions the stage compiled: its path (`index`), `digest` and `count`. |
| `scanners` | object or null | What the stage read from the scanner reports it was given (see below). `null` for a stage given no scanner report. |
| `coverage`, `verdict`, `assurance_status` | object | The stage's own, in the shape of the record's. |

A stage's `scanners` says what it read from scanner reports and how much of it became a verdict:

| Field | Type | Meaning |
| --- | --- | --- |
| `evaluator_binding_set` | object | The one [evaluator binding set](#evaluatorbindingset) in force (see below). |
| `reports` | list | Each scanner report the stage was given, at most 16, one per scanner (see below). The model also accepts an empty list. |
| `results_accepted` | integer | Results an evaluator binding accepted as the `pass` or `fail` of the assertion it names, from 0. Each is one event whose evaluator is the scanner. |
| `results_scanner_version_not_allowed` | integer | Results an evaluator binding matched, but whose scanner version does not satisfy its `tool_version_constraint` (a pre-release or a string that is not a version satisfies none), from 0. Each evaluation stays `not_evaluated` with reason `scanner_version_not_allowed`. |
| `results_without_binding` | integer | Results that became no evaluation, from 0. It is the sum of the reports' own `results_without_binding`. |

`results_accepted`, `results_scanner_version_not_allowed` and `results_without_binding` add up to the sum of the
reports' `results_read`: every result a scanner reported is counted once.

`evaluator_binding_set` names the binding set by:

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | The binding set's `metadata.id`: upper-case segments joined by dots, at least two, at most 128 characters. |
| `version` | string | The binding set's `metadata.version`: a semantic version `X.Y.Z`. |
| `origin` | string | `shipped` for the set this package ships, `file` for one read from a file. The writer sets it, not the binding set; in a self-attested record it is the writer's claim. |
| `file_name` | string or null | The name of the file the set was read from, without its directories. It follows the same rule as the plan's `artifact_file_name`. Present exactly when `origin` is `file`. |
| `digest` | digest | The digest of the binding set's canonical JSON as parsed, not of the file's bytes. A reader recomputes it from the copy at `copy_path`. An event's `evaluator_binding.digest` names an entry of the set, which a reader checks against the copy. |
| `copy_path` | string | Where the stage kept its copy of the binding set, in the record's directory. |
| `binding_count` | integer | How many entries the set holds, for every scanner and stage, not only those this stage could use, from 0. |

Each `reports` entry:

| Field | Type | Meaning |
| --- | --- | --- |
| `tool` | string | `checkov` or `trivy`. |
| `tool_version` | identifier | The version the scanner reported. |
| `input_kinds` | list | What the scanner was reading, in its own words, such as `terraform_plan` (identifiers). |
| `report_digest` | digest | The digest of the report as the stage kept it, the same value as that file's `evidence_refs` digest. Events answered from the report name it as their `input_digest`. |
| `observations` | string | Where the stage kept what it read from the report, in the record's directory. |
| `results_read` | integer | Results the stage read from the report, from 0. |
| `results_without_binding` | integer | This report's results that became no evaluation, from 0. |
| `parsing_errors` | integer | Inputs the scanner itself reported it could not parse, from 0. A value above 0 means the scanner did not cover everything it was given; 0 does not show that everything was parsed, because a scanner may not report parse errors at all. |

A stage's redaction report (`redaction`) says what the stage's redaction hid, left unknown or allowed, by
path. It holds no value.

| Field | Type | Meaning |
| --- | --- | --- |
| `policy` | object | The redaction policy that ran: `id`, `version` (identifiers) and `digest`. |
| `input` | object | What was redacted: `kind` and the `digest` of the redacted tree. The `kind` is what the stage reads: `observation` at `plan`, `facts` at `pre_deploy`, `deployment` at `post_deploy` and `post_verify` (`iltero_schemas.models.stages.REDACTED_INPUT_KIND`): "the pre_deploy stage's redaction report is of the facts it read". |
| `redacted` | list | Each path the policy hid: `path`, and `reason`, a token of a lowercase letter followed by up to 63 lowercase letters, digits or `_`. |
| `unknown` | list | The paths left unknown. |
| `allowed` | list | Each path the project allowed through: `path`, and `reason`, the project configuration's own words: one line of plain text, at most 1024 characters. |

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
tree the report describes, so the two differ.

A stage's `coverage.subjects_in_scope.excluded` lists the plan resources left out of the subjects in scope, at most
100,000:

| Field | Type | Meaning |
| --- | --- | --- |
| `plan_index` | integer | The resource's index in the plan's resource list, from 0. |
| `id` | string or null | The resource's address as the plan wrote it, kept as written whatever its characters, at most 64 KiB of UTF-8. `null` when it was redacted. |
| `reason` | string | `not_managed` (not managed by the configuration), `deposed` (an old copy a replacement set aside), `identity_redacted` or `identity_unnameable` (an identity redacted, or one that cannot be named). |

A resource excluded for its identity is also a gap whose `kind` is the exclusion's `reason` and whose `plan_index` is
the resource's, listed once, and every identity gap names such a resource: "the identity gaps name, once each, the
resources the scope excludes for their identity, by the same reason". A plan resource is excluded at most once: "a
plan resource is excluded once, for one reason".

A stage's `coverage.gaps` lists what is missing from what the stage evaluated. Each gap has one of four shapes,
chosen by its `kind`:

| `kind` | Other field | Meaning |
| --- | --- | --- |
| `plan_incomplete`, `plan_not_applyable` | `value`: `false` or the `not_reported_by_tool` marker | A plan flag that is not `true`. The kind names the flag (`plan_incomplete` for `complete`, `plan_not_applyable` for `applyable`) and `value` carries what the plan said: `false` means the plan said so, the marker means it did not say. |
| `identity_redacted`, `identity_unnameable` | `plan_index`: integer from 0 | A plan resource whose identity was redacted or cannot be named, by its index in the plan's resource list. |
| `deferred_changes`, `related_copies_omitted`, `unresolved_references`, `accepted_by_binding`, or a `not_evaluated` or `error` [status reason](#assuranceevent) | `count`: integer from 1 | How many of one thing are missing: what the plan left out, evaluations that stand on a scanner's result an evaluator binding accepted rather than on a program the run ran, or evaluations with that `not_evaluated` or `error` reason. |
| `state_not_read` | none | The state after the apply was not read, so no outcome of the apply was held to it (`StateNotReadGap`; see [When the state after the apply was not read](#apply-with-the-state-not-read)). |

A gap in a stage's own `coverage` names no `stage`: the field is left out or `null`. The record's combined `coverage`
names the stage each gap came from. The kinds a count gap may name are
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

- Every path in the record is relative to the record's directory, except `units_file.path` and
  `out_of_scope[].declared_in.path`, which are relative to the project and hold no `.` or `..` part and no `:` (a
  Windows drive or file stream). A path in the
  record's directory is plain names joined by `/`, at most 6 deep and 1024 characters, each name using only letters,
  digits, `.`, `_`, `@` and `-`, and never `.` or `..`. No two `evidence_refs` entries share a `path` or a `ref_id`.
- These files that a record's stages and events name are entries of its evidence register
  (`iltero_schemas.models.register.check_register`): each stage's events file and assertion index, by the `path` and
  `digest` the stage gives ("the plan stage's events file is an entry of the evidence register", or "... assertion
  index ..."); the input every event was evaluated over, by its `provenance.input_digest` ("the input every event was
  evaluated over is an entry of the evidence register"); and what the plan stage redacted, by its
  `redaction.input.digest` ("what the plan stage redacted is an entry of the evidence register"). In an `iac_change`
  record whose post-deploy stage has reported, the apply log the deployment was read from is an entry too, by its
  `source.digest`, which is `change.deployment.apply.source.digest`: "the apply log the deployment was read from is an
  entry of the evidence register".
- A record redacts under one policy: every stage's `redaction.policy` and every `evidence_refs[].redaction_policy`
  that is not `null` name the same `id`, `version` and `digest`, whatever the validation context. The digest tells
  apart two policies that share an `id` and `version`.
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
  it names that stage.
- A stage's evaluations are about one kind of subject, one its assertions can target, and the stage counts its subjects
  by that kind (`iltero_schemas.models.stages.scope_counted_from`): the plan stage enumerates the plan's resources
  (`counted_from: plan_resource_enumeration`); a change counts as its one unit (`change_unit`, with the record's
  `change.digest` as its `source_digest`); a deployment counts as its one unit (`deployment_unit`), with the digest of
  the record's `change.deployment` as its `source_digest` at `post_deploy`, and of its `change.drift_check` at
  `post_verify`; a build's artifact counts as its one unit (`artifact_unit`), with the digest of the record's
  `change` as its `source_digest`. Only the plan stage enumerates the plan's resources. A stage with no evaluations
  counts by the one kind its change type's assertions can target, so a `post_verify` stage with none counts the
  deployment. A stage that counts a change, a deployment or an artifact has exactly one subject in scope, none
  removed by the plan and none excluded. The record's combined coverage counts what its first stage counts: the
  plan's resources, a build's one artifact, or an image deploy's one change.
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
  the change: a gate reads `assurance_status` with the verdict. The record's reason is the first stage's that is
  incomplete for an evaluator error, or else the first incomplete stage's; readers find placeholder use by
  `coverage.substituted_inputs`, not by the reason.
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
  `assurance_status.reason` is that of the first incomplete stage, after an evaluator error, so a plan stage's reason
  can lead it: readers find a state not read by the post-deploy stage's `state_not_read` gap, or by
  `change.deployment.apply.state`, not by the record's reason alone.
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
  `coverage.subjects_in_scope.source_digest`, each approval of a change and `change.drift_check.change_digest`), status
  counts from events, each stage's verdict and status, the plan stage's plan-flag gaps, the post-deploy stage's
  `state_not_read` gap (see the gap's rules above), the status each built-in check must have, and the combined top
  level. An event's `status_reason` is `state_not_read` only in an `iac_change` record whose state was not read, at `post_deploy`;
  otherwise it is an integrity failure at `events.<index>.evaluation.status_reason`: "names a state not read the
  record does not". In an `iac_change` record, `ILT.DEPLOYMENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN`
  must be `pass` exactly when `change.deployment.plan` has the evaluated plan's `digest`, `artifact_digest` and
  `artifact_digest_source`, and `fail` otherwise; `ILT.IAC.NO_DRIFT_AFTER_APPLY` must be `pass` exactly when
  `change.drift_check.differences_count` is 0, and `fail` otherwise. An event of either check whose status is one a
  policy answers with (`pass`, `fail`, `unknown` or `not_applicable`, `iltero_schemas.models.event.POLICY_STATUSES`) and
  not the recomputed one is an integrity failure at `events.<index>.evaluation.status`: "is not fail, what the record's
  change gives". An event that is `not_evaluated` or `error` decides nothing and is not compared. The `image_deploy`
  checks are recomputed the same way (see [The `image_deploy` body](#the-image_deploy-body)). The change digest problems
  come first, so a forged `change.digest` is refused as `change.digest is not the digest of the change type, unit,
  environment and plan`. A reader that reports integrity failures itself sets `SKIP_INTEGRITY_CHECKS`
  (`iltero_schemas.models.car`) to `True` in the validation context (any other value is ignored), then calls
  `iltero_schemas.models.stages.integrity_problems`, which returns every problem as a `(where, what)` pair. An approval
  of another run is refused whatever the context.
- A record of a run the tool opened (`governance.run_opened_by: local`) names no Iltero Platform bundle, no
  evaluation from one, no facts from Iltero Platform, and no stage `reference_time` from it (`source: server`). Every
  stage's `coverage.assertions_expected.origin` is `server_pinned` exactly when Iltero Platform opened the run
  (`governance.run_opened_by: server`): "stages.plan: counts its assertions as server_pinned exactly when the server
  opened the run". In a record of a run Iltero Platform opened for an activity whose run is a change
  run (`run_type: change`), `subject.environment` names the environment the run was opened for. A build run belongs
  to no environment, whoever opened it. Either way the record is the writer's own: only Iltero Platform can confirm a
  run it opened, by its `run.id`.
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
  index; a writer that leaves out an owed assertion and its events still agrees with itself. What a stage owed is shown
  only against the project's assertion files at `source_commit`, or the set Iltero Platform pinned for the run.
- These rules establish consistency only. An unsigned record cannot prove that Iltero Platform opened its run. Only
  Iltero Platform can confirm a run, by its `run.id`.
- `compiler.contract_digest` is the SHA-256 over the sorted `path,hash` lines of the wheel's `RECORD` entries for the
  package's own files. `iltero_schemas.distribution.installed_identity()` returns it for the installed package. An
  editable install has none.

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
| `carried_out_matches_checked` | `ILT.DEPLOYMENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN` at `post_deploy`. | `ILT.IMAGE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT` at `plan`. | `ILT.DEPLOYMENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE` at `post_deploy`. |
| `always_evaluated` | `ILT.DEPLOYMENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN` at `post_deploy`, `ILT.IAC.NO_DRIFT_AFTER_APPLY` at `post_verify`. | `ILT.IMAGE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT` at `plan`. | `ILT.IMAGE.BUILD_ACCEPTED_FOR_ENVIRONMENT` at `pre_deploy`, `ILT.DEPLOYMENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE` at `post_deploy`, `ILT.IMAGE.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE` at `post_verify`. |
| `reads_a_state_after_the_apply` | `True`: its records read the IaC tool's state after the apply, which can go unread (see [When the state after the apply was not read](#apply-with-the-state-not-read)). | `False`. | `False`. |

`carried_out_matches_checked` is the built-in assertion that checks that what the pipeline carried out matches what was
checked, with the stage it is evaluated at: it ties a record's evaluations to its checked content. No policy leaves it
out. `always_evaluated` lists every built-in assertion of the activity by the stage it belongs to,
`carried_out_matches_checked` among them. Once that stage has reported, the record evaluates the assertion exactly once,
at that stage only, and never as `not_applicable`, since it always has the stage's one subject:
"ILT.DEPLOYMENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN is evaluated once, at the post_deploy stage, once it has reported"
and "ILT.IMAGE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT always applies to the plan stage's one subject" (the id and stage
are the assertion's). A record evaluates no built-in assertion of another activity:
"ILT.DEPLOYMENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN is a built-in assertion of another activity, not of image_deploy"
(the id and activity are the record's).

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
one commit the record ties to the image. `ILT.IMAGE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT` compares it with the commit
Iltero Platform verified for the run.

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
- On a run Iltero Platform opened, `ILT.IMAGE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT` compares the commit the record
  names, which the tool read from the pipeline's metadata file, with the commit Iltero Platform verified for the run.
  Iltero Platform does not check that commit against the file, which it never receives. The record's file digests let
  anyone given the pipeline's files run the checks again later.
- Only the commit is compared. The repository it names (`configSource.uri`) is not compared with the run's repository.
- A build given additional named build contexts may use files from more than that one commit.
- A record that names no tag and no build commit names no metadata file, and may keep none.

**What the check shows.** `ILT.IMAGE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT` reads `artifact.build_commit` from its input:
the commit, or the unknown marker `{"__unknown": true, "reason": "not_reported_by_tool"}` when the build named none. The
record holds the status to what it can be (see the last row of the key rules below):

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
| The `plan` stage evaluates `ILT.IMAGE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT`, the activity's `carried_out_matches_checked`, exactly once (see `always_evaluated` above). | "ILT.IMAGE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT is evaluated once, at the plan stage, once it has reported" |
| Every event's `facts_source` is `server` when Iltero Platform opened the run (`governance.run_opened_by: server`), and `none` when the tool opened it (`local`). The verified source comes only from the server, so in a run the tool opened it is the unknown marker. | "every evaluation of a build whose run was opened by local reads its facts from none", or "... opened by server reads its facts from server" |
| With no build commit (`build_commit: null`), on any run, the `ILT.IMAGE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT` event is never `pass` or `fail`, and when it is `unknown` its `status_reason` is `not_reported_by_tool`. With a build commit, on a run the tool opened, the same holds with `server_facts_unavailable`. An event that was not evaluated (`not_evaluated`, such as with `evaluator_unavailable`) or that ended in `error` is accepted. | "ILT.IMAGE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT is unknown with reason not_reported_by_tool, never pass or fail, when the build names no commit", or "ILT.IMAGE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT is unknown with reason server_facts_unavailable, never pass or fail, on a run the tool opened: only the server verifies the commit" |
| On a run the tool opened, an `ILT.IMAGE.SIGNED_PROVENANCE_MATCHES_RUN` event is never `pass`, `fail` or `not_applicable`, and when it is `unknown` its `status_reason` is `server_facts_unavailable`. An event that was not evaluated or that ended in `error` is accepted. | "ILT.IMAGE.SIGNED_PROVENANCE_MATCHES_RUN is unknown with reason server_facts_unavailable, never pass, fail or not_applicable, on a run the tool opened: only the server checks an attestation" |
| On a run the tool opened, a kept attestation has `sent_to_server: false`. | "a run the tool opened sent the server no attestation" |
| An `ILT.IMAGE.SIGNED_PROVENANCE_MATCHES_RUN` event passes only when the record keeps an attestation with `sent_to_server: true`. | "ILT.IMAGE.SIGNED_PROVENANCE_MATCHES_RUN passes only for a build whose record keeps the attestation it sent the server" |

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
| `ILT.IMAGE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT` | The commit the build tool's provenance names is the commit the server verified for the run | `artifact.build_commit` equals `verified_source.commit`. Its remediation: "Build the image with Buildx provenance, from the commit the run was opened for." Built in: a runner evaluates it at every build's `plan` stage (`iltero_schemas.assertions.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT`), whatever a project's own assertions are. When no verified source was supplied, or the build names no commit (`not_reported_by_tool`), it is `unknown`; see [The build's commit](#the-builds-commit). |
| `ILT.IMAGE.TESTS_RAN` | The pipeline gave a test report for the built image, and at least one test in it ran | Some `tests` report has more tests than skipped tests (`counts.tests` greater than `counts.skipped`) and names the image's digest or one of its platform digests. |
| `ILT.IMAGE.SCAN_RAN` | A vulnerability scan ran whose report names the built image or at least one of its platform images | Some `scans` report is an `image_vulnerability` scan whose report itself names the image (`image_digest_source: report`), by one of its platform digests, or by its own digest for an image pushed as a single manifest. One scanned platform image is enough: [scan coverage](#scan-coverage) says how many there are. |
| `ILT.IMAGE.SIGNED_PROVENANCE_MATCHES_RUN` | Signed build provenance names the built image and this run's repository, commit and run | `attestation_outcome.outcome` is `verified`, its `image_digest` is `artifact.digest`, and its `ci_provider`, `ci_instance`, `repository_id`, `commit`, `ci_run_id` and `ci_run_attempt` equal `verified_source`'s. `fail` when no attestation was sent (`outcome: not_sent`) or Iltero Platform refused it; `unknown` when the fact is the unknown marker. Not built in: a project adds it. See [The build's attestation](#the-builds-attestation). |

#### Scan coverage

Scan coverage says which of an image's platform images the build's scan reports name.
`iltero_schemas.change_types.scan_coverage(build)` returns a `ScanCoverage` with two sorted tuples of digests:
`platforms_scanned` and `platforms_not_scanned`. It counts the reports `ILT.IMAGE.SCAN_RAN` counts: a `trivy_json` or
`grype_json` report whose `image_digest_source` is `report`. An image pushed as a single manifest is its own one
platform image. A report's tie to a platform image is the report's own word, so a reader writes "scan reports name
1 of 2 platform images", not "scanned", and shows the count even when it is 0. It is a pure function, so every reader
computes the same result from the record.

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
evaluation input, and its verdict is in the `ILT.IMAGE.SIGNED_PROVENANCE_MATCHES_RUN` event.

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
- `ILT.IMAGE.SIGNED_PROVENANCE_MATCHES_RUN` compares the CI run and its attempt as well as the commit, so an attestation
  from another run of the same commit fails, and a build that sends none fails.
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

- **The build.** The server finds the build of the image by its digest and accepts it against the environment's
  accepted build sources. The record copies the build as the server served it (`build`), and never names a build a
  pipeline chose. A record of a run the tool opened names none. At `pre_deploy`, `ILT.IMAGE.BUILD_ACCEPTED_FOR_ENVIRONMENT`
  checks that there is one (see the built-in assertions below).
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
  `ILT.IMAGE.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE`.

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
| The `pre_deploy` stage evaluates `ILT.IMAGE.BUILD_ACCEPTED_FOR_ENVIRONMENT`, the `post_deploy` stage `ILT.DEPLOYMENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE`, and the `post_verify` stage `ILT.IMAGE.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE`, each exactly once and never as `not_applicable` (see `always_evaluated` above). | "ILT.IMAGE.BUILD_ACCEPTED_FOR_ENVIRONMENT is evaluated once, at the pre_deploy stage, once it has reported", or the same for the others; a `not_applicable` event: "ILT.IMAGE.BUILD_ACCEPTED_FOR_ENVIRONMENT always applies to the pre_deploy stage's one subject" |
| An `ILT.IMAGE.BUILD_ACCEPTED_FOR_ENVIRONMENT` event that was not evaluated, or that ended in `error`, gives a fault of the evaluator as its reason: `timeout` or `evaluator_unavailable` for `not_evaluated`; `evaluator_crash`, `evaluator_timeout`, `evaluator_memory_limit`, `output_overflow`, `output_contract_violation`, `bundle_verification_failed` or `compile_failure` for `error`, never `adapter_parse_failure` (`iltero_schemas.models.event.EVALUATOR_FAULT_REASONS`). | "ILT.IMAGE.BUILD_ACCEPTED_FOR_ENVIRONMENT is not_evaluated only for a fault of the evaluator, never for want of the change or its facts", or the same with `error` |
| On a run the tool opened, any other `ILT.IMAGE.BUILD_ACCEPTED_FOR_ENVIRONMENT` event is `unknown` with `server_facts_unavailable`. | "ILT.IMAGE.BUILD_ACCEPTED_FOR_ENVIRONMENT is unknown with reason server_facts_unavailable on a run the tool opened: only the server accepts a build for the environment" |

The `post_verify` stage's redaction report (`redaction`) describes one input, the deployment input (`input.kind:
deployment`); it does not list what redaction hid in the files the reading was taken from. For each of those files the
record keeps the redaction policy that ran (`redaction_policy`) and the digest of the file as read (`source.digest`),
not a list of what was hidden.

An evaluation input's `drift_check` is read with the same model, so the rules on the reading itself hold there too:
the rollout, the two container lists, the pods, the finished-rollout rules, the different files and the compared
containers. The rules on the record's run, stages and evidence register hold only in a record.

The integrity checks recompute `change.digest` from the record's change type, unit, environment and image, and hold the
`pre_deploy` stage's `coverage.subjects_in_scope.source_digest`, each approval of a change and
`change.drift_check.change_digest` to it. Each one that differs is an integrity failure, such as "change.digest is not
the digest of the change type, unit, environment and image" and "change.drift_check.change_digest is not change.digest".
They also recompute the status each built-in check must have from the record's own image, deployment, reading and
build, with the rules of the three assertions below: on a run Iltero Platform opened,
`ILT.IMAGE.BUILD_ACCEPTED_FOR_ENVIRONMENT` passes with a `build` and fails without one;
`ILT.DEPLOYMENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE` passes or fails; and
`ILT.IMAGE.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE` passes, fails or is `unknown` as its row in the table below says. An
event of any of them whose status is `pass`, `fail`, `unknown` or `not_applicable` and not the recomputed one is an
integrity failure at `events.<index>.evaluation.status`: "is not fail, what the record's change gives". An event that is
`not_evaluated` or `error` is not compared. On a run the tool opened, `ILT.IMAGE.BUILD_ACCEPTED_FOR_ENVIRONMENT` is not
recomputed: the key rules above refuse an event that is neither `unknown` with `server_facts_unavailable` nor
`not_evaluated` or `error` for a fault of the evaluator, even when the integrity checks are skipped.

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

The evaluation input of a deploy carries the `change` (its `digest`, the `image` by `repository` and `digest`, and
the `build`, without a tag; in a run the tool opened, `build` is the unknown marker
`{"__unknown": true, "reason": "server_facts_unavailable"}`, where the record has `null`), and from `post_deploy` on
the `deployment`, and at `post_verify` the `drift_check`, in the shapes above. At `pre_deploy`, an assertion about any
change, such as `ILT.CHANGE.PRODUCTION_APPROVED`, reads only what both the `iac_change` and the `image_deploy` input
carry, so it never reads `plan`.

Three built-in assertions check a deploy: the first about the `change` target, the other two about the `deployment`
target.

| Assertion | Title | Passes when |
| --- | --- | --- |
| `ILT.IMAGE.BUILD_ACCEPTED_FOR_ENVIRONMENT` | The server accepted a build of the image for the environment | At `pre_deploy` (`iltero_schemas.assertions.BUILD_ACCEPTED_FOR_ENVIRONMENT`): `change.build` is not `null`. It fails when Iltero Platform opened the run and accepted no build of the image for the environment (`build: null`), and is `unknown` with `server_facts_unavailable` in a run the tool opened, where `build` is the unknown marker. So the `pre_deploy` stage of an image deploy in a run the tool opened never passes: at best it is indeterminate (exit code `3`). Its remediation: "Deploy an image built by a run the server recorded, from a source the environment accepts." |
| `ILT.DEPLOYMENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE` | The image the pipeline reports it deployed is the image the deploy checked | At `post_deploy`: `deployment.repository` equals `change.image.repository`, and `deployment.digest` equals `change.image.digest`. The activity's `carried_out_matches_checked` check (`iltero_schemas.assertions.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE`). |
| `ILT.IMAGE.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE` | After its rollout finished, every live pod of the workload runs the deployed image, or one of its platform images, in every compared container | At `post_verify` (`iltero_schemas.assertions.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE`): `drift_check.rollout.complete` is `true`; `drift_check.live_pods_read` equals `drift_check.rollout.expected_live_pods`; at least one `template_containers` entry is compared; at least one `containers_read` entry is a compared container of a live pod; and every compared container of a live pod runs `change.image.digest` or one of `change.build.platform_digests`. It fails when the rollout had not finished, when the live pods read are not the number the rollout calls for, when the template compares no container, when no live pod has a compared container (so a workload scaled to zero fails, having no live pod to check), or when the change names an accepted build and a compared container of a live pod runs a digest that is neither the image's nor one of that build's platform digests. It is `unknown` when such a container's `digest` is the `not_reported_by_tool` marker, or when the change names no accepted build (`build` is `null`, or the unknown marker in a run the tool opened) and such a container runs a digest other than the image's, since there is no platform digest to compare it with. A failure decides before an unknown. Iltero Platform recomputes the same status from a record (`iltero_schemas.change_types.image.deploy.running_image_status`). Terminating and finished pods, and containers not compared, never decide it. |

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

- **apiVersion:** `iltero.io/verification-report/v1`
- **Model:** `iltero_schemas.models.verification.VerificationReport`

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion` | string | `iltero.io/verification-report/v1`. |
| `record` | object | The record's `uuid`, and the `digest` of its bytes as the verifier read them. |
| `verifier` | object | `name: iltero` and the verifier's `version`. |
| `properties` | object | Nine properties, each with a `state` and a `reason`: a short name for why the property has its state, or `null`. |

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
  "`<property>` is one of the results a verifier gives that property".

  | Property | State | Reason | Meaning |
  | --- | --- | --- | --- |
  | `integrity` | `client_asserted` | `file_digests` | The files the record cites hold the digests it names, which anyone who can edit them can recompute. |
  | `source_identity` | `not_assessed` | `ci_job_held_by_server` | Iltero Platform, which opened the run, verifies its CI jobs; the record does not carry them. |
  | `source_identity` | `not_performed` | `run_opened_locally` | The tool opened the run, so no CI job was verified. |
  | `approval_identity` | `client_asserted` | `approvals_listed` | The pre-deploy stage lists approvals: its writer's claim. |
  | `approval_identity` | `not_performed` | `no_approval_served` | Iltero Platform opened the run, and the pre-deploy stage lists no approval. |
  | `approval_identity`, `exceptions` | `not_assessed` | `not_in_activity` | The record's activity has no pre-deploy stage, as an image build has none. |
  | `approval_identity`, `exceptions` | `not_performed` | `server_facts_unavailable` | The pre-deploy stage ran with no facts from Iltero Platform. |
  | `approval_identity`, `exceptions` | `not_assessed` | `pre_deploy_pending` | The record expects the pre-deploy stage, and the run that would report it is still in progress. |
  | `approval_identity`, `exceptions` | `not_assessed` | `pre_deploy_out_of_scope` | The record leaves the pre-deploy stage out of scope. |
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

- The report has no overall verdict, and no report establishes certification or compliance with a regulatory
  framework.

## ResourceIdentities

A resource identities document lists, for one unit after an apply, the resolved identity of each resource of its
IaC configuration: the resource tied to the cloud resource it created. A resource is resolved only by a resolver
verified for its type, and otherwise listed as unresolved with a reason. A resolver is the part of a tool that reads
identifiers for one cloud provider.

- **apiVersion:** `iltero.io/resource-identities/v1`
- **Model:** `iltero_schemas.models.iac.resource_identities.ResourceIdentities`

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion` | string | `iltero.io/resource-identities/v1`. |
| `unit` | identifier | The unit. |
| `generator` | object | `name: iltero` and the writer's `version`. |
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

An evaluator binding set is a set of licenses. Each entry says that one rule of one scanner (Checkov calls its rules
checks), at a version inside a stated range, establishes one assertion at one stage. A bound rule is not run again.
The scanner's result is accepted for the assertion the entry names.

- **apiVersion:** `iltero.io/v1`, with `kind: EvaluatorBindingSet`
- **Model:** `iltero_schemas.models.binding.EvaluatorBindingSet`

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion`, `kind` | string | `iltero.io/v1` and `EvaluatorBindingSet`. |
| `metadata` | object | The binding set's `id` and `version`. |
| `bindings` | list | 1 to 10,000 entries, each described below. |

Each entry:

| Field | Type | Meaning |
| --- | --- | --- |
| `id`, `version` | string | The entry's own id and version. |
| `tool` | string | `checkov` or `trivy`. |
| `tool_version_constraint` | string | A PEP 440 version specifier, such as `>=3,<4`. |
| `rule_id` | string | The scanner's own rule id, such as `CKV_AWS_16`. |
| `input_kind` | string or null | What the scanner must have been reading, in its own words, such as `terraform_plan`. Null for a scanner that reads one kind of input. |
| `assertion` | object | The `id` and `version` of the assertion the rule establishes. |
| `stage` | stage | The stage the binding applies to. |
| `status_map` | object | 1 to 32 of the scanner's status words, each mapped to `pass` or `fail`. |

Key rules:

- Ids are unique. A scanner's rule is bound once per stage. A scanner establishes an assertion with one rule per
  stage.
- Only `pass` and `fail` are accepted. A status word the map does not list leaves the result not accepted.
- A pre-release scanner version, or a version string that is not a version, satisfies no constraint.
- An event accepted through an entry names the entry's id, its version and the digest of the entry's canonical
  JSON.
- `iltero_schemas.bindings.load_binding_set` reads a set from YAML text with the loader of a
  [TechnicalAssertion](#technicalassertion), under the same rules: one document of at most 256 KiB, nested at most 32
  levels, with no anchors, aliases, tags, merge keys or duplicate keys, and no value written other than as `null`.

## PolicySourceManifest

A policy source manifest describes a directory of hand-written Rego policies, for rules the assertion language
cannot express. Each entry names the assertion a policy decides, the stage, the target and the one `.rego` file it
is written in.

- **apiVersion:** `iltero.io/v1`, with `kind: PolicySourceManifest`
- **Model:** `iltero_schemas.models.policy_source.PolicySourceManifest`

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion`, `kind` | string | `iltero.io/v1` and `PolicySourceManifest`. |
| `policies` | list | 1 to 512 entries, each described below. |

Each entry:

| Field | Type | Meaning |
| --- | --- | --- |
| `title` | string | What the policy claims, at most 200 characters. |
| `assertion` | object | The `id` and `version` of the assertion the policy decides. |
| `stage` | stage | When the policy is evaluated. |
| `target` | object | The same shape as a TechnicalAssertion's `spec.target`. |
| `file` | string | A plain `.rego` file name inside the directory, with no directory part. |

Key rules:

- The stage and the target kind form a combination some change type allows (`VALID_COMBINATIONS`), as for a
  TechnicalAssertion whose `change_type` is `null`: a hand-written policy names no change type.
- One policy decides an assertion at a stage. Two policies are never written in the same file.
- Each file declares the package `iltero.assertions["<id>"]` of the assertion it decides.
- A record that ran a hand-written policy says so, and a replay runs the retained code, because nothing can derive
  it again.

## BundleDescriptor

A bundle descriptor is how Iltero Platform serves a signed assertion bundle. It carries the signed Open Policy Agent
(OPA) bundle tarball and each assertion's source, so a tool can recompile every assertion and compare the result
with the module in the tarball before it runs anything.

- **apiVersion:** `iltero.io/assertion-bundle/v1`
- **Model:** `iltero_schemas.models.bundle.BundleDescriptor`

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion` | string | `iltero.io/assertion-bundle/v1`. |
| `content_digest` | digest | The digest of the bundle's content: the `metadata.iltero` object of its `.manifest` file, which holds the `apiVersion`, `compiler_version`, `capabilities_digest`, `minimum_cli_version`, `assertion_set_digest` and `assertions` (each without its `source`). The `.manifest` file carries the same value under OPA's key `revision`. |
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
  `the bundle was compiled by compiler <version>; this package's is <version>`.
- `check_descriptor` refuses a descriptor whose `capabilities_digest` is not `iltero_schemas.opa.CAPABILITIES_DIGEST`:
  `the bundle was built under allowlist <digest>; this package's is <digest>`. The content digest covers the
  allowlist, so the same assertions built under another allowlist have another `content_digest`.
- The signing key must be in the trusted keys and must not be revoked.
- A descriptor is at most 64 MiB as canonical JSON (`iltero_schemas.models.bundle.MAX_DESCRIPTOR_BYTES`); a larger
  one is refused. The limit is applied to the parsed descriptor, so a tool also caps the bytes it reads before parsing.

## Trusted bundle keys

The trusted bundle keys file lists the public keys that may sign an assertion bundle. It ships inside the package
as `iltero_schemas/trust/bundle-keys.json`, so a tool that pins one package version also pins the keys it trusts.

- **apiVersion:** `iltero.io/bundle-keys/v1`
- **Reader:** `iltero_schemas.trust.parse_bundle_keys`, with the shipped set in `iltero_schemas.trust.BUNDLE_KEYS`
  and the digest of the file's bytes in `iltero_schemas.trust.TRUST_FILE_DIGEST`

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion` | string | `iltero.io/bundle-keys/v1`. |
| `keys` | list | Each key's `key_id`, `algorithm` (`ES256`), `public_key` (an uncompressed P-256 SubjectPublicKeyInfo, base64), `spki_sha256`, `status`, `valid_from`, `retired_at`, `revoked_at` and `revocation_reason`. |

Key rules:

- `active` keys sign and verify. `retired` keys only verify. `revoked` keys never verify again, whenever the
  signature was made.
- Keys are never removed. A status only moves forward: `active` to `retired` or `revoked`, `retired` to `revoked`.
- A key id starting with `dev-` (`iltero_schemas.trust.DEVELOPMENT_KEY_PREFIX`) is a development key. The reader
  refuses it, unless it is called with `development=True`, for a development tool's own local file; then every key
  must be a development key.
- Any change to the keys requires a new package version.
