# Document formats

Iltero components exchange JSON documents (an assertion is written in YAML). Each document named here has a
Pydantic model in `iltero_schemas.models`. A consumer validates a document with that model before it uses any value.

- [Conventions](#conventions)
- [TechnicalAssertion](#technicalassertion)
- [AssuranceContext](#assurancecontext)
- [AssuranceEvent](#assuranceevent)
- [Change Assurance Record (CAR)](#change-assurance-record-car)
- [VerificationReport](#verificationreport)
- [IdentityBindings](#identitybindings)
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
  Fields that carry data as another tool wrote it, such as a resource's planned values in an AssuranceContext,
  accept any JSON value.
- A list of names that the model keeps sorted is sorted by Unicode code point, with no name twice.
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
| stage | `plan`, `pre_deploy`, `post_deploy`, `post_verify` or `runtime`. |

## TechnicalAssertion

A technical assertion is a rule about infrastructure, written in YAML. It states what must be true, at which stage of
a change it is checked, and what kind of thing it is about. The compiler turns it into one OPA program.

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
| `spec.stage` | stage | When the assertion is checked. |
| `spec.target` | object | What the assertion is about. `kind` is `resource`, `change`, `deployment` or `assurance`. `resources` lists resource selectors: a `resource` target names exactly one; a `change` or `deployment` target may name up to 16, and is then in scope only when the change touches a resource one of them picks. |
| `spec.type` | string | Optional. `state` for a `resource` target, `process` otherwise. When written, it must match the target. |
| `spec.when` | object | Optional condition. When it is false, the result is `not_applicable`. |
| `spec.assert` | object | The rule. |

Key rules:

- Only these stage and target pairs are valid:

  | Target kind | Stages |
  | --- | --- |
  | `resource` | `plan`, `post_verify`, `runtime` |
  | `change` | `pre_deploy` |
  | `deployment` | `post_deploy`, `post_verify`, `runtime` |
  | `assurance` | `post_verify`, `runtime` |

- A resource selector is one of:

  | Selector | Where | Picks |
  | --- | --- | --- |
  | `{tool, provider, resource_types}` | A `resource` target: exactly one. | Resources of `provider` whose type, as the infrastructure-as-code (IaC) `tool` (`terraform`) spells it, is one of `resource_types` (1 to 64). A resource's values are that tool's own attributes. |
  | `{provider, kinds}` | A `change` target, or a `deployment` target at `post_deploy`: up to 16. | Resources of `provider` whose kind is one of `kinds` (1 to 64), from the provider's list (`iltero_schemas.kinds.RESOURCE_KINDS`). |

  A kind is a tool-independent name for what a resource is, such as `rds_instance`, so one selector holds for every
  IaC tool. Each tool's table gives its resource types their kinds: `iltero_schemas/kinds/terraform.json`, read with
  `iltero_schemas.kinds.kind_of`. From a `change` or `deployment` target's selectors the compiler writes a scope
  guard (`iltero_schemas.ast.scope.scope_guard`): a condition that decides whether the assertion applies. It is
  checked ahead of `when`, and holds when some resource of the provider has one of the kinds. A resource whose type
  the table lacks holds the unknown marker, so the guard is `unknown`, not `false`. When the guard is `false`, the
  result is `not_applicable`: the policy's reason is `when: false`, and the status reason is `when_guard_excluded`.
  A hand-written policy names no selectors.
- A rule is built from predicates. A predicate names a `path` and exactly one comparison: `equal`, `not_equal`,
  `greater_than`, `greater_than_or_equal`, `less_than`, `less_than_or_equal`, `in`, `not_in` or `contains`. The
  operand is a literal or `{path: ...}`. Predicates combine with `all`, `any`, `not` and `exists` (`in` and an
  optional `where`, in which `item` names the element).
- A path's first segment must be a part of the [assurance context](#assurancecontext) that the stage provides.
- A comparison between values of different types is false, never an error. `null` is not accepted as an operand.
- A predicate whose value is missing, redacted or not yet known is `unknown`, with a reason: `path_missing`, `redacted`,
  `not_a_list`, or the reason the value's marker carries (such as `known_after_deploy` or `not_reported_by_tool`, or
  `unspecified` when it carries none). `all`, `any`, `not` and `exists` follow three-valued logic. The assertion's
  result is `not_applicable`, `unknown`, `pass` or `fail`.
- Limits: a document of at most 256 KiB, nested at most 32 levels; at most 128 expressions (predicates and
  combinators), nested at most 8 levels, and 64 in one `all` or `any`; a path of at most 16 segments of 64 characters;
  at most 256 values in an `in` list; text values of at most 1024 characters; integers within ±(2^53 − 1). YAML
  anchors, aliases, tags, merge keys and duplicate keys are refused. The document is read as YAML 1.1, so unquoted
  `yes`, `no`, `on` and `off` are booleans.
- `iltero_schemas.ast.source_digest` gives the assertion's source digest. It covers the id, version, type, stage,
  target, `when` and `assert`, and not the title or the remediation. The compiler ignores both. The assertion's
  digest, the one evidence cites, is taken over the whole document and covers both.

```yaml
apiVersion: iltero.io/v1
kind: TechnicalAssertion
metadata:
  id: ACME.AWS.RDS.PRODUCTION_BASELINE
  version: "1.0.0"
  title: Production databases are encrypted and private
  remediation: Set storage_encrypted to true and publicly_accessible to false.
spec:
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
- **Model:** `iltero_schemas.models.context.AssuranceContext`. `iltero_schemas.profiles.profile_for(stage, kind)`
  gives the parts a stage provides.

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion` | string | `iltero.io/assurance-context/v1`. |
| `evaluation` | object | This evaluation: its `id`, `stage`, the runner's `timestamp`, and the `assertion` (`id`, `version`). |
| `organization_scope` | object | The `organization`, `workspace` and `environment`, each `null` when the run has none. The `environment` has its `name` and `production`: whether Iltero Platform's environment policy treats it as production, or the unknown marker in a run Iltero Platform did not open. |
| `reference_time` | object | The time every expiry and ordering comparison uses: `value`, `source` (`server`, `timestamp_authority`, `rekor` or `runner_clock`), `trust` (`attested`, `corroborated` or `asserted`; always `asserted` for `runner_clock`), and `time_window`: the two timestamps the evaluation sits between (`not_before`, `not_after`) and a `nonce_digest`, present exactly when `source` is `timestamp_authority`, otherwise left out or `null`. `not_before` ≤ `value` ≤ `not_after`. |
| `source` | object | The code the change comes from: `vcs` (`git`) and the `commit` (`sha`); the `repository` (`name`), `null` for a checkout with no remote; the `ref` (`type`: `branch` or `tag`, and `name`), `null` for a detached head; and the `pull_request` (`id`), `null` for a run outside a pull request. A run on a developer's machine is never a pull request. |
| `change` | object | The resources the plan changes (`id`, `provider`, `type`, `kind`, `action`, `module`), and the change `digest`: `iltero_schemas.canonical.change_digest({<unit>: plan.digest})`, where the unit is the subject's unit. A context with any other `digest` is refused. `provider` is the provider's short name: lower-case letters, digits, `_` and `-`, starting with a letter (`aws`, `google-beta`). `kind` is the kind the plan tool's table gives the type, or the unknown marker `{"__unknown": true, "reason": "kind_unmapped"}` when the table lacks it; it is `null` exactly for a provider with no kinds. A context whose kinds differ from the table's is refused. |
| `plan` | object | The IaC `tool` and `tool_version`, the plan `format_version`, the plan's digests, `source_commit`, whether the plan is `complete` and `applyable`, and the same table of contents for every resource the plan covers. `tool_version`, `complete` and `applyable` hold the unknown marker `{"__unknown": true, "reason": "not_reported_by_tool"}` when the tool's plan does not say; `null` is refused. |
| `subject` | object | The subject's `kind`, its `key`, its `identities` (`scheme`, `value`, `scope`), and `resolution` (`resolved` once a cloud identity is bound, `unresolved` until then). |
| `resource` | object | For a resource subject, the resource as planned: `id`, `provider`, `type`, `kind`, `name`, `module`, `action`, `before`, `after`, the resources that refer to it (`related`), and `tool_data`. |
| `deployment` | object | What the apply did: the applied `plan`, and `apply` with its `source` log, the `state` after it, `outcomes_from` (`apply_log`, or `apply_log_and_state` when the log lost messages and the state settled what it could), each change of the applied plan once (`changes`, each saying where its outcome came from in `outcome_from`: `apply_log`, `state` or `none`), `timing`, and `tool_data`: what only the IaC tool says, keyed by `tool`, which must be `apply.source.tool`. For `terraform`: the `summary` counts it reported, the `log_lines` it could not read (`other_output_lines`, `damaged_messages`, `interrupted_operations`), and the delete of each `deposed` object (an old copy a replacement set aside), settled by the state. `superseded_by` is `{"reason": "dependency_replanned"}` when the pipeline says it applied a re-plan, which must differ from the evaluated plan, and `null` otherwise. |
| `evaluations`, `approvals`, `exceptions` | list or marker | Facts only Iltero Platform holds, as the items below (`iltero_schemas.models.server_facts`). |
| `run` | object | The run the input belongs to, by Iltero's run `id`; an approval of a run names it. |
| `verification`, `assurance` | object | Facts after deployment. |

Key rules:

- The parts present are exactly those the stage's profile provides. A part outside the profile is written as `null`
  and reads as absent, as does one left out. A missing required part or an extra part is refused, and the error
  names it. `evaluation`, `organization_scope` and `reference_time` are always required. A resource
  target also requires `resource`.

  | Stage | Required | Optional |
  | --- | --- | --- |
  | `plan` | `source`, `change`, `plan`, `subject` | none |
  | `pre_deploy` | `source`, `change`, `plan`, `subject`, `evaluations`, `approvals`, `exceptions`, `run` | none |
  | `post_deploy` | `source`, `change`, `plan`, `subject`, `deployment` | none |
  | `post_verify` | `subject`, `deployment` | `source`, `verification`, `assurance` |
  | `runtime` | `subject` | `source`, `deployment`, `assurance`, `exceptions` |

- A subject's `key` is `sha256:` and the hex SHA-256 of the canonical bytes of `{"kind": <kind>, "identity": {"scheme":
  ..., "value": ..., "scope": ...}}`, the local identity with all three fields, `scope` as `null` when it has none,
  computed by `iltero_schemas.models.subjects.subject_key`. Every document is checked against it. The key is over
  the identity's text exactly as written, with no Unicode normalization, so a composed and a decomposed spelling of
  one character (`é` as U+00E9, or `e` and U+0301) give two keys. The
  local identity is exactly one of the subject's identities:

  | Subject | Local identity |
  | --- | --- |
  | A resource an IaC tool manages | Its address (`scheme: terraform_address`), with `scope` exactly `{"unit": <its unit>}`. |
  | A resource no IaC tool manages, read at `post_verify` or `runtime` | Its cloud identity (`scheme: aws_arn`). |
  | A `change`, `deployment` or `assurance` subject | Its unit (`scheme: iltero_unit`), with no `scope`. |

  The key names an address in a unit, not a cloud resource: a resource replaced in the cloud keeps its key, and a
  resource moved to another address gets a new one. Only an identity document ties a key to a cloud resource over
  time. A key is unique within one project's records. Neither a stack nor any other Iltero Platform scope is part of
  it, so a project keeps every key when it connects to Iltero Platform. A cloud identity bound later is added beside
  the local identity, never in its place. A resource subject's address is the `id` of the `resource` the input
  carries, and an event's local identity is of the event's `provenance.run.unit`.
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
  `relevant_attributes` (`PLAN_EXCLUDED_TOP_LEVEL_KEYS`).
  `artifact_digest` is the digest of the saved plan file. It is present exactly when `artifact_digest_source` is
  `plan_binary`, and `null` when it is `not_provided`. `ILT.DEPLOYMENT.PLAN_BINDING` compares `plan.digest`,
  `plan.artifact_digest` and `plan.artifact_digest_source` with the same fields of `deployment.plan`. When neither
  side was given the saved plan file, both artifact digests are `null` and both sources `not_provided`: the assertion
  passes, and the event's observations show `not_provided`. Such a pass shows that the applied plan's digest equals
  the evaluated plan's, not that the applied plan file is the evaluated one byte for byte. When only one side has
  the saved plan file, it fails.
- `plan.source_commit` equals `source.commit.sha`.
- A value removed by redaction is a marker, `{"__redacted": true, "reason": ..., "present": true, "type": ...}`. A
  value not yet known is `{"__unknown": true, "reason": ..., "present": true}`. A predicate that reaches either is
  `unknown`.
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
- The context holds no evaluator version, bundle digest or provenance.

The facts only Iltero Platform holds are normalised whatever produced them. Each item is Iltero Platform's claim, as
served.

| Item | Fields |
| --- | --- |
| Approval | `id`, `actor` (`provider`, and `id`: the provider's stable account id, never a login, a name or an address), `roles`, `status` (`approved`), `subject`, `method` (`ci_deployment_review` or `iltero_review`), `independence` (`independent` when the approver neither started the run nor triggered the attempt; `self_permitted_by_policy` otherwise, with the permitting `policy_version`, `null` when independent), `timestamp`. An approval from a CI deployment review names no role, since none is verified. |
| Exception | `id`, `status` (`approved`: only granted exceptions are served), `scope` (`assertion.id`, `environment`, and the `resources` it covers, by their identities), `valid_from`, `expires_at` (after `valid_from`), `approved_by`, `reason`. |
| Earlier evaluation | `id`, `assertion` (`id`, `version`), `stage`, `subject` (`kind`, `key`), `result.status`, `plan_digest` (`null` exactly for an evaluation at a stage that reads no plan, such as `runtime`), `observed_at`. |

- An approval's `subject` names what it approves: `{kind: change, digest}`, that plan and no other, or `{kind: run,
  id}`, Iltero's run, never a CI run. An approval of a run approves the run, not a plan's content: a CI deployment
  review approves the deploy job when it starts, whether or not that run has planned yet.
- `ILT.CHANGE.PRODUCTION_APPROVED` and `ILT.CHANGE.SENSITIVE_CHANGE_APPROVED` pass on an approved, independent
  approval of the change by its digest from the `security` role, or on an approval of the run whose `subject.id` is
  the input's `run.id`. Each is its own `exists`, so the observations show which one held. An approval of the run may
  be a self-approval the policy permitted; an approval of the change may not. For an approval of the run, both
  assertions read the same CI environment approval: there is no separate security sign-off behind it.

## AssuranceEvent

An assurance event is one verdict: the result of one assertion about one subject, with the provenance needed to say
who produced it and to reproduce it.

- **apiVersion:** none. An event travels inside a [CAR](#change-assurance-record-car).
- **Model:** `iltero_schemas.models.event.AssuranceEvent`

| Field | Type | Meaning |
| --- | --- | --- |
| `assertion` | object | The assertion's `id`, `version` and the `digest` of its document as it was read. |
| `subject` | object | The subject's `kind`, `key`, `identities` and `resolution`, in the same shape as on the evaluation input. `key` is `null`, and `identities` empty, exactly when no subject was in scope. |
| `evaluation` | object | The `stage`, the `status`, the runner's `status_reason` and `status_detail`, and the policy's own reason (`policy_reason`) and `observations`. |
| `provenance` | object | Where the verdict came from (see below). |
| `observed_at` | timestamp | The run's timestamp. Every event of one run carries the same value. |

| `provenance` field | Meaning |
| --- | --- |
| `run` | The run `id`, its `origin` (`server_issued` or `locally_derived`) and the `unit`. A unit is the part of a project the IaC tool plans and applies as one. |
| `source_commit`, `plan_digest` | The commit and the plan the evaluation is about. `plan_digest` holds the plan's digest (`value`), the IaC `tool` that wrote the plan, and the `version` of that tool's plan digest rule; any other `version` is refused. |
| `input_digest` | The digest of the assurance context the evaluator received. |
| `evaluator` | The engine that produced the verdict. For `opa`: its `version`, binary `digest` and the `limits` applied: `timeout_seconds`, `memory_limit`, `max_output_bytes`, `evaluations_per_process`, `capabilities_digest` and `platform`. For a scanner (`checkov`, `trivy` or `prowler`): its reported `version`, a `digest` when known, and `reason: not_executed_by_cli`. |
| `bundle` | The bundle the program came from: `kind` (`server` or `local_bundle`) and `digest`. Present exactly when the evaluator is `opa`. |
| `binding` | The evaluator binding that let a scanner's result stand for the assertion. Present exactly when the evaluator is a scanner. |
| `assertion_source`, `assertion_source_digest` | Where the assertion came from, and its source digest. `server_bundle`: an assertion bundle Iltero Platform served. `local`: the project's own files; `custom_rego` when hand-written in Rego. `contract_starter`: a starter assertion this package ships, added to a local run. The writer's claim. |
| `compiled_digest`, `compiler` | The compiled program's digest, and the compiler's `version`, `contract_version`, `contract_digest` and `install` (`wheel` or `editable`). Absent for a scanner. |
| `executor` | Who ran the evaluation: `type` (`human` or `workload`), `provider` (`local`, `ci` or a CI system such as `github_actions`) and the CI system's run id (`ci_run_id`). |
| `facts_source` | For an evaluation at a stage whose input may carry Iltero Platform facts (approvals, exceptions, earlier evaluations: `pre_deploy` and `runtime`), where they came from: `server`, `local_file` or `none`. `null` at every other stage. |

Key rules:

- `status` is one of six values. Only `pass` and `fail` may omit `status_reason`, and a reason must belong to its
  status:

  | Status | Reasons |
  | --- | --- |
  | `pass` | none |
  | `fail` | none: a failure's reason is the policy's `policy_reason` |
  | `unknown` | `known_after_deploy`, `redacted`, `path_missing`, `not_a_list`, `unspecified`, `server_facts_unavailable`, `not_reported_by_tool`, `reference_time_untrusted`, `deployment_log_incomplete`, `kind_unmapped` |
  | `not_applicable` | `when_guard_excluded`, `no_subject_in_scope` |
  | `not_evaluated` | `scanner_not_run`, `credential_denied`, `resource_type_unsupported`, `binding_unverified`, `timeout`, `subject_unresolved`, `evaluator_unavailable`, `identity_unverified`, `stage_not_run` |
  | `error` | `evaluator_crash`, `evaluator_timeout`, `evaluator_memory_limit`, `output_overflow`, `output_contract_violation`, `adapter_parse_failure`, `bundle_verification_failed`, `compile_failure` |

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

A Change Assurance Record (CAR) is the record of one attempted infrastructure change, for one unit of one run. It
holds the evaluations, what the deployment did and the evidence each part cites. It exists whatever the outcome:
deployed, failed, stopped, refused before deployment, or a plan that changes nothing.

A CAR records technical and process assurance facts. It does not, by itself, establish certification or compliance
with a regulatory framework.

- **apiVersion:** `iltero.io/car/v1`
- **Model:** `iltero_schemas.models.car.CAR`

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion` | string | `iltero.io/car/v1`. |
| `uuid` | UUID | The record's id. |
| `run` | object | The run's `id` (UUID) and `origin` (`server_issued` or `locally_derived`). |
| `unit` | identifier | The unit the record covers. |
| `trust_level` | string | How far the record's facts were established (see below). Always `self_attested` in this version. |
| `compliance_determination` | null | Always `null`. |
| `issuer` | object | `type: local` and `identity_verified: false`. |
| `governance` | object | `run_opened_by`: `server` for a run Iltero Platform issued (`run.origin: server_issued`), `local` otherwise. |
| `subject` | object | `kind: change`, the `environment`, the `unit` and the `source`: the code the change comes from, in the shape of an [AssuranceContext](#assurancecontext)'s `source`. |
| `change` | object | `unit`: the record's own unit, by `name`, with its `plan.digest` (a change covers one unit); and the change `digest`: `iltero_schemas.canonical.change_digest({<unit>: plan.digest})`. |
| `units_file` | object or null | The project's units file as the writer read it: its `path` in the project, the SHA-256 `digest` of its bytes, and its `units` in deploy order (1 to 64 names of lowercase letters, digits, `_` and `-`, not starting with `-`, each once). `null` for a project that declares none. |
| `plan` | object | The plan's `digest`, `digest_version`, `artifact_digest`, `artifact_digest_source`, `context_digest` (the plan as kept after redaction), the IaC `tool`, `tool_version` and `format_version`, and whether the plan is `complete` and `applyable`. `tool_version`, `complete` and `applyable` hold the unknown marker `{"__unknown": true, "reason": "not_reported_by_tool"}` when the tool's plan does not say; `null` is refused. |
| `stages` | object | One entry per stage that reported, keyed by stage: what ran its evaluations (`execution`: the evaluator and bundle, or the `reason` nothing ran), the mode its gate ran in (`enforcement`: `enforcing` or `advisory`), the approvals its evaluations read (`approvals`: whatever their source, each listed once and of the record's change or run; `null` at a stage whose input carries no approvals), what was redacted (`redaction`), the files written, what it read from scanner reports (`scanners`), and the stage's own `coverage`, `verdict` and `assurance_status`. Its `reference_time` has the shape and rules of an [AssuranceContext](#assurancecontext)'s; read from the runner's clock (`source: runner_clock`), its `value` is the same instant as the stage's `observed_at`. Its `redaction` is its redaction report (see below). |
| `events` | list | Every [event](#assuranceevent), grouped in stage order. At most 100,000. |
| `coverage` | object | The stages' coverage combined: subjects in scope and evaluated, assertions expected and evaluated, counts per status, the number of `evaluations`, gaps, truncation and sampling, and the inputs replaced with placeholders (`substituted_inputs`), each naming its stage. |
| `verdict` | object | `value` (`pass`, `fail` or `indeterminate`), `exit_code`, `computed_from` (`status_counts` for a stage, `stage_precedence` for the record) and the deciding `stage`. |
| `assurance_status` | object | `complete` or `incomplete`, with a `reason`: `required_policy_evaluation_failed` (an evaluation ended in an evaluator error), `plan_not_complete` (the plan said it is incomplete, or did not say it is complete) or `upstream_state_unavailable` (the stage read placeholders for an input). The `reason` is the leading cause, in that order; every cause stays in the stage's `coverage`: its gaps, substituted inputs and error count. A record that is `complete` (every expected stage reported) can still be `incomplete` here. |
| `complete` | boolean | Whether every expected stage has reported. |
| `expected_stages` | list | The stages the record expects. |
| `out_of_scope` | list | Each lifecycle stage the record does not expect, with a `reason` (`project_config` or `not_supported`). |
| `deployment` | object or null | What the apply did. `null` until the `post_deploy` stage reports. |
| `identity` | object or null | The unit's [identity bindings](#identitybindings) after the apply. Present exactly when `deployment` is. |
| `evidence_refs` | list | The evidence register: every file the record cites (see below). At most 100,000. |
| `integrity` | object | `scheme: file_digests` (the record is bound together by its files' digests only) and `signature: null`. |
| `expires_at`, `retention_class` | null | Always `null`. |
| `retention_reason` | string | `no_server_scope`. |

Trust levels, from weakest to strongest:

| Level | Meaning |
| --- | --- |
| `self_attested` | The tool that wrote the record is its only source. |
| `source_authenticated` | A service other than the writer authenticated the repository, the CI system and the identities named in the record. |
| `governed` | Iltero Platform enforced a declared assurance profile and verified the evidence chain. |

Every level above `self_attested` requires a signature. This version of the record carries none, so the model
accepts only `self_attested`.

A stage's redaction report (`redaction`) says what the stage's redaction hid, left unknown or allowed, by
path. It holds no value.

| Field | Type | Meaning |
| --- | --- | --- |
| `policy` | object | The redaction policy that ran: `id`, `version` (identifiers) and `digest`. |
| `input` | object | What was redacted: `kind` (`observation`, `facts` or `deployment`) and the `digest` of the redacted tree. |
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
| `source` | object or null | Identifiers that name what the file was made from, such as the `name` and `digest` of a tool's output. `null` when the entry names none. |
| `canonicalization` | identifier or null | The canonical form the file's bytes are in, such as `RFC8785`, or `null`. |
| `redaction_policy` | object or null | The redaction policy that redacted the file's content, in the shape of a redaction report's `policy`: `id`, `version` and `digest`. `null` for a file no redaction touched. |

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

A stage's `coverage.gaps` lists what is missing from what the stage evaluated. Each gap has one of three shapes,
chosen by its `kind`:

| `kind` | Other field | Meaning |
| --- | --- | --- |
| `plan_incomplete`, `plan_not_applyable` | `value`: `false` or the `not_reported_by_tool` marker | A plan flag that is not `true`. The kind names the flag (`plan_incomplete` for `complete`, `plan_not_applyable` for `applyable`) and `value` carries what the plan said: `false` means the plan said so, the marker means it did not say. |
| `identity_redacted`, `identity_unnameable` | `plan_index`: integer from 0 | A plan resource whose identity was redacted or cannot be named, by its index in the plan's resource list. |
| `deferred_changes`, `related_copies_omitted`, `unresolved_references`, `accepted_by_binding`, or a `not_evaluated` or `error` [status reason](#assuranceevent) | `count`: integer from 1 | How many of one thing are missing: what the plan left out, evaluations that stand on a scanner's result a binding accepted rather than on a program the run ran, or evaluations with that `not_evaluated` or `error` reason. |

A gap in a stage's own `coverage` names no `stage`: the field is left out or `null`. The record's combined `coverage`
names the stage each gap came from. The kinds a count gap may name are
`iltero_schemas.models.coverage.COUNT_GAP_KINDS`. A coverage lists at most
`iltero_schemas.models.coverage.MAX_GAPS` gaps.

Key rules:

- Every path in the record is relative to the record's directory, except `units_file.path` and
  `out_of_scope[].declared_in.path`, which are relative to the project and hold no `.` or `..` part and no `:` (a
  Windows drive or file stream). A path in the
  record's directory is plain names joined by `/`, at most 6 deep and 1024 characters, each name using only letters,
  digits, `.`, `_`, `@` and `-`, and never `.` or `..`. No two `evidence_refs` entries share a `path` or a `ref_id`.
- A record redacts under one policy: every stage's `redaction.policy` and every `evidence_refs[].redaction_policy`
  that is not `null` name the same `id`, `version` and `digest`, whatever the validation context. The digest tells
  apart two policies that share an `id` and `version`.
- The first expected stage is `plan`, and `post_deploy` is always expected. `runtime` is never a stage of a record.
  Every lifecycle stage is either expected or listed once in `out_of_scope`. Only `pre_deploy` can be left out by
  `project_config`, and it then names the declaring file in `declared_in`.
- A stage's verdict follows from its own counts. Exit code `6` (coverage gap), `4` (evaluator error), `3`
  (indeterminate), `1` (assertion failed) or `0` applies, and the stage takes the first in the order
  `2, 5, 9, 10, 7, 8, 6, 4, 3, 1, 0`. The record's verdict is the stage verdict that comes first in that order, and
  it names that stage.
- A stage's evaluations are about one kind of subject, one its assertions can target, and the stage counts its
  subjects by that kind (`iltero_schemas.models.stages.scope_counted_from`): the plan stage enumerates the plan's
  resources (`counted_from: plan_resource_enumeration`); a change counts as its one unit (`change_unit`, with the
  record's `change.digest` as its `source_digest`); a deployment counts as its one unit (`deployment_unit`). Only the
  plan stage enumerates the plan's resources. A stage with no evaluations counts by the one kind its assertions can
  target. A stage that counts a change or a deployment has exactly one subject in scope, none removed by the plan and
  none excluded.
- `enforcement` is the mode the stage's gate ran in. Under `enforcing`, every non-zero exit code stopped the pipeline.
  Under `advisory`, a verdict with exit code `1` or `3` did not stop it; every other non-zero code did. A waiver
  happened when a stage is `advisory` and its exit code is `1` or `3`. Only the plan and pre-deploy stages can be
  `advisory`. In a run Iltero Platform opened, Iltero Platform's policy sets it; otherwise it is the tool's choice.
  It is the writer's claim; only the CI job's own result shows what the pipeline did.
- A stage that could not read an input, such as the state of a unit it reads from, lists each replaced input once in
  `coverage.substituted_inputs`: `kind: upstream_state` and the input's `source`, the tool's address of the input (for
  a Terraform configuration, its module path and data source, with no instance key). A stage lists at most 256, sorted
  by `source` by Unicode code point; a record lists at most 256 across its stages. Its verdict still follows its
  evaluations, and it is `incomplete` with reason `upstream_state_unavailable`; an evaluator error's or the plan's
  reason wins when there is one.
- A `pass` or exit code `0` on a stage that lists `substituted_inputs` is a verdict on the placeholder plan, not on
  the change: a gate reads `assurance_status` with the verdict. The record's reason is the first stage's that is
  incomplete for an evaluator error, or else the first incomplete stage's; readers find placeholder use by
  `coverage.substituted_inputs`, not by the reason.
- The plan stage lists one plan-flag gap for each plan flag that is not `true`, with the plan's flag as its `value`,
  in kind order: `plan_incomplete` before `plan_not_applyable`. A plan-flag gap in any other stage is refused.
- A plan stage with a `plan_incomplete` gap is `incomplete` with reason `plan_not_complete`, and its verdict still
  follows its evaluations. The `detail` is `the plan says it is incomplete` (`value: false`) or `the plan does not say
  it is complete` (the marker). An evaluator error's reason wins over it; it wins over `upstream_state_unavailable`. A
  `plan_not_applyable` gap leaves the status as it is: Terraform marks a plan that changes nothing as not applyable.
- The model runs the integrity checks: it recomputes every value a reader can recompute and refuses a record whose
  value differs. They cover the change digest and the digests bound to it (the pre-deploy stage's
  `coverage.subjects_in_scope.source_digest` and each approval of a change), status counts from events, each stage's
  verdict and status, the plan stage's plan-flag gaps and the combined top level. The change digest problems come
  first, so a forged `change.digest` is refused as `change.digest is not the digest of the change's units`. A reader
  that reports integrity failures itself sets `SKIP_INTEGRITY_CHECKS` (`iltero_schemas.models.car`) to `True` in the
  validation context (any other value is ignored), then calls `iltero_schemas.models.stages.integrity_problems`, which
  returns every problem as a `(where, what)` pair. An approval of another run is refused whatever the context.
- A record of a run the tool opened (`run.origin: locally_derived`) names no Iltero Platform bundle, no evaluation
  from one, no facts from Iltero Platform, and no stage `reference_time` from it (`source: server`). A record of a
  run Iltero Platform opened says so everywhere: `run.origin: server_issued`, `governance.run_opened_by: server`, and
  every stage's `coverage.assertions_expected.origin` is `server_pinned`. Either way the record is the writer's own:
  only Iltero Platform can confirm a run it opened, by its `run.id`.
- `plan.digest_version` is the version of the plan digest rule for `plan.tool`; any other version is refused. Every
  event's `provenance.plan_digest` names the record's plan: the same `value`, `version` and `tool`.
- The change digest is the digest of `[{"unit": name, "plan": {"digest": ...}}]`, sorted by unit name
  (`iltero_schemas.canonical.change_digest`), over the change's one unit. Approvals bind to it. A record's
  `change.unit` is its own unit with the plan it names. A unit is planned, approved and applied on its own.
- A record's `subject.unit` is its `unit`. When `units_file` is set, the record's `unit` is one of its `units`.
- Across records: the records of one run share `run.id`, and every one of them names the same `units_file`, or
  every one names `null`. The run has a record for each declared unit when the records' units equal `units_file.units`.
  The units file is the writer's copy: records cannot show a run with no record at all, or a units file the writer
  left out or shortened. Only the file at the record's commit can, by its digest.
- A stage's `coverage.assertions_expected.required_assertion_digest` is the digest of the assertions it owed, whether
  or not each was evaluated: as the project's files gave them (`origin: locally_derived`), or as Iltero Platform set
  them for the run (`origin: server_pinned`). The model does not recompute a stage's digest.
- These rules establish consistency only. An unsigned record cannot prove that Iltero Platform opened its run. Only
  Iltero Platform can confirm a run, by its `run.id`.
- `compiler.contract_digest` is the SHA-256 over the sorted `path,hash` lines of the wheel's `RECORD` entries for the
  package's own files. `iltero_schemas.distribution.installed_identity()` returns it for the installed package. An
  editable install has none.

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

| Property | It is `verified` when |
| --- | --- |
| `integrity` | The record's structure and signature are valid, and the evidence it cites is unchanged. |
| `source_identity` | The repository, commit and pipeline came from an authenticated source. |
| `approval_identity` | Every approval came from an authenticated identity. |
| `bundle_provenance` | The evaluations ran from a bundle signed by an authorised key that was not revoked. |
| `stage_completeness` | Every required stage is present, and every evaluation owed has a result or is listed as not evaluated. |
| `plan_apply_match` | The approved plan is the applied plan. |
| `runtime_verification` | A verification ran after the deployment. |
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

- `integrity` is never `verified`, because no record carries a signature in this version. Matching digests give
  `client_asserted`.
- When `integrity` is `failed` or `not_determined`, every other property is `not_determined`.
- The report has no overall verdict. A report in which every property is `verified` does not establish
  certification or compliance with a regulatory framework.

## IdentityBindings

An identity bindings document ties each resource of one unit's IaC configuration to the cloud resource it created,
after an apply. A resource is bound only by a resolver verified for its type, and otherwise listed as unresolved
with a reason. A resolver is the part of a tool that reads identifiers for one cloud provider.

- **apiVersion:** `iltero.io/identity-bindings/v1`
- **Model:** `iltero_schemas.models.identity.IdentityBindings`

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion` | string | `iltero.io/identity-bindings/v1`. |
| `unit` | identifier | The unit. |
| `generator` | object | `name: iltero` and the writer's `version`. |
| `sources` | object | The `state` read (its digest, IaC `tool` and `tool_version`) and the applied `plan` (`digest`, `digest_version`), or `null` when no applied plan was read. |
| `resolvers` | list | One resolver per cloud provider, sorted by provider, at most 16. Each names its `provider`, `version` and the resource types verified for it (`verified_resource_types`). |
| `bindings` | list | Each managed resource in the state after the apply that was bound: `iac` (`tool`, `unit`, `address`), `cloud` (per provider) and `resolution: resolved`. |
| `unresolved` | list | Each managed resource that was not bound: `address` and `reason`. |
| `removed`, `removed_unresolved` | list or null | Each object that left the state during the apply, by its identity before the apply, with its `removal` (`deleted` or `forgotten`). |
| `tool_data` | object | What only the state's IaC tool says, keyed by `tool`, which must be `sources.state.tool`. For `terraform`: `deposed_deleted` (integer or null), how many deposed objects the apply deleted, and `deposed_remaining`, how many the state still holds. |

Key rules:

- Each resource appears once in each half, either bound or unresolved, never both. Both lists are sorted by address.
- No two entries of `bindings` name the same cloud identity: the same `provider`, `identifier.scheme` and
  `identifier.value`, compared exactly as written. The same holds within `removed`. The two lists are not compared with
  each other: for example, a resource destroyed and created again under the same name in one apply appears in both.
  The removed entry's `removal` says whether the old object was deleted or only forgotten.
- A binding is accepted only for a resource type its provider's resolver lists in `verified_resource_types`.
- Every entry of `bindings` and `removed` names the document's `unit` in `iac.unit`, and the tool in
  `sources.state.tool` in `iac.tool`.
- An unresolved `reason` is the first that holds, in this order: `no_resolver`, `provider_untrusted`,
  `resolver_unverified`, `identifier_sensitive`, `identifier_invalid`, `identifier_missing`,
  `identifier_ambiguous`.
- For `aws`, `cloud` holds the `resource_type` (`s3_bucket`, `rds_instance`, `security_group`, `iam_role` or
  `kms_key`) and the `identifier` (`scheme: aws_arn`, `value`). Each ARN must match its type's published
  naming rule, holds no wildcard and is at most 2048 characters. An S3 bucket name and an RDS instance identifier are
  lowercase, as AWS stores them.
- `removed`, `removed_unresolved` and `tool_data.deposed_deleted` are `null` exactly when `sources.plan` is
  `null`.
- `sources.plan.digest_version` is the version of the plan digest rule for `sources.state.tool`, since the tool that
  wrote the state wrote the applied plan. Any other version is refused.
- The document carries identifiers only. The state file it was read from never leaves the machine that read it.

## EvaluatorBindingSet

An evaluator binding set is a set of licences. Each entry says that one rule of one scanner (Checkov calls its rules
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
| `tool` | string | `checkov`, `trivy` or `prowler`. |
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

- The stage and the target kind form a combination a TechnicalAssertion also allows.
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
| `revision` | digest | The address of the bundle's content. |
| `digest` | digest | The SHA-256 of the decoded tarball bytes. |
| `key_id` | identifier | The key that signed the bundle. |
| `algorithm` | string | `ES256`. |
| `compiler_version` | identifier | The compiler version the modules were built with. |
| `minimum_cli_version` | string | The oldest CLI version able to evaluate the bundle. |
| `assertion_set_digest` | digest | The digest of every assertion in the bundle, by id, version and document digest. |
| `assertions` | list | 1 to 1,024 assertions, sorted by id: `id`, `version`, `digest`, `source_digest`, `compiled_digest` and the YAML `source`. |
| `tarball` | string | The signed tarball, standard base64 with padding, at most 16 MiB decoded. |

Key rules:

- The same content signed under two keys has one `revision` and two `digest` values.
- `assertion_set_digest` names everything in the bundle.
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
- A key id starting with `dev-` is a development key and is refused.
- Any change to the keys requires a new package version.
