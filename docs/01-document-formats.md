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
- [Attestation](#attestation)
- [EvaluatorBindingSet](#evaluatorbindingset)
- [PolicySourceManifest](#policysourcemanifest)
- [BundleDescriptor](#bundledescriptor)
- [Trusted bundle keys](#trusted-bundle-keys)

## Conventions

Every model applies the same rules:

- A key the model does not define is refused.
- No value is converted. The string `"true"` is not a boolean, and `"7"` is not a number.
- A text field the model types (a name, an identifier, an address, a title) never contains a control character,
  a zero-width character or a bidirectional formatting character. Fields that carry data as another tool wrote it,
  such as a resource's planned values in an AssuranceContext, accept any JSON value.
- A list of names that the model keeps sorted is sorted by Unicode code point, with no name twice.

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

A technical assertion is a compliance rule written in YAML. It states what must be true, at which stage of a change
it is checked, and what kind of thing it is about. The compiler turns it into one OPA program.

- **apiVersion:** `iltero.io/v1`, with `kind: TechnicalAssertion`
- **Model:** `iltero_schemas.models.assertion.TechnicalAssertion`. `iltero_schemas.ast.parse` reads the YAML text,
  applies the limits below and validates the rule's grammar.

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion`, `kind` | string | `iltero.io/v1` and `TechnicalAssertion`. |
| `metadata.id` | string | Upper-case segments joined by dots, at least two, at most 128 characters. `ILT.` is reserved for assertions Iltero maintains. The first segment must not be a Windows device name (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`). |
| `metadata.version` | string | A semantic version `X.Y.Z`. Evidence cites the assertion's digest, not this version. |
| `metadata.title` | string | One line, at most 200 characters. |
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
  `iltero_schemas.kinds.kind_of`. The compiler writes a `change` or `deployment` target's scope check from its
  selectors, ahead of `when`: some resource of the provider has one of the kinds. A resource whose type the table
  lacks holds the unknown marker, so the check is `unknown`, not `false`. A target out of scope is
  `not_applicable` with the reason `when: false`. A hand-written policy names no selectors.
- A rule is built from checks. A check names a `path` and exactly one comparison: `equal`, `not_equal`,
  `greater_than`, `greater_than_or_equal`, `less_than`, `less_than_or_equal`, `in`, `not_in` or `contains`. The
  operand is a literal or `{path: ...}`. Checks combine with `all`, `any`, `not` and `exists` (`in` and an optional
  `where`, in which `item` names the element).
- A path's first segment must be a part of the [assurance context](#assurancecontext) that the stage provides.
- A comparison between values of different types is false, never an error. `null` is not accepted as an operand.
- A check whose value is missing, hidden or not yet known is `unknown`, with a reason: `path_missing`, `redacted`,
  `not_a_list`, or the reason the value's marker carries (`known_after_deploy`, or `unspecified` when it carries
  none). `all`, `any`, `not` and `exists` follow three-valued logic. The assertion's result is `not_applicable`,
  `unknown`, `pass` or `fail`.
- Limits: a document of at most 256 KiB, nested at most 32 levels; at most 128 checks, nested at most 8 levels, and
  64 in one `all` or `any`; a path of at most 16 segments of 64 characters; at most 256 values in an `in` list; text
  values of at most 1024 characters; integers within ±(2^53 − 1). YAML anchors, aliases, tags, merge keys and
  duplicate keys are refused. The document is read as YAML 1.1, so unquoted `yes`, `no`, `on` and `off` are
  booleans.
- `iltero_schemas.ast.source_digest` gives the assertion's source digest. It covers the id, version, type, stage,
  target, `when` and `assert`, and not the title.

```yaml
apiVersion: iltero.io/v1
kind: TechnicalAssertion
metadata:
  id: ACME.AWS.RDS.PRODUCTION_BASELINE
  version: "1.0.0"
  title: Production databases are encrypted and private
spec:
  stage: plan
  target:
    kind: resource
    resources:
      - tool: terraform
        provider: aws
        resource_types: [aws_db_instance]
  when:
    path: context.environment.production
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
| `context` | object | The `organization`, `workspace` and `environment`, each present only when known. The `environment` has its `name` and `production`: whether Iltero Cloud's policy treats it as production, or the unknown marker in a run Iltero Cloud did not open. |
| `reference_time` | object | The time every expiry and ordering comparison uses: `value`, `source` (`server`, `timestamp_authority`, `rekor` or `runner_clock`) and `trust` (`attested`, `corroborated` or `asserted`). |
| `source` | object | The git `commit`, and the `repository`, `ref` and `pull_request` when known. |
| `change` | object | The resources the plan changes (`id`, `provider`, `type`, `kind`, `action`, `module`), and the change `digest` once known. `provider` is the provider's short name (`aws`). `kind` is the kind the plan tool's table gives the type, or the unknown marker `{"__unknown": true, "reason": "kind_unmapped"}` when the table lacks it; it is `null` exactly for a provider with no kinds. A context whose kinds differ from the table's is refused. |
| `plan` | object | The IaC `tool` and `tool_version`, the plan `format_version`, the plan's digests, `source_commit`, and the same table of contents for every resource the plan covers. |
| `subject` | object | The subject's `kind`, local `id`, its `identities` (`scheme`, `value`, `scope`), and `authority` (`authoritative` once a cloud identity is bound, `unresolved` until then). |
| `resource` | object | For a resource subject, the resource as planned: `id`, `provider`, `type`, `action`, `before`, `after`, `related` and more. |
| `deployment` | object | What the apply did. |
| `evaluations`, `approvals`, `exceptions` | list or marker | Facts only Iltero Cloud holds, as the items below (`iltero_schemas.models.server_facts`). |
| `run` | object | The run the input belongs to, by Iltero's run `id`; an approval of a run names it. |
| `verification`, `assurance` | object | Facts after deployment. |

Key rules:

- The parts present are exactly those the stage's profile provides. A missing required part or an extra part is
  refused, and the error names it. `evaluation`, `context` and `reference_time` are always required. A resource
  target also requires `resource`.

  | Stage | Required | Optional |
  | --- | --- | --- |
  | `plan` | `source`, `change`, `plan`, `subject` | none |
  | `pre_deploy` | `source`, `change`, `plan`, `subject`, `evaluations`, `approvals`, `exceptions`, `run` | none |
  | `post_deploy` | `source`, `change`, `plan`, `subject`, `deployment` | none |
  | `post_verify` | `subject`, `deployment` | `source`, `verification`, `assurance` |
  | `runtime` | `subject` | `source`, `deployment`, `assurance`, `exceptions` |

- A resource is named by its address in the IaC tool's configuration. `provider` is the short name an assertion
  targets (`aws`), and `provider_source` is the provider's full source address.
- `plan.digest` is the digest of the plan as `terraform show -json` prints it, after the top-level keys `timestamp`,
  `terraform_version`, `format_version`, `prior_state`, `resource_drift` and `relevant_attributes` are removed.
  `digest_version` names that rule. `artifact_digest` is the digest of the saved plan file. It is present exactly
  when `artifact_digest_basis` is `plan_binary`, and `null` when it is `not_provided`.
- `plan.source_commit` equals `source.commit.sha`.
- A value hidden by redaction is a marker, `{"__redacted": true, "reason": ..., "present": true, "type": ...}`. A
  value not yet known is `{"__unknown": true, "reason": ..., "present": true}`. A check that reaches either is
  `unknown`.
- `context.environment.production` comes from Iltero Cloud's policy for the run's environment. A run Iltero Cloud did
  not open cannot know it, so it is the unknown marker, and a guard on it is `unknown`, never `false`: a run without
  the server never silently skips a production check.
- A fact Iltero Cloud could not supply is the marker `{"__unknown": true, "reason": "server_facts_unavailable"}`,
  never an empty list. A check that reads it is `unknown`, never `fail`.
- The context holds no evaluator version, bundle digest or provenance.

The facts only Iltero Cloud holds are normalised whatever produced them. Each item is Iltero Cloud's claim, as
served.

| Item | Fields |
| --- | --- |
| Approval | `id`, `actor` (`provider`, and `id`: the provider's stable account id, never a login, a name or an address), `roles`, `status` (`approved`), `subject`, `method` (`ci_deployment_review` or `iltero_review`), `independence` (`independent` when the approver neither started the run nor triggered the attempt; `self_permitted_by_policy` otherwise, with the permitting `policy_version`, `null` when independent), `timestamp`. An approval from a CI deployment review names no role, since none is verified. |
| Exception | `id`, `status` (`approved`: only granted exceptions are served), `scope` (`assertion.id`, `environment`, and the `resources` it covers, by their identities), `valid_from`, `expires_at` (after `valid_from`), `approved_by`, `reason`. |
| Earlier evaluation | `id`, `assertion` (`id`, `version`), `stage`, `subject` (`kind`, `id`), `result.status`, `plan_digest`, `observed_at`. |

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
| `subject` | object | The subject's `kind`, local `id`, `identities` and `authority`. `id` is `null` only when no subject was in scope. |
| `evaluation` | object | The `stage`, the `status`, the runner's `status_reason` and `status_detail`, and the policy's own `reason` and `observations`. |
| `provenance` | object | Where the verdict came from (see below). |
| `observed_at` | timestamp | The run's timestamp. Every event of one run carries the same value. |

| `provenance` field | Meaning |
| --- | --- |
| `run` | The run `id`, its `basis` (`server_issued` or `locally_derived`) and the `unit`. A unit is the part of a project the IaC tool plans and applies as one. |
| `source_commit`, `plan_digest` | The commit and the plan the check is about. |
| `input_digest` | The digest of the assurance context the evaluator received. |
| `evaluator` | The engine that produced the verdict. For `opa`: its `version`, binary `digest` and the limits applied (`environment`, including `capabilities_digest`). For a scanner (`checkov`, `trivy` or `prowler`): its reported `version`, a `digest` when known, and `basis: not_executed_by_cli`. |
| `bundle` | The bundle the program came from: `kind` (`server` or `local_bundle`) and `digest`. Present exactly when the evaluator is `opa`. |
| `binding` | The evaluator binding that let a scanner's result stand for the assertion. Present exactly when the evaluator is a scanner. |
| `assertion_source`, `assertion_source_digest` | Where the assertion came from, and its source digest. `server_bundle`: the Iltero Cloud bundle. `local`: the project's own files; `custom_rego` when hand-written in Rego. `contract_starter`: a starter assertion this package ships, added to a local run. The writer's claim. |
| `compiled_digest`, `compiler` | The compiled program's digest, and the compiler's `version`, `contract_version`, `contract_digest` and `install` (`wheel` or `editable`). Absent for a scanner. |
| `executor` | Who ran the evaluation: `type` (`human` or `workload`), `provider` (`local`, `ci` or a CI system such as `github_actions`) and `run_id`. |
| `facts_source` | For a check at a stage whose input may carry Iltero Cloud facts (approvals, exceptions, earlier evaluations: `pre_deploy` and `runtime`), where they came from: `server`, `local_file` or `none`. `null` at every other stage. |
| `fs_hardening` | How the writer protected its files: `posix`, `windows_profile_acl` or `none`. |

Key rules:

- `status` is one of six values. Only `pass` and `fail` may omit `status_reason`, and a reason must belong to its
  status:

  | Status | Reasons |
  | --- | --- |
  | `pass` | none |
  | `fail` | none: a failure's reason is the policy's `reason` |
  | `unknown` | `known_after_deploy`, `redacted`, `path_missing`, `not_a_list`, `unspecified`, `server_facts_unavailable`, `reference_time_untrusted`, `deployment_log_incomplete` |
  | `not_applicable` | `when_guard_excluded`, `no_subject_in_scope` |
  | `not_evaluated` | `scanner_not_run`, `credential_denied`, `resource_type_unsupported`, `binding_unverified`, `timeout`, `subject_unresolved`, `evaluator_unavailable`, `identity_unverified`, `stage_not_run` |
  | `error` | `evaluator_crash`, `evaluator_timeout`, `evaluator_memory_cap`, `output_overflow`, `output_contract_violation`, `adapter_parse_failure`, `bundle_verification_failed`, `compile_failure` |

- A policy can return `pass`, `fail`, `unknown` or `not_applicable`. Only the runner sets `not_evaluated` and
  `error`.
- A policy verdict names its `input_digest`. When no subject was in scope, the event has no subject `id` and no
  `input_digest`.
- `evaluator` is `null` only for `evaluator_unavailable` and `no_subject_in_scope`.
- From worst to best, statuses rank `not_evaluated`, `error`, `unknown`, `fail`, `not_applicable`, `pass`
  (`iltero_schemas.models.event.STATUS_SEVERITY`).
- A policy's `reason` is at most 2 KiB. Its `observations` are at most 512 KiB of canonical JSON, nested at most 4
  levels.

## Change Assurance Record (CAR)

A Change Assurance Record (CAR) is the record of one attempted infrastructure change, for one unit of one run. It
holds the checks, what the deployment did and the evidence each part cites. It exists whatever the outcome:
deployed, failed, stopped, refused before deployment, or a plan that changes nothing.

A CAR records technical and process assurance facts. It does not, by itself, establish certification or compliance
with a regulatory framework.

- **apiVersion:** `iltero.io/car/v1`
- **Model:** `iltero_schemas.models.car.CAR`

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion` | string | `iltero.io/car/v1`. |
| `uuid` | UUID | The record's id. |
| `run_id` | object | The run's `value` (UUID) and `basis` (`server_issued` or `locally_derived`). |
| `unit` | identifier | The unit the record covers. |
| `trust_level` | string | How far the record's facts were established (see below). Always `self_attested` in this version. |
| `compliance_determination` | null | Always `null`. |
| `issuer` | object | `type: local` and `identity_verified: false`. |
| `governance` | object | `run_opened_by`: `server` for a run Iltero Cloud issued (`run_id.basis: server_issued`), `local` otherwise. |
| `subject` | object | `kind: change`, the `environment`, the `unit` and the `source` commit. |
| `change` | object | `unit`: the record's own unit, by `name`, with its `plan.digest` (a change covers one unit); and the change `digest` once the pre-deploy stage fixes it. |
| `units_file` | object or null | The project's units file as the writer read it: its `path` in the project, the SHA-256 `digest` of its bytes, and its `units` in deploy order (1 to 64 names of lowercase letters, digits, `_` and `-`, not starting with `-`, each once). `null` for a project that declares none. |
| `plan` | object | The plan's `digest`, `digest_version`, `artifact_digest`, `artifact_digest_basis`, `context_digest` (the plan as kept after redaction), the IaC `tool`, `tool_version` and `format_version`. |
| `stages` | object | One entry per stage that reported, keyed by stage: what ran it and under which limits, the mode its gate ran in (`enforcement`: `enforcing` or `advisory`), the approvals its checks read (`approvals`: whatever their source, each listed once and of the record's change or run; `null` at a stage whose input carries no approvals), what was redacted, the files written, scanner reports, and the stage's own `coverage`, `verdict` and `assurance_status`. |
| `events` | list | Every [event](#assuranceevent), grouped in stage order. At most 100,000. |
| `coverage` | object | The stages' coverage combined: subjects in scope and evaluated, assertions expected and evaluated, counts per status, checks, gaps, truncation and sampling, and the inputs replaced with placeholders (`substituted_inputs`), each naming its stage. |
| `verdict` | object | `value` (`pass`, `fail` or `indeterminate`), `exit_code`, `basis` and the deciding `stage`. |
| `assurance_status` | object | `complete` or `incomplete`, with a `reason`: `required_policy_evaluation_failed` (a check ended in an evaluator error) or `upstream_state_unavailable` (the stage read placeholders for an input). A record that is `complete` (every expected stage reported) can still be `incomplete` here. |
| `complete` | boolean | Whether every expected stage has reported. |
| `expected_stages` | list | The stages the record expects. |
| `not_in_scope` | list | Each lifecycle stage the record does not expect, with `basis` (`project_config` or `not_supported`). |
| `deployment` | object or null | What the apply did. `null` until the `post_deploy` stage reports. |
| `identity` | object or null | The unit's [identity bindings](#identitybindings) after the apply. Present exactly when `deployment` is. |
| `evidence_refs` | list | The evidence register: every file the record cites, by `ref_id`, `media_type`, `digest`, `size_bytes` and `path`. |
| `integrity` | object | `scheme: digest_linkage` and `signature: null`. |
| `expires_at`, `retention_class` | null | Always `null`. |
| `retention_basis` | string | `no_server_scope`. |

Trust levels, from weakest to strongest:

| Level | Meaning |
| --- | --- |
| `self_attested` | The tool that wrote the record is its only source. |
| `source_authenticated` | A service other than the writer authenticated the repository, the CI system and the identities named in the record. |
| `governed` | Iltero Cloud enforced a declared assurance profile and verified the evidence chain. |
| `assessor_reviewed` | A named external assessor reviewed the record. |
| `authority_accepted` | A named authority accepted the record for a stated purpose. |

Every level above `self_attested` requires a signature. This version of the record carries none, so the model
accepts only `self_attested`.

Key rules:

- Every path in the record is relative to the record's directory, except `units_file.path` and
  `not_in_scope[].declared_in.path`, which are relative to the project and hold no `.` or `..` part and no `:` (a
  Windows drive or file stream). A path in the
  record's directory is plain names joined by `/`, at most 6 deep and 1024 characters, each name using only letters,
  digits, `.`, `_`, `@` and `-`, and never `.` or `..`. No two `evidence_refs` entries share a `path` or a `ref_id`.
- The first expected stage is `plan`, and `post_deploy` is always expected. `runtime` is never a stage of a record.
  Every lifecycle stage is either expected or listed once in `not_in_scope`. Only `pre_deploy` can be left out by
  `project_config`, and it then names the declaring file in `declared_in`.
- A stage's verdict follows from its own counts. Exit code `6` (coverage gap), `4` (evaluator error), `3`
  (indeterminate), `1` (assertion failed) or `0` applies, and the stage takes the first in the order
  `2, 5, 9, 10, 7, 8, 6, 4, 3, 1, 0`. The record's verdict is the stage verdict that comes first in that order, and
  it names that stage.
- A stage's checks are about one kind of subject, one its assertions can target, and the stage counts its subjects
  by that kind (`iltero_schemas.models.stages.scope_basis`): the plan stage enumerates the plan's resources (`basis:
  plan_resource_enumeration`); a change counts as its one unit (`change_unit`, with the record's `change.digest` as
  its `source_digest`); a deployment counts as its one unit (`deployment_unit`). Only the plan stage enumerates the
  plan's resources. A stage with no checks counts by the one kind its assertions can target.
- `enforcement` is the mode the stage's gate ran in. Under `enforcing`, every non-zero exit code stopped the pipeline.
  Under `advisory`, a verdict with exit code `1` or `3` did not stop it; every other non-zero code did. A waiver
  happened when a stage is `advisory` and its exit code is `1` or `3`. Only the plan and pre-deploy stages can be
  `advisory`. In a run Iltero Cloud opened, Iltero Cloud's policy sets it; otherwise it is the tool's choice. It is
  the writer's claim; only the CI job's own result shows what the pipeline did.
- A stage that could not read an input, such as the state of a unit it reads from, lists each replaced input once in
  `coverage.substituted_inputs`: `kind: upstream_state` and the input's `source`, the tool's address of the input (for
  a Terraform configuration, its module path and data source, with no instance key). A stage lists at most 256, sorted
  by `source` by Unicode code point; a record lists at most 256 across its stages. Its verdict still follows its
  checks, and it is `incomplete` with reason `upstream_state_unavailable`; an evaluator error's reason wins when there
  is one.
- A `pass` or exit code `0` on a stage that lists `substituted_inputs` is a verdict on the placeholder plan, not on
  the change: a gate reads `assurance_status` with the verdict. The record's reason is the first stage's that is
  incomplete for an evaluator error, or else the first incomplete stage's; readers find placeholder use by
  `coverage.substituted_inputs`, not by the reason.
- The model recomputes every derived value: status counts from events, each stage's verdict, the change digest and
  the combined top level. A reader that reports a mismatch itself sets `DERIVED_CHECKED_BY_READER` in the validation
  context and calls `iltero_schemas.models.stages.derived_problems`.
- A record of a run the tool opened (`run_id.basis: locally_derived`) names no Iltero Cloud bundle, no check from one,
  and no facts from Iltero Cloud. A record of a run Iltero Cloud opened says so everywhere: `run_id.basis:
  server_issued`, `governance.run_opened_by: server`, and every stage counts its checks as `server_pinned`. Either way
  the record is the writer's own: only Iltero Cloud can confirm a run it opened, by its `run_id`.
- The change digest is the digest of `[{"unit": name, "plan": {"digest": ...}}]`, sorted by unit name
  (`iltero_schemas.canonical.change_digest`), over the change's one unit. A record's `change.unit` is its own unit with
  the plan it names. A unit is planned, approved and applied on its own.
- A record's `subject.unit` is its `unit`. When `units_file` is set, the record's `unit` is one of its `units`.
- Across records: the records of one run share `run_id.value`, and every one of them names the same `units_file`, or
  every one names `null`. The run has a record for each declared unit when the records' units equal `units_file.units`.
  The units file is the writer's copy: records cannot show a run with no record at all, or a units file the writer
  left out or shortened. Only the file at the record's commit can, by its digest.
- A stage's `coverage.assertions_expected.required_assertion_digest` is the digest of the assertions it owed, whether
  or not each was evaluated: as the project's files gave them (`basis: locally_derived`), or as Iltero Cloud set them
  for the run (`basis: server_pinned`). The model does not recompute a stage's digest.
- These rules establish consistency only. An unsigned record cannot prove that Iltero Cloud opened its run. Only
  Iltero Cloud can confirm a run, by its `run_id`.
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
| `properties` | object | Nine properties, each with a `state` and a `basis` (a short name, or `null`). |

| Property | It is `verified` when |
| --- | --- |
| `integrity` | The record's structure and signature are valid, and the evidence it cites is unchanged. |
| `source_identity` | The repository, commit and pipeline came from an authenticated source. |
| `approval_identity` | Every approval came from an authenticated identity. |
| `bundle_provenance` | The checks ran from a bundle signed by an authorised key that was not revoked. |
| `stage_completeness` | Every required stage is present, and every check owed has a result or is listed as not evaluated. |
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
| `resolvers` | list | One resolver per cloud provider, sorted by provider, at most 16. Each names its `provider`, `version` and the resource types `verified` for it. |
| `bindings` | list | Each managed resource in the state after the apply that was bound: `iac` (`tool`, `unit`, `address`), `cloud` (per provider) and `authority: authoritative`. |
| `unresolved` | list | Each managed resource that was not bound: `address` and `reason`. |
| `removed`, `removed_unresolved` | list or null | Each object that left the state during the apply, by its identity before the apply, with its `fate` (`deleted` or `forgotten`). |
| `deposed_destroyed` | integer or null | How many deposed objects the apply destroyed. |
| `deposed_objects` | integer | How many deposed objects the state still holds. |

Key rules:

- Each resource appears once in each half, either bound or unresolved, never both. Both lists are sorted by address.
- No two entries of `bindings` name the same cloud identity: the same `provider`, `primary.scheme` and
  `primary.value`, compared exactly as written. The same holds within `removed`. The two lists are not compared with
  each other: for example, a resource destroyed and created again under the same name in one apply appears in both.
  The removed entry's `fate` says whether the old object was deleted or only forgotten.
- A binding is accepted only for a resource type its provider's resolver lists as `verified`.
- Every entry of `bindings` and `removed` names the document's `unit` in `iac.unit`, and the tool in
  `sources.state.tool` in `iac.tool`.
- An unresolved `reason` is the first that holds, in this order: `no_resolver`, `provider_untrusted`,
  `resolver_unverified`, `identifier_sensitive`, `identifier_invalid`, `identifier_missing`,
  `identifier_ambiguous`.
- For `aws`, `cloud` holds the `resource_type` (`s3_bucket`, `rds_instance`, `security_group`, `iam_role` or
  `kms_key`) and the `primary` identifier (`scheme: aws_arn`, `value`). Each ARN must match its type's published
  naming rule, holds no wildcard and is at most 2048 characters. An S3 bucket name and an RDS instance identifier are
  lowercase, as AWS stores them.
- `removed`, `removed_unresolved` and `deposed_destroyed` are `null` exactly when `sources.plan` is `null`.
- The document carries identifiers only. The state file it was read from never leaves the machine that read it.

## Attestation

An attestation is a person's written claim about a fact no technical assertion can establish, such as a policy
existing or a review taking place. It is evidence a person reads, never a verdict: no assertion status is derived
from it.

- **apiVersion:** `iltero.io/v1`, with `kind: Attestation`
- **Model:** `iltero_schemas.models.attestation.Attestation`

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion`, `kind` | string | `iltero.io/v1` and `Attestation`. |
| `uuid` | UUID | The claim's id. |
| `statement` | string | The claim, verbatim, at most 4096 characters. |
| `scope` | object | The `system_id`, the `environment`, and the `assertion_id` it stands in for or the `control_ref` it addresses. |
| `attester` | object | `identity`, `idp`, `auth_method`, `role`, `role_source_ref`, and `identity_source` (`asserted` or `ci_oidc`). |
| `assessment_method` | string | `EXAMINE` or `INTERVIEW`. |
| `supporting_evidence` | list | Up to 256 files, each by `ref_id` and `digest`. |
| `attested_at` | object | When the claim was made: `value`, `source` (`server`, `timestamp_authority` or `runner_clock`) and `trust`. |
| `valid_until` | timestamp | When the claim stops counting. Required. |
| `next_review_at` | timestamp or null | When the claim is due for review. |
| `supersedes` | UUID or null | The claim this one replaces. |
| `signature` | null | Always `null` in this version. |
| `written_by` | string or null | The version of the tool that wrote it. |

Key rules:

- `valid_until` is later than `attested_at.value`, and `next_review_at` is no later than `valid_until`.
- `scope` names an `assertion_id`, a `control_ref`, or both.
- `identity_source: asserted` means the tool recorded a name it was given and verified nothing.
- A record lists an attestation in `evidence_refs` with `media_type: application/vnd.iltero.attestation+json`.

## EvaluatorBindingSet

An evaluator binding set is a catalogue of licences. Each entry says that one check of one scanner, at a version
inside a stated range, establishes one assertion at one stage. A bound check is not run again. The scanner's result
is credited to the assertion the entry names.

- **apiVersion:** `iltero.io/v1`, with `kind: EvaluatorBindingSet`
- **Model:** `iltero_schemas.models.binding.EvaluatorBindingSet`

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion`, `kind` | string | `iltero.io/v1` and `EvaluatorBindingSet`. |
| `metadata` | object | The catalogue's `id` and `version`. |
| `bindings` | list | 1 to 10,000 entries, each described below. |

Each entry:

| Field | Type | Meaning |
| --- | --- | --- |
| `id`, `version` | string | The entry's own id and version. |
| `tool` | string | `checkov`, `trivy` or `prowler`. |
| `tool_version_constraint` | string | A PEP 440 version specifier, such as `>=3,<4`. |
| `check_id` | string | The scanner's own check id, such as `CKV_AWS_16`. |
| `framework` | string or null | What the scanner must have been reading, in its own words, such as `terraform_plan`. Null for a scanner that reads one kind of input. |
| `assertion` | object | The `id` and `version` of the assertion the check establishes. |
| `stage` | stage | The stage the credit applies to. |
| `status_map` | object | 1 to 32 of the scanner's status words, each mapped to `pass` or `fail`. |

Key rules:

- Ids are unique. A scanner's check is bound once per stage. A scanner establishes an assertion with one check per
  stage.
- Only `pass` and `fail` are credited. A status word the map does not list leaves the check uncredited.
- A pre-release scanner version, or a version string that is not a version, satisfies no constraint.
- An event credited through an entry names the entry's id, its version and the digest of the entry's canonical
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

A bundle descriptor is how Iltero Cloud serves a signed assertion bundle. It carries the signed Open Policy Agent
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
| `min_cli_version` | string | The oldest CLI version able to evaluate the bundle. |
| `assertion_set_digest` | digest | The digest of every assertion in the bundle, by id, version and document digest. |
| `assertions` | list | 1 to 1,024 assertions, sorted by id: `id`, `version`, `digest`, `source_digest`, `compiled_digest` and the YAML `source`. |
| `tarball` | string | The signed tarball, standard base64 with padding, at most 16 MiB decoded. |

Key rules:

- The same content signed under two keys has one `revision` and two `digest` values.
- `assertion_set_digest` names everything in the bundle.
- The signing key must be in the trusted keys and must not be revoked.

## Trusted bundle keys

The trusted bundle keys file lists the public keys that may sign an assertion bundle. It ships inside the package
as `iltero_schemas/trust/bundle-keys.json`, so a tool that pins one package version also pins the keys it trusts.

- **apiVersion:** `iltero.io/bundle-keys/v1`
- **Reader:** `iltero_schemas.trust.parse_bundle_keys`, with the shipped set in `iltero_schemas.trust.BUNDLE_KEYS`
  and the digest of the file's bytes in `iltero_schemas.trust.TRUST_FILE_DIGEST`

| Field | Type | Meaning |
| --- | --- | --- |
| `apiVersion` | string | `iltero.io/bundle-keys/v1`. |
| `keys` | list | Each key's `keyid`, `algorithm` (`ES256`), `public_key` (an uncompressed P-256 SubjectPublicKeyInfo, base64), `spki_sha256`, `status`, `valid_from`, `retired_at`, `revoked_at` and `revocation_reason`. |

Key rules:

- `active` keys sign and verify. `retired` keys only verify. `revoked` keys never verify again, whenever the
  signature was made.
- Keys are never removed. A status only moves forward: `active` to `retired` or `revoked`, `retired` to `revoked`.
- A key id starting with `dev-` is a development key and is refused.
- Any change to the keys requires a new package version.
