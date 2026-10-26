# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

The first release of `iltero-schemas`: the contract every Iltero tool shares.
It defines the documents they read and write, and the rules each document must
keep, so any two tools agree on what a record means.

### Added

- The assertion language: `TechnicalAssertion` v1 documents, a strict parser,
  and one compiler to Rego for Open Policy Agent, with the evaluator's allowed
  functions and its pinned release.
- Nine starter assertions, among them the one that holds the plan applied to
  the plan that was evaluated.
- An optional `metadata.remediation` on a `TechnicalAssertion`: one line, at
  most 300 characters, saying what a person does to make a failing subject
  meet the assertion. The compiler ignores it. The assertion's digest covers
  it; the source digest does not. Each starter assertion has one.
- An evaluation of a starter assertion that a project added to its local run
  says so (`assertion_source: contract_starter`).
- The evaluation input (`AssuranceContext` v1), with a fixed set of parts for
  each stage.
- A JSON document a tool writes has one form, so one set of facts has one
  digest: every optional field is written, as `null` when it has no value,
  as its model dumps it. A context part outside its stage's profile is `null`. A field
  left out still reads. Every document vector is in this form.
- A reference time claims no more than its source: a runner's clock is
  always `asserted`, and a `time_window` is present exactly when a timestamp
  authority gave the time, with the time inside it. A stage's reference time
  read from its runner's clock is the same instant the stage observed
  (`observed_at`).
  Invalid-record vectors cover them.
- In an `AssuranceContext`, `null` means a fact has no value, never that it is
  unknown. A plan's `complete`, `applyable` and `tool_version` hold the unknown
  marker with the new reason `not_reported_by_tool` when the tool's plan does
  not say. `change.digest` is required and is the change digest of its unit's
  plan. A resource's `type` and `name`, its provider source and a related
  resource's `type` are never `null`. An earlier evaluation names its plan's
  digest exactly when its stage reads a plan.
- `ILT.DEPLOYMENT.PLAN_BINDING` also compares the two `artifact_digest_source` values,
  so its observations show when neither side had the saved plan file. It
  passes then, and fails when only one side has it. Evaluation vectors cover
  both, and how a `null` value evaluates.
- The Change Assurance Record (`CAR` v1) and its events (`AssuranceEvent`
  v1): each stage's coverage and verdict, the rules that tie the stages
  together, what a deployment did, the resources' cloud identities, and which
  stages are in scope.
- A record's plan `complete`, `applyable` and `tool_version`, and a
  plan-flag gap's `value`, hold the `not_reported_by_tool` marker when the
  tool's plan does not say; `null` is refused. A record's `change.digest` is
  required. The plan stage lists one plan-flag gap for each plan flag that is
  not `true`, with the plan's value, in kind order; a plan-flag gap in any
  other stage is refused.
  Record vectors cover each rule.
- A plan stage with a `plan_incomplete` gap, whether the plan said it is
  incomplete or did not say it is complete, is incomplete with reason
  `plan_not_complete`. Its verdict still follows its evaluations. An evaluator
  error's reason wins over it, and it wins over
  `upstream_state_unavailable`. A plan that cannot be applied leaves the
  status as it is. The status's `reason` is the leading cause; every cause
  stays in the coverage. Record vectors cover it and pin the order.
- The integrity checks: a record's values that a reader can recompute,
  including its `change.digest`, the pre-deploy stage's source digest and
  each approval of a change, must be what they recompute to. Change digest
  problems come first, so a forged digest is refused as such. A reader that
  sets `SKIP_INTEGRITY_CHECKS` to `True` (any other value is ignored) reads
  the record and gets every problem from `integrity_problems`, to report as
  integrity failures. Record vectors (`records_integrity_failed/`) cover it.
- The identity document (`IdentityBindings` v1), and the shape of each AWS
  resource name (ARN) it may hold. No two of its bindings, and no two of its
  removed entries, name the same cloud identity.
- Hand-written policy sources and scanner binding sets. Binding
  sets, events and records name a scanner from one list.
- A record's scanner report now refuses any scanner other than `checkov`,
  `trivy` and `prowler`.
- Named constants for values consumers write as plain strings. Each constant
  lives with the part of the contract it belongs to. `SCHEME_UNIT` is in
  `iltero_schemas.models.vocabulary`, `SCHEME_AWS_ARN` in
  `iltero_schemas.models.providers.aws`, and the CI systems an executor may
  name in `iltero_schemas.models.event.CI_SYSTEMS`.
- Canonical JSON (RFC 8785) and `sha256` digests, including a plan's digest
  by its IaC tool's rule (`plan_digest(tool, plan)`); `PLAN_DIGEST_VERSIONS`
  gives each rule's version. A plan, or a deployment's applied plan, whose
  `digest_version` is not its tool's rule version is refused
  (`check_plan_digest_version`), and so is an identity document whose
  applied plan's is not the rule version of the tool that wrote the state,
  with a vector. A tool with no rule has no plan digest. Two timestamps
  compare to the nanosecond.
- Conformance vectors that another implementation can test itself against,
  including records of runs the tool opened (one of a project that declares
  its units, one whose plan stage read placeholders), a record of a run
  Iltero Platform opened, an identity document with no bindings, the identity
  documents that must be refused, and changed ones that must still be
  accepted. The rules about bindings have no vector, because a binding holds
  a cloud identifier this repository does not publish.
- A record says who opened its run (`run.origin` and
  `governance.run_opened_by`), the same way everywhere. A record of a run
  the tool opened claims nothing only Iltero Platform can give: no Iltero
  Platform bundle or evaluation from one, no facts from Iltero Platform, and no
  stage reference time from it. Every event names the record's own run and
  unit. Every record is self-attested: only Iltero Platform can confirm a run
  it opened, by its `run.id`.
- The contract digest a record names is defined in the package
  (`iltero_schemas.distribution`): the same value from the published wheel
  and from its installation, which is checked file by file; each release
  prints it.
- Releases are published from a tag by a workflow that checks the version and
  the trusted-key history, builds reproducibly from hash-pinned tools, attests
  the build, and publishes through PyPI Trusted Publishing after a
  maintainer's approval.
- The signed bundle's descriptor, at most 64 MiB of canonical JSON
  (`MAX_DESCRIPTOR_BYTES`).
- A stage counts its subjects by their kind: resources by enumerating the
  plan, a change or a deployment as its one unit (`counted_from: change_unit`, by
  the record's change digest, or `deployment_unit`). Every stage records the
  mode its gate ran in (`enforcement`: `enforcing` or `advisory`, always
  enforcing after the deployment).
- A stage that replaced an input it could not read, such as another unit's
  state, with a placeholder lists it (`coverage.substituted_inputs`: at most
  256, by the tool's address of the input, sorted). Its verdict still
  follows its evaluations, and it is incomplete with reason
  `upstream_state_unavailable`, so a pass on placeholders reads as
  incomplete; an evaluator error's reason wins, in the stage and in the
  record. A record of a run Iltero Platform opened has none.
- The fixed order of statuses, worst first.
- The digest of an assertion set and the digest of a change, with vectors.
  A record's change covers its own unit only: that unit's plan, bound by
  the change digest, which readers check. A record names its project's
  units file as the writer read it (`units_file`: path, digest of its
  bytes, units in deploy order), and its unit is one of them, so the
  records of one run can be checked against it.
- The evaluation input's environment says whether Iltero Platform's policy
  treats it as production (`organization_scope.environment.production`), and
  the starter assertions guard on that, not on the environment's name. A run
  Iltero Platform did not open holds the unknown marker there, so an
  assertion that guards on production is `unknown`, never skipped.
- Resource selectors on an assertion's target. A resource target names one
  IaC tool's types (`{tool, provider, resource_types}`), whose values are
  that tool's own attributes. A change or deployment target may name a
  provider's tool-independent kinds (`{provider, kinds}`), and the compiler
  writes its scope condition from them. Each tool's table gives its types their
  kinds (`iltero_schemas.kinds`, Terraform's for AWS IAM, KMS, network, S3
  and RDS types). Each resource in the evaluation input names its provider's
  short name and the kind the table gives its type, or the unknown marker
  when the table lacks it, so an unnamed type makes the evaluation unknown rather
  than out of scope. `ILT.CHANGE.SENSITIVE_CHANGE_APPROVED` names IAM, KMS
  and network kinds instead of Terraform types, roles, policy attachments,
  key policies and grants included.
- The facts only Iltero Platform holds, as items an assertion reads: approvals,
  exceptions and earlier evaluations. An approval names the change it
  approves by its digest, or the run by Iltero's run id, and says how it was
  obtained and whether it was a self-approval the policy permitted. The
  pre-deploy input names its run (`run.id`), and the approval assertions
  accept either kind, each in its own branch. A stage whose input carries
  approvals lists the ones its evaluations read, whatever their source, each
  once and of the record's own change or run.
- The unknown marker: where a fact only Iltero Platform holds (approvals,
  exceptions, evaluations) is missing, the evaluation input holds a marker,
  so a condition that reads it is `unknown`, never true or false. An
  evaluation at a stage that reads Iltero Platform facts records where they came
  from (`facts_source`).
- The trusted bundle keys: the public keys an assertion bundle may be signed
  with, shipped in the package with their status (active, retired or
  revoked), and a reader that refuses development keys and every broken rule.
  The set is empty until the first signing key is published.
  CI refuses a change to the set that does not raise the version, and a
  release that changes it raises the major or minor version.
- Signed assertion bundles: building one from assertion sources (the files
  and the bytes a key signs are reproducible), and `check_descriptor`, which
  rebuilds a served bundle from its sources and compares it byte for byte
  before anything in it is evaluated. It returns an `UnverifiedBundle`: the
  pinned OPA, or the signer's library, verifies the signature. Signatures are
  accepted only in their low-S form (`normalized_signature`), which `descriptor` writes whatever form
  the signer returned, so one signing gives one digest. A run
  and a bundle each hold one version of an assertion.
- The verification report (`VerificationReport` v1): what a verifier found
  about one record, property by property, with no overall verdict. It never
  calls a record's integrity verified, because no record carries a signature
  in this version. When the report cannot establish a record's integrity, it trusts
  nothing else the record says.

### Changed

These changes break documents written before them.

- Parts of a record that accepted any content now have a fixed shape. A
  stage's `reference_time` and the record's `subject.source` are those of
  the evaluation input. A stage's `redaction` is a redaction report:
  the policy that ran, what was redacted, and the paths redacted (each with a
  reason token), left unknown, or allowed (each with the project's reason).
  An excluded resource (`subjects_in_scope.excluded`) names its index in
  the plan's resource list (`plan_index`), its address as written or `null`, and one of four reasons. A
  coverage gap is one of three shapes, chosen by its `kind`: a plan flag, a
  resource's `plan_index`, or a count of at least 1 (`COUNT_GAP_KINDS`); the
  record's combined coverage names each gap's stage.
- A subject is keyed, in the evaluation input, in events and in an earlier
  evaluation, by `key`: the digest of its kind and its one local identity,
  computed by `models.subjects.subject_key` and checked in every document,
  with a conformance vector. The local identity is a managed resource's
  address scoped by its unit, the cloud identity of a resource only the
  cloud knows (after deployment), or the unit of a change, a deployment or
  an assurance subject. The key is over the identity's text as written, with
  no Unicode normalization. `key` replaces `id`, which was the resource's
  address. No stack or other Iltero Platform scope is part of it. An event's
  subject has no key and no identity exactly when no subject was in scope.
- A typed text field (a name, an identifier, an address, a title) and an
  assertion's literal also refuse the characters that show as nothing: a
  soft hyphen, the combining grapheme joiner, the Arabic letter mark, the
  Mongolian vowel separator and the Hangul fillers.
- A deployment's apply and the identity document are a neutral core plus
  `tool_data`, keyed by `tool`, with that tool's validation in its own module.
  For Terraform, the apply's `tool_data` holds the `summary` counts, the
  `log_lines` it could not read, and the delete of each deposed object (an
  old copy a replacement set aside) settled by the state; the identity
  document's holds its deposed counts. The apply's `tool_data` must be the
  variant of its log's tool, and the identity document's that of its state's
  tool (`models.tools.variants.check_tool_data`). The apply's `changes` name
  each address's current object once.
- A plan resource in the evaluation input is a neutral core (`id`,
  `provider`, `type`, `kind`, `name`, `module`, `action`, `before`, `after`,
  `related`), and what only its IaC tool says about it is under `tool_data`,
  keyed by `tool`: Terraform's `provider_source`, `action_reason`,
  `previous_address`, `importing`, `replace_paths`, and a related resource's
  `match`. Its `tool_data`, and each related resource's, must be the
  variant of the plan's tool. It names the kind its tool's table gives its
  type, like a change entry, and `provider` is required and is the
  provider's short name.
- An identity binding accepts an S3 bucket or RDS instance only by an ARN AWS
  could issue. A bucket name that looks like an IP address, holds two dots in a
  row or uses a reserved prefix or suffix is refused. So is an RDS identifier
  that is not lowercase, ends with a hyphen or holds two hyphens in a row.
- CAR now stands for Change Assurance Record: the record of one attempted
  infrastructure change, whatever its outcome. It records assurance facts and
  does not, by itself, establish certification or compliance with a
  regulatory framework. In plain words, a record says what was checked and
  how. On its own, it does not show that anything is certified or complies
  with a regulation or standard.
- A record's `trust_level` replaces `assurance_level`. It lists three levels,
  and a record may claim only `self_attested`, since it carries no signature.
- A record has a new `compliance_determination` field, which is always `null`.
- A record's issuer is always `local`, and its identity is never verified,
  whoever opened the run.
- `governance.run_opened_by` (`server` or `local`) replaces
  the earlier field that said whether the service managed the run.
- A CI identity, and the cloud side and resolver of an identity binding,
  each have one shape per provider, chosen by a `provider`
  field. GitHub Actions and AWS are the first providers.
- An identity binding's `terraform` side is now `iac`, which names its
  `tool`. A document lists its `resolvers`, one per cloud provider.
- The plan, the apply log and the state name their IaC tool (`tool`) and its
  version (`tool_version`), in place of `format` and `terraform_version`. An
  apply's timing source is `apply_log`.
- A resource assertion's target names its IaC tool (`tool: terraform`), so
  every assertion's source digest and compiled program change.
- An event's executor provider is `local`, `ci` or a CI system's name, such
  as `github_actions`. A resource's identity scheme is `terraform_address`.
- An evaluator binding's `framework` is now `input_kind`: what the scanner
  must have been reading. A record's scanner report lists `input_kinds`, in
  place of `frameworks`.
- An event's `provenance.plan_digest` names the plan's IaC tool (`value`,
  `version`, `tool`), and a record holds every event's to its own plan.

- Fields, values and names say what they hold:
  - Evaluation input: `context` is `organization_scope`; a reference time's
    `bracket` is `time_window`; a subject's `authority: authoritative` is
    `resolution: resolved`; `artifact_digest_basis` is
    `artifact_digest_source`.
  - Events: the policy's `reason` is `policy_reason`; the OPA evaluator's
    `environment` is `limits`, with `timeout_seconds`, `memory_limit`,
    `max_output_bytes` and `evaluations_per_process`; a scanner evaluator's
    `basis` is `reason`; the run's `basis` is `origin`; the executor's
    `run_id` is `ci_run_id`; the status reason `binding_unverified` is
    `results_binding_unverified`.
  - Records: `run_id` (`value`, `basis`) is `run` (`id`, `origin`);
    `not_in_scope` is `out_of_scope`, with a `reason`; `retention_basis` is
    `retention_reason`; the integrity scheme `digest_linkage` is
    `file_digests`. A stage's `ran` is `execution`, and its
    `redaction_applied` is `redaction`, whose `subject` is `input`. An
    evidence file's `redaction_applied` (`policy_id`) is `redaction_policy`
    (`id`).
  - Coverage: `checks` is `evaluations`; the verdict's `basis` is
    `computed_from`; `subjects_in_scope.basis` is `counted_from`;
    `assertions_expected.basis` is `origin`; `position` is `plan_index`;
    `identity_hidden` is `identity_redacted`; the gap kind
    `credited_by_binding` is `accepted_by_binding`.
  - Scanners: a stage's `catalogue` is `binding_set` (`copy_path`,
    `binding_count`); its counts are `results_accepted`,
    `results_binding_unverified` and `results_without_binding`, and a
    report's are `results_read` and `results_without_binding`.
  - Deployments: the apply's `basis` is `outcomes_from` (`apply_log` or
    `apply_log_and_state`); a change's `basis` is `outcome_from`
    (`apply_log`, `state` or `none`); a re-plan's `basis: dependency_replan`
    is `reason: dependency_replanned`; Terraform's log lines `noise` and
    `damaged` are `other_output_lines` and `damaged_messages`.
  - Identity documents: `authority: authoritative` is `resolution:
    resolved`; `fate` is `removal`; the AWS `primary` identifier is
    `identifier`; a resolver's `verified` is `verified_resource_types`;
    Terraform's `deposed_destroyed` and `deposed_objects` are
    `deposed_deleted` and `deposed_remaining`.
  - Binding sets: an entry's `check_id` is `rule_id`. Trusted bundle keys:
    `keyid` is `key_id`.
  - Python names: `OPA_RELEASE_PIN` (was `PIN`), `RUNTIME_REGO`,
    `ALWAYS_REQUIRED_PARTS`, `BUNDLE_SIGNING_SCOPE`, `SIGNING_ALGORITHM`,
    `LITERAL_LIST_MAX_ITEMS`, `LITERAL_STRING_MAX_CHARS`,
    `normalized_signature` (was `low_s`), `parse_timestamp`,
    `ASSERTION_TYPE_FOR_TARGET`, `SCOPE_COUNTED_FROM` and
    `scope_counted_from`; the types `ServerFactsUnavailable`,
    `KindNotMapped`, `ApplyLogIncomplete`, `EventsFile`, `AssertionIndex`,
    `Execution`, `BindingSetUsed`, `AcceptedStatus`, `TimeWindow`,
    `ExecutionEvaluator`, `ExecutionBundle`, `MemoryLimit`, `PlanIndexGap`,
    `RedactedPath`, `MaybeRedacted`, `MaybeRedactedAddress`, `RecordRun`,
    `RedactionPolicyUsed`, `OutOfScopeReason`, `Resolution`, `Removal` and
    `OutcomeSource`; `RULE_ID_PATTERN` and `RULE_ID_MAX_LENGTH`.
  - Vector folders: `invalid/` is `assertions_invalid/`.
  The starter assertions that read the organization scope or the artifact
  digest source keep their versions and have new digests.

### Removed

- An event's `fs_hardening`.
- The evaluation limits' `python_platform`: `platform` names the system the
  evaluation ran on.
- The messages a pipeline exchanges with Iltero Platform during a run: opening
  a run, a stage's token, closing a run, uploads and their answers, the facts
  document, the artifact store, and their vectors. The record vectors are in
  `vectors/records/`.
- The `Attestation` document and its media type, and the `assessor_reviewed`
  and `authority_accepted` trust levels. A record states machine facts only.
