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
- Ten starter assertions, among them the one that holds the plan applied to
  the plan that was evaluated, and `ILT.IAC.NO_DRIFT_AFTER_APPLY`, which holds
  that no deployed resource drifted after the apply. These two are built in
  (`PLAN_BINDING` and `NO_DRIFT_AFTER_APPLY` in `iltero_schemas.assertions`):
  a runner evaluates the first at every post-deploy stage and the second at
  every post-verify stage, whatever a project's own assertions are.
  `ILT.CHANGE.PRODUCTION_APPROVED` is about any change (`change_type: null`);
  the others are about `iac_change`.
- Every `TechnicalAssertion` says which change type it is about
  (`spec.change_type`: `iac_change`, or `null` for an assertion about any
  change); an assertion that leaves it out is refused. Each change type
  allows its own stage and target pairs (`COMBINATIONS`); an assertion about
  any change, and a hand-written policy, may use only the pairs every change
  type allows (`SHARED_COMBINATIONS`). At the post-verify stage an
  assertion targets only the deployment. The change type is part of the
  abstract syntax tree and of the source digest.
- An optional `metadata.remediation` on a `TechnicalAssertion`: one line, at
  most 300 characters, saying what a person does to make a failing subject
  meet the assertion. The compiler ignores it. The assertion's digest covers
  it; the source digest does not. Each starter assertion has one.
- An evaluation of a starter assertion that a project added to its local run
  says so (`assertion_source: contract_starter`).
- A typed text field (a name, an identifier, an address, a title) and an
  assertion's literal refuse control, zero-width and bidirectional formatting
  characters, and the characters that show as nothing: a soft hyphen, the
  combining grapheme joiner, the Arabic letter mark, the Mongolian vowel
  separator and the Hangul fillers.
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
  marker with the reason `not_reported_by_tool` when the tool's plan does
  not say. `change.digest` is required and is the change digest of its unit's
  plan in the input's environment. A resource's `type` and `name`, its provider source and a related
  resource's `type` are never `null`. An earlier evaluation names the content it
  checked (`checked_content`) exactly when its stage reads a plan.
- A plan resource in the evaluation input is a neutral core (`id`,
  `provider`, `type`, `kind`, `name`, `module`, `action`, `before`, `after`,
  `related`), and what only its IaC tool says about it is under `tool_data`,
  keyed by `tool`: Terraform's `provider_source`, `action_reason`,
  `previous_address`, `importing`, `replace_paths`, and a related resource's
  `match`. Its `tool_data`, and each related resource's, must be the
  variant of the plan's tool. It names the kind its tool's table gives its
  type, like a change entry, and `provider` is required and is the
  provider's short name.
- The plan, the apply log and the state name their IaC tool (`tool`) and its
  version (`tool_version`). An apply's timing source is `apply_log`.
- A subject is keyed, in the evaluation input, in events and in an earlier
  evaluation, by `key`: the digest of its kind and its one local identity,
  computed by `models.subjects.subject_key` and checked in every document,
  with a conformance vector. The local identity is a managed resource's
  address scoped by its unit (scheme `terraform_address`), the cloud identity
  of a resource only the cloud knows (after deployment), or the unit of a
  change, a deployment or an assurance subject. The key is over the
  identity's text as written, with no Unicode normalization. No stack or
  other Iltero Platform scope is part of it. An event's subject has no key
  and no identity exactly when no subject was in scope.
- `ILT.DEPLOYMENT.PLAN_BINDING` compares the plan digests, the saved plan
  file's digests and the two `artifact_digest_source` values, so its
  observations show when neither side had the saved plan file. It passes
  then, and fails when only one side has it. Evaluation vectors cover both,
  and how a `null` value evaluates.
- The Change Assurance Record (`CAR` v1) and its events (`AssuranceEvent`
  v1): the record of one attempted infrastructure change, whatever its
  outcome. It holds each stage's coverage and verdict, the rules that tie the
  stages together, what a deployment did, the resources' cloud identities, and
  which stages are in scope. It says what was checked and how; on its own, it
  does not show that anything is certified or complies with a regulation or
  standard, and its `compliance_determination` is always `null`.
- A record's `trust_level` is one of three levels (`self_attested`,
  `source_authenticated`, `governed`), and a record may claim only
  `self_attested`, since it carries no signature. Its issuer is always
  `local`, and its identity is never verified, whoever opened the run.
- Each part of a record has a fixed shape. A stage's `reference_time` and the
  record's `subject.source` are those of the evaluation input. A stage's
  `redaction` is a redaction report: the policy that ran, what was redacted,
  and the paths redacted (each with a reason token), left unknown, or allowed
  (each with the project's reason). A stage's `scanners` names the binding set
  in force and counts each scanner result once: accepted as `pass` or `fail`,
  matched by a binding whose version constraint the scanner does not satisfy,
  or one that became no evaluation. An excluded resource (`subjects_in_scope.excluded`)
  names its index in the plan's resource list (`plan_index`), its address as
  written or `null`, and one of four reasons. A coverage gap is one of three
  shapes, chosen by its `kind`: a plan flag, a resource's `plan_index`, or a
  count of at least 1 (`COUNT_GAP_KINDS`); the record's combined coverage
  names each gap's stage.
- A record redacts under one policy. An evidence file's `redaction_policy`
  names it as a stage's redaction report does (`id`, `version`, `digest`),
  or is `null` for a file no redaction touched, and every stage and every
  redacted evidence file name the same one, whatever the validation context.
  Invalid-record vectors cover it.
- A record's `change.plan` `complete`, `applyable` and `tool_version`, and a
  plan-flag gap's `value`, hold the `not_reported_by_tool` marker when the
  tool's plan does not say; `null` is refused. A record's `change.digest` is
  required. The plan stage lists one plan-flag gap for each plan flag that is
  not `true`, with the plan's value, in kind order; a plan-flag gap in any
  other stage is refused. When the plan was read from a saved plan file, the
  record's plan names the file's digest and its file name without its
  directories (`artifact_digest`, `artifact_file_name`); the record keeps
  them, not the file. A name that holds `/`, `\`, `:` or a character that
  looks like a slash or backslash, or consists only of dots and spaces, in
  its NFKC (Unicode compatibility) form, is refused. A name is at most 255
  UTF-8 bytes as written, with no control character. A binding set's
  `file_name` follows the same rule. Record vectors cover each rule.
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
  problems come first, so a change digest that does not recompute is refused
  first. A reader that sets `SKIP_INTEGRITY_CHECKS` to `True` (any other
  value is ignored) reads the record and gets every problem from
  `integrity_problems`, to report as integrity failures. The checks show that
  a record agrees with itself, not that it is unchanged since it was written.
  Record vectors (`records_integrity_failed/`) cover it.
- An event's `provenance.checked_content` names the content its evaluation
  checked: for an IaC change, the plan, by its `digest`, the `digest_version`
  of its tool's rule and the IaC `tool`. A record holds every event's to the
  content its own change checked. An
  event's executor provider is `local`, `ci` or a CI system's name, such as
  `github_actions`. An event's and a record stage's `bundle` give its
  `kind`, its `tarball_digest` and, for a bundle the server served, the
  descriptor's `content_digest` and `key_id`, which are `null` for a bundle
  the tool built; a stage's also gives its `capabilities_digest`. An
  evaluation of an assertion from the server's bundle that ran over a
  bundle names a bundle of kind `server`.
- A deployment's apply and the identity document are a neutral core plus
  `tool_data`, keyed by `tool`, with that tool's validation in its own module.
  For Terraform, the apply's `tool_data` holds the `summary` counts, the
  `log_lines` it could not read, and the delete of each deposed object (an
  old copy a replacement set aside) settled by the state; the identity
  document's holds its deposed counts. The apply's `tool_data` must be the
  variant of its log's tool, and the identity document's that of its state's
  tool (`models.tools.variants.check_tool_data`). The apply's `changes` name
  each address's current object once.
- The identity document (`IdentityBindings` v1). A binding's `iac` side names
  its `tool`, and the document lists its `resolvers`, one per cloud provider.
  The cloud side and resolver of an identity binding each have one shape per
  cloud provider, chosen by a `provider` field; AWS is the first. Each AWS resource name (ARN) has the shape
  AWS could issue: an S3 bucket name that looks like an IP address, holds two
  dots in a row or uses a reserved prefix or suffix is refused, and so is an
  RDS identifier that is not lowercase, ends with a hyphen or holds two
  hyphens in a row. No two of its bindings, and no two of its removed
  entries, name the same cloud identity.
- Hand-written policy sources and scanner binding sets. An evaluator
  binding's `input_kind` says what the scanner must have been reading, and a
  record's scanner report lists its `input_kinds`. Binding sets, events and
  records name a scanner from one list: `checkov`, `trivy` and `prowler`.
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
  documents that must be refused, and altered ones that must still be
  accepted. The record vectors are in `vectors/records/`. The rules about
  bindings have no vector, because a binding holds a cloud identifier this
  repository does not publish.
- A record says who opened its run (`run.origin` and
  `governance.run_opened_by`: `server` or `local`), the same way everywhere.
  A record of a run the tool opened claims nothing only Iltero Platform can
  give: no Iltero Platform bundle or evaluation from one, no facts from
  Iltero Platform, and no stage reference time from it. Every event names the
  record's own run and unit. Iltero Platform can confirm, by `run.id`, that
  it opened a run; that does not confirm what the record says about it.
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
  mode its gate ran in (`enforcement_mode`: `enforcing` or `advisory`, always
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
  The change digest (`change_digest`) is taken over the change type, the
  unit, the environment key and the checked content (its kind, digest,
  digest rule version and tool), so an
  approval of a change counts only for that content, in that unit and
  environment. A record's environment key is its `subject.environment`, null
  for a change made outside any environment, and a record of a run Iltero
  Platform opened always names one; an evaluation input's is
  `organization_scope.environment.name`. A record names
  its project's units file as the writer read it (`units_file`: path, digest
  of its bytes, and its units in deploy order, each with the units it
  `depends_on`, which come before it), and its unit is one of them, so the
  records of one run can be checked against it.
- Change types and activities (`iltero_schemas.change_types`). A change type
  is the kind of thing a change changes; an activity is one kind of work a
  single record describes. The one change type, `iac_change`, a change made
  with an IaC tool, has one activity of the same name. A record's `change` is
  the body of its activity (`change.activity`), holding the change digest,
  the `plan`, and once they are known the `deployment`, the `identity` and
  the `drift_check`. The activity declares the stages a record passes
  through, which of them a project, an environment's policy or the tool may
  leave out, and the documents each stage owes.
- The evaluation input's environment says whether Iltero Platform's policy
  treats it as production (`organization_scope.environment.production`), and
  the starter assertions guard on that, not on the environment's name. A run
  Iltero Platform did not open holds the unknown marker there, so an
  assertion that guards on production is `unknown`, never skipped.
- Resource selectors on an assertion's target. A resource target names one
  IaC tool's types (`{tool, provider, resource_types}`), whose values are
  that tool's own attributes. A change or deployment target may name a
  provider's tool-independent kinds (`{provider, kinds}`), and the compiler
  writes its scope guard from them: a condition that decides whether the
  assertion applies. Each tool's table gives its types their kinds
  (`iltero_schemas.kinds`, Terraform's for AWS IAM, KMS, network, S3
  and RDS types). Each resource in the evaluation input names its provider's
  short name and the kind the table gives its type, or the unknown marker
  when the table lacks it, so an unnamed type makes the evaluation unknown rather
  than out of scope. `ILT.CHANGE.SENSITIVE_CHANGE_APPROVED` names IAM, KMS
  and network kinds, roles, policy attachments, key policies and grants
  included.
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
  The shipped set is empty.
  CI refuses a change to the set that does not raise the version, and a
  release that changes it raises the major or minor version.
- Signed assertion bundles: building one from assertion sources (the files
  and the bytes a key signs are reproducible), and `check_descriptor`, which
  rebuilds a served bundle from its sources and compares it byte for byte
  before anything in it is evaluated. A bundle's content digest covers its
  assertions, the compiler version, the evaluator's allowlist
  (`capabilities_digest`) and the oldest CLI version allowed;
  `check_descriptor` refuses a bundle built by another compiler version or
  under another allowlist, naming both values. It returns an
  `UnverifiedBundle`: the pinned OPA, or the signer's library, verifies the
  signature. Signatures are accepted only in their low-S form
  (`normalized_signature`), which `descriptor` writes whatever form the
  signer returned, so one signing gives one digest. A run and a bundle each
  hold one version of an assertion.
- The verification report (`VerificationReport` v1): what a verifier found
  about one record, property by property, with no overall verdict. It never
  calls a record's integrity verified, because no record carries a signature
  in this version. When the report cannot establish a record's integrity, it trusts
  nothing else the record says.
- The drift check (`change.drift_check`): what two readings of a unit's
  deployed resources, taken after the apply by a refresh-only plan (a plan that reads
  the resources back and changes nothing), found. It names the run, the
  change, the IaC tool, how many resources were read, when each reading was
  taken and how far apart they had to be, and each resource that changed or
  was deleted in the second reading, the latest, by address only, each
  resource that differed in the first reading but not in the latest
  (`first_reading_only_differences`; the check does not say why), and the
  digest of each reading. Neither reading writes the state, so both compare
  the resources with the state the apply wrote. A record carries it exactly
  when its post-verify stage has reported, and the post-verify evaluation
  input requires it. A drift check of another change is an integrity
  failure. A first reading written without a fraction of a second is compared
  with the whole second the apply ended in and the whole second the
  post-deploy stage was observed in; one written with a fraction, even
  `.000`, is compared exactly. An IaC tool may date a reading in whole
  seconds, from when it started; Terraform does. Record, context and
  evaluation vectors cover it.
- A record of a run Iltero Platform opened can leave out its post-verify
  stage because the environment's policy does not require it
  (`out_of_scope[].reason: environment_policy`). The record does not name
  the policy. A project's configuration can leave out the post-verify stage
  as well as the pre-deploy approval gate. A record calls a stage
  unsupported only when its plan's IaC tool cannot run it; Terraform, which
  has a drift reader, runs every stage.
  The sample records expect all four stages.
- An identity document says where its state was read from
  (`sources.read_from`): the state file the apply left, or a refresh-only
  plan, which names no applied plan. A record's identities are always read
  from the state file.
- A verification report's `runtime_verification` is one of six results,
  each a state and its reason, or `not_determined` when the record's
  integrity is not established.
