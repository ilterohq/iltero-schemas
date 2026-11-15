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
- One way for every document to name itself. Every contract document has
  `apiVersion: iltero.com/v1` (`iltero_schemas.models.base.API_VERSION`) and
  a top-level `kind` that names the document type. A reader accepts exactly
  its own pair: a document with another `apiVersion`, including a name used
  before this release such as `iltero.io/v1` or `iltero.io/car/v1`, with no
  `kind`, or with the `kind` of another document is refused. A `kind` nested
  inside a document, such as a target's or a subject's, is unchanged. The
  kinds are:

  | `kind` | Document |
  | --- | --- |
  | `TechnicalAssertion` | An assertion |
  | `AssuranceContext` | An evaluation input |
  | `AssuranceEvents` | The events file a stage keeps, which a record names by path and digest |
  | `ChangeAssuranceRecord` | A record (`CAR`) |
  | `VerificationReport` | A verification report |
  | `ResourceIdentities` | A resource identities document |
  | `EvaluatorBindingSet` | An evaluator binding set |
  | `ScannerObservations` | What a stage read from one scanner's report |
  | `LocalExceptions` | A project's own exceptions |
  | `PolicySource` | A directory of hand-written policies |
  | `AssertionBundleDescriptor` | How Iltero Platform serves a signed assertion bundle |
  | `AssertionBundle` | The bundle's own description in its `.manifest` file |
  | `BundleSigningKeys` | The trusted bundle keys file |

  Documents take one of two shapes. A document Iltero writes as evidence keeps
  its content at the top level, with facts about the document itself in a
  `metadata` object where it has any: a record's `uuid` and `issuer`, a
  verification report's `verifier` and `verified_at`, and a resource
  identities document's `generator`. A document a person writes has `apiVersion`, `kind`,
  `metadata` and `spec`: an evaluator binding set keeps its `id` and
  `version` in `metadata` and its bindings in `spec.bindings`, and local
  exceptions and a policy source name themselves by `metadata.name`, a
  name the project chooses (1 to 63 lowercase letters, digits and inner
  hyphens, `iltero_schemas.models.fields.PROJECT_DOCUMENT_NAME_PATTERN`), and
  keep their entries in
  `spec.exceptions` and `spec.policies`. A document's digest covers the whole
  document, `metadata` included. Every conformance vector, and every digest
  that cites one, uses these names and shapes.
- Assertion ids that say what kind of check an assertion is. An id is now
  segments in fixed places, joined by dots:
  `<NAMESPACE>.<CHANGE_TYPE>.<TARGET>.<SCOPE...>.<CHECK>`
  (`iltero_schemas.models.assertion_id`). The namespace is `ILT` for Iltero's
  own assertions and the project's own name for its own. The change type
  segment is `IAC` for `iac_change`, `IMAGE` for `image_release` and `COMMON`
  when `spec.change_type` is `null`. The target segment is the target kind in
  upper case: `RESOURCE` for a check of a resource's state, and `CHANGE`,
  `DEPLOYMENT`, `ARTIFACT` or `ASSURANCE` for a check of a process. The scope
  is the provider and service for a resource (`AWS.RDS`), and one area for a
  process; Iltero's own process assertions take an area from `ASSERTION_AREAS`
  (`APPROVAL`, `SOURCE`, `CONTENT`, `DRIFT`, `BUILD`, `CHECKS`,
  `PROVENANCE`, `HISTORY`), and a project names its own. An id is at most 96
  characters, and each segment at most 48. A TechnicalAssertion whose id does
  not match its own `spec` is refused, and so is a policy source entry whose
  id does not match its stage and target: a hand-written policy's change type
  is read from its id. An id that refers to an assertion, in an event, a
  record or a binding, keeps only the general shape (upper-case segments
  joined by dots), and a binding set's id is not an assertion id. Every id
  has the same limit of 96 characters: `ID_MAX_LENGTH` is
  `ASSERTION_ID_MAX_LENGTH`.

  How to read an id: the change type segment says what an assertion is
  about, not which change it was evaluated in, so a `COMMON` assertion
  appears in records of every change type and evidence is grouped by change
  with an event's `evaluation.activity`. An area compares only within one
  namespace, and a resource's service is the author's word. Once released,
  an id is never renamed: a renamed check is a new assertion.

  The starter assertions were renamed to this form.
  `ILT.COMMON.ASSURANCE.HISTORY.NO_UNEXPLAINED_REGRESSION` is now about every
  change type (`change_type: null`). Every conformance vector uses the new
  ids, and the vector assertions of a project's own are now
  `ACME.IAC.RESOURCE.AWS.RDS.*`.

  | Old id | New id |
  | --- | --- |
  | `ILT.ASSURANCE.NO_UNEXPLAINED_REGRESSION` | `ILT.COMMON.ASSURANCE.HISTORY.NO_UNEXPLAINED_REGRESSION` |
  | `ILT.AWS.RDS.BACKUP_RETENTION` | `ILT.IAC.RESOURCE.AWS.RDS.BACKUP_RETENTION` |
  | `ILT.AWS.RDS.NOT_PUBLIC` | `ILT.IAC.RESOURCE.AWS.RDS.NOT_PUBLIC` |
  | `ILT.AWS.RDS.PRODUCTION_BASELINE` | `ILT.IAC.RESOURCE.AWS.RDS.PRODUCTION_BASELINE` |
  | `ILT.AWS.RDS.STORAGE_ENCRYPTED` | `ILT.IAC.RESOURCE.AWS.RDS.STORAGE_ENCRYPTED` |
  | `ILT.AWS.S3.PUBLIC_ACCESS_BLOCKED` | `ILT.IAC.RESOURCE.AWS.S3.PUBLIC_ACCESS_BLOCKED` |
  | `ILT.CHANGE.COMMITS_REVIEWED` | `ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED` |
  | `ILT.CHANGE.PRODUCTION_APPROVED` | `ILT.COMMON.CHANGE.APPROVAL.PRODUCTION_APPROVED` |
  | `ILT.CHANGE.SENSITIVE_CHANGE_APPROVED` | `ILT.IAC.CHANGE.APPROVAL.SENSITIVE_CHANGE_APPROVED` |
  | `ILT.DEPLOYMENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN` | `ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN` |
  | `ILT.DEPLOYMENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE` | `ILT.IMAGE.DEPLOYMENT.CONTENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE` |
  | `ILT.IAC.NO_DRIFT_AFTER_APPLY` | `ILT.IAC.DEPLOYMENT.DRIFT.NO_DRIFT_AFTER_APPLY` |
  | `ILT.IMAGE.BUILD_ACCEPTED_FOR_ENVIRONMENT` | `ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT` |
  | `ILT.IMAGE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT` | `ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT` |
  | `ILT.IMAGE.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE` | `ILT.IMAGE.DEPLOYMENT.DRIFT.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE` |
  | `ILT.IMAGE.SCAN_RAN` | `ILT.IMAGE.ARTIFACT.CHECKS.SCAN_RAN` |
  | `ILT.IMAGE.SIGNED_PROVENANCE_MATCHES_RUN` | `ILT.IMAGE.ARTIFACT.PROVENANCE.SIGNED_PROVENANCE_MATCHES_RUN` |
  | `ILT.IMAGE.TESTS_RAN` | `ILT.IMAGE.ARTIFACT.CHECKS.TESTS_RAN` |

  The other seven starters had no earlier id and are new:
  `ILT.IAC.RESOURCE.AWS.CLOUDTRAIL.RECORDS_ALL_REGIONS`,
  `ILT.IAC.RESOURCE.AWS.CLOUDTRAIL.VALIDATES_LOG_FILES`,
  `ILT.IAC.RESOURCE.AWS.CONFIG.RECORDER_ENABLED`,
  `ILT.IAC.RESOURCE.AWS.CONFIG.RECORDER_RECORDS_GLOBAL_RESOURCES`,
  `ILT.IAC.RESOURCE.AWS.EC2.NO_SSH_OR_RDP_OPEN_TO_THE_INTERNET`,
  `ILT.IAC.RESOURCE.AWS.IAM.NO_POLICY_ALLOWS_ALL_ACTIONS_ON_ALL_RESOURCES` and
  `ILT.IAC.RESOURCE.AWS.S3.ENCRYPTED_WITH_KMS_KEY`.
- The namespace `ILT` is Iltero's alone. No assertion id has a namespace
  that starts with `ILT` other than `ILT` itself, such as `ILTX`: "an
  assertion id's namespace must be ILT or one not starting ILT". Every
  assertion id is also checked for a Windows device name as its first
  segment. Where an id is a project's own, `ILT` itself is refused too
  (`iltero_schemas.models.assertion_id.check_project_id`, "a project's own
  id has a namespace of its own, not ILT or one starting so"): a policy
  source entry's assertion, a binding set read from a file, and the binding
  set a record names as read from a file. An event whose assertion comes
  from the project's own files (`assertion_source` `local` or
  `custom_rego`) is refused when its id is in `ILT` or a namespace that
  starts so: "an assertion from a project's own files has an id outside
  ILT". An event that names a starter (`contract_starter`) names one this
  package ships, at its shipped version and document digest
  (`iltero_schemas.assertions.SHIPPED_ASSERTIONS`, each a
  `ShippedAssertion`): "an assertion named as this package's starter is the
  document this package ships".
- A record's events files are checked against its events. Each stage's
  `events.digest` must be the digest of the bytes `events_file_bytes` gives
  for that stage's events, or the record has the integrity problem "is not
  the digest of the stage's events" at `stages.<stage>.events.digest`. The
  events file's entry in the evidence register must have the same size, or
  the problem is "is kept in the register at another size than its events".
  These problems are listed after every other integrity problem. The entry
  must also say the file is canonical JSON: "the plan stage's events file is
  kept as canonical JSON (RFC8785)".

- A record's id is derived from its run and unit. `metadata.uuid` is the
  version 5 UUID that `iltero_schemas.canonical.record_uuid(run_id, unit)`
  gives: the text `iltero-car:<run id>:<unit>` in the namespace
  `RECORD_UUID_NAMESPACE`. Every stage that reports on the unit writes the
  same record under the same id. A reader recomputes it, and a record whose
  `metadata.uuid` is another value is an integrity problem: "metadata.uuid is
  not the id of the record's run and unit".
- A verification report says when it was written: `metadata.verified_at`, by
  the verifier's own clock. Its `record.digest` is the digest of the record's
  canonical JSON, the record's document digest.
- One form for a stage's events file.
  `iltero_schemas.models.event.events_file_bytes(events)` gives its bytes: the
  RFC 8785 canonical JSON of `{apiVersion, kind: AssuranceEvents, events}`,
  with the stage's events in the order the record lists them
  (`EVENTS_FILE_KIND` is the `kind`). The stage's `events.digest` is the
  digest of those bytes, and its evidence register entry has
  `canonicalization: RFC8785`.
- The `kind` of the trusted bundle keys file is
  `iltero_schemas.trust.TRUST_FILE_KIND`. The `kind` of a bundle's own
  description, `iltero_schemas.models.bundle.BUNDLE_KIND`, sits beside the
  descriptor's `KIND`.
- A compiled program's reason for a failure names the comparison that
  decided it: `assert: false; <path> <op> is false`, or, when a condition
  under `not` held, `assert: false; <path> <op> is true, but must be false`.
  A false `all` is decided by its first false part and a true `any` by its
  first true part. `VEC.IAC.RESOURCE.VEC.THING.TRUTH_REASON` and its evaluation cases cover it.
- Twenty-five starter assertions, among them
  `ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN`, which
  holds that the plan applied is the plan that was evaluated,
  `ILT.IAC.DEPLOYMENT.DRIFT.NO_DRIFT_AFTER_APPLY`, which holds that no deployed resource drifted after the apply, and
  `ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT`, which holds that the commit the build
  tool's provenance names is the commit Iltero Platform verified for the run,
  and is unknown when the build names none,
  `ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT`, which holds that Iltero
  Platform accepted a build of the image for the environment it is deployed to,
  `ILT.IMAGE.DEPLOYMENT.CONTENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE`, which holds that the image the pipeline
  reports it deployed is the image the deploy checked, and
  `ILT.IMAGE.DEPLOYMENT.DRIFT.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE`, which holds that, once the
  workload's rollout has finished, every compared container of every live
  pod runs that image or one of its platform images.
  These six are
  built in (`APPLIED_PLAN_MATCHES_EVALUATED_PLAN`, `NO_DRIFT_AFTER_APPLY`, `BUILD_COMMIT_MATCHES_VERIFIED_COMMIT`,
  `BUILD_ACCEPTED_FOR_ENVIRONMENT`, `REPORTED_IMAGE_MATCHES_CHECKED_IMAGE` and `RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE`
  in `iltero_schemas.assertions`):
  a runner evaluates the first at every infrastructure post-deploy stage, the
  second at every infrastructure post-verify stage, the third at every build's
  plan stage, the fourth at every image deploy's pre-deploy stage, the fifth
  at every image deploy's post-deploy stage and the sixth at every image
  deploy's post-verify stage, whatever a project's own assertions are.
  Their ids are reserved (`BUILT_INS`, each a `ShippedAssertion` with its
  version, document digest and compiled module digest, and `BUILT_IN_IDS`
  for the ids alone): an evaluation that names one
  names the shipped version and document, comes from this package or
  Iltero Platform's bundle and never from a scanner, and ran the shipped module.
  Each activity names the built-in check that what the pipeline carried out
  matches what was checked (`carried_out_matches_checked`) and every
  built-in assertion it always evaluates (`always_evaluated`): once the
  assertion's stage has reported, a record evaluates it exactly once, at that
  stage only, and never as not applicable. An infrastructure record's
  `post_deploy` stage evaluates `ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN` and its
  `post_verify` stage `ILT.IAC.DEPLOYMENT.DRIFT.NO_DRIFT_AFTER_APPLY`; a build's `plan` stage
  evaluates `ILT.IMAGE.ARTIFACT.SOURCE.BUILD_COMMIT_MATCHES_VERIFIED_COMMIT`, which never passes or fails
  when the build names no commit, where it is unknown with
  `not_reported_by_tool`, or on a run the tool opened, where it is unknown
  with `server_facts_unavailable`, since only Iltero Platform verifies the
  commit (an event that was not evaluated, or that ended in error, is
  accepted); an image deploy's `pre_deploy` stage evaluates
  `ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT`, its `post_deploy` stage
  `ILT.IMAGE.DEPLOYMENT.CONTENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE` and its `post_verify` stage
  `ILT.IMAGE.DEPLOYMENT.DRIFT.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE`.
  `ILT.IMAGE.ARTIFACT.CHECKS.TESTS_RAN` holds that the pipeline gave a test report for the
  built image in which at least one test ran rather than being skipped, and
  `ILT.IMAGE.ARTIFACT.CHECKS.SCAN_RAN` that a vulnerability scan ran whose report itself
  names the built image or at least one of its platform images.
  `ILT.COMMON.CHANGE.APPROVAL.PRODUCTION_APPROVED` and `ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED` are
  about any change (`change_type: null`); the seven image assertions are about
  `image_release`, and the others about `iac_change`.
- Every `TechnicalAssertion` says which change type it is about
  (`spec.change_type`: `iac_change`, `image_release`, or `null` for an
  assertion about any change); an assertion that leaves it out is refused.
  Each change type allows its own stage and target pairs (`COMBINATIONS`); an
  assertion about any change, and a hand-written policy, may use any pair
  some change type allows (`VALID_COMBINATIONS`), and an assertion about
  any change reads only the parts every input at that stage and target
  carries (`roots_for`). At the post-verify stage an
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
  separator and the Hangul fillers. They also refuse every other control and
  format character and the tag characters, which spell hidden text, listed
  by code point so every reader refuses the same ones. Variation selectors,
  which follow ordinary emoji, are accepted.
- The evaluation input (`AssuranceContext` v1), with a fixed set of parts for
  each activity, stage and target (`profile_for`). Every input, and every
  event, names the activity it belongs to (`evaluation.activity`). An event
  is checked on its own against its activity: its stage and subject kind
  must have a profile, and its checked content must be of the activity's
  kind (`CHECKED_CONTENT_KIND_OF`). The `assurance` part has no fixed shape in this version:
  any object, held to the bounds of an event's observations.
- Every count is an integer from 0 to 2^53 − 1 (`INT_MAX`), the largest
  integer the evaluator reads exactly.
- A JSON document a tool writes has one form, so one set of facts has one
  digest: every optional field is written, as `null` when it has no value,
  as its model dumps it. A context part outside its stage's profile is `null`. A field
  left out still reads. Every document vector is in this form.
- A reference time claims no more than its source: a runner's clock is
  always `asserted`, and a `time_window` is present exactly when a timestamp
  authority gave the time, with the time inside it. A stage's reference time
  read from its runner's clock is the same instant the stage observed
  (`observed_at`), and an input's is the same instant as its evaluation's
  `timestamp`. Invalid-record and invalid-input vectors cover them.
- In an `AssuranceContext`, `null` means a fact has no value, never that it is
  unknown. A plan's `complete`, `applyable` and `tool_version` hold the unknown
  marker with the reason `not_reported_by_tool` when the tool's plan does
  not say. `change.digest` is required and is the digest of the change type, unit,
  environment and plan. A resource's `type` and `name`, its provider source and a related
  resource's `type` are never `null`. An earlier evaluation names the content it
  checked (`checked_content`) exactly when its stage reads checked content:
  a plan, a built artifact or a deployed image: its kind, or `null`, is one
  some activity's input carries at that stage (`reads_checked_content`). At
  `post_verify`, where an image deploy's input carries the image and an
  infrastructure input nothing, it is the image or `null`, never a plan.
- A plan resource in the evaluation input is a neutral core (`id`,
  `provider`, `type`, `kind`, `name`, `module`, `action`, `before`, `after`,
  `related`), and what only its IaC tool says about it is under `tool_data`,
  keyed by `tool`: Terraform's `provider_source`, `action_reason`,
  `previous_address`, `importing`, `replace_paths`, and a related resource's
  `match`. Its `tool_data`, and each related resource's, must be the
  variant of the plan's tool. It names the kind its tool's table gives its
  type, like a change entry, and `provider` is required and is the
  provider's short name.
- The plan, the apply log and the state, when it was read, name their IaC
  tool (`tool`) and its version (`tool_version`). An apply's timing source
  is `apply_log`.
- A subject is keyed, in the evaluation input, in events and in an earlier
  evaluation, by `key`: the digest of its kind and its one local identity,
  computed by `models.subjects.subject_key` and checked in every document,
  with a conformance vector. The local identity is a managed resource's
  address scoped by its unit (scheme `terraform_address`), the cloud identity
  of a resource only the cloud knows (at runtime), or the unit of a
  change, a deployment or an assurance subject. Only a resource has a cloud
  identity. The key is over the identity's text as written, with no Unicode
  normalization. No stack or
  other Iltero Platform scope is part of it. A subject has at most two
  identities (`MAX_SUBJECT_IDENTITIES`): its local identity and, at runtime,
  its cloud identity; an input's subject has at least one. An identity's
  `scope` holds at most eight keys (`MAX_SCOPE_KEYS`). An event's subject has no key
  and no identity exactly when no subject was in scope.
- `ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN` compares the plan digests, the saved plan
  file's digests and the two `artifact_digest_source` values, so its
  observations show when neither side had the saved plan file. It passes
  then, and fails when only one side has it. Evaluation vectors cover both,
  and how a `null` value evaluates.
- The Change Assurance Record (`CAR` v1) and its events (`AssuranceEvent`
  v1): the record of one attempted change, whatever its outcome. It holds
  each stage's coverage and verdict, the rules that tie the stages together,
  what a deployment did, the resources' cloud identities, and which stages
  are in scope, and its evidence register: each file it cites, by its
  path and digest, with the name and digest of the file as the pipeline
  gave it (`source`). It holds each stage's events file and assertion
  index, each stage's copy of each binding set it applied, what it read from each
  scanner report and each report as it kept it, redacted from the file the
  pipeline gave, each an entry of its own, every event's input, what
  the plan stage redacted, as an entry that names the redaction policy, and,
  once deployed, the apply log the deployment was read from. It says what was checked and how; on its own, it
  does not show that anything is certified or complies with a regulation or
  standard, and its `compliance_determination` is always `null`.
- A record's `trust_level` is one of three levels (`self_attested`,
  `source_authenticated`, `governed`), and a record may claim only
  `self_attested`, since it carries no signature. Its issuer is always
  `local`, and its identity is never verified, whoever opened the run.
- Each part of a record has a fixed shape. A stage's `reference_time` and the
  record's `subject.source` are those of the evaluation input. A stage's
  `redaction` is a redaction report: the policy that ran, what was redacted
  (what that stage reads, and at an infrastructure change's plan stage the
  plan the record names; at `post_deploy` the deployment and at `post_verify`
  the drift check, each the part the stage counts, which those stages keep as
  it is, so they list no path), and the paths redacted (each with a reason
  token), left unknown, or allowed (each with the project's reason). A stage's
  `scanners` names the evaluator binding sets it applied and the scanner
  reports it was given. An excluded resource (`subjects_in_scope.excluded`) names its
  index in the plan's resource list (`plan_index`), its address as written or
  `null`, and one of four reasons. A coverage gap is one of four shapes,
  chosen by its `kind`: a plan flag, a resource's `plan_index`, a count of at
  least 1 (`COUNT_GAP_KINDS`), or the state not read; the record's combined
  coverage names each gap's stage. A resource excluded for its identity is
  also a gap of that kind, once, and every identity gap names such a resource.
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
  UTF-8 bytes as written, with no control character. An evaluator binding set's
  `file_name` follows the same rule. Record vectors cover each rule.
- A plan stage with a `plan_incomplete` gap, whether the plan said it is
  incomplete or did not say it is complete, is incomplete with reason
  `plan_not_complete`. Its verdict still follows its evaluations. An evaluator
  error's reason wins over it, and it wins over
  `upstream_state_unavailable`. A plan that cannot be applied leaves the
  status as it is. The status's `reason` is the leading cause; every cause
  stays in the coverage. Record vectors cover it and pin the order.
- The integrity checks: a record's values that a reader can recompute,
  including its `change.digest`, the pre-deploy stage's source digest and each
  approval of a change, must be what they recompute to. They also recompute
  the status each built-in check must have from the record's own change, and
  report an event a policy answered (`pass`, `fail`, `unknown` or
  `not_applicable`) that says otherwise; an event not evaluated, or that ended
  in error, decides nothing. A stage's owed count is its assertion index's
  count, and, unless the stage was cut short, its owed count and digest are
  those of its events' assertions. These describe the stage's own events and
  index: what a stage owed is shown only against the project's assertion files
  at its commit, or the set Iltero Platform pinned. In an infrastructure
  record, `ILT.IAC.DEPLOYMENT.CONTENT.APPLIED_PLAN_MATCHES_EVALUATED_PLAN`
  must pass exactly when the applied plan has the evaluated plan's digest,
  artifact digest and its source, and
  `ILT.IAC.DEPLOYMENT.DRIFT.NO_DRIFT_AFTER_APPLY` exactly when the drift check
  found no difference; each fails otherwise. Change digest problems come
  first, so a change digest that does not recompute is refused first. A reader
  that sets `SKIP_INTEGRITY_CHECKS` to `True` (any other value is ignored)
  reads the record and gets every problem from `integrity_problems`, to report
  as integrity failures. The checks show that a record agrees with itself, not
  that it is unchanged since it was written. Record vectors
  (`records_integrity_failed/`) cover it.
- An event's `provenance.checked_content` names the content its evaluation
  checked: for an IaC change, the plan, by its `digest`, the `digest_version`
  of its tool's rule and the IaC `tool`. A record holds every event's to the
  content its own change checked. An
  event's executor provider is `local`, `ci` or a CI system's name, such as
  `github_actions`. An event's and a record stage's `bundle` give its
  `kind`, its `tarball_digest` and, for a bundle Iltero Platform served, the
  descriptor's `content_digest` and `key_id`, which are `null` for a bundle
  the tool built; a stage's also gives its `capabilities_digest`. An
  evaluation of an assertion from Iltero Platform's bundle that ran over a
  bundle names a bundle of kind `server`.
- A deployment's apply and the resource identities document are a neutral core plus
  `tool_data`, keyed by `tool`, with that tool's validation in its own module.
  For Terraform, the apply's `tool_data` holds the `summary` counts, the
  number of error diagnostics the log holds (`errors_reported`), the
  `log_lines` it could not read, and the delete of each deposed object (an
  old copy a replacement set aside) settled by the state, or unknown when the
  state was not read; the resource
  identities document's holds its deposed counts. The `summary` is `null`
  exactly when the log reports an error; a log that holds neither its counts
  nor an error was cut short, so its `summary` is the
  `deployment_log_incomplete` marker and it counts as a log that lost
  messages. The apply's `tool_data` must be the
  variant of its log's tool, and the resource identities document's that of its state's
  tool (`models.iac.tools.variants.check_tool_data`). The apply's `changes` name
  each address's current object once. When the applied plan is the
  evaluated one, the apply names, at each address, at least the deposed
  objects the plan stage excluded as `deposed` there, and, at any address, one
  more for each of its `deposed` exclusions whose address was redacted. Any
  more are allowed only against the plan stage's exclusions for identity at
  their address, or its
  exclusions as `deposed` or for identity whose address was redacted, at
  any address, matched by count.
- The resource identities document (`ResourceIdentities` v1), whose
  `resolved` list ties each resource of a unit's configuration to the cloud
  resource it created. A resolved identity's `iac` side names its `tool`, and
  the document lists its `resolvers`, one per cloud provider.
  The cloud side and resolver of a resolved identity each have one shape per
  cloud provider, chosen by a `provider` field; AWS is the first. Each AWS resource name (ARN) has the shape
  AWS could issue: an S3 bucket name that looks like an IP address, holds two
  dots in a row or uses a reserved prefix or suffix is refused, and so is an
  RDS identifier that is not lowercase, ends with a hyphen or holds two
  hyphens in a row. No two of its resolved identities, and no two of its removed
  entries, name the same cloud identity.
- Hand-written policy sources and evaluator binding sets. A scanner
  evaluator's `input_kind` says what the scanner read, and a record's scanner
  report lists its `input_kinds`, in the contract's words. Binding sets,
  events and records name a scanner from one list: `checkov` and `trivy`. An
  event read from a scanner's results names the evaluator whose checks
  decided it (`provenance.evaluator_binding`).
- Named constants for values consumers write as plain strings. Each constant
  lives with the part of the contract it belongs to. `SCHEME_UNIT` is in
  `iltero_schemas.models.vocabulary`, `SCHEME_AWS_ARN` in
  `iltero_schemas.models.providers.aws`, and the CI systems an executor may
  name in `iltero_schemas.models.ci.CI_SYSTEMS`.
- Canonical JSON (RFC 8785) and `sha256` digests, including a plan's digest
  by its IaC tool's rule (`plan_digest(tool, plan)`); `PLAN_DIGEST_VERSIONS`
  gives each rule's version. A plan, or a deployment's applied plan, whose
  `digest_version` is not its tool's rule version is refused
  (`check_plan_digest_version`), and so is a resource identities document whose
  applied plan's is not the rule version of the tool that wrote the state,
  with a vector. A tool with no rule has no plan digest. Two timestamps
  compare to the nanosecond.
- Conformance vectors that another implementation can test itself against,
  including records of runs the tool opened (one of a project that declares
  its units, one whose plan stage read placeholders), a record of a run
  Iltero Platform opened, a resource identities document with no resolved
  identity, the resource identities documents that must be refused, altered ones that must still be accepted,
  the assurance contexts that must be refused, a verification report of
  an image build, and one of an infrastructure change whose commit review
  failed because a commit it ships was not reviewed. The record vectors are in `vectors/records/iac/` and
  `vectors/records/image/`. The rules
  about resolved identities have no vector, because a resolved identity holds
  a cloud identifier this repository does not publish.
- A record says once who opened its run (`governance.run_opened_by`:
  `server` or `local`), and every stage agrees: its assertions are counted
  as `server_pinned` exactly when Iltero Platform opened the run, and as
  `project_files` otherwise.
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
  plan, a change, a deployment or a built artifact as its one unit
  (`counted_from: change_unit`, by the record's change digest,
  `deployment_unit` or `artifact_unit`). Every stage records the
  mode its gate ran in (`enforcement_mode`: `enforcing` or `advisory`, always
  enforcing after the deployment).
- A stage that replaced an input it could not read, such as another unit's
  state, with a placeholder lists it (`coverage.substituted_inputs`: at most
  256, by the tool's address of the input, sorted). Its verdict still
  follows its evaluations, and it is incomplete with reason
  `upstream_state_unavailable`, so a pass on placeholders reads as
  incomplete; an evaluator error's, a state not read's or the plan's reason
  wins over it. One order (`INCOMPLETE_REASON_PRECEDENCE`) serves both: a
  stage takes the first reason that holds, and a record the stage reason
  that comes first, from the earliest stage incomplete for it. A record of a run Iltero Platform opened has none.
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
  single record describes. `iac_change`, a change made with an IaC tool, has
  one activity of the same name; `image_release`, a container image built
  once and released to environments, has the activities `image_build` and
  `image_deploy`. `iltero_schemas.models.change_type` names each
  (`IAC_CHANGE_TYPE`, `IAC_CHANGE_ACTIVITY`, `IMAGE_RELEASE_TYPE`,
  `IMAGE_BUILD_ACTIVITY`, `IMAGE_DEPLOY_ACTIVITY`) and
  gives each activity's change type (`CHANGE_TYPE_OF`). A record's `change` is the body of its activity
  (`change.activity`). An `iac_change` body holds the change digest, the
  `plan`, and once they are known the `deployment`, the `identity` and the
  `drift_check`. The activity declares the type of run that records it, the
  stages a record passes through, which of them a project, an environment's
  policy or the tool may leave out, and the documents each stage owes,
  always or only when the change names one, with the field that names it.
- The evaluation input's environment says whether Iltero Platform's policy
  treats it as production (`organization_scope.environment.production`), and
  the starter assertions guard on that, not on the environment's name. A run
  Iltero Platform did not open holds the unknown marker there, so an
  assertion that guards on production is `unknown`, never skipped.
- Resource selectors on an assertion's target. A resource target names one
  IaC tool's types (`{tool, provider, resource_types}`), whose values are
  that tool's own attributes. A change or deployment target of an
  assertion about an `iac_change` may name a provider's tool-independent
  kinds (`{provider, kinds}`), and the compiler
  writes its scope guard from them: a condition that decides whether the
  assertion applies. Each tool's table gives its types their kinds
  (`iltero_schemas.kinds`, Terraform's for AWS IAM, KMS, network, S3
  and RDS types). Each resource in the evaluation input names its provider's
  short name and the kind the table gives its type, or the unknown marker
  when the table lacks it, so an unnamed type makes the evaluation unknown rather
  than out of scope. `ILT.IAC.CHANGE.APPROVAL.SENSITIVE_CHANGE_APPROVED` names IAM, KMS
  and network kinds, roles, policy attachments, key policies and grants
  included.
- The facts only Iltero Platform holds, as items an assertion reads: approvals,
  exceptions and earlier evaluations. An approval names the change it
  approves by its digest, or the run by Iltero's run id, and says how it was
  obtained and whether it was a self-approval the policy permitted. The
  pre-deploy input names its run (`run.id`), and the approval assertions
  accept either kind, each in its own branch. A stage whose input carries
  approvals lists the ones its evaluations read, whatever their source, each
  once and of the record's own change or run, and lists any only when its
  results read facts from Iltero Platform.
- The unknown marker: where a fact only Iltero Platform holds (approvals,
  exceptions, evaluations, the verified source of a build) is missing, the evaluation input holds a marker,
  so a condition that reads it is `unknown`, never true or false. An
  evaluation whose input reads Iltero Platform facts records where they came
  from (`facts_source`: `server`, or `none`).
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
  about one record, property by property, with no overall verdict. No
  property of an unsigned record is verified, and no record carries a
  signature. Each property has one of a fixed list of results, each a state
  and a reason; a report of a run still in progress gives
  `stage_completeness` `not_assessed`. When the
  report cannot establish a record's integrity, it trusts nothing else the
  record says.
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
  as well as the pre-deploy approval gate. A record of any activity calls a
  stage unsupported only when its activity says the record cannot run it
  (`not_supported`, given the record): for an infrastructure record, when
  its IaC tool cannot; Terraform, which has a drift reader, runs every
  stage. `iltero_schemas.change_types.not_supported_by(tool)` gives the
  stages an IaC tool cannot run.
  The sample records expect all four stages.
- A resource identities document says where its state was read from
  (`sources.read_from`): the state file the apply left, or a refresh-only
  plan, which names no applied plan. A record's identities are always read
  from the state file.
- An apply whose state was not read. When the pipeline says the IaC tool
  could not read its state after the apply, the post-deploy stage is still
  recorded, from the apply log alone. The state is then the unknown marker
  `{"__unknown": true, "reason": "state_not_read"}` (`StateNotRead`), and
  `outcomes_from` is `apply_log_alone`: the log's word, held to the applied
  plan only. Each change's `outcome_from` is `apply_log_alone`, or `none`
  when it stays unknown. A change only the state would have settled (a
  create, delete or replace whose end the log lost, or a change that needs
  no operation) is unknown with that marker; an update
  the log lost stays `deployment_log_incomplete`. Such a record shows that
  an apply was invoked, which plan the pipeline says it applied and what the
  log says of each change. Its post-deploy stage lists the gap `state_not_read`, which makes
  it a coverage gap (exit code 6) and incomplete with reason
  `state_not_read`; an evaluator error's reason comes first. When the log
  lost messages, whether or not the state was read, no change that needs an
  operation, and no deposed object's delete, is `not_attempted`: it is
  unknown. The record
  names no identities, and refuses a drift check and a post-verify stage, as
  a post-verify evaluation input does. `state_not_read` is also a reason an
  `unknown` evaluation can give, only at that post-deploy stage. An activity
  says whether its records read a state after an apply
  (`reads_a_state_after_the_apply`); image builds and deploys do not, so
  they refuse the gap and the reason. Record, context, evaluation and
  compiler vectors cover it.
- A record of a container image build (`change.activity: image_build`). It
  names the image by its repository and digest, the digest of each
  platform's image when the build pushed an index (the manifest that lists
  one image per platform), the commit the build tool's provenance names
  (`build_commit`), the build's attestation file, by its digest and not
  verified, and the test and scan reports the build was given (`reports`: each
  report's file, its format, `junit`, `trivy_json` or `grype_json`, and the
  image it is about, which is the image or one of its platform images; a
  JUnit report names no image, so only the pipeline ties it to one). A tag
  the pipeline gave is kept for reading only, with the build tool's
  metadata file that tied it to the digest (`read_from`,
  `read_from_evidence_ref`); no registry is asked. The build commit is read only from the Docker Buildx metadata
  file (`docker buildx build --metadata-file`), from the provenance summary
  BuildKit writes there when the build context is a Git repository URL
  (`invocation.configSource.digest.sha1`), never from an image label. A
  build from a local directory names no commit there, so its
  `build_commit` is `null`. The file is the pipeline's and unsigned, so the
  commit is `not_verified`; the record keeps the file as the pipeline gave
  it, and it is the same file the tag is read from. The metadata file the
  tag or the commit is read from is JSON and kept unredacted, exactly as
  given.
  `iltero_schemas.models.image.buildx.build_metadata_of` reads the image digest,
  the image names and the commit from the kept file, strictly and at most
  1 MiB, so every reader reads the same values, and
  `iltero_schemas.change_types.check_build_metadata` compares them with the
  record: the image's digest, the image's repository with its tag (each
  image name put in its one spelling first by
  `iltero_schemas.models.image.naming.in_one_spelling`), and exactly its build
  commit. A metadata file whose `containerimage.descriptor` names another
  digest than `containerimage.digest` is refused. Building with
  `--provenance=mode=min` is recommended: the commit is the same as in
  `mode=max`, which also writes the build's arguments, and a build argument
  can hold a secret value. The tool that writes a record runs it, and so can
  any reader given the file from the pipeline's store. Iltero stores none of
  a build's evidence files except the attestation, when it was sent
  (`sent_to_server: true`), and never reads the pipeline's store: the
  pipeline keeps them in the run's artifact store, and the record keeps each
  file's digest. The raw image index, which the plan stage owes
  (`image_index`, the one document an image build's `named_documents`
  lists), passes through Iltero Platform, which checks it with
  `platform_digests_of`, refusing an index over 4 MiB or one that lists more
  than 64 platform images, and then discards it.
  On a run Iltero Platform opened, the commit check compares the commit the
  record names, read by the tool from the pipeline's metadata file and
  `not_verified`, with the commit Iltero Platform verified; Iltero Platform
  does not check that commit against the file. The repository the commit is of is not compared, a build
  with additional named contexts may use more than that commit, and a
  record that names no tag and no commit may keep no metadata file. The
  commit the run's checkout was at stays in the record's source and says
  nothing of the image. A repository is written in one fully qualified,
  lower-case spelling with its registry host (`docker.io/library/nginx`,
  never `nginx`), a port only when it is not the default 443, and Docker
  Hub always as `docker.io` with no port. The raw index, the attestation,
  the metadata file and each report are different files of the record, the
  index, the attestation, the metadata file a commit is read from and each
  report each of a file type their role allows, a report the type of its
  format. Each report's entry names the digest of the file as the pipeline
  gave it, a different one for each report, and a report nothing redacted
  is stored exactly as given. A report an evaluation reads is matched on
  that digest, so redacting the stored copy never breaks the match.
  `platform_digests_of` reads the platform digests from the kept index
  bytes, so every reader computes the same list; it reads plain UTF-8 JSON
  only, and skips a manifest only when it is marked as an attestation and
  has no real platform. A build has only a plan stage, belongs to no environment, even
  in a run Iltero Platform opened, and deploys nothing, so it has no change
  digest and nothing to approve. Its evaluations are about the built
  artifact, and their input carries the image with its build commit, or
  the unknown marker when the build named none, the test and scan reports
  the build was given, each saying whether the report itself names the
  image or only the pipeline does (`image_digest_source`: `report` or
  `pipeline`), and the commit Iltero Platform verified for the build job, with
  the CI system and its instance, the repository by id and name, and the
  CI run and attempt it was verified for, since a CI system's ids are unique
  only within one instance of it. A build's input names no environment. A
  build's evaluations say their facts came from Iltero Platform exactly when
  Iltero Platform opened the run, and from nowhere otherwise, never from a local
  file. Record, context and evaluation vectors cover it. The values it adds:

  | Where | Added value |
  | --- | --- |
  | Change type (`spec.change_type`) | `image_release` |
  | Activity (`change.activity`, `evaluation.activity`) | `image_build` |
  | Run type of an activity | `build` |
  | Document a stage owes | `image_index` |
  | Assertion target kind | `artifact` |
  | Evaluation input parts | `artifact`, `tests`, `scans`, `verified_source` |
  | Checked content kind | `container_image` |
  | How a stage counts its subjects (`counted_from`) | `artifact_unit` |

- A record of the deployment of a built container image to one environment
  (`change.activity: image_deploy`). The image was checked when it was
  built, so the record starts at its `pre_deploy` stage, where the change is
  approved, and its change digest names the image, by its repository and
  digest, in the record's unit and environment. The record keeps the build
  Iltero Platform accepted for the environment (`build`: its run, its
  record's digest, its platform digests, the commit Iltero Platform verified
  for it (`verified_commit`), the commit its build metadata names
  (`build_commit`, `null` when it names none) and the repository its verified
  source names, as its git host names it (`repository`: `host`, `instance`
  and `repository_id`)), as Iltero Platform served it,
  and never a build a pipeline chose; a record of a run the tool opened
  names none. `ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT` checks at
  `pre_deploy` that there is one: it passes when Iltero Platform accepted a
  build, fails when a run Iltero Platform opened has none, and is unknown
  with `server_facts_unavailable` in a run the tool opened, so that stage is
  then at best indeterminate (exit code 3). It may otherwise only be not
  evaluated (`timeout`, `evaluator_unavailable`) or end in an error, for a
  fault of the evaluator. The evaluation input tells the two cases apart:
  it always names its environment, and its `change.build` is the unknown
  marker in a run the tool opened, exactly when the environment's
  production flag is, and `null` only when Iltero Platform accepted no
  build. The Iltero CLI talks to no cluster and no deploy tool: after the deployment
  the pipeline reports the image it deployed (`deployment`), and at
  `post_verify` what one reading of the workload found (`drift_check`: the
  workload, in the shape of its platform, here a Kubernetes Deployment,
  StatefulSet or DaemonSet with its cluster, namespace, name and uid; the
  state of its rollout, in the shape of its kind, with the resource
  version the cluster gave the workload object, the counts its status
  reported, whether the rollout had finished, by the test
  `kubectl rollout status` applies, and the live pods it calls for; every
  container of its pod template, with its role (app, init or sidecar), the
  image reference it names and whether the reading compares it
  (`template_containers`); what every container of every pod the workload controls
  ran, grouped by container, role, image reference, digest, pod state and
  revision (`containers_read`), with the unknown marker where a container's
  status names no registry digest; the number of live pods read; the
  resource version of the pod list; and the files the reading was taken
  from: the workload object read before and after the pods were listed,
  the pod list and, for a Deployment, its ReplicaSets, each a different
  JSON file in the evidence register, redacted under the record's
  redaction policy), each read from files the pipeline wrote. The record
  names no time of its own for the deployment or the reading, which are the
  pipeline's word: the stage that reports each was observed no earlier than
  the pipeline reported it. A reading lists the pods whose
  controller owner reference leads to the workload, and compares every
  container, of the pod template or of a pod, whose image reference names
  the deployed repository in its one spelling, and every container of a
  pod whose template container is compared. A container only the pods
  have, under another repository, is recorded with its digest but not
  compared. Once the rollout has finished, every live pod lists every
  template container in its role and all live pods share one revision, a
  stateful set's update revision. A partitioned or on-delete rollout, and
  a stateful set whose status names no update revision, never finish, and
  neither does a daemon set with a pod on a node it no longer selects.
  `ILT.IMAGE.DEPLOYMENT.DRIFT.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE` fails when the template compares no
  container, and terminating and finished pods never decide it.
  A container may report the index digest or a platform
  image's digest, depending on its runtime, so either counts. Only the
  `post_verify` stage may be left out, by the project, the environment's
  policy, or as not supported for a workload no reader reads. An
  evaluation input reads its `change`, `deployment` and `drift_check` in
  the shapes of its activity, and its `post_verify` input refuses a
  reading of the workload taken before the deployment. At `pre_deploy`, an
  assertion about any
  change reads what both the infrastructure and the image deploy input
  carry, which leaves out `plan`. The integrity checks recompute the status
  each of its built-in checks must have from the record's own image,
  deployment, reading and build, and report an event that says otherwise;
  `ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT` is recomputed only in a run
  Iltero Platform opened. In a run the tool opened, the record's own rules
  refuse that check unless it is unknown with `server_facts_unavailable`,
  or did not run or ended in an error for a fault of the evaluator, even
  when the integrity checks are skipped.
  A record refuses a built-in assertion of another activity. Record,
  context, evaluation and change digest vectors cover it. The values it
  adds:

  | Where | Added value |
  | --- | --- |
  | Activity (`change.activity`, `evaluation.activity`) | `image_deploy` |
  | Stage and target pairs of `image_release` (`COMBINATIONS`) | `pre_deploy` and `change`; `post_deploy` and `deployment`; `post_verify` and `deployment` |
  | Evaluation input profiles | `image_pre_deploy_change`, `image_post_deploy`, `image_post_verify` |
  | Workload platform (`drift_check.workload.platform`) | `kubernetes` |
  | Workload kind (`drift_check.workload.kind`) | `deployment`, `stateful_set`, `daemon_set` |
  | Rollout strategy (`drift_check.rollout.strategy`) | `rolling_update`; `recreate` for a Deployment; `on_delete` for a StatefulSet or DaemonSet |
  | Container role in the pod template (`template_containers[].role`) | `app`, `init`, `sidecar` |
  | Container role in a pod (`containers_read[].role`) | `app`, `init`, `sidecar`, `ephemeral` |
  | Pod state (`containers_read[].pod_state`) | `live`, `terminating`, `finished` |
  | Who reports a deployment (`deployment.reported_by`) | `pipeline` |
  | Built-in assertions | `ILT.IMAGE.CHANGE.BUILD.BUILD_ACCEPTED_FOR_ENVIRONMENT`, `ILT.IMAGE.DEPLOYMENT.CONTENT.REPORTED_IMAGE_MATCHES_CHECKED_IMAGE`, `ILT.IMAGE.DEPLOYMENT.DRIFT.RUNNING_IMAGE_MATCHES_DEPLOYED_IMAGE` |

- Commit review. The `pre_deploy` input of an infrastructure change and of an
  image deploy carries `commit_review`, a fact only Iltero Platform holds:
  whether every commit the change ships since its review starting point, a
  commit an administrator recorded, was merged through a pull request with a
  qualifying approval (`iltero_schemas.models.commit_review.CommitReview`).
  Its outcome is `reviewed`, `not_reviewed` (with up to 50 commits not
  reviewed, each with one reason, and whether that list is complete),
  `too_many_commits` (more than the 100 Iltero Platform checks),
  `no_review_starting_point`, `review_starting_point_not_in_history`,
  `head_commit_before_review_starting_point`, or one that comes before every
  other: for an infrastructure change, `source_commit_not_verified_commit`,
  when the input's source commit is not the one Iltero Platform verified, and
  for an image deploy, `build_commit_not_verified_commit`, when the image's
  build names no commit or another than the one Iltero verified. It names the
  reading of the git host it was decided from, a digest of what the decision
  rests on, the repository and the head commit Iltero Platform verified: an
  infrastructure change's `source.commit.sha` (the verified commit for
  `source_commit_not_verified_commit`), or the accepted build's
  `verified_commit` and `repository`. A counted outcome (`reviewed`,
  `not_reviewed`, `too_many_commits`) says where its count starts
  (`counted_since`), which Iltero Platform chooses: after the review starting
  point, or after the head commit of an earlier `reviewed` reading of
  the same repository, decided after the same starting point was set, whose
  head commit is on this head's first-parent line (`earlier_reading`: that
  reading's own `host_reading_id`, `host_reading_digest` and `decided_at`,
  `null` for the starting point); and how many commits it counted
  (`commits_counted`). A later reading does not judge again the commits an
  earlier one covered. An approval
  qualifies only as the reviewer's latest decision when the git host is read.
  `check_commit_review` holds it to the rest of the input, and
  it is the unknown marker in a run no server opened, for an infrastructure
  change that names no environment, and for an image deploy with no accepted
  build. The starter assertion `ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED`
  passes only for `reviewed`, fails for every other outcome and is `unknown`
  for the marker; it is not built in. A `pre_deploy` stage record keeps the
  commit review its evaluations read, whole, or the unknown marker in its
  place (`commit_review`), and its approvals the same way (`approvals`;
  `StageRecord.listed_approvals` gives the list). Both are the marker when
  the stage's results read no facts from Iltero Platform. The commit review
  is also the marker when `ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED` could not read one,
  and is kept when that check passed or failed, `reviewed` exactly when it
  passed. A stage
  evaluates the check at most once. The kept review was decided no later
  than the stage observed the change, and names the record's source commit
  (unless it is `source_commit_not_verified_commit`), or an image deploy's
  accepted build's verified commit and repository. A verification report
  gives it a tenth property, `commit_review`, whose result follows the kept
  outcome (`COMMIT_REVIEW_RESULTS`). A record of a
  run the tool opened refuses an `ILT.COMMON.CHANGE.SOURCE.COMMITS_REVIEWED` event that is
  `pass`, `fail` or `not_applicable`, or `unknown` for another reason than
  `server_facts_unavailable`; a record of a run Iltero Platform opened
  refuses one that passed or failed without facts from Iltero Platform. A git
  repository is named by its host (`github`), the host's instance and its id
  there (`iltero_schemas.models.git.GitRepository`). Context, evaluation and
  record vectors cover it.
- Scan coverage. `iltero_schemas.change_types.scan_coverage(build)` says
  which of a build's platform images its scan reports name and which none
  does, counted as `ILT.IMAGE.ARTIFACT.CHECKS.SCAN_RAN` counts them, with vectors in
  `vectors/scan_coverage/`. A scan report of an image built for several
  platforms, in a record or an evaluation input, names the platform it
  scanned, never the image's own digest.
- Signed build provenance. `iltero_schemas.models.image.attestation` reads the
  in-toto statement a build's Sigstore attestation carries, without checking
  its signature, and checks that it names the image's own digest. A build's
  input carries `attestation_outcome`: whether Iltero Platform verified the
  attestation, with what its signing certificate names, refused it, or was
  sent none, with what it checked the attestation against. The record keeps
  the digest of the attestation file as the pipeline gave it, not its bytes,
  and says whether the file was sent to Iltero Platform for checking
  (`sent_to_server`), which on a run the tool opened it never is.
  `check_attestation_outcome` checks that the answer is about the
  attestation the record keeps, and that it is `not_sent` exactly when the
  record keeps none or one it did not send. The starter assertion
  `ILT.IMAGE.ARTIFACT.PROVENANCE.SIGNED_PROVENANCE_MATCHES_RUN` holds that a verified
  attestation names the built image and the run's repository, commit and
  run; it fails when no attestation was sent, passes only for a record that
  keeps the attestation it sent, and on a run the tool opened is always
  `unknown` (`server_facts_unavailable`). Vectors are in
  `vectors/attestations/` and `vectors/evaluation/`.
- A verification report's `runtime_verification` is one of seven results,
  each a state and its reason, among them `not_assessed` with
  `not_in_activity` for a record whose activity has no stage after
  deployment, such as an image build, or `not_determined` when the record's
  integrity is not established.
- Files grouped by change type. Modules and conformance vectors that belong
  to one change type live under `iac/`, for changes made with an
  infrastructure-as-code (IaC) tool, or `image/`, for container image builds
  and deploys, such as `iltero_schemas.models.image.deploy` and
  `vectors/records/iac/`. Each document folder's `digests.json` and each
  conformance case name a document by its path from that folder
  (`image/local_run_build.json`).
- Comparisons with `null`. An assertion checks whether a value is null with
  `equal: null`, or that it is set with `not_equal: null`. Any other
  comparison with `null` is refused ("only equal and not_equal compare with
  null"). A value that is absent, or an unknown marker, is still unknown.
  The conformance vector `VEC.IAC.RESOURCE.VEC.THING.OPS_NULL` and its evaluation cases show each
  outcome. Existing assertions compile to the same bytes as before.
- One spelling of no value. An assertion document or an evaluator binding
  set writes no value only as the word `null`. YAML also reads an empty
  value, `~`, `Null` and `NULL` as null, so the loader refuses them, and a
  forgotten value is never read as a comparison with null.
- An exception never covers a built-in assertion: an exception served for
  one is refused, since what a built-in assertion records is never excused.
- Refusals that never repeat the input. A refusal message says which rule
  was broken and never repeats the value it refused; a caller that reads
  `ValidationError.errors()` passes `include_input=False`. The
  `assertions_invalid/` vectors expect these messages, such as
  `duplicate key`.
- Evaluations from a scanner's results. A scanner such as Checkov or Trivy
  runs in the pipeline, and an evaluator binding set says which of its
  checks decide which assertion. The plan stage of an infrastructure change
  reads each report it is given and turns the bound results into one
  evaluation per scanner, beside the assertion's own evaluation, and every
  reader can recompute each of those verdicts from the files the stage kept.
  - An assertion can leave its rule to scanners. `assert` is always written;
    `assert: null` marks an assertion that only scanners decide. Such an
    assertion is about a resource, names the stages whose scanner results may
    decide it (`spec.evidence.stages`, only stages whose scanner results
    Iltero reads, which is `plan`) instead of `spec.stage`, and needs a
    `metadata.description` that says exactly what is true of a resource that
    meets it. Its compiled program never passes or fails: it applies the
    `when` guard and is otherwise `unknown` with the reason
    `observed_by_scanners`. Any assertion may now carry a description.
  - An evaluator binding set holds one binding per assertion: the assertion
    it decides, by id, version and document digest, and its `evaluators`.
    Each evaluator names a tool, a stage, the checks that decide together
    (`rule_ids`: any failure fails, all must pass), a version range that must
    have an upper bound, what the scanner read (`input_kind`: `plan` at the
    plan stage, `deployed_resources` at runtime), how a result finds its
    subject (`subject_match`: `exact_address`, or `plan_configures` for a
    resource that configures the subject, such as a bucket's public access
    block), and the attribute paths the checks read (`paths_read`). A binding
    is a lookup table, not a requirement: a scanner with no report adds
    nothing, and a check bound nowhere is kept as evidence only. Results a
    tool wrote about the configuration as written decide nothing: they are
    counted (`written_configuration_results`) and left out.
    `check_project_set` refuses a project's own set that takes an `ILT.` id
    or decides an assertion Iltero ships.
  - A run can require scanners (`required_scanners`, as the record states
    them; a reader does not check them against any configuration). A required scanner that gave
    no report gives every subject its bound checks cover an evaluation that
    is `not_evaluated` with `scanner_not_run`, naming no version and no input.
    That, or a required scanner's report from a version its binding does not
    allow (`scanner_version_not_allowed`), is a gap no pass fills: it cancels
    every pass and not applicable verdict, and a failure, an unknown result or
    another evaluator's error still stands. A scanner the run does not
    require cancels nothing. `combined_verdict`, `stage_verdicts` and the
    stage counts take the scanners the run requires
    (`stage_required_scanners`).
  - Each stage lists, for each reason an evaluation was not evaluated or
    ended in error, a count gap of the combined verdicts that reason left
    undecided (`undecided_reason_counts`). The integrity checks recompute
    the counts from the events.
  - An evaluation that could not decide and that the subject's combined
    verdict does not count is a gap too: beside a verdict another evaluator
    decided, beside an undecided verdict another evaluator reached, or beside
    one with another status. The verdict stands, and the stage
    lists one `evaluator_did_not_decide` gap for each evaluator and reason,
    with the number of such evaluations (`evaluator_did_not_decide_counts`),
    which the integrity checks recompute from the events. A gap for an
    evaluator error marks the stage incomplete with reason
    `required_policy_evaluation_failed`; a gap for a check not evaluated is
    listed only.
  - Seven starter assertions about AWS resources join the package: no SSH or
    RDP open to the internet in a security group, S3 default encryption with
    a KMS key (Key Management Service), unknown at plan when the plan has no
    encryption configuration for the bucket (checked again after the
    deployment, a bucket left on Amazon S3 managed keys fails), and five that
    only scanners decide, about IAM (Identity and Access Management) policies, CloudTrail trails and
    AWS Config recorders. The shipped set `ILT.BINDINGS.STARTER` binds nine
    starters to Checkov and Trivy checks.
  - Scanner observations (`ScannerObservations` v1) are what a stage read
    from one report, in one shape for every tool. The Checkov and Trivy
    readers build them from a report and the plan's addresses. A result's
    address resolves to a plan resource by an exact rule per tool: Checkov
    writes the plan's address, and Trivy writes the type and name, with the
    MD5 digest of the module path inside a module. Resources made by `count`
    or `for_each` share a Trivy address, so a result about one is ambiguous.
    A result whose word for what it read is not a string is an unreadable
    result, not a failure of the reader, and so is a Trivy `CauseMetadata` or
    a Checkov `connected_node` that is present but not an object. A reader
    refuses a report with a redaction marker where it expects an object, a
    list or a count, such as a list of results, whatever the marker's
    `present` says; only a marker whose `type` is `null` and whose `present`
    is `false` reads as the `null` it stands for. A Checkov report that gives its parsing-error count for
    some frameworks but not others, gives one that is not a count, or gives
    a framework a `summary` that is not an object, is refused.
  - A stage keeps each scanner report in the contract's kept form
    (`kept_report`): only the fields the reader reads, plus each check's
    title and severity and the reason the scanned source gives for skipping
    a check. It keeps none of the plan's values, file paths, source lines,
    secrets or rendered source, and it reads into the same observations as
    the whole report. A value read only for its shape that is not of that
    shape, and a list of names that is not a list of strings and redaction
    markers, is kept as `null` or as its truth, never as text. An object the
    reader reads that is neither an object nor `null` is kept as its truth,
    never as `null`, so it is never read as absent. A whole
    redaction marker is kept as written wherever it stands in place of a kept
    value, object, list or name, so a report the stage kept and then redacted
    is its own kept form. A Checkov framework whose results
    the reader only counts keeps only enough of each to be counted and read
    the same way. A reader refuses a kept report whose canonical bytes are not those
    of its kept form.
  - Each scanner report entry of a record counts, in `redacted_values`, the
    redaction markers that stand for a value in the report as the stage kept
    it, by reason (`{}` for none). It describes the kept file, not what the
    redaction policy did: a marker in a field the kept form drops is not
    counted. A reader recomputes the count with `redacted_value_counts` and
    refuses a report entry whose count differs. Only the JSON value `true`
    marks a value redacted, never `1` or `1.0`, as in the evaluator's runtime;
    the context case `redaction_marker_written_with_one_for_true` refuses a
    marker whose `__redacted` is `1`.
  - Each scanner evaluation names the checks it rests on, the resources their
    results were about, the paths the plan knows only after the deployment,
    and which checks failed or decided nothing. Its verdict is a pass, a
    fail, `unknown` (a value known only after the deployment, no result from
    a tool that reports passes, an ambiguous failure, a failure tied to no
    resource of the plan, or an incomplete report) or `not_evaluated` (a version outside the range, a check the
    source suppressed, no result from a tool that names only failures, or a
    required scanner that gave no report). A report that holds results the
    stage could not read, or files the tool could not parse, makes every
    subject that no failure decides `unknown` with
    `scanner_report_incomplete`, for every tool, before a check with no
    result is read as silence. A failed check tied to no resource of the
    plan (no address, or one the plan does not hold) makes every subject
    without a failure of its own `unknown` with `scanner_result_unresolved`,
    before a suppression or a tool's silence. A suppressed check gives `suppressed_in_source`
    only when nothing else is left open: the stage read the whole report, no
    other result is a word that is not a decision, and every other check
    without a decision is suppressed too or, for a tool that names only
    failures, silent.
    An assertion that only scanners decide and that no report covers is
    `not_evaluated` with `no_scanner_report`. Such an assertion's subjects
    leave out every resource the stage's coverage excludes for its identity,
    and a reader checks each exclusion against the plan the stage kept, for a
    stage that keeps a scanner report or requires a scanner: its `id` is the
    address the plan wrote there, or `null` when that address is not text, and
    its `reason` is exactly the one the plan gives for that resource
    (`exclusion_reason`). That reason is the first that holds, in this order:
    `identity_redacted` when a naming field holds a whole redaction marker
    (any other value that is not text makes the plan unreadable);
    `identity_unnameable` when a naming field is empty, too long or holds a
    control character; `not_managed` when the resource's `mode` is not
    `managed`; `deposed` when its `deposed` holds a value; and
    `identity_unnameable` when its provider has no short name an assertion
    can target. For Terraform the naming fields are `address`,
    `module_address`, `type` and `provider_name`.
  - A stage evaluates an assertion once per subject and evaluator. Its
    verdict for an assertion and subject combines its evaluators: a failure
    wins, then `unknown`, then a pass (`COMBINING_ORDER`). Coverage counts
    these combined verdicts, and an earlier evaluation served by Iltero
    Platform names the engines that reached its verdict (`decided_by`).
  - A record's `scanners` names the binding sets the stage applied
    (`evaluator_binding_sets`), the scanners the run requires, and each
    report. A stage always applies the binding set Iltero ships, and may
    also apply one binding set from the project's own file, listed first.
    The project's set decides only the project's own assertions and the
    shipped set only Iltero's starter assertions, so each scanner verdict's
    `provenance.evaluator_binding.digest` matches exactly one binding across
    the stage's sets, and a reader finds the set that decided it from that
    digest. The evidence register lists the copy of each set, and the copy
    of a project's set names the file it was read from. For each report the
    record names who supplied it, what it read, its results,
    unreadable results, results about the configuration and the files the
    tool could not parse. A reader must call
    `scanner_evidence_problems` with the files the stage kept (`KeptFiles`):
    it rebuilds the observations from the kept report and the one plan the
    stage kept, and checks every evaluation against the verdict they give.
  - A plan stage may postpone a check that read a value the plan knows only
    after the deployment (`values_known_after_deployment: postpone`). It
    lists each such check (`postponed_checks`) and counts it as a
    `checked_after_deployment` gap, so its gate treats the check as decided
    later; the post-verify stage then evaluates it over the values after the
    apply and reports what it redacted of them (`resource_redaction`). The
    list may leave a check out, which then stays unknown and holds the gate.
    Each evaluation about a resource at post-verify
    (`settles_a_postponed_check`) settles one postponed check, once, over the
    plan it was postponed from: the assertion's own rule decides it, or, when
    no evaluator could run, it is `not_evaluated` with no evaluator.
    Until the post-verify stage reports, the record is incomplete with reason
    `checks_postponed_until_after_the_deployment` (`OPEN_CHECKS_REASON`) and a
    detail that counts the open checks, unless its stages give a reason that
    comes earlier. Only a record holds this reason. In
    `INCOMPLETE_REASON_PRECEDENCE` it comes after `state_not_read` and before
    `plan_not_complete`. `postponed_check_problems` checks the list against
    the kept plan.
  - A stage none of whose evaluations ran over an input that carries approvals
    or a commit review keeps the marker `not_read_by_the_stage` in their
    place; one whose checks read such an input keeps the list, the review or
    the `server_facts_unavailable` marker as before. An evaluation input is at most 16 MiB of canonical JSON, and
    the input's `assurance` part has a shape: an assertion's current and
    previous results about one subject, and the deployments and exceptions in
    between.
  - A project's own exceptions file (`LocalExceptions` v1) names, for each
    exception, an assertion, an environment, resources and a period, and who
    the project says approved it: it is the project's own word. Each
    resource is named by its address, scoped by exactly its unit, each
    exception lasts at most 365 days of 24 hours from its `valid_from`
    (`MAX_EXCEPTION_DAYS`), and no two
    exceptions cover the same assertion, environment and resource at
    overlapping times. `read_local_exceptions` reads the file as JSON for
    `.json` and as YAML for `.yaml` or `.yml`, at most 256 KiB. A stage that
    applies it names it in `scanners.local_exceptions` (`file_path`, the
    `digest` of its raw bytes, and `copy_path`, with the same suffix) and
    keeps a byte copy in the evidence register, unredacted, whose `source`
    names the file. A scanner evaluation whose check the source suppressed
    may name an exception from that file only; it stays not evaluated. A
    record of a run Iltero Platform opened applies no such file and names no
    such exception. An exception is in force from `valid_from` up to and
    including `expires_at`, judged at the stage's reference time
    (`exception_in_force`); `why_no_exception` says why none covers a result.
    `scanner_evidence_problems`, given the copy in `KeptFiles.exceptions`,
    works out again which exception covers each suppressed result and lists
    a record that names another, or leaves one out.
  - These checks show that each verdict follows from what the stage kept.
    They do not show that the scanner ran, that the report is what it wrote,
    that it read the plan the record names, or that its version is genuine.
    In a self-attested record, all of it is the writer's claim, and so is
    `required_scanners`: a record that leaves a scanner out of the list,
    with its evaluations and gaps, still holds together, so a reader
    compares the list with the scanners its own policy requires.
  - Names and shapes that changed:

    | Before | Now |
    | --- | --- |
    | A binding entry with its own `id` and `version`, one `rule_id` and a `status_map` | A binding per assertion, with `evaluators` and `rule_ids`; a tool's words are read only as `TOOL_DECISIONS` lists them |
    | An event's `evaluator_binding` with `id`, `version` and `digest` | `evaluator_binding` with the evaluator's `digest` only |
    | `binding_count` | `assertions_bound` |
    | A report's `parsing_errors` | `tool_parsing_errors`, `null` when the tool does not say |
    | A report's `input_kinds` in the tool's words (`terraform_plan`) | The contract's words (`plan`) |
    | `results_accepted`, `results_scanner_version_not_allowed`, `results_without_binding` | Removed: every verdict is an event |
    | The `accepted_by_binding` gap | Removed; the `checked_after_deployment` gap is new |

  - Vectors are in `vectors/binding_sets/`, `vectors/binding_sets_invalid/`,
    `vectors/binding_sets_project_invalid/`, `vectors/scanner_reports/iac/`,
    `vectors/scanner_observations/iac/`, `vectors/scanner_evidence/iac/`,
    `vectors/records/iac/local_run_scanned.json`,
    `vectors/records/iac/local_run_scanned_project.json`,
    `vectors/records/iac/local_run_scanner_required.json`,
    `vectors/records/iac/local_run_scanned_project_required.json` (a
    required scanner's version that its binding does not allow cancels a
    pass), `vectors/records/iac/local_run_scanned_redacted_result.json` (a
    redacted Trivy result leaves the subjects Trivy is silent about
    `unknown`), `vectors/records/iac/local_run_suppressed_with_exception.json`
    (a suppressed result names the exception the kept exceptions file gives
    it), each with its kept files in its own folder of
    `vectors/scanner_evidence/iac/`, which may hold a `cases.json`,
    `vectors/records/iac/local_run_postponed.json`,
    `vectors/records/iac/local_run_postponed_settled.json` (with the project
    assertion `ACME.IAC.RESOURCE.TERRAFORM.DATA.OUTPUT_SET` it evaluates) and
    the evaluation cases.
