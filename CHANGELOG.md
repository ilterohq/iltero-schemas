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
  `apiVersion: iltero.com/v1` (`iltero_schemas.models.common.base.API_VERSION`) and
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
  | `ScannerCheckMapping` | A scanner check mapping: which scanner checks decide which assertion |
  | `ScannerObservations` | What a stage read from one scanner's report |
  | `LocalExceptions` | A project's own exceptions |
  | `ServedExceptions` | The exceptions Iltero Platform serves one stage of a run |
  | `PolicySource` | A directory of hand-written policies |
  | `AssertionBundleDescriptor` | How Iltero Platform serves a signed assertion bundle |
  | `ScannerCheckMappingDescriptor` | How Iltero Platform serves a signed scanner check mapping |
  | `AssertionBundle` | The bundle's own description in its `.manifest` file |
  | `SigningKeys` | The trusted signing keys file |

  Documents take one of two shapes. A document Iltero writes as evidence keeps
  its content at the top level, with facts about the document itself in a
  `metadata` object where it has any: a record's `uuid` and `issuer`, a
  verification report's `verifier` and `verified_at`, and a resource
  identities document's `generator`. A document a person writes has `apiVersion`, `kind`,
  `metadata` and `spec`: a scanner check mapping keeps its `id` and
  `version` in `metadata` and its assertion mappings in
  `spec.assertion_mappings`, and local
  exceptions and a policy source name themselves by `metadata.name`, a
  name the project chooses (1 to 63 lowercase letters, digits and inner
  hyphens, `iltero_schemas.models.common.fields.PROJECT_DOCUMENT_NAME_PATTERN`), and
  keep their entries in
  `spec.exceptions` and `spec.policies`. A document's digest covers the whole
  document, `metadata` included. Every conformance vector, and every digest
  that cites one, uses these names and shapes.
- Assertion ids that say what kind of check an assertion is. An id is now
  segments in fixed places, joined by dots:
  `<NAMESPACE>.<CHANGE_TYPE>.<TARGET>.<SCOPE...>.<CHECK>`
  (`iltero_schemas.models.common.assertion_id`). The namespace is `ILT` for Iltero's
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
  record or an assertion mapping, keeps only the general shape (upper-case
  segments joined by dots), and a scanner check mapping's id is not an
  assertion id. Every id
  has the same limit of 96 characters: `ID_MAX_LENGTH` is
  `ASSERTION_ID_MAX_LENGTH`.

  How to read an id: the change type segment says what an assertion is
  about, not which change it was evaluated in, so a `COMMON` assertion
  appears in records of every change type and evidence is grouped by change
  with an event's `evaluation.activity`. An area compares only within one
  namespace, and a resource's service is the author's word. Once released,
  an id is never renamed: a renamed check is a new assertion.

  The starter assertions were renamed to this form. Every conformance vector uses the new
  ids, and the vector assertions of a project's own are now
  `ACME.IAC.RESOURCE.AWS.RDS.*`.

  | Old id | New id |
  | --- | --- |
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
  (`iltero_schemas.models.common.assertion_id.check_project_id`, "a project's own
  id has a namespace of its own, not ILT or one starting so"): a policy
  source entry's assertion, a scanner check mapping read from a file, and
  the scanner check mapping a record names as read from a file. An event whose assertion comes
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
  `iltero_schemas.models.common.event.events_file_bytes(events)` gives its bytes: the
  RFC 8785 canonical JSON of `{apiVersion, kind: AssuranceEvents, events}`,
  with the stage's events in the order the record lists them
  (`EVENTS_FILE_KIND` is the `kind`). The stage's `events.digest` is the
  digest of those bytes, and its evidence register entry has
  `canonicalization: RFC8785`.
- The `kind` of the trusted signing keys file is
  `iltero_schemas.trust.TRUST_FILE_KIND`. The `kind` of a bundle's own
  description, `iltero_schemas.models.common.bundle.BUNDLE_KIND`, sits beside the
  descriptor's `KIND`.
- A compiled program's reason for a failure names the comparison that
  decided it: `assert: false; <path> <op> is false`, or, when a condition
  under `not` held, `assert: false; <path> <op> is true, but must be false`.
  A false `all` is decided by its first false part and a true `any` by its
  first true part. `VEC.IAC.RESOURCE.VEC.THING.TRUTH_REASON` and its evaluation cases cover it.
- Twenty-four starter assertions, among them
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
- A reference time names its source, `server` or `runner_clock`. A stage's reference time
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
  index, each stage's copy of each scanner check mapping it applied, what it read from each
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
  `scanners` names the scanner check mappings it applied and the scanner
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
  UTF-8 bytes as written, with no control character. Record vectors cover
  each rule.
- A plan stage with a `plan_incomplete` gap, whether the plan said it is
  incomplete or did not say it is complete, has evidence with gaps, with
  reason `plan_not_complete`. Its verdict still follows its evaluations. It
  is listed after an evaluator error's reason and before
  `upstream_state_unavailable`. A plan that cannot be applied leaves the
  evidence status as it is. The status lists every reason; every cause also
  stays in the coverage. Record vectors cover it and pin the order.
- The integrity checks: a record's values that a reader can recompute,
  including its `change.digest`, the pre-deploy stage's source digest and each
  approval of a change, must be what they recompute to. They also recompute
  the status each built-in check must have from the record's own change, and
  report an event a policy answered (`pass`, `fail`, `unknown` or
  `not_applicable`) that says otherwise; an event not evaluated, or that ended
  in error, decides nothing. A stage's required count is its assertion index's
  count, and, unless the stage was cut short, its required count and digest are
  those of its events' assertions. These describe the stage's own events and
  index: which assertions a stage was required to evaluate is shown only
  against the project's assertion files
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
- Hand-written policy sources and scanner check mappings. A scanner checks
  entry's `input_kind` says what the scanner read, and a record's scanner
  report lists its `input_kinds`, in the contract's words. Scanner check
  mappings, events and records name a scanner from one list: `checkov` and
  `trivy`. An event read from a scanner's results names the scanner checks
  entry whose checks decided it (`provenance.scanner_checks`).
- Named constants for values consumers write as plain strings. Each constant
  lives with the part of the contract it belongs to. `SCHEME_UNIT` is in
  `iltero_schemas.models.common.vocabulary`, `SCHEME_AWS_ARN` in
  `iltero_schemas.models.providers.aws`, and the CI systems an executor may
  name in `iltero_schemas.models.common.ci.CI_SYSTEMS`.
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
  follows its evaluations, and its evidence has gaps, with reason
  `upstream_state_unavailable`, so a `met` verdict on placeholders reads
  beside evidence with gaps; an evaluator error's, a state not read's or the
  plan's reason is listed before it. One order (`GAP_REASON_PRECEDENCE`)
  serves both a stage's reasons and a record's, which list every stage's. A record of a run Iltero Platform opened has none.
- The fixed order of statuses, worst first.
- The digest of an assertion set and the digest of a change, with vectors.
  The change digest (`change_digest`) is taken over the change type, the
  unit, the environment key and the checked content (its kind, digest,
  digest rule version and tool), so an
  approval of a change counts only for that content, in that unit and
  environment. A record's environment key is the name of its
  `subject.environment`, null for a change made outside any environment,
  and a record of a run Iltero
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
  `image_deploy`. `iltero_schemas.models.common.change_type` names each
  (`IAC_CHANGE_TYPE`, `IAC_CHANGE_ACTIVITY`, `IMAGE_RELEASE_TYPE`,
  `IMAGE_BUILD_ACTIVITY`, `IMAGE_DEPLOY_ACTIVITY`) and
  gives each activity's change type (`CHANGE_TYPE_OF`). A record's `change` is the body of its activity
  (`change.activity`). An `iac_change` body holds the change digest, the
  `plan`, and once they are known the `deployment`, the `identity` and the
  `drift_check`. The activity declares the type of run that records it, the
  stages a record passes through, which of them a project, an environment's
  policy or the tool may leave out, and the documents each stage must keep,
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
- The facts only Iltero Platform holds, as items an assertion reads: approvals
  and earlier evaluations. Exceptions are never part of an evaluation input:
  no assertion reads one, and an input that carries them is refused. An approval names the change it
  approves by its digest, or the run by Iltero's run id, and says how it was
  obtained and whether it was a self-approval the policy permitted. The
  pre-deploy input names its run (`run.id`), and the approval assertions
  accept either kind, each in its own branch. A stage whose input carries
  approvals lists the ones its evaluations read, whatever their source, each
  once and of the record's own change or run, and lists any only when its
  results read facts from Iltero Platform.
- The unknown marker: where a fact only Iltero Platform holds (approvals,
  evaluations, the verified source of a build) is missing, the evaluation input holds a marker,
  so a condition that reads it is `unknown`, never true or false. An
  evaluation whose input reads Iltero Platform facts records where they came
  from (`facts_source`: `server`, or `none`). An `iac_change` input at
  `runtime` reads no fact only Iltero Platform holds, so its event's
  `provenance.facts_source` is `null`, and an event with `server` or `none`
  there is refused.
- The trusted signing keys: the public keys that sign what Iltero Platform
  serves, assertion bundles and scanner check mappings, shipped in the
  package as `iltero_schemas/trust/signing-keys.json` (`kind: SigningKeys`)
  with their status (active, retired or revoked), and a reader,
  `iltero_schemas.trust.parse_signing_keys`, that refuses development keys
  and every broken rule. The shipped keys are
  `iltero_schemas.trust.SIGNING_KEYS`, each a `SigningKey`. The renamed
  names:

  | Before | Now |
  | --- | --- |
  | `BundleKey` | `SigningKey` |
  | `BUNDLE_KEYS` | `SIGNING_KEYS` |
  | `parse_bundle_keys` | `parse_signing_keys` |
  | `kind: BundleSigningKeys` | `kind: SigningKeys` |
  | `trust/bundle-keys.json` | `trust/signing-keys.json` |
  | `vectors/bundle_keys/` | `vectors/signing_keys/` |
  | test key ids `iltero-bundle-test`, `iltero-bundle-2026-09` | `iltero-signing-test`, a throwaway key no trust file holds |

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
- Signed scanner check mappings (`ScannerCheckMappingDescriptor` v1): the
  document Iltero Platform serves a scanner check mapping in, with the
  mapping as a JSON object (at most 8 MiB of canonical JSON), its `digest`,
  the `key_id` that signed it, `algorithm: ES256` and the `signature`, the
  raw `r` then `s` in base64url with no padding. The key signs a JSON Web
  Signature (JWS) header and a payload naming the mapping's digest under the
  scope `iltero-scanner-check-mappings`. ES256 (ECDSA, the Elliptic Curve
  Digital Signature Algorithm, on P-256 with SHA-256) and its low-S form are
  shared with assertion bundles (`iltero_schemas.signing`), and a verifier
  asks for the scope of the document it checks, so a bundle's signature is
  never accepted for a mapping. `check_scanner_check_mapping_descriptor`
  checks the key, the mapping and its id (in `ILT.SCANNER_CHECKS.`, not the
  starter), the digest and the signature's form, in that order, and returns
  an `UnverifiedScannerCheckMapping`: the tool verifies the signature before
  it reads any scanner result with the mapping. Its `descriptor_digest` is
  the value a record names for the served mapping: the SHA-256 of the
  canonical JSON of the descriptor as served, signature included. New
  vectors: `scanner_check_mapping_descriptors/` (the sample served mapping,
  signed once with a development key),
  `scanner_check_mapping_descriptors_invalid/` (10 refusals, each naming
  whether the model or the check refuses it in `refused_by`) and
  `signing_keys/development.json`, the trust file holding that one
  development key. `scripts/sign_descriptor_vectors.py` signs the sample
  again with a new throwaway development key, since a signature cannot be
  rebuilt from its input. The trusted signing keys verify both assertion
  bundles and served scanner check mappings.
  - `iltero_schemas.bundle.normalized_signature` now raises
    `SignatureError`, from `iltero_schemas.signing`, instead of
    `BundleError`. `descriptor` and the bundle check still raise
    `BundleError`.
  - `P256_ORDER` moved from `iltero_schemas.bundle.build` to
    `iltero_schemas.signing`.
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
  its verdict `incomplete` (unless a check failed) and gives its evidence
  gaps with reason `state_not_read`; an evaluator error's reason comes first. When the log
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
  file's digest. The raw image index, which the plan stage must keep
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
  | Document a stage must keep | `image_index` |
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
  then never `met`, and `undecided` when nothing else is wrong. It may otherwise only be not
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
  qualifying approval (`iltero_schemas.models.common.commit_review.CommitReview`).
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
  there (`iltero_schemas.models.common.git.GitRepository`). Context, evaluation and
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
  deployment, such as an image build, or `could_not_decide` when the record's
  integrity is not established.
- Files grouped by change type. Modules and conformance vectors that belong
  to one change type live under `iac/`, for changes made with an
  infrastructure-as-code (IaC) tool, or `image/`, for container image builds
  and deploys, such as `iltero_schemas.models.image.deploy` and
  `vectors/records/iac/`. Each document folder's `digests.json` and each
  conformance case name a document by its path from that folder
  (`image/local_run_build.json`).

  Code that every change type shares lives in a `common/` folder of its
  layer, beside `iac/` and `image/`, so a model is imported from
  `iltero_schemas.models.common.car` rather than `iltero_schemas.models.car`:

  | Layer | Before | Now |
  | --- | --- | --- |
  | Models | `iltero_schemas.models.<module>`, such as `car`, `event` and `assertion` | `iltero_schemas.models.common.<module>` |
  | Canonical form | `iltero_schemas.canonical.<module>` (`assertion_set`, `change`, `encoding`, `record`, `time`) | `iltero_schemas.canonical.common.<module>` |
  | Change types | `iltero_schemas.change_types.<module>` (`activity`, `bindings`, `evidence`, `owed_status`, `registry`) | `iltero_schemas.change_types.common.<module>` |
  | Resource kinds | `iltero_schemas.kinds.vocabulary` | `iltero_schemas.kinds.common.vocabulary` |
  | Tests | `tests/test_<module>.py` | `tests/common/test_<module>.py` |

  The package-level imports are unchanged: `iltero_schemas.canonical`,
  `iltero_schemas.change_types` and `iltero_schemas.kinds` export the same
  names as before. No document shape, vector or digest changed.
- Comparisons with `null`. An assertion checks whether a value is null with
  `equal: null`, or that it is set with `not_equal: null`. Any other
  comparison with `null` is refused ("only equal and not_equal compare with
  null"). A value that is absent, or an unknown marker, is still unknown.
  The conformance vector `VEC.IAC.RESOURCE.VEC.THING.OPS_NULL` and its evaluation cases show each
  outcome. Existing assertions compile to the same bytes as before.
- One spelling of no value. An assertion document or a scanner check
  mapping writes no value only as the word `null`. YAML also reads an empty
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
  runs in the pipeline, and a scanner check mapping says which of its
  checks decide which assertion. The plan stage of an infrastructure change
  reads each report it is given and turns the mapped results into one
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
  - A scanner check mapping holds one assertion mapping per assertion: the
    assertion it decides, by id, version and document digest, and its
    `scanner_checks`. Each scanner checks entry names a tool, a stage, the
    checks that decide together
    (`rule_ids`: any failure fails, all must pass), a version range that must
    have an upper bound, what the scanner read (`input_kind`: `plan` at the
    plan stage, `deployed_resources` at runtime), how a result finds its
    subject (`subject_match`: `exact_address`, or `plan_configures` for a
    resource that configures the subject, such as a bucket's public access
    block), and the attribute paths the checks read (`paths_read`). A
    mapping is a lookup table, not a requirement: a scanner with no report
    adds nothing, and a check mapped nowhere is kept as evidence only. Results a
    tool wrote about the configuration as written decide nothing: they are
    counted (`written_configuration_results`) and left out.
    `check_project_mapping` refuses a project's own mapping that takes an
    `ILT.` id or decides an assertion Iltero ships.
  - A run can require groups of scanners, one scanner of each group
    (`scanner_requirements`, as the record states them; a reader does not
    check them against any configuration). Each group is a
    `ScannerRequirement` whose `any_of` names its members, sorted, each once.
    The groups are sorted, and a scanner is a member of one group at most
    (`Scanners.required_members` is every member). A group of one requires
    that scanner. Every member that gave no report gives every subject its
    mapped checks cover an evaluation that is `not_evaluated` with
    `scanner_not_run`, naming no version and no input, even when another
    member met the group. A member gives a gap when it gave no report, when
    its report came from a version its scanner checks entry does not allow
    (`scanner_version_not_allowed`), or when its report holds no result of the
    entry's checks or no result at all (`SCANNER_REQUIREMENT_GAP_REASONS`). Only
    members whose checks are mapped to the assertion count. A group where at
    least one member that counts evaluated the assertion and subject, and each
    one that did gave a gap, is a gap no pass fills: it cancels every pass and
    not applicable verdict (`CANCELLED_BY_AN_UNMET_SCANNER_REQUIREMENT`), and a
    failure, an unknown result or another evaluator's error still stands. A
    group one of whose members read the input cancels nothing, and neither does
    a scanner no group names. The members need not check the same things, so a
    group is only as strong as its weakest member. `combined_verdict`,
    `stage_verdicts` and the stage counts take the groups
    (`stage_scanner_requirements`).
  - `scanner_requirement_problems` (`iltero_schemas.models.iac.scanner_requirements`)
    lists every group that can never be met, given the run's assertions and
    the scanner check mappings it applies, counting only the mapping entries
    of the run's assertions: a group none of whose members is mapped to any
    assertion of the run, and, for each assertion only scanners decide
    (`assert: null`) at each stage, a group whose every member mapped to it
    names resources only when they fail, such as Trivy alone, which never
    gives a pass. It is written for a server to apply when it saves an
    environment's policy and when it opens a run, and for a tool to apply
    when it reads a project's settings. A record is not refused for such a
    group.
  - Names that changed for scanner requirements:

    | Before | Now |
    | --- | --- |
    | `Scanners.required_scanners`, a list of scanner names | `Scanners.scanner_requirements`, a list of `ScannerRequirement` groups |
    | `stage_required_scanners` | `stage_scanner_requirements` |
    | `REQUIRED_SCANNER_GAP_REASONS` | `SCANNER_REQUIREMENT_GAP_REASONS` |
    | `CANCELLED_BY_A_REQUIRED_SCANNERS_GAP` | `CANCELLED_BY_AN_UNMET_SCANNER_REQUIREMENT` |
    | The `required_scanners` keyword of `combined_verdict`, `stage_verdicts` and the stage counts | `scanner_requirements` |
    | The `records_integrity_failed/iac/` cases `required_scanners_gap_left_out_of_the_coverage` and `required_scanners_gap_miscounted` | `scanner_requirement_gap_left_out_of_the_coverage` and `scanner_requirement_gap_miscounted` |

    Every record vector's `scanners` has `scanner_requirements`, each former
    required scanner a group of one. The `records_valid/iac/` case
    `iac_record_whose_group_of_two_scanners_is_met_by_the_one_that_read_the_plan`
    names one group of Checkov and Trivy: Checkov read the plan, so its passes
    stand and the evidence is whole. New `records_invalid/iac/` cases refuse a
    scanner named in two groups, groups out of order, and a group whose
    members are out of order.
  - Each stage lists, for each reason an evaluation was not evaluated or
    ended in error, a count gap of the combined verdicts that reason left
    without a decision (`no_decision_reason_counts`). The integrity checks recompute
    the counts from the events.
  - An evaluation that could not decide and that the subject's combined
    verdict does not count is a gap too: beside a verdict another evaluator
    decided, beside a verdict without a decision that another evaluator
    reached, or beside
    one with another status. The verdict stands, and the stage
    lists one `evaluator_did_not_decide` gap for each evaluator and reason,
    with the number of such evaluations (`evaluator_did_not_decide_counts`),
    which the integrity checks recompute from the events. A gap for an
    evaluator error gives the stage's evidence gaps with reason
    `required_policy_evaluation_failed`; a gap for a check not evaluated is
    listed only.
  - Seven starter assertions about AWS resources join the package: no SSH or
    RDP open to the internet in a security group, S3 default encryption with
    a KMS key (Key Management Service), unknown at plan when the plan has no
    encryption configuration for the bucket (checked again after the
    deployment, a bucket left on Amazon S3 managed keys fails), and five that
    only scanners decide, about IAM (Identity and Access Management) policies, CloudTrail trails and
    AWS Config recorders. The shipped mapping `ILT.SCANNER_CHECKS.STARTER`
    maps nine starters to Checkov and Trivy checks.
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
    member of a scanner requirement that gave no report). A report that holds results the
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
  - A record's `scanners` names the scanner check mappings the stage applied
    (`scanner_check_mappings`), the groups of scanners the run requires
    (`scanner_requirements`), and each report. A stage applies the mapping
    Iltero ships, with at most one mapping from the project's own file listed
    first, or only the mapping Iltero Platform served the run
    (`origin: served`). A served mapping names the digest of the signed
    descriptor it was served in (`descriptor_digest`) and the key that signed
    it (`key_id`); no other mapping names them, and no mapping but the shipped
    one has the id `ILT.SCANNER_CHECKS.STARTER`. Iltero Platform compares the
    mapping's digest, descriptor digest and key with the values it pinned
    when it opened the run. A reader with the kept files checks only that
    each verdict's entry is in the stage's copy of the served mapping. Every
    scanner check mapping entry in the vectors of runs the tool opened has
    `descriptor_digest: null` and `key_id: null`.
    `vectors/scanner_check_mappings/iac/served_catalog.json`
    (`ILT.SCANNER_CHECKS.CATALOG`) is a sample of a served mapping. The
    project's mapping decides only the project's own assertions and the
    shipped mapping only Iltero's starter assertions, so each scanner
    verdict's `provenance.scanner_checks.digest` matches exactly one scanner
    checks entry across the stage's mappings, and a reader finds the entry
    that decided it from that digest. The evidence register lists the copy
    of each mapping, and the copy of a project's mapping names the file it
    was read from. For each report the
    record names who supplied it, what it read, its results,
    unreadable results, results about the configuration and the files the
    tool could not parse. `scanner_evidence_problems`, which a reader calls
    through `kept_file_problems` with the files the stage kept (`KeptFiles`),
    rebuilds the observations from the kept report and the one plan the
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
    Until the post-verify stage reports, the record's evidence has gaps, with
    reason `checks_postponed_until_after_the_deployment` (`OPEN_CHECKS_REASON`)
    and a detail that counts the open checks; the reason names no stage. Only
    a record holds this reason. In `GAP_REASON_PRECEDENCE` it comes after
    `required_checks_not_evaluated` and before `plan_not_complete`. `postponed_check_problems` checks the list against
    the kept plan.
  - A stage none of whose evaluations ran over an input that carries approvals
    or a commit review keeps the marker `not_read_by_the_stage` in their
    place; one whose checks read such an input keeps the list, the review or
    the `server_facts_unavailable` marker as before. An evaluation input is at most 16 MiB of canonical JSON, and
    the input's `assurance` part has a shape: an assertion's current and
    previous results about one subject, and the deployments in between.
  - A project's own exceptions file (`LocalExceptions` v1) holds 0 to 256
    exceptions, so a project with none keeps a valid file with
    `exceptions: []`. It names, for each exception, an assertion, an environment, resources and a period, and who
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
    `scanner_evidence_problems`, given the copy in `KeptFiles.local_exceptions`,
    works out again which exception covers each suppressed result and lists
    a record that names another, or leaves one out.
    `vectors/local_exceptions_invalid/cases.json` changes the kept exceptions
    file of `local_run_suppressed_with_exception` into files `LocalExceptions`
    refuses: an exception that covers a built-in assertion, lasts more than
    365 days, ends before it starts, or names a resource by its unit rather
    than its address.
  - The exceptions Iltero Platform serves one stage of a run it opened
    (`ServedExceptions` v1, `metadata.run_id` and `metadata.stage`, 0 to 256
    exceptions, at most 16 MiB of canonical JSON,
    `MAX_SERVED_EXCEPTIONS_BYTES`). A served exception names the assertion document it was
    approved for by `id`, `version` and `digest` (`scope.kind: resources`),
    who asked for it (`requested_by`), who approved it and when
    (`approved_by`, `approved_at`), each by the pseudonym Iltero issued
    their Iltero user for the organization (`Pseudonym`: `provider:
    iltero_pseudonym` and a UUID `id`), and
    whether the requester and the approver are each the run's starter, the
    account of the continuous integration system that triggered the run, not
    necessarily the author of the change (`requester_and_run_starter`,
    `approver_and_run_starter`, Iltero Platform's finding: `same_user` when
    it links that account to this Iltero user, `different_users` only when it
    linked both to Iltero users and they differ, which shows two Iltero users
    and not two people, or `could_not_tell`, which never means they differ).
    The fields do not cover who triggered a later attempt; the record's
    continuous integration facts show that. A requester or an approver found
    to be the run's starter is recorded, not refused, because the exception
    was approved before the run opened; a reader judges it, so separation of
    duties rests on Iltero Platform and on a reader that checks these fields.
    In one document, one Iltero user, as requester or approver, has one
    finding about the run's starter ("a run has one starter, so one Iltero
    user is found to be them, or not, in every exception"). At most one
    Iltero user is found to be the run's starter, since Iltero Platform links
    a CI account to at most one Iltero user of the organization ("a run has
    one starter, and the server links its account to one Iltero user at
    most, so no two are found to be them"). Iltero
    Platform reads the exceptions in force when it opens a run and serves
    that one document to every plan stage of the run, re-runs of the run's
    plan stage included; an exception approved after the run opened applies
    from a new run of the pipeline. Each plan stage holds an exception to its
    own reference time. It
    is approved no later than it expires, and the requester and the approver
    have different pseudonyms: two Iltero users, not necessarily two people.
    A pseudonym is the same for one Iltero user in every exception of the
    organization, and unrelated to the same person's pseudonym in another
    organization. Erasing
    which user it stands for removes Iltero's link only: the pseudonym stays
    the same across the organization's exceptions, the record names the run's own CI facts, and
    the free-text `reason` can name a person, so the person may still be
    identified. Every exception, a project's or a served one,
    follows the same rules (`iltero_schemas.models.common.exception_terms`),
    the 365-day limit included. A project's exception is `LocalException`.
    Vectors: `served_exceptions/plan.json`,
    `served_exceptions/plan_covering_every_failure.json`,
    `served_exceptions/plan_without_exceptions.json`,
    `served_exceptions/deployed_run_plan_without_exceptions.json` and
    `served_exceptions_invalid/cases.json`.
  - The `plan` stage of an `iac_change` run Iltero Platform opened applies
    the exceptions served it
    (`Activity.stage_that_applies_served_exceptions`; an image build or
    deploy applies none). The stage names them in `served_exceptions`
    (`ServedExceptionsUsed`): the `digest` of the document's canonical JSON,
    the `copy_path` of its copy in the evidence register (canonical, with
    no `source` and no redaction policy), and `excepted_failures`, each
    failed result an exception covers (`ExceptedFailure`: `assertion`,
    `resource`, `engine` and `exception_id`), at most 100,000
    (`MAX_EXCEPTED_FAILURES`, one per failed event of the stage), sorted
    and each once, in the order `sorted_excepted_failures` gives, empty
    when none is. An excepted failure names its resource by its address,
    scoped by its unit, as an exception does. The field is set at that stage even when nothing was
    served, takes the stage's time from Iltero Platform, and is `null` at
    every other stage and in a run the tool opened. Each excepted failure is
    one of the stage's `fail` events. The result stays `fail`.
    `served_exception_for` gives the exception that covers a failed result:
    one in force for the assertion's id, the resource and the environment,
    approved for the result's exact assertion document (`id`, `version` and
    `digest`), and approved no later than the stage's reference time; or the
    reason none does, the reasons of any exception first, then
    `approved_for_another_document_of_the_assertion` and
    `approved_after_the_reference_time`. `served_exception_problems`, which
    every reader calls through `kept_file_problems` with the copy in
    `KeptFiles.served_exceptions`, checks the copy's digest, that it is
    canonical and valid, that it was served to the record's run, stage and
    environment, and that `excepted_failures` is exactly what
    `served_exception_for` gives. That shows the record agrees with the copy
    it kept, not that Iltero Platform served it or that Iltero approved the
    exceptions in it: only Iltero Platform can check that. The copy names
    the requester and the approver of each exception by their pseudonyms,
    with its `reason`, so a record keeps those among its files.
    `served_exceptions_kept/cases.json` checks copies a reader is given
    against a record. Every record vector has
    `served_exceptions: null` at each stage, and a `set` pointer in a case
    file may end in `-` to append to a list.
  - A stage counts the failed checks served exceptions cover in full
    (`Coverage.failed_checks_excepted`, recomputed by
    `verdicts.excepted_failure_count`): every `fail` event of the check is
    one of the stage's `excepted_failures`, and every other event of it is
    `pass` or `not_applicable`. The count is at most the stage's failed
    checks ("a stage counts no more failed checks as excepted than it has
    failed checks"), 0 at a stage that applies no served exceptions ("a stage that applies no
    served exceptions counts no failure as excepted"), and summed in the
    record's coverage. A stage whose every failed check is covered in full,
    with nothing else open, is `not_met` with the reason
    `every_failure_excepted`. The checks did not pass: their events stay
    `fail`. A stage that also left a check undecided or not made shows that
    instead. A failure with no resource address, a built-in's failure, a
    check another evaluator could not decide and a postponed check that
    fails at post-verify are never excepted. A project's exception never
    gives this reason. The reason says nothing about whether an exception
    was justified, or about compliance; a tool that lets a gate proceed on it
    applies its own policy, not a pass.
  - `kept_file_problems(car, files)`
    (`iltero_schemas.models.iac.kept_file_problems`) makes, in one call, every
    check a reader makes of an `iac_change` record: `integrity_problems`,
    `scanner_evidence_problems`, `served_exception_problems` and
    `postponed_check_problems`. Every reader of such a record calls it, with
    or without `SKIP_INTEGRITY_CHECKS`, and does not trust the record while
    it returns any problem. An empty list means every check a reader can make
    holds; what only Iltero Platform can check stays unchecked.
  - These checks show that each verdict follows from what the stage kept.
    They do not show that the scanner ran, that the report is what it wrote,
    that it read the plan the record names, or that its version is genuine.
    In a self-attested record, all of it is the writer's claim, and so is
    `scanner_requirements`: a record that leaves a group out, with its
    evaluations and gaps, still holds together, so a reader compares the
    groups with the ones its own policy requires.
  - Each scanner report, and the observations read from it, says who ran
    the scanner (`ran_by`): `pipeline`, which gave the stage the report, or
    `iltero_cli`, the Iltero CLI, which ran the scanner itself on the runner.
    An evaluation from the results of a scanner the Iltero CLI ran names the
    `digest` of what ran and the `platform` it ran on, in the OPA evaluator's
    words (`linux-x86_64`), and, for a scanner installed as Python packages
    (Checkov), the `python_version` as an interpreter tag (`cp312`, with `t`
    for a free-threaded build). These replace `supplied_by` and the evaluator's
    `reason: not_executed_by_cli`. A record of a run Iltero Platform opened
    keeps only scanner reports the Iltero CLI ran. A reader refuses kept
    observations whose `ran_by` differs from their report entry's. `ran_by`,
    the digest and the platform are the record's own claim: copying the pinned
    values into a record is all it takes, so, like the OPA evaluator's pinned
    binary, they are at best claimed by the record, never verified. In a run
    the tool opened, `iltero_cli` claims no more than `pipeline`. Every record
    and observations vector has `ran_by: pipeline`, and every scanner
    evaluator `platform: null` and `python_version: null`. The new
    `records_invalid/iac/` case
    `iac_record_of_a_run_the_server_opened_keeping_a_scanner_report_the_pipeline_ran`
    refuses a record of a run Iltero Platform opened that keeps a report the
    pipeline ran.
  - A record of a run Iltero Platform opened evaluates only assertions from
    Iltero Platform's bundle: every event's `assertion_source` is
    `server_bundle`, so it evaluates no hand-written Rego, no assertion of
    the project's own and no copy of this package's starter assertions. Each
    of its stages that reads scanner reports applies only the scanner check
    mapping Iltero Platform served, and a scanner verdict on an assertion
    from the bundle comes from that mapping. A record of a run the tool
    opened applies no served mapping. A record of a run Iltero Platform
    opened also postpones no check until after the deployment (no stage's
    `values_known_after_deployment` is `postpone`): its plan stage blocks on
    a value the plan knows only after the deployment
    (`iltero_schemas.models.common.provenance.check_provenance`). Every case
    of a run Iltero Platform opened in `records_valid/`, `records_invalid/`
    and `records_integrity_failed/` names Iltero Platform's bundle on every
    evaluation and stage, with `server_bundle` sources, and each stage that
    reads scanner reports applies that served mapping. New
    `records_invalid/iac/` cases refuse such a record that evaluates this
    package's copy of a starter assertion or one of the project's own, or
    applies the shipped mapping, alone or beside a project's, and a record of
    a run the tool opened that applies the served mapping.
  - Names and shapes that changed:

    | Before | Now |
    | --- | --- |
    | A binding entry with its own `id` and `version`, one `rule_id` and a `status_map` | An assertion mapping per assertion, with `scanner_checks` and `rule_ids`; a tool's words are read only as `TOOL_DECISIONS` lists them |
    | An event's `evaluator_binding` with `id`, `version` and `digest` | `scanner_checks` with the scanner checks entry's `digest` only |
    | `binding_count` | `assertions_mapped` |
    | A report's `parsing_errors` | `tool_parsing_errors`, `null` when the tool does not say |
    | A report's `input_kinds` in the tool's words (`terraform_plan`) | The contract's words (`plan`) |
    | `results_accepted`, `results_scanner_version_not_allowed`, `results_without_binding` | Removed: every verdict is an event |
    | The `accepted_by_binding` gap | Removed; the `checked_after_deployment` gap is new |

  - Vectors are in `vectors/scanner_check_mappings/iac/`,
    `vectors/scanner_check_mappings_invalid/iac/`,
    `vectors/scanner_check_mappings_project_invalid/iac/`,
    `vectors/scanner_reports/iac/`,
    `vectors/scanner_observations/iac/`, `vectors/scanner_evidence/iac/`,
    `vectors/records/iac/local_run_scanned.json`,
    `vectors/records/iac/local_run_scanned_project.json`,
    `vectors/records/iac/local_run_scanner_required.json`,
    `vectors/records/iac/local_run_scanned_project_required.json` (a
    version that the scanner checks entry of a group of one does not allow
    cancels a pass), `vectors/records/iac/local_run_scanned_redacted_result.json` (a
    redacted Trivy result leaves the subjects Trivy is silent about
    `unknown`), `vectors/records/iac/local_run_suppressed_with_exception.json`
    (a suppressed result names the exception the kept exceptions file gives
    it), each with its kept files in its own folder of
    `vectors/scanner_evidence/iac/`, which may hold a `cases.json`,
    `vectors/records/iac/local_run_postponed.json`,
    `vectors/records/iac/local_run_postponed_settled.json` (with the project
    assertion `ACME.IAC.RESOURCE.TERRAFORM.DATA.OUTPUT_SET` it evaluates) and
    the evaluation cases.
- The scanner check mapping, a plain name for the document that says which
  scanner checks decide which assertion. It was called the evaluator binding
  set. Each assertion it maps is an assertion mapping, and each tool's checks
  for that assertion at one stage are a scanner checks entry. The document
  keeps its structure and its rules. Its fields, the code and vectors around
  it, and the refusal messages that name it use the new words:

  | Before | Now |
  | --- | --- |
  | `kind: EvaluatorBindingSet` | `kind: ScannerCheckMapping` |
  | `spec.bindings` (`AssertionBinding`) | `spec.assertion_mappings` (`AssertionMapping`) |
  | A binding's `evaluators` (`ScannerBinding`) | An assertion mapping's `scanner_checks` (`ScannerChecks`) |
  | `BindingSetSpec`, `SetMetadata` | `ScannerCheckMappingSpec`, `MappingMetadata` |
  | A record's `scanners.evaluator_binding_sets` (`EvaluatorBindingSetUsed`) | `scanners.scanner_check_mappings` (`ScannerCheckMappingUsed`) |
  | `assertions_bound` | `assertions_mapped` |
  | An event's `provenance.evaluator_binding` (`EvaluatorBindingRef`) | `provenance.scanner_checks` (`ScannerChecksRef`) |
  | The digest of `{"assertion": ..., "evaluator": ...}` | The digest of `{"assertion": ..., "scanner_checks": ...}`, from `AssertionMapping.scanner_checks_digest` |
  | `ILT.BINDINGS.STARTER`, `ACME.BINDINGS.PAYMENTS` | `ILT.SCANNER_CHECKS.STARTER`, `ACME.SCANNER_CHECKS.PAYMENTS` |
  | `iltero_schemas.bindings` | `iltero_schemas.scanner_check_mappings` |
  | `BINDINGS`, `STARTER_SET`, `STARTER_SET_ID` | `SCANNER_CHECK_MAPPINGS`, `STARTER_MAPPING`, `STARTER_MAPPING_ID` |
  | `SHIPPED_SET`, `SHIPPED_SET_DIGEST` | `SHIPPED_MAPPING`, `SHIPPED_MAPPING_DIGEST` |
  | `SHIPPED_SET_EVALUATORS`, `SHIPPED_SET_ASSERTIONS` | `SHIPPED_SCANNER_CHECKS`, `SHIPPED_MAPPING_ASSERTIONS` |
  | `load_binding_set`, `starter_set` | `load_scanner_check_mapping`, `starter_mapping` |
  | `check_project_set` | `check_project_mapping` |
  | `MAX_BINDINGS`, `MAX_EVALUATORS`, `MAX_RULES_PER_EVALUATOR` | `MAX_ASSERTION_MAPPINGS`, `MAX_SCANNER_CHECKS`, `MAX_RULE_IDS` |
  | The kept copies `bindings.json`, `shipped-bindings.json`, `project-bindings.json` and `bindings.yaml` in the vectors | `scanner-check-mapping.json`, `shipped-scanner-check-mapping.json`, `project-scanner-check-mapping.json` and `scanner-check-mapping.yaml` |

  The code that serves only changes made with an IaC tool moved into `iac/`
  folders, like the rest of the contract:

  | Before | Now |
  | --- | --- |
  | `iltero_schemas.models.binding` | `iltero_schemas.models.iac.scanner_check_mapping` |
  | `iltero_schemas.models.scanner_results` | `iltero_schemas.models.iac.scanner_results` |
  | `iltero_schemas.models.kept_files` | `iltero_schemas.models.iac.kept_files` |
  | The shipped mapping and its loader, in `iltero_schemas/bindings/` | `iltero_schemas/scanner_check_mappings/iac/`, still imported from `iltero_schemas.scanner_check_mappings` |
  | `vectors/binding_sets/` | `vectors/scanner_check_mappings/iac/` |
  | `vectors/binding_sets_invalid/cases.json` | `vectors/scanner_check_mappings_invalid/iac/cases.json` |
  | `vectors/binding_sets_project_invalid/cases.json` | `vectors/scanner_check_mappings_project_invalid/iac/cases.json` |

  Every digest of a document that cites a mapping, or one of its scanner
  checks entries, changed with the names.
- A plain verdict that never hides a failed check, and an evidence status
  that lists every reason the evidence has gaps. A verdict says what the
  stage's required checks came to. A required check is one assertion the
  stage was required to evaluate about one subject in scope; an assertion
  that ran and found no subject in scope counts as evaluated. The verdict
  words describe those checks only: they never say that a framework control
  is met or that anything is compliant. Before, the verdict and the status
  each used the word "incomplete" for a different idea; now the verdict words
  are about checks and the evidence status words are about evidence. A
  verdict (`iltero_schemas.models.common.coverage.Verdict`) is
  `{value, reason, computed_from, stage}`:

  | `value` | Meaning |
  | --- | --- |
  | `met` | Every required check passed, did not apply, or was postponed until after the deployment. A stage none of whose required assertions found a subject, or that was required to evaluate none, is `met`, and its evidence says so. A check postponed until after the deployment counts as decided later. |
  | `not_met` | A required check failed. `reason` is `every_failure_excepted` when served exceptions cover every failed check in full and nothing else is open; the checks still did not pass. |
  | `undecided` | A required check could not be decided: it is `unknown`, and not a check postponed until after the deployment. |
  | `incomplete` | The stage could not make every required check. `reason` says why: `not_evaluated` (a required assertion has no evaluation, a required check was not evaluated, the list of evaluations was cut short, or the state after the apply was not read) or `evaluator_failed` (an evaluator ended in an error). |

  `reason` is present exactly when the value is `incomplete`, or `not_met`
  with every failure excepted, or the record is refused with "a verdict
  names its reason exactly when it is incomplete, or not_met with every
  failure excepted". A record holds no exit code: the Iltero CLI turns a verdict
  into its own process exit code.

  A stage's verdict is `not_met` whenever a required check failed that no
  served exception covers in full. Otherwise it is `incomplete` (with
  `not_evaluated` before `evaluator_failed`), then `undecided`, then
  `not_met` with `every_failure_excepted`, and otherwise `met`
  (`VERDICT_RANKING`). A record's verdict is the stage verdict that comes
  first in the same ranking,
  from the earliest such stage on a tie, and names that stage
  (`computed_from: stage_precedence`). Before, a check that was not made
  outranked a failure, so a stage with five failures and one missing check
  read as a gap. A failure now always shows in the verdict, and a missing
  check always shows in the evidence status.

  The evidence status
  (`iltero_schemas.models.common.evidence_status.EvidenceStatus`) is
  `{value, reasons}`. It `has_gaps` exactly when `reasons` lists at least one
  `{reason, stage, detail}`, sorted by `GAP_REASON_PRECEDENCE` and then by
  stage, each reason once per stage. A stage's own reasons name no stage; a
  record's name the stage each holds for, except
  `checks_postponed_until_after_the_deployment`, which holds for the record.
  The reasons, in order: `required_policy_evaluation_failed`,
  `state_not_read`, `expected_stage_not_reported` (new, a record only: an
  expected stage did not report though a later one did),
  `required_checks_not_evaluated` (new: a required check was not made,
  whatever the verdict), `checks_postponed_until_after_the_deployment`,
  `plan_not_complete`, `upstream_state_unavailable`,
  `plan_resources_excluded_for_their_identity` (new: plan resources were left out
  of scope because their identity was redacted or cannot be named; it does
  not change the verdict), `no_resource_in_scope_for_any_check` (new: no
  required assertion had a subject in scope; one assertion that does not
  apply to the plan, beside others that do, is not a gap) and
  `no_assertion_required` (new: the stage was required to evaluate no
  assertion). The refusals are "the evidence has gaps exactly when the
  status lists a reason", "the reasons are in the order of
  GAP_REASON_PRECEDENCE" and "each reason is listed once for each stage it
  holds for". `stages.record_outcome(car)` gives a record's coverage,
  verdict and evidence status, and
  `record_coverage.record_evidence_status` adds the two reasons only a
  record holds.

  The integrity checks also recompute, from each stage's events, its
  `assertions_evaluated` (required assertions whose combined verdict reached
  a result, one that found no subject in scope included), its
  `subjects_evaluated` (distinct subjects a required assertion reached a
  result about) and its `subjects_per_assertion` (the
  distinct subjects each required assertion was evaluated about, 0 when it
  found none); the assertions a post-verify stage evaluates to settle
  postponed checks are not among a stage's required assertions. A count
  that differs is refused with "does not count the assertions and subjects
  the stage's evaluations reached a result for, or the subjects each
  required assertion was evaluated about" (`stage_counts.evaluated_counts`).

  "Undecided" now names only a verdict, the stage's or the record's. A
  combined verdict that is `not_evaluated` or `error` is a verdict without a
  decision. The renamed fields, values, names and messages:

  | Before | Now |
  | --- | --- |
  | A verdict's `value`: `pass`, `fail`, `indeterminate` | `met`, `not_met`, `undecided`, `incomplete` |
  | A verdict's `exit_code` | Removed; an `incomplete` verdict names its `reason` |
  | `VERDICT_PRECEDENCE` (exit codes), `VERDICT_WORDS` | `VERDICT_RANKING` |
  | `assurance_status` (`AssuranceStatus`), on a stage and on a record | `evidence_status` (`EvidenceStatus`) |
  | An assurance status's `complete`, `incomplete` | An evidence status's `whole`, `has_gaps` |
  | An assurance status's one `reason` and `detail` | `reasons`, every reason with its `stage` and `detail`; `EvidenceStatus.leading_reason` gives the first |
  | `AssuranceStatus` and the reason constants in `iltero_schemas.models.common.coverage` | `EvidenceStatus`, `GapReason` and the reason constants in `iltero_schemas.models.common.evidence_status` |
  | `INCOMPLETE_REASON_PRECEDENCE` | `GAP_REASON_PRECEDENCE`, with five new reasons |
  | `INCOMPLETE_REASON` | `EVALUATOR_ERROR_REASON` (`required_policy_evaluation_failed`) |
  | `iltero_schemas.models.iac.postponed_checks.open_checks_status` | Removed; `record_coverage.record_evidence_status` lists the open postponed checks |
  | `coverage.assertions_expected` (`AssertionsExpected`) | `coverage.assertions_required` (`AssertionsRequired`) |
  | A record's `complete` | `all_expected_stages_reported` |
  | "a record is complete exactly when every expected stage has reported" | "all_expected_stages_reported is true exactly when every expected stage has reported" |
  | `UNDECIDED_STATUSES`, `undecided_reason_counts`, `UNDECIDED_REASON_GAP_KINDS` | `NO_DECISION_STATUSES`, `no_decision_reason_counts`, `NO_DECISION_REASON_GAP_KINDS` |
  | "… the verdicts of the stage it left undecided" | "does not count, for each reason, the verdicts of the stage that the reason left without a decision" |
  | "… no undecided verdict of the stage counts" | "… the evaluations that could not decide where the stage's verdict about the same assertion and subject reached a decision or decided nothing for another reason" |
  | `iltero_schemas.change_types.owed_status` (`owed_status_problems`) | `iltero_schemas.change_types.common.expected_status` (`expected_status_problems`) |

  The record vectors' verdicts and statuses are recomputed, and every digest
  that cites a record changed with them.
- A verification report says more about each result, gives one result per
  property for a record, and judges where each stage took its time and
  which OPA binary it names. Every result now has a `detail`: a plain
  sentence about what the verifier found, 1 to 1024 characters
  (`RESULT_DETAIL_MAX_LENGTH`), or `null` when there is nothing to add. A
  detail never changes what a state means or makes it stronger, and a
  reader must not parse it. Two states have plainer names:

  | Before | Now |
  | --- | --- |
  | `client_asserted` | `claimed_by_record` |
  | `not_determined` | `could_not_decide` |
  | `NOT_DETERMINED` | `COULD_NOT_DECIDE` |
  | "when a record's integrity is not established, every other property is not_determined with the reason integrity_failed" | "… every other property is could_not_decide with the reason integrity_failed" |

  The report has two new properties:

  | Property | What `verified` would mean | Results |
  | --- | --- | --- |
  | `reference_time` | Every stage took its reference time, the time every expiry and ordering comparison uses, from a source a verifier can trust. | `not_performed` with `runner_clock` when any stage used the runner's own clock, since no trusted time source was used; `claimed_by_record` with `server` when every stage took Iltero Platform's time, since no signature binds that time to the record. |
  | `evaluator_binary` | Every evaluation ran on the binary of the Open Policy Agent (OPA) release this contract pins, for its platform. | `claimed_by_record` with `pinned_binary_named`, `failed` with `other_binary_named` (the first problem in the `detail`), or `not_assessed` with `no_opa_evaluation`. |

  Approvals, exceptions and the commit review now tell apart a run the tool
  opened from a fact Iltero Platform did not supply:

  | Case | Before | Now |
  | --- | --- | --- |
  | The tool opened the run | `not_performed`, `server_facts_unavailable` | `not_performed`, `run_opened_locally` |
  | Iltero Platform opened the run, a check needed an approval or the commit review, and the stage kept the unknown marker | `not_performed`, `server_facts_unavailable` | `could_not_decide`, `server_facts_unavailable` (never an `exceptions` result) |
  | None of the stage's results read an approval or the commit review | Not given | `not_assessed`, `not_read_by_the_stage` |

  The `exceptions` property now means that every exception relied on was
  approved and in force at the reference time of the stage that relied on
  it, rather than at the time of deployment. It is `claimed_by_record` with
  `project_exception_relied_on` when an event names an exception from the
  project's own exceptions file, and with
  `project_exceptions_file_not_relied_on` when a stage applied such a file
  and no event relied on one.

  For approvals, exceptions and the commit review, a verifier takes the
  first result that holds, in the order
  `iltero_schemas.models.common.verification.PRE_DEPLOY_RESULT_ORDER`
  (`first_that_holds`): `kept_exceptions_do_not_hold`,
  `served_exception_approved_by_run_starter`, `served_exception_relied_on`,
  `project_exception_relied_on`, `served_exceptions_not_relied_on`,
  `project_exceptions_file_not_relied_on`, `not_in_activity`,
  `pre_deploy_out_of_scope`, `run_opened_locally`, `pre_deploy_pending`;
  when none holds, the stage's own result. The exception results come
  first, so a pre-deploy stage that is not in the activity, out of scope
  or still pending does not hide an exception the record relied on. So one
  record gives one report. The new
  `reports_expected/` vectors name a record, a property and the result
  every verifier must give it, and three new accepted-record cases cover a
  run on Iltero Platform's time, a pre-deploy stage that read no fact
  from Iltero Platform, and a record relying on a project exception whose
  pre-deploy stage is out of scope. The report vectors carry the new
  results. Two more cases give `bundle_provenance`: `not_performed` with
  `local_assertions` for a run the tool opened, and `claimed_by_record`
  with `server_bundle_named` for a run Iltero Platform opened. Each sample
  report's `bundle_provenance` is checked against the record it names:
  `reports/iac/verification_report_commit_not_reviewed.json`, whose record
  is of a run Iltero Platform opened that names its bundle at every stage,
  gives `claimed_by_record` with `server_bundle_named`.
- A reference time states only its value and its source; the verification
  report judges how far it can be trusted. The record and the evaluation
  input change in place:

  | Before | Now |
  | --- | --- |
  | `source`: `server`, `timestamp_authority`, `rekor` or `runner_clock` | `source`: `server` or `runner_clock`; any other is refused with "Input should be 'server' or 'runner_clock'" |
  | `trust`: `attested`, `corroborated` or `asserted` | Removed; refused with "Extra inputs are not permitted" |
  | `time_window` (`TimeWindow`: `not_before`, `not_after`, `nonce_digest`) | Removed |
  | The event status reason `reference_time_untrusted` | Removed, since nothing could give it |

  A verified build attestation's `timestamp_source` (`transparency_log` or
  `timestamp_authority`) is a different fact and is unchanged. Every record,
  context and evaluation vector drops `trust` and `time_window`. The
  invalid-record cases about a runner's clock that claimed more than
  `asserted` and about time windows are removed, and two cases are added: a
  reference time that names a timestamp authority, and one that says how far
  it is trusted.
- A verifier can check that each evaluation names the pinned OPA release's
  binary for its platform.
  `iltero_schemas.models.common.pinned_evaluator.pinned_evaluator_problems(events)`
  lists, as `(where, what)` pairs, each OPA evaluator whose version is not
  the pinned release, whose platform has no pinned binary, or whose digest
  is not the pinned binary's for its platform, and `evaluator_binary_result`
  turns them into the report's `evaluator_binary` result. A scanner's
  evaluation, and one no evaluator ran, is not compared. The check compares
  what the record states with this contract release's pin; it cannot show
  which binary ran. Reading a record does not run it. Six record vectors
  name placeholder OPA digests, and their `evaluator_binary` is `failed`;
  the others name the pinned binaries.
- A stage counts subjects only for the assertions it was required to
  evaluate, so a post-verify stage counts none for the checks it settles. The
  refusal reads "the `<stage>` stage counts subjects only for the assertions it
  was required to evaluate", where it read "… only for assertions it has
  events for".
- A Checkov report of a plan that changes nothing is read. When no
  framework has a result and no file failed to parse, Checkov writes one
  summary object with no framework: exactly `passed`, `failed`, `skipped`,
  `parsing_errors` and `resource_count`, each the count 0, and
  `checkov_version`. Checkov 3.3.8 writes it for an empty plan, `{}`, `[]`,
  a file that is not JSON, an unknown check id, and a `--check` or
  `--skip-check` filter that matches nothing on a plan with resources. Such
  a report was refused before, so a run whose plan changed nothing failed
  when it was given a Checkov report. `read_checkov` now reads it as a
  report with no result (its `tool_version` from `checkov_version`,
  `tool_parsing_errors` 0), and `kept_checkov` keeps it unchanged. A count
  other than 0, or a truth or text in place of one, is refused with "the
  checkov report is a summary with no framework, whose counts are not all
  the number 0"; another set of keys with "the checkov report is not one or
  more framework objects with results"; and a hidden count with "the report
  hides the summary's count of resources, where its reader expects a count"
  (or of another summary count). A
  missing file is not such a summary: Checkov writes a whole framework with
  `parsing_errors` 1, which reads as `scanner_report_incomplete`.
- Two new reasons say when a scanner's report holds no result to decide a
  subject from. Each applies only to a report the stage read in full; one
  it could not read in full stays `unknown` with
  `scanner_report_incomplete`. Both are decided after the version check.

  | Tool | Report | Every subject of the entry |
  | --- | --- | --- |
  | Trivy, which names a resource only when a check fails | Holds no result, passed, failed or skipped, of any check the scanner checks entry names, of the entry's input kind | `not_evaluated` with `no_result_of_the_mapped_checks` |
  | Checkov, which reports passes | Holds no result at all, such as Checkov's summary with no framework | `not_evaluated` with `no_result_in_the_report` |

  Without `--include-non-failures` Trivy lists only failures, so a clean
  plan leaves no result even when Trivy checked every resource; the report
  then says nothing about any subject of the entry. When it leaves Trivy's
  scanner requirement unmet, `no_result_of_the_mapped_checks` cancels every
  pass and `not_applicable`, as `scanner_not_run` does
  (`SCANNER_REQUIREMENT_GAP_REASONS`), so the stage's evidence lists
  `required_checks_not_evaluated`; otherwise it cancels nothing.
  `no_result_in_the_report` does the same for Checkov; for a Checkov no group
  names, or whose group another member met, another evaluator's pass stands, and the
  stage lists an `evaluator_did_not_decide` gap for `checkov`. Trivy's
  silence about one subject in a report that holds any result of the entry's
  checks, even a pass about no resource, stays
  `not_evaluated` with `tool_reports_only_failures`, which cancels nothing. A `no_result_of_the_mapped_checks` evaluation
  names its version and input but no result address, unknown path or failed
  check, and all its checks are undecided: "a scanner whose report holds no
  result of its mapped checks decided none of them and read no resource". A
  `no_result_in_the_report` evaluation follows the same rule: "a scanner
  whose report holds no result at all decided none of its checks and read no
  resource". A Checkov report with results about other resources still
  leaves a silent subject `unknown` with `not_reported_by_tool`.

  Trivy 0.72.0 reads the `terraform show -json` output of an applied state
  as a plan. With `--include-non-failures` it also lists 51 checks as passed,
  about no resource, even when it read no resource, such as `AWS-0019`,
  `AWS-0056`, `AWS-0123` and `AWS-0140`, and `AZU-` and `GCP-` checks. None
  is in the shipped mapping `ILT.SCANNER_CHECKS.STARTER`, whose Trivy checks
  are `AWS-0014`, `AWS-0016`, `AWS-0080`, `AWS-0107` and `AWS-0180`. An
  entry that names one of those always-listed checks never gets
  `no_result_of_the_mapped_checks`: for it the rule shows nothing about what
  Trivy read, and a scanner requirement of Trivy then leaves another
  evaluator's pass standing. For the shipped mapping, a result of an entry's checks shows
  Trivy read a plan with resources those checks cover, not that it read
  this plan.

  New scanner report vectors cover a plan that changes nothing for each
  tool, and Trivy given an open-SSH plan and its state file. The new
  `scanner_verdicts/` vectors give the status and reason every program
  gives one subject from a scanner checks entry and one scanner's
  observations. The Trivy evaluations of the three scanned record vectors,
  and the coverage gaps that name them, are `no_result_of_the_mapped_checks`
  in place of `tool_reports_only_failures`; no verdict changes. A new
  accepted-record case
  (`iac_record_whose_required_trivy_report_holds_no_result_of_its_checks`)
  requires Trivy on `records/iac/local_run_scanned.json`. Two more give that
  record a Checkov report with no result at all, one requiring Checkov
  (`iac_record_whose_required_checkov_report_holds_no_result_at_all`) and
  one not (`iac_record_whose_optional_checkov_report_holds_no_result_at_all`).
- A Trivy pass never decides a subject, even one that names a resource,
  which no Trivy release up to 0.76.2 writes: it counts as no result about
  that resource, so a subject Trivy names no failure for is `not_evaluated`
  with `tool_reports_only_failures`, and a failure still fails it. A
  hand-written scanner report vector, `hand_written_pass_naming_a_resource_trivy.json`,
  and a `scanner_verdicts/` case cover it.
- Every project path a record names can now be located in the repository
  at the record's commit, when the record names its repository. Before, a
  path such as the units file's was relative to a project directory the
  record did not name, and a scanner check mapping kept in a subdirectory
  could be named only by its file name. The file found there is the one the
  writer read only when its digest matches: the record does not say whether
  the checkout was clean. Three fields are new or changed:

  | Field | Before | Now |
  | --- | --- | --- |
  | `subject.project_directory` | Not given | Required: the project's directory relative to the repository's root, `.` for the root |
  | A units file unit's `directory` (`DeclaredUnit`) | Not given | Required, after `name`: the unit's directory relative to the project's directory, `.` for the project's own |
  | A scanner check mapping's `file_name` (`ScannerCheckMappingUsed`) | The file's name without its directories | `file_path`: the file's path in the project, `null` for the shipped mapping |

  Every project path the record names (`units_file.path`, each unit's
  `directory`, `out_of_scope[].declared_in.path`,
  `scanners.local_exceptions.file_path` and a mapping's `file_path`) is
  relative to `subject.project_directory`. `project_directory` is not part
  of `subject.source`, which an evaluation reads, so no evaluation input or
  input digest changes. The record's unit's code is in its entry's
  directory, a record with no units file is about the one unit in the
  project's own directory, and two units may share a directory. Each
  directory is the writer's reading of the units file; a reader can check
  only the file's digest at the commit.

  A directory (`iltero_schemas.models.common.fields.DirectoryPath`) is
  exactly `.` or a relative path of plain parts, with no leading `./` and
  no trailing `/`; any other value is refused with "must be '.' or a
  relative path with no '..', '.', empty part, ':' or leading '/'". A
  mapping's `file_path` outside the project is refused with "must be a
  relative path inside the project, with no '..', '.', empty part, ':' or
  leading '/'". Every project path and directory is now also refused when a
  part, in its compatibility form (NFKC), holds a character that looks like
  a slash or is only dots and spaces, which Windows drops from the end of a
  name: "must name each part plainly: not only dots and spaces, and with no
  look-alike slash". This tightens `units_file.path`,
  `out_of_scope[].declared_in.path` and `scanners.local_exceptions.file_path`
  too. The kept copy of a project's mapping names, as its source, the last
  part of `file_path`.

  Every record vector names `project_directory: .`; the units of
  `local_run_declared_units.json` are in `network` and `app`. New invalid
  record cases cover project directories with a leading `./`, a trailing
  `/`, a `..` part, a drive, a look-alike slash or only dots, a unit with no
  directory or one outside the project, a mapping read from outside the
  project, and a mapping whose `file_path` names another file than its kept
  copy. A new accepted case is a project in a subdirectory whose mapping is
  in a subdirectory of the project.
- Each stage's coverage, and the record's, counts each evaluator's own
  results before they combine (`Coverage.evaluator_status_counts`), keyed
  by engine: `opa`, `checkov`, `trivy`, or `none` for evaluations no
  evaluator ran. Each value names every status with a count, one per
  assertion and subject the evaluator evaluated, so the counts add up to the
  stage's events, not to `evaluations`. A member of a scanner requirement
  that gave no report is counted under its own name, as `not_evaluated`. An engine that
  gave no evaluation is not listed, so a stage with no events has `{}`. The
  record's coverage sums each evaluator over the stages that name it.

  The verdict reads only `status_counts`: these counts decide nothing. An
  unmet scanner requirement cancels other evaluators' passes, so an
  evaluator's passes can sit beside a combined `pass` count of 0. A
  scanner's counts are the results of its report as the pipeline supplied
  it, not Iltero's own finding.

  A stage's counts are refused when one leaves out a status ("each
  evaluator's status counts name every status: pass, fail, unknown,
  not_applicable, not_evaluated, error"), lists an evaluator that gave no
  evaluation ("an evaluator's status counts are listed only for an
  evaluator that gave an evaluation") or names an unknown engine. The
  integrity checks recompute them from the stage's events with
  `iltero_schemas.models.common.stage_counts.evaluator_status_counts`,
  which a writer uses too: "does not count, for each evaluator, the
  statuses of the evaluations it gave", at `stages.<stage>.coverage`. Every
  record vector counts each evaluator, with three new invalid record cases
  and two new integrity cases.
- A record names the project's git tree at its commit
  (`subject.project_tree`, required, beside `subject.project_directory`):
  `{"id": <git object id>}`, git's id of the names, file modes and contents
  of every file git tracks under the project directory at the commit, the
  commit's root tree for `.`. A reader with the repository reads it again
  with `git rev-parse <commit>:<project_directory>/`, or
  `git rev-parse <commit>^{tree}` for `.`. It covers only committed files
  under the directory: no uncommitted, untracked or ignored file, no shared
  or remote module outside it, a submodule only by the commit it points
  at, and no variable, state or tool version. Two records of the same
  repository and project directory that name the same tree come from
  commits whose project files are the same. That says nothing about the
  files on disk when each run ran, and does not make their changes the
  same. The id is lowercase hexadecimal and uses the same hash as
  `subject.source.commit.sha`, or the record is refused with "the project
  tree's id and the commit's id use the same hash: both are 40 or both 64
  characters long". The subject's model is now
  `iltero_schemas.models.common.record_subject.RecordSubject`, and the
  public constant `iltero_schemas.models.common.fields.COMMIT_PATTERN` is
  renamed `GIT_OBJECT_ID_PATTERN`, since it matches any git object id.
  Every record vector names a project tree, with three new invalid record
  cases and a new accepted case for a repository that names its git
  objects by SHA-256. The verification report gains no field; its vectors name the
  changed records' new digests.
- The starter assertion
  `ILT.COMMON.ASSURANCE.HISTORY.NO_UNEXPLAINED_REGRESSION` is withdrawn: no
  record ever evaluated it. Its document, its compiler vectors and its
  evaluation cases are removed, so the package ships 24 starter assertions,
  and the digest of the starter set in
  `vectors/canonical/assertion_set_cases.json` changes. The `runtime` stage,
  the `assurance` target kind, the `assurance` part of an AssuranceContext
  and the `HISTORY` area stay, with no starter assertion in that area.
- Two more limits of a record are stated beside the fields they affect. A Checkov
  report that checked nothing (`no_result_in_the_report`) may come from a
  plan that changes nothing or from a run set up wrongly, such as one given
  the wrong file or a check filter that matches nothing, and the record
  cannot tell which. A scanner's version is the one the scanner wrote in its
  own report.
- A Checkov report run with `--quiet` is no longer read as a full report.
  With `--quiet`, Checkov lists only failed checks, while each framework's
  summary still counts the passed and skipped ones. The kept Checkov report
  now keeps the summary's `passed`, `failed` and `skipped` counts beside
  `checkov_version` and `parsing_errors`. The reader requires every
  framework's summary and all four counts, each a whole number from 0, and
  refuses a count lower than the length of its own list. The results a
  summary counts that the report does not list are a new count,
  `results_not_listed`, in the scanner observations and in each scanner
  report entry of a record (`null` for Trivy, which writes no counts); the
  integrity checks compare the two. Since `parsing_errors` is now required,
  `tool_parsing_errors` is never `null` for Checkov: a report in which any
  framework leaves out `parsing_errors` is now refused. Observations give both
  counts as `null` exactly when the tool writes no counts. A report not read
  in full (`ScannerObservations.read_in_full` is false) leaves `unknown` with
  `scanner_report_incomplete` every subject the earlier rules do not decide: a
  quiet report whose checks all passed no longer reads as one that checked
  nothing (`no_result_in_the_report`), and a skip it does not list no longer
  gives `suppressed_in_source`. A listed failure still fails its subject. For a
  Checkov a scanner requirement names, a quiet report whose checks all passed
  leaves the stage `undecided`, not `incomplete` with a required check not
  made, and the quiet report of a Checkov no group names makes a subject `unknown` even when the
  assertion's own rule passed. The count is Checkov's own: a check left out
  of the run by a command-line filter, such as `--skip-check`, is in neither
  the counts nor the lists. Checkov is meant to run without `--quiet`: a
  quiet report passes no subject, so the formats reference advises against
  it. Every Checkov report vector keeps its summary counts and every
  observations and record vector gains `results_not_listed`, with three new
  `--quiet` captures from Checkov 3.3.8, four new verdict cases and one new
  integrity case.
- A record's `subject.environment` is no longer only a name. It has the
  shape of an evaluation input's `organization_scope.environment`: its
  `name`, and `production`, whether Iltero Platform's environment policy
  treats it as production. It is still `null` when the change is for no
  environment, such as an image build. A record names whether its
  environment is production, as `true` or `false`, exactly when Iltero
  Platform opened its run, and holds the unknown marker
  `{"__unknown": true, "reason": "server_facts_unavailable"}` when the tool
  did, since a tool cannot know Iltero Platform's policy; any other record is
  refused with "a record names whether its environment is production
  exactly when the server opened its run, and holds the unknown marker
  when the tool opened it". The environment's name still decides which
  exceptions are in force and enters the change digest;
  `RecordSubject.environment_name` gives it. Every record vector and case writes the new shape, with two new
  invalid record cases.
- A reader checks each evaluation input a record's stages kept against the
  record. An evaluation input is the `AssuranceContext` the policy evaluator
  read for one evaluation; a stage keeps each one, and each evaluation names
  it by `provenance.input_digest`.
  `iltero_schemas.models.common.kept_inputs.kept_input_problems(car, inputs)`,
  given the bytes of each kept input by its digest, checks, for every
  evaluation that names an input and is not a scanner's, that the input is
  at most `MAX_INPUT_BYTES` (checked first), is kept (given, its bytes having
  the digest), is
  canonical JSON, is an `AssuranceContext`, names the record's
  `subject.environment` (the same name and production value), and, where it
  carries a change digest, names the record's change digest. It reads each
  distinct input once and lists each failing evaluation at
  `events.<index>.provenance.input_digest`, with one of "names an evaluation
  input larger than an input may be (16777216 bytes)", "names an evaluation
  input the stage did not keep, or one whose bytes have another digest",
  "names an evaluation input not kept as canonical JSON", "names a kept file
  that is not an evaluation input", "names an evaluation input about another
  environment than the record's" or "names an evaluation input about another
  change than the record's". `KeptFiles` gains `inputs`, and
  `kept_file_problems` makes this check too; a reader of an image record calls
  it directly, beside `integrity_problems`.
- New conformance vectors for the files a record kept that a reader checks.
  `kept_files/`, split into `iac/` and `image/`, holds each record's kept
  evaluation inputs and, for a run Iltero Platform opened, the plan stage's
  copy of the exceptions it was served (`served-exceptions.json`), in a
  folder named after the record (`iac/local_run/`,
  `image/local_run_deploy_rolled_out/`), at the paths its evidence register
  names them by, and, under `iac/cases/`, the inputs of the `records_valid/`
  case `iac_record_of_a_run_the_server_opened_whose_every_plan_failure_a_served_exception_covers`,
  whose production value is `false`, and the served exceptions copy of the
  case
  `iac_record_of_a_run_the_server_opened_keeping_its_commit_review_without_a_commit_review_check`.
  `records/iac/local_run.json` is the
  record the Iltero CLI writes, run with the pinned evaluator: it names the
  pinned OPA binary for `darwin-aarch64` and the digest of the bundle it
  evaluated. `records/image/local_run_deploy_rolled_out.json` is an image
  deploy the Iltero CLI wrote from a captured rollout of
  `docker.io/library/nginx`. Every record names the redaction policy digest
  `sha256:a0ae1edd716af5f441d9bb028494eb0be3468dd618c3a693c06d9c7ccad46f5f`.
  The sample report `reports/iac/verification_report.json` gives
  `evaluator_binary` as `claimed_by_record` with `pinned_binary_named`, the
  `reports_expected/` case of a record on a placeholder binary names
  `iac/local_run_declared_units.json`, and each sample report's
  `evaluator_binary` is checked against its record. A record case's evidence
  register entry that names a file of its base record, by the same path and
  digest, has that file's size.
- A verification report's `exceptions` property now judges the exceptions
  Iltero Platform served, and the report has a thirteenth property,
  `scanner_evidence`. Both results are worked out from the record and the
  files its stages kept, so every verifier gives the same one.
  `iltero_schemas.models.iac.report_results.exception_results(car, files)`
  gives each exception result that holds, which a verifier passes with the
  pre-deploy results that hold to `first_that_holds`. The new `exceptions`
  results are:

  | State | Reason | When |
  | --- | --- | --- |
  | `failed` | `kept_exceptions_do_not_hold` | An exceptions file a stage kept, the project's own or the one Iltero Platform served, does not give the exceptions the record names, or was served to another run, stage or environment. |
  | `claimed_by_record` | `served_exception_approved_by_run_starter` | The plan stage relies on a served exception, and the kept copy says the person who approved it started the run. |
  | `claimed_by_record` | `served_exception_relied_on` | The plan stage names a failed result a served exception covers, and the kept copy gives that exception. Only Iltero Platform confirms that it served that copy, who approved each exception and whether one was revoked later; whether an exception was in force rests on the stage's reference time, itself the record's claim. |
  | `claimed_by_record` | `served_exceptions_not_relied_on` | The plan stage applied the served exceptions and names no failed result they cover. |
  | `not_assessed` | `not_in_activity` | The record's activity applies no exception at any stage, Iltero Platform's or the project's own, as an image build or deploy applies none. |

  | Case | Before | Now |
  | --- | --- | --- |
  | The exceptions of a run Iltero Platform opened | `not_assessed`, `served_exceptions_not_assessed` | `kept_exceptions_do_not_hold`, `served_exception_approved_by_run_starter`, `served_exception_relied_on` or `served_exceptions_not_relied_on` |

  `PRE_DEPLOY_RESULT_ORDER` now takes `kept_exceptions_do_not_hold`,
  `served_exception_approved_by_run_starter`, `served_exception_relied_on`,
  `project_exception_relied_on`, `served_exceptions_not_relied_on` and
  `project_exceptions_file_not_relied_on` first, then `not_in_activity`,
  `pre_deploy_out_of_scope`, `run_opened_locally` and `pre_deploy_pending`,
  so a pre-deploy stage that is not in the activity, out of scope or still
  pending does not hide an exception the record relied on.

  `scanner_evidence` means that every scanner verdict comes from a report of
  the pinned scanner Iltero Platform required, run on the plan the record
  evaluated. `report_results.scanner_evidence_result(car, files)` gives the
  first result of `SCANNER_EVIDENCE_RESULT_ORDER` that holds:

  | State | Reason | When |
  | --- | --- | --- |
  | `failed` | `kept_files_do_not_give_the_verdicts` | A scanner evaluation does not follow from the files its stage kept. |
  | `not_performed` | `scanner_requirement_not_met` | A group of scanners a stage requires gave only gaps for a check and subject. |
  | `claimed_by_record` | `ran_by_pipeline` | A kept report says the pipeline ran it. |
  | `claimed_by_record` | `ran_by_iltero_cli` | Every kept report says the Iltero CLI ran it. |
  | `not_assessed` | `not_in_activity` | The record's activity reads no scanner report. |
  | `not_assessed` | `no_scanner_report` | No stage read a scanner report and none requires one; in a run Iltero Platform opened, only Iltero Platform confirms that its stages required none. |

  A failed result's detail is the first problem the checks list, then
  "(and N more problems)"; a served exception result's detail is the fixed
  sentence `report_results.SERVED_EXCEPTION_RELIED_ON` or
  `APPROVED_BY_RUN_STARTER`, only beside kept copies that hold; the
  `scanner_requirement_not_met` detail names the stage and the group's
  scanners. No detail holds a value from a kept file. An image record gets
  `scanner_evidence_result` too, as `not_in_activity`. `kept_file_problems`
  now calls `local_exception_problems` itself, and
  `scanner_evidence_problems` checks only the scanner verdicts. The three
  sample reports gain `scanner_evidence`, and
  `reports/iac/verification_report_commit_not_reviewed.json` gives
  `exceptions` as `claimed_by_record` with `served_exceptions_not_relied_on`.
  Two new `reports_invalid/` cases refuse an `exceptions` result the
  contract does not give and a `scanner_evidence` reason of another
  property.
  New `reports_expected/` cases cover a server-opened run relying on an
  exception its run's starter approved while its pre-deploy stage is
  pending, and the scanner evidence of a record with no scanner report, of
  one whose reports the pipeline ran, of one whose required group of
  scanners gave only gaps, and of a build. A test works out every `iac/`
  expected `exceptions` and `scanner_evidence` result from its record and
  kept files.
- Six new records of runs Iltero Platform opened, which the Iltero CLI wrote
  with the pinned evaluator. Each evaluates a bundle Iltero Platform served,
  signed by the development key `dev-bundle-test-vectors`, which no shipped
  trust set accepts.

  | Record | What it shows |
  | --- | --- |
  | `iac/governed_run.json` | A plan stage in a production environment, with no exception served; `not_met`. |
  | `iac/governed_run_every_failure_excepted.json` | A plan stage outside production whose every failure a served exception covers; `not_met` with `every_failure_excepted`. |
  | `iac/governed_run_every_failure_excepted_one_check_undecided.json` | A plan with a value known only after the deployment, in production, whose every failure is excepted and one check is undecided; `undecided`. |
  | `iac/governed_run_deployed.json` | Plan, pre-deploy and post-deploy stages, with an independent approval with the `security` role and a reviewed commit review served; `met`. |
  | `iac/governed_run_deployed_without_server_facts.json` | The same run with the unknown marker for every fact Iltero Platform serves the pre-deploy stage; `undecided`. |
  | `image/governed_run_deploy_rolled_out.json` | An image deploy through pre-deploy, post-deploy and post-verify on a captured rollout, with an accepted build served; `met`. |

  Their kept files are in `kept_files/`, and a test runs every check a
  reader makes over each record whose kept files the vectors hold:
  `kept_input_problems`, and `kept_file_problems` for an `iac_change`
  record; the records kept by hand, whose `kept_files/` folders hold the
  scanner files their plan stage kept and no evaluation input, are left
  out. Another test checks that every file in every
  `kept_files/` folder, a case's included, has the digest and size its
  evidence register entry names. New `reports_expected/` cases cover the
  exceptions of a run Iltero Platform opened that relies on no served
  exception and of one that relies on served exceptions, the scanner
  evidence of such a run with no scanner report, the approvals and commit
  review Iltero Platform served (`approvals_listed`, `reviewed`) or that
  stayed unknown (`could_not_decide`, `server_facts_unavailable`), the
  reference time of a plan stage that left a check undecided (`server`),
  and the exceptions of an image deploy, opened by Iltero Platform or by
  the tool (`not_in_activity`).
- The `records_valid/`, `records_invalid/` and `records_integrity_failed/`
  cases of runs Iltero Platform opened now build on the Iltero CLI's records
  of such runs, `iac/governed_run.json`,
  `iac/governed_run_every_failure_excepted.json`,
  `iac/governed_run_every_failure_excepted_one_check_undecided.json`,
  `iac/governed_run_deployed.json` and
  `image/governed_run_deploy_rolled_out.json`, instead of turning a record
  of a run the tool opened into one, and each keeps its outcome. Seven still
  turn such a record into one: the two image build cases, since a build
  names no environment, and five refused cases about scanner reports or a
  postponed check, on `iac/local_run_scanned.json`,
  `iac/local_run_scanned_project.json` and `iac/local_run_postponed.json`.
  A case that keeps a copy of the exceptions served to its run, or
  evaluation inputs evaluated again for the facts it changes, has them in
  `kept_files/<type>/cases/<case>/`. The three image deploy integrity cases
  about the build check report it at `events.2`, the expected case
  `approvals_a_server_opened_run_needed_and_did_not_get` names
  `iac/governed_run_deployed_without_server_facts.json`, and
  `reports/iac/verification_report_commit_not_reviewed.json` gives
  `approval_identity` as `claimed_by_record` with `approvals_listed`.
- `kept_files/` also holds the files the hand-kept records
  `iac/local_run_scanned.json` and
  `iac/local_run_scanned_project_required.json` kept to decide their scanner
  verdicts: their assertion documents, scanner check mapping copies,
  reports, observations and redacted plan. Their evaluation inputs were
  never written, so the test of every reader check leaves the two out, and
  their assertion index (`compiled.json`) is not shipped. A test checks
  that their scanner verdicts follow from those files.
- `records/iac/local_run_suppressed_with_exception.json` is now the record
  the Iltero CLI writes, with the pinned evaluator: a plan of one RDS
  instance, `aws_db_instance.noncompliant`, with 14 events, whose Checkov
  result `CKV_AWS_16` is reported as suppressed and is covered by `ex-1` in
  the project's exceptions file. Its scanner report is the kept form of
  `scanner_reports/iac/rds_skipped_checkov.json`.
  `kept_files/iac/local_run_suppressed_with_exception/` holds every file its
  register names, its evaluation inputs and assertion index included, so
  the test of every reader check runs on it, scanner checks included.
  `scanner_evidence/iac/local_run_suppressed_with_exception/` holds the new
  record's files, and its cases name its event 11.
- The `exceptions` result of an image deploy the tool opened is now
  `not_assessed` with `not_in_activity`, not `not_performed` with
  `run_opened_locally`, since `not_in_activity` comes first in
  `PRE_DEPLOY_RESULT_ORDER`.
