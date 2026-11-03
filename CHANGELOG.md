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
- Fifteen starter assertions, among them the one that holds the plan
  applied to the plan that was evaluated, `ILT.IAC.NO_DRIFT_AFTER_APPLY`,
  which holds that no deployed resource drifted after the apply, and
  `ILT.IMAGE.BUILT_FROM_RUN_COMMIT`, which holds that the commit the build
  tool's provenance names is the commit the server verified for the run,
  and is unknown when the build names none,
  `ILT.DEPLOYMENT.IMAGE_BINDING`, which holds that the image the pipeline
  reports it deployed is the image the deploy checked, and
  `ILT.IMAGE.RUNNING_DIGEST_MATCHES`, which holds that, once the
  workload's rollout has finished, every compared container of every live
  pod runs that image or one of its platform images.
  These five are
  built in (`PLAN_BINDING`, `NO_DRIFT_AFTER_APPLY`, `BUILT_FROM_RUN_COMMIT`,
  `IMAGE_BINDING` and `RUNNING_DIGEST_MATCHES` in `iltero_schemas.assertions`):
  a runner evaluates the first at every infrastructure post-deploy stage, the
  second at every infrastructure post-verify stage, the third at every build's
  plan stage, the fourth at every image deploy's post-deploy stage and the
  fifth at every image deploy's post-verify stage, whatever a project's own
  assertions are.
  Their ids are reserved (`BUILT_INS`, each a `BuiltIn` with its version,
  document digest and compiled module digest): an evaluation that names one
  names the shipped version and document, comes from this package or the
  server's bundle and never from a scanner, and ran the shipped module.
  Each activity names its binding check (`binding_check`) and every
  built-in assertion it always evaluates (`always_evaluated`): once the
  assertion's stage has reported, a record evaluates it exactly once, at that
  stage only, and never as not applicable. An infrastructure record's
  `post_deploy` stage evaluates `ILT.DEPLOYMENT.PLAN_BINDING` and its
  `post_verify` stage `ILT.IAC.NO_DRIFT_AFTER_APPLY`; a build's `plan` stage
  evaluates `ILT.IMAGE.BUILT_FROM_RUN_COMMIT`, which never passes or fails
  when the build names no commit, where it is unknown with
  `not_reported_by_tool`, or on a run the tool opened, where it is unknown
  with `server_facts_unavailable`, since only the server verifies the
  commit (an event that was not evaluated, or that ended in error, is
  accepted); an image deploy's `post_deploy` stage evaluates
  `ILT.DEPLOYMENT.IMAGE_BINDING` and its `post_verify` stage
  `ILT.IMAGE.RUNNING_DIGEST_MATCHES`.
  `ILT.IMAGE.TESTS_RAN` holds that the pipeline gave a test report for the
  built image in which at least one test ran rather than being skipped, and
  `ILT.IMAGE.SCAN_RAN` that a vulnerability scan ran whose report itself
  names the built image or one of its platform images. `ILT.CHANGE.PRODUCTION_APPROVED` is about any change
  (`change_type: null`); the five image assertions are about
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
  separator and the Hangul fillers.
- The evaluation input (`AssuranceContext` v1), with a fixed set of parts for
  each activity, stage and target (`profile_for`). Every input, and every
  event, names the activity it belongs to (`evaluation.activity`). An event
  is checked on its own against its activity: its stage and subject kind
  must have a profile, and its checked content must be of the activity's
  kind (`CHECKED_CONTENT_KIND_OF`).
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
  (`observed_at`).
  Invalid-record vectors cover them.
- In an `AssuranceContext`, `null` means a fact has no value, never that it is
  unknown. A plan's `complete`, `applyable` and `tool_version` hold the unknown
  marker with the reason `not_reported_by_tool` when the tool's plan does
  not say. `change.digest` is required and is the change digest of its unit's
  plan in the input's environment. A resource's `type` and `name`, its provider source and a related
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
- The plan, the apply log and the state name their IaC tool (`tool`) and its
  version (`tool_version`). An apply's timing source is `apply_log`.
- A subject is keyed, in the evaluation input, in events and in an earlier
  evaluation, by `key`: the digest of its kind and its one local identity,
  computed by `models.subjects.subject_key` and checked in every document,
  with a conformance vector. The local identity is a managed resource's
  address scoped by its unit (scheme `terraform_address`), the cloud identity
  of a resource only the cloud knows (at runtime), or the unit of a
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
  v1): the record of one attempted change, whatever its outcome. It holds
  each stage's coverage and verdict, the rules that tie the stages together,
  what a deployment did, the resources' cloud identities, and which stages
  are in scope. It says what was checked and how; on its own, it
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
  each approval of a change, must be what they recompute to. They also
  recompute the status each built-in check must have from the record's own
  change, and report an event a policy answered (`pass`, `fail`, `unknown`
  or `not_applicable`) that says otherwise; an event not evaluated, or that ended in error, decides
  nothing. In an infrastructure record, `ILT.DEPLOYMENT.PLAN_BINDING` must
  pass exactly when the applied plan has the evaluated plan's digest,
  artifact digest and its source, and `ILT.IAC.NO_DRIFT_AFTER_APPLY`
  exactly when the drift check found no difference; each fails otherwise.
  Change digest
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
  records name a scanner from one list: `checkov` and `trivy`.
- Named constants for values consumers write as plain strings. Each constant
  lives with the part of the contract it belongs to. `SCHEME_UNIT` is in
  `iltero_schemas.models.vocabulary`, `SCHEME_AWS_ARN` in
  `iltero_schemas.models.providers.aws`, and the CI systems an executor may
  name in `iltero_schemas.models.ci.CI_SYSTEMS`.
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
  exceptions, evaluations, the verified source of a build) is missing, the evaluation input holds a marker,
  so a condition that reads it is `unknown`, never true or false. An
  evaluation whose input reads Iltero Platform facts records where they came
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
  as well as the pre-deploy approval gate. A record of any activity calls a
  stage unsupported only when its activity says the record cannot run it
  (`not_supported`, given the record): for an infrastructure record, when
  its IaC tool cannot; Terraform, which has a drift reader, runs every
  stage. `iltero_schemas.change_types.not_supported_by(tool)` gives the
  stages an IaC tool cannot run.
  The sample records expect all four stages.
- An identity document says where its state was read from
  (`sources.read_from`): the state file the apply left, or a refresh-only
  plan, which names no applied plan. A record's identities are always read
  from the state file.
- A record of a container image build (`change.activity: image_build`). It
  names the image by its repository and digest, the digest of each
  platform's image when the build pushed an index (the manifest that lists
  one image per platform), the commit the build tool's provenance names
  (`build_commit`), the build's attestation file, kept but not verified,
  and the test and scan reports the build was given (`reports`: each
  report's file, its format, `junit`, `trivy_json` or `grype_json`, and the
  image it is about, which is the image or one of its platform images; a
  JUnit report names no image, so only the pipeline ties it to one). A tag
  the pipeline gave is kept for reading only, with the build tool's
  metadata file that tied it to the digest and the time the pipeline read
  that file (`read_from`, `read_from_evidence_ref`, `read_at`); no registry
  is asked. The build commit is read only from the Docker Buildx metadata
  file (`docker buildx build --metadata-file`), from the provenance summary
  BuildKit writes there when the build context is a Git repository URL
  (`invocation.configSource.digest.sha1`), never from an image label. A
  build from a local directory names no commit there, so its
  `build_commit` is `null`. The file is the pipeline's and unsigned, so the
  commit is `not_verified`; the record keeps the file as the pipeline gave
  it, and it is the same file the tag is read from. The metadata file the
  tag or the commit is read from is JSON and kept unredacted, exactly as
  given.
  `iltero_schemas.models.buildx.build_metadata_of` reads the image digest,
  the image names and the commit from the kept file, strictly and at most
  1 MiB, so every reader reads the same values, and
  `iltero_schemas.change_types.check_build_metadata` compares them with the
  record: the image's digest, the image's repository with its tag (each
  image name put in its one spelling first by
  `iltero_schemas.models.image.in_one_spelling`), and exactly its build
  commit. A metadata file whose `containerimage.descriptor` names another
  digest than `containerimage.digest` is refused. Building with
  `--provenance=mode=min` is recommended: the commit is the same as in
  `mode=max`, which also writes the build's arguments, and a build argument
  can hold a secret value. The
  tool that writes a record runs it, and so can any reader given the file
  from the pipeline's store. Iltero stores none of a build's evidence files
  and never reads the pipeline's store: the pipeline keeps them in the
  run's artifact store, and the record keeps each file's digest. The one
  file that passes through Iltero Platform is the raw image index, which
  the plan stage owes (`image_index`, the one document an image build's
  `named_documents` lists) and which Iltero Platform checks with
  `platform_digests_of`, refusing an index over 4 MiB, and then discards.
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
  in a run the server opened, and deploys nothing, so it has no change
  digest and nothing to approve. Its evaluations are about the built
  artifact, and their input carries the image with its build commit, or
  the unknown marker when the build named none, the test and scan reports
  the build was given, each saying whether the report itself names the
  image or only the pipeline does (`image_digest_source`: `report` or
  `pipeline`), and the commit the server verified for the build job, with
  the CI system and its instance, the repository by id and name, and the
  CI run and attempt it was verified for, since a CI system's ids are unique
  only within one instance of it. A build's input names no environment. A
  build's evaluations say their facts came from the server exactly when the
  server opened the run, and from nowhere otherwise, never from a local
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
  the server accepted for the environment (`build`: its run, its record's
  digest and its platform digests), as the server served it, and never a
  build a pipeline chose; a record of a run the tool opened names none. The
  Iltero CLI talks to no cluster and no deploy tool: after the deployment
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
  redaction policy and kept no earlier than the reading), each read from files the pipeline wrote
  and dated by its runner's clock. A reading lists the pods whose
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
  `ILT.IMAGE.RUNNING_DIGEST_MATCHES` fails when the template compares no
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
  each of its two built-in checks must have from the record's own image,
  deployment, reading and build, and report an event that says otherwise.
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
  | Built-in assertions | `ILT.DEPLOYMENT.IMAGE_BINDING`, `ILT.IMAGE.RUNNING_DIGEST_MATCHES` |

- A verification report's `runtime_verification` is one of seven results,
  each a state and its reason, among them `not_assessed` with
  `not_in_activity` for a record whose activity has no stage after
  deployment, such as an image build, or `not_determined` when the record's
  integrity is not established.
