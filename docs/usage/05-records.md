# The record

A **Change Assurance Record** (CAR) is the record of one infrastructure
change. It can hold the checks, the approvals, what the deployment did, and
checks made after deployment. Each part says where it came from. It names no
regulatory framework. A view for a framework is built from records, outside
them.

A CAR records technical and process assurance facts. It does not, by itself,
establish certification or compliance with a regulatory framework. In plain
words, a record says what was checked and how. On its own, it does not show
that anything is certified or complies with a regulation or standard.

One record covers one unit of one run. A unit is the part of a project that
is planned and applied as one. A record describes one attempted change,
whatever its outcome. The change may have been deployed, failed, been
stopped, been refused before deployment, or had a plan that changes nothing.
So a record is not a certificate of success. It exists even when a check
fails.

The record is the document a tool hands on: to an auditor, to a colleague,
or to Iltero Cloud. This package defines its shape.

Anyone may receive a record, including a verifier on someone else's machine.
So the package accepts exactly the fields below and nothing else. A reader
validates the document once. After that, it works with values whose shape
it knows.

## On this page

- [What a record holds](#what-a-record-holds)
- [How far a record can be trusted](#how-far-a-record-can-be-trusted)
- [Every path stays inside the record](#every-path-stays-inside-the-record)
- [Several stages, one record](#several-stages-one-record)
- [The record checks itself](#the-record-checks-itself)
- [Which package checked the record](#which-package-checked-the-record)
- [For developers](#for-developers)

## What a record holds

| Part | What it says |
| --- | --- |
| `uuid`, `run_id`, `unit` | Which record this is, which run it belongs to, and which unit it covers. `run_id` also says whether the run's id was derived locally or issued by a server. |
| `pins` | For a run Iltero Cloud opened, what Iltero Cloud fixed when the run opened: the bundle, the checks owed, the environment policy's digest, whether a failed check stops the pipeline (`gate_mode`), and the oldest tool version allowed. See [governed runs](09-governed-runs.md#the-pins). It is `null` for a run the tool opened on its own. |
| `trust_level` | How far a reader can trust the record. It is always `self_attested`. See [how far a record can be trusted](#how-far-a-record-can-be-trusted). |
| `compliance_determination` | Always `null`. A record never decides whether something complies with a framework. |
| `issuer` | Who wrote the record. `type` is always `local`, the tool on the machine it ran on. `identity_verified` is always `false`, because nothing signs the record. |
| `governance` | Who opened the run. `run_opened_by` is `server` exactly when the record has `pins`, and `local` otherwise. |
| `subject` | What the record is about: the environment, the unit and the commit. |
| `change` | Every unit of the change with its plan digest, sorted by unit name, with no unit twice and the record's own unit among them. It also holds the change's `digest` once that is known. A record with a pre-deploy stage always names it (see [the two digests](09-governed-runs.md#the-two-digests)). |
| `plan` | The plan's fingerprints and what the infrastructure-as-code (IaC) tool said about it (see [the plan's fingerprints](03-compiler-and-evaluation.md#the-plans-fingerprints)). It names the IaC tool that wrote the plan (`tool`, such as `terraform`) and that tool's version (`tool_version`). The tool the plan names is the tool the whole record is about. It also holds `context_digest`, the fingerprint of the plan as the tool kept it after hiding sensitive values. |
| `stages` | One entry per stage (see below). |
| `events` | One event per check. See [what is recorded with a verdict](04-events.md). |
| `coverage` | The stages' coverage combined (see [several stages, one record](#several-stages-one-record)). It holds the resources in scope and how they were counted, the assertions expected and where that set came from, how many of each were evaluated, the counts per status, and the gaps. When there are several stages, each gap names its stage. |
| `verdict`, `assurance_status`, `complete` | The verdict and the exit code it produced. Whether the evaluation finished. Whether every expected stage has reported. |
| `expected_stages`, `not_in_scope` | Which stages the record expects, and each stage it leaves out with the reason (see below). |
| `deployment` | What the apply did, in the same shape as the [post-deploy input](03-compiler-and-evaluation.md#what-goes-in). It is `null` until the post-deploy stage has reported. |
| `identity` | Which cloud resource each resource of the unit's configuration is, and which objects left the state in the apply and how. Each is bound, or listed with the reason it could not be. It also names the state and plan they were read from. See [identity bindings](08-identity-bindings.md). It is present exactly when `deployment` is. |
| `evidence_refs` | The record's **evidence register**: every file the record cites. Each entry gives the file's id (`ref_id`), its type (`media_type`), its digest, its size and where it sits. |
| `integrity`, `retention_*` | How the record is bound together (by digests, with no signature), and that no server assigned it a retention period. |

Each entry of `stages` says:

- what ran the stage, under which limits, and what it hid;
- the CI job Iltero Cloud said it verified (`ci_identity`), copied into the
  record without a signature, or `null` for a run the tool opened on its own;
- the files it wrote: its events, and the index of the assertions it
  compiled;
- its own `coverage`, `verdict` and `assurance_status`.

A stage that was given a scanner report also says which binding catalogue
was in force. For each report it names the tool (`checkov`, `trivy` or
`prowler`), its version, what the tool was reading, how many checks the
report held, and how many it left unbound.

A record names a reason for each stage it leaves out (`not_in_scope`):

- `project_config`: the project left the stage out on purpose. The record
  names the file that says so (`declared_in`) by its path and digest. A
  project can leave out only the pre-deploy approval gate.
- `not_supported`: the tool that wrote the record cannot run that stage.

## How far a record can be trusted

A record's `trust_level` says how far its facts were established. The
contract lists five levels, from the weakest to the strongest:

| Level | What it means |
| --- | --- |
| `self_attested` | The tool that wrote the record is its only source. |
| `source_authenticated` | A service other than the writer confirmed where the record came from. It confirmed the repository, the CI system, and the people and jobs named in it. |
| `server_governed` | Iltero Cloud checked the record against a set of rules the organization chose, and checked that each piece of evidence links to the one before it. |
| `assessor_reviewed` | A named external assessor reviewed the record. |
| `authority_accepted` | A named authority accepted the record for a stated purpose. |

Every level above `self_attested` needs a signature from whoever vouches
for it. This version of the record cannot carry a signature. So the package
accepts only `self_attested` and refuses every other level. The other four
are listed so that a reader can see the whole scale.

For the same reason, a record always names the local tool as its issuer.
Without a signature, nobody can prove who wrote a record. So a record never
says its issuer's identity was verified. This holds even for a record of a run
Iltero Cloud opened.

A record also never decides compliance. Its `compliance_determination` is
always `null`. A view of a framework, such as which controls a change meets,
is built from records, outside them.

A check of a record's properties, such as whether its sources were
authenticated, is not written into the record. It goes into a separate
[verification report](14-verification-reports.md).

## Every path stays inside the record

Every path a record names is a **relative path inside the record's own
directory**. This covers `evidence_refs[].path` and the paths in each stage
entry. Such a path:

- is plain names joined by `/`, at most six deep and 1024 characters long;
- uses only letters, digits, `.`, `_`, `@` and `-` in each name;
- is never absolute, and never contains `.` or `..` as a name.

The package refuses a record that names any other path, before a reader can
follow it.

This rule is what lets a record move. Beside the run that wrote it, the
paths lead to the files that run wrote. In a bundle, they lead to the
bundle's own copies. The rule also stops a record someone hands you from
pointing at the rest of your disk.

No two entries of `evidence_refs` may name the same file or share a
`ref_id`.

## Several stages, one record

A record can cover several stages. Each stage counts its own checks and
reaches its own verdict. Then the record combines them.

**Each stage counts its own subjects.** A subject is the thing a check is
about. The plan stage counts the resources the plan names
(`basis: plan_resource_enumeration`). The post-deploy stage counts one
subject, the deployment of the unit (`basis: deployment_unit`). Only the
plan stage counts the plan's resources.

Each count also names what it was counted from, in `source_digest`. That is
the fingerprint of the document the stage read its subjects from. For the
post-deploy stage, it is the digest of the record's `deployment` part.

**A stage's verdict follows from its own counts** by one rule
(`basis: status_counts`), and it names no stage. The rule collects every
exit code that applies:

- `6` (coverage gap) when nothing was expected, no subject was evaluated,
  fewer assertions were evaluated than expected, a check was not evaluated,
  or the run was cut short (truncated);
- `4` (evaluator error) when a check ended in an error. This also makes the
  stage incomplete;
- `3` (indeterminate) when a check was undecided;
- `1` (assertion failed) when a check failed;
- `0` otherwise.

The stage takes the code that comes first in the fixed order
`2, 5, 9, 10, 7, 8, 6, 4, 3, 1, 0`.

**The record's top level combines the stages.** It never counts the
events again. It combines the stages in the order the record expects them:

- The resources in scope, and how many were evaluated, are the plan
  stage's.
- The checks, the assertions and the counts per status are added up. Each
  assertion is counted by one stage only.
- The record names its assertion set by one digest, computed over every
  stage's own set. So it differs from the digest of any single stage's set.
- The gaps are kept, and each names its stage. The record is truncated or
  sampled when any stage is.
- The verdict is the stage verdict whose exit code comes first in the same
  order. It names that stage (`basis: stage_precedence`). So a gap one stage
  found is never cured by another stage's checks. When two stages tie, the
  earlier one is named. Read each stage for its own verdict.
- The record is incomplete when any stage is, and names the first that is.

The stages count different things. So "checks = assertions × subjects"
holds within each stage, but not across the whole record. The top level
covers only the stages that have reported. A record still waiting on a
stage says so in `complete`, not in its verdict.

**A record always starts at its plan stage.** The plan is what was
reviewed, so a later stage only means something against it:

- The first expected stage is `plan`, and the plan stage is present.
- The record always expects its `post_deploy` stage, the stage that
  observes the deployment.
- The plan stage counts the resources of the plan the record names. Its
  `source_digest` is the record's `plan.context_digest`.
- The plan stage was observed no later than the apply started, by the
  clocks that wrote them.
- `post_verify` comes only after `post_deploy`.
- `runtime` is never a stage of a record. What is observed at runtime
  belongs to no deployment.

## The record checks itself

When the package reads a record, it checks that the record is consistent.

**The structure holds together.** Besides the rules above:

- each stage entry is filed under its own name;
- every event belongs to a stage the record has, and the events are grouped
  in stage order;
- each assertion is evaluated by one stage only;
- every event names the plan the record evaluated;
- the deployment was read from output of the same IaC tool that wrote the
  plan;
- every event names the record's own run, how that run was opened
  (`run_id.basis`), and the record's unit.

**Every value a reader can recompute is recomputed.** Each stage carries
one event per check. Its status counts are its events' statuses. Its
verdict and status are the ones its counts give. The change's `digest` is
the digest of its units. The record's top level is its stages combined.

**No record claims more trust than it can carry.** Its `trust_level` is
`self_attested`. Its issuer is the local tool, and that identity is not
verified. These rules hold whoever opened the run, so no record names
Iltero Cloud as its issuer.

**A record with `pins` agrees with them.**

- It says Iltero Cloud opened its run (`governance.run_opened_by: server`).
- Its environment is the pinned one.
- Every stage says its expected checks came from the pins
  (`server_pinned`). The stages together expect no more checks than were
  pinned.
- Every stage and every check that names a bundle names the pinned one.
  Every check is of an assertion from that bundle
  (`assertion_source: server_bundle`).
- Every check is of a pinned assertion.
- No pre-deploy check read its facts from a local file.
- It names the commit it is about (`subject.source.commit.sha`).
- Every stage names the CI job that Iltero Cloud said it verified
  (`ci_identity`). All its stages share the same CI system, the same token
  issuer, the same repository and the same commit. GitHub Actions
  identifies the repository by its id and its owner's id. That commit is
  the one the record is about.

**A record without pins claims nothing only Iltero Cloud can give.**

- It says the tool opened its run on its own
  (`governance.run_opened_by: local`). It says the tool chose its expected
  checks itself (`locally_derived`).
- It names no Iltero Cloud bundle and no check from one.
- It has no facts from Iltero Cloud (`facts_source: server`).
- It has no CI context file checked with a run's context key, and no CI
  job verified by Iltero Cloud. (The context key is a secret Iltero Cloud hands
  out with a run. See
  [governed runs](09-governed-runs.md#the-run-token-and-the-context-key).)

These rules check that a record is consistent. They cannot prove that
Iltero Cloud really opened the run. The record is not signed, so whoever
writes it can also write pins, and a verified CI job for each stage, that
agree with it. Only Iltero Cloud can confirm a run, and the CI jobs it
verified, by looking up its `run_id`.

The signed bundle, not the record, says which pinned assertions belong to
which stage. So the package cannot compare a stage's own set of checks with
the pins. That comparison needs the bundle, and no tool makes it yet.

**A record accounts for every stage of the lifecycle.** The lifecycle
stages are `plan`, `pre_deploy`, `post_deploy` and `post_verify`. Each is
either expected or named once in `not_in_scope` with a reason, never both.

- A record is `complete` exactly when every stage it expects has reported.
- It describes the deployment and its identities exactly when its
  post-deploy stage has reported.
- Its identities are read from the applied plan its deployment names, and
  from the state its deployment was checked against.
- Its identities list each resource at most once in each half, all of the
  record's own unit.
- They name as removed exactly the objects that the deployment says left
  the state, and how each left.

## Which package checked the record

Each stage's `compiler`, and each event's, names the `iltero-schemas`
package the record was checked with:

- `contract_version`: the package version.
- `install`: how it was installed, `wheel` or `editable`.
- `contract_digest`: a fingerprint of the package's own files.

The `contract_digest` is SHA-256 over the sorted `path,hash` lines that the
wheel's `RECORD` file gives for the package's own files. It is the same
value from the published wheel as from its installation, and each release
prints it.

- The package reports its own digest only after it has hashed every file
  `RECORD` lists and found each matches its entry. The package directory
  must also hold no other file, apart from bytecode caches.
- An editable development install has no digest.
- A tool may compute the digest from `RECORD` alone, without hashing the
  files. It then names the same value, but it has not checked it.

Some readers report an edited value as tampering, rather than as a record
they cannot read. Such a reader can tell the package to skip the
recomputed values when it validates (see [for developers](#for-developers)).
The package still enforces the structure. The reader must then recompute
the values itself, and act on every difference, before it trusts any count
or verdict.

## For developers

| On this page | In the package (`iltero_schemas`) |
| --- | --- |
| A record | `models.car.CAR` |
| The trust levels, and the only one a record may claim | `models.car.TrustLevel`, `models.car.UNSIGNED_TRUST_LEVEL` |
| The deployment's tool matches the plan's | `models.deployment.check_tool` |
| A stage's verdict from its counts | `models.coverage.stage_outcome` |
| The exit-code order | `models.coverage.VERDICT_PRECEDENCE` |
| Combining the stages | `models.coverage.combine` |
| The structure rules | `models.stages.check_structure` |
| The values a reader recomputes | `models.stages.derived_problems` |
| The rules for pins | `models.pins.check_pins` |
| Skipping the recomputed values | validate with `models.car.DERIVED_CHECKED_BY_READER` set to true in Pydantic's validation `context` argument, then call `models.stages.derived_problems` |
| Reproducing the package digest | `distribution.record_digest` (from a `RECORD` file), `distribution.wheel_digest` (from a wheel) |
| The installed package's digest | `distribution.installed_identity()` |
