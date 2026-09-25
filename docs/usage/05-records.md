# The record

A **Compliance Assurance Record** (CAR) says what was checked, against
what, and with which result — for one unit of one run. It is the document a
tool hands on: to an auditor, to a colleague, or to Iltero Compass.
`iltero_schemas.models.car.CAR` is its shape.

A record is read by whoever receives it, including a verifier running on
someone else's machine against a record they were given. So the model
accepts exactly the fields below and nothing else: a reader validates the
document once, then works with values whose shape it knows.

## On this page

- [What a record holds](#what-a-record-holds)
- [Every path stays inside the record](#every-path-stays-inside-the-record)
- [Several stages, one record](#several-stages-one-record)
- [The record checks itself](#the-record-checks-itself)
- [Which package checked the record](#which-package-checked-the-record)

## What a record holds

| Part | What it says |
| --- | --- |
| `uuid`, `run_id`, `unit` | Which record this is, which run it belongs to and whether that run's id was derived locally or issued by a server, and which unit it covers |
| `pins` | For a run Iltero Compass opened, what it fixed when the run opened: the bundle, the checks owed, the environment policy's digest and whether a failed check stops the pipeline (`gate_mode`), and the oldest tool allowed — see [governed runs](09-governed-runs.md#the-pins). `null` for a run the tool opened on its own |
| `assurance_level`, `issuer`, `governance` | That this record is self-attested, who wrote it, and whether Iltero Compass manages the run. `governance.managed_by_compass` is true exactly when the record has `pins`. Only a record with `pins` may name Iltero Compass as its `issuer` |
| `subject`, `change`, `plan` | What the record is about: the environment, the unit and the commit; the change — every unit of it with its plan digest, sorted by unit name with none twice and the record's own unit among them, and its `digest` once known, which a record with a pre-deploy stage always names (see [the two digests](09-governed-runs.md#the-two-digests)); the plan's fingerprints and what Terraform said about it |
| `stages` | Per stage: what ran it, under which limits, what it hid, the files it wrote (the events, and the index of the assertions it compiled), and its own `coverage`, `verdict` and `assurance_status`. A stage given a scanner report also says which binding catalogue was in force and, per report, the tool, its version, what it was reading, and how many checks it held and left unbound |
| `events` | One event per check — see [what is recorded with a verdict](04-events.md) |
| `coverage` | The stages' coverage combined (see below): the resources in scope and how they were enumerated, assertions expected and where that set came from, how many of each were evaluated, the counts per status, and the gaps, each naming its stage when there are several |
| `verdict`, `assurance_status`, `complete` | The verdict and the exit code it produced; whether the evaluation finished; whether every expected stage has reported |
| `expected_stages`, `not_in_scope` | Which stages of the lifecycle the record expects, and each stage it leaves out with why: `project_config` (the project left it out on purpose, in the file `declared_in` names by path and digest) or `not_supported` (the tool that wrote the record cannot run it). Only the pre-deploy approval gate can be left out by a project |
| `deployment` | What the apply did, in the same shape the [post-deploy input](03-compiler-and-evaluation.md#what-goes-in) carries; `null` until the post-deploy stage has reported |
| `identity` | Which cloud resource each Terraform resource of the unit is, and which objects left the state in the apply and how, each bound or listed with the reason it could not be, with the state and plan they were read from — see [identity bindings](08-identity-bindings.md); present exactly when `deployment` is |
| `evidence_refs` | Every file the record cites, each with its digest, its size and where it sits |
| `integrity`, `retention_*` | How the record is bound together, and that no server assigned it a retention |

## Every path stays inside the record

`evidence_refs[].path`, and the paths in each stage record, are **relative
paths inside the record's own directory**: plain names joined by `/`, at
most six deep, never absolute, never containing `..`. A record that names
anything else is refused before a reader can follow it.

That rule is what lets a record be moved: beside the run that wrote it the
paths lead to the files it wrote, and in a bundle they lead to the bundle's
own copies. It is also what stops a record someone hands you from pointing
at the rest of your disk.

## Several stages, one record

Each stage counts its own checks against its own denominator and reaches its
own verdict: the plan stage over the resources the plan names, post-deploy
over the one deployment of the unit (`deployment_unit`, whose `source_digest`
is the digest of the record's `deployment` part). Only the plan stage
counts the plan's resources.

A stage's verdict follows from its own counts by one rule
(`iltero_schemas.models.coverage.stage_outcome`, `basis: status_counts`),
and names no stage. The exit code is the one that wins by
`VERDICT_PRECEDENCE` among:

- `6` (coverage gap) when nothing was expected, no subject was evaluated,
  fewer assertions were evaluated than expected, a check was not evaluated,
  or the run was truncated;
- `4` (evaluator error) when a check ended in an error, which also makes the
  stage incomplete;
- `3` (indeterminate) when a check was undecided;
- `1` (assertion failed) when a check failed;
- `0` otherwise.

The record's `coverage`, `verdict` and `assurance_status` are never counted
again; they are the stages combined by one rule
(`iltero_schemas.models.coverage.combine`), in the order the record expects
its stages:

- the resources in scope are the plan's;
- the checks, the assertions and the counts per status are summed;
- the assertion set is named by a digest over each stage's own set, so it
  is not the digest any one stage's set was pinned under (see below);
- the gaps are kept, each naming its stage;
- the verdict is the stage verdict whose exit code wins by
  `VERDICT_PRECEDENCE`, and names that stage (`basis: stage_precedence`) —
  a gap one stage found is never cured by another stage's checks. When two
  stages tie, the earlier one is named; read each stage for its own verdict;
- the record is incomplete when any stage is, and names the first that is.

Because the stages count different things, "checks = assertions × subjects"
holds within each stage, not across the whole record. The top level covers
the stages that have reported: a record still waiting on a stage says so in
`complete`, not in its verdict.

A record always starts at its plan stage. The plan is what was reviewed, so
a later stage is only meaningful against it:

- the first expected stage is `plan`, and the plan stage is present;
- the plan stage counts the resources of the plan the record names (its
  `source_digest` is the plan's `context_digest`);
- the plan stage was observed no later than the apply started, by the
  clocks that wrote them;
- `post_verify` comes only after `post_deploy`;
- `runtime` is never a stage of a record: what is observed at runtime
  belongs to no deployment.

## The record checks itself

The model enforces how the stages hold together: the rules above, each
stage record under its own name, every event belonging to a stage the record
has and grouped in stage order, each assertion evaluated by one stage
only, and every event naming the plan the record evaluated. Every event also
names the record's own run, how that run was opened (`run_id.basis`) and the
record's unit. It also recomputes every value a reader can
(`iltero_schemas.models.stages.derived_problems`): each stage carries one
event per check, its status counts are its events', its verdict and status
are the ones its counts give, and the record's top level is its stages
combined.

A record with `pins` agrees with them:

- it says it is managed by Iltero Compass;
- its environment is the pinned one;
- every stage counts its expected checks as `server_pinned`, and expects no
  more of them than were pinned;
- every stage and every check that names a bundle names the pinned one, and
  every check is of an assertion from that bundle
  (`assertion_source: compass_bundle`);
- every check is of a pinned assertion;
- no pre-deploy check read its facts from a local file.

A record without pins claims nothing only Iltero Compass can give. It is not
managed by Iltero Compass. It names no Iltero Compass bundle and no check
from one. It does not name Iltero Compass as its issuer, and its issuer's
identity is not verified. It has no facts from Iltero Compass
(`facts_source: server`), and no CI context verified with a run's context
key. It counts its expected checks as `locally_derived`.

These rules check that a record is consistent. They cannot prove that
Iltero Compass really opened the run: the record is not signed, so whoever
writes it can also write pins that agree with it. Only Iltero Compass can
confirm a run, by looking up its `run_id`.

Which pinned assertions belong to which stage is written in the signed
bundle, not in the record. So the model cannot compare a stage's own set of
checks with the pins. That comparison needs the bundle, and no tool makes it
yet.

## Which package checked the record

Each stage's `compiler`, and each event's, names the `iltero-schemas` package
it was checked with: its `contract_version`, how it was installed, and its
`contract_digest` — SHA-256 over the sorted `path,hash` lines the wheel's
`RECORD` file gives for the package's own files. It is the same value from the
published wheel as from its installation, and each release prints it.
`iltero_schemas.distribution.installed_identity()` reports it only after every
file `RECORD` lists hashes to its entry and the package directory holds no
other file (bytecode caches aside); an editable development install has no
digest. A tool that computes the digest from `RECORD` alone, without hashing
the files, names the same value but has not checked it.

A reader that reports an edited value as tampering, rather than as a record
it cannot read, validates with the context key `DERIVED_CHECKED_BY_READER`
set. The structure is still enforced; the recomputed values are not. Such a
reader must call `derived_problems` and act on what it returns before it
trusts any count or verdict.

A record accounts for every stage of a deployment's lifecycle (`plan`,
`pre_deploy`, `post_deploy`, `post_verify`): each is expected, or named once in
`not_in_scope` with why, never both. A record is `complete` exactly when every
stage it expects has reported. It describes the
deployment and its identities exactly when its post-deploy stage has
reported. Its identities are read from the applied plan its deployment names
and from the state its deployment was held to,
list each resource at most once in each half, all of its own unit, and name
as removed exactly the objects its deployment says left the state, with how
each left.
