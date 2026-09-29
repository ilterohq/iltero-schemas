# How an assertion is checked

Iltero does not check assertions itself. It turns each assertion into a
small program for **Open Policy Agent (OPA)**, a widely used policy engine,
and runs that program over the facts. This page explains that program: what
goes in, what comes out, and what is recorded so the result can be trusted
and re-checked later.

## On this page

- [Compiling](#compiling)
- [What goes in](#what-goes-in)
- [What comes out](#what-comes-out)
- [What the program may call](#what-the-program-may-call)
- [A rule written by hand](#a-rule-written-by-hand)
- [What is recorded with a result](#what-is-recorded-with-a-result)
- [The assertions that ship with the package](#the-assertions-that-ship-with-the-package)
- [For developers](#for-developers)

## Compiling

The package's compiler turns one assertion into one OPA program. The program
names the assertion it came from, where OPA should look for its answer, and
the fingerprint of its own bytes. Two properties matter:

- **Same assertion, same bytes.** Compiling an assertion always produces the
  exact same program. So anyone who receives a program can compile the
  assertion again and compare. If the bytes differ, the program is not what
  it claims to be and is refused. A signature says *who* published a program;
  recompiling says *what it does*.
- **Each program stands alone.** It contains the assertion's own rules
  followed by a copy of the shared runtime, which does the looking-up of
  values and the combining of results. There is no
  separate library to ship or trust. The program also states the assertion
  id, version and source fingerprint it was made from.

Each assertion gets its own key under `iltero.assertions`, so any number of
assertions can be loaded together.

## What goes in

OPA is run **once per assertion and per subject** (for example: once per
database instance). The input is one JSON document — the **assurance
context** — whose top-level keys are the parts listed for the stage in
[writing an assertion](02-assertions.md#paths). For a resource, `resource`
holds that one resource's state.

The package defines the shape of that document. Every part refuses unknown
keys, and the parts present must be exactly what the stage's **profile**
provides. The profile depends on the stage and on what kind of thing the
check is about. A required part that is missing, or a part the stage cannot
know, is refused by name. Three parts are always there:

| Part | What it says |
| --- | --- |
| `evaluation` | this evaluation run: `id`, `stage`, the runner's own `timestamp`, and the `assertion` (`id`, `version`) the input is for |
| `context` | the organization, workspace and environment, each only when known |
| `reference_time` | the time every expiry or ordering comparison uses: `value`, where it came from (`source`) and how far it can be trusted (`trust`) |

At the `plan` stage the profile adds `source` (the git commit, and the
repository, branch and pull request when the runner is told them), `change`
(the resources the plan changes, as a table of contents: `id`, `provider`,
`type`, `action`, `module`), `plan` (its fingerprints and what Terraform said
about it, plus the same table for every resource it covers), `subject` (the
resource's local `id` and the identities known for it) and `resource` (that
one resource: `id`, `provider`, `type`, `action`, `before`, `after`,
`related`, …). The conformance vectors include a complete example, with its
`input_digest` (see [conformance vectors](../development/03-conformance-vectors.md)).

At the `pre_deploy` stage the subject is the change, and the profile adds
`evaluations`, `approvals` and `exceptions`: facts only Iltero Compass holds.
Each is a list, or the unknown marker
`{"__unknown": true, "reason": "server_facts_unavailable"}` when the fact
could not be supplied, so a check that reads it is `unknown` rather than
failed — see [facts only Iltero Compass holds](10-server-facts.md).
The conformance vectors include a complete example.

At the `post_deploy` stage the subject is the deployment rather than a
resource, and the profile adds `deployment`:

- `plan`: the plan the pipeline says it gave Terraform to apply, by the same
  fingerprints the plan stage recorded. `ILT.DEPLOYMENT.PLAN_BINDING` checks
  it is the evaluated plan; that proves the file the pipeline supplied
  matches the approved one, not that Terraform read it. It ships with the
  package, and a runner evaluates
  it at every post-deploy stage, whatever a project's own assertions are.
  When it fails, the runner records `plan_superseded`: another plan was
  applied.
- `apply`: the apply log it was read from (`source`: the digest of its bytes,
  the Terraform version that wrote it, and the lines it could not read:
  `noise_lines`, output the pipeline mixed in, and `damaged_lines`, messages
  of Terraform's own that were cut or broken, and `interrupted_operations`,
  operations it saw start and never saw end), the state after the apply it
  was held to (`state`: its digest and the Terraform version that wrote it),
  and every change of the applied
  plan, once each, sorted by address. A change names its `action`, the
  operations it needed (`required`: a replacement needs a create, and a
  delete unless it only forgets its old object) the ones the log shows
  completed (`completed`), and its `outcome` —
  `applied`, `errored` (an operation failed or never ended, or only part of
  a replacement ran), `not_attempted` (nothing started) or `no_operation` (a
  rename, an import or a resource taken out of management, which needs no
  operation and which the state after the apply shows done). A rename names
  the address it came from (`moved_from`); `imported` says the change
  brought an existing resource under management. `summary` holds
  Terraform's own counts, present only when every change was made and equal
  to what the changes show; `timing` holds when the first operation started
  and the last message about any operation, by the clock that wrote the log
  (`trust: asserted`), and is present exactly when an operation ran. The outcomes are the log's word, held to the
  applied plan by address, action and operation and to the state by which
  resources it holds, not by their values; `basis` says so.

  When the log lost messages (`damaged_lines` or `interrupted_operations`
  above 0), what it did not see end is taken from the state where the state
  settles it, and each change says how it is known (`basis`: `log`, `state`,
  or `unsettled`). The state settles only a create, a delete or a
  replacement, as applied, errored or unknown. The state proves a
  create or a delete finished, but not whether an attempt that left nothing
  failed or never started, and not whether an update took effect. A fact
  neither source gives is written as the evaluator's unknown marker,
  `{"__unknown": true, "reason": "apply_log_incomplete"}`: a check that reads
  it is `unknown`, and one that does not is evaluated as usual. Only an
  update's operations may stay unsettled; a change that can remove an object
  from the state never does. `summary` is that marker when the log lost
  messages and holds none. The apply's `basis` is then
  `log_and_state_where_log_incomplete`.
- `superseded_by`: the reason the pipeline gives for applying a plan other
  than the evaluated one. It is the pipeline's word, and it does not make the
  applied plan an approved one: `ILT.DEPLOYMENT.PLAN_BINDING` still fails. It is refused
  when the applied plan is the evaluated one.

In both `plan` parts the binary's `artifact_digest` is present exactly when
`artifact_digest_basis` is `plan_binary`. `post_deploy.json` beside the plan
example is a complete one.

Two conventions hold throughout: a resource is named by its Terraform
address (`id` on the subject, the resource and the table of contents;
`address` inside `resource.related`, which embeds the other resources as
the plan adapter observed them), and `provider` is the short name an
assertion targets (`aws`), with the full source address in
`provider_source`. A name that redaction may hide (`resource.name`, a related
resource's `address`) accepts a `__redacted` marker in its place, so a
hidden name is still a fact and never a refused document. The model coerces
nothing: `"true"` is not a boolean, and a timestamp must be a real date.

The context carries nothing the evaluator does not need — no evaluator
version, bundle fingerprint or provenance. The tool that runs OPA records
those around the result.

Two special objects may appear in place of a value:

```json
{"__redacted": true, "reason": "terraform_sensitive", "present": true, "type": "string"}
{"__unknown": true, "reason": "known_after_apply", "present": true}
```

The first means "there is a value here, but it is sensitive and was hidden".
The second means "the value is not known yet". A check that reaches either
comes out unknown. The `reason` of an `__unknown` marker is copied into the
result only if it is a short lower-case word (`[a-z][a-z0-9_]*`, at most 64
characters); otherwise the result says `unspecified`.

`resource.related` is the list of other resources that refer to this one at
the same stage. Each entry is `{address, type, relation, resource}`, where
`relation` is one of `attached_to`, `member_of`, `targets`, `configures`, and
`resource` is that resource as observed — for a plan, `{address, type,
action, before, after}` — or a marker if it was not observed.

Building the input, choosing the subjects and recording the input's
fingerprint is the job of the tool that runs OPA (the Iltero CLI or Iltero
Compass).

## What comes out

Asking for `evaluate` returns a list with exactly one result:

```json
[{
  "subject": {"kind": "resource", "id": "aws_db_instance.payments"},
  "status": "pass",
  "reason": "assert: true",
  "observations": {
    "when": "true",
    "predicates": [
      {"path": "context.environment.name", "op": "equal", "expected": "production", "actual": "production",
       "status": "true", "clause": "when", "index": 0},
      {"path": "deployment.plan.digest", "op": "equal", "expected": {"ref": "plan.digest"}, "resolved": "sha256:…",
       "actual": "sha256:…", "status": "true", "clause": "assert", "index": 1},
      {"path": "resource.related", "op": "exists", "expected": null, "actual": {"type": "array", "count": 2},
       "status": "true", "matched": 1, "clause": "assert", "index": 2}
    ],
    "unknown": null
  }
}]
```

| Field | Meaning |
| --- | --- |
| `subject` | The `kind` and `id` from the input, nothing else. `null` if the input had no subject |
| `status` | `pass`, `fail`, `unknown` or `not_applicable`. A program never says `error` or `not_evaluated`; those come from the tool running it |
| `reason` | One line saying why. `assert: true`; `assert: false; predicate 3 is false: <path> <comparison>`; `assert: false; a negated expression held` (a `not` whose inner checks all held); `<path>: <reason>` when unknown; `when: false` |
| `observations.when` | How the `when` condition came out, or `null` if there was none |
| `observations.predicates` | One entry per check, `when` first, in the order written. Each says which clause it belongs to and its position (`index`), so a reason can point at exactly one check. An `exists` gives one entry with `matched`, the number of elements that satisfied `where` (`0` if none did but some element was unknown; `null` if the list itself was unknown). Checks inside `where` are not listed one element at a time |
| `expected` / `resolved` / `actual` | What the check compared with, and what it found. A comparison with another path shows `{"ref": path}` and, under `resolved`, the value found there |
| `observations.unknown` | The first value that could not be resolved, as `{path, reason}`, or `null` |

How large an answer can be is fixed by the language's own limits. A `reason`
is at most 2 KiB. The observations are at most 512 KiB of canonical JSON and
at most 4 levels deep. Each subject field is at most 128 characters. Every
assertion the parser accepts answers within these limits, and a consumer
refuses anything larger.

Values in observations are kept small on purpose. Short texts (up to 128
characters), numbers, `true`/`false`, and lists of up to four such values are
recorded as they are. Anything bigger is recorded by its shape only:
`{"type": "string", "length": 300}`, `{"type": "array", "count": 12}`,
`{"type": "object"}`. This means a program can never copy large or sensitive
parts of the input into evidence. (The tool running it still puts an upper
bound on the whole result.)

## What the program may call

OPA offers about two hundred built-in functions, including ones that talk to
the network or read the clock. Iltero only allows 83 of them, listed in the
package's capabilities allowlist. The list was built from nothing, adding
only comparison, arithmetic, text, list, type-check, `object.*`, `json.*`
(object operations only) and `semver.*` functions. Nothing in it can reach
the network, the clock, random numbers, the machine it runs on, regular
expressions, tokens, certificates, or parse text formats.

This list must be given to OPA both when building a bundle
(`opa build --capabilities`) and when running it (`opa eval --capabilities`),
for generated and hand-written programs alike. Its fingerprint is recorded
with every evaluation (`capabilities_digest`), so a later re-check uses the
same list. The conformance vectors list every function of the pinned OPA
release that is left out.

## A rule written by hand

Some rules need logic the language does not have. Those are written in Rego
and kept as a **custom policy source**: a directory of `.rego` files with a
manifest saying which assertion each one decides, at which stage and about what. The assertion
document stays engine-neutral — it never carries a package, a query or a
Rego field — and the manifest carries everything an assertion carries except
the logic.

Such a policy answers in the shape described above. It declares the same
package a compiled program for that assertion id would declare
(`iltero.assertions["<ID>"]`), and it is bound by the same capability list.
What a tool then does with it is that tool's business, for example how a
record says which of its rules were compiled and which were written. The CLI
describes it under "When the assertion language is not enough".

## What is recorded with a result

| Fingerprint | Taken over |
| --- | --- |
| `assertion_source_digest` | the assertion's logic: id, version, type, stage, target, `when`, `assert`. The title is not part of it; the tool records the title next to it |
| `compiled_digest` | the program's bytes. Must equal a fresh compilation |
| `compiler.version` | the compiler's version, together with this package's version |
| `capabilities_digest` | the capabilities allowlist |
| `plan.digest` | a Terraform plan as `terraform show -json` renders it, minus the keys that describe the rendering rather than the change (`timestamp`, `terraform_version`, `format_version`, `prior_state`, `resource_drift`, `relevant_attributes`). The rule has a version of its own, recorded with the digest. The CLI computes it from the plan it evaluates and again from the plan the apply used; the two must match. It binds to the saved plan file: a plan made again from the same code can differ. Iltero Compass records the value; it cannot recompute it from the redacted artifact it receives |

All fingerprints are computed over bytes produced the same way everywhere:
RFC 8785 canonical JSON. Each is written as `sha256:<lowercase hex>`.

## The assertions that ship with the package

The package holds ten ready-made assertions:

- for a Terraform plan: RDS storage is encrypted, RDS is not public, RDS
  backups are kept at least seven days, and a production baseline combining
  those with the instance class; an S3 bucket blocks public access (checked
  through the related `aws_s3_bucket_public_access_block` resource);
- before deploying: a production change has a security reviewer's approval;
  the same for a change that touches IAM, network or key resources; an
  approved, unexpired exception names the assertion being evaluated (the tool
  sets `evaluation.assertion.id` to the assertion being excepted);
- after deploying: the plan that was applied is the plan that was evaluated;
- at runtime: a check that went from pass to fail is explained by a recorded
  deployment or an approved exception.

They are also part of the conformance vectors (see
[conformance vectors](../development/03-conformance-vectors.md)).

## For developers

Compiling an assertion:

```python
from iltero_schemas.ast import parse
from iltero_schemas.compiler import COMPILER_VERSION, compile

module = compile(parse(text))
module.assertion_id   # "ACME.AWS.RDS.PRODUCTION_BASELINE"
module.package        # 'iltero.assertions["ACME.AWS.RDS.PRODUCTION_BASELINE"]'
module.entrypoint     # 'data.iltero.assertions["ACME.AWS.RDS.PRODUCTION_BASELINE"].evaluate'
module.source         # the program, as bytes
module.digest         # "sha256:..." — the fingerprint of those bytes
```

Where each part of this page lives:

| On this page | In the package |
| --- | --- |
| The shared runtime | `compiler/runtime.rego` |
| The assurance context and a stage's profile | `models.context.AssuranceContext`, `profiles.profile_for(stage, target_kind)` |
| The `deployment` part | `models.deployment` |
| The built-in plan check and its failure reason | `assertions.PLAN_BINDING`, `assertions.FAIL_REASONS` |
| The answer's limits | `compiler.REASON_MAX_BYTES`, `OBSERVATIONS_MAX_BYTES`, `OBSERVATIONS_MAX_DEPTH`, `SUBJECT_FIELD_MAX_CHARS` |
| The capabilities allowlist and its fingerprint | `opa.CAPABILITIES`, `opa.CAPABILITIES_DIGEST`; the functions left out are in `vectors/opa/not_allowed.txt` |
| A custom policy source's manifest, and its package | `models.policy_source.PolicySourceManifest`, `compiler.package_of` |
| The fingerprints | `ast.source_digest`, `module.digest`, `compiler.COMPILER_VERSION`, `canonical.plan_digest` (`PLAN_DIGEST_VERSION`), `canonical.canonical_bytes`, `canonical.digest`, `canonical.digest_of` |
| The ready-made assertions | `src/iltero_schemas/assertions/` |
| The example contexts | `src/iltero_schemas/vectors/contexts/`: `plan_resource.json`, `pre_deploy_change.json`, `post_deploy.json`, and their digests in `digests.json` |

Module names are under `iltero_schemas`. `module.digest` is a property of
the compiled result.
