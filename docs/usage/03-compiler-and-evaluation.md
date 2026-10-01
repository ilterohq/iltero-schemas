# How an assertion is checked

Iltero does not check an assertion itself. It turns each assertion into a
small program for **Open Policy Agent (OPA)**, a widely used policy engine.
It then runs that program over the facts. This page explains the program:
what goes in, what comes out, and what Iltero records so that anyone can
trust the result and check it again later.

## On this page

- [Compiling](#compiling)
- [What goes in](#what-goes-in)
  - [The plan stage](#the-plan-stage)
  - [The plan's fingerprints](#the-plans-fingerprints)
  - [The pre-deploy stage](#the-pre-deploy-stage)
  - [The post-deploy stage](#the-post-deploy-stage)
  - [When the apply log lost messages](#when-the-apply-log-lost-messages)
  - [Deposed objects](#deposed-objects)
  - [Conventions that hold everywhere](#conventions-that-hold-everywhere)
- [What comes out](#what-comes-out)
- [What the program may call](#what-the-program-may-call)
- [A rule written by hand](#a-rule-written-by-hand)
- [What is recorded with a result](#what-is-recorded-with-a-result)
- [The assertions that ship with the package](#the-assertions-that-ship-with-the-package)
- [For developers](#for-developers)

## Compiling

The package's compiler turns one assertion into one OPA program. The
program states the assertion it came from: its id, its version and the
fingerprint of its source. It also says where OPA should look for the
answer. Two properties matter.

- **Same assertion, same bytes.** Compiling an assertion always gives the
  exact same program. So anyone who receives a program can compile the
  assertion again and compare. If the bytes differ, the program is not what
  it claims to be, and a consumer refuses it. A signature says *who*
  published a program. Recompiling says *what it does*.
- **Each program stands alone.** It holds the assertion's own rules,
  followed by a copy of a shared runtime. The runtime looks up values and
  combines results. There is no separate library to ship or to trust.

Each assertion gets its own name under `iltero.assertions`, so any number of
assertions can be loaded together. A tool asks OPA for the program's answer
at `data.iltero.assertions["<ID>"].evaluate`, with the assertion's id in
place of `<ID>`. The [documentation index](../README.md#how-the-pieces-fit-and-what-a-record-shows)
shows the full `opa eval` command.

## What goes in

A tool runs OPA **once per assertion and per subject**. A subject is the
thing a check is about, for example one database instance. The input is one
JSON document, called the **assurance context**. Its top-level keys are the
parts the stage provides, as listed in
[writing an assertion](02-assertions.md#paths). For a resource, `resource`
holds that one resource.

The package defines the shape of this document strictly:

- Every part refuses keys it does not know.
- The parts present must be exactly the ones the stage's **profile**
  provides. The profile depends on the stage and on the kind of subject.
- The package refuses a document that lacks a required part, or that holds
  a part the stage cannot know. The error names the part.
- The package converts nothing. `"true"` is not a boolean, and a timestamp
  must be a real date.

Three parts are present at every stage:

| Part | What it says |
| --- | --- |
| `evaluation` | This evaluation: its `id`, its `stage`, the runner's own `timestamp`, and the `assertion` (`id`, `version`) the input is for. |
| `context` | The organization, workspace and environment. Each is present only when known. |
| `reference_time` | The time that every expiry or ordering comparison uses. It holds the `value`, where it came from (`source`) and how far it can be trusted (`trust`). |

The context carries nothing the evaluator does not need. It holds no
evaluator version, bundle fingerprint or provenance. The tool that runs OPA
records those around the result.

Building the input, choosing the subjects and recording the input's
fingerprint is the job of the tool that runs OPA, which is the Iltero CLI or
Iltero Compass.

### The plan stage

At the `plan` stage the subject is one resource. The profile adds these
parts:

| Part | What it says |
| --- | --- |
| `source` | The git commit. It also names the repository, branch and pull request when the runner is told them. |
| `change` | The resources the plan changes, as a table of contents. Each entry has an `id`, `provider`, `type`, `action` and `module`. |
| `plan` | The infrastructure-as-code (IaC) tool that wrote the plan (`tool`, such as `terraform`) and that tool's version (`tool_version`, `null` when the plan does not say). Then the plan format's version (`format_version`), the plan's fingerprints, and the same table of contents for every resource the plan covers. The fingerprints are explained [below](#the-plans-fingerprints). |
| `subject` | The resource's local `id`, the identities known for it, and whether a cloud identity is bound to it yet (`authority`). |
| `resource` | That one resource: `id`, `provider`, `type`, `action`, `before`, `after`, `related`, and more. |

`resource.related` lists the other resources that refer to this one. Each
entry holds:

- `address` and `type`: which resource it is.
- `relation`: how it relates. It is one of `attached_to`, `member_of`,
  `targets` or `configures`.
- `match`: whether the reference matched this one instance (`instance`) or
  every instance of a repeated resource (`every_instance`).
- `via`: where the reference was written, such as the attribute names.
- `resource`: that resource as the plan shows it (`address`, `type`,
  `action`, `before`, `after`). It is `null` when its values were left out.

The conformance vectors include a complete example with its
`input_digest`, the fingerprint of the whole input document (see
[conformance vectors](../development/03-conformance-vectors.md)).

### The plan's fingerprints

The `plan` part names the plan by up to two fingerprints.

- `digest` is the fingerprint of the plan as `terraform show -json` prints
  it. Iltero computes it by a fixed rule, described in
  [what is recorded with a result](#what-is-recorded-with-a-result).
  `digest_version` names the version of that rule.
- `artifact_digest` is the fingerprint of the saved plan file itself. That
  is the binary file `terraform plan -out` writes. A tool has it only when
  someone gave it that file.
- `artifact_digest_basis` says which case holds. It is `plan_binary` when
  the tool was given the file, and then `artifact_digest` is present. It is
  `not_provided` otherwise, and then `artifact_digest` is `null`.

At the post-deploy stage, `deployment.plan` names the applied plan with the
same three fields.

### The pre-deploy stage

At the `pre_deploy` stage the subject is the change. The profile adds
`evaluations`, `approvals` and `exceptions`. These are facts only Iltero
Compass holds.

Each of the three is a list. When Iltero Compass could not supply a fact,
the part holds the unknown marker
`{"__unknown": true, "reason": "server_facts_unavailable"}` instead. A check
that reads it then comes out `unknown` rather than failed. See
[facts only Iltero Compass holds](10-server-facts.md). The conformance
vectors include a complete example.

### The post-deploy stage

At the `post_deploy` stage the subject is the deployment, not a resource.
The profile adds `deployment`. It describes which plan was applied and what
the apply did. It has three parts.

**`plan`** is the plan the pipeline says it gave Terraform to apply. It is
named by the same fingerprints the plan stage recorded. The assertion
`ILT.DEPLOYMENT.PLAN_BINDING` checks that it is the evaluated plan.

- The check proves that the file the pipeline supplied matches the approved
  one. It does not prove that Terraform read that file.
- The assertion ships with this package. A runner evaluates it at every
  post-deploy stage, whatever a project's own assertions are.
- When it fails, the runner records the reason `plan_superseded`, which
  means another plan was applied.

**`apply`** says what the apply did. Iltero reads it from two sources. The
apply log is the stream of messages `terraform apply -json` prints. The
state is what `terraform show -json` prints after the apply.

| Field | What it says |
| --- | --- |
| `source` | The apply log: the digest of its bytes, the IaC tool that wrote it (`tool`) and its version (`tool_version`), and three counts of lines Iltero could not use. `noise_lines` counts lines the pipeline mixed into the log. `damaged_lines` counts Terraform messages that were cut off or broken. `interrupted_operations` counts operations the log saw start but never saw end. |
| `state` | The state after the apply: its digest, the IaC tool that wrote it (`tool`) and its version (`tool_version`). The version is `null` when the state holds nothing. Iltero compares the outcomes with it. |
| `changes` | Every change of the applied plan, once each, sorted by address. See the next table. |
| `summary` | Terraform's own counts (`added`, `changed`, `imported`, `removed`). It is present only when every change was made and the counts equal what the changes show. It is `null` when Terraform stopped before reporting counts. |
| `timing` | When the first operation started, and when the log last mentioned any operation. The times come from the apply log (`source: apply_log`), so from the clock of the machine that wrote it (`trust: asserted`). The field is present exactly when an operation ran. |
| `basis` | How Iltero worked out the outcomes (see below). |

The apply log and the state must name the same IaC tool. That tool must
also be the one that wrote the plan. The package refuses a document that
names two different tools.

Each change says this:

| Field | What it says |
| --- | --- |
| `address`, `action` | Which resource, and what the plan meant to do to it. |
| `required` | The operations the change needed. A replacement needs a create. It also needs a delete, unless it only stops managing the old object. |
| `completed` | The operations the log shows completed. |
| `outcome` | `applied`, `errored`, `not_attempted` or `no_operation` (see below). |
| `basis` | Where the outcome came from. `log` means the apply log. `state` means the state after the apply. `unsettled` means neither source could tell. |
| `moved_from` | For a rename, the address the resource came from. |
| `imported` | Whether the change brought an existing resource under management. |
| `deposed` | For a deposed object, its key (see [deposed objects](#deposed-objects)). It is `null` for every other change. |

The four outcomes mean:

- `applied`: every operation the change needed completed.
- `errored`: an operation failed or never ended, or only part of a
  replacement ran.
- `not_attempted`: nothing started.
- `no_operation`: the change needed no operation, and the state after the
  apply shows it done. This is a rename, an import, or a resource taken out
  of management.

**How Iltero works out the outcomes.** Normally each outcome comes from the
apply log. Iltero compares it with the applied plan, by address, action and
operation. It also compares it with the state, but only by which resources
the state holds, not by their values. In this case the apply's `basis` is
`log_held_to_plan_and_state_presence`. Deposed objects are the one exception
(see [deposed objects](#deposed-objects)).

**`superseded_by`** is the reason the pipeline gives for applying a plan
other than the evaluated one. Today the only reason is
`basis: dependency_replan`. Iltero records it as the pipeline's claim and
does not check it. It does not make the applied plan an approved one, so
`ILT.DEPLOYMENT.PLAN_BINDING` still fails. The package refuses the field
when the applied plan is the evaluated one.

### When the apply log lost messages

Sometimes the log loses messages. Then `damaged_lines` or
`interrupted_operations` is above 0. For each operation the log did not see
end, Iltero then looks at the state after the apply. Each change's `basis`
says where its outcome came from.

- The state can decide the outcome of a create, a delete or a replacement,
  because each of them adds an object to the state or removes one. The state
  decides it as applied, errored or unknown.
- The state shows that a create or a delete finished. It cannot show
  whether an attempt that left nothing behind failed or never started. It
  cannot show whether an update took effect, because an update leaves the
  object in the state either way.
- When neither source gives a fact, Iltero writes the unknown marker
  `{"__unknown": true, "reason": "apply_log_incomplete"}`. A check that
  reads it comes out `unknown`. A check that does not read it is evaluated
  as usual.
- Only an update can end with `basis: unsettled`. Every other change can
  remove an object from the state, and Iltero never guesses what left the
  state. So Iltero always takes those outcomes from the state, even when
  the answer is unknown.
- `summary` is the same marker when the log lost messages and holds no
  counts.

The apply's `basis` is then `log_and_state_where_log_incomplete`.

### Deposed objects

A **deposed object** is an old copy of a resource that an earlier
replacement left in the state. Terraform sets the old copy aside when it
creates the resource's new object before it deletes the old one. If that
delete fails, the old copy stays in the state under the same address, with
a key of its own. The next plan plans its delete.

That delete is a change of its own:

- The change is named by the resource's address and the object's `deposed`
  key, which is 8 lowercase hex characters.
- It is listed after the change to the resource's current object.

Terraform's apply log names the object when its delete starts, but not when
the delete finishes. So Iltero always takes a deposed object's outcome from
the state after the apply (`basis: state`), whether or not the log lost
messages:

| The object after the apply | Outcome |
| --- | --- |
| Gone from the state | `applied` |
| Still there, and its delete started | `errored` |
| Still there, and its delete never started | `not_attempted` |
| Still there, and the log lost messages | the unknown marker, because a failed delete and one never started look the same |

"Gone from the state" means Terraform removed the object from the state
after its delete returned. Iltero trusts that as much as a delete the log
reports. It is not a check of the cloud. To find which cloud object it was,
read the old object's values in the applied plan.

The identity document does not list a destroyed deposed object under
`removed`. It only counts it, in `deposed_destroyed` (see
[identity bindings](08-identity-bindings.md#deposed-objects)).

Terraform counts the operations it ran by address. So the `removed` count
in `summary` includes a deposed object's delete when that delete is the
only change at its address. It may leave the delete out when another change
shares the address.

### Conventions that hold everywhere

- **A resource is named by its Terraform address.** The address is `id` on
  the subject, on the resource and in the table of contents. Inside
  `resource.related` it is `address`.
- **`provider` is the short name** an assertion targets, such as `aws`. The
  full source address is in `provider_source`.
- **A hidden name is still a fact.** Where redaction may hide a name
  (`resource.name`, a related resource's `address`), the field accepts a
  `__redacted` marker instead. A hidden name never makes the document
  invalid.

Two special objects may appear in place of a value:

```json
{"__redacted": true, "reason": "terraform_sensitive", "present": true, "type": "string"}
{"__unknown": true, "reason": "known_after_apply", "present": true}
```

The first means "there is a value here, but it is sensitive and was
hidden". The second means "the value is not known yet". A check that
reaches either comes out unknown.

The result copies the `reason` of an `__unknown` marker only when it is a
short word. It must be 1 to 64 characters of lowercase letters, digits and
`_`, and must not start with `_` or `0`. Otherwise the result says
`unspecified`.

`post_deploy.json`, beside the plan example in the conformance vectors, is
a complete post-deploy input.

## What comes out

When asked for `evaluate`, the program returns a list with exactly one
result. Here is the answer for the production database rule from
[writing an assertion](02-assertions.md), at the `plan` stage, for a
production database that is encrypted and private:

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
      {"path": "resource.after.storage_encrypted", "op": "equal", "expected": true, "actual": true,
       "status": "true", "clause": "assert", "index": 1},
      {"path": "resource.after.publicly_accessible", "op": "equal", "expected": false, "actual": false,
       "status": "true", "clause": "assert", "index": 2}
    ],
    "unknown": null
  }
}]
```

| Field | Meaning |
| --- | --- |
| `subject` | The `kind` and `id` from the input, and nothing else. It is `null` if the input had no subject. |
| `status` | `pass`, `fail`, `unknown` or `not_applicable`. A program never says `error` or `not_evaluated`. Only the tool running it says those. |
| `reason` | One line that says why (see below). |
| `observations.when` | How the `when` condition came out, or `null` if there was none. |
| `observations.predicates` | One entry per check (see the numbering below). Each entry names its clause (`when` or `assert`) and its number (`index`). |
| `expected`, `resolved`, `actual` | What the check compared with, and what it found. When a check compares with another path, `expected` is `{"ref": "<that path>"}` and `resolved` holds the value found there. |
| `observations.unknown` | The first value that could not be resolved, as `{path, reason}`, or `null`. |

**How the checks are numbered.** The program numbers the checks from 0. It
numbers the checks of `when` first, then those of `assert`, each in the
order they are written. An `exists` check counts as one check. The checks
inside its `where` get no number of their own. A failed result names a
check by this number.

The `reason` takes one of these forms:

- `assert: true` for a pass.
- `assert: false; predicate 3 is false: <path> <comparison>` for a fail.
  Here check number 3 was false.
- `assert: false; a negated expression held` for a fail caused by a `not`
  whose inner checks all held.
- `<path>: <reason>` for an unknown result.
- `when: false` for a result that is not applicable.

An `exists` check gives one entry. Its `matched` field counts the elements
that satisfied `where`. It is `0` if none did but some element was unknown,
and `null` if the list itself was unknown. The checks inside `where` are not
listed one element at a time.

An answer has fixed size limits. A `reason` is at most 2 KiB. The
observations are at most 512 KiB of canonical JSON and at most 4 levels
deep. Each subject field is at most 128 characters. Every assertion the
parser accepts answers within these limits, and a consumer refuses anything
larger.

Values in the observations are kept small on purpose:

- Iltero records short texts (up to 128 characters), numbers, `true` and
  `false` as they are. It also records lists of up to four such values as
  they are.
- Iltero records anything bigger by its shape only, such as
  `{"type": "string", "length": 300}`, `{"type": "array", "count": 12}` or
  `{"type": "object"}`.

So a program can never copy large or sensitive parts of the input into
evidence. The tool running it still puts an upper limit on the whole result.

## What the program may call

OPA offers about two hundred built-in functions. Some of them reach the
network or read the clock. Iltero allows only 83 of them, listed in the
package's **capabilities allowlist**.

The list was built from nothing. It holds only comparison, arithmetic,
text, list and type-check functions, the `object.*` functions, the `json.*`
functions that work on objects, and the `semver.*` functions. Nothing in it
can reach the network, the clock, random numbers or the machine it runs on.
Nothing in it handles regular expressions, tokens or certificates, or parses
a text format.

A tool must give this list to OPA both when building a bundle
(`opa build --capabilities`) and when running it
(`opa eval --capabilities`). This holds for compiled and hand-written
programs alike. The list's fingerprint is recorded with every evaluation
(`capabilities_digest`), so a later re-check uses the same list. The
conformance vectors list every function of the pinned OPA release that the
list leaves out.

## A rule written by hand

Some rules need logic the assertion language does not have. Those are
written in Rego, OPA's own language, and kept as a **custom policy source**.
A custom policy source is a directory of `.rego` files with a manifest. For
each file, the manifest says which assertion it decides, at which stage and
about what.

The assertion document stays independent of any engine. It never carries a
package name, a query or a Rego field. The manifest carries everything an
assertion carries except the logic.

A hand-written policy follows the same rules as a compiled one:

- It answers in the shape described in [what comes out](#what-comes-out).
- It declares the same package name a compiled program for that assertion
  id would declare (`iltero.assertions["<ID>"]`).
- It is bound by the same capabilities allowlist.

Each tool decides how it uses such a policy. For example, it decides how a
record shows which rules were compiled and which were written by hand. The
Iltero CLI documentation describes its own rules on its page "When the
assertion language is not enough".

## What is recorded with a result

Iltero records a set of fingerprints with each result. Together they let
anyone check later exactly what ran.

| Fingerprint | What it covers |
| --- | --- |
| `assertion_source_digest` | The assertion's logic: id, version, type, stage, target, `when` and `assert`. The title is not part of it. The tool records the title next to it. |
| `compiled_digest` | The program's bytes. It must equal a fresh compilation. |
| `compiler.version` | The compiler's version, recorded together with this package's version. |
| `capabilities_digest` | The capabilities allowlist. |
| `plan.digest` | The Terraform plan (see below). |

`plan.digest` covers a Terraform plan as `terraform show -json` renders it.
Iltero first removes the top-level keys that describe the rendering rather
than the change: `timestamp`, `terraform_version`, `format_version`,
`prior_state`, `resource_drift` and `relevant_attributes`.

- The rule has a version of its own, which Iltero records with the digest.
- The CLI computes the digest from the plan it evaluates. It computes it
  again from the plan the apply used, and the two must match.
- The digest binds to the saved plan file. A plan made again from the same
  code can differ.
- Iltero Compass records the value. It cannot recompute it, because it
  receives only the redacted plan.

Every fingerprint is computed over bytes produced the same way everywhere,
as RFC 8785 canonical JSON. Each is written as `sha256:<lowercase hex>`.

## The assertions that ship with the package

The package holds ten ready-made assertions.

For a Terraform plan:

- RDS storage is encrypted.
- RDS is not publicly accessible.
- RDS backups are kept for at least seven days.
- A production baseline for RDS combines those three with a check on the
  instance class.
- An S3 bucket blocks public access. The check reads the related
  `aws_s3_bucket_public_access_block` resource.

Before deploying, two approval checks and one exception check:

- A production change has a security reviewer's approval.
- A change that touches IAM, network or key resources has a security
  reviewer's approval.
- An approved, unexpired exception names the assertion being evaluated. The
  tool sets `evaluation.assertion.id` to the assertion being excepted.

After deploying:

- The plan that was applied is the plan that was evaluated.

At runtime:

- A check that went from pass to fail is explained by a recorded deployment
  or an approved exception.

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

Where each part of this page lives (module names are under `iltero_schemas`):

| On this page | In the package |
| --- | --- |
| The shared runtime | `compiler/runtime.rego` |
| The assurance context and a stage's profile | `models.context.AssuranceContext`, `profiles.profile_for(stage, target_kind)` |
| The `deployment` part | `models.deployment` |
| The IaC tools a plan or a deployment may name | `models.iac.IacTool` |
| The built-in plan check and its failure reason | `assertions.PLAN_BINDING`, `assertions.FAIL_REASONS` |
| The answer's limits | `compiler.REASON_MAX_BYTES`, `OBSERVATIONS_MAX_BYTES`, `OBSERVATIONS_MAX_DEPTH`, `SUBJECT_FIELD_MAX_CHARS` |
| The capabilities allowlist and its fingerprint | `opa.CAPABILITIES`, `opa.CAPABILITIES_DIGEST`; the functions left out are in `vectors/opa/not_allowed.txt` |
| A custom policy source's manifest, and its package | `models.policy_source.PolicySourceManifest`, `compiler.package_of` |
| The fingerprints | `ast.source_digest`, `module.digest` (a property of the compiled result), `compiler.COMPILER_VERSION`, `canonical.plan_digest` (`PLAN_DIGEST_VERSION`), `canonical.canonical_bytes`, `canonical.digest`, `canonical.digest_of` |
| The ready-made assertions | `src/iltero_schemas/assertions/` |
| The example contexts | `src/iltero_schemas/vectors/contexts/`: `plan_resource.json`, `pre_deploy_change.json`, `post_deploy.json`, and their digests in `digests.json` |
