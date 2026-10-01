# What is recorded with a verdict

Every check produces one **assurance event**. The event holds the verdict.
It also holds everything needed to say who produced the verdict and to
reproduce it.

The evaluator's answer is not the event. The tool that ran the evaluator
wraps the answer with **provenance**, the facts about where the verdict came
from. The policy program sets nothing in the event itself.

This package defines the shape of an event as a tool submits it. The
package refuses keys it does not know, and it never changes a value's type.

## On this page

- [The parts of an event](#the-parts-of-an-event)
- [Six statuses, each with its reasons](#six-statuses-each-with-its-reasons)
  - [Who produced the verdict](#who-produced-the-verdict)
- [What is not in an event](#what-is-not-in-an-event)
- [For developers](#for-developers)

## The parts of an event

| Part | What it says |
| --- | --- |
| `assertion` | The assertion's `id` and `version`, and the `digest` of the assertion document as it was read. |
| `subject` | What the verdict is about: its `kind`, its local `id`, the `identities` known for it, and whether a cloud identity is bound to it (`authority`: `authoritative` or `unresolved`). The `id` is absent only when the assertion had no subject in scope at all. |
| `evaluation` | The `stage` and the `status`. It also holds the runner's own `status_reason` and `status_detail`, and what the policy said: its `reason` and `observations`. |
| `provenance` | Where the verdict came from (see the next table). |
| `observed_at` | The run's timestamp, by the runner's clock. Every event of one run carries the same value. |

The provenance holds these fields:

| Field | What it says |
| --- | --- |
| `run` | The run's `id`, and where that id came from. `server_issued` means Iltero Compass issued it. `locally_derived` means the tool made it up on its own. It also names the `unit`, the part of a project that Terraform plans and applies as one. |
| `source_commit`, `plan_digest` | The git commit and the plan the check is about. |
| `input_digest` | The fingerprint of the exact document the evaluator saw. |
| `evaluator` | Which engine ran the check, and its version and digest. For OPA run by this tool, it also holds the limits the tool applied (see below). |
| `bundle` | The bundle the program came from. |
| `binding` | The binding entry, when a scanner's result was read for this check. |
| `assertion_source`, `assertion_source_digest` | Where the assertion came from, and the fingerprint of its logic. `compass_bundle` means a signed bundle Iltero Compass served (see [assertion bundles](12-assertion-bundles.md)). `local` means an assertion file the tool was given. `custom_rego` means a policy written by hand in Rego. |
| `compiled_digest`, `compiler` | The compiled program and the compiler that made it. |
| `executor` | Who ran the evaluation: a person (`human`) or a pipeline (`workload`). |
| `ci_context` | Whether the tool checked the CI context file, which describes the CI job. The value is `verified`, `unverified` or `absent`. It is `verified` exactly when the tool checked the file with the run's context key (`basis: context_key_mac`). The context key is a secret Iltero Compass hands out with a run (see [governed runs](09-governed-runs.md#the-run-token-and-the-context-key)). |
| `facts_source` | For a `pre_deploy` check, where the facts document came from: `server`, `local_file` or `none`. It is `null` at every other stage. See [facts only Iltero Compass holds](10-server-facts.md). |
| `fs_hardening` | How the tool protected the files it wrote: `posix`, `windows_profile_acl` or `none`. |

## Six statuses, each with its reasons

A status is never a bare true or false. There are six:

- Four can come from a policy's answer: `pass`, `fail`, `unknown` and
  `not_applicable`.
- Two come only from the runner's own observation. `not_evaluated` means
  the check could not be run. `error` means it ran and went wrong.

Every status other than `pass` and `fail` must carry a `status_reason` from
a closed list:

| Status | Reasons |
| --- | --- |
| `unknown` | `known_after_apply`, `redacted`, `path_missing`, `not_a_list`, `unspecified`, `server_facts_unavailable`, `reference_time_untrusted`, `apply_log_incomplete` |
| `not_applicable` | `when_guard_excluded`, `no_subject_in_scope` |
| `not_evaluated` | `scanner_not_run`, `credential_denied`, `resource_type_unsupported`, `binding_unverified`, `timeout`, `subject_unresolved`, `evaluator_unavailable`, `identity_unverified`, `stage_not_run` |
| `error` | `evaluator_crash`, `evaluator_timeout`, `evaluator_memory_cap`, `output_overflow`, `output_contract_violation`, `adapter_parse_failure`, `bundle_verification_failed`, `compile_failure` |
| `fail` | No reason, or `plan_superseded` when the runner found that the applied plan differs from the evaluated one. |
| `pass` | No reason. |

The package also checks that the parts agree:

- It refuses a reason that does not belong to its status.
- A verdict that came from a policy's answer always names the
  `input_digest` it was computed over.
- When no subject was in scope, the event has no subject `id` and no
  `input_digest`.
- The `evaluator` is absent only for a check that no evaluator ran. That
  happens when none was available (`not_evaluated` with
  `evaluator_unavailable`) or there was nothing to run it on
  (`not_applicable` with `no_subject_in_scope`).

### Who produced the verdict

A verdict comes from one of two kinds of evaluator, and the event says
which:

| | The evaluator this tool ran | A scanner whose result was credited |
| --- | --- | --- |
| `evaluator.engine` | `opa` | `checkov`, `trivy` or `prowler` |
| `evaluator` also carries | the `digest` of the OPA binary that ran, and the limits it ran under, as applied | the `version` the scanner reported, a `digest` when one is known, and `basis: not_executed_by_cli` |
| `bundle` | the bundle the program came from | absent |
| `compiled_digest`, `compiler` | the program and the compiler that made it | absent |
| `binding` | absent | the entry that was read for this check: its `id`, `version` and digest |

A scanner names its binding entry whether its result was credited or the
entry was found not to apply. The scanner ran somewhere else, so there is
nothing here to reproduce it with: no bundle, no program and no limits. What
makes its verdict checkable is the binding. See
[when a scanner's result may stand for an assertion](06-bindings.md).

## What is not in an event

Iltero Compass may assign values to an event when it receives one. Those
values are not part of a submission. The package refuses any key beyond the
ones above.

Some further limits apply:

- Timestamps this package writes are in UTC, to the millisecond, and end in
  `Z`. So they compare correctly as text.
- An event may hold any UTC timestamp that ends in `Z`, with up to nine
  digits after the second.
- A policy's `reason` and `observations` have the same limits as a compiled
  program's answer (see
  [how an assertion is checked](03-compiler-and-evaluation.md#what-comes-out)).
- No text anywhere in an event may hold a control character.

The conformance vectors include a complete example event, with its digest.

## For developers

| On this page | In the package (`iltero_schemas`) |
| --- | --- |
| An event | `models.event.AssuranceEvent` |
| The example event | `src/iltero_schemas/vectors/events/plan_pass.json`, with `digests.json` |
| The closed list of status reasons | `models.event.STATUS_REASONS` |
| Writing a timestamp | `canonical.now_rfc3339_ms` |
| The limits on `reason` and `observations` | `compiler.limits` |
