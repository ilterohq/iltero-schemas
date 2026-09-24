# What is recorded with a verdict

Every check produces one **assurance event**: the verdict, and everything
needed to say who produced it and to reproduce it. The evaluator's answer
is not the event — the tool that ran the evaluator wraps the answer with
provenance, and nothing in the event is set by the policy program itself.

`iltero_schemas.models.event.AssuranceEvent` is the shape of an event as a
tool submits it. It refuses unknown keys and coerces nothing.

## On this page

- [The parts of an event](#the-parts-of-an-event)
- [Six statuses, each with its reasons](#six-statuses-each-with-its-reasons)
  - [Who produced the verdict](#who-produced-the-verdict)
- [What is not in an event](#what-is-not-in-an-event)

## The parts of an event

| Part | What it says |
| --- | --- |
| `assertion` | `id`, `version`, and the `digest` of the assertion document as it was read |
| `subject` | What the verdict is about: `kind`, its local `id` and the `identities` known for it. The `id` is absent only when the assertion had no subject in scope at all |
| `evaluation` | The `stage`, the `status`, the runner's `status_reason` and `status_detail`, and what the policy said: its `reason` and `observations` |
| `provenance` | The `run` (`id`, whether it was `server_issued` or `locally_derived`, the `unit`), the `source_commit`, the `plan_digest`, the `input_digest` of the exact document the evaluator saw, the `evaluator` (which engine, its version and digest, and, for the evaluator this tool ran, the limits as applied), the `bundle`, the `binding` when a scanner's result was credited, where the assertion came from (`assertion_source`) and its `assertion_source_digest`, the `compiled_digest`, the `compiler`, the `executor`, whether a CI context was verified, and the file-system hardening in force |
| `observed_at` | The run's timestamp, by the runner's clock: every event of one run carries the same value |

## Six statuses, each with its reasons

A status is never a bare boolean. Four can come from a policy answer —
`pass`, `fail`, `unknown`, `not_applicable` — and two only from the runner's
own observation: `not_evaluated` (the check could not be run) and `error`
(it ran and went wrong). Every status but `pass` and `fail` carries a
`status_reason` from a closed list (`STATUS_REASONS`):

| Status | Reasons |
| --- | --- |
| `unknown` | `known_after_apply`, `redacted`, `path_missing`, `not_a_list`, `unspecified`, `server_facts_unavailable`, `reference_time_untrusted`, `apply_log_incomplete` |
| `not_applicable` | `when_guard_excluded`, `no_subject_in_scope` |
| `not_evaluated` | `scanner_not_run`, `credential_denied`, `resource_type_unsupported`, `binding_unverified`, `timeout`, `subject_unresolved`, `evaluator_unavailable`, `identity_unverified`, `stage_not_run` |
| `error` | `evaluator_crash`, `evaluator_timeout`, `evaluator_memory_cap`, `output_overflow`, `output_contract_violation`, `adapter_parse_failure`, `bundle_verification_failed`, `compile_failure` |
| `fail` | none, or `plan_superseded` when the runner found the applied plan differs from the evaluated one |

A reason outside its status is refused. A verdict that came from a policy
answer always names the `input_digest` it was computed over. The `evaluator`
is absent only for a check no evaluator ran: there was none available
(`not_evaluated / evaluator_unavailable`) or nothing to run it on
(`not_applicable / no_subject_in_scope`).

### Who produced the verdict

A verdict comes from one of two kinds of evaluator, and the event says
which:

| | The evaluator this tool ran | A scanner whose result was credited |
| --- | --- | --- |
| `evaluator.engine` | `opa` | `checkov`, `trivy` or `prowler` |
| `evaluator` also carries | the `digest` of the program and the limits it ran under, as applied | the `version` the tool reported, a `digest` when one is known, and `basis: not_executed_by_cli` |
| `bundle` | the bundle the program came from | absent |
| `compiled_digest`, `compiler` | the module and the compiler that made it | absent |
| `binding` | absent | the entry that was read for this check: its `id`, `version` and digest — named whether the result was credited or the entry was found not to apply |

A scanner ran somewhere else, so there is nothing here to reproduce it
with: no bundle, no module, no limits. What makes the verdict checkable is
the binding — see [When a scanner's result may stand for an
assertion](06-bindings.md).

## What is not in an event

Whatever Iltero Compass assigns to an event when it receives one is not
part of a submission; any key beyond the ones above is refused.

`src/iltero_schemas/vectors/events/plan_pass.json` is a complete example,
and `digests.json` next to it records its digest. Timestamps are written
by `iltero_schemas.canonical.now_rfc3339_ms`: UTC, millisecond precision,
`Z`, so values it wrote compare correctly as text. A policy's `reason` and
`observations` are bounded the same way the evaluator's output contract
bounds them (`iltero_schemas.compiler.limits`), and no string anywhere in an
event may hold a control character.
