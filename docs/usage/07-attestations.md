# When a person has to say it

Most of what a compliance framework asks about cannot be decided from a
plan. That a policy exists. That someone is responsible for it. That a
review happened, and who did it. No technical rule establishes any of that,
and a tool that only records what it can evaluate leaves the larger half of
an audit with no evidence at all.

An **attestation** is how a person says it instead, written down in a shape
a record can carry and an auditor can test.
`iltero_schemas.models.attestation.Attestation` is that shape.

## On this page

- [What one claim holds](#what-one-claim-holds)
- [Three rules that make it evidence](#three-rules-that-make-it-evidence)
- [How sure the record is of who wrote it](#how-sure-the-record-is-of-who-wrote-it)

## What one claim holds

| Part | What it says |
| --- | --- |
| `statement` | The claim itself, in the attester's own words, kept verbatim |
| `scope` | What it is about: the `system_id` and `environment`, and the `assertion_id` it stands in for or the `control_ref` it speaks to |
| `attester` | Who is saying it: their `identity`, the `role` they hold and where that role is written down, and how the identity was established |
| `assessment_method` | How they arrived at it — `EXAMINE` (they looked at something) or `INTERVIEW` (they asked someone) |
| `supporting_evidence` | The files they looked at, named as the record's evidence register names them |
| `attested_at`, `valid_until`, `next_review_at` | When it was made, when it stops counting, and when someone should look again |
| `supersedes` | The earlier claim this one replaces |
| `signature` | Nothing signs an attestation yet; the field is here so a reader never has to ask |

## Three rules that make it evidence

**An expiry is required.** `valid_until` has no default and no way to be
absent. A claim that never stops counting is the written equivalent of a
stale screenshot, and it is the finding auditors raise most often against
automated compliance tooling. A claim that expires before, or at the moment
it was made, is refused — as is a review scheduled for after it expires.

**It is an artifact, never a verdict.** Nothing derives an assertion's
status from an attestation. It sits in the record's evidence register and is
read by a person. A tool that let a written claim turn a check green would
be letting the audited party grade their own work.

**It says what it is about.** A claim has to name either the assertion it
stands in for or the control it speaks to. "We are compliant" is not
evidence of anything.

## How sure the record is of who wrote it

`attester.identity_source` says how the identity was established, and there
are only two answers:

| Value | What it means |
| --- | --- |
| `asserted` | The tool wrote down a name it was given and verified nothing |
| `ci_oidc` | The identity came from a token the tool could verify |

`ci_oidc` is the shape an identity takes once something can check a token;
nothing writes it yet. Every attestation written today is `asserted`, and a
verifier says so in those words rather than implying more. `signature` stays
empty for the same reason: an unsigned claim is one a reader has to weigh,
and the record should not hide that.
