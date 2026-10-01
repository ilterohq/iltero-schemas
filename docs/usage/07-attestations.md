# When a person has to say it

Most of what a compliance framework asks about cannot be decided from a
plan. Does a policy exist? Is someone responsible for it? Did a review
happen, and who did it? No technical rule can establish any of that. A tool
that records only what it can evaluate leaves the larger half of an audit
with no evidence at all.

An **attestation** is how a person states such a fact instead. It is a
written claim, in a shape a record can carry and an auditor can test. This
package defines that shape.

## On this page

- [What one claim holds](#what-one-claim-holds)
- [Three rules that make it evidence](#three-rules-that-make-it-evidence)
- [How sure the record is of who wrote it](#how-sure-the-record-is-of-who-wrote-it)
- [How a claim gets into a record](#how-a-claim-gets-into-a-record)
- [For developers](#for-developers)

## What one claim holds

| Part | What it says |
| --- | --- |
| `apiVersion`, `kind`, `uuid` | Always `iltero.io/v1` and `Attestation`, and the claim's own id. |
| `statement` | The claim itself, in the attester's own words, kept exactly as written. It is at most 4096 characters. |
| `scope` | What the claim is about: the `system_id` and the `environment`, and the `assertion_id` it stands in for or the `control_ref` (a control in an audit framework) it is about. |
| `attester` | Who is making the claim. It gives their `identity` and the `role` they hold. `idp` names the identity provider, the service that issued the identity, such as a company's single sign-on. `auth_method` says how the person signed in to it. `role_source_ref` says where the role is written down. `identity_source` says how sure the record is of the identity (see below). |
| `assessment_method` | How they reached the claim: `EXAMINE` (they looked at something) or `INTERVIEW` (they asked someone). |
| `supporting_evidence` | The files they looked at, at most 256. Each is named by its `ref_id` and digest, as in the record's [evidence register](05-records.md#what-a-record-holds). |
| `attested_at` | When the claim was made, which clock said so (`source`), and how far that clock can be trusted (`trust`). |
| `valid_until`, `next_review_at` | When the claim stops counting, and when someone should look at it again. |
| `supersedes` | The earlier claim this one replaces, by its id. |
| `signature` | Always empty. Nothing signs an attestation yet. The field is here so a reader never has to ask. |
| `written_by` | The version of the tool that wrote the claim, when it is known. |

## Three rules that make it evidence

**An expiry is required.** `valid_until` has no default and cannot be left
out. A claim that never stops counting is like a stale screenshot. It is
the finding auditors raise most often against automated compliance tools.
The package refuses a claim that expires at or before the moment it was
made. It also refuses a review scheduled for after the claim expires.

**It is evidence, never a verdict.** Nothing derives an assertion's status
from an attestation. The claim sits in the record's evidence register (its
list of cited files), and a person reads it. If a written claim could turn a check green, the audited
party would be grading their own work.

**It says what it is about.** A claim must name either the assertion it
stands in for or the control it is about. "We are compliant" is not
evidence of anything.

## How sure the record is of who wrote it

`attester.identity_source` says how the identity was established. It has
only two values:

| Value | What it means |
| --- | --- |
| `asserted` | The tool wrote down a name it was given and verified nothing. |
| `ci_oidc` | The identity came from an OpenID Connect (OIDC) token that the tool could verify. An OIDC token is a signed identity token, such as the one a CI system gives each job. |

`ci_oidc` is the shape an identity will take once something can check a
token. Nothing writes it yet. Every attestation written today is
`asserted`, and a verifier says so in those words rather than implying
more. `signature` stays empty for the same reason. A reader has to weigh an
unsigned claim, and the record should not hide that.

## How a claim gets into a record

A tool writes the claim as a JSON file into the record's directory. It then
lists the file in the record's evidence register, `evidence_refs` (see
[the record](05-records.md#what-a-record-holds)). The entry's `media_type`
is `application/vnd.iltero.attestation+json`. That type is how a reader
tells a claim apart from the other files the record cites.

## For developers

| On this page | In the package (`iltero_schemas`) |
| --- | --- |
| An attestation | `models.attestation.Attestation` |
| How a record's evidence register marks a claim | `models.attestation.MEDIA_TYPE` |
