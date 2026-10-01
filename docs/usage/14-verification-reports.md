# Verification reports

A **verification report** says what a verifier found when it checked one
[Change Assurance Record](05-records.md). A verifier is a program, such as
`iltero car verify`, that reads a record and the files it cites. The report looks
at nine properties of the record, one at a time. For each one it says what
the verifier could establish. The Iltero CLI prints one when you run
`iltero car verify --format json`.

## On this page

- [Why the report is not part of the record](#why-the-report-is-not-part-of-the-record)
- [The document](#the-document)
- [The nine properties](#the-nine-properties)
- [The six states](#the-six-states)
- [No overall verdict](#no-overall-verdict)
- [For developers](#for-developers)

## Why the report is not part of the record

A tool's word about its own record is not independent evidence. A record
that said "I am verified" would only be its writer's claim. So a record
carries no verification results, and a verifier writes its findings in a
separate document.

The report names the record it is about by the record's id and by the digest
of the record's bytes, as the verifier read them. A digest is a fingerprint
of the bytes. If anyone changes a single byte of the record, the report no
longer names it.

## The document

| Field | What it says |
| --- | --- |
| `apiVersion` | `iltero.io/verification-report/v1` |
| `record` | The record the report is about: its `uuid`, and the `digest` of its bytes |
| `verifier` | The program that wrote the report. Its `name` is `iltero`, and `version` is the version the program reports |
| `properties` | The nine properties below. Each holds a `state` and a `basis` |

A property's `state` is one of the six states below. Its `basis` is a short
name for what the state rests on, such as `digest_linkage`. It is `null` when
there is nothing to name. The package refuses any other key.

## The nine properties

Each row says what `verified` means for that property.

| Property | It is `verified` when |
| --- | --- |
| `integrity` | The record's structure and its signature are valid, and the evidence it cites has not changed. No record carries a signature in this version, so the package refuses a report that calls a record's integrity `verified`. If the only evidence is that the digests match, integrity is `client_asserted`. Anyone who can edit a record can also compute new digests that match. |
| `source_identity` | The repository, the commit and the pipeline came from an authenticated source. |
| `approval_identity` | Every approval came from an authenticated identity. |
| `bundle_provenance` | The checks ran from an [assertion bundle](12-assertion-bundles.md) signed by an authorised key that was not revoked. |
| `stage_completeness` | Every required stage is present. Every check owed has a result or is listed as not evaluated. |
| `plan_apply_match` | The plan that was approved is the plan that was applied. |
| `runtime_verification` | A verification ran after the deployment. |
| `deployment_coverage` | No deployment that the verifier can see in the connected CI system or cloud is missing a record. |
| `exceptions` | Every exception used was approved and valid at the time of the deployment. |

## The six states

A property is never a bare yes or no. It takes one of six states:

| State | What it means |
| --- | --- |
| `verified` | The verifier checked the property, and it holds. |
| `failed` | The verifier checked the property, and it does not hold. |
| `not_determined` | The verifier looked, but could not decide. |
| `not_assessed` | The verifier did not assess the property for this record, for example because the step it reads is pending or out of scope, or because no offline verifier can know it. |
| `not_performed` | The record shows that the step the property is about did not happen. An example is a deployment with no verification after it. |
| `client_asserted` | The only evidence is the record's own claim. Nothing outside the record confirms it. |

The difference between the last four matters to an auditor. A property that
was `not_determined` was looked at but left open. A property that was
`not_assessed` may still hold. A step that was `not_performed` did not
happen. A `client_asserted` property rests only on the word of the tool that
wrote the record.

If integrity failed, or the verifier could not decide it, the verifier cannot
rely on anything the record says about itself. So every other property must
be `not_determined`. The package refuses a report that says otherwise.

Two examples show what `not_performed` means for a run the Iltero CLI opened
on its own:

- `source_identity` is `not_performed` with the basis `run_opened_locally`.
  The step is source authentication by Iltero Cloud. It does not happen in
  a run the CLI opened on its own.
- `bundle_provenance` is `not_performed` with the basis `local_assertions`.
  The step is checking a bundle Iltero Cloud signed. A run the CLI opened
  on its own uses its own assertions and no signed bundle.

## No overall verdict

The report has no single "verified" field and no overall verdict. One badge
would hide which properties were checked and which were only claimed. A
reader looks at each property it needs, and decides for itself what is
enough.

A report in which every property is `verified` is still not a statement of
compliance. Like the record, it does not establish certification or
compliance with a regulatory framework. In plain words, it says what was
checked and how. On its own, it does not show that anything is certified or
complies with a regulation or standard.

## For developers

| On this page | In the package (`iltero_schemas`) |
| --- | --- |
| The report | `models.verification.VerificationReport` |
| The six states | `models.verification.VerificationState` |
| One property's result | `models.verification.PropertyResult` |
| An example report | `src/iltero_schemas/vectors/reports/verification_report.json`, with `digests.json` |
