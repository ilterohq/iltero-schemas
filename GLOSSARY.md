# Glossary

This page defines the words the contract uses, and lists the words to use and to
avoid when you write about a record.

## Terms

**Change Assurance Record (CAR).** The record of one infrastructure change. It
can hold the checks, the approvals, what the deployment did, and checks made
after deployment. Each part says where it came from. It names no regulatory
framework. A view for a framework is built from records, outside them. A CAR
records technical and process assurance facts. It does not, by itself,
establish certification or compliance with a regulatory framework. In plain
words, a record says what was checked and how. On its own, it does not show
that anything is certified or complies with a regulation or standard. One CAR
describes one attempted change, whatever its outcome. See
[the record](docs/usage/05-records.md).

**Trust level.** How far a record's facts were established. There are five
levels, from the weakest to the strongest:

| Level | What it means |
| --- | --- |
| `self_attested` | The tool that wrote the record is its only source. |
| `source_authenticated` | A service other than the writer confirmed where the record came from. It confirmed the repository, the CI system, and the people and jobs named in it. |
| `compass_governed` | Iltero Compass checked the record against a set of rules the organization chose, and checked that each piece of evidence links to the one before it. |
| `assessor_reviewed` | A named external assessor reviewed the record. |
| `authority_accepted` | A named authority accepted the record for a stated purpose. |

Every level above `self_attested` needs a signature. A record cannot carry one
in this version, so every record is `self_attested`.

**Compliance determination.** A decision that something meets a framework's
requirements. A record never makes one, so its `compliance_determination` is
always `null`. A view of a framework is built from records, outside them.

**Governed run.** A run of a pipeline that was opened through Iltero Compass.
Compass fixes what the run is judged against and confirms which CI job ran
each stage. See [governed runs](docs/usage/09-governed-runs.md).

**Verification report.** A separate document that says what a verifier found
about one record. It reports on nine properties, one at a time, and gives no
overall verdict. See [verification reports](docs/usage/14-verification-reports.md).
Each property takes one of six states:

| State | What it means |
| --- | --- |
| `verified` | The verifier checked the property, and it holds. |
| `failed` | The verifier checked the property, and it does not hold. |
| `not_determined` | The verifier looked, but could not decide. |
| `not_assessed` | The verifier did not assess the property for this record, for example because the step it reads is pending or out of scope, or because no offline verifier can know it. |
| `not_performed` | The record shows that the step the property is about did not happen. |
| `client_asserted` | The only evidence is the record's own claim. Nothing outside the record confirms it. |

**Assurance profile.** A set of rules an organization chose that every change
must meet.

**IaC tool.** An infrastructure-as-code tool, such as Terraform. It plans and
applies changes to cloud resources. Iltero reads what the tool wrote: the plan,
the apply log and the state. Iltero never runs it.

**CI provider.** A continuous integration (CI) system that runs the pipeline's
jobs, such as GitHub Actions (`github_actions`).

**Cloud provider.** The cloud where a resource lives, such as Amazon Web
Services (`aws`).

**Resolver.** The part of a tool that reads the identifiers of resources for one
cloud provider. It says which cloud resource each address in the configuration
became. See [identity bindings](docs/usage/08-identity-bindings.md).

## Words to use and to avoid

Use these words about a record, each only in the case it describes:

| Words | When to use them |
| --- | --- |
| Change Assurance Record | Always, as the record's name. |
| signature valid | When a signature on the record was checked and is valid. No record carries a signature in this version. |
| integrity verified | Only when a valid signature backs the record's integrity. |
| source authenticated | When a service other than the writer confirmed where the record came from. |
| assurance profile satisfied | When the record meets every rule of the organization's assurance profile. |
| Compass-governed CAR | Only for a record whose `trust_level` is `compass_governed`. No record can have that level in this version. |
| externally reviewed | When a named external assessor or authority reviewed the record. |

Do not use these words about a record:

- "Iltero Verified", or any other single verification badge
- certified
- compliant
- audit-ready
- auditor-approved
- governed, on its own

"Governed run" stays the name of the process: a run opened through Iltero
Compass.
