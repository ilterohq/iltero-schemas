# Uploads, closing a run, and where artifacts go

During a [governed run](09-governed-runs.md), each stage of the pipeline
tells Iltero Cloud what it found. When the last stage is done, the pipeline
closes the run. If the organization keeps artifacts with the run, the
pipeline also stores each artifact in the organization's own storage bucket.
This page describes those three exchanges.

## On this page

- [The flow in brief](#the-flow-in-brief)
- [What a pipeline uploads](#what-a-pipeline-uploads)
- [The answer to an upload](#the-answer-to-an-upload)
- [Which checks count](#which-checks-count)
- [Limits](#limits)
- [Closing a run](#closing-a-run)
- [Where artifacts go](#where-artifacts-go)
- [For developers](#for-developers)

## The flow in brief

1. **Open the run.** The first job opens the run, and each later job asks
   for a run token for its own stage. See [governed runs](09-governed-runs.md).
2. **Upload each stage's results.** Each stage sends its checks in batches,
   then its record. The `post_deploy` and `post_verify` stages also send
   their identity bindings.
3. **Check each answer.** Iltero Cloud answers every upload with one result
   per check. The pipeline confirms that Iltero Cloud stored exactly what it sent.
4. **Store the artifacts.** When the run names an artifact store, the
   pipeline puts each artifact it keeps in that bucket, locked until a fixed
   date.
5. **Close the run.** The pipeline closes the run with its latest stage's
   token. The answer lists every owed check that never got a result.

The sections below give the detail of each step.

## What a pipeline uploads

A pipeline makes three kinds of upload. Every upload carries the stage's run
token in the `Authorization` header (`Authorization: Bearer irt_…`). The
token never goes in the body.

| Upload | Body |
| --- | --- |
| Checks | A **batch** of 1 to 2,000 events. The batch names `apiVersion: iltero.io/assurance-event-batch/v1`, the `run_id`, the `stage` and the `unit` |
| Identity bindings | One [identity document](08-identity-bindings.md), unchanged |
| The record | One [record](05-records.md), unchanged |

Every event in a batch must belong to the run, the stage and the unit the
batch names. The batch's run and stage must also be the ones the token was
issued for.

Iltero Cloud keeps an uploaded record as the tool's own claim. It does not
treat that record as something Iltero Cloud itself vouches for.

Iltero Cloud accepts identity bindings only from the `post_deploy` and
`post_verify` stages, and only once for each unit.

## The answer to an upload

Iltero Cloud answers each upload with a **submission outcome**. It holds
these fields:

| Field | What it says |
| --- | --- |
| `apiVersion` | `iltero.io/submission-outcome/v1` |
| `submission_id` | The id of this upload |
| `received_at` | When Iltero Cloud received it |
| `body_digest` | The `sha256` of the request body, exactly as Iltero Cloud received it |
| `results` | One result for each event, in the order the events were sent. An upload of one document gets one result, at index 0 |

### Checking the answer

The pipeline refuses an answer unless all three of these hold:

- The answer holds one result for each event the pipeline sent.
- `body_digest` is the digest of the body the pipeline sent.
- Each stored event's digest is the digest of the event the pipeline sent.

### One result

| Field | What it says |
| --- | --- |
| `index` | The position of the event in the upload |
| `disposition` | What Iltero Cloud did with the event (see the next table) |
| `reason` | Why Iltero Cloud refused the event. It is set only when the event was `rejected` or `invalid`, and is `null` otherwise |
| `event_id`, `event_digest` | The stored event's id and its digest. The digest is the `sha256` of the canonical JSON of the event, exactly as the pipeline sent it. (Canonical JSON follows RFC 8785, which gives every JSON value one exact byte form.) The two fields are given together or not at all. For a duplicate, they name the first submission, whose digest is the same |
| `conflicts_with` | For a `conflict`, the id of the event stored first. It is `null` for every other disposition |

Two events are **for the same check** when they share the run, the stage, the
unit, the assertion id and the subject id. The subject id is `subject.id`,
which is `null` when no subject was in scope.

| Disposition | Meaning | `event_id` |
| --- | --- | --- |
| `accepted` | Iltero Cloud stored the event | The new event |
| `duplicate` | Iltero Cloud already held an event for the same check with the same content (the same digest) | The event stored first |
| `conflict` | Iltero Cloud already held an event for the same check with different content. It stores the new one too and overwrites nothing. The worse of the two statuses stands | The new event |
| `rejected` | The event is well formed, but Iltero Cloud did not accept it for this run. `reason` says why. A rejected event never counts toward any check | The refused event if Iltero Cloud kept it, or `null` |
| `invalid` | The event does not match its schema. `reason` is `schema_invalid` | `null` |

When two results for the same check conflict, the worse status stands. From
worst to best, the statuses are `not_evaluated`, `error`, `unknown`, `fail`,
`not_applicable` and `pass`. A record's verdict uses the same order. A check
that did not run weighs more than one that failed.

### Why an event was refused

| Reason | Meaning |
| --- | --- |
| `stage_mismatch` | The event belongs to a different stage than the token's |
| `stage_not_allowed` | This stage may not upload this kind of document. Only `post_deploy` and `post_verify` may send identity bindings |
| `run_mismatch` | The event belongs to a different run |
| `bundle_not_pinned` | The event was not evaluated with the bundle the run was pinned to |
| `assertion_not_in_required_set` | The run was not pinned to this assertion |
| `assertion_version_mismatch` | The run pins this assertion's document, but under a different id or version |
| `unit_limit_reached` | The run already has results for as many units as it may have |
| `event_cap_reached` | The stage already has as many results as it may have |
| `schema_invalid` | The event does not match its schema |
| `pins_mismatch` | The uploaded record names different pins from the run's |

### When the whole upload fails

One refused event does not fail the others. The whole upload fails only with
one of these answers:

| Answer | Meaning | What the pipeline does |
| --- | --- | --- |
| `400` | Iltero Cloud could not read the body at all. The answer is for people to read and has no fixed shape | Fix the upload |
| `403` | The body names a different run from the token's | Stop. Never retry |
| `413` | The body is larger than 5 MiB, or holds more than 2,000 events | Send smaller batches |
| `429` | The run has used up its upload allowance | Stop uploading for this run |

## Which checks count

An event counts only for an assertion the run was pinned to. The event's
assertion `digest` must be one of the pinned document digests. Its assertion
id and version must be the ones pinned with that digest.

The event must also name the run's bundle. Its provenance must say
`bundle: {kind: server, digest: <the pinned bundle digest>}`.

## Limits

| Limit | Value |
| --- | --- |
| Size of one upload body | 5 MiB |
| Events in one upload | 2,000 |
| Accepted events in one stage of a run | 100,000 |
| Units with results in one run | 50 |

## Closing a run

The pipeline closes the run with the run token of the run's latest stage. The
close request has no body.

Closing tells Iltero Cloud that no more results are coming. Iltero Cloud then
records every owed check that has no result as `not_evaluated`. A check has a
result when Iltero Cloud stored a counting result for it in any unit of the run.
A result counts when its disposition was `accepted`, `duplicate` or
`conflict`. Iltero Cloud judges this for the run as a whole, not for each unit.

The answer to the close holds these fields:

| Field | What it says |
| --- | --- |
| `apiVersion` | `iltero.io/run/v1` |
| `run_id` | The run |
| `status` | `closed` |
| `closed_at` | When the run closed |
| `not_evaluated` | Each pinned check that had no result, sorted by assertion id. No two entries name the same stored event. Each entry is described in the next table |
| `materialized_not_evaluated` | How many entries `not_evaluated` holds |

| Entry field | What it says |
| --- | --- |
| `assertion` | The check's assertion: its id, version and document digest |
| `stage` | The stage the check belongs to |
| `reason` | `stage_not_run` when the run never reached that stage. `scanner_not_run` when it reached the stage but no result came |
| `event_id` | The id of the `not_evaluated` event Iltero Cloud stored for the check |

After the close, the run's tokens work only for the close itself. A repeated
close with the same token returns the same answer, event ids included. So a
pipeline that lost the first answer can ask again.

A run the pipeline never closes ends on its own 7 days after its last token
was issued. Iltero Cloud then applies the same `not_evaluated` rule.

## Where artifacts go

An **artifact** is a file a record cites as evidence. Every run response
names an `artifact_store`, or `null` when the organization keeps no
artifacts with the run. A run names a store in every
response or in none. With `null`, the artifacts stay with the pipeline.

Each storage provider has its own kind of store, and the store's
`provider` field says which one it is. Every kind names a `uri_prefix` and a
`retention_until`. The only provider so far is `aws`. Its store is an
Amazon S3 bucket (Amazon's object storage service). Its files are encrypted
with a key held in AWS KMS (Key Management Service).

Nothing about the store changes within a run, except its lock date. That
date may move later from one stage to the next, never earlier.

| Field | What it says |
| --- | --- |
| `provider` | The storage provider. It is `aws` |
| `uri_prefix` | Where the files go. It is `s3://`, then an ordinary bucket whose name has no dots, then one or more folder names, ending in `/`. The last folder is the run's id |
| `retention_until` | The date until which each file stays locked. It is later than the response's `server_time`. A later stage's response may name a later date, never an earlier one |
| `lock_mode` | Always `COMPLIANCE`. No one can shorten the lock or delete the file before that date |
| `kms_key_id` | The KMS key the bucket encrypts with, given by its key id alone. It is `null` when the bucket uses its default encryption. A key id always names a key in the account the pipeline runs in |

### Uploading an artifact

The pipeline uploads each artifact it keeps once. It sends one single-part
`PUT` of at most 5 GiB. The object's name is `uri_prefix` followed by the
lowercase hex `sha256` of the artifact's bytes. The request carries these
headers and settings:

| Header or setting | Value |
| --- | --- |
| `x-amz-checksum-sha256` | The base64 of the digest's 32 raw bytes, not of its hex text |
| `If-None-Match` | `*`, so S3 never replaces an object that is already there |
| Object lock | `COMPLIANCE` mode until exactly `retention_until`. Iltero Cloud has already made that date at least as late as the bucket's default |
| `x-amz-expected-bucket-owner` | The pipeline's own AWS account id. The upload fails if anyone else owns the bucket |
| `x-amz-server-side-encryption` | `aws:kms`, sent only when `kms_key_id` is set |
| `x-amz-server-side-encryption-aws-kms-key-id` | The key's ARN (Amazon Resource Name), sent only when `kms_key_id` is set. The pipeline builds the ARN from the bucket's region, its own account id and `kms_key_id` |

Two answers need a follow-up:

- **`412`** means an object with that name is already there. The pipeline
  reads that object's lock date. If `retention_until` is later, the pipeline
  extends the lock to `retention_until` with a separate retention request.
  That request also names the expected bucket owner.
- **`409`** means another upload of the same name was in progress. The
  pipeline tries again.

Each entry of a record's `evidence_refs` gives a file's digest. The hex part
of that digest is the object's name under `uri_prefix`, so a reader of the
record can find each stored file.

A record the tool writes keeps `storage_uri` and `retention_until` of each
artifact `null`. Only Iltero Cloud sets them.

### Permissions the pipeline needs

The pipeline uploads with its own cloud role, not with an Iltero credential.
The role needs these permissions and no others:

| Permission | On | Why |
| --- | --- | --- |
| `s3:PutObject` | The prefix | To upload a file |
| `s3:PutObjectRetention` | The prefix | To extend a file's lock |
| `s3:GetObjectRetention` | The prefix | To read a file's lock date. It reads nothing else |
| `kms:GenerateDataKey` | The one key | To encrypt the file |

The role needs no permission to read a file's content. It also needs none to
delete a file, to place a legal hold on it, or to bypass its lock.

### A bucket policy that enforces the rules

The pipeline sends the headers above, but the bucket should also insist on
them. A bucket policy can refuse any request that breaks them. S3 refuses a
request only when every condition of one statement holds. So each test below
is its own statement.

Before you use the policy, make these replacements:

- Replace `RESOURCE` with the Amazon Resource Name (ARN) of the objects
  under the prefix. That is the bucket's ARN, then `/`, then the prefix's
  folders after the bucket name, then `*`.
- Replace `DAYS` with the bucket's default lock, in days.
- Replace `KEY` with the key's ARN.
- Leave out the last statement when `kms_key_id` is `null`.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "RESOURCE",
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject", "Resource": "RESOURCE",
      "Condition": { "Null": { "s3:if-none-match": "true" } }
    },
    {
      "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObject", "s3:PutObjectRetention"], "Resource": "RESOURCE",
      "Condition": { "StringNotEquals": { "s3:object-lock-mode": "COMPLIANCE" } }
    },
    {
      "Effect": "Deny", "Principal": "*", "Action": ["s3:PutObject", "s3:PutObjectRetention"], "Resource": "RESOURCE",
      "Condition": { "NumericLessThan": { "s3:object-lock-remaining-retention-days": "DAYS" } }
    },
    {
      "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject", "Resource": "RESOURCE",
      "Condition": { "StringNotEquals": { "s3:x-amz-server-side-encryption-aws-kms-key-id": "KEY" } }
    }
  ]
}
```

## For developers

| On this page | In the package (`iltero_schemas`) |
| --- | --- |
| A batch, as a sender builds it | `models.ingest.AssuranceEventBatch` (`MAX_BATCH_EVENTS`, `MAX_UPLOAD_BYTES`) |
| A batch, read with each event left unread | `models.ingest.AssuranceEventBatchEnvelope` |
| The answer and one result | `models.ingest.SubmissionOutcome`, `models.ingest.EventResult` |
| Checking an answer against what was sent | `models.ingest.check_answers` |
| The digest of a stored event | `models.ingest.document_digest` |
| Which of two statuses stands | `models.event.STATUS_SEVERITY`, `models.event.worse_status` |
| The dispositions and reasons | `models.ingest.Disposition`, `models.ingest.RejectReason` |
| The artifact store, one variant per provider | `models.run.ArtifactStore` (a union keyed by `provider`) |
| The S3 store | `models.providers.aws.S3ArtifactStore` |
| A later response continues the run | `models.run.check_continues` |
| The answer to closing a run | `models.run.RunCloseResponse`, `models.run.NotEvaluatedCheck` |

A receiver reads a batch with `AssuranceEventBatchEnvelope` first, then reads
each event with `AssuranceEvent`. One malformed event then gets its own
`invalid` result. A sender builds `AssuranceEventBatch`, which checks every
event.
