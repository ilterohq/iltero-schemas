# Uploads, closing a run, and where artifacts go

During a [governed run](09-governed-runs.md), the pipeline sends Iltero
Compass what each stage found: its checks, its identity bindings and its
record. When the last stage is done, the pipeline closes the run. If the
organization keeps artifacts with the run, the pipeline also puts each
artifact in the organization's own storage bucket.

## On this page

- [What a pipeline uploads](#what-a-pipeline-uploads)
- [The answer to an upload](#the-answer-to-an-upload)
- [Which checks count](#which-checks-count)
- [Limits](#limits)
- [Closing a run](#closing-a-run)
- [Where artifacts go](#where-artifacts-go)
- [For developers](#for-developers)

## What a pipeline uploads

Every upload carries the stage's run token in the `Authorization` header
(`Authorization: Bearer irt_…`), never in the body.

| Upload | Body |
| --- | --- |
| Checks | A **batch**: `apiVersion: iltero.io/assurance-event-batch/v1`, the `run_id`, the `stage`, the `unit`, and 1 to 2,000 `events` |
| Identity bindings | One [identity document](08-identity-bindings.md), as it is |
| The record | One [record](05-records.md), as it is |

Every event in a batch belongs to the run, the stage and the unit the batch
names. The batch's run and stage must also be the ones the token was issued
for.

Iltero Compass keeps the record the tool uploads as the tool's own claim. It
does not treat that record as its own. Identity bindings are accepted only
from the `post_deploy` and `post_verify` stages, once for each unit.

## The answer to an upload

When Iltero Compass reads an upload, it answers with a **submission
outcome**. The answer holds:

- `apiVersion: iltero.io/submission-outcome/v1`;
- a `submission_id`, and the time the upload was `received_at`;
- `body_digest`: the `sha256` of the request body exactly as Iltero Compass
  received it;
- `results`: one result for each event, in the order the events were sent.
  An upload of one document gets one result, at index 0.

The pipeline checks that the answer holds one result for each event it sent,
that `body_digest` is the digest of the body it sent, and that each stored
event's digest is the digest of the event it sent. An answer that fails any
of these checks is refused.

A result has these fields:

- `index`: the position of the event in the upload.
- `disposition`: what Iltero Compass did with the event (see the table below).
- `reason`: why the event was refused. It is set only when the event was
  `rejected` or `invalid`, and `null` otherwise.
- `event_id` and `event_digest`: the stored event's id, and the `sha256` of
  the canonical JSON (RFC 8785, a byte-exact JSON form) of the event exactly
  as the pipeline sent it. They are given together or not at all. For a
  duplicate, the digest is the first submission's, which is the same by
  definition. A pipeline compares each digest with the event it sent, and
  `body_digest` with the body it sent.
- `conflicts_with`: for a `conflict`, the id of the event stored first. It is
  `null` for every other disposition.

Two events are **for the same check** when they have the same run, stage,
unit, assertion id and subject id (`subject.id`, which is `null` when no
subject was in scope).

| Disposition | Meaning | `event_id` |
| --- | --- | --- |
| `accepted` | The event was stored | The new event |
| `duplicate` | An event for the same check with the same content (the same digest) was already stored | The event stored first |
| `conflict` | An event for the same check with different content was already stored. Iltero Compass stores the new one too, and overwrites nothing. The worse of the two statuses stands | The new event |
| `rejected` | The event is well formed, but Iltero Compass did not accept it for this run. `reason` says why. A rejected event never counts toward any check | The refused event if Iltero Compass kept it, or `null` |
| `invalid` | The event does not match its schema. `reason` is `schema_invalid` | `null` |

When two results for the same check conflict, the worse status stands. From
worst to best, the statuses are `not_evaluated`, `error`, `unknown`, `fail`,
`not_applicable` and `pass`. This is the order a record's verdict already
uses: a check that did not run weighs more than one that failed.

The reasons for a refusal are:

| Reason | Meaning |
| --- | --- |
| `stage_mismatch` | The event is of another stage than the token's |
| `stage_not_allowed` | This stage may not upload this kind of document. Identity bindings come only from `post_deploy` and `post_verify` |
| `run_mismatch` | The event is of another run |
| `bundle_not_pinned` | The event was not evaluated with the bundle the run was pinned to |
| `assertion_not_in_required_set` | The run was not pinned to this assertion |
| `assertion_version_mismatch` | The assertion's document is pinned, but under another id or version |
| `unit_limit_reached` | The run already has results for the most units it may have |
| `event_cap_reached` | The stage already has the most results it may have |
| `schema_invalid` | The event does not match its schema |
| `pins_mismatch` | The uploaded record names other pins than the run's |

One refused event does not fail the others. Apart from the answer above, an
upload can end in one of these ways:

| Answer | Meaning | What the pipeline does |
| --- | --- | --- |
| `400` | The body could not be read at all. The answer is for people to read and has no fixed shape | Fix the upload |
| `403` | The body names another run or stage than the token's | Stop. Never retry |
| `413` | The body is larger than 5 MiB, or holds more than 2,000 events | Send smaller batches |
| `429` | The run has used up its upload allowance | Stop uploading for this run |

## Which checks count

An event counts only for an assertion the run was pinned to. Iltero Compass
matches the assertion by the digest of its document, so the event's
assertion id and version must be the pinned ones for that digest. The event
must also name the run's bundle: its provenance says
`bundle: {kind: compass, digest: <the pinned bundle digest>}`.

## Limits

- One upload body is at most 5 MiB and holds at most 2,000 events.
- One stage of a run keeps at most 100,000 accepted events.
- One run has results for at most 50 units.

## Closing a run

The pipeline closes the run with the run token of the run's latest stage.
The close request has no body. The answer holds:

- `apiVersion: iltero.io/run/v1`, the `run_id`, `status: closed`, and the
  time it was `closed_at`;
- `not_evaluated`: each pinned check that had no accepted result, sorted by
  assertion id. An entry names the `assertion` (id, version and digest), its
  `stage`, the `reason`, and `event_id`: the id of the `not_evaluated`
  record Iltero Compass stored for it. No two entries name the same record;
- `materialized_not_evaluated`: how many entries that list holds.

Each check in that list is recorded as `not_evaluated`. The reason is
`stage_not_run` when the run never reached that check's stage, and
`scanner_not_run` when it did. A check counts as having a result when any
unit of the run has a stored result for it that counts: `accepted`,
`duplicate` or `conflict`. Coverage is judged for the run as a whole, not
for each unit.

After the close, the run's tokens work for nothing but the close itself. A
repeated close with the same token returns the same answer, record ids
included, so a pipeline that lost the first answer can ask again. A run the
pipeline never closes ends on its own 7 days after its last token was
issued, with the same `not_evaluated` rule.

## Where artifacts go

Every run response names an `artifact_store`, or `null` when the
organization keeps no artifacts with the run. A run names one in every
response or in none. With `null`, artifacts stay with the pipeline.

The store is an Amazon S3 bucket (Amazon's object storage service). Its
files are encrypted with a key held in AWS KMS (Key Management Service).

| Field | What it says |
| --- | --- |
| `uri_prefix` | Where the files go: `s3://`, an ordinary bucket whose name has no dots, and one or more folder names, ending in `/`. The last folder is the run's id. It never changes within a run |
| `retention_until` | The date until which each file stays locked. It is later than the response's `server_time`. A later stage's response may name a later date, never an earlier one |
| `lock_mode` | Always `COMPLIANCE`: no one can shorten the lock or delete the file before that date |
| `kms_key_id` | The KMS key the bucket encrypts with, by its key id alone, or `null` when the bucket uses its default encryption. A key id always names a key in the account the pipeline runs in. It never changes within a run |

The pipeline uploads each artifact it keeps once, with one single-part `PUT`
of at most 5 GiB. The object's name is `uri_prefix` followed by the
lowercase hex `sha256` of the artifact's bytes. The request carries:

- `x-amz-checksum-sha256`: the base64 of the digest's 32 raw bytes, not of
  its hex text;
- `If-None-Match: *`, so an object already there is never replaced;
- an object lock in `COMPLIANCE` mode until exactly `retention_until`.
  Iltero Compass has already made that date at least as late as the bucket's
  default;
- `x-amz-expected-bucket-owner`: the pipeline's own AWS account id, so the
  upload fails if the bucket belongs to anyone else;
- when `kms_key_id` is set, `x-amz-server-side-encryption: aws:kms` and
  `x-amz-server-side-encryption-aws-kms-key-id` with the key's ARN (Amazon
  Resource Name). The pipeline builds that ARN from the bucket's region, its
  own account id and `kms_key_id`.

A `412` answer means an object with that name is already there. The
pipeline then reads that object's lock date. When `retention_until` is
later, it extends the lock to `retention_until` with a separate retention
request, which also names the expected bucket owner. A `409` answer means
another upload of the same name was in progress, and the pipeline tries
again.

The pipeline uploads with its own cloud role, not with an Iltero credential.
On the prefix, that role needs `s3:PutObject`, `s3:PutObjectRetention` and
`s3:GetObjectRetention`, which reads an object's lock date and nothing else.
It also needs `kms:GenerateDataKey` on that one key. It needs no permission
to read an object's content, or to delete, place a legal hold on, or bypass
the lock of any object.

The headers above are sent by the pipeline, so the bucket should also insist
on them. A bucket policy can refuse any request that breaks them. S3 refuses
a request only when every condition of one statement holds, so each test is
its own statement. Replace `RESOURCE` with the prefix's objects, `DAYS` with
the bucket's default lock in days, and `KEY` with the key's ARN. Leave out
the key statement when `kms_key_id` is `null`.

```json
[
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
```

Iltero Compass, not the pipeline, checks each stored file's checksum and
lock before it names the file in a record.

A record written without Iltero Compass keeps `storage_uri` and
`retention_until` of each artifact `null`. Only Iltero Compass sets them.

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
| The artifact store | `models.run.ArtifactStore` |
| A later response continues the run | `models.run.check_continues` |
| The answer to closing a run | `models.run.RunCloseResponse`, `models.run.NotEvaluatedCheck` |

A receiver reads a batch with `AssuranceEventBatchEnvelope` first, then each
event with `AssuranceEvent`, so one malformed event gets its own `invalid`
result. A sender builds `AssuranceEventBatch`, which checks every event.
