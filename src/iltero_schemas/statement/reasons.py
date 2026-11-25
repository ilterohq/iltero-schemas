"""Why a run statement is refused, as one reason code per refusal, and how a record differs from one.

The refusals fall in two groups. ``NOT_A_RUN_STATEMENT``: the bytes are not a run statement: not an envelope as this
contract writes one, or a payload that is not the canonical JSON of a run statement. ``RUN_STATEMENT_DOES_NOT_HOLD``:
the bytes are a signed envelope that cannot be relied on: it carries more or fewer than one signature, its key is not
trusted, of another purpose, revoked or of another server than the statement names, its signature does not verify,
or the run ended before the key's status began or after it was retired. The key's purpose, trust and revocation and
the signature are found before the payload is read. A signature carries no trusted time, so the check of the run's end
against the key's dates is one of consistency only.

``RECORD_DIFFERENCES`` are the ways a statement that verified differs from a record it is read with
(``differences.compare_record``), the statement of another run (``ANOTHER_RUN``) among them. ``RECORD_NOTES`` are what
a comparison says that is not a difference.
"""

from __future__ import annotations

from typing import Final

TOO_LARGE: Final = "too_large"
NOT_JSON: Final = "not_json"
NOT_AN_ENVELOPE: Final = "not_an_envelope"
ANOTHER_PAYLOAD_TYPE: Final = "another_payload_type"
PAYLOAD_NOT_BASE64: Final = "payload_not_base64"
PAYLOAD_NOT_A_RUN_STATEMENT: Final = "payload_not_a_run_statement"
PAYLOAD_NOT_CANONICAL: Final = "payload_not_canonical"
NOT_A_RUN_STATEMENT: Final = frozenset(
    {
        TOO_LARGE,
        NOT_JSON,
        NOT_AN_ENVELOPE,
        ANOTHER_PAYLOAD_TYPE,
        PAYLOAD_NOT_BASE64,
        PAYLOAD_NOT_A_RUN_STATEMENT,
        PAYLOAD_NOT_CANONICAL,
    }
)

SIGNATURE_INVALID: Final = "signature_invalid"
NOT_EXACTLY_ONE_SIGNATURE: Final = "not_exactly_one_signature"
KEY_OF_ANOTHER_PURPOSE: Final = "key_of_another_purpose"
KEY_REVOKED: Final = "key_revoked"
KEY_NOT_TRUSTED: Final = "key_not_trusted"
KEY_OF_ANOTHER_SERVER: Final = "key_of_another_server"
KEY_NOT_VALID_AT_THE_RUN_END: Final = "key_not_valid_at_the_run_end"
RUN_STATEMENT_DOES_NOT_HOLD: Final = frozenset(
    {
        KEY_NOT_VALID_AT_THE_RUN_END,
        SIGNATURE_INVALID,
        NOT_EXACTLY_ONE_SIGNATURE,
        KEY_OF_ANOTHER_PURPOSE,
        KEY_REVOKED,
        KEY_NOT_TRUSTED,
        KEY_OF_ANOTHER_SERVER,
    }
)


ANOTHER_RUN: Final = "another_run"
ANOTHER_UNIT: Final = "another_unit"
ANOTHER_ACTIVITY: Final = "another_activity"
ANOTHER_ENVIRONMENT: Final = "another_environment"
ANOTHER_BUILD: Final = "another_build"
RECORD_NOT_LISTED: Final = "record_not_listed"
RECORD_REFUSED_BY_THE_SERVER: Final = "record_refused_by_the_server"
RECORD_IS_A_CONFLICTING_UPLOAD: Final = "record_is_a_conflicting_upload"
RUN_NOT_OPENED_BY_THE_SERVER: Final = "run_not_opened_by_the_server"
REFERENCE_TIME_DIFFERS: Final = "reference_time_differs"
BUNDLE_DIFFERS: Final = "bundle_differs"
ENFORCEMENT_MODE_DIFFERS: Final = "enforcement_mode_differs"
SCANNER_CHECK_MAPPING_DIFFERS: Final = "scanner_check_mapping_differs"
BUNDLE_OF_ANOTHER_SERVER: Final = "bundle_of_another_server"
STAGE_NOT_LISTED: Final = "stage_not_listed"
SERVED_PART_DIFFERS: Final = "served_part_differs"
CI_JOB_DIFFERS: Final = "ci_job_differs"
REQUIRED_ASSERTIONS_DIFFER: Final = "required_assertions_differ"
EXPECTED_STAGES_DIFFER: Final = "expected_stages_differ"
RECORD_DIFFERENCES: Final = frozenset(
    {
        ANOTHER_RUN,
        ANOTHER_UNIT,
        ANOTHER_ACTIVITY,
        ANOTHER_ENVIRONMENT,
        ANOTHER_BUILD,
        RECORD_NOT_LISTED,
        RECORD_REFUSED_BY_THE_SERVER,
        RECORD_IS_A_CONFLICTING_UPLOAD,
        RUN_NOT_OPENED_BY_THE_SERVER,
        STAGE_NOT_LISTED,
        REFERENCE_TIME_DIFFERS,
        BUNDLE_DIFFERS,
        BUNDLE_OF_ANOTHER_SERVER,
        ENFORCEMENT_MODE_DIFFERS,
        SCANNER_CHECK_MAPPING_DIFFERS,
        SERVED_PART_DIFFERS,
        CI_JOB_DIFFERS,
        REQUIRED_ASSERTIONS_DIFFER,
        EXPECTED_STAGES_DIFFER,
    }
)

# An accepted record that is not the one that counts at its stage: a later record replaced it.
RECORD_NOT_THE_ONE_THAT_COUNTS: Final = "record_not_the_one_that_counts"
RECORD_NOTES: Final = frozenset({RECORD_NOT_THE_ONE_THAT_COUNTS})


class RunStatementError(ValueError):
    """A run statement refused: ``reason`` is its code, of ``NOT_A_RUN_STATEMENT`` or ``RUN_STATEMENT_DOES_NOT_HOLD``,
    and the message says why in a sentence."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
