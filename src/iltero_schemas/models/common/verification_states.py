"""The states of a verification report's results, and the results more than one part of the report names."""

from __future__ import annotations

from typing import Literal

# verified: the verifier checked the property, a signature it checked covers the facts it rests on, and it holds.
# failed: it checked it and it does not hold. could_not_decide: it looked and could not decide. not_assessed: it did
# not assess the property for this record, for example because the step it reads is pending or out of scope.
# not_performed: the record shows that the step the property is about did not happen. claimed_by_record: the only
# evidence is the record's own claim.
VerificationState = Literal[
    "verified",
    "failed",
    "could_not_decide",
    "not_assessed",
    "not_performed",
    "claimed_by_record",
]
# A property result: its state and its reason (None when there is none to name).
Result = tuple[VerificationState, str | None]
# The result of a property a run statement that verified covers, and shows to hold.
RUN_STATEMENT: tuple[VerificationState, str] = ("verified", "run_statement")
# The result of the bundle signature when every stage that names the server's bundle kept its tarball, and the tarball
# read back under a key of the reader's trust set, its signature verified. It is the one verified result that rests on
# a signature other than the run statement's.
BUNDLE_SIGNATURE_CHECKED: tuple[VerificationState, str] = ("verified", "bundle_signature_checked")
# The result of a property whose served part a stage kept a copy of that is not the one the run statement signs.
SERVED_PART_DIFFERS: tuple[VerificationState, str] = ("failed", "served_part_differs")
# The result of the stages a record does not hold that a later record holds: the run statement names the record as one
# a later record replaced.
LATER_RECORD_HOLDS_THE_LATER_STAGES: tuple[VerificationState, str] = (
    "not_assessed",
    "later_record_holds_the_later_stages",
)
# The integrity of a record the run statement lists as one the server refused.
REFUSED_BY_SERVER: tuple[VerificationState, str] = ("failed", "refused_by_server")
# A record whose integrity is not established: its integrity failed on the files it cites, and the verifier could not
# decide any other property, since a record that does not hold together says nothing a verifier can take about itself.
INTEGRITY_FAILED: tuple[VerificationState, str] = ("failed", "file_digests")
COULD_NOT_DECIDE: tuple[VerificationState, str] = ("could_not_decide", "integrity_failed")
