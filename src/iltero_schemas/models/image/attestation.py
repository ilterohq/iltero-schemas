"""What a build's attestation says before anyone checks its signature: the images it is about, and its kind.

An attestation is a Sigstore bundle whose signed envelope (DSSE, Dead Simple
Signing Envelope) carries an in-toto statement: a list of subjects, each an
artifact named by its digest, and a predicate saying something about them. A
build's provenance is the predicate of kind SLSA provenance (Supply-chain
Levels for Software Artifacts), such as the one GitHub's artifact attestations
write.

This module reads the statement and nothing else. It never checks the
signature, the signing certificate or a transparency log: that needs a trust
root, which only the server holds. Its result is named unverified so that no
reader takes it for a fact. The server reads the statement from the exact
payload bytes whose signature it verified (``attestation_statement_of_payload``).
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Any, Literal, NamedTuple, get_args

from iltero_schemas.models.image.naming import ATTESTATION_MEDIA_TYPES
from iltero_schemas.models.strict_json import strict_json

# No build writes an attestation this large; a reader refuses a larger one before parsing it.
MAX_ATTESTATION_BYTES = 1_048_576
# More subjects than one statement about one image and its platform images names.
MAX_SUBJECTS = 1_024
# The payload type of an envelope that carries an in-toto statement.
_IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"
# The payload type of a plain image signature, which signs an image without saying anything about how it was built.
_SIMPLE_SIGNING_PAYLOAD_TYPE = "application/vnd.dev.cosign.simplesigning.v1+json"
# The in-toto statement versions a reader accepts.
STATEMENT_TYPES = frozenset({"https://in-toto.io/Statement/v1", "https://in-toto.io/Statement/v0.1"})
# The predicate types of a build's provenance: SLSA provenance 1.0, and 0.2 as older statements carry it.
ProvenancePredicateType = Literal["https://slsa.dev/provenance/v1", "https://slsa.dev/provenance/v0.2"]
PROVENANCE_PREDICATE_TYPES: frozenset[str] = frozenset(get_args(ProvenancePredicateType))
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


class UnverifiedAttestationStatement(NamedTuple):
    """What a build's attestation says, read without checking its signature."""

    # The digest of each subject, as ``sha256:<hex>``, sorted and named once each.
    subject_digests: tuple[str, ...]
    predicate_type: str


def _decoded(text: Any, what: str) -> bytes:
    """The bytes of standard, padded base64 ``text``."""
    if not isinstance(text, str):
        raise ValueError(f"{what} is base64 text")
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError(f"{what} is base64 text") from None


def attestation_statement_of_payload(payload: bytes) -> UnverifiedAttestationStatement:
    """The subjects and predicate type of the in-toto statement ``payload``, the bytes an envelope signs.

    Raises ``ValueError`` for bytes that are not an in-toto statement of a build's provenance naming at least one
    subject by its SHA-256 digest. A subject named only by another algorithm is left out.
    """
    if len(payload) > MAX_ATTESTATION_BYTES:
        raise ValueError(f"an in-toto statement is at most {MAX_ATTESTATION_BYTES} bytes")
    statement = strict_json(payload, "an in-toto statement")
    kind = statement.get("_type") if isinstance(statement, dict) else None
    if not isinstance(kind, str) or kind not in STATEMENT_TYPES:
        raise ValueError(f"an attestation carries an in-toto statement of type {' or '.join(sorted(STATEMENT_TYPES))}")
    predicate_type = statement.get("predicateType")
    if not isinstance(predicate_type, str) or predicate_type not in PROVENANCE_PREDICATE_TYPES:
        raise ValueError("an attestation of a build is its SLSA provenance")
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not subjects or len(subjects) > MAX_SUBJECTS:
        raise ValueError(f"an in-toto statement names 1 to {MAX_SUBJECTS} subjects")
    digests: set[str] = set()
    for subject in subjects:
        named = subject.get("digest") if isinstance(subject, dict) else None
        if not isinstance(named, dict):
            raise ValueError("each subject of an in-toto statement names its digests")
        if "sha256" not in named:
            continue
        value = named["sha256"]
        if not isinstance(value, str) or not _SHA256_HEX.fullmatch(value):
            raise ValueError("a subject's sha256 digest is 64 lower-case hexadecimal characters")
        digests.add(f"sha256:{value}")
    if not digests:
        raise ValueError("an in-toto statement names at least one subject by its sha256 digest")
    return UnverifiedAttestationStatement(tuple(sorted(digests)), predicate_type)


def attestation_statement_of(bundle: bytes) -> UnverifiedAttestationStatement:
    """The subjects and predicate type of the statement the Sigstore bundle ``bundle`` carries.

    Raises ``ValueError`` for bytes that are not a bundle of one signed in-toto statement of a build's provenance.
    The bundle's signature is not checked.
    """
    if len(bundle) > MAX_ATTESTATION_BYTES:
        raise ValueError(f"an attestation is at most {MAX_ATTESTATION_BYTES} bytes")
    document = strict_json(bundle, "an attestation")
    media_type = document.get("mediaType") if isinstance(document, dict) else None
    if not isinstance(document, dict) or not isinstance(media_type, str) or media_type not in ATTESTATION_MEDIA_TYPES:
        raise ValueError("an attestation is a Sigstore bundle that names its media type")
    if "messageSignature" in document:
        raise ValueError("an attestation is a signed in-toto statement, not the signature of a file")
    envelope = document.get("dsseEnvelope")
    if not isinstance(envelope, dict):
        raise ValueError("an attestation carries its statement in a signed envelope (dsseEnvelope)")
    payload_type = envelope.get("payloadType")
    if payload_type == _SIMPLE_SIGNING_PAYLOAD_TYPE:
        raise ValueError("an attestation says how the image was built; a signature of the image alone says nothing")
    if payload_type != _IN_TOTO_PAYLOAD_TYPE:
        raise ValueError(f"an attestation's envelope carries an in-toto statement ({_IN_TOTO_PAYLOAD_TYPE})")
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise ValueError("an attestation's envelope carries exactly one signature")
    return attestation_statement_of_payload(_decoded(envelope.get("payload"), "an attestation's envelope payload"))


def check_attestation_subject(image_digest: str, statement: UnverifiedAttestationStatement) -> None:
    """Raise ``ValueError`` unless ``statement`` names the image by its own digest: for an image built for several
    platforms, its index digest, which covers every platform image.

    Run it before sending an attestation, and again once its signature is verified.
    """
    if image_digest not in statement.subject_digests:
        raise ValueError("the attestation names the image's own digest")
