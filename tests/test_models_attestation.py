"""A build's attestation, read before its signature is checked: the images it is about, and that it is provenance."""

from __future__ import annotations

import base64
import json
import re
from typing import Any

import pytest

from iltero_schemas.models.attestation import (
    MAX_ATTESTATION_BYTES,
    UnverifiedAttestationStatement,
    attestation_statement_of,
    attestation_statement_of_payload,
    check_attestation_subject,
)
from tests.conftest import VECTORS

ATTESTATIONS = VECTORS / "attestations"
CASES: list[dict[str, Any]] = json.loads((ATTESTATIONS / "cases.json").read_text(encoding="utf-8"))["cases"]
READ = [case for case in CASES if "message" not in case]
REFUSED = [case for case in CASES if "message" in case]
PROVENANCE_V1 = "https://slsa.dev/provenance/v1"
PROVENANCE = json.loads((ATTESTATIONS / "provenance_v1.sigstore.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", READ, ids=[case["name"] for case in READ])
def test_an_attestation_of_a_builds_provenance_names_its_subjects_by_sha256(case: dict[str, Any]) -> None:
    statement = attestation_statement_of((ATTESTATIONS / case["file"]).read_bytes())
    assert list(statement.subject_digests) == case["subject_digests"]
    assert statement.predicate_type == case["predicate_type"]


@pytest.mark.parametrize("case", REFUSED, ids=[case["name"] for case in REFUSED])
def test_an_attestation_that_is_not_one_signed_provenance_statement_is_refused(case: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match=f"^{re.escape(case['message'])}$"):
        attestation_statement_of((ATTESTATIONS / case["file"]).read_bytes())


def test_the_statement_is_read_the_same_from_the_payload_bytes_the_envelope_signs() -> None:
    payload = base64.b64decode(PROVENANCE["dsseEnvelope"]["payload"])
    expected = attestation_statement_of((ATTESTATIONS / "provenance_v1.sigstore.json").read_bytes())
    assert attestation_statement_of_payload(payload) == expected


def test_an_attestation_over_its_size_limit_is_refused_before_it_is_read() -> None:
    oversized = b" " * (MAX_ATTESTATION_BYTES + 1)
    with pytest.raises(ValueError, match=f"an attestation is at most {MAX_ATTESTATION_BYTES} bytes"):
        attestation_statement_of(oversized)
    with pytest.raises(ValueError, match=f"an in-toto statement is at most {MAX_ATTESTATION_BYTES} bytes"):
        attestation_statement_of_payload(oversized)


def test_an_attestation_is_read_strictly() -> None:
    with pytest.raises(ValueError):
        attestation_statement_of(b'{"mediaType": 1, "mediaType": 2}')


def test_an_attestation_names_the_image_by_its_own_digest_not_only_a_platform_image() -> None:
    image, platform = "sha256:" + "1" * 64, "sha256:" + "2" * 64
    check_attestation_subject(image, UnverifiedAttestationStatement((image, platform), PROVENANCE_V1))
    with pytest.raises(ValueError, match="the attestation names the image's own digest"):
        check_attestation_subject(image, UnverifiedAttestationStatement((platform,), PROVENANCE_V1))
