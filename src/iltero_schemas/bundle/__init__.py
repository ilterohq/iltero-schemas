"""Signed assertion bundles: building one (``build``), checking a served one before use (``check``) and reading a
run's pinned one back under any key status (``read_back``)."""

from iltero_schemas.bundle.build import (
    BundleError,
    UnsignedBundle,
    descriptor,
    files_signing_input,
    signing_input,
    unsigned_bundle,
)
from iltero_schemas.bundle.check import UnverifiedBundle, check_descriptor, signature_in, signature_of
from iltero_schemas.bundle.read_back import ReadBackBundle, read_signed_bundle
from iltero_schemas.signing import BUNDLE_SIGNING_SCOPE, SIGNATURE_BYTES, SIGNING_ALGORITHM, normalized_signature

__all__ = [
    "SIGNING_ALGORITHM",
    "BUNDLE_SIGNING_SCOPE",
    "SIGNATURE_BYTES",
    "BundleError",
    "UnsignedBundle",
    "UnverifiedBundle",
    "ReadBackBundle",
    "check_descriptor",
    "descriptor",
    "files_signing_input",
    "normalized_signature",
    "read_signed_bundle",
    "signature_in",
    "signature_of",
    "signing_input",
    "unsigned_bundle",
]
