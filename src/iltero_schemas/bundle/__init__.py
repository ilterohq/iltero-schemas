"""Signed assertion bundles: building one (``build``) and checking a served one before use (``check``)."""

from iltero_schemas.bundle.build import (
    BUNDLE_SIGNING_SCOPE,
    SIGNATURE_BYTES,
    SIGNING_ALGORITHM,
    BundleError,
    UnsignedBundle,
    descriptor,
    normalized_signature,
    signing_input,
    unsigned_bundle,
)
from iltero_schemas.bundle.check import UnverifiedBundle, check_descriptor, signature_of

__all__ = [
    "SIGNING_ALGORITHM",
    "BUNDLE_SIGNING_SCOPE",
    "SIGNATURE_BYTES",
    "BundleError",
    "UnsignedBundle",
    "UnverifiedBundle",
    "check_descriptor",
    "descriptor",
    "normalized_signature",
    "signature_of",
    "signing_input",
    "unsigned_bundle",
]
