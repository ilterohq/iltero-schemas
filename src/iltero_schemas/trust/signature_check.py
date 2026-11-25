"""The signature check a reader supplies to verify what a trusted key signed."""

from collections.abc import Callable

# Whether an ES256 signature verifies: called with the key's SubjectPublicKeyInfo DER bytes, the signed bytes and the
# raw 64-byte ``r‖s`` signature. The reader supplies it; this package holds no cryptography.
SignatureCheck = Callable[[bytes, bytes, bytes], bool]
