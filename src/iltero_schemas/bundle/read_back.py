"""Reading a run's pinned bundle back, under any status of the key that signed it, without compiling it.

A run pins the bundle it was served by the digest of its tarball and the key that signed it. Long after, that key may
be retired or revoked, and a reader still shows the run's bundle. ``read_signed_bundle`` checks what the tarball and the
trust set can show: the tarball is the pinned one, the pinned key is one the trust set holds, the tarball holds its
manifest and assertion modules and nothing else, the manifest's revision is the digest of its metadata, and the
signature covers exactly the tarball's files under the pinned key. It does not look at the key's status and compiles
nothing, so its result is for showing a run's bundle only: the caller still verifies the signature with the key's
public key, and a bundle is evaluated only through ``check.check_descriptor``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from iltero_schemas.bundle.build import MANIFEST, SIGNATURES, BundleError, files_signing_input
from iltero_schemas.bundle.check import read_tarball, signature_in
from iltero_schemas.canonical.common.encoding import digest, digest_of
from iltero_schemas.models.common.strict_json import strict_json
from iltero_schemas.trust import SigningKey

# Why ``read_signed_bundle`` refuses a tarball, for the rules a caller tells apart.
NOT_THE_PINNED_TARBALL = "the tarball is not the one the run pinned"
KEY_NEVER_HELD = "the pinned key_id names a key the trust set never held"
SIGNATURE_DOES_NOT_COVER = "the signature does not cover exactly this tarball's files under the pinned key_id"
REVISION_NOT_ITS_METADATA = f"the revision {MANIFEST} names is not the digest of its metadata"


@dataclass(frozen=True)
class ReadBackBundle:
    """A run's pinned bundle as read back, for showing it only: the key the trust set holds for it, whatever its
    status, the bytes it signed and the signature over them, still to verify, the tarball's files, and the content
    digest its signed manifest gives. Nothing in it may be evaluated, even once its signature verifies."""

    key: SigningKey
    signed: bytes
    signature: bytes
    files: Mapping[str, bytes]
    content_digest: str


def read_signed_bundle(
    tarball: bytes, *, tarball_digest: str, key_id: str, keys: Mapping[str, SigningKey]
) -> ReadBackBundle:
    """The bundle in ``tarball``, read back as the one a run pinned by ``tarball_digest`` and ``key_id``, against the
    trust set ``keys``. Raises ``BundleError`` naming the first rule that fails."""
    if digest(tarball) != tarball_digest:
        raise BundleError(NOT_THE_PINNED_TARBALL)
    key = keys.get(key_id)
    if key is None:
        raise BundleError(KEY_NEVER_HELD)
    files = read_tarball(tarball)
    signed, signature = signature_in(files)
    signed_files = {name: data for name, data in files.items() if name != SIGNATURES}
    if MANIFEST not in signed_files or any(
        name != MANIFEST and not (name.endswith(".rego") and len(name) > len(".rego")) for name in signed_files
    ):
        raise BundleError(f"the tarball must hold {MANIFEST}, {SIGNATURES} and assertion modules, nothing else")
    try:
        manifest = strict_json(signed_files[MANIFEST], MANIFEST)
        revision = manifest["revision"]
        metadata = manifest["metadata"]["iltero"]
        revision_holds = isinstance(revision, str) and digest_of(metadata) == revision
    except (ValueError, KeyError, TypeError, RecursionError):
        revision_holds = False
    if not revision_holds:
        raise BundleError(REVISION_NOT_ITS_METADATA)
    if signed != files_signing_input(signed_files, key_id=key_id):
        raise BundleError(SIGNATURE_DOES_NOT_COVER)
    return ReadBackBundle(key, signed, signature, MappingProxyType(files), revision)
