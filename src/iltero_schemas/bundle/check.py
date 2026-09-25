"""Checking a served bundle before anything in it is evaluated.

A tool that receives a bundle descriptor, before evaluating anything:

1. takes the key the descriptor names from the trust set, refusing one that
   may not verify, and verifies the ES256 signature over :func:`signature_of`'s
   bytes with it — with a signature library, or with OPA's own verification;
2. calls :func:`check_descriptor`, which rebuilds the bundle from the
   assertion sources the descriptor carries, with this package's compiler,
   and requires the tarball to hold exactly those files, byte for byte, and a
   ``.signatures.json`` that is exactly the one a signer of those files under
   that key writes.

It then evaluates the files :func:`check_descriptor` returns, or checks the
tarball's signature with OPA (``opa build --verification-key``) and evaluates
that same file with ``opa eval --bundle``. Either way every
module it evaluates is one it compiled itself from the sources it was given,
signed by a key the trust set names.
"""

from __future__ import annotations

import base64
import binascii
import io
import json
import tarfile
import zlib
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from iltero_schemas.ast import AssertionSyntaxError
from iltero_schemas.ast.document import DocumentError
from iltero_schemas.bundle.build import (
    MANIFEST,
    SIGNATURE_BYTES,
    SIGNATURES,
    BundleError,
    signatures_file,
    signing_input,
    unsigned_bundle,
)
from iltero_schemas.canonical import CanonicalizationError
from iltero_schemas.compiler import COMPILER_VERSION
from iltero_schemas.models.bundle import MAX_BUNDLE_ASSERTIONS, BundleDescriptor
from iltero_schemas.trust import BundleKey

# The tar entry types OPA loads as files; it skips every other type, so no other is accepted here either.
_PLAIN_FILE = (tarfile.REGTYPE, tarfile.AREGTYPE)
# The manifest, the signatures, and one module per assertion.
MAX_MEMBERS = MAX_BUNDLE_ASSERTIONS + 2
# Far more than 1024 modules and their manifest take unpacked.
MAX_UNPACKED_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class UnverifiedBundle:
    """What passed every check but the signature: the key to verify it with, and the files as they were compared.

    Nothing in it may be evaluated until the signature is verified with ``key``.
    """

    key: BundleKey
    files: Mapping[str, bytes]


def _decompressed(data: bytes) -> bytes:
    """``data`` gunzipped, refused as soon as it grows past ``MAX_UNPACKED_BYTES``."""
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = inflater.decompress(data, MAX_UNPACKED_BYTES + 1)
    except zlib.error:
        raise BundleError("the tarball is not gzip-compressed") from None
    if len(out) > MAX_UNPACKED_BYTES or inflater.unconsumed_tail:
        raise BundleError(f"the tarball unpacks to more than {MAX_UNPACKED_BYTES} bytes")
    if not inflater.eof or inflater.unused_data:
        raise BundleError("the tarball is not one complete gzip stream")
    return out


def read_tarball(data: bytes) -> dict[str, bytes]:
    """The files of a bundle tarball by name: only plain files at the top level, each once, within fixed limits.

    A plain file's bytes are part of the unpacked tar, so the unpacked limit
    bounds them too; a sparse file, whose declared size is not, is refused.
    """
    files: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(_decompressed(data)), mode="r:") as archive:
            for entry in archive:
                if len(files) >= MAX_MEMBERS:
                    raise BundleError(f"the tarball holds more than {MAX_MEMBERS} files")
                name = entry.name
                if entry.type not in _PLAIN_FILE or entry.issparse() or not name or "/" in name or name in (".", ".."):
                    raise BundleError(f"the tarball holds something other than a plain top-level file: {name!r}")
                if name in files:
                    raise BundleError(f"the tarball holds {name!r} twice")
                extracted = archive.extractfile(entry)
                if extracted is None:
                    raise BundleError(f"the tarball's {name!r} cannot be read")
                files[name] = extracted.read()
    except tarfile.TarError as exc:
        raise BundleError(f"the tarball cannot be read: {exc}") from None
    return files


def _unique_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    names = [name for name, _ in pairs]
    if len(set(names)) != len(names):
        raise BundleError(f"{SIGNATURES} names a field twice")
    return dict(pairs)


def _signature(files: Mapping[str, bytes]) -> tuple[bytes, bytes]:
    """The signed bytes and raw signature of a bundle's ``.signatures.json``, which must be exactly as written."""
    if SIGNATURES not in files:
        raise BundleError(f"the tarball holds no {SIGNATURES}")
    try:
        document = json.loads(files[SIGNATURES], object_pairs_hook=_unique_fields)
        (token,) = document["signatures"]
        header, payload, encoded = token.split(".")
        signed = f"{header}.{payload}".encode("ascii")
        signature = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except BundleError:
        raise
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError, binascii.Error):
        raise BundleError(f"{SIGNATURES} must hold exactly one signature") from None
    if len(signature) != SIGNATURE_BYTES:
        raise BundleError(f"{SIGNATURES} must hold one {SIGNATURE_BYTES}-byte signature")
    if files[SIGNATURES] != signatures_file(signed, signature):
        raise BundleError(f"{SIGNATURES} is not written the one way this package writes it")
    return signed, signature


def signature_of(descriptor: BundleDescriptor) -> tuple[bytes, bytes]:
    """The signed bytes and the raw 64-byte ``r‖s`` signature, to verify with the key's ``public_key_der``."""
    return _signature(read_tarball(base64.b64decode(descriptor.tarball)))


def check_descriptor(descriptor: BundleDescriptor, keys: Mapping[str, BundleKey]) -> UnverifiedBundle:
    """Check everything about ``descriptor`` but the signature's mathematics.

    ``keys`` is the trust set: ``iltero_schemas.trust.BUNDLE_KEYS``, or a
    development tool's own set. Raises ``BundleError`` naming the first rule
    that fails; returns the key and the files that passed.
    """
    key = keys.get(descriptor.key_id)
    if key is None or not key.can_verify:
        raise BundleError(f"key {descriptor.key_id!r} is not trusted to verify bundles")
    if descriptor.compiler_version != COMPILER_VERSION:
        raise BundleError(
            f"the bundle was compiled by compiler {descriptor.compiler_version}; this package's is {COMPILER_VERSION}"
        )
    try:
        rebuilt = unsigned_bundle([a.source for a in descriptor.assertions], min_cli_version=descriptor.min_cli_version)
    except (DocumentError, AssertionSyntaxError, CanonicalizationError) as exc:
        raise BundleError(f"a source cannot be compiled: {exc}") from None
    described = [{k: v for k, v in a.model_dump().items() if k != "source"} for a in descriptor.assertions]
    if described != [m.record() for m in rebuilt.members]:
        raise BundleError("the digests the descriptor gives are not those of its sources")
    if descriptor.revision != rebuilt.revision:
        raise BundleError("the revision is not the digest of the bundle's metadata")
    files = read_tarball(base64.b64decode(descriptor.tarball))
    if set(files) != {*rebuilt.files, SIGNATURES}:
        raise BundleError(f"the tarball must hold {MANIFEST}, {SIGNATURES} and one module per assertion, nothing else")
    for name, expected in rebuilt.files.items():
        if files[name] != expected:
            raise BundleError(f"{name} is not what this package builds from the bundle's sources")
    signed, _ = _signature(files)
    if signed != signing_input(rebuilt, key_id=descriptor.key_id):
        raise BundleError(f"the signature does not cover exactly this bundle's files under key {descriptor.key_id!r}")
    return UnverifiedBundle(key, MappingProxyType(files))
