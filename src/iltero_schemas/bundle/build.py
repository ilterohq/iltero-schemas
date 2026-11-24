"""Building a signed assertion bundle: the files, the bytes that are signed, and the tarball.

An assertion bundle is an Open Policy Agent (OPA) bundle: a gzip-compressed
tar file holding

- ``.manifest``: the bundle's content digest (under OPA's key ``revision``), its ``roots`` (one path per
  assertion under the policy tree), the policy language version, and
  ``metadata.iltero``, which names every assertion with the digests of its
  document, its source and its compiled module;
- one compiled module per assertion, named ``<ID>.rego``, at the top level;
- ``.signatures.json``: one signature over the digest of every other file.

The files and the bytes to sign are a pure function of the assertions'
source documents and the versions, so anyone holding the sources builds the
same ones. The content digest is the digest of ``metadata.iltero``: the assertions
together with the compiler version, the evaluator's allowlist and the oldest tool
allowed. Signing is
left to the holder of the key; this module produces the bytes to sign and
places the signature. The compressed tarball itself can differ between
compression libraries, which is why a bundle's ``tarball_digest`` is taken over
the bytes that were served.

A file's digest is SHA-256 over its bytes. OPA hashes a JSON file over its
own compact, key-sorted encoding; the manifest is written in exactly that
form, so the two agree.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import re
import tarfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from iltero_schemas import signing
from iltero_schemas.ast import parse_document, source_digest
from iltero_schemas.ast.document import load_document
from iltero_schemas.canonical import canonical_bytes, digest, digest_of, required_assertion_digest
from iltero_schemas.compiler import COMPILER_VERSION, PACKAGE_PREFIX, compile
from iltero_schemas.models.common.assertion import VERSION_PATTERN
from iltero_schemas.models.common.bundle import API_VERSION, BUNDLE_KIND, KIND, MAX_BUNDLE_ASSERTIONS, BundleDescriptor
from iltero_schemas.opa.capabilities import CAPABILITIES_DIGEST

MANIFEST = ".manifest"
SIGNATURES = ".signatures.json"
# The policy language version the modules are written in.
REGO_VERSION = 1
_ROOT_PREFIX = PACKAGE_PREFIX.replace(".", "/")


class BundleError(ValueError):
    """A bundle, or a descriptor of one, that breaks a rule; the message names the rule."""


@dataclass(frozen=True)
class Member:
    """One assertion of a bundle: its identity, the digests that name it, its source and its compiled module."""

    id: str
    version: str
    digest: str
    source_digest: str
    compiled_digest: str
    source: str
    module: bytes

    @property
    def file(self) -> str:
        return f"{self.id}.rego"

    def record(self) -> dict[str, str]:
        """How ``metadata.iltero`` and the descriptor name this assertion."""
        return {
            "id": self.id,
            "version": self.version,
            "digest": self.digest,
            "source_digest": self.source_digest,
            "compiled_digest": self.compiled_digest,
        }


def member(source: str) -> Member:
    """Read one assertion's YAML source and compile it; a broken document raises the parser's own error."""
    document = load_document(source)
    assertion = parse_document(document)
    module = compile(assertion)
    return Member(
        id=assertion.id,
        version=assertion.version,
        digest=digest_of(document),
        source_digest=source_digest(assertion),
        compiled_digest=module.digest,
        source=source,
        module=module.source,
    )


@dataclass(frozen=True)
class UnsignedBundle:
    """Every file of a bundle except its signature, with the metadata and content digest the manifest carries."""

    members: tuple[Member, ...]
    metadata: Mapping[str, Any]
    content_digest: str
    files: Mapping[str, bytes]


def unsigned_bundle(sources: Sequence[str], *, minimum_cli_version: str) -> UnsignedBundle:
    """The files of a bundle of ``sources``, built by this package's compiler.

    A bundle holds each assertion id once: two versions of one assertion would
    compile to the same policy package. ``minimum_cli_version`` is the oldest tool
    that may evaluate the bundle, written ``X.Y.Z``; it is signed with the rest.
    """
    if not sources:
        raise BundleError("a bundle holds at least one assertion")
    if len(sources) > MAX_BUNDLE_ASSERTIONS:
        raise BundleError(f"a bundle holds at most {MAX_BUNDLE_ASSERTIONS} assertions")
    if not re.fullmatch(VERSION_PATTERN, minimum_cli_version):
        raise BundleError("minimum_cli_version must be a version such as 1.2.3")
    members = tuple(sorted((member(source) for source in sources), key=lambda m: m.id))
    ids = [m.id for m in members]
    if len(set(ids)) != len(ids):
        raise BundleError("a bundle holds each assertion id once")
    metadata = {
        "apiVersion": API_VERSION,
        "kind": BUNDLE_KIND,
        "compiler_version": COMPILER_VERSION,
        "capabilities_digest": CAPABILITIES_DIGEST,
        "minimum_cli_version": minimum_cli_version,
        "assertion_set_digest": required_assertion_digest((m.id, m.version, m.digest) for m in members),
        "assertions": [m.record() for m in members],
    }
    content_digest = digest_of(metadata)
    manifest = {
        "revision": content_digest,
        "roots": [f"{_ROOT_PREFIX}/{m.id}" for m in members],
        "rego_version": REGO_VERSION,
        "metadata": {"iltero": metadata},
    }
    files = {MANIFEST: canonical_bytes(manifest), **{m.file: m.module for m in members}}
    return UnsignedBundle(members, MappingProxyType(metadata), content_digest, MappingProxyType(files))


def signing_input(bundle: UnsignedBundle, *, key_id: str) -> bytes:
    """The bytes the key signs: a JSON Web Signature header and payload listing every file and its digest.

    The signer computes SHA-256 over these bytes and signs that digest with
    ES256 (ECDSA on the P-256 curve). A signing service that takes the digest
    rather than the bytes is given exactly that value. The signature it
    returns is usually DER-encoded. It goes to :func:`descriptor` as the raw
    64 bytes, r then s.
    """
    return files_signing_input(bundle.files, key_id=key_id)


def files_signing_input(files: Mapping[str, bytes], *, key_id: str) -> bytes:
    """The bytes the key signs for a bundle of ``files``, every file but its signature: each file's name and SHA-256
    digest, by name, under ``key_id`` and the bundle signing scope."""
    listed = [
        {"name": name, "hash": hashlib.sha256(files[name]).hexdigest(), "algorithm": "SHA-256"}
        for name in sorted(files)
    ]
    return signing.signing_input(key_id=key_id, scope=signing.BUNDLE_SIGNING_SCOPE, payload={"files": listed})


def signatures_file(signed: bytes, signature: bytes) -> bytes:
    """``.signatures.json`` for ``signed`` (from :func:`signing_input`) and its raw 64-byte ``r‖s`` signature."""
    try:
        signing.check_low_s(signature)
    except signing.SignatureError as error:
        raise BundleError(str(error)) from None
    return canonical_bytes({"signatures": [(signed + b"." + signing.base64url(signature)).decode("ascii")]})


def tarball(files: Mapping[str, bytes]) -> bytes:
    """The files as a gzip-compressed tar: names sorted, no timestamps, owners or permissions of the machine."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name in sorted(files):
            entry = tarfile.TarInfo(name)
            entry.size = len(files[name])
            entry.mode = 0o644
            entry.mtime = 0
            archive.addfile(entry, io.BytesIO(files[name]))
    return gzip.compress(raw.getvalue(), compresslevel=9, mtime=0)


def _normalized(signature: bytes) -> bytes:
    """``signature`` in its low-S form, refused as a ``BundleError`` when it is no ES256 signature at all."""
    try:
        return signing.normalized_signature(signature)
    except signing.SignatureError as error:
        raise BundleError(str(error)) from None


def descriptor(bundle: UnsignedBundle, *, key_id: str, signature: bytes) -> BundleDescriptor:
    """The descriptor to serve: ``bundle`` signed under ``key_id``, where ``signature`` is over its signing input.

    The tarball is packed here from the same key id the signing input named, so
    the two cannot disagree. ``signature`` is written in its low-S form
    (``normalized_signature``), whichever form the signer returned. A signer checks its own
    output with ``check_descriptor`` and a signature check before storing it.
    """
    signed_bundle = tarball(
        {
            **bundle.files,
            SIGNATURES: signatures_file(signing_input(bundle, key_id=key_id), _normalized(signature)),
        }
    )
    return BundleDescriptor.model_validate(
        {
            "apiVersion": API_VERSION,
            "kind": KIND,
            "content_digest": bundle.content_digest,
            "tarball_digest": digest(signed_bundle),
            "key_id": key_id,
            "algorithm": signing.SIGNING_ALGORITHM,
            "compiler_version": bundle.metadata["compiler_version"],
            "capabilities_digest": bundle.metadata["capabilities_digest"],
            "minimum_cli_version": bundle.metadata["minimum_cli_version"],
            "assertion_set_digest": bundle.metadata["assertion_set_digest"],
            "assertions": [{**m.record(), "source": m.source} for m in bundle.members],
            "tarball": base64.b64encode(signed_bundle).decode("ascii"),
        }
    )
