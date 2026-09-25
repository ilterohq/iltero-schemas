"""Building a signed assertion bundle: the files, the bytes that are signed, and the tarball.

An assertion bundle is an Open Policy Agent (OPA) bundle: a gzip-compressed
tar file holding

- ``.manifest``: the bundle's ``revision``, its ``roots`` (one path per
  assertion under the policy tree), the policy language version, and
  ``metadata.iltero``, which names every assertion with the digests of its
  document, its source and its compiled module;
- one compiled module per assertion, named ``<ID>.rego``, at the top level;
- ``.signatures.json``: one signature over the digest of every other file.

The files and the bytes to sign are a pure function of the assertions'
source documents and the versions, so anyone holding the sources builds the
same ones. ``revision`` is the digest of ``metadata.iltero``: the assertions
together with the compiler version and the oldest tool allowed. Signing is
left to the holder of the key; this module produces the bytes to sign and
places the signature. The compressed tarball itself can differ between
compression libraries, which is why a bundle's ``digest`` is taken over the
bytes that were served.

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

from iltero_schemas.ast import parse_document, source_digest
from iltero_schemas.ast.document import load_document
from iltero_schemas.canonical import canonical_bytes, digest, digest_of, required_assertion_digest
from iltero_schemas.compiler import COMPILER_VERSION, PACKAGE_PREFIX, compile
from iltero_schemas.models.assertion import VERSION_PATTERN
from iltero_schemas.models.bundle import API_VERSION, MAX_BUNDLE_ASSERTIONS, BundleDescriptor

MANIFEST = ".manifest"
SIGNATURES = ".signatures.json"
# The scope every signature names; a verifier asks for exactly this one.
SCOPE = "iltero-assertions"
ALGORITHM = "ES256"
# An ES256 signature is the two 32-byte numbers r and s, one after the other.
SIGNATURE_BYTES = 64
# The order of the P-256 curve. An ECDSA signature (r, s) stays valid with s replaced by ORDER - s, so only the
# smaller of the two ("low-S") is accepted: one signing then gives one signature, and one tarball digest.
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
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
    """Every file of a bundle except its signature, with the metadata and revision the manifest carries."""

    members: tuple[Member, ...]
    metadata: Mapping[str, Any]
    revision: str
    files: Mapping[str, bytes]


def unsigned_bundle(sources: Sequence[str], *, min_cli_version: str) -> UnsignedBundle:
    """The files of a bundle of ``sources``, built by this package's compiler.

    A bundle holds each assertion id once: two versions of one assertion would
    compile to the same policy package. ``min_cli_version`` is the oldest tool
    that may evaluate the bundle, written ``X.Y.Z``; it is signed with the rest.
    """
    if not sources:
        raise BundleError("a bundle holds at least one assertion")
    if len(sources) > MAX_BUNDLE_ASSERTIONS:
        raise BundleError(f"a bundle holds at most {MAX_BUNDLE_ASSERTIONS} assertions")
    if not re.fullmatch(VERSION_PATTERN, min_cli_version):
        raise BundleError("min_cli_version must be a version such as 1.2.3")
    members = tuple(sorted((member(source) for source in sources), key=lambda m: m.id))
    ids = [m.id for m in members]
    if len(set(ids)) != len(ids):
        raise BundleError("a bundle holds each assertion id once")
    metadata = {
        "apiVersion": API_VERSION,
        "compiler_version": COMPILER_VERSION,
        "min_cli_version": min_cli_version,
        "assertion_set_digest": required_assertion_digest((m.id, m.version, m.digest) for m in members),
        "assertions": [m.record() for m in members],
    }
    revision = digest_of(metadata)
    manifest = {
        "revision": revision,
        "roots": [f"{_ROOT_PREFIX}/{m.id}" for m in members],
        "rego_version": REGO_VERSION,
        "metadata": {"iltero": metadata},
    }
    files = {MANIFEST: canonical_bytes(manifest), **{m.file: m.module for m in members}}
    return UnsignedBundle(members, MappingProxyType(metadata), revision, MappingProxyType(files))


def _b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def signing_input(bundle: UnsignedBundle, *, key_id: str) -> bytes:
    """The bytes the key signs: a JSON Web Signature header and payload listing every file and its digest.

    The signer computes SHA-256 over these bytes and signs that digest with
    ES256 (ECDSA on the P-256 curve). A signing service that takes the digest
    rather than the bytes is given exactly that value. The signature it
    returns is usually DER-encoded. It goes to :func:`descriptor` as the raw
    64 bytes, r then s.
    """
    header = {"alg": ALGORITHM, "kid": key_id, "typ": "JWT"}
    files = [
        {"name": name, "hash": hashlib.sha256(bundle.files[name]).hexdigest(), "algorithm": "SHA-256"}
        for name in sorted(bundle.files)
    ]
    payload = {"files": files, "keyid": key_id, "scope": SCOPE}
    return _b64url(canonical_bytes(header)) + b"." + _b64url(canonical_bytes(payload))


def _r_and_s(signature: bytes) -> tuple[int, int]:
    """The two numbers of a raw 64-byte ``r‖s`` signature. Each must lie strictly between 0 and the curve order."""
    if len(signature) != SIGNATURE_BYTES:
        raise BundleError(f"an {ALGORITHM} signature is {SIGNATURE_BYTES} bytes, r then s")
    half = SIGNATURE_BYTES // 2
    r, s = int.from_bytes(signature[:half], "big"), int.from_bytes(signature[half:], "big")
    if not (0 < r < P256_ORDER and 0 < s < P256_ORDER):
        raise BundleError(f"an {ALGORITHM} signature's r and s each lie between 0 and the curve order")
    return r, s


def signatures_file(signed: bytes, signature: bytes) -> bytes:
    """``.signatures.json`` for ``signed`` (from :func:`signing_input`) and its raw 64-byte ``r‖s`` signature."""
    _, s = _r_and_s(signature)
    if s > P256_ORDER // 2:
        raise BundleError(f"an {ALGORITHM} signature is written in its low-S form: s at most half the curve order")
    return canonical_bytes({"signatures": [(signed + b"." + _b64url(signature)).decode("ascii")]})


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


def low_s(signature: bytes) -> bytes:
    """``signature`` (raw ``r‖s``) in its low-S form: ``s`` replaced by the curve order minus ``s`` when larger.

    Both forms verify. Signing services do not all return the low one, and a
    bundle carries only that form, so one signing gives one tarball digest.
    """
    _, s = _r_and_s(signature)
    half = SIGNATURE_BYTES // 2
    return signature[:half] + min(s, P256_ORDER - s).to_bytes(half, "big")


def descriptor(bundle: UnsignedBundle, *, key_id: str, signature: bytes) -> BundleDescriptor:
    """The descriptor to serve: ``bundle`` signed under ``key_id``, where ``signature`` is over its signing input.

    The tarball is packed here from the same key id the signing input named, so
    the two cannot disagree. ``signature`` is written in its low-S form
    (:func:`low_s`), whichever form the signer returned. A signer checks its own
    output with ``check_descriptor`` and a signature check before storing it.
    """
    signed_bundle = tarball(
        {**bundle.files, SIGNATURES: signatures_file(signing_input(bundle, key_id=key_id), low_s(signature))}
    )
    return BundleDescriptor.model_validate(
        {
            "apiVersion": API_VERSION,
            "revision": bundle.revision,
            "digest": digest(signed_bundle),
            "key_id": key_id,
            "algorithm": ALGORITHM,
            "compiler_version": bundle.metadata["compiler_version"],
            "min_cli_version": bundle.metadata["min_cli_version"],
            "assertion_set_digest": bundle.metadata["assertion_set_digest"],
            "assertions": [{**m.record(), "source": m.source} for m in bundle.members],
            "tarball": base64.b64encode(signed_bundle).decode("ascii"),
        }
    )
