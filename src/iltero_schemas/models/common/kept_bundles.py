"""The served bundle a stage kept, against the trust set, the stage and its events.

A stage of a run the server opened evaluates the assertions of the bundle the server served it, and keeps that bundle's
tarball beside the record as an entry of its evidence register. A reader finds the entry by the tarball digest the stage
names, the stage's own entry first (named ``<stage>/bundle.tar.gz``, ``SERVED_BUNDLE_REF_ID``), so it finds it in a
record package too, which moves every file and keeps each entry's name and digest. The stage's own entry, when the
register holds one, names the stage's tarball. Given the kept tarballs, its trust set and its signature check, it reads
each back with ``bundle.read_back.read_signed_bundle``: the key the stage names is in the trust set, for signing
assertion bundles, the tarball holds its manifest and modules only, the manifest's revision is the digest of its
metadata, and the signed bytes cover exactly its files under that key. The key must not be revoked, the signature must
verify under it, and the content digest and the allowlist digest (``capabilities_digest``) the stage names must be the
ones the signed manifest gives. It then checks that every event that ran over a served bundle names its stage's, and
that each such event's assertion is a module of the tarball whose digest is the event's ``compiled_digest``. A tarball
the bundle reader refuses is a problem, never an exception.

This package holds no cryptography: the reader passes the function that verifies an ES256 signature
(``trust.SignatureCheck``), and the check calls it for each bundle it read back.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from iltero_schemas.bundle.build import MANIFEST, BundleError
from iltero_schemas.bundle.read_back import (
    KEY_NEVER_HELD,
    PINNED_KEY_OF_ANOTHER_PURPOSE,
    REVISION_NOT_ITS_METADATA,
    SIGNATURE_DOES_NOT_COVER,
    ReadBackBundle,
    read_signed_bundle,
)
from iltero_schemas.canonical.common.encoding import digest
from iltero_schemas.models.common.strict_json import strict_json
from iltero_schemas.trust import SignatureCheck, SigningKey

if TYPE_CHECKING:
    from iltero_schemas.models.common.car import CAR, ExecutionBundle

# The name (``ref_id``) of the register entry a stage keeps the tarball of its served bundle as. Readers find the entry
# by its digest, and take the stage's own entry first when stages share a tarball.
SERVED_BUNDLE_REF_ID = "{stage}/bundle.tar.gz"

ANOTHER_TARBALL = "is the stage's served bundle entry, and its digest is not the tarball digest the stage names"
BUNDLE_NOT_IN_THE_REGISTER = (
    "names a served bundle, and the evidence register holds no entry with the digest of its tarball"
)
TARBALL_NOT_GIVEN = (
    "is the stage's served bundle tarball, and the files given do not hold it with the digest the entry names"
)
KEY_NOT_IN_THE_TRUST_SET = (
    "is the stage's served bundle tarball, and the trust set given holds no key with the id the stage names"
)
REVISION_NOT_THE_METADATA = (
    "is the stage's served bundle tarball, and the revision its manifest names is not the digest of its metadata"
)
KEY_OF_ANOTHER_PURPOSE = (
    "is the stage's served bundle tarball, and the key the stage names is not for signing assertion bundles"
)
KEY_REVOKED = "is the stage's served bundle tarball, and the key the stage names is revoked"
SIGNATURE_NOT_VALID = (
    "is the stage's served bundle tarball, and its signature does not verify under the key the stage names"
)
ANOTHER_CONTENT_DIGEST = (
    "is the stage's served bundle tarball, and the content digest the stage names is not the one its signed manifest "
    "gives"
)
ANOTHER_CAPABILITIES_DIGEST = (
    "is the stage's served bundle tarball, and the allowlist digest the stage names is not the one its signed manifest "
    "gives"
)
SIGNATURE_NOT_COVERING_THE_FILES = (
    "is the stage's served bundle tarball, and the bytes it signed do not cover exactly its files under the key the "
    "stage names"
)
TARBALL_NOT_READABLE = "is the stage's served bundle tarball, and it is not a bundle tarball the contract can read"
ANOTHER_BUNDLE = "is not the served bundle the stage ran over"
MODULE_NOT_IN_THE_BUNDLE = "names an assertion that has no module in the stage's kept bundle"
ANOTHER_MODULE = "is not the digest of the module the stage's kept bundle holds for the event's assertion"
# The problem each refusal of the bundle reader gives; any other refusal gives ``TARBALL_NOT_READABLE``.
_REFUSALS = {
    KEY_NEVER_HELD: KEY_NOT_IN_THE_TRUST_SET,
    PINNED_KEY_OF_ANOTHER_PURPOSE: KEY_OF_ANOTHER_PURPOSE,
    REVISION_NOT_ITS_METADATA: REVISION_NOT_THE_METADATA,
    SIGNATURE_DOES_NOT_COVER: SIGNATURE_NOT_COVERING_THE_FILES,
}


@dataclass(frozen=True)
class ServedBundleResults:
    """What ``served_bundle_results`` found: its problems, and the stages whose kept served bundle passed every check:
    read back under a key the trust set holds and has not revoked, its signature verified, its content and allowlist
    digests the stage's, and every module its events ran held."""

    problems: list[tuple[str, str]]
    verified_stages: frozenset[str]


def _signed_capabilities_digest(read: ReadBackBundle) -> object:
    """The allowlist digest the bundle's signed manifest gives, or None when it gives none."""
    try:
        metadata = strict_json(read.files[MANIFEST], MANIFEST)["metadata"]["iltero"]
        return metadata["capabilities_digest"] if isinstance(metadata, dict) else None
    except (ValueError, KeyError, TypeError):
        return None


def _read_back(
    car: CAR,
    stage: str,
    bundle: ExecutionBundle,
    bundles: Mapping[str, bytes],
    keys: Mapping[str, SigningKey],
    verify: SignatureCheck,
) -> tuple[tuple[str, str] | None, ReadBackBundle | None]:
    """The problem of the tarball the stage kept, or the bundle read back from it, signed and verified."""
    own = SERVED_BUNDLE_REF_ID.format(stage=stage)
    named = next(((i, r) for i, r in enumerate(car.evidence_refs) if r.ref_id == own), None)
    if named is not None and named[1].digest != bundle.tarball_digest:
        return (f"evidence_refs.{named[0]}", ANOTHER_TARBALL), None
    entries = [(index, ref) for index, ref in enumerate(car.evidence_refs) if ref.digest == bundle.tarball_digest]
    if not entries:
        return (f"stages.{stage}.execution.bundle", BUNDLE_NOT_IN_THE_REGISTER), None
    index, ref = named if named is not None else entries[0]
    where = f"evidence_refs.{index}"
    data = bundles.get(ref.digest)
    if data is None or digest(data) != ref.digest:
        return (where, TARBALL_NOT_GIVEN), None
    # A served bundle names its key: the event and stage models require it.
    key_id = bundle.key_id or ""
    try:
        read = read_signed_bundle(data, tarball_digest=bundle.tarball_digest, key_id=key_id, keys=keys)
    except BundleError as error:
        return (where, _REFUSALS.get(str(error), TARBALL_NOT_READABLE)), None
    if not read.key.can_verify:
        return (where, KEY_REVOKED), None
    if not verify(read.key.public_key_der, read.signed, read.signature):
        return (where, SIGNATURE_NOT_VALID), None
    if read.content_digest != bundle.content_digest:
        return (where, ANOTHER_CONTENT_DIGEST), None
    if _signed_capabilities_digest(read) != bundle.capabilities_digest:
        return (where, ANOTHER_CAPABILITIES_DIGEST), None
    return None, read


def served_bundle_results(
    car: CAR, bundles: Mapping[str, bytes], keys: Mapping[str, SigningKey], verify: SignatureCheck
) -> ServedBundleResults:
    """The problems of the served bundles ``car``'s stages kept, as (where, what) pairs, given the kept tarballs
    ``bundles`` by digest, the trust set ``keys`` and the reader's signature check ``verify``, and the stages whose
    bundle passed every check.

    Each stage that ran over the server's bundle keeps its tarball as an entry of the register with the digest it names;
    the bundle reader reads it back under the key the stage names, which is not revoked, whose signature ``verify``
    accepts, and whose signed manifest gives the content and allowlist digests the stage names. Each event that ran
    over a served bundle names its stage's, and its assertion is a module of the tarball whose digest is the event's
    ``compiled_digest``.
    """
    problems: list[tuple[str, str]] = []
    read: dict[str, ReadBackBundle] = {}
    failed: set[str] = set()
    for name, record in car.stages.items():
        bundle = record.execution.bundle
        if bundle is None or bundle.kind != "server":
            continue
        problem, read_back = _read_back(car, name.value, bundle, bundles, keys, verify)
        if problem is not None:
            problems.append(problem)
        if read_back is not None:
            read[name.value] = read_back
    for index, event in enumerate(car.events):
        provenance = event.provenance
        if provenance.bundle is None or provenance.bundle.kind != "server":
            continue
        stage_name = event.evaluation.stage.value
        stage = car.stages.get(event.evaluation.stage)
        ran = stage.execution.bundle if stage is not None else None
        named = provenance.bundle
        if ran is None or (named.kind, named.tarball_digest, named.content_digest, named.key_id) != (
            ran.kind,
            ran.tarball_digest,
            ran.content_digest,
            ran.key_id,
        ):
            problems.append((f"events.{index}.provenance.bundle", ANOTHER_BUNDLE))
            failed.add(stage_name)
            continue
        read_back = read.get(stage_name)
        if read_back is None:
            continue
        module = read_back.files.get(f"{event.assertion.id}.rego")
        if module is None:
            problems.append((f"events.{index}.assertion.id", MODULE_NOT_IN_THE_BUNDLE))
            failed.add(stage_name)
        elif digest(module) != provenance.compiled_digest:
            problems.append((f"events.{index}.provenance.compiled_digest", ANOTHER_MODULE))
            failed.add(stage_name)
    return ServedBundleResults(problems=problems, verified_stages=frozenset(set(read) - failed))


def served_bundle_problems(
    car: CAR, bundles: Mapping[str, bytes], keys: Mapping[str, SigningKey], verify: SignatureCheck
) -> list[tuple[str, str]]:
    """The problems ``served_bundle_results`` lists."""
    return served_bundle_results(car, bundles, keys, verify).problems
