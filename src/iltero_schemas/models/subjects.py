"""How a subject is keyed: one value every consumer computes the same way, from the subject's own identity.

A subject's ``key`` is the digest of its kind and its one local identity:

- a resource an IaC tool manages: its address in the tool's configuration,
  scoped by its unit and nothing else;
- a resource only the cloud knows, read after deployment: its cloud identity;
- a change, a deployment or an assurance check: its unit.

The key names an address in a unit, not a cloud resource. A resource replaced
in the cloud keeps its key; a resource moved to another address gets a new
one. Only an identity document ties a key to a cloud resource over time. A
stack, a workspace or an organization is never an input, so a project keeps
every key when it connects to the server. A cloud identity bound later is
added beside the local identity, never in its place.

The key is over the identity's text exactly as its writer gave it: no
Unicode normalization. An IaC tool tells two spellings of one character
apart (composed and decomposed), so they are two addresses with two keys.
"""

from __future__ import annotations

from collections.abc import Sequence

from iltero_schemas.canonical.encoding import digest_of
from iltero_schemas.models.assertion import Stage
from iltero_schemas.models.fields import Identity
from iltero_schemas.models.iac import ADDRESS_SCHEMES
from iltero_schemas.models.providers.aws import SCHEME_AWS_ARN
from iltero_schemas.models.vocabulary import SCHEME_UNIT

# The schemes a resource's address is written in: every IaC tool's.
ADDRESS_IDENTITY_SCHEMES = frozenset(ADDRESS_SCHEMES.values())
# The schemes a resource's cloud identity is written in: each cloud provider's primary identifier.
CLOUD_IDENTITY_SCHEMES = frozenset({SCHEME_AWS_ARN})
# The stages that read resources from the cloud, where a resource no IaC tool manages may be a subject.
CLOUD_STAGES = frozenset({Stage.POST_VERIFY.value, Stage.RUNTIME.value})


def local_identity(kind: str, identities: Sequence[Identity]) -> Identity:
    """The one identity a subject of ``kind`` is keyed by; ``ValueError`` unless it is there exactly once."""
    if kind != "resource":
        return _one(identities, frozenset({SCHEME_UNIT}), f"a {kind} subject")
    if any(identity.scheme in ADDRESS_IDENTITY_SCHEMES for identity in identities):
        return _one(identities, ADDRESS_IDENTITY_SCHEMES, "a resource an IaC tool manages")
    return _one(identities, CLOUD_IDENTITY_SCHEMES, "a resource only the cloud knows")


def _one(identities: Sequence[Identity], schemes: frozenset[str], what: str) -> Identity:
    found = [identity for identity in identities if identity.scheme in schemes]
    if len(found) != 1:
        raise ValueError(f"{what} has exactly one identity in {', '.join(sorted(schemes))}")
    return found[0]


def subject_key(kind: str, identities: Sequence[Identity]) -> str:
    """The key of a subject of ``kind``: the digest of its kind and its local identity, canonically."""
    identity = local_identity(kind, identities)
    # The digested identity always holds its three fields, ``scope`` as ``null`` when it has none.
    return digest_of(
        {"kind": kind, "identity": {"scheme": identity.scheme, "value": identity.value, "scope": identity.scope}}
    )


def unit_of(identity: Identity) -> str:
    """The unit a local identity belongs to; ``ValueError`` for one only the cloud knows."""
    if identity.scheme == SCHEME_UNIT:
        return identity.value
    if identity.scheme in ADDRESS_IDENTITY_SCHEMES and identity.scope is not None and "unit" in identity.scope:
        return identity.scope["unit"]
    raise ValueError(f"a {identity.scheme} identity names no unit")


def check_subject(kind: str, key: str, identities: Sequence[Identity], stage: str, unit: str | None) -> None:
    """Raise ``ValueError`` unless ``key`` is the subject's own and its local identity is well formed.

    ``unit`` is the unit the document belongs to, when it names one: the local identity must then be of it.
    """
    identity = local_identity(kind, identities)
    if identity.scheme in ADDRESS_IDENTITY_SCHEMES and (
        identity.scope is None or set(identity.scope) != {"unit"} or unit not in (None, identity.scope["unit"])
    ):
        raise ValueError("a resource's address is scoped by its own unit and nothing else")
    if identity.scheme == SCHEME_UNIT and (identity.scope is not None or unit not in (None, identity.value)):
        raise ValueError(f"a {kind} subject is its own unit, with no scope")
    if identity.scheme in CLOUD_IDENTITY_SCHEMES and stage not in CLOUD_STAGES:
        raise ValueError(f"a resource only the cloud knows is read after deployment, never at {stage}")
    if key != subject_key(kind, identities):
        raise ValueError("a subject's key is the digest of its kind and its local identity")
