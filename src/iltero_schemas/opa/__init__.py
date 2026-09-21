"""The pinned Open Policy Agent (OPA) release.

Every Iltero component evaluates assertions with the same OPA release. ``PIN``
names that release and the SHA-256 digest of its published binary for each
supported platform. A consumer must verify the binary it is about to execute
against the digest for its platform before every invocation, and refuse to run
on a mismatch.

The pin is data, reviewed like code: ``PIN.json`` next to this module is the
only place it is written down.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from importlib import resources
from types import MappingProxyType

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")

# ``platform.machine()`` spellings that mean the same architecture.
_MACHINE_ALIASES: Mapping[str, str] = MappingProxyType(
    {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}
)


@dataclass(frozen=True)
class OpaBinary:
    """One platform's release asset and its digest."""

    platform: str
    asset: str
    sha256: str


@dataclass(frozen=True)
class OpaPin:
    """The pinned release and its binaries, keyed by platform."""

    version: str
    release_tag: str
    binaries: Mapping[str, OpaBinary]


def platform_key(system: str, machine: str) -> str:
    """Return the ``PIN.binaries`` key for a host, e.g. ``linux-x86_64``.

    ``system`` is ``platform.system()`` and ``machine`` is
    ``platform.machine()``. Raises ``KeyError`` for an unsupported host.
    """
    normalized_system = system.lower()
    normalized_machine = _MACHINE_ALIASES[machine.lower()]
    key = f"{normalized_system}-{normalized_machine}"
    if key not in PIN.binaries:
        raise KeyError(key)
    return key


def _load() -> OpaPin:
    raw = json.loads(resources.files(__package__).joinpath("PIN.json").read_text(encoding="utf-8"))
    binaries = {}
    for key, entry in raw["binaries"].items():
        if not _SHA256_HEX.fullmatch(entry["sha256"]):
            raise ValueError(f"PIN.json: {key}: sha256 is not 64 lowercase hex characters")
        binaries[key] = OpaBinary(platform=key, asset=entry["asset"], sha256=entry["sha256"])
    return OpaPin(version=raw["version"], release_tag=raw["release_tag"], binaries=MappingProxyType(binaries))


PIN: OpaPin = _load()
