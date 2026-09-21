"""The OPA pin is data every consumer trusts; these tests keep it well-formed."""

from __future__ import annotations

import pytest

from iltero_schemas.opa import PIN, OpaBinary, platform_key

_PLATFORMS = {"linux-x86_64", "linux-aarch64", "darwin-x86_64", "darwin-aarch64", "windows-x86_64"}


def test_pin_names_one_release() -> None:
    assert PIN.release_tag == f"v{PIN.version}"


def test_every_supported_platform_is_pinned() -> None:
    assert set(PIN.binaries) == _PLATFORMS
    for key, binary in PIN.binaries.items():
        assert isinstance(binary, OpaBinary)
        assert binary.platform == key
        assert len(binary.sha256) == 64


def test_digests_are_distinct_per_asset() -> None:
    """Two different assets never share a digest; two names for one binary may."""
    by_digest: dict[str, set[str]] = {}
    for binary in PIN.binaries.values():
        by_digest.setdefault(binary.sha256, set()).add(binary.asset)
    for assets in by_digest.values():
        stems = {asset.replace("_static", "") for asset in assets}
        assert len(stems) == 1


def test_pin_is_immutable() -> None:
    with pytest.raises(TypeError):
        PIN.binaries["linux-x86_64"] = OpaBinary("x", "y", "0" * 64)  # type: ignore[index]


@pytest.mark.parametrize(
    ("system", "machine", "expected"),
    [
        ("Linux", "x86_64", "linux-x86_64"),
        ("Linux", "aarch64", "linux-aarch64"),
        ("Darwin", "arm64", "darwin-aarch64"),
        ("Darwin", "x86_64", "darwin-x86_64"),
        ("Windows", "AMD64", "windows-x86_64"),
    ],
)
def test_platform_key(system: str, machine: str, expected: str) -> None:
    assert platform_key(system, machine) == expected


@pytest.mark.parametrize(("system", "machine"), [("FreeBSD", "x86_64"), ("Windows", "ARM64"), ("Linux", "mips")])
def test_unsupported_host_is_refused(system: str, machine: str) -> None:
    with pytest.raises(KeyError):
        platform_key(system, machine)
