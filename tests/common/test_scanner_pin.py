"""The scanner pin holds: each release is the one its kept files give, and the loader refuses what breaks it."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

import pytest

from iltero_schemas.models.common.scanners import SCANNER_TOOLS
from iltero_schemas.opa.pin import OPA_RELEASE_PIN
from iltero_schemas.scanners.common import pin
from iltero_schemas.scanners.common.pin import SCANNER_PIN

RAW: dict[str, Any] = json.loads(pin._file("PIN.json").decode("utf-8"))
PYTHON_VERSIONS = ("cp311", "cp312", "cp313", "cp314")


def test_trivy_is_pinned_for_every_platform_the_policy_evaluator_is() -> None:
    assert set(SCANNER_PIN.trivy.programs) == set(OPA_RELEASE_PIN.binaries)


def test_each_trivy_archive_is_the_one_the_kept_signed_checksums_file_gives() -> None:
    signed = pin._file(SCANNER_PIN.trivy.checksums_file).decode("utf-8")
    for program in SCANNER_PIN.trivy.programs.values():
        assert f"{program.archive_sha256}  {program.archive}" in signed.splitlines()
        assert program.archive_format in pin.ARCHIVE_FORMATS
        assert program.program == ("trivy.exe" if program.platform.startswith("windows") else "trivy")


def test_trivy_s_checksums_file_is_signed_by_its_release_workflow_at_the_release_tag() -> None:
    trivy = SCANNER_PIN.trivy
    bundle = json.loads(pin._file(trivy.signature_bundle_file))
    assert trivy.certificate_identity == (
        f"https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/{trivy.release_tag}"
    )
    assert trivy.certificate_oidc_issuer == "https://token.actions.githubusercontent.com"
    assert int(bundle["verificationMaterial"]["tlogEntries"][0]["logIndex"]) == trivy.transparency_log_index
    assert trivy.release_tag == f"v{trivy.version}" and len(trivy.release_commit) == 40


def test_checkov_is_locked_for_every_platform_and_python_version_the_iltero_cli_supports() -> None:
    covered = {(lock.platform, lock.python_version) for lock in SCANNER_PIN.checkov.locks}
    assert covered == {(platform, python) for platform in OPA_RELEASE_PIN.binaries for python in PYTHON_VERSIONS}
    for arch in ("aarch64", "x86_64"):
        linux = {lock.wheel_platform for lock in SCANNER_PIN.checkov.locks if lock.platform == f"linux-{arch}"}
        assert linux == {f"manylinux_2_17_{arch}", f"manylinux_2_28_{arch}", f"musllinux_1_2_{arch}"}


def test_each_checkov_lock_names_the_pinned_release_and_only_wheels() -> None:
    for lock in SCANNER_PIN.checkov.locks:
        lines = pin._file(lock.file).decode("utf-8").splitlines()
        assert (
            f"checkov=={SCANNER_PIN.checkov.version} --hash=sha256:{SCANNER_PIN.checkov.wheel_sha256}  # "
            + (SCANNER_PIN.checkov.wheel_file)
            in lines
        )
        assert all(line.endswith(".whl") for line in lines)


def test_the_digests_an_evaluation_may_name_are_the_program_or_the_locks_of_its_target() -> None:
    linux = SCANNER_PIN.digests("checkov", "linux-x86_64", "cp312")
    assert len(linux) == 2  # the glibc and the musl lock
    assert SCANNER_PIN.digests("checkov", "linux-x86_64", None) == frozenset()
    assert SCANNER_PIN.digests("trivy", "darwin-aarch64", None) == {
        SCANNER_PIN.trivy.programs["darwin-aarch64"].program_sha256
    }


def test_a_trivy_archive_the_signed_checksums_do_not_give_is_refused() -> None:
    raw = copy.deepcopy(RAW["trivy"])
    raw["programs"]["linux-x86_64"]["archive_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="not the digest the signed checksums file gives"):
        pin._trivy(raw)


def test_an_archive_format_trivy_does_not_ship_is_refused() -> None:
    raw = copy.deepcopy(RAW["trivy"])
    raw["programs"]["linux-x86_64"]["archive_format"] = "rar"
    with pytest.raises(ValueError, match="archive_format is not one of"):
        pin._trivy(raw)


def test_a_lock_whose_file_is_not_the_one_its_digest_names_is_refused() -> None:
    entry = {**RAW["checkov"]["locks"][0], "sha256": "0" * 64}
    with pytest.raises(ValueError, match="the file's digest is not the one the pin gives"):
        pin._lock(entry, RAW["checkov"]["version"])


def test_a_lock_naming_a_source_distribution_or_unsorted_lines_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    entry = RAW["checkov"]["locks"][0]
    lines = pin._file(entry["file"]).decode("utf-8").splitlines()
    for changed in (
        [*lines[:-1], lines[-1].replace(".whl", ".tar.gz")],
        list(reversed(lines)),
    ):
        data = "".join(f"{line}\n" for line in changed).encode("utf-8")
        monkeypatch.setattr(pin, "_file", lambda name, data=data: data)
        with pytest.raises(ValueError, match="one wheel per package, a line each, sorted"):
            pin._lock({**entry, "sha256": hashlib.sha256(data).hexdigest()}, RAW["checkov"]["version"])


def test_a_target_locked_twice_is_refused() -> None:
    raw = copy.deepcopy(RAW["checkov"])
    raw["locks"].append(raw["locks"][0])
    with pytest.raises(ValueError, match="names each platform, wheel platform and Python version once"):
        pin._checkov(raw)


def test_every_scanner_a_record_may_name_has_a_pinned_release_and_no_other_does() -> None:
    for tool in SCANNER_TOOLS:
        assert SCANNER_PIN.version(tool)
    with pytest.raises(KeyError, match="no release of semgrep is pinned"):
        SCANNER_PIN.version("semgrep")
    with pytest.raises(KeyError, match="no release of semgrep is pinned"):
        SCANNER_PIN.digests("semgrep", "linux-x86_64", None)


def test_a_digest_that_is_not_64_lowercase_hex_characters_is_refused() -> None:
    raw = copy.deepcopy(RAW["checkov"])
    raw["wheel"]["sha256"] = "A" * 64
    with pytest.raises(ValueError, match="is not 64 lowercase hex characters"):
        pin._checkov(raw)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"python_version": "cp313"}, "the file is named for its release, wheel platform and Python version"),
        ({"platform": "linux-x86_64"}, "the wheel platform is not one of its platform's architecture"),
        ({"platform": "linux-s390x"}, "the wheel platform is not one of its platform's architecture"),
    ],
    ids=["file_names_another_target", "another_architecture", "unknown_architecture"],
)
def test_a_lock_whose_fields_do_not_match_its_file_or_platform_is_refused(change: dict[str, str], message: str) -> None:
    entry = next(lock for lock in RAW["checkov"]["locks"] if lock["wheel_platform"] == "musllinux_1_2_aarch64")
    with pytest.raises(ValueError, match=message):
        pin._lock({**entry, **change}, RAW["checkov"]["version"])


def test_a_lock_naming_a_python_version_that_is_not_an_interpreter_tag_is_refused() -> None:
    entry = {**RAW["checkov"]["locks"][0], "python_version": "3.12"}
    entry["file"] = f"locks/checkov-{RAW['checkov']['version']}-{entry['wheel_platform']}-3.12.txt"
    with pytest.raises(ValueError, match="python_version is an interpreter tag"):
        pin._lock(entry, RAW["checkov"]["version"])


def test_a_checksums_file_with_a_malformed_or_repeated_line_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    line = f"{'a' * 64}  trivy.tar.gz"
    for text in (f"{line}\n{line}\n", "not a digest  trivy.tar.gz\n"):
        monkeypatch.setattr(pin, "_file", lambda name, text=text: text.encode("utf-8"))
        with pytest.raises(ValueError, match="each line is a digest, two spaces and a file named once"):
            pin._checksums("checksums.txt")
