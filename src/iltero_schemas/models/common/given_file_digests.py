"""Which digest a record names for a file the pipeline gave, by how the record keeps the file and who opened the run.

A file the record keeps exactly as the pipeline gave it is named by its own digest, a plain ``sha256:`` digest equal
to the digest of the kept file. A file the record keeps only redacted, or never keeps, is named in a run the server
opened by its keyed digest (``canonical.common.run_digest_key.keyed_given_file_digest``, ``hmac-sha256:``), and in a run
the tool opened by no digest at all (null). This module checks the given file digest of each entry of the evidence
register; each change type checks the digests its own change names (``models.iac.given_file_digests`` for a change made
with an IaC tool). The one file kept with no redaction policy but not as given is the copy of a project's scanner check
mapping, kept as canonical JSON: its given file digest is the plain digest of the project's file.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING

from iltero_schemas.canonical.common.run_digest_key import KEYED_DIGEST_PREFIX

if TYPE_CHECKING:
    from iltero_schemas.models.common.car import CAR
    from iltero_schemas.models.common.fields import RunOpenedBy

SERVER_RUN_FORM = (
    "a record of a run the server opened names every file it keeps redacted, or never keeps, by its keyed digest"
)
TOOL_RUN_FORM = (
    "a record of a run the tool opened names no given file digest of a file it keeps redacted, or never keeps"
)
KEPT_AS_GIVEN = "a file the record keeps as the pipeline gave it is named by its own digest"
PROJECT_MAPPING_COPY = (
    "the copy of a project's scanner check mapping is named by the plain digest of the project's file"
)


def follows_the_run(value: str | None, run_opened_by: RunOpenedBy) -> bool:
    """Whether ``value``, the digest of a file kept redacted or never kept, has the form of who opened the run: keyed
    in a run the server opened, null in a run the tool opened."""
    if run_opened_by == "server":
        return value is not None and value.startswith(KEYED_DIGEST_PREFIX)
    return value is None


def form_problem(values: Iterable[str | None], run_opened_by: RunOpenedBy) -> str | None:
    """The refusal for ``values``, digests of files kept redacted or never kept, when any of them does not have the
    form of who opened the run; None when every one has it."""
    if all(follows_the_run(value, run_opened_by) for value in values):
        return None
    return SERVER_RUN_FORM if run_opened_by == "server" else TOOL_RUN_FORM


def project_mapping_copies(car: CAR) -> frozenset[str]:
    """The paths of the copies of a project's scanner check mappings the record's stages applied."""
    return frozenset(
        used.copy_path
        for record in car.stages.values()
        if record.scanners is not None
        for used in record.scanners.scanner_check_mappings
        if used.file_path is not None
    )


def check_given_file_digest_form(car: CAR) -> None:
    """Raise ``ValueError`` unless every entry of ``car``'s evidence register names the file the pipeline gave in the
    form its keeping and its run give it: an entry kept as given, its own digest; the copy of a project's scanner check
    mapping, a plain digest; an entry kept redacted, keyed in a run the server opened and null in a run the tool
    opened."""
    copies = project_mapping_copies(car)
    redacted: list[str | None] = []
    for ref in car.evidence_refs:
        if ref.source is None:
            continue
        if ref.redaction_policy is not None:
            redacted.append(ref.source.digest)
        elif ref.path in copies:
            if ref.source.digest is None or ref.source.digest.startswith(KEYED_DIGEST_PREFIX):
                raise ValueError(PROJECT_MAPPING_COPY)
        elif ref.source.digest != ref.digest:
            raise ValueError(KEPT_AS_GIVEN)
    problem = form_problem(redacted, car.governance.run_opened_by)
    if problem is not None:
        raise ValueError(problem)
