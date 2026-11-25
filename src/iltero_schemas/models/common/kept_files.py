"""The files a record's stages kept, as a reader gives them to the checks that read them."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class KeptFiles:
    """The files a record's stages kept that a reader checks the record against, each as read from its JSON or YAML.

    ``scanner_check_mappings`` and ``observations`` are keyed by the path the stage names them at; ``reports`` and
    ``plans`` by the digest of the file as the stage kept it, redacted (``ScannerReport.report_digest``,
    ``ScannerObservations.kept_plan_digest``), each an entry of the record's evidence register; ``assertions`` by the
    digest of the assertion's document (``AssertionRef.digest``), or for a rule written by hand in Rego, of its policy
    entry; ``local_exceptions`` by the digest of the project's exceptions file a stage applied
    (``LocalExceptionsUsed.digest``), ``served_exceptions`` by the digest of the exceptions the server served a stage
    (``ServedExceptionsUsed.digest``), ``inputs`` by the digest each evaluation names its evaluation input by
    (``Provenance.input_digest``), ``identities`` by the digest of the resource identities document the post-verify
    stage kept (``models.iac.post_verify_identities``), and ``served_bundles`` by the digest of the tarball of each
    served bundle a stage kept (``models.common.kept_bundles``), each the bytes of the stage's copy, unparsed, so the
    contract checks the digest and reads the file one way for every reader.
    """

    scanner_check_mappings: Mapping[str, object]
    observations: Mapping[str, object]
    reports: Mapping[str, object]
    plans: Mapping[str, object]
    assertions: Mapping[str, object]
    local_exceptions: Mapping[str, bytes]
    served_exceptions: Mapping[str, bytes]
    inputs: Mapping[str, bytes]
    identities: Mapping[str, bytes]
    served_bundles: Mapping[str, bytes]
