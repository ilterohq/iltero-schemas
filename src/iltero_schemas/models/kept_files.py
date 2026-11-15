"""The files a record's stages kept, as a reader gives them to the checks that read them."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class KeptFiles:
    """The files a stage kept that a reader checks scanner evaluations against, each as read from its JSON or YAML.

    ``binding_sets`` and ``observations`` are keyed by the path the stage names them at; ``reports`` and ``plans`` by
    the digest of the file as the stage kept it, redacted (``ScannerReport.report_digest``,
    ``ScannerObservations.plan_digest``), each an entry of the record's evidence register; ``assertions`` by the digest
    of the assertion's document (``AssertionRef.digest``); ``exceptions`` by the digest of the project's exceptions file
    a stage applied (``LocalExceptionsUsed.digest``), each the bytes of the stage's copy, unparsed, so the contract
    checks the digest and reads the file one way for every reader.
    """

    binding_sets: Mapping[str, object]
    observations: Mapping[str, object]
    reports: Mapping[str, object]
    plans: Mapping[str, object]
    assertions: Mapping[str, object]
    exceptions: Mapping[str, bytes]
