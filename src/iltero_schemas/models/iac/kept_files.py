"""The files a record's stages kept, as a reader gives them to the checks that read them, and the limits of those a
stage that reads scanner reports sends with its record."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from iltero_schemas.change_types.common.activity import DocumentName
from iltero_schemas.models.common.sent_documents import SentDocumentLimits


@dataclass(frozen=True)
class KeptFiles:
    """The files a stage kept that a reader checks scanner evaluations against, each as read from its JSON or YAML.

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


# The limits of each document a stage that reads scanner reports sends with its record, by its name
# (``Activity.named_documents``). A whole plan of a change of about a thousand resources, at about 5 KiB and 20 bytes a
# value per resource, fits the plan's limits; a larger change's plan is over them. A scanner's report and its
# observations, at about 24 bytes a value, fill 2 MiB at about 90,000 values. Each value limit leaves room above that
# and bounds the memory a hostile file of that size can take.
SENT_DOCUMENT_LIMITS: Mapping[DocumentName, SentDocumentLimits] = MappingProxyType(
    {
        "redacted_plan": SentDocumentLimits(max_bytes=6 * 1024 * 1024, max_values=400_000),
        "scanner_report": SentDocumentLimits(max_bytes=2 * 1024 * 1024, max_values=120_000),
        "scanner_observations": SentDocumentLimits(max_bytes=2 * 1024 * 1024, max_values=120_000),
    }
)
# The bytes of all the documents one stage sends with its record together; the record itself keeps its own limit.
MAX_STAGE_SENT_DOCUMENT_BYTES = 12 * 1024 * 1024
