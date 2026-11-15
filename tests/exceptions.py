"""A project's exceptions file, and the scanned record applying it to a result its scanned source suppressed."""

from __future__ import annotations

import copy
import json
from typing import Any

from iltero_schemas.canonical.encoding import digest
from tests.conftest import VECTORS
from tests.records import keep_events_files

GRANT: dict[str, Any] = {
    "id": "exc_0001",
    "status": "approved",
    "scope": {
        "assertion": {"id": "ILT.IAC.RESOURCE.AWS.RDS.NOT_PUBLIC"},
        "environment": "production",
        "resources": [{"scheme": "terraform_address", "scope": {"unit": "root"}, "value": "aws_db_instance.payments"}],
    },
    "valid_from": "2026-09-01T00:00:00Z",
    "expires_at": "2026-12-01T00:00:00Z",
    "approved_by": {"provider": "github", "id": "u_1"},
    "reason": "The database is reached through a private link added in the next change.",
}
FILE: dict[str, Any] = {
    "apiVersion": "iltero.com/v1",
    "kind": "LocalExceptions",
    "metadata": {"name": "payments-exceptions"},
    "spec": {"exceptions": [GRANT]},
}
# The file as the project wrote it, a comment and all.
FILE_BYTES = b"""# Exceptions the payments team approved.
apiVersion: iltero.com/v1
kind: LocalExceptions
metadata:
  name: payments-exceptions
spec:
  exceptions:
    - id: exc_0001
      status: approved
      scope:
        assertion:
          id: ILT.IAC.RESOURCE.AWS.RDS.NOT_PUBLIC
        environment: production
        resources:
          - scheme: terraform_address
            scope:
              unit: root
            value: aws_db_instance.payments
      valid_from: "2026-09-01T00:00:00Z"
      expires_at: "2026-12-01T00:00:00Z"
      approved_by:
        provider: github
        id: u_1
      reason: The database is reached through a private link added in the next change.
"""
FILE_DIGEST = digest(FILE_BYTES)
COPY_PATH = "units/root/plan/local-exceptions.yaml"
SCANNED: dict[str, Any] = json.loads(
    (VECTORS / "records" / "iac" / "local_run_scanned.json").read_text(encoding="utf-8")
)


def suppressed(record: dict[str, Any]) -> dict[str, Any]:
    """The scanned record's Trivy result about the database's public access, the one the exception covers."""
    return next(
        event
        for event in record["events"]
        if event["provenance"]["evaluator"]
        and event["provenance"]["evaluator"]["engine"] == "trivy"
        and event["assertion"]["id"] == GRANT["scope"]["assertion"]["id"]
    )


def applying_exceptions(named: bool = True) -> dict[str, Any]:
    """The scanned record whose plan stage applied the project's exceptions file, kept byte for byte, to its Trivy
    result about public access, made one the scanned source suppressed; that result names the exception when
    ``named``."""
    record = copy.deepcopy(SCANNED)
    record["stages"]["plan"]["scanners"]["local_exceptions"] = {
        "file_path": "exceptions.yaml",
        "digest": FILE_DIGEST,
        "copy_path": COPY_PATH,
    }
    template = next(ref for ref in record["evidence_refs"] if ref["source"] is not None)
    record["evidence_refs"].append(
        {
            **copy.deepcopy(template),
            "ref_id": "plan-local-exceptions",
            "media_type": "application/yaml",
            "digest": FILE_DIGEST,
            "size_bytes": len(FILE_BYTES),
            "path": COPY_PATH,
            "collector": {"tool": "local_exceptions", "version": "0.1.0"},
            "source": {"name": "exceptions.yaml", "digest": FILE_DIGEST},
            "canonicalization": None,
            "redaction_policy": None,
        }
    )
    event = suppressed(record)
    event["evaluation"].update(status="not_evaluated", status_reason="suppressed_in_source")
    if named:
        event["provenance"]["evaluator"]["local_exception"] = {"id": GRANT["id"], "file_digest": FILE_DIGEST}
    return keep_events_files(record)
