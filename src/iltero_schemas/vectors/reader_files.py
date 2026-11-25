"""The files a reader gives the checks of a record of the conformance vectors, from the files the record kept.

``reader_kept_files`` gives them for a record of ``vectors/records`` (or a package of one), and
``case_reader_kept_files`` for the record of a ``records_valid`` case: its evaluation inputs, the exceptions the
server served it, the plans it kept, its post-verify identities and its served bundles. A real reader reads the same
files from beside the record.
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Mapping
from pathlib import PurePosixPath
from typing import Any

from iltero_schemas.ast.document import load_document
from iltero_schemas.canonical.common.encoding import digest_of
from iltero_schemas.models.common.assertion import Stage
from iltero_schemas.models.common.car import CAR
from iltero_schemas.models.common.kept_files import KeptFiles
from iltero_schemas.models.iac.post_verify_identities import POST_VERIFY_IDENTITIES_REF_ID
from iltero_schemas.vectors.kept_files import kept_served_bundles


def _identities(record: CAR, by_path: Mapping[str, bytes]) -> dict[str, bytes]:
    """The resource identities document the record's post-verify stage kept, among the kept files ``by_path``, by the
    digest its register entry names; empty when the stage kept none."""
    return {
        ref.digest: by_path[ref.path]
        for ref in record.evidence_refs
        if ref.ref_id == POST_VERIFY_IDENTITIES_REF_ID and ref.path in by_path
    }


def _scanner_files(record: CAR, by_path: Mapping[str, bytes], kept: dict[str, bytes]) -> KeptFiles:
    """The scanner files a record's plan stage kept, among the kept files ``by_path``: its scanner check mapping copies
    and observations by path, its reports and plan by digest, its exceptions file's bytes, and the assertion documents
    it kept, and every plan it kept; only its kept plans and assertion documents when the stage read no scanner
    report or the record has no plan stage."""
    plan_stage = record.stages.get(Stage.PLAN)
    scanners = None if plan_stage is None else plan_stage.scanners
    # The assertion documents, and the policy entry of each rule written by hand in Rego.
    documents = [
        load_document(data.decode("utf-8")) if path.endswith(".yaml") else json.loads(data)
        for path, data in by_path.items()
        if PurePosixPath(path).parent.name == "assertions" and path.endswith((".yaml", ".policy.json"))
    ]
    if scanners is None:
        # A stage that read no scanner report keeps the plan only for the checks it postponed.
        plans = {
            ref.digest: json.loads(kept[ref.digest])
            for ref in record.evidence_refs
            if ref.collector.tool == "terraform_plan" and ref.digest in kept
        }
        return KeptFiles(
            scanner_check_mappings={},
            observations={},
            reports={},
            plans=plans,
            assertions={digest_of(document): document for document in documents},
            local_exceptions={},
            served_exceptions={},
            inputs={},
            identities={},
            served_bundles={},
        )
    observations = {report.observations: json.loads(by_path[report.observations]) for report in scanners.reports}
    used = scanners.local_exceptions
    return KeptFiles(
        scanner_check_mappings={
            mapping.copy_path: json.loads(by_path[mapping.copy_path]) for mapping in scanners.scanner_check_mappings
        },
        observations=observations,
        reports={report.report_digest: json.loads(kept[report.report_digest]) for report in scanners.reports},
        plans={
            **{
                ref.digest: json.loads(kept[ref.digest])
                for ref in record.evidence_refs
                if ref.collector.tool == "terraform_plan" and ref.digest in kept
            },
            **{str(o["kept_plan_digest"]): json.loads(kept[str(o["kept_plan_digest"])]) for o in observations.values()},
        },
        assertions={digest_of(document): document for document in documents},
        local_exceptions={} if used is None else {used.digest: kept[used.digest]},
        served_exceptions={},
        inputs={},
        identities={},
        served_bundles={},
    )


def _evaluation_inputs(record: CAR) -> set[str]:
    """The digests the record's evaluations name their inputs by, of the policy evaluator only."""
    return {
        event.provenance.input_digest
        for event in record.events
        if event.provenance.input_digest is not None and event.provenance.scanner_checks is None
    }


def _served(record: CAR) -> set[str]:
    return {stage.served_exceptions.digest for stage in record.stages.values() if stage.served_exceptions is not None}


def reader_kept_files(document: Mapping[str, Any], by_path: Mapping[str, bytes]) -> KeptFiles:
    """The files a reader gives the checks of the record ``document``, from the files it kept ``by_path``: whatever
    path its register names each by, as a packaged record names them too. A file the record cites but did not keep is
    not given, so the checks that read it report it missing."""
    record = CAR.model_validate(document)
    kept = {ref.digest: by_path[ref.path] for ref in record.evidence_refs if ref.path in by_path}
    return dataclasses.replace(
        _scanner_files(record, by_path, kept),
        served_exceptions={served: kept[served] for served in _served(record) if served in kept},
        # Only the inputs the record keeps: a hand-made record keeps none (``paths.HAND_MADE_RECORDS``).
        inputs={named: kept[named] for named in _evaluation_inputs(record) if named in kept},
        identities=_identities(record, by_path),
        served_bundles=kept_served_bundles(document, by_path),
    )


def case_reader_kept_files(document: Mapping[str, Any], by_path: Mapping[str, bytes]) -> KeptFiles:
    """The files a reader gives the checks of the record of a ``records_valid`` case, ``document``, from the files it
    kept ``by_path``: its inputs, the exceptions the server served it, the plans it kept, its post-verify identities
    and its served bundles."""
    record = CAR.model_validate(document)
    kept = {ref["digest"]: by_path[ref["path"]] for ref in document["evidence_refs"] if ref["path"] in by_path}
    return KeptFiles(
        scanner_check_mappings={},
        observations={},
        reports={},
        plans={
            ref.digest: json.loads(kept[ref.digest])
            for ref in record.evidence_refs
            if ref.collector.tool == "terraform_plan" and ref.digest in kept
        },
        assertions={},
        local_exceptions={},
        served_exceptions={served: kept[served] for served in _served(record) if served in kept},
        inputs={named: kept[named] for named in _evaluation_inputs(record) if named in kept},
        identities=_identities(record, by_path),
        served_bundles=kept_served_bundles(document, by_path),
    )
