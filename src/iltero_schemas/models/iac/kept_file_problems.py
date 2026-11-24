"""Every check a reader makes of a record, in one call.

A record's model checks its structure. What it claims beyond that, a reader works out again: the values it can
recompute from the record (``stages.integrity_problems``), the scanner verdicts from the files its stages kept
(``scanner_results.scanner_evidence_problems``), the project's exceptions
(``exception_evidence.local_exception_problems``), the failed results the exceptions the server served cover
(``exception_evidence.served_exception_problems``), the checks the plan stage postponed
(``postponed_checks.postponed_check_problems``), each evaluation input against the record's environment and change
(``kept_inputs.kept_input_problems``), in a run the tool opened each plan digest against the redacted plan the record
keeps (``plan_digests.kept_plan_digest_problems``), the resource identities document the post-verify stage kept
against the run and its drift check (``post_verify_identities.post_verify_identities_problems``), the evaluated side
of the re-plan check against the redacted plan the plan stage kept (``replan_recount.replan_recount_problems``), the
served bundle
each stage kept against the trust set, its signature, the stage and its events
(``kept_bundles.served_bundle_problems``), and each document a stage sends with its record against the record's
redaction policy (``redaction.iac.sent_documents.kept_document_redaction_problems``). ``kept_file_problems`` makes
them all, so no reader trusts a verdict the record states, such as one whose every failure is excepted, without working
it out again.
The reader supplies the function that verifies a signature; this package holds no cryptography.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from iltero_schemas.change_types.iac.change import IacChange
from iltero_schemas.models.common.kept_bundles import served_bundle_problems
from iltero_schemas.models.common.kept_inputs import kept_input_problems
from iltero_schemas.models.common.stages import integrity_problems
from iltero_schemas.models.iac.exception_evidence import local_exception_problems, served_exception_problems
from iltero_schemas.models.iac.plan_digests import kept_plan_digest_problems
from iltero_schemas.models.iac.post_verify_identities import post_verify_identities_problems
from iltero_schemas.models.iac.postponed_checks import postponed_check_problems
from iltero_schemas.models.iac.replan_recount import replan_recount_problems
from iltero_schemas.models.iac.scanner_results import scanner_evidence_problems
from iltero_schemas.redaction.iac.sent_documents import kept_document_redaction_problems

if TYPE_CHECKING:
    from collections.abc import Mapping

    from iltero_schemas.models.common.car import CAR
    from iltero_schemas.models.common.kept_bundles import SignatureCheck
    from iltero_schemas.models.iac.kept_files import KeptFiles
    from iltero_schemas.trust import SigningKey


def kept_file_problems(
    car: CAR, files: KeptFiles, keys: Mapping[str, SigningKey], verify: SignatureCheck
) -> list[tuple[str, str]]:
    """Every value of ``car`` that is not what a reader works out again from the record, the ``files`` its stages kept,
    the trust set ``keys`` its served bundles are read back under (``trust.SIGNING_KEYS`` for a real reader) and the
    reader's signature check ``verify``, as (where, what) pairs: empty exactly when every check a reader can make holds,
    so a reader trusts the record when it lists nothing. What only the server can check, such as whether a kept copy is
    what it served, stays unchecked.

    Call on a record whose structure holds (``check_structure``), read with or without ``SKIP_INTEGRITY_CHECKS``.
    """
    # Only a change made with an IaC tool names a plan digest or keeps resource identities.
    change = car.change if isinstance(car.change, IacChange) else None
    plan_digests = [] if change is None else kept_plan_digest_problems(car, change, files)
    identities = [] if change is None else post_verify_identities_problems(car, change, files)
    recount = [] if change is None else replan_recount_problems(car, change, files)
    return [
        *integrity_problems(car),
        *scanner_evidence_problems(car, files),
        *local_exception_problems(car, files),
        *served_exception_problems(car, files),
        *postponed_check_problems(car, files),
        *kept_input_problems(car, files.inputs),
        *plan_digests,
        *identities,
        *recount,
        *served_bundle_problems(car, files.served_bundles, keys, verify),
        *kept_document_redaction_problems(car, files),
    ]
