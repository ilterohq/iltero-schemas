"""The run statement vector cases, for ``sign_run_statement_vectors.py``: how each envelope is built from a record
vector's statement, and what reading it with its record gives."""

from __future__ import annotations

import base64
import copy
import json
from collections.abc import Mapping
from typing import Any

from run_statement_vector_builders import (
    DEPLOYED,
    HALF,
    IMAGE,
    OTHER_DIGEST,
    Edit,
    Signer,
    differs,
    final_is,
    no_record_accepted,
    packaged_case,
    payload_of,
    refused,
    sets,
)

from iltero_schemas.canonical import digest_of
from iltero_schemas.signing import P256_ORDER
from iltero_schemas.statement import der_signature
from iltero_schemas.vectors.vector_run_statements import (
    OPERATOR_RUN_STATEMENT_KEY_ID,
    OPERATOR_SERVER,
    RUN_STATEMENT_KEY_ID,
    case_record,
)

# A case: its name, the record it names (and the record's changes), the envelope (None for the statement of that
# record, signed as it is), the trust set, and what reading it gives.
Case = tuple[str, Mapping[str, Any], dict[str, Any] | None, str, dict[str, Any]]


def cases(signer: Signer, operator: Signer) -> dict[str, list[dict[str, Any]]]:
    """Every case, by its folder of cases, with what reading it gives; ``operator`` signs for the sample operator's
    server."""
    deployed = {"record": DEPLOYED}
    scanned = {"record": "iac/tracked_run_scanned_with_the_served_mapping.json"}
    image = {"record": IMAGE}
    payload = payload_of(deployed)
    statement = signer.envelope(payload)
    record_digest = digest_of(case_record(deployed).model_dump(mode="json", by_alias=True))
    pre_deploy = "/units/0/stages/1"
    image_build = case_record(image).model_dump(mode="json", by_alias=True)["change"]["build"]
    signature = signer.signature(payload)
    high = signature[:HALF] + (P256_ORDER - int.from_bytes(signature[HALF:], "big")).to_bytes(HALF, "big")
    high_s = {
        **statement,
        "signatures": [{"keyid": RUN_STATEMENT_KEY_ID, "sig": base64.b64encode(der_signature(high)).decode()}],
    }

    def signed(edit: Edit, base: Mapping[str, Any] = deployed, *, checked: bool = True) -> dict[str, Any]:
        return signer.envelope(payload_of(base, edit, checked=checked))

    def no_post_verify_expected(predicate: dict[str, Any], _subjects: list[dict[str, Any]]) -> None:
        predicate["settings"]["expected_stages"] = ["plan", "pre_deploy", "post_deploy"]

    def drop_plan(predicate: dict[str, Any], _subjects: list[dict[str, Any]]) -> None:
        predicate["units"][0]["stages"].pop(0)
        predicate["gaps"]["stages_never_accepted"].insert(0, {"unit": "root", "stage": "plan"})

    def unanswered_at(stage: str) -> Edit:
        result = {"unit": "root", "stage": stage, "assertion": "ILT.IAC.RESOURCE.AWS.RDS.NOT_PUBLIC"}
        return sets({"/gaps/unanswered_results": [result]})

    def refused_record(stage: str, digest: str = record_digest) -> dict[str, Any]:
        return {"unit": "root", "stage": stage, "digest": digest, "reason": "record_not_accepted"}

    def accepted_and_refused(predicate: dict[str, Any], subjects: list[dict[str, Any]]) -> None:
        predicate["gaps"]["refused_records"] = [refused_record("post_deploy")]

    def refused_as(predicate: dict[str, Any], subjects: list[dict[str, Any]]) -> None:
        no_record_accepted(predicate, subjects)
        predicate["gaps"]["refused_records"] = [refused_record("post_deploy")]

    def conflicting(predicate: dict[str, Any], subjects: list[dict[str, Any]]) -> None:
        final_is(OTHER_DIGEST)(predicate, subjects)
        predicate["units"][0]["stages"][-1]["conflicting_uploads"] = [record_digest]

    def subject_without_record(predicate: dict[str, Any], subjects: list[dict[str, Any]]) -> None:
        no_record_accepted(predicate, subjects)
        subjects.append({"name": "root", "digest": {"sha256": OTHER_DIGEST.removeprefix("sha256:")}})

    # The payload with a lone surrogate, which has no canonical form, written as a JSON escape in its citation.
    surrogate = payload.replace(b'"citation":"The', b'"citation":"\\ud800The', 1)

    invalid_iac: list[Case] = [
        (
            "statement_signed_with_a_key_of_another_purpose",
            deployed,
            signer.envelope(payload, key_id="dev-scanner-check-mapping-vectors"),
            "development",
            refused("key_of_another_purpose"),
        ),
        ("statement_signed_with_a_revoked_key", deployed, statement, "development_key_revoked", refused("key_revoked")),
        (
            "statement_signed_with_a_key_not_trusted",
            deployed,
            signer.envelope(payload, key_id="dev-key-not-listed"),
            "development",
            refused("key_not_trusted"),
        ),
        (
            "statement_signed_for_another_server",
            deployed,
            signed(sets({"/run/server": "iltero.operator.example"})),
            "development",
            refused("key_of_another_server"),
        ),
        (
            "statement_of_a_run_that_ended_after_its_key_was_retired",
            deployed,
            signed(sets({"/run/ended_at": "2026-11-27T00:00:00.000Z"})),
            "development_key_retired",
            refused("key_not_valid_at_the_run_end"),
        ),
        (
            "statement_whose_signature_was_made_with_another_key",
            deployed,
            Signer().envelope(payload),
            "development",
            refused("signature_invalid"),
        ),
        (
            "statement_whose_signature_is_in_its_high_s_form",
            deployed,
            high_s,
            "development",
            refused("signature_invalid"),
        ),
        (
            "statement_with_two_signatures",
            deployed,
            {**statement, "signatures": statement["signatures"] * 2},
            "development",
            refused("not_exactly_one_signature"),
        ),
        (
            "statement_with_no_signature",
            deployed,
            {**statement, "signatures": []},
            "development",
            refused("not_exactly_one_signature"),
        ),
        (
            "statement_of_another_payload_type",
            deployed,
            {**statement, "payloadType": "application/json"},
            "development",
            refused("another_payload_type"),
        ),
        (
            "statement_whose_payload_is_not_canonical",
            deployed,
            signer.envelope(json.dumps(json.loads(payload), indent=2).encode("utf-8")),
            "development",
            refused("payload_not_canonical"),
        ),
        (
            "statement_whose_payload_holds_a_lone_surrogate",
            deployed,
            signer.envelope(surrogate),
            "development",
            refused(
                "payload_not_a_run_statement",
                "Input should be a valid string, unable to parse raw data as a unicode string",
            ),
        ),
        (
            "statement_listing_a_refused_record_as_a_subject",
            deployed,
            signed(accepted_and_refused, checked=False),
            "development",
            refused(
                "payload_not_a_run_statement",
                "an upload the server refused is never a record it accepted or one that conflicted",
            ),
        ),
        (
            "statement_missing_a_stage_never_accepted",
            deployed,
            signed(sets({"/gaps/stages_never_accepted": []}), checked=False),
            "development",
            refused(
                "payload_not_a_run_statement",
                "stages_never_accepted names exactly the expected stages of each unit that accepted no record",
            ),
        ),
        (
            "statement_with_a_gap_of_a_stage_it_does_not_expect",
            deployed,
            signed(no_post_verify_expected, checked=False),
            "development",
            refused(
                "payload_not_a_run_statement",
                "a run statement's gaps name units of the run and stages it expects only",
            ),
        ),
        (
            "statement_with_an_unanswered_result_of_a_stage_never_accepted",
            deployed,
            signed(unanswered_at("post_verify"), checked=False),
            "development",
            refused(
                "payload_not_a_run_statement",
                "unanswered_results names results of stages that accepted a record only",
            ),
        ),
        (
            "statement_whose_subject_is_not_the_final_record",
            deployed,
            signed(sets({"/subject/0/digest/sha256": OTHER_DIGEST.removeprefix("sha256:")}), checked=False),
            "development",
            refused(
                "payload_not_a_run_statement",
                "a run statement's subjects are the record that counts at each unit's latest stage that accepted one, "
                "and no other",
            ),
        ),
        (
            "statement_with_a_subject_for_a_unit_that_accepted_no_record",
            deployed,
            signed(subject_without_record, checked=False),
            "development",
            refused(
                "payload_not_a_run_statement",
                "a run statement's subjects are the record that counts at each unit's latest stage that accepted one, "
                "and no other",
            ),
        ),
        (
            "statement_with_gaps_out_of_order",
            deployed,
            signed(
                sets(
                    {
                        "/gaps/refused_uploads": [
                            refused_record("post_deploy", OTHER_DIGEST),
                            refused_record("plan", OTHER_DIGEST),
                        ]
                    }
                ),
                checked=False,
            ),
            "development",
            refused(
                "payload_not_a_run_statement",
                "refused_uploads names each entry once, sorted by unit, then stage in the order of the lifecycle, then "
                "assertion id or digest",
            ),
        ),
        (
            "statement_with_a_refused_upload_naming_no_stage",
            deployed,
            signed(
                sets({"/gaps/refused_uploads": [{"unit": "root", "digest": OTHER_DIGEST, "reason": "too_large"}]}),
                checked=False,
            ),
            "development",
            refused(
                "payload_not_a_run_statement",
                "Field required",
            ),
        ),
        (
            "statement_not_listing_the_record",
            deployed,
            signed(final_is(OTHER_DIGEST)),
            "development",
            differs("record_not_listed", listed_as="not_listed"),
        ),
        (
            "statement_listing_the_record_as_refused",
            deployed,
            signed(refused_as),
            "development",
            differs("record_refused_by_the_server", listed_as="refused"),
        ),
        (
            "statement_listing_the_record_as_a_conflicting_upload",
            deployed,
            signed(conflicting),
            "development",
            differs("record_is_a_conflicting_upload", listed_as="conflicting_upload"),
        ),
        (
            "statement_of_another_run",
            deployed,
            signed(sets({"/run/id": "1c0a4d63-7d2e-4e5f-8a1b-3b8e6c2d9f54"})),
            "development",
            differs("another_run", listed_as="not_listed"),
        ),
        (
            "statement_of_another_unit",
            deployed,
            signed(
                sets(
                    {
                        "/run/units": ["network"],
                        "/units/0/unit": "network",
                        "/subject/0/name": "network",
                        "/gaps/stages_never_accepted/0/unit": "network",
                    }
                )
            ),
            "development",
            differs("another_unit", "record_not_listed", listed_as="not_listed"),
        ),
        (
            "statement_of_another_activity",
            deployed,
            signed(sets({"/run/activity": "image_deploy", "/units/0/accepted_build": image_build})),
            "development",
            differs("another_activity"),
        ),
        (
            "statement_of_another_environment",
            deployed,
            signed(sets({"/run/environment": "staging"})),
            "development",
            differs("another_environment"),
        ),
        (
            "statement_whose_apply_job_facts_digest_differs",
            deployed,
            signed(sets({f"{pre_deploy}/served_parts/apply_job_facts": OTHER_DIGEST})),
            "development",
            differs("served_part_differs"),
        ),
        (
            "statement_whose_approvals_digest_differs",
            deployed,
            signed(sets({f"{pre_deploy}/served_parts/approvals": OTHER_DIGEST})),
            "development",
            differs("served_part_differs"),
        ),
        (
            "statement_whose_commit_review_digest_differs",
            deployed,
            signed(sets({f"{pre_deploy}/served_parts/commit_review": OTHER_DIGEST})),
            "development",
            differs("served_part_differs"),
        ),
        (
            "statement_whose_served_exceptions_digest_differs",
            deployed,
            signed(sets({"/units/0/stages/0/served_parts/served_exceptions": OTHER_DIGEST})),
            "development",
            differs("served_part_differs"),
        ),
        (
            "statement_signing_no_approvals_the_record_keeps",
            deployed,
            signed(sets({f"{pre_deploy}/served_parts/approvals": None})),
            "development",
            differs("served_part_differs"),
        ),
        (
            "statement_signed_by_another_server_over_a_record_whose_bundle_is_the_development_servers",
            deployed,
            operator.envelope(
                payload_of(deployed, sets({"/run/server": OPERATOR_SERVER})), key_id=OPERATOR_RUN_STATEMENT_KEY_ID
            ),
            "development",
            differs("bundle_of_another_server", "bundle_of_another_server", "bundle_of_another_server"),
        ),
        (
            "statement_whose_ci_job_names_another_commit",
            deployed,
            signed(sets({f"{pre_deploy}/ci_job/commit": "a1b2c3d000000000000000000000000000000000"})),
            "development",
            differs("ci_job_differs"),
        ),
        (
            "statement_whose_ci_job_ran_in_another_repository",
            {**deployed, "record_set": {"/subject/source/repository": {"name": "example/another"}}},
            None,
            "development",
            differs("ci_job_differs", "ci_job_differs", "ci_job_differs"),
        ),
        (
            "statement_with_other_required_assertions",
            deployed,
            signed(sets({"/settings/required_assertion_digests/plan": OTHER_DIGEST})),
            "development",
            differs("required_assertions_differ"),
        ),
        (
            "statement_with_other_expected_stages",
            deployed,
            signed(
                sets(
                    {
                        "/settings/expected_stages": ["plan", "pre_deploy", "post_deploy"],
                        "/gaps/stages_never_accepted": [],
                    }
                )
            ),
            "development",
            differs("expected_stages_differ"),
        ),
        ("statement_listing_no_plan_stage", deployed, signed(drop_plan), "development", differs("stage_not_listed")),
        (
            "statement_whose_facts_were_issued_at_another_time",
            deployed,
            signed(sets({"/units/0/stages/0/facts/issued_at": "2026-09-16T18:29:00Z"})),
            "development",
            differs("reference_time_differs"),
        ),
        (
            "statement_naming_another_bundle",
            deployed,
            signed(sets({"/settings/bundle_content_digest": OTHER_DIGEST})),
            "development",
            differs("bundle_differs", "bundle_differs", "bundle_differs"),
        ),
        (
            "statement_naming_another_enforcement_mode",
            deployed,
            signed(sets({"/settings/enforcement_mode": "advisory"})),
            "development",
            differs("enforcement_mode_differs", "enforcement_mode_differs"),
        ),
        (
            "statement_naming_another_scanner_check_mapping",
            scanned,
            signed(sets({"/settings/scanner_check_mapping_descriptor_digest": OTHER_DIGEST}), scanned),
            "development",
            differs("scanner_check_mapping_differs"),
        ),
        (
            "statement_for_a_record_of_a_run_the_tool_opened",
            {"record": "iac/local_run.json"},
            None,
            "development",
            differs("run_not_opened_by_the_server"),
        ),
    ]
    invalid_image: list[Case] = [
        (
            "statement_naming_another_build",
            image,
            signed(sets({"/units/0/accepted_build/record_digest": OTHER_DIGEST}), image),
            "development",
            differs("another_build"),
        ),
        (
            "statement_of_another_environment",
            image,
            signed(sets({"/run/environment": "staging"}), image),
            "development",
            differs("another_environment"),
        ),
    ]
    earlier = [{"digest": record_digest, "counts": False}]
    without_facts = {"record": "iac/tracked_run_deployed_without_server_facts.json"}
    post_verify = {"record": "iac/tracked_run_post_verify.json"}

    def abandoned_with_an_unanswered_result(predicate: dict[str, Any], subjects: list[dict[str, Any]]) -> None:
        unanswered_at("post_deploy")(predicate, subjects)
        predicate["run"].update(ending="abandoned", ending_reason="no_upload_before_the_idle_limit")

    def later_stage_holds_another_record(predicate: dict[str, Any], subjects: list[dict[str, Any]]) -> None:
        """A later record counts at the post-verify stage, the record's run expects, and is the unit's subject; the
        run leaves nothing unanswered."""
        later = copy.deepcopy(predicate["units"][0]["stages"][-1])
        later.update(stage="post_verify", accepted_records=[{"digest": OTHER_DIGEST, "counts": True}])
        later["served_parts"] = {part: None for part in later["served_parts"]}
        predicate["units"][0]["stages"].append(later)
        predicate["gaps"]["stages_never_accepted"] = []
        predicate["run"].update(ending="closed", ending_reason="closed_by_the_pipeline")
        subjects[0]["digest"]["sha256"] = OTHER_DIGEST.removeprefix("sha256:")

    valid_iac: list[Case] = [
        ("statement_signed_with_a_retired_key", deployed, statement, "development_key_retired", differs()),
        (
            "statement_listing_the_record_as_an_earlier_accepted_copy",
            deployed,
            signed(final_is(OTHER_DIGEST, also=earlier)),
            "development",
            differs(listed_as="earlier_copy", replaced_by=OTHER_DIGEST, notes=("record_not_the_one_that_counts",)),
        ),
        (
            "statement_signing_parts_the_record_keeps_no_copy_of",
            without_facts,
            signed(sets({f"{pre_deploy}/served_parts/approvals": OTHER_DIGEST}), without_facts),
            "development",
            differs(not_compared=(("pre_deploy", "approvals"),)),
        ),
        (
            "statement_of_a_closed_run_naming_a_result_no_accepted_record_answered",
            post_verify,
            signed(unanswered_at("post_deploy"), post_verify),
            "development",
            differs(),
        ),
        (
            "statement_of_an_abandoned_run_naming_a_result_no_accepted_record_answered",
            post_verify,
            signed(abandoned_with_an_unanswered_result, post_verify),
            "development",
            differs(),
        ),
        (
            "statement_of_a_run_whose_later_stage_a_later_record_holds",
            deployed,
            signed(later_stage_holds_another_record),
            "development",
            differs(listed_as="counting_record", replaced_by=OTHER_DIGEST),
        ),
        (
            "statement_of_a_closed_run_naming_an_expected_stage_never_accepted",
            deployed,
            signed(sets({"/run/ending": "closed", "/run/ending_reason": "closed_by_the_pipeline"})),
            "development",
            differs(),
        ),
    ]
    valid_image: list[Case] = [
        (
            "statement_signed_with_a_retired_key",
            image,
            signer.envelope(payload_of(image)),
            "development_key_retired",
            differs(),
        ),
    ]

    def written(listed: list[Case]) -> list[dict[str, Any]]:
        return [
            {
                "name": name,
                **base,
                "envelope": built or signer.envelope(payload_of(base)),
                "trust_set": trust,
                **expected,
            }
            for name, base, built, trust, expected in listed
        ]

    packaged = {"name": "packaged_record_against_its_statement", **packaged_case(signer), **differs()}
    return {
        "run_statements_invalid/iac": written(invalid_iac),
        "run_statements_invalid/image": written(invalid_image),
        "run_statements_valid/iac": [*written(valid_iac), packaged],
        "run_statements_valid/image": written(valid_image),
    }
