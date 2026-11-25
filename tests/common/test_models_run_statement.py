"""The run statement is read strictly, and each rule of its shape refuses a statement that breaks it."""

from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.common.run_statement import RunStatement
from tests.statements import DEPLOYED, IMAGE_DEPLOY, statement_document, statement_parts

Edit = Callable[[list[dict[str, Any]], dict[str, Any]], None]
OTHER = "sha256:" + "0" * 63 + "1"


def _read(edit: Edit, name: str = DEPLOYED) -> RunStatement:
    subjects, predicate = statement_parts(name)
    subjects, predicate = copy.deepcopy(subjects), copy.deepcopy(predicate)
    edit(subjects, predicate)
    return RunStatement.model_validate(statement_document(subjects, predicate))


def _refused(edit: Edit, message: str, name: str = DEPLOYED) -> None:
    with pytest.raises(ValidationError, match=message):
        _read(edit, name)


def test_the_statement_of_a_record_vector_is_read() -> None:
    statement = _read(lambda _s, _p: None)
    assert statement.type == "https://in-toto.io/Statement/v1"
    assert statement.predicate_type == "https://iltero.com/statements/run-close/v1"


def test_a_statement_of_another_type_or_predicate_type_is_refused() -> None:
    subjects, predicate = statement_parts()
    for field, value in (("_type", "https://in-toto.io/Statement/v0.1"), ("predicateType", "https://example.com/x")):
        with pytest.raises(ValidationError):
            RunStatement.model_validate({**statement_document(subjects, predicate), field: value})


def test_a_statement_with_a_field_it_does_not_define_is_refused() -> None:
    _refused(lambda _s, p: p["run"].update(row_id="17"), "Extra inputs are not permitted")


def test_a_statement_missing_a_field_is_refused() -> None:
    _refused(lambda _s, p: p["retention"].pop("citation"), "Field required")


def test_a_settings_digest_that_is_not_the_settings_digest_is_refused() -> None:
    subjects, predicate = statement_parts()
    document = statement_document(subjects, predicate)
    document["predicate"]["settings_digest"] = "sha256:" + "0" * 64
    with pytest.raises(ValidationError, match="settings_digest is the digest of the run's settings"):
        RunStatement.model_validate(document)


@pytest.mark.parametrize("refused_list", ["refused_records", "refused_uploads"])
def test_an_upload_the_server_refused_is_never_a_record_it_accepted_or_one_that_conflicted(refused_list: str) -> None:
    def refuse(digest_of_stage: Callable[[dict[str, Any]], str]) -> Edit:
        def edit(_subjects: list[dict[str, Any]], predicate: dict[str, Any]) -> None:
            digest = digest_of_stage(predicate["units"][0]["stages"][0])
            refused = {"unit": "root", "stage": "plan", "digest": digest, "reason": "record_not_accepted"}
            predicate["gaps"][refused_list] = [refused]

        return edit

    def conflicting(stage: dict[str, Any]) -> str:
        stage["conflicting_uploads"] = [OTHER]
        return OTHER

    rule = "an upload the server refused is never a record it accepted or one that conflicted"
    _refused(refuse(lambda stage: stage["accepted_records"][0]["digest"]), rule)
    _refused(refuse(conflicting), rule)


def test_the_subjects_are_each_units_final_record_and_no_other() -> None:
    final = "the record that counts at each unit's latest stage that accepted one"
    _refused(lambda s, _p: s[0].update(name="network"), final)
    _refused(lambda s, _p: s[0]["digest"].update(sha256=OTHER.removeprefix("sha256:")), final)
    _refused(lambda s, _p: s.clear(), final)
    _refused(lambda s, _p: s.append(copy.deepcopy(s[0])), "names each subject once, sorted by unit")


def test_a_unit_that_accepted_no_record_has_no_subject() -> None:
    def nothing_accepted(subjects: list[dict[str, Any]], predicate: dict[str, Any]) -> None:
        for stage in predicate["units"][0]["stages"]:
            stage["accepted_records"] = []
        expected = predicate["settings"]["expected_stages"]
        predicate["gaps"]["stages_never_accepted"] = [{"unit": "root", "stage": stage} for stage in expected]

    def nothing_accepted_and_no_subject(subjects: list[dict[str, Any]], predicate: dict[str, Any]) -> None:
        nothing_accepted(subjects, predicate)
        subjects.clear()

    _refused(nothing_accepted, "and no other")
    _read(nothing_accepted_and_no_subject)


def test_a_run_names_the_server_that_opened_it_by_a_host_name() -> None:
    _refused(lambda _s, p: p["run"].update(server="Not A Host"), "String should match pattern")
    _refused(lambda _s, p: p["run"].pop("server"), "Field required")


def test_stages_never_accepted_are_exactly_each_units_expected_stages_that_accepted_no_record() -> None:
    rule = "stages_never_accepted names exactly the expected stages"
    _refused(lambda _s, p: p["gaps"].update(stages_never_accepted=[]), rule)

    def none_accepted_at_plan(_subjects: list[dict[str, Any]], predicate: dict[str, Any]) -> None:
        predicate["units"][0]["stages"][0]["accepted_records"] = []

    _refused(none_accepted_at_plan, rule)


def test_every_gap_and_unit_stage_is_an_expected_stage() -> None:
    def fewer(_subjects: list[dict[str, Any]], predicate: dict[str, Any]) -> None:
        predicate["settings"]["expected_stages"] = ["plan", "pre_deploy", "post_deploy"]

    _refused(fewer, "gaps name units of the run and stages it expects only")

    def unexpected_stage(_subjects: list[dict[str, Any]], predicate: dict[str, Any]) -> None:
        predicate["settings"]["expected_stages"] = ["plan", "pre_deploy", "post_verify"]
        predicate["settings"]["required_assertion_digests"].pop("post_deploy")

    _refused(unexpected_stage, "a unit's stages are stages the run expects")


def test_unanswered_results_are_of_stages_that_accepted_a_record_only() -> None:
    def unanswered(stage: str) -> Edit:
        result = {"unit": "root", "stage": stage, "assertion": "ILT.IAC.RESOURCE.AWS.RDS.NOT_PUBLIC"}
        return lambda _s, p: p["gaps"].update(unanswered_results=[result])

    _refused(unanswered("post_verify"), "unanswered_results names results of stages that accepted a record only")
    _read(unanswered("plan"))


@pytest.mark.parametrize("field", ["unanswered_results", "stages_never_accepted", "refused_records", "refused_uploads"])
def test_each_gap_list_names_each_entry_once_sorted_by_unit_stage_and_assertion_or_digest(field: str) -> None:
    gaps = {
        "unanswered_results": [{"unit": "root", "stage": "pre_deploy", "assertion": "ILT.IAC.X.Y"}],
        "stages_never_accepted": [{"unit": "root", "stage": "post_verify"}],
        "refused_records": [{"unit": "root", "stage": "pre_deploy", "digest": OTHER, "reason": "record_not_accepted"}],
        "refused_uploads": [{"unit": "root", "stage": "pre_deploy", "digest": OTHER, "reason": "too_large"}],
    }
    entry = gaps[field][0]
    earlier = {**entry, "stage": "plan"}
    _read(lambda _s, p: p["gaps"].update({field: [earlier, entry]}) if field != "stages_never_accepted" else None)
    _refused(lambda _s, p: p["gaps"].update({field: [entry, earlier]}), f"{field} names each entry once, sorted")
    _refused(lambda _s, p: p["gaps"].update({field: [entry, entry]}), f"{field} names each entry once, sorted")


def test_a_refused_upload_names_the_unit_and_stage_whose_token_it_came_with() -> None:
    refused = {"digest": OTHER, "reason": "too_large"}
    _refused(lambda _s, p: p["gaps"].update(refused_uploads=[refused]), "Field required")


def test_a_stage_names_its_conflicting_uploads_sorted_each_once() -> None:
    rule = "conflicting uploads sorted, each once"
    later = "sha256:" + "f" * 64
    _read(lambda _s, p: p["units"][0]["stages"][0].update(conflicting_uploads=[OTHER, later]))
    _refused(lambda _s, p: p["units"][0]["stages"][0].update(conflicting_uploads=[later, OTHER]), rule)
    _refused(lambda _s, p: p["units"][0]["stages"][0].update(conflicting_uploads=[OTHER, OTHER]), rule)


def test_a_run_names_its_units_sorted_each_once() -> None:
    _refused(lambda _s, p: p["run"].update(units=["root", "root"]), "units sorted, each once")


def test_a_run_ends_no_earlier_than_it_opened() -> None:
    _refused(lambda _s, p: p["run"].update(opened_at="2027-01-01T00:00:00Z"), "ends no earlier than it opened")


def test_the_predicate_names_every_unit_of_the_run_in_order() -> None:
    _refused(lambda _s, p: p["units"][0].update(unit="network"), "names every unit of the run once")


def test_a_unit_names_its_build_exactly_when_the_run_is_an_image_deploy() -> None:
    build = statement_parts(IMAGE_DEPLOY)[1]["units"][0]["accepted_build"]
    _refused(lambda _s, p: p["units"][0].update(accepted_build=build), "names the build it deployed exactly when")
    _refused(lambda _s, p: p["units"][0].update(accepted_build=None), "exactly when", IMAGE_DEPLOY)


def test_a_run_names_an_environment_exactly_when_it_is_not_an_image_build() -> None:
    _refused(lambda _s, p: p["run"].update(environment=None), "names an environment exactly when")


def test_the_gaps_name_units_of_the_run_only() -> None:
    _refused(lambda _s, p: p["gaps"]["stages_never_accepted"][0].update(unit="network"), "gaps name units of the run")


def test_settings_name_expected_stages_once_in_lifecycle_order() -> None:
    _refused(
        lambda _s, p: p["settings"].update(expected_stages=["pre_deploy", "plan", "post_deploy", "post_verify"]),
        "each expected stage once, in the order of the lifecycle",
    )


def test_settings_name_the_required_assertions_of_expected_stages_only() -> None:
    def unexpected(_s: list[dict[str, Any]], predicate: dict[str, Any]) -> None:
        predicate["settings"]["expected_stages"] = ["plan", "pre_deploy", "post_deploy"]
        predicate["settings"]["required_assertion_digests"]["post_verify"] = "sha256:" + "1" * 64

    _refused(unexpected, "required assertions of expected stages only")


def test_settings_name_each_excluded_assertion_once_sorted() -> None:
    excluded = {"id": "ILT.IAC.RESOURCE.AWS.RDS.NOT_PUBLIC", "reason": "not_in_scope", "ends_at": None}
    _refused(
        lambda _s, p: p["settings"].update(excluded_assertions=[excluded, excluded]), "each excluded assertion once"
    )


def test_a_unit_names_its_stages_once_in_lifecycle_order() -> None:
    _refused(lambda _s, p: p["units"][0]["stages"].reverse(), "each of its stages once, in the order of the lifecycle")


def test_of_the_records_a_stage_accepted_exactly_one_counts() -> None:
    def two_count(_s: list[dict[str, Any]], predicate: dict[str, Any]) -> None:
        predicate["units"][0]["stages"][0]["accepted_records"].append({"digest": "sha256:" + "1" * 64, "counts": True})

    _refused(two_count, "exactly one counts")


def test_a_stage_names_each_accepted_record_once() -> None:
    def twice(_s: list[dict[str, Any]], predicate: dict[str, Any]) -> None:
        accepted = predicate["units"][0]["stages"][0]["accepted_records"]
        accepted.append({**accepted[0], "counts": False})

    _refused(twice, "each accepted record once")


def test_a_stage_names_no_accepted_record_among_its_conflicting_uploads() -> None:
    def conflicting(_s: list[dict[str, Any]], predicate: dict[str, Any]) -> None:
        stage = predicate["units"][0]["stages"][0]
        stage["conflicting_uploads"] = [stage["accepted_records"][0]["digest"]]

    _refused(conflicting, "none it accepted")


def test_a_reason_code_is_a_short_lower_case_token() -> None:
    _refused(lambda _s, p: p["run"].update(ending_reason="Closed by the pipeline"), "String should match pattern")


def test_a_subject_digest_is_lowercase_sha256_hex() -> None:
    _refused(lambda s, _p: s[0]["digest"].update(sha256="A" * 64), "String should match pattern")
    _refused(lambda s, _p: s[0]["digest"].update(sha512="a" * 128), "Extra inputs are not permitted")


def test_a_ci_job_whose_identity_names_no_job_is_read_with_no_job_id() -> None:
    def no_job(_s: list[dict[str, Any]], p: dict[str, Any]) -> None:
        for unit in p["units"]:
            for stage in unit["stages"]:
                stage["ci_job"]["ci_job_id"] = None

    statement = _read(no_job)
    assert all(stage.ci_job.ci_job_id is None for unit in statement.predicate.units for stage in unit.stages)


def test_a_ci_job_with_an_empty_job_id_is_refused() -> None:
    def empty_job(_s: list[dict[str, Any]], p: dict[str, Any]) -> None:
        p["units"][0]["stages"][0]["ci_job"]["ci_job_id"] = ""

    with pytest.raises(ValidationError):
        _read(empty_job)
