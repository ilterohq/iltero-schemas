"""A display words file has exactly one entry for each code the contract defines, with none extra, and names its reason
groups rightly; each set is taken from the contract's own constants."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

import pytest

from iltero_schemas.display import DISPLAY_WORDS
from iltero_schemas.display.complete import named, near_miss_reasons, reported_results
from iltero_schemas.models.common.coverage import VERDICT_RANKING
from iltero_schemas.models.common.event import STATUS_REASONS
from iltero_schemas.models.common.report_trust import TRUST_LEVEL_RESULTS
from iltero_schemas.models.common.verification import COULD_NOT_DECIDE, INTEGRITY_FAILED, PROPERTY_RESULTS, Properties
from tests.common.test_display_model import read_words, words_document

Change = Callable[[dict[str, Any]], None]
NOT_COMPLETE = "the display words file is not complete: "


def _refused(change: Change, message: str) -> None:
    document = words_document()
    change(document)
    with pytest.raises(ValueError, match=f"^{re.escape(NOT_COMPLETE + message)}$"):
        read_words(document)


# One entry removed from each section, and the problem the reader names.
MISSING: list[tuple[str, Change, str]] = [
    ("result_status", lambda d: d["result_statuses"].pop("error"), "result_statuses has no entry for error"),
    (
        "status_reason",
        lambda d: d["status_reasons"]["unknown"].pop("redacted"),
        "status_reasons.unknown has no entry for redacted",
    ),
    ("verdict", lambda d: d["verdicts"].pop("undecided"), "verdicts has no entry for undecided"),
    (
        "verdict_reason",
        lambda d: d["verdicts"]["incomplete"]["reasons"].pop("evaluator_failed"),
        "verdicts.incomplete.reasons has no entry for evaluator_failed",
    ),
    (
        "near_miss",
        lambda d: d["notes"]["no_exception_in_force"].pop("expired"),
        "notes.no_exception_in_force has no entry for expired",
    ),
    (
        "trust_level",
        lambda d: d["trust_levels"].pop("policy_enforced"),
        "trust_levels has no entry for policy_enforced",
    ),
    (
        "trust_level_reason",
        lambda d: d["trust_levels"]["self_attested"]["reasons"].pop("integrity_failed"),
        "trust_levels.self_attested.reasons has no entry for integrity_failed",
    ),
    ("signer", lambda d: d["signed_by"].pop("operator"), "signed_by has no entry for operator"),
    (
        "verification_state",
        lambda d: d["verification_states"].pop("claimed_by_record"),
        "verification_states has no entry for claimed_by_record",
    ),
    (
        "verification_property",
        lambda d: d["verification_properties"].pop("plan_age"),
        "verification_properties has no entry for plan_age",
    ),
    (
        "verification_result",
        lambda d: d["verification_properties"]["integrity"]["results"].pop(0),
        "verification_properties.integrity has no entry for state verified with reason run_statement",
    ),
    ("process_outcome", lambda d: d["process_outcomes"].pop("stopped"), "process_outcomes has no entry for stopped"),
]


@pytest.mark.parametrize(("change", "message"), [(c, m) for _, c, m in MISSING], ids=[n for n, _, _ in MISSING])
def test_a_words_file_missing_an_entry_is_refused(change: Change, message: str) -> None:
    _refused(change, message)


SENTENCE = {"text": "Something.", "placeholders": []}
WORD = {"word": "Stray", "plain": "[-] Stray", "tone": "neutral", "icon": "dash", "sentence": SENTENCE}
# One entry added to each keyed section, and the problem the reader names.
EXTRA: list[tuple[str, Change, str]] = [
    ("result_status", lambda d: d["result_statuses"].update(stray=WORD), "result_statuses has an entry for stray"),
    (
        "status_reason",
        lambda d: d["status_reasons"]["pass"].update(stray={"group": None, "sentence": SENTENCE}),
        "status_reasons.pass has an entry for stray",
    ),
    (
        "verdict",
        lambda d: d["verdicts"].update(stopped={**WORD, "reasons": {}}),
        "verdicts has an entry for stopped",
    ),
    (
        "verdict_reason",
        lambda d: d["verdicts"]["met"]["reasons"].update(stray=SENTENCE),
        "verdicts.met.reasons has an entry for stray",
    ),
    (
        "near_miss",
        lambda d: d["notes"]["no_exception_in_force"].update(no_exception_for_the_assertion_and_resource=SENTENCE),
        "notes.no_exception_in_force has an entry for no_exception_for_the_assertion_and_resource",
    ),
    (
        "trust_level_reason",
        lambda d: d["trust_levels"]["policy_enforced"]["reasons"].update(run_opened_locally=SENTENCE),
        "trust_levels.policy_enforced.reasons has an entry for run_opened_locally",
    ),
    ("signer", lambda d: d["signed_by"].update(stray=SENTENCE), "signed_by has an entry for stray"),
    (
        "verification_result",
        lambda d: d["verification_properties"]["integrity"]["results"].append(
            {"state": "verified", "reason": "stray", "sentence": SENTENCE}
        ),
        "verification_properties.integrity has an entry for state verified with reason stray",
    ),
    (
        "process_outcome",
        lambda d: d["process_outcomes"].update(passed=WORD),
        "process_outcomes has an entry for passed",
    ),
]


@pytest.mark.parametrize(("change", "message"), [(c, m) for _, c, m in EXTRA], ids=[n for n, _, _ in EXTRA])
def test_a_words_file_with_an_entry_the_contract_does_not_define_is_refused(change: Change, message: str) -> None:
    _refused(change, f"{message}, which the contract does not define")


def test_a_result_is_named_inwords_document() -> None:
    assert named(("verified", "run_statement")) == "state verified with reason run_statement"
    assert named(("not_assessed", None)) == "state not_assessed with no reason"
    assert named("stopped") == "stopped"


def test_every_status_reason_has_exactly_one_entry() -> None:
    assert {status: set(reasons) for status, reasons in DISPLAY_WORDS.status_reasons.items()} == {
        status: set(reasons) for status, reasons in STATUS_REASONS.items()
    }


def test_every_verdict_word_and_reason_has_exactly_one_entry() -> None:
    given = {(value, None) for value in DISPLAY_WORDS.verdicts} | {
        (value, reason) for value, verdict in DISPLAY_WORDS.verdicts.items() for reason in verdict.reasons
    }
    assert given == set(VERDICT_RANKING) | {(value, None) for value, _ in VERDICT_RANKING}


def test_every_trust_level_and_reason_has_exactly_one_entry() -> None:
    given = {(level, reason) for level, entry in DISPLAY_WORDS.trust_levels.items() for reason in entry.reasons}
    assert given == set(TRUST_LEVEL_RESULTS)


def test_every_verification_property_state_and_reason_has_exactly_one_entry() -> None:
    assert set(DISPLAY_WORDS.verification_properties) == set(Properties.model_fields) == set(PROPERTY_RESULTS)
    for name, entry in DISPLAY_WORDS.verification_properties.items():
        given = [(result.state, result.reason) for result in entry.results]
        assert sorted(given, key=str) == sorted(reported_results(name), key=str), name


def test_the_results_of_a_record_whose_integrity_failed_have_theirwords_document() -> None:
    assert INTEGRITY_FAILED in reported_results("integrity")
    assert all(COULD_NOT_DECIDE in reported_results(name) for name in PROPERTY_RESULTS if name != "integrity")


def test_every_near_miss_of_an_exception_has_its_note() -> None:
    assert set(DISPLAY_WORDS.notes.no_exception_in_force) == near_miss_reasons()
    assert near_miss_reasons() >= {"expired", "not_yet_in_force", "for_another_environment", "run_names_no_environment"}


def test_every_reason_group_reads_reasons_of_one_status() -> None:
    groups = {
        reason.group: status
        for status, reasons in DISPLAY_WORDS.status_reasons.items()
        for reason in reasons.values()
        if reason.group is not None
    }
    assert set(groups) == set(DISPLAY_WORDS.status_reason_groups)
    assert set(groups.values()) == {"unknown"}
    assert all(reason.group is not None for reason in DISPLAY_WORDS.status_reasons["unknown"].values())


def test_a_reason_in_a_group_the_file_does_not_define_is_refused() -> None:
    document = words_document()
    document["status_reasons"]["unknown"]["redacted"]["group"] = "stray"
    with pytest.raises(ValueError, match=f"^{re.escape(NOT_COMPLETE)}status_reason_groups has no group stray$"):
        read_words(document)


def test_a_group_holding_reasons_of_two_statuses_is_refused() -> None:
    document = words_document()
    document["status_reasons"]["error"]["compile_failure"]["group"] = "hidden"
    with pytest.raises(
        ValueError, match=f"^{re.escape(NOT_COMPLETE)}group hidden holds reasons of more than one status$"
    ):
        read_words(document)
