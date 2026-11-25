"""The rules the display words follow: the server is "the server", Iltero is named only as the holder of a signing key,
a local run says the CLI opened it, no sentence offers a paid feature, the compliance sentence is always shown, and
``policy_enforced`` says the server accepted the record, never that the change passed."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

import pytest

from iltero_schemas.display import DISPLAY_WORDS, render
from iltero_schemas.display.model import Word

COMPLIANCE = "A record states facts; it never establishes compliance with a framework."
LOCAL_RUN = "opened by the CLI, not by a server"


def _texts(node: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Every sentence, word and label of the file, by its path."""
    if isinstance(node, dict):
        if set(node) == {"text", "placeholders"}:
            yield path, node["text"]
            return
        for key, value in node.items():
            if key not in {"apiVersion", "kind", "tone", "icon", "placeholders", "state", "reason", "group"}:
                yield from _texts(value, f"{path}/{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _texts(value, f"{path}/{index}")
    elif isinstance(node, str):
        yield path, node


DUMPED = DISPLAY_WORDS.model_dump(mode="json", by_alias=True)
TEXTS = dict(_texts(DUMPED))


def _sentence_paths(node: Any, path: str = "") -> Iterator[str]:
    """The path of every sentence of the file: each entry with its text and placeholders."""
    if isinstance(node, dict):
        if set(node) == {"text", "placeholders"}:
            yield path
            return
        for key, value in node.items():
            yield from _sentence_paths(value, f"{path}/{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _sentence_paths(value, f"{path}/{index}")


SENTENCE_PATHS = list(_sentence_paths(DUMPED))


def test_the_file_holds_text() -> None:
    assert len(TEXTS) > 200


@pytest.mark.parametrize("path", sorted(TEXTS))
def test_no_text_names_the_server_by_the_product_name(path: str) -> None:
    assert "Iltero Platform" not in TEXTS[path], path
    assert "the platform" not in TEXTS[path].lower(), path


def test_iltero_is_named_only_as_the_holder_of_a_signing_key() -> None:
    named = sorted(path for path, text in TEXTS.items() if "Iltero" in text)
    assert named == ["/signed_by/iltero", "/signed_by/operator"]


def test_a_run_statement_an_operator_signed_names_the_operators_server_and_says_iltero_did_not_sign_it() -> None:
    text = render(
        DISPLAY_WORDS.signed_by["operator"],
        {"operator": "Example Corp", "key_id": "example-1", "operator_file": "trust.json", "trust_data_digest": "d"},
    )
    assert text.startswith("The run statement is signed by Example Corp's server")
    assert text.endswith("Iltero did not sign it.")


def test_a_signer_signs_the_run_statement_never_the_record() -> None:
    for sentence in DISPLAY_WORDS.signed_by.values():
        assert sentence.text.startswith("The run statement is signed by")
        assert "sign this record" not in sentence.text


# Whose word a result the record claims rests on.
WHOSE_WORD = re.compile(r"\bonly (the record|the pipeline|the project|the job|that server)\b")


def test_every_result_the_record_claims_says_whose_word_it_is() -> None:
    claimed = [
        (name, result.reason, result.sentence.text)
        for name, entry in DISPLAY_WORDS.verification_properties.items()
        for result in entry.results
        if result.state == "claimed_by_record"
    ]
    assert len(claimed) > 20
    assert [found for found in claimed if not WHOSE_WORD.search(found[2])] == []


def test_every_sentence_about_a_local_run_says_the_cli_opened_it_not_a_server() -> None:
    local = [DISPLAY_WORDS.trust_levels["self_attested"].reasons["run_opened_locally"]] + [
        result.sentence
        for entry in DISPLAY_WORDS.verification_properties.values()
        for result in entry.results
        if result.reason == "run_opened_locally"
    ]
    assert len(local) > 1
    assert all(LOCAL_RUN in sentence.text for sentence in local)


# Words that would offer a feature of a paid plan.
PAID_FEATURE = re.compile(
    r"\b(paid|subscription|upgrade|control mapping|framework mapping|requirement assessment|period package)",
    re.IGNORECASE,
)


@pytest.mark.parametrize("path", sorted(TEXTS))
def test_no_text_mentions_a_paid_feature(path: str) -> None:
    assert not PAID_FEATURE.search(TEXTS[path]), path


@pytest.mark.parametrize("path", sorted(TEXTS))
def test_no_text_says_owe_or_waiver(path: str) -> None:
    assert not re.search(r"\b(owe|owed|owes|owing|waiver|waivers|waive|waived)\b", TEXTS[path], re.IGNORECASE), path


def test_the_compliance_sentence_is_one_the_report_always_shows() -> None:
    assert DISPLAY_WORDS.always_shown.compliance.text == COMPLIANCE
    assert [path for path, text in TEXTS.items() if text == COMPLIANCE] == ["/always_shown/compliance"]


def test_policy_enforced_says_the_server_accepted_the_record_and_signed_for_it_never_that_the_change_passed() -> None:
    for text in (
        DISPLAY_WORDS.trust_levels["policy_enforced"].reasons["run_statement"].text,
        next(
            result.sentence.text
            for result in DISPLAY_WORDS.verification_properties["integrity"].results
            if (result.state, result.reason) == ("verified", "run_statement")
        ),
    ):
        assert "accepted this record and signed for it" in text
        assert "passed" not in text


def test_the_verdict_words_are_kept_apart_from_the_result_words() -> None:
    results = {entry.word for entry in DISPLAY_WORDS.result_statuses.values()}
    verdicts = {entry.word for entry in DISPLAY_WORDS.verdicts.values()}
    assert DISPLAY_WORDS.verdicts["met"].word == "Checks met"
    assert DISPLAY_WORDS.result_statuses["pass"].word == "Met"
    assert not results & verdicts


def test_a_process_outcome_is_never_a_verdict_or_a_result_status() -> None:
    assert not set(DISPLAY_WORDS.process_outcomes) & (set(DISPLAY_WORDS.verdicts) | set(DISPLAY_WORDS.result_statuses))


def _words() -> Iterator[Word]:
    for section in (
        DISPLAY_WORDS.result_statuses,
        DISPLAY_WORDS.verdicts,
        DISPLAY_WORDS.verification_states,
        DISPLAY_WORDS.process_outcomes,
    ):
        yield from section.values()


def test_one_icon_has_one_plain_mark_everywhere() -> None:
    marks: dict[str, set[str]] = {}
    for word in _words():
        marks.setdefault(word.icon, set()).add(word.plain.removesuffix(f" {word.word}"))
    assert all(len(found) == 1 for found in marks.values()), marks


def test_every_sentence_is_a_full_sentence() -> None:
    assert len(SENTENCE_PATHS) > 200
    for path in SENTENCE_PATHS:
        text = TEXTS[path]
        assert text[0].isupper() and text.endswith("."), path


def test_no_word_or_label_ends_like_a_sentence() -> None:
    labels = [text for path, text in TEXTS.items() if path not in SENTENCE_PATHS]
    assert labels
    assert not [text for text in labels if text.endswith(".")]
