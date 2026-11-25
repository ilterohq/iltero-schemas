"""The shape of the display words file (``words.json``): the words every report shows for the codes the contract
defines.

A sentence is a ``Text``: the words, and the named placeholders, such as ``{approver}``, it allows. A tone is a meaning
(``positive``, ``negative``, ``caution``, ``neutral``), never a colour; an icon is a name a display draws its own way;
``plain`` is the form a terminal with no colour and no icons prints, in printable ASCII: a mark for the icon, a space,
and the word.
"""

from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import AfterValidator, Field, model_validator

from iltero_schemas.models.common.base import StrictModel, sorted_unique
from iltero_schemas.models.common.fields import plain_text
from iltero_schemas.models.common.verification_states import VerificationState

# A placeholder is a name in braces, in lower case with underscores, such as ``{approver}``.
PLACEHOLDER_NAME = "[a-z][a-z0-9_]*"
PLACEHOLDER = re.compile(rf"\{{({PLACEHOLDER_NAME})\}}")
# Longer than any sentence the file holds, and short enough to read on one screen.
MAX_TEXT_LENGTH = 512
# Longer than any word or label the file holds.
MAX_WORD_LENGTH = 64
# The outcomes of the CLI's process that no record holds: ``stopped``, a stage that stopped before it could judge the
# change (a usage, input, integrity or connection problem).
ProcessOutcome = Literal["stopped"]
Tone = Literal["positive", "negative", "caution", "neutral"]
Icon = Literal["check", "cross", "dash", "question", "circle", "warning", "info", "stop"]
_PRINTABLE_ASCII = re.compile(r"[ -~]+")

ShortText = Annotated[str, Field(min_length=1, max_length=MAX_WORD_LENGTH), AfterValidator(plain_text)]


def _printable_ascii(value: str) -> str:
    if not _PRINTABLE_ASCII.fullmatch(value):
        raise ValueError("a plain form holds printable ASCII only")
    return value


class Text(StrictModel):
    """A sentence, and the placeholders it allows, each a name in braces it holds, sorted, each once."""

    text: Annotated[str, Field(min_length=1, max_length=MAX_TEXT_LENGTH), AfterValidator(plain_text)]
    placeholders: list[Annotated[str, Field(pattern=f"^{PLACEHOLDER_NAME}$")]]

    @model_validator(mode="after")
    def _placeholders_listed(self) -> Text:
        if not sorted_unique(self.placeholders):
            raise ValueError("a sentence lists its placeholders sorted, each once")
        outside = PLACEHOLDER.sub("", self.text)
        if "{" in outside or "}" in outside:
            raise ValueError("a sentence holds a brace only around a placeholder name")
        if set(PLACEHOLDER.findall(self.text)) != set(self.placeholders):
            raise ValueError("a sentence lists exactly the placeholders it holds")
        return self


class Word(StrictModel):
    """How a display shows one code: its word, its plain form, its tone and icon, and the sentence that says what it
    means."""

    word: ShortText
    plain: Annotated[ShortText, AfterValidator(_printable_ascii)]
    tone: Tone
    icon: Icon
    sentence: Text

    @model_validator(mode="after")
    def _plain_ends_with_the_word(self) -> Word:
        if not self.plain.endswith(f" {self.word}"):
            raise ValueError("a plain form is a mark for its icon, a space, and the word")
        return self


class AlwaysShown(StrictModel):
    """The sentences every report shows, whatever the record says."""

    compliance: Text


class ReasonGroup(StrictModel):
    """A group of status reasons a display may show as one sentence; the exact reason stays in the data."""

    label: ShortText
    sentence: Text


class StatusReason(StrictModel):
    """One reason a result has its status: the group it reads in, if any, and its own sentence."""

    group: str | None
    sentence: Text


class VerdictWords(Word):
    """A verdict's words, and a sentence for each reason it may give."""

    reasons: dict[str, Text]


class Notes(StrictModel):
    """The notes a report adds to a result or a gate, each a sentence of its own.

    ``served_exception``: a failed result an exception the server served covers. ``project_exception``: one an
    exception of the project's own file covers, whose approver nothing checks. ``suppressed_in_source_excepted`` and
    ``suppressed_in_source_not_excepted``: a scanner check the source suppressed, covered by a project's exception or by
    none. ``no_exception_in_force``: a failed result an exception was about, by why it did not cover it.
    ``every_failure_excepted``: every failure was excepted, so the gate let the pipeline go on.
    ``advisory_let_through``: shown only when advisory mode let a result not met or undecided through.
    ``incomplete_stopped``: an incomplete verdict stops the pipeline even in advisory mode.
    """

    served_exception: Text
    project_exception: Text
    suppressed_in_source_excepted: Text
    suppressed_in_source_not_excepted: Text
    no_exception_in_force: dict[str, Text]
    every_failure_excepted: Text
    advisory_let_through: Text
    incomplete_stopped: Text


class TrustLevelWords(StrictModel):
    """A trust level's label, and a sentence for each reason a verifier gives it."""

    label: ShortText
    reasons: dict[str, Text]


class PropertyResultWords(StrictModel):
    """The sentence for one result of a property: its state and its reason (null for a result with none)."""

    state: VerificationState
    reason: str | None
    sentence: Text


class PropertyWords(StrictModel):
    """A property's label, and the sentence for each result a verifier gives it."""

    label: ShortText
    results: list[PropertyResultWords]

    @model_validator(mode="after")
    def _each_result_once(self) -> PropertyWords:
        keys = [(result.state, result.reason) for result in self.results]
        if len(set(keys)) != len(keys):
            raise ValueError("a property gives each of its results one sentence")
        return self


class DisplayWords(StrictModel):
    """The display words file's shape. That it has exactly one entry for each code the contract defines, and none
    extra, is ``complete.completeness_problems``, which ``words.read_display_words`` applies."""

    api_version: Literal["iltero.com/v1"] = Field(alias="apiVersion")
    kind: Literal["DisplayWords"]
    always_shown: AlwaysShown
    result_statuses: dict[str, Word]
    status_reason_groups: dict[str, ReasonGroup]
    status_reasons: dict[str, dict[str, StatusReason]]
    verdicts: dict[str, VerdictWords]
    notes: Notes
    trust_levels: dict[str, TrustLevelWords]
    signed_by: dict[str, Text]
    verification_states: dict[str, Word]
    verification_properties: dict[str, PropertyWords]
    process_outcomes: dict[str, Word]
