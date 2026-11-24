"""What is hidden, and why: the redaction policy.

Five rules, in order of precedence. A tool's own marks (a sensitive or not-yet-known value) are always honoured and
nothing configured can override them. Then a string that holds a value a tool marked sensitive is hidden wherever it
appears. Then a configured exempt path keeps the value there, with a stated reason, though each value inside it is still
judged by the rules after it; then a configured path is hidden; then a value is hidden when its key looks like a
credential or when the value itself looks like one. A value's key can be the name written beside it
(``{"name": "DB_PASSWORD", "value": ...}``) or the name before an ``=`` inside it (``DB_PASSWORD=...``). The policy is
recorded with every run, so what was hidden is itself evidence.

Configured paths name an attribute of a resource, such as ``tags.owner`` or ``ingress[*].cidr_blocks``, and apply to
every resource, before and after, wherever a resource's values appear, and under each value the tool declared
sensitive whole, such as a sensitive output's or root variable's value. A policy lists them in code-point order, each
once, so its digest does not depend on the order a configuration wrote them in; where two exempt paths match one
value, the first in that order gives the reason.

A build tool may also name, in its own metadata file only, a list that holds just the ids of the build's secrets. A
tool lets that list through when it checks the file (``also_exempting``), and still checks each id. That allowance
hides nothing, so it is never part of the policy a record names.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, TypeAlias

from iltero_schemas.canonical.common.encoding import digest_of
from iltero_schemas.models.common.redaction import (
    MAX_POLICY_PATH_LENGTH,
    MAX_POLICY_PATHS,
    ExemptPathRule,
    RedactionPolicyDocument,
)
from iltero_schemas.redaction.common.credentials import (
    ASSIGNMENT,
    CREDENTIAL_WORDS,
    IDENTIFIER_WORDS,
    KEY_FORMAT_WORDS,
    KEY_QUALIFIERS,
    KEY_WORD,
    NAMED_VALUE_PAIRS,
    VALUE_SHAPES,
)
from iltero_schemas.redaction.common.paths import PathPattern, TreePath, parse_path
from iltero_schemas.redaction.common.words import TRAILING_DIGITS_PATTERN, WORD_SPLIT

POLICY_ID = "iltero.redaction"
# The version of the policy's rules and of ``redact()``, which applies them, so the policy's digest names both. It stays
# "1" until the first release; after it, any change to what ``redact()`` hides or reports moves it.
POLICY_VERSION = "1"
# A marked string shorter than this is too common a word (a port, "true") to hide by equality.
REUSE_MIN_CHARS = 8

# Paths whose values a policy keeps, each with the reason it keeps them.
ExemptPaths: TypeAlias = tuple[tuple[PathPattern, str], ...]


@dataclass(frozen=True)
class RedactionPolicy:
    """The rules a run redacted with; recorded by id, version and digest.

    Both lists are kept in code-point order of their path text, each path once, and at most ``MAX_POLICY_PATHS`` paths
    of at most ``MAX_POLICY_PATH_LENGTH`` characters each; a policy built otherwise raises ``ValueError``.
    """

    additional_paths: tuple[PathPattern, ...]
    exempt_paths: ExemptPaths

    def __post_init__(self) -> None:
        additional = tuple(sorted(self.additional_paths, key=lambda pattern: pattern.text))
        exempt = tuple(sorted(self.exempt_paths, key=lambda rule: rule[0].text))
        for texts in ([pattern.text for pattern in additional], [pattern.text for pattern, _ in exempt]):
            if len(set(texts)) != len(texts):
                raise ValueError("a redaction policy names each additional and each exempt path once")
            if len(texts) > MAX_POLICY_PATHS or any(len(text) > MAX_POLICY_PATH_LENGTH for text in texts):
                raise ValueError(
                    f"a redaction policy names at most {MAX_POLICY_PATHS} additional and {MAX_POLICY_PATHS} exempt "
                    f"paths, each at most {MAX_POLICY_PATH_LENGTH} characters long"
                )
        object.__setattr__(self, "additional_paths", additional)
        object.__setattr__(self, "exempt_paths", exempt)

    def as_dict(self) -> dict[str, Any]:
        """Every input of every rule, so the digest changes whenever what is hidden would."""
        return {
            "id": POLICY_ID,
            "version": POLICY_VERSION,
            "credential_words": sorted(CREDENTIAL_WORDS),
            "key_qualifiers": sorted(KEY_QUALIFIERS),
            "key_format_words": sorted(KEY_FORMAT_WORDS),
            "identifier_words": sorted(IDENTIFIER_WORDS),
            "key_word": KEY_WORD,
            "named_value_pairs": [list(pair) for pair in NAMED_VALUE_PAIRS],
            "assignment_pattern": ASSIGNMENT.pattern,
            # How a key is split into words, and the digits dropped from each word's end.
            "word_split_pattern": WORD_SPLIT.pattern,
            "trailing_digits_pattern": TRAILING_DIGITS_PATTERN,
            "value_shapes": [{"name": name, "pattern": pattern.pattern} for name, pattern in VALUE_SHAPES],
            "reuse_min_chars": REUSE_MIN_CHARS,
            "additional_paths": [pattern.text for pattern in self.additional_paths],
            "exempt_paths": [{"path": pattern.text, "reason": reason} for pattern, reason in self.exempt_paths],
        }

    @property
    def digest(self) -> str:
        return digest_of(self.as_dict())

    def identity(self) -> dict[str, str]:
        return {"id": POLICY_ID, "version": POLICY_VERSION, "digest": self.digest}

    def document(self) -> RedactionPolicyDocument:
        """The policy as a record writes it out."""
        return RedactionPolicyDocument(
            id=POLICY_ID,
            version=POLICY_VERSION,
            additional_paths=[pattern.text for pattern in self.additional_paths],
            exempt_paths=[ExemptPathRule(path=pattern.text, reason=reason) for pattern, reason in self.exempt_paths],
        )

    def is_additional_path(self, relative: TreePath) -> bool:
        return any(pattern.matches(relative) for pattern in self.additional_paths)

    def also_exempting(self, paths: ExemptPaths) -> RedactionPolicy:
        """This policy, with ``paths`` added to what it exempts, each with its reason."""
        return RedactionPolicy(self.additional_paths, self.exempt_paths + paths)

    def exempt_reason(self, relative: TreePath) -> str | None:
        """The stated reason when the attribute path is exempt, else None."""
        for pattern, reason in self.exempt_paths:
            if pattern.matches(relative):
                return reason
        return None


# The built-in policy: the rules every policy holds, with no path a project added or exempted.
BUILT_IN_REDACTION_POLICY = RedactionPolicy((), ())


def policy_from_document(document: RedactionPolicyDocument) -> RedactionPolicy:
    """The policy a record writes out, rebuilt. Raises ``ValueError`` when the record names a policy this contract does
    not define, or lists a path out of code-point order or twice."""
    if (document.id, document.version) != (POLICY_ID, POLICY_VERSION):
        raise ValueError(
            f"the record names a redaction policy this contract does not define: it defines {POLICY_ID} version "
            f"{POLICY_VERSION}"
        )
    additional = document.additional_paths
    exempt = [rule.path for rule in document.exempt_paths]
    if any(paths != sorted(set(paths)) for paths in (additional, exempt)):
        raise ValueError("the record's redaction policy lists each additional and each exempt path once, in order")
    return RedactionPolicy(
        tuple(parse_path(path) for path in additional),
        tuple((parse_path(rule.path), rule.reason) for rule in document.exempt_paths),
    )
