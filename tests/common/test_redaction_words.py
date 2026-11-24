"""Whether a key's name, or a value, looks like a credential."""

from __future__ import annotations

import re
import time
from collections.abc import Callable

import pytest

from iltero_schemas.redaction.common.credentials import CREDENTIAL_WORDS, IDENTIFIER_WORDS, VALUE_SHAPES
from iltero_schemas.redaction.common.words import (
    DIGITS,
    TRAILING_DIGITS_PATTERN,
    assigns_a_credential,
    key_is_denied,
    key_is_shaped_like_a_credential,
    matching_shape,
    names_by_value_key,
    singular,
)


@pytest.mark.parametrize(
    ("key", "denied"),
    [
        ("password", True),
        ("db_password", True),
        ("DBPassword", True),
        ("dbPassword", True),
        ("password_wo_version", False),
        ("passwords", True),
        ("db_creds", True),
        ("password1", True),
        ("api_key_2", True),
        ("primary_key", True),
        ("sas_key", True),
        ("container_definitions", True),
        ("containerDefinitions", True),
        ("client-secret", True),
        ("ApiToken", True),
        ("credentials", True),
        ("private_key_pem", True),
        ("passphrase", True),
        ("connection_string", True),
        ("ConnectionString", True),
        ("user_data", True),
        ("userData", True),
        ("access_key", True),
        ("secret_key", True),
        ("api-key", True),
        ("key_material", True),
        ("private_key_base64", True),
        ("kms_key_id", False),
        ("kms_key_arn", False),
        ("secret_name", False),
        ("secret_version", False),
        ("secret_status", False),
        ("password_policies", False),
        ("key_arns", False),
        ("token_endpoint", False),
        ("password_policy", False),
        ("key", False),
        ("hash_key", False),
        ("provider_config_key", False),
        ("public_key", False),
        ("key_usage", False),
        ("enable_key_rotation", False),
        ("username", False),
        ("bucket", False),
        ("", False),
    ],
)
def test_keys_that_look_like_credentials(key: str, denied: bool) -> None:
    assert key_is_denied(key) is denied


@pytest.mark.parametrize("word", sorted(CREDENTIAL_WORDS))
def test_every_credential_word_is_denied_bare_prefixed_and_plural(word: str) -> None:
    plural = word if word.endswith("s") else f"{word}s"
    assert key_is_denied(word) and key_is_denied(f"db_{word}") and key_is_denied(plural)


@pytest.mark.parametrize("word", sorted(IDENTIFIER_WORDS))
def test_every_identifier_word_exempts_a_credential_key(word: str) -> None:
    assert not key_is_denied(f"password_{word}")


def test_singular_forms() -> None:
    assert singular("policies") == "policy" and singular("passwords") == "password"
    assert singular("pass") == "pass" and singular("access") == "access"


def test_values_that_look_like_credentials() -> None:
    assert matching_shape("export AWS_ACCESS_KEY_ID=" + "AKIA" + "IOSFODNN7EXAMPLE") == "aws_access_key_id"
    assert matching_shape("-----BEGIN RSA " + "PRIVATE KEY-----\nabc") == "private_key_block"
    assert matching_shape("eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 12) == "jwt"
    assert matching_shape("postgres://user:hidden@db.internal/app") == "url_credentials"
    assert matching_shape("token = abc") == "embedded_assignment"
    assert matching_shape("export DB_PASSWORD=hunter2") == "embedded_assignment"
    assert matching_shape('{"password":"x"}') == "embedded_assignment"
    assert matching_shape("redis://:hidden@cache.internal") == "url_credentials"
    assert matching_shape("Authorization: Bearer abcdefghijklmnop.qrstuvwxyz") == "authorization_header"
    assert matching_shape("ilt_" + "a" * 20) == "iltero_token"
    assert matching_shape("irt_" + "a" * 43) == "iltero_token"
    assert matching_shape("irk_" + "a" * 43) == "iltero_token"
    assert matching_shape("password_length = 16") is None
    assert matching_shape("just a plain value") is None
    assert matching_shape("https://db.internal/app") is None


def test_a_key_that_names_where_a_credential_is_kept_does_not_hold_one() -> None:
    assert not key_is_denied("password_file")
    assert not key_is_denied("ssh_private_key_path")
    assert key_is_denied("password")


def test_every_name_written_beside_a_value_is_found_whatever_its_case() -> None:
    entry = {"Name": "label", "Key": "DB_PASSWORD", "Value": "v", "other": "x"}
    assert names_by_value_key(entry)["value"] == ("label", "DB_PASSWORD")
    assert names_by_value_key({"OptionName": "DB_PASSWORD", "Value": "v"}) == {"value": ("DB_PASSWORD",)}
    assert "other" not in names_by_value_key(entry)


@pytest.mark.parametrize(
    ("text", "assigns"),
    [
        ("DB_PASS=x", True),
        ("--db-password=x", True),
        ("RUN |2 A=1 DB_PASS=x make", True),
        ("PATH=/usr/bin", False),
        ("API_KEY_ID=1", False),
        ("DB_PASSWORD=", False),
    ],
)
def test_a_string_assigns_a_credential_when_a_name_before_an_equals_sign_is_denied(text: str, assigns: bool) -> None:
    assert assigns_a_credential(text) is assigns


def test_searching_a_long_string_for_assignments_takes_time_in_proportion_to_its_length() -> None:
    started = time.perf_counter()
    assert not assigns_a_credential("aB-" * 300_000)
    assert time.perf_counter() - started < 1


# Each case is named, so the test's id is not the megabyte of text itself.
@pytest.mark.parametrize(
    "text",
    ["a" * 1_000_000, "a-" * 500_000, "password" + " " * 1_000_000],
    ids=["one-letter", "letter-and-dash", "word-then-spaces"],
)
def test_searching_a_long_string_for_a_credential_shape_takes_time_in_proportion_to_its_length(text: str) -> None:
    started = time.perf_counter()
    assert matching_shape(text) is None
    assert time.perf_counter() - started < 1


def test_every_name_beside_each_value_key_is_found_in_one_reading_of_the_entry() -> None:
    entry = {"Name": "label", "Key": "DB_PASSWORD", "Value": "v", "ParameterKey": "p", "other": 1}
    assert names_by_value_key(entry) == {"value": ("label", "DB_PASSWORD"), "parametervalue": ("p",)}


# How much longer four times the input may take. Linear work takes about four times as long, and quadratic work about
# sixteen. The ratio, not a wall-clock limit, keeps a slow runner from failing the test.
_GROWTH_LIMIT = 10


def _fastest_seconds(work: Callable[[], object]) -> float:
    fastest = float("inf")
    for _ in range(5):
        started = time.perf_counter()
        work()
        fastest = min(fastest, time.perf_counter() - started)
    return fastest


def _grows_linearly(work: Callable[[int], object], size: int) -> None:
    small = _fastest_seconds(lambda: work(size))
    large = _fastest_seconds(lambda: work(4 * size))
    assert large < _GROWTH_LIMIT * small, (small, large)


def test_a_key_with_a_long_run_of_digits_inside_a_word_is_judged_in_linear_time() -> None:
    _grows_linearly(lambda n: key_is_denied("a" + "1" * n + "b"), 100_000)


def test_a_string_assigning_a_name_with_a_long_run_of_digits_is_judged_in_linear_time() -> None:
    _grows_linearly(lambda n: assigns_a_credential("a" + "1" * n + "b=x"), 100_000)


@pytest.mark.parametrize("word", ["password", "1234", "pass1word", "password12", "Password1", ""])
def test_dropping_a_words_trailing_digits_does_what_the_recorded_pattern_says(word: str) -> None:
    assert re.sub(TRAILING_DIGITS_PATTERN, "", word) == word.rstrip(DIGITS)


@pytest.mark.parametrize(
    ("key", "shaped"),
    [
        ("AKIA" + "IOSFODNN7EXAMPLE", True),
        ("DB_PASSWORD=hunter2", True),
        ("https://user:hidden@db.internal", True),
        ("password", False),
        ("db_password", False),
        ("tags", False),
        ("", False),
    ],
)
def test_a_key_is_shaped_like_a_credential_by_its_shape_or_an_assignment_never_by_its_words(
    key: str, shaped: bool
) -> None:
    assert key_is_shaped_like_a_credential(key) is shaped


# For each value shape, the longest text that almost matches it: the input a pattern that searched it again from
# each start would take the square of its length to refuse.
NEAR_MISSES = {
    "aws_access_key_id": lambda n: "AKIA" * n,
    "private_key_block": lambda n: "-----BEGIN " + "A " * n,
    "jwt": lambda n: "eyJaaaaaaaaaaa-" * n,
    "url_credentials": lambda n: "a://" * n,
    "github_token": lambda n: "ghp_" * n,
    "slack_token": lambda n: "xoxb-" * n,
    "google_api_key": lambda n: "AIza" * n,
    "authorization_header": lambda n: "bearer " * n,
    "iltero_token": lambda n: "ilt" + "_" * n,
    "embedded_assignment": lambda n: "password " * n,
    "assignment": lambda n: "a" + "1" * n + "b",
    "word_split": lambda n: "aB" * n,
}


@pytest.mark.parametrize("shape", sorted(NEAR_MISSES))
def test_text_that_almost_matches_a_credential_shape_is_searched_in_linear_time(shape: str) -> None:
    def search(n: int) -> object:
        text = NEAR_MISSES[shape](n)
        return matching_shape(text), assigns_a_credential(text), key_is_denied(text)

    _grows_linearly(search, 20_000)


# A sample of each credential shape, built from parts so no tracked file holds one whole.
SHAPE_SAMPLES = {
    "aws_access_key_id": "AKIA" + "IOSFODNN7EXAMPLE",
    "private_key_block": "-----BEGIN RSA " + "PRIVATE KEY-----",
    "jwt": "eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 12,
    "url_credentials": "postgres://user:hidden@db.internal/app",
    "github_token": "ghp" + "_" + "a" * 36,
    "slack_token": "xoxb" + "-" + "a" * 12,
    "google_api_key": "AIza" + "a" * 35,
    "authorization_header": "Bearer abcdefghijklmnop",
    "iltero_token": "ilt" + "_" + "a" * 20,
    "embedded_assignment": "token = abc",
}


def test_every_credential_shape_has_a_sample_here() -> None:
    assert set(SHAPE_SAMPLES) == {name for name, _pattern in VALUE_SHAPES}


@pytest.mark.parametrize("shape", sorted(SHAPE_SAMPLES))
def test_each_credential_shape_is_found_by_its_name(shape: str) -> None:
    assert matching_shape(SHAPE_SAMPLES[shape]) == shape
