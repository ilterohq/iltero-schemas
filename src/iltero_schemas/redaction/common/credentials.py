"""What a credential looks like: the words a key's name holds and the shapes a value has.

Redaction reads this one list, and so can any other part of a tool that must recognise a credential the same way,
such as a filter for its messages. Words are compared as words of a key name; shapes are matched inside a value. This
module uses the standard library only.
"""

from __future__ import annotations

import re

# A key holding one of these words (as a word: ``db_password``, ``apiToken``, ``db_creds``)
# holds a credential. Words are compared in singular form: ``creds`` is ``cred``.
CREDENTIAL_WORDS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "pass",
        "secret",
        "token",
        "bearer",
        "credential",
        "cred",
        "authorization",
        "passphrase",
        "private_key",
        "connection_string",
        "user_data",
        "custom_data",
        "container_definition",
        "apikey",
        "secretkey",
        "accesskey",
    }
)
# ``key`` alone names too many things (a map key, a table's hash key, a provider key). It
# names a credential when a word before it says whose key it is (``access_key``, ``api_key``)
# or when a word after it says how it is written (``key_pem``, ``key_material``).
KEY_WORD = "key"
KEY_QUALIFIERS = frozenset(
    {
        "access",
        "secret",
        "api",
        "private",
        "signing",
        "encryption",
        "decryption",
        "master",
        "ssh",
        "auth",
        "license",
        "service",
        "account",
        "client",
        "app",
        "consumer",
        "shared",
        "symmetric",
        "session",
        "recovery",
        "admin",
        "root",
        "wrapping",
        "activation",
        "registration",
        "primary",
        "secondary",
        "sas",
        "tls",
        "cert",
        "hmac",
    }
)
KEY_FORMAT_WORDS = frozenset({"pem", "data", "base64", "content", "material", "json", "text", "value"})
# A key that names an identifier, a setting or a status of a credential, not the credential
# (last word, singular form).
IDENTIFIER_WORDS = frozenset(
    {
        "id",
        "arn",
        "name",
        "status",
        "enabled",
        "ttl",
        "length",
        "count",
        "type",
        "version",
        "policy",
        "endpoint",
        "url",
        "uri",
        "file",
        "path",
    }
)
# Many tools write a setting as an object that holds its name and its value apart, such as
# ``{"name": "DB_PASSWORD", "value": "..."}``. The value's own key says nothing, so the name beside it is
# judged as the value's key. Each pair is a naming key and the value key it names, compared in lower case.
NAMED_VALUE_PAIRS: tuple[tuple[str, str], ...] = (
    ("name", "value"),
    ("key", "value"),
    ("optionname", "value"),
    ("parameterkey", "parametervalue"),
)
# A name followed by ``=`` and a value, as in an environment list or a build command (``DB_PASS=...``).
# The name is judged by the same rule as a key. Leading dashes, as in ``--db-password=...``, are not part of it.
# A name starts only where no name character comes before it, so the time to search a string grows with its length.
ASSIGNMENT = re.compile(r"(?<![A-Za-z0-9_.-])-*([A-Za-z_][A-Za-z0-9_.-]*)=(?=[^\s=])")

# Shapes a value can have, whatever its key. Each is a high-confidence shape. Each pattern is written so that the
# time to search a string grows with its length.
AWS_ACCESS_KEY_PREFIXES = ("AKIA", "ASIA", "ABIA", "ACCA")
ILTERO_TOKEN_PREFIXES = ("ilt_", "itk_", "irt_", "irk_")
# Words that, followed by ``=`` or ``:``, introduce a credential in text (``DB_PASSWORD=...``).
_ASSIGNED_WORDS = (
    r"password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key"
    r"|account[_-]?key|sharedaccesskey"
)
VALUE_SHAPES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key_id", re.compile(rf"\b({'|'.join(AWS_ACCESS_KEY_PREFIXES)})[0-9A-Z]{{16}}\b")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    # A token starts only where no token character comes before it, so a run of token characters is read once.
    ("jwt", re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("url_credentials", re.compile(r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*+://[^/\s:@]*+:[^/\s@]+@")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("authorization_header", re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._=+/-]{16,}")),
    ("iltero_token", re.compile(rf"\b(?:{'|'.join(ILTERO_TOKEN_PREFIXES)})[A-Za-z0-9_-]{{16,}}")),
    ("embedded_assignment", re.compile(rf"(?i)(?:{_ASSIGNED_WORDS})\s*+(?:[\"']\s*+)?[:=]\s*+[\"']?\S")),
)
