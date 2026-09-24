"""The assertion compiler (see ``emit``) and the size limits of its answers (see ``limits``)."""

from iltero_schemas.compiler.emit import (
    COMPILER_VERSION,
    ENTRYPOINT_RULE,
    PACKAGE_PREFIX,
    RUNTIME,
    RegoModule,
    compile,
    package_of,
)
from iltero_schemas.compiler.limits import (
    OBSERVATIONS_MAX_BYTES,
    OBSERVATIONS_MAX_DEPTH,
    REASON_MAX_BYTES,
    SHORT_LIST_MAX,
    SHORT_STRING_MAX_CHARS,
    SUBJECT_FIELD_MAX_CHARS,
    nesting_depth,
)

__all__ = [
    "COMPILER_VERSION",
    "ENTRYPOINT_RULE",
    "OBSERVATIONS_MAX_BYTES",
    "OBSERVATIONS_MAX_DEPTH",
    "PACKAGE_PREFIX",
    "REASON_MAX_BYTES",
    "RUNTIME",
    "SHORT_LIST_MAX",
    "SHORT_STRING_MAX_CHARS",
    "SUBJECT_FIELD_MAX_CHARS",
    "RegoModule",
    "compile",
    "nesting_depth",
    "package_of",
]
