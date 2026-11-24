"""The shape of a reviewed run of a pinned scanner, how its placeholders are filled, and its configuration digest.

Each change type keeps the runs of the inputs it scans in its own ``RUNS.json`` (``scanners.iac.runs``). A run holds
the arguments that follow the program (the scanner's own program for Trivy, the Python interpreter for Checkov), the
complete environment the scanner process receives (``environment`` on every platform, with ``posix_environment`` added
on Linux and macOS or ``windows_environment`` on Windows, the program search path among them), the contents of each
file the Iltero CLI writes and names in the arguments (``files``), and the folder the process starts in. Every path the
Iltero CLI chooses is a placeholder that names its role, such as ``{input_file}``: ``{name}`` stands for the value
given, ``{name!r}`` for its Python ``repr``. In an argument a placeholder is the whole argument or a ``repr``, so a path
is never read as part of an option or of code. The Iltero CLI starts the scanner in a new, empty working folder, with
new, empty home and temporary folders and, where the run names one, a new, empty cache folder, the input file a copy of
the input the stage hashed, alone in its folder, and no environment variable but the run's.

A report of a scanner the Iltero CLI ran names the run's configuration digest: the digest of the run's canonical JSON
as its ``RUNS.json`` holds it, placeholders unfilled, so the same run gives the same digest on every runner. Like the
pinned program digest, it is the record's own claim. The runs are data: changing one is a reviewed change to a
``RUNS.json``, a change to the scanner pin.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from iltero_schemas.canonical.common.encoding import digest_of

# A placeholder: ``{name}`` for the value, ``{name!r}`` for its Python repr.
_PLACEHOLDER = re.compile(r"\{([a-z][a-z_]*)(!r)?\}")
_ENVIRONMENT_NAME = re.compile(r"[A-Z][A-Z0-9_]*")
_RUN_KEYS = frozenset(
    {"arguments", "environment", "posix_environment", "windows_environment", "files", "working_folder"}
)
# What a filled value may not hold: a leading dash would read as an option, a NUL would cut the argument short, and a
# line break would split a line of the code or the files a scanner reads.
_REFUSED_IN_VALUES = re.compile(r"^-|[\x00\r\n]")


@dataclass(frozen=True)
class ScannerRun:
    """One reviewed run of a pinned scanner, its paths as placeholders (see the module docstring)."""

    arguments: tuple[str, ...]
    environment: Mapping[str, str]
    posix_environment: Mapping[str, str]
    windows_environment: Mapping[str, str]
    files: Mapping[str, str]
    working_folder: str
    configuration_digest: str

    def environment_on(self, windows: bool) -> Mapping[str, str]:
        """The environment the scanner process receives on Windows (``windows``) or on Linux and macOS."""
        return {**self.environment, **(self.windows_environment if windows else self.posix_environment)}

    def placeholders(self, windows: bool) -> frozenset[str]:
        """Every placeholder the run names on Windows (``windows``) or on Linux and macOS, each needing a value."""
        texts = [*self.arguments, *self.environment_on(windows).values(), self.working_folder]
        return frozenset(match.group(1) for text in texts for match in _PLACEHOLDER.finditer(text))


@dataclass(frozen=True)
class FilledScannerRun:
    """A run with every placeholder filled: what the Iltero CLI passes the scanner process."""

    arguments: tuple[str, ...]
    environment: Mapping[str, str]
    # The contents to write at each filled path the run names, before the scanner starts.
    files: Mapping[str, str]
    working_folder: str


def _fill(text: str, values: Mapping[str, str]) -> str:
    return _PLACEHOLDER.sub(lambda m: repr(values[m.group(1)]) if m.group(2) else values[m.group(1)], text)


def fill_scanner_run(
    run: ScannerRun, values: Mapping[str, str], windows: bool, run_description: str
) -> FilledScannerRun:
    """``run`` (named ``run_description`` in a refusal) with each placeholder replaced by its value, with the Windows
    environment when ``windows`` is true and the one of Linux and macOS otherwise. Raises ``ValueError`` for a value
    missing, not used, empty, starting with a dash, holding a NUL or a line break, or given for two placeholders, since
    two roles never share a path."""
    needed = run.placeholders(windows)
    if set(values) != needed:
        raise ValueError(f"{run_description} needs a value for exactly: {sorted(needed)}")
    for name, value in values.items():
        if not value or _REFUSED_IN_VALUES.search(value):
            raise ValueError(f"{name} is empty, starts with a dash or holds a NUL or a line break")
    if len(set(values.values())) != len(values):
        raise ValueError(f"{run_description} is given one value for two placeholders")
    environment = run.environment_on(windows)
    return FilledScannerRun(
        arguments=tuple(_fill(argument, values) for argument in run.arguments),
        environment=MappingProxyType({name: _fill(value, values) for name, value in environment.items()}),
        files=MappingProxyType({values[name]: contents for name, contents in run.files.items()}),
        working_folder=_fill(run.working_folder, values),
    )


def _strings(value: Any, where: str) -> Mapping[str, str]:
    if not isinstance(value, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
        raise ValueError(f"RUNS.json: {where} maps names to strings")
    return MappingProxyType(dict(value))


def parse_scanner_run(raw: Any, where: str) -> ScannerRun:
    """The run ``raw`` holds, ``where`` naming it in a refusal; ``ValueError`` when it is not one."""
    if not isinstance(raw, dict) or set(raw) != _RUN_KEYS:
        raise ValueError(f"RUNS.json: {where} holds exactly {sorted(_RUN_KEYS)}")
    arguments = raw["arguments"]
    if not isinstance(arguments, list) or not arguments or not all(isinstance(a, str) and a for a in arguments):
        raise ValueError(f"RUNS.json: {where}.arguments is a list of strings, none empty")
    environment = _strings(raw["environment"], f"{where}.environment")
    posix_environment = _strings(raw["posix_environment"], f"{where}.posix_environment")
    windows_environment = _strings(raw["windows_environment"], f"{where}.windows_environment")
    for names in ([*environment, *posix_environment], [*environment, *windows_environment]):
        if not all(_ENVIRONMENT_NAME.fullmatch(name) for name in names) or len(set(names)) != len(names):
            raise ValueError(f"RUNS.json: {where} names each environment variable once on each system, in capitals")
    files = _strings(raw["files"], f"{where}.files")
    if not isinstance(raw["working_folder"], str) or not _PLACEHOLDER.fullmatch(raw["working_folder"]):
        raise ValueError(f"RUNS.json: {where}.working_folder is one placeholder")
    whole = {
        match.group(1) for argument in arguments if (match := _PLACEHOLDER.fullmatch(argument)) and not match.group(2)
    }
    if not set(files) <= whole:
        raise ValueError(f"RUNS.json: {where}.files names only placeholders that are whole arguments, not a repr")
    for argument in arguments:
        if any(not m.group(2) and m.group(0) != argument for m in _PLACEHOLDER.finditer(argument)):
            raise ValueError(f"RUNS.json: {where}.arguments puts a placeholder only as a whole argument or a repr")
    texts = [*arguments, *environment.values(), *posix_environment.values(), *windows_environment.values()]
    if any({"{", "}"} & set(_PLACEHOLDER.sub("", text)) for text in texts):
        raise ValueError(f"RUNS.json: {where} holds a brace that is not part of a placeholder")
    return ScannerRun(
        arguments=tuple(arguments),
        environment=environment,
        posix_environment=posix_environment,
        windows_environment=windows_environment,
        files=files,
        working_folder=raw["working_folder"],
        configuration_digest=digest_of(raw),
    )
