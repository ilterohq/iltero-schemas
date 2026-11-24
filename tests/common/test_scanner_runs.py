"""The shape of a reviewed scanner run, how its placeholders are filled and what loading one refuses."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from iltero_schemas.canonical import digest_of
from iltero_schemas.scanners.common.runs import fill_scanner_run, parse_scanner_run

# A run of the shape every change type's runs share, with a file the Iltero CLI writes and a code placeholder.
RUN: dict[str, Any] = {
    "arguments": ["scan", "--config", "{config_file}", "-c", "load({packages_folder!r})", "{input_file}"],
    "environment": {"HOME": "{home_folder}"},
    "posix_environment": {"PATH": "/usr/bin:/bin"},
    "windows_environment": {"PATH": "{system_root_folder}\\System32", "USERPROFILE": "{home_folder}"},
    "files": {"config_file": ""},
    "working_folder": "{working_folder}",
}
VALUES = {
    "config_file": "/w/own/config.yaml",
    "packages_folder": "C:\\w\\own\\packages",
    "input_file": "/w/input/plan.json",
    "home_folder": "/w/home",
    "working_folder": "/w/run",
}
WINDOWS_VALUES = {**VALUES, "system_root_folder": "C:\\Windows"}
DESCRIPTION = "the sample run"


def _fill(values: dict[str, str], windows: bool) -> Any:
    return fill_scanner_run(parse_scanner_run(RUN, "sample"), values, windows, DESCRIPTION)


def test_a_runs_configuration_digest_is_the_digest_of_its_entry_with_placeholders_unfilled() -> None:
    assert parse_scanner_run(RUN, "sample").configuration_digest == digest_of(RUN)


def test_a_run_is_filled_whole_with_its_files_and_the_environment_of_its_system() -> None:
    posix = _fill(VALUES, windows=False)
    assert posix.arguments[2] == "/w/own/config.yaml" and posix.arguments[-1] == "/w/input/plan.json"
    assert dict(posix.environment) == {"HOME": "/w/home", "PATH": "/usr/bin:/bin"}
    assert dict(posix.files) == {"/w/own/config.yaml": ""}
    assert posix.working_folder == "/w/run"
    windows = _fill(WINDOWS_VALUES, windows=True)
    assert dict(windows.environment) == {"HOME": "/w/home", "PATH": "C:\\Windows\\System32", "USERPROFILE": "/w/home"}


def test_a_code_placeholder_is_filled_with_the_values_python_repr() -> None:
    assert _fill(VALUES, windows=False).arguments[4] == f"load({VALUES['packages_folder']!r})"


def test_the_windows_only_placeholders_are_needed_only_on_windows() -> None:
    with pytest.raises(ValueError, match="needs a value for exactly"):
        _fill(WINDOWS_VALUES, windows=False)
    with pytest.raises(ValueError, match="needs a value for exactly"):
        _fill(VALUES, windows=True)


@pytest.mark.parametrize(
    "values",
    [{k: v for k, v in VALUES.items() if k != "input_file"}, {**VALUES, "cache_folder": "/w/own/cache"}],
    ids=["a value missing", "a value no placeholder names"],
)
def test_a_run_is_filled_with_a_value_for_exactly_its_placeholders(values: dict[str, str]) -> None:
    with pytest.raises(ValueError, match=f"{DESCRIPTION} needs a value for exactly"):
        _fill(values, windows=False)


@pytest.mark.parametrize("value", ["", "--config=/x", "/w/a\nb", "/w/a\rb", "/w/a\x00b"])
def test_a_value_that_could_change_an_argument_is_refused(value: str) -> None:
    with pytest.raises(ValueError, match="is empty, starts with a dash or holds a NUL or a line break"):
        _fill({**VALUES, "input_file": value}, windows=False)


def test_one_value_for_two_placeholders_is_refused() -> None:
    with pytest.raises(ValueError, match=f"{DESCRIPTION} is given one value for two placeholders"):
        _fill({**VALUES, "config_file": VALUES["input_file"]}, windows=False)


def test_a_value_holding_a_brace_is_filled_once_and_never_read_as_a_placeholder() -> None:
    value = "C:\\Temp\\{0A1B}\\{input_file}"
    assert _fill({**VALUES, "input_file": value}, windows=False).arguments[-1] == value


def _changed(change: Any) -> dict[str, Any]:
    raw = copy.deepcopy(RUN)
    change(raw)
    return raw


def _write_at_a_repr(run: dict[str, Any]) -> None:
    run["arguments"][run["arguments"].index("{config_file}")] = "{config_file!r}"


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (_changed(lambda run: run.pop("files")), "holds exactly"),
        (_changed(lambda run: run.update(arguments=[])), "arguments is a list of strings, none empty"),
        (_changed(lambda run: run["environment"].update(Path="/bin")), "names each environment variable once"),
        (_changed(lambda run: run["windows_environment"].update(HOME="/w")), "names each environment variable once"),
        (_changed(lambda run: run.update(working_folder="/w/run")), "working_folder is one placeholder"),
        (_changed(lambda run: run["files"].update(home_folder="")), "only placeholders that are whole arguments"),
        (_changed(_write_at_a_repr), "whole arguments, not a repr"),
        (_changed(lambda run: run["arguments"].append("--cache-dir={cache_folder}")), "whole argument or a repr"),
        (_changed(lambda run: run["arguments"].append("{not a placeholder}")), "a brace that is not part of"),
        (_changed(lambda run: run["environment"].update(X=1)), "maps names to strings"),
    ],
    ids=[
        "a field missing",
        "no arguments",
        "an environment name not in capitals",
        "an environment variable named twice on one system",
        "a working folder that is a path",
        "a file whose path is not an argument",
        "a file written at a repr",
        "a placeholder inside an option",
        "a stray brace",
        "an environment value that is not a string",
    ],
)
def test_a_run_that_is_not_one_is_refused(raw: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        parse_scanner_run(raw, "sample")


def test_one_name_may_differ_between_the_two_systems() -> None:
    run = parse_scanner_run(RUN, "sample")
    assert run.environment_on(windows=False)["PATH"] != run.environment_on(windows=True)["PATH"]
