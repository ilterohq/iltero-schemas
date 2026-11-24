"""The reviewed runs of the pinned scanners over the inputs of a change made with an IaC tool.

``RUNS.json`` holds, for each scanner and each input kind it reads (``plan`` today), one run in the shape
``scanners.common.runs`` describes. A report of a scanner the Iltero CLI ran names the run's configuration digest
(``scanner_configuration_digest``).
"""

from __future__ import annotations

from collections.abc import Mapping
from importlib import resources
from types import MappingProxyType
from typing import Any, get_args

from iltero_schemas.models.common.scanners import SCANNER_TOOLS
from iltero_schemas.models.common.strict_json import strict_json
from iltero_schemas.models.iac.scanner_check_mapping import InputKind
from iltero_schemas.scanners.common.runs import FilledScannerRun, ScannerRun, fill_scanner_run, parse_scanner_run


def parse_scanner_runs(raw: Any) -> Mapping[str, Mapping[str, ScannerRun]]:
    """The runs a ``RUNS.json`` document holds, by tool and input kind; ``ValueError`` when it is not one."""
    if not isinstance(raw, dict) or set(raw) != set(SCANNER_TOOLS):
        raise ValueError(f"RUNS.json holds the runs of each scanner a record may name, and only those: {SCANNER_TOOLS}")
    runs: dict[str, Mapping[str, ScannerRun]] = {}
    for tool, by_kind in raw.items():
        if not isinstance(by_kind, dict) or not by_kind or not set(by_kind) <= set(get_args(InputKind)):
            raise ValueError(f"RUNS.json: {tool} holds runs keyed by input kinds: {get_args(InputKind)}")
        runs[tool] = MappingProxyType({kind: parse_scanner_run(run, f"{tool}.{kind}") for kind, run in by_kind.items()})
    return MappingProxyType(runs)


SCANNER_RUNS: Mapping[str, Mapping[str, ScannerRun]] = parse_scanner_runs(
    strict_json(resources.files("iltero_schemas.scanners.iac").joinpath("RUNS.json").read_bytes(), "RUNS.json")
)


def filled_scanner_run(tool: str, input_kind: str, values: Mapping[str, str], windows: bool) -> FilledScannerRun:
    """The pinned run of ``tool`` over ``input_kind`` filled as ``fill_scanner_run`` fills it. Raises ``KeyError`` for
    a run the pin does not hold and ``ValueError`` for values ``fill_scanner_run`` refuses."""
    return fill_scanner_run(SCANNER_RUNS[tool][input_kind], values, windows, f"the {tool} run over {input_kind}")


def scanner_configuration_digest(tool: str, input_kind: str) -> str:
    """The configuration digest of the pinned run of ``tool`` over ``input_kind``; ``KeyError`` when there is none."""
    return SCANNER_RUNS[tool][input_kind].configuration_digest
