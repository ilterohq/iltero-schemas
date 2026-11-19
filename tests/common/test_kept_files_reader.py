"""The vectors' kept files are read by the path each record's register names them by, as text or as base64."""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from pathlib import Path

import pytest

from iltero_schemas.vectors import kept_files
from iltero_schemas.vectors.kept_files import kept_files_of, kept_files_of_case
from tests.conftest import VECTORS


def test_a_record_s_kept_files_are_its_register_paths_with_their_bytes() -> None:
    record = json.loads((VECTORS / "records" / "iac" / "local_run.json").read_text(encoding="utf-8"))
    files = kept_files_of("iac/local_run")
    assert files and set(files) <= {ref["path"] for ref in record["evidence_refs"]}
    assert kept_files_of("iac/local_run.json") == files


def test_a_record_whose_files_the_vectors_do_not_hold_keeps_none() -> None:
    assert kept_files_of("iac/local_run_deployed") == {}


def _vectors(root: Path, record_files: Mapping[str, object]) -> None:
    """A vectors folder at ``root`` holding the record ``iac/base`` and its kept files ``record_files``."""
    (root / "records" / "iac").mkdir(parents=True)
    (root / "records" / "iac" / "base.json").write_text("{}", encoding="utf-8")
    (root / "kept_files" / "iac" / "cases").mkdir(parents=True)
    (root / "kept_files" / "iac" / "base.json").write_text(json.dumps(record_files), encoding="utf-8")


def test_a_case_keeps_its_own_file_in_place_of_its_record_s_at_the_same_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = {"files": {"a.json": {"text": "record"}, "b.bin": {"base64": base64.b64encode(b"\x00\xff").decode()}}}
    case = {"files": {"a.json": {"text": "case"}}}
    _vectors(tmp_path, record)
    (tmp_path / "kept_files" / "iac" / "cases" / "changed.json").write_text(json.dumps(case), encoding="utf-8")
    monkeypatch.setattr(kept_files, "VECTORS", tmp_path)
    assert kept_files_of_case({"name": "iac_changed", "vector": "iac/base.json"}) == {
        "a.json": b"case",
        "b.bin": b"\x00\xff",
    }
    assert kept_files_of_case({"name": "iac_other", "vector": "iac/base.json"}) == {
        "a.json": b"record",
        "b.bin": b"\x00\xff",
    }


def test_a_record_the_vectors_do_not_hold_is_refused() -> None:
    with pytest.raises(KeyError, match="the vectors hold no record iac/no_such_record"):
        kept_files_of("iac/no_such_record")


@pytest.mark.parametrize(
    ("files", "message"),
    [
        ({"../outside.json": {"text": "x"}}, "is not a relative path inside the record's folder"),
        ({"/etc/x": {"text": "x"}}, "is not a relative path inside the record's folder"),
        ({"a\\b.json": {"text": "x"}}, "is not a relative path inside the record's folder"),
        ({"a.json": {"text": "x", "base64": "eA=="}}, "holds exactly one of text or base64"),
        ({"a.json": {"bytes": "x"}}, "holds exactly one of text or base64"),
        ({"a.json": {"base64": "not base64!"}}, "is not base64"),
    ],
    ids=["parent_folder", "absolute", "backslash", "both_forms", "unknown_form", "bad_base64"],
)
def test_a_kept_file_outside_its_folder_or_in_no_one_form_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, files: dict[str, dict[str, str]], message: str
) -> None:
    _vectors(tmp_path, {"files": files})
    monkeypatch.setattr(kept_files, "VECTORS", tmp_path)
    with pytest.raises(ValueError, match=message):
        kept_files_of("iac/base")


def test_a_kept_files_file_holding_anything_beside_its_files_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _vectors(tmp_path, {"files": {}, "note": "x"})
    monkeypatch.setattr(kept_files, "VECTORS", tmp_path)
    with pytest.raises(ValueError, match="holds only its files"):
        kept_files_of("iac/base")
