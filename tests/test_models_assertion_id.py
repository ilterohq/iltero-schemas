"""An assertion id names, in fixed places, the change type, target kind and scope of what it checks."""

from __future__ import annotations

from typing import get_args

import pytest

from iltero_schemas.bindings import STARTER_SET_ID
from iltero_schemas.models.assertion import TargetKind
from iltero_schemas.models.assertion_id import (
    ASSERTION_ID_MAX_LENGTH,
    SCOPE_SEGMENTS,
    SEGMENT_MAX_LENGTH,
    TargetKindName,
    change_type_of_id,
    check_assertion_id,
    provider_segment,
)
from iltero_schemas.models.binding import SetMetadata
from iltero_schemas.models.change_type import CHANGE_TYPE_SEGMENT, COMMON_SEGMENT, ChangeTypeName
from tests.conftest import STARTER_ASSERTIONS


def test_every_change_type_has_one_segment_of_its_own() -> None:
    assert set(CHANGE_TYPE_SEGMENT) == set(get_args(ChangeTypeName))
    segments = list(CHANGE_TYPE_SEGMENT.values())
    assert len(set(segments)) == len(segments) and COMMON_SEGMENT not in segments


def test_every_target_kind_has_its_scope_and_its_id_name() -> None:
    assert set(SCOPE_SEGMENTS) == {kind.value for kind in TargetKind} == set(get_args(TargetKindName))


def test_every_starter_id_names_a_change_type_segment_and_a_target_kind() -> None:
    ids = sorted(path.stem for path in STARTER_ASSERTIONS.glob("*.yaml"))
    assert ids and all(i.split(".")[1] in {*CHANGE_TYPE_SEGMENT.values(), COMMON_SEGMENT} for i in ids)
    assert all(i.split(".")[2] in {kind.value.upper() for kind in TargetKind} for i in ids)


@pytest.mark.parametrize(
    ("assertion_id", "change_type", "kind", "provider"),
    [
        ("ILT.IAC.RESOURCE.AWS.RDS.STORAGE_ENCRYPTED", "iac_change", "resource", "aws"),
        ("ILT.COMMON.CHANGE.APPROVAL.PRODUCTION_APPROVED", None, "change", None),
        ("ILT.IMAGE.ARTIFACT.CHECKS.SCAN_RAN", "image_release", "artifact", None),
        ("ACME.IAC.RESOURCE.GOOGLE_BETA.COMPUTE.NO_PUBLIC_IP", "iac_change", "resource", "google-beta"),
        ("ACME.COMMON.CHANGE.WINDOW.WINDOW_RESPECTED", None, "change", None),
    ],
)
def test_an_id_of_the_positional_form_is_accepted(
    assertion_id: str, change_type: ChangeTypeName | None, kind: TargetKindName, provider: str | None
) -> None:
    check_assertion_id(assertion_id, change_type, kind, provider)


@pytest.mark.parametrize(
    ("assertion_id", "change_type", "kind", "provider", "message"),
    [
        ("ILT.AWS.RDS.STORAGE_ENCRYPTED", "iac_change", "resource", "aws", "PROVIDER.SERVICE.CHECK"),
        ("ILT.CHANGE.PRODUCTION_APPROVED", None, "change", None, "CHANGE.AREA.CHECK"),
        ("ILT.IMAGE.RESOURCE.AWS.RDS.X", "iac_change", "resource", "aws", "second segment must be IAC"),
        ("ILT.IAC.CHANGE.APPROVAL.X", None, "change", None, "second segment must be COMMON"),
        ("ILT.IAC.DEPLOYMENT.DRIFT.X", "iac_change", "change", None, "third segment must be CHANGE"),
        ("ILT.IAC.RESOURCE.GCP.RDS.X", "iac_change", "resource", "aws", "fourth segment must be AWS"),
        ("ILT.COMMON.CHANGE.WINDOW.X", None, "change", None, "area must be one of"),
        ("A." + "B" * SEGMENT_MAX_LENGTH + "X.CHANGE.TEST.X", None, "change", None, "each segment"),
        ("ACME.COMMON.CHANGE.TEST." + "X" * ASSERTION_ID_MAX_LENGTH, None, "change", None, "at most 96"),
    ],
)
def test_an_id_that_does_not_say_what_it_checks_is_refused(
    assertion_id: str, change_type: ChangeTypeName | None, kind: TargetKindName, provider: str | None, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        check_assertion_id(assertion_id, change_type, kind, provider)


def test_a_provider_segment_is_its_name_in_upper_case_with_underscores() -> None:
    assert (provider_segment("aws"), provider_segment("google-beta")) == ("AWS", "GOOGLE_BETA")


def test_an_ids_change_type_is_read_from_its_second_segment() -> None:
    assert change_type_of_id("ACME.IAC.RESOURCE.AWS.S3.X") == "iac_change"
    assert change_type_of_id("ACME.IMAGE.ARTIFACT.TEST.X") == "image_release"
    assert change_type_of_id("ACME.COMMON.CHANGE.TEST.X") is None
    with pytest.raises(ValueError, match="names its change type"):
        change_type_of_id("ACME.HELM.CHANGE.TEST.X")


def test_a_binding_set_id_is_not_held_to_the_assertion_form() -> None:
    assert SetMetadata(id=STARTER_SET_ID, version="1.0.0").id == "ILT.BINDINGS.STARTER"
