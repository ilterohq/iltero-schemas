"""The identity binding contract: an ARN of the right kind and nothing more, one entry per resource, never state."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from pydantic import ValidationError

from iltero_schemas.models.identity import API_VERSION, IdentityBindings
from tests.conftest import binding, identity_record, removed

DOCUMENT: dict[str, Any] = {
    "apiVersion": API_VERSION,
    "unit": "root",
    "generator": {"name": "iltero", "version": "0.1.0"},
    **identity_record(
        bindings=[binding("aws_db_instance.payments"), binding("aws_s3_bucket.logs", "s3_bucket")],
        unresolved=[{"address": "aws_lambda_function.worker", "reason": "no_resolver"}],
        removed=[removed("aws_db_instance.payments")],
        removed_unresolved=[{"address": "aws_kms_key.old", "reason": "identifier_missing", "fate": "forgotten"}],
        deposed_objects=1,
    ),
}


def test_a_document_of_bound_and_unresolved_resources_validates() -> None:
    bindings = IdentityBindings.model_validate(DOCUMENT)
    addresses = [entry.terraform.address for entry in bindings.bindings]
    assert addresses == ["aws_db_instance.payments", "aws_s3_bucket.logs"]
    assert bindings.unresolved[0].reason == "no_resolver"
    assert bindings.sources.state.terraform_version == "1.14.0" and bindings.deposed_objects == 1


def test_a_replacement_old_object_is_removed_while_its_new_one_is_bound() -> None:
    """One address in both halves: the list of what the state holds, and the list of what the apply removed."""
    document = IdentityBindings.model_validate(DOCUMENT)
    assert document.removed is not None
    assert document.removed[0].terraform.address == document.bindings[0].terraform.address


def test_what_left_the_state_is_null_exactly_when_no_applied_plan_was_read() -> None:
    """Without the applied plan nothing was checked, so the document says "not checked", never "none"."""
    document = copy.deepcopy(DOCUMENT)
    document["sources"]["plan"] = None
    with pytest.raises(ValidationError, match="exactly when the applied plan was read"):
        IdentityBindings.model_validate(document)
    document.update(removed=None, removed_unresolved=None, deposed_destroyed=None)
    assert IdentityBindings.model_validate(document).removed is None
    document["removed"] = []
    with pytest.raises(ValidationError, match="exactly when the applied plan was read"):
        IdentityBindings.model_validate(document)
    checked = copy.deepcopy(DOCUMENT)
    checked["deposed_destroyed"] = None
    with pytest.raises(ValidationError, match="exactly when the applied plan was read"):
        IdentityBindings.model_validate(checked)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda d: d["bindings"].reverse(), "sorted by address"),
        (lambda d: d["bindings"].append(binding("aws_s3_bucket.logs", "s3_bucket")), "name each resource once"),
        (lambda d: d["unresolved"].insert(0, {"address": "zz.x", "reason": "no_resolver"}), "sorted by address"),
        (lambda d: d["unresolved"].append({"address": "aws_s3_bucket.logs", "reason": "no_resolver"}), "never both"),
        (lambda d: d["bindings"][0]["terraform"].update(unit="network"), "belongs to the unit"),
        (lambda d: d["bindings"][0]["cloud"].update(resource_type="kms_key"), "not the ARN of a kms_key"),
        (lambda d: d["bindings"][0]["cloud"]["primary"].update(value="x" * 2049), "at most 2048"),
        (lambda d: d["bindings"][0].update(authority="heuristic"), "Input should be 'authoritative'"),
        (lambda d: d["resolver"].update(version="latest build"), "String should match pattern"),
        (lambda d: d["generator"].update(name="terraform"), "Input should be 'iltero'"),
        (lambda d: d.pop("generator"), "Field required"),
        (lambda d: d["resolver"].update(verified=["s3_bucket"]), "only a verified resource type is ever bound"),
        (lambda d: d["resolver"].update(verified=[]), "only a verified resource type is ever bound"),
        (lambda d: d["resolver"].update(verified=["s3_bucket", "rds_instance"]), "sorted and named once"),
        (lambda d: d["resolver"].update(verified=["rds_instance", "rds_instance"]), "sorted and named once"),
        (lambda d: d["bindings"][0].update(resolver={"name": "aws", "version": "1.0.0"}), "Extra inputs"),
        (lambda d: d["unresolved"][0].update(reason="guessed"), "Input should be"),
        (lambda d: d["bindings"][0].update(state={"password": "x"}), "Extra inputs are not permitted"),
        (lambda d: d.update(unresolved=[{"address": "x", "reason": "no_resolver"}] * 100_001), "at most 100000"),
        (lambda d: d["removed"].append(removed("aws_db_instance.payments")), "name each resource once"),
        (
            lambda d: d["removed_unresolved"].insert(
                0, {"address": "aws_db_instance.payments", "reason": "no_resolver", "fate": "deleted"}
            ),
            "never both",
        ),
        (lambda d: d.update(deposed_objects=-1), "greater than or equal to 0"),
        (lambda d: d.update(deposed_objects=100_001), "less than or equal to 100000"),
        (lambda d: d["removed"][0].update(fate="vanished"), "Input should be"),
        (lambda d: d["removed"][0].pop("fate"), "Field required"),
        (lambda d: d["removed"][0]["terraform"].update(unit="network"), "belongs to the unit"),
        (lambda d: d["sources"]["state"].update(digest="sha256:abc"), "String should match pattern"),
    ],
    ids=[
        "unsorted",
        "twice",
        "unresolved unsorted",
        "bound and unresolved",
        "other unit",
        "wrong type",
        "long identifier",
        "heuristic",
        "resolver version",
        "another generator",
        "no generator",
        "a type bound that was not verified",
        "bound with nothing verified",
        "verified types unsorted",
        "verified type twice",
        "a resolver on a binding",
        "reason",
        "state carried",
        "too many",
        "removed twice",
        "removed and unresolved",
        "negative deposed count",
        "too many deposed",
        "unknown fate",
        "no fate",
        "removed from another unit",
        "state digest",
    ],
)
def test_a_document_that_does_not_hold_together_is_refused(change: Any, message: str) -> None:
    document = copy.deepcopy(DOCUMENT)
    change(document)
    with pytest.raises(ValidationError, match=message):
        IdentityBindings.model_validate(document)
