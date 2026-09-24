"""Shared fixtures: the vector directories and the pinned evaluator when present.

The evaluator is found through ``ILTERO_OPA_PATH`` or ``opa`` on ``PATH``
and is used only if its digest matches the pin for this platform; a
different binary is an error. An absent one skips the tests that need it,
unless ``ILTERO_OPA_REQUIRED=1`` (set in CI), in which case it is a failure.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
from pathlib import Path
from typing import Any

import pytest

from iltero_schemas.opa import PIN, platform_key

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "src" / "iltero_schemas" / "vectors"
STARTER_ASSERTIONS = ROOT / "src" / "iltero_schemas" / "assertions"
POST_DEPLOY: dict[str, Any] = json.loads((VECTORS / "contexts" / "post_deploy.json").read_text(encoding="utf-8"))

# Cloud identifiers are built from parts, so no tracked line holds one.
PARTITION = "aws"
ACCOUNT = "0" * 11 + "1"
REGION = "eu-west-1"


def arn(service: str, region: str, account: str, resource: str, partition: str = PARTITION) -> str:
    return ":".join(("arn", partition, service, region, account, resource))


# One valid ARN per resource type the contract knows.
ARNS: dict[str, str] = {
    "s3_bucket": arn("s3", "", "", "logs-bucket"),
    "rds_instance": arn("rds", REGION, ACCOUNT, "db:payments"),
    "security_group": arn("ec2", REGION, ACCOUNT, "security-group/sg-0123456789abcdef0"),
    "iam_role": arn("iam", "", ACCOUNT, "role/service/deployer"),
    "kms_key": arn("kms", REGION, ACCOUNT, "key/1234abcd-12ab-34cd-56ef-1234567890ab"),
}


def binding(address: str, resource_type: str = "rds_instance", unit: str = "root") -> dict[str, Any]:
    """An identity binding of ``address`` to the stand-in ARN of ``resource_type``."""
    return {
        "terraform": {"unit": unit, "address": address},
        "cloud": {
            "provider": "aws",
            "resource_type": resource_type,
            "primary": {"scheme": "aws_arn", "value": ARNS[resource_type]},
        },
        "authority": "authoritative",
    }


def _candidate() -> Path | None:
    override = os.environ.get("ILTERO_OPA_PATH")
    if override:
        return Path(override)
    found = shutil.which("opa")
    return Path(found) if found else None


@pytest.fixture(scope="session")
def opa() -> Path:
    """The pinned evaluator, or a skip when none is available."""
    binary = _candidate()
    if binary is None:
        if os.environ.get("ILTERO_OPA_REQUIRED") == "1":
            pytest.fail("ILTERO_OPA_REQUIRED=1 but no pinned opa is available: set ILTERO_OPA_PATH")
        pytest.skip("pinned opa not available: set ILTERO_OPA_PATH")
    expected = PIN.binaries[platform_key(platform.system(), platform.machine())].sha256
    actual = hashlib.sha256(binary.read_bytes()).hexdigest()
    if actual != expected:
        pytest.fail(f"{binary} is not the pinned opa release {PIN.version} (sha256 {actual})")
    return binary


STATE_DIGEST = "sha256:" + "5" * 64
PLAN_DIGEST = "sha256:" + "6" * 64


def identity_record(**fields: Any) -> dict[str, Any]:
    """An identity record of one state and applied plan, with nothing listed unless ``fields`` says so."""
    record: dict[str, Any] = {
        "sources": {
            "state": {"digest": STATE_DIGEST, "terraform_version": "1.14.0"},
            "plan": {"digest": PLAN_DIGEST, "digest_version": "1"},
        },
        "resolver": {"name": "aws", "version": "1.0.0", "verified": sorted(ARNS)},
        "bindings": [],
        "unresolved": [],
        "removed": [],
        "removed_unresolved": [],
        "deposed_objects": 0,
        "deposed_destroyed": 0,
    }
    return {**record, **fields}


def removed(address: str, resource_type: str = "rds_instance", fate: str = "deleted") -> dict[str, Any]:
    """A binding of an object that left the state, and how it left."""
    return {**binding(address, resource_type), "fate": fate}


def change(address: str, action: str, required: list[str], outcome: str, **fields: Any) -> dict[str, Any]:
    """One change of an applied plan, neither renamed nor imported unless ``fields`` says so.

    What completed follows from the outcome unless ``fields`` names it: all of it when applied, nothing
    when never attempted or needing nothing; an errored change must say.
    """
    completed = sorted(required) if outcome == "applied" else []
    entry = {"address": address, "action": action, "required": required, "basis": "log"}
    return {**entry, "completed": completed, "outcome": outcome, "moved_from": None, "imported": False, **fields}
