"""The pins of a governed run: what the server fixed when it opened the run.

When the server opens a run, it fixes the run's **pins**: the stack and
environment, the bundle, the checks the run owes, the environment's policy and
the oldest tool version allowed. A record of the run carries them
(``CAR.pins``), and ``models.pins.check_pins`` checks that the record agrees
with them.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field, model_validator

from iltero_schemas.canonical.assertion_set import required_assertion_digest
from iltero_schemas.models.base import StrictModel
from iltero_schemas.models.bundle import MAX_BUNDLE_ASSERTIONS
from iltero_schemas.models.event import AssertionRef
from iltero_schemas.models.fields import Digest, EnvironmentKey, GateMode, Uuid, Version


class BundleRef(StrictModel):
    """The bundle a run evaluates: its content address and the digest of the signed tarball, together."""

    revision: Digest
    digest: Digest


class PolicyPin(StrictModel):
    """The environment policy the run was opened under, whether a failed check stops the pipeline, and whether the
    environment is production."""

    digest: Digest
    gate_mode: GateMode
    # The server sets it from its own record of the environment when it opens the run; a client never sets it.
    production: bool


class RunPins(StrictModel):
    """What the run was opened under."""

    stack_id: Uuid
    environment: EnvironmentKey
    bundle: BundleRef
    # The checks the run owes, sorted by id, one version of each, each named by its exact document digest.
    required_assertions: Annotated[list[AssertionRef], Field(min_length=1, max_length=MAX_BUNDLE_ASSERTIONS)]
    required_assertion_digest: Digest
    policy: PolicyPin
    # Compared as numbers, part by part: 0.10.0 is newer than 0.9.0.
    min_cli_version: Version

    @model_validator(mode="after")
    def _required_set_matches_its_digest(self) -> RunPins:
        ids = [a.id for a in self.required_assertions]
        if ids != sorted(set(ids)):
            raise ValueError("required_assertions must be sorted by id with no id twice")
        computed = required_assertion_digest((a.id, a.version, a.digest) for a in self.required_assertions)
        if self.required_assertion_digest != computed:
            raise ValueError("required_assertion_digest must be the digest of required_assertions")
        return self
