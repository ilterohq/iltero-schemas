"""What a change type declares: its activities, and for each the stages a record of it passes through and its rules.

A **change type** is the kind of thing a change changes, such as infrastructure
made with an infrastructure-as-code (IaC) tool. It is made of one or more
**activities**, each one kind of work a single record describes. A record's
``change`` is the body of its activity, told apart by ``change.activity``, and
the activity's declaration says which stages such a record passes through,
which of them may be left out and by whom, which documents are owed at each,
and the rules that compare the body with the record's stages and events.

Every declaration is data a reader can read without calling a rule, except the
rules themselves.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from iltero_schemas.models.assertion import Stage
from iltero_schemas.models.change_type import ActivityName, ChangeTypeName
from iltero_schemas.models.checked_content import CheckedContent

if TYPE_CHECKING:
    from iltero_schemas.models.car import CAR

# The type of the run that records an activity: ``change``, a run that changes a project's unit in an environment;
# ``build``, a run that builds an artifact, in no environment.
RunType = Literal["change", "build"]
# A document a stage owes: the record itself, the identity document that lists the deployed resources, or the raw
# index of a container image built for several platforms. Every other file a record names stays in the pipeline's own
# store; the record keeps its digest.
DocumentName = Literal["record", "identity_document", "image_index"]


@dataclass(frozen=True)
class Activity:
    """One activity of a change type: the stages its records pass through, what they owe, and its rules."""

    name: ActivityName
    change_type: ChangeTypeName
    run_type: RunType
    # The stages a record of this activity accounts for, in the order they run. The first is where it starts.
    stages: tuple[Stage, ...]
    # The stages a project's configuration may leave out of a record.
    project_may_leave_out: frozenset[Stage]
    # The stages the policy of the environment a server opened the run for may leave out of a record.
    environment_policy_may_leave_out: frozenset[Stage]
    # The stages a record may call not supported: those its tool or its target cannot run, such as the post-verify
    # stage of an IaC tool whose drift no pipeline reads back. Any other stage is expected, or left out by a project or
    # a policy.
    not_supported: Callable[[CAR], frozenset[Stage]]
    # The documents a run uploads to the server for each stage, which the server counts as owed: the record, and
    # after the deployment the identity document, the file that lists the deployed resources by their cloud ids.
    required_documents: Mapping[Stage, tuple[DocumentName, ...]]
    # The documents a stage owes only because the record's change names them, by stage and document, each by its name
    # in the record's evidence register: for a build, its raw index.
    named_documents: Callable[[CAR], Mapping[Stage, Mapping[DocumentName, tuple[str, ...]]]]
    # The built-in assertion that ties the record's evaluations to its checked content, by its id, and the stage it is
    # evaluated at. No policy excludes it.
    binding_check: tuple[str, Stage]
    # Every built-in assertion a record of this activity evaluates, by the stage it belongs to: once that stage has
    # reported, it evaluated the assertion once, and found it applies. The binding check is one of them.
    always_evaluated: Mapping[Stage, str]
    # The content the record's change checked, which every event of the record names.
    checked_content: Callable[[CAR], CheckedContent]
    # Raise ``ValueError`` unless the change's body holds together with the record's stages.
    check_record: Callable[[CAR], None]
    # The values of the body a reader can recompute that are bound to the change digest, and are not what they
    # recompute to, as (where, what) pairs; the change digest itself first.
    change_digest_problems: Callable[[CAR], list[tuple[str, str]]]
    # Every other value of the body a reader can recompute that is not what it recomputes to.
    integrity_problems: Callable[[CAR], list[tuple[str, str]]]


@dataclass(frozen=True)
class ChangeType:
    """A change type and the activities it is made of."""

    name: ChangeTypeName
    activities: tuple[Activity, ...]
