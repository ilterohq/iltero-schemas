"""Marks and anchors from what a Terraform or OpenTofu plan writes (``terraform show -json``).

The plan writes, beside a tree of values, a tree of booleans shaped like it (``after_sensitive``, ``after_unknown``,
``sensitive_values``): ``true`` at a path flags the value there and everything under it. Its configuration says which
variables and outputs are sensitive, and holds provider and provisioner settings, which are hidden whatever they look
like. ``plan_marks_and_anchors`` reads all of these into marks, and gives the anchors where each resource's values
start, so a policy's configured paths apply under each, and where each value the tool declared sensitive as a whole
starts (an output's, a root variable's), so every string inside one is hidden wherever else it appears. It reads a plan
as the tool wrote it or as redaction left it: redaction keeps every flag, key and address it does not hide, so a
redacted plan gives the same anchors and the same marks, except those under a value redaction hid whole. A section of
the wrong shape is read as absent, but a resource with no ``sensitive_values``, or with one that holds anything but
objects, lists and booleans, is refused: the tool writes it for every resource, so a missing or misread flag would
leave a sensitive value unmarked.

``state_marks_and_anchors`` reads a state as ``terraform show -json`` prints it the same way, with the walk a plan's
``prior_state`` gets. A state is read only in the shape the tool writes: any other is refused. The plan's reader stays
lenient about the sections it does not mark from, as a kept plan is read again by every reader of its record; the
state's reader is strict, since the record keeps no copy of the state for a reader to look at.
"""

from __future__ import annotations

import re
from typing import Any

from iltero_schemas.models.iac.tools.terraform import configured_address, configured_modules
from iltero_schemas.redaction.common.apply import RedactionError
from iltero_schemas.redaction.common.marks import Mark, MarkReason
from iltero_schemas.redaction.common.paths import TreePath, dotted
from iltero_schemas.redaction.common.words import key_is_shaped_like_a_credential

# What a plan's flags say of a value the tool declared sensitive.
SENSITIVE: MarkReason = "declared_sensitive"
# The keys a state holds at its top level, and under its ``values``.
# ``checks`` holds the results of the configuration's checks: accepted with any value, and never read.
STATE_KEYS = frozenset({"format_version", "terraform_version", "values", "checks"})
STATE_VALUES_KEYS = frozenset({"root_module", "outputs"})
# An unknown key a refusal may name: letters, digits and ``_``, at most 64 characters.
PLAIN_KEY = re.compile(r"[A-Za-z0-9_]{1,64}")


def marks_from_flags(flags: Any, prefix: TreePath, reason: MarkReason, *, declared_sensitive: bool) -> list[Mark]:
    """Marks for a tree of booleans shaped like the value tree: ``true`` marks that path and everything under it."""
    if flags is True:
        return [Mark(prefix, reason, declared_sensitive)]
    if isinstance(flags, dict):
        return [
            mark
            for key, child in flags.items()
            for mark in marks_from_flags(child, (*prefix, key), reason, declared_sensitive=declared_sensitive)
        ]
    if isinstance(flags, list):
        return [
            mark
            for index, child in enumerate(flags)
            for mark in marks_from_flags(child, (*prefix, index), reason, declared_sensitive=declared_sensitive)
        ]
    return []


def _mapping(value: Any) -> dict[str, Any]:
    """A JSON object, or nothing: a plan section of the wrong shape is read as absent."""
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _declared(path: TreePath) -> Mark:
    """A mark for a value the tool itself declared sensitive."""
    return Mark(path, SENSITIVE, declared_sensitive=True)


def _any_true(flags: Any) -> bool:
    """Whether a tree of flags marks anything."""
    if flags is True:
        return True
    children = flags.values() if isinstance(flags, dict) else flags if isinstance(flags, list) else ()
    return any(_any_true(child) for child in children)


def _flag_marks(change: dict[str, Any], prefix: TreePath) -> list[Mark]:
    """The marks a change's own flags put on its ``before`` and ``after``."""
    return (
        marks_from_flags(change.get("before_sensitive"), (*prefix, "before"), SENSITIVE, declared_sensitive=True)
        + marks_from_flags(change.get("after_sensitive"), (*prefix, "after"), SENSITIVE, declared_sensitive=True)
        + marks_from_flags(
            change.get("after_unknown"), (*prefix, "after"), "known_after_deploy", declared_sensitive=False
        )
    )


def _refuse_flags_of_another_shape(flags: Any, where: str) -> None:
    """Raise ``RedactionError`` unless ``flags``, a resource's ``sensitive_values``, holds only objects, lists and
    booleans. Walked without recursion, so a deep tree is read to its end."""
    pending = [flags]
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
        elif not isinstance(node, bool):
            raise RedactionError(
                f"the sensitive values of the resource at {where} hold only objects, lists and booleans"
            )


def _values_marks(module: Any, prefix: TreePath, marks: list[Mark], anchors: list[TreePath]) -> None:
    """Marks and anchors for a ``planned_values``, ``prior_state`` or state module tree, child modules included.
    Raises ``RedactionError`` for a resource that names no ``sensitive_values``, or one that holds anything but objects,
    lists and booleans."""
    module = _mapping(module)
    for index, resource in enumerate(_list(module.get("resources"))):
        if isinstance(resource, dict):
            if "sensitive_values" not in resource:
                where = dotted((*prefix, "resources", index))
                raise RedactionError(
                    f"every resource names its sensitive values, as the tool writes them; the resource at {where} "
                    "names none"
                )
            _refuse_flags_of_another_shape(resource["sensitive_values"], dotted((*prefix, "resources", index)))
            values: TreePath = (*prefix, "resources", index, "values")
            marks.extend(marks_from_flags(resource["sensitive_values"], values, SENSITIVE, declared_sensitive=True))
            anchors.append(values)
    for index, child in enumerate(_list(module.get("child_modules"))):
        _values_marks(child, (*prefix, "child_modules", index), marks, anchors)


def _output_marks(outputs: Any, prefix: TreePath, marks: list[Mark], anchors: list[TreePath]) -> None:
    """A mark and an anchor at the value of each output the tool declared sensitive, under ``prefix``."""
    for name, output in _mapping(outputs).items():
        if _mapping(output).get("sensitive") is True:
            value: TreePath = (*prefix, name, "value")
            marks.append(_declared(value))
            anchors.append(value)


def _changes(document: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Each resource change the plan lists with an address as text, by its address and its change."""
    entries = (_mapping(entry) for entry in _list(document.get("resource_changes")))
    return [
        (entry["address"], _mapping(entry.get("change"))) for entry in entries if isinstance(entry.get("address"), str)
    ]


def _sensitive_attributes(changes: list[tuple[str, dict[str, Any]]]) -> dict[str, set[str]]:
    """Per configured address, the attribute names the tool flags sensitive (anywhere inside) in any instance."""
    names: dict[str, set[str]] = {}
    for address, change in changes:
        flagged = names.setdefault(configured_address(address), set())
        for tree in (change.get("before_sensitive"), change.get("after_sensitive")):
            flagged.update(key for key, flag in _mapping(tree).items() if _any_true(flag))
    return names


def _configuration_marks(
    document: dict[str, Any], changes: list[tuple[str, dict[str, Any]]], marks: list[Mark], anchors: list[TreePath]
) -> None:
    """Marks over the configuration block: sensitive variable defaults, module inputs, flagged constants, providers;
    and an anchor at the value of each sensitive root variable."""
    configuration = _mapping(document.get("configuration"))
    for name, provider in _mapping(configuration.get("provider_config")).items():
        for attribute in _mapping(_mapping(provider).get("expressions")):
            marks.append(
                Mark(
                    ("configuration", "provider_config", name, "expressions", attribute),
                    "provider_configuration",
                    declared_sensitive=False,
                )
            )
    flagged = _sensitive_attributes(changes)
    planned = {configured_address(address) for address, _change in changes}
    root: TreePath = ("configuration", "root_module")
    for prefix, module in configured_modules(configuration).items():
        path = root
        for name in prefix[:-1].split(".module.") if prefix else []:
            path = (*path, "module_calls", name.removeprefix("module."), "module")
        for name, variable in _mapping(module.get("variables")).items():
            if _mapping(variable).get("sensitive") is True:
                marks.append(_declared((*path, "variables", name, "default")))
                if prefix == "":
                    marks.append(_declared(("variables", name, "value")))
                    anchors.append(("variables", name, "value"))
        for name, output in _mapping(module.get("outputs")).items():
            if _mapping(output).get("sensitive") is True:
                marks.append(_declared((*path, "outputs", name, "expression")))
        for index, resource in enumerate(_list(module.get("resources"))):
            resource = _mapping(resource)
            address = f"{prefix}{resource.get('address')}"
            expressions = _mapping(resource.get("expressions"))
            here: TreePath = (*path, "resources", index)
            for attribute in flagged.get(address, ()):
                if attribute in expressions:
                    marks.append(_declared((*here, "expressions", attribute)))
            # A configured resource with no instance in the plan (``count = 0``, left out by ``-target``) has no flags
            # to say which of its values are sensitive: every one is hidden.
            if address not in planned:
                marks.extend(
                    Mark((*here, "expressions", attribute), "unplanned_configuration", declared_sensitive=False)
                    for attribute in expressions
                )
            for position, provisioner in enumerate(_list(resource.get("provisioners"))):
                if "expressions" in _mapping(provisioner):
                    marks.append(
                        Mark(
                            (*here, "provisioners", position, "expressions"),
                            "provisioner_configuration",
                            declared_sensitive=False,
                        )
                    )
        for name, call in _mapping(module.get("module_calls")).items():
            child = _mapping(_mapping(call).get("module"))
            for variable, declared in _mapping(child.get("variables")).items():
                if _mapping(declared).get("sensitive") is True:
                    marks.append(_declared((*path, "module_calls", name, "expressions", variable)))


def plan_marks_and_anchors(document: Any) -> tuple[list[Mark], list[TreePath]]:
    """Marks and anchors over a whole plan: every place the tool flags a value as sensitive or unknown, every setting
    hidden whatever it looks like, and where each resource's values start."""
    document = _mapping(document)
    marks: list[Mark] = []
    anchors: list[TreePath] = []
    for key in ("resource_changes", "resource_drift"):
        for index, entry in enumerate(_list(document.get(key))):
            prefix: TreePath = (key, index, "change")
            marks += _flag_marks(_mapping(_mapping(entry).get("change")), prefix)
            anchors += [(*prefix, "before"), (*prefix, "after")]
    for index, entry in enumerate(_list(document.get("deferred_changes"))):
        prefix = ("deferred_changes", index, "resource_change", "change")
        marks += _flag_marks(_mapping(_mapping(_mapping(entry).get("resource_change")).get("change")), prefix)
        anchors += [(*prefix, "before"), (*prefix, "after")]
    for index, invocation in enumerate(_list(document.get("action_invocations"))):
        config: TreePath = ("action_invocations", index, "config_values")
        marks += marks_from_flags(
            _mapping(invocation).get("config_sensitive"), config, SENSITIVE, declared_sensitive=True
        )
        marks += marks_from_flags(
            _mapping(invocation).get("config_unknown"), config, "known_after_deploy", declared_sensitive=False
        )
        anchors.append(config)
    for name, output in _mapping(document.get("output_changes")).items():
        output = _mapping(output)
        marks += _flag_marks(output, ("output_changes", name))
        # An output's value the tool flags sensitive, whole or in part, is where a sensitive value starts.
        for side in ("before", "after"):
            if _any_true(output.get(f"{side}_sensitive")):
                anchors.append(("output_changes", name, side))
    for holder_key, base in (("planned_values", ("planned_values",)), ("prior_state", ("prior_state", "values"))):
        values = _mapping(document.get(holder_key))
        if holder_key == "prior_state":
            values = _mapping(values.get("values"))
        _values_marks(values.get("root_module"), (*base, "root_module"), marks, anchors)
        _output_marks(values.get("outputs"), (*base, "outputs"), marks, anchors)
    _configuration_marks(document, _changes(document), marks, anchors)
    return marks, anchors


def _refuse_a_module_of_another_shape(root: Any) -> None:
    """Raise ``RedactionError`` unless the state's ``root_module`` has the shape the tool writes: an object whose
    ``resources`` is a list of objects, and whose ``child_modules`` is a list of modules of the same shape. Walked
    without recursion, so a deep tree of modules is read to its end."""
    pending: list[tuple[Any, TreePath]] = [(root, ("values", "root_module"))]
    while pending:
        module, prefix = pending.pop()
        where = dotted(prefix)
        if not isinstance(module, dict):
            raise RedactionError(f"the module at {where} of the state is an object")
        resources = module.get("resources", [])
        if not isinstance(resources, list) or not all(isinstance(resource, dict) for resource in resources):
            raise RedactionError(f"the resources of the module at {where} of the state are a list of objects")
        children = module.get("child_modules", [])
        if not isinstance(children, list):
            raise RedactionError(f"the child modules of the module at {where} of the state are a list")
        pending.extend((child, (*prefix, "child_modules", index)) for index, child in enumerate(children))


def _named(lead: str, key: str) -> str:
    """``; <lead> <key>`` to end a refusal that names an unknown key, when the key is a short plain identifier no rule
    would take for a credential; nothing otherwise, so a refusal never repeats a value-like key."""
    if PLAIN_KEY.fullmatch(key) and not key_is_shaped_like_a_credential(key):
        return f"; {lead} {key}"
    return ""


def _refuse_a_state_of_another_shape(document: Any) -> None:
    """Raise ``RedactionError`` unless ``document`` has the shape of a state ``terraform show -json`` prints. A state
    with no ``values``, or no ``terraform_version``, holds nothing and is read as empty."""
    if not isinstance(document, dict):
        raise RedactionError("a state is a JSON object")
    unknown = sorted(set(document) - STATE_KEYS)
    if unknown:
        raise RedactionError(
            "a state holds no top-level key other than format_version, terraform_version, values and checks"
            + _named("it holds", unknown[0])
        )
    values = document.get("values", {})
    if not isinstance(values, dict):
        raise RedactionError("the values of a state are an object")
    unknown = sorted(set(values) - STATE_VALUES_KEYS)
    if unknown:
        raise RedactionError(
            "the values of a state hold no key other than root_module and outputs" + _named("they hold", unknown[0])
        )
    outputs = values.get("outputs", {})
    if not isinstance(outputs, dict) or not all(isinstance(output, dict) for output in outputs.values()):
        raise RedactionError("the outputs of a state are an object of outputs, each an object")
    if not all(isinstance(output.get("sensitive"), bool) for output in outputs.values()):
        raise RedactionError("every output of a state says whether it is sensitive, true or false")
    if "root_module" in values:
        _refuse_a_module_of_another_shape(values["root_module"])


def state_marks_and_anchors(document: Any) -> tuple[list[Mark], list[TreePath]]:
    """Marks and anchors over a state as ``terraform show -json`` prints it: each resource's ``sensitive_values`` over
    its ``values``, child modules and deposed objects included, and each output the tool declared sensitive. Raises
    ``RedactionError`` for a state of another shape, with a resource that names no ``sensitive_values``, or nested
    deeper than the reader's walk reads."""
    _refuse_a_state_of_another_shape(document)
    marks: list[Mark] = []
    anchors: list[TreePath] = []
    values = document.get("values", {})
    try:
        _values_marks(values.get("root_module"), ("values", "root_module"), marks, anchors)
    except RecursionError as error:
        raise RedactionError("the state nests deeper than its reader reads") from error
    _output_marks(values.get("outputs"), ("values", "outputs"), marks, anchors)
    return marks, anchors
