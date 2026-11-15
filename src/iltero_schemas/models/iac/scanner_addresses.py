"""How a scanner's resource address resolves to an address of the plan the stage evaluated.

A result decides nothing about a resource unless its address names exactly one
resource of that plan. Each tool writes addresses its own way, and the rule for
each is exact, never a guess by name:

* Checkov writes the plan's own address (``module.db.aws_db_instance.main``), so
  its address resolves when the plan has that address.
* Trivy writes the resource's type and name without its instance key, and for a
  resource inside a module adds ``_`` and the MD5 digest of the module path
  (``aws_db_instance.main_<md5 of "module.db">``). Its address resolves when exactly
  one resource of the plan is written that way; resources made by ``count`` or
  ``for_each`` share one Trivy address, so a result about one of them is
  ``ambiguous``.

An address that names no resource of the plan is ``not_in_plan``. The addresses
a result is resolved against are every managed resource instance of the plan,
whatever its action (``plan_resource_addresses``): a list that left one out could
let a Trivy address name the one that remained.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterable, Mapping
from types import MappingProxyType

from iltero_schemas.models.iac.scanner_observations import UnresolvedReason

# One step of a Terraform address: a name, then an optional instance key ``[0]`` or ``["a.b"]``.
_STEP = re.compile(r'([A-Za-z0-9_-]+)(\[(?:[0-9]+|"(?:[^"\\]|\\.)*")\])?')


def _steps(address: str) -> list[tuple[str, str]]:
    """The steps of ``address`` as (name, instance key) pairs; ``ValueError`` for text that is not an address."""
    steps, position = [], 0
    while True:
        match = _STEP.match(address, position)
        if match is None:
            raise ValueError("is not a Terraform resource address")
        steps.append((match.group(1), match.group(2) or ""))
        position = match.end()
        if position == len(address):
            return steps
        if address[position] != ".":
            raise ValueError("is not a Terraform resource address")
        position += 1


def split_address(plan_address: str) -> tuple[list[tuple[str, str]], tuple[str, str]]:
    """A managed resource address as its module path, as (``module``, name with instance key) steps, and its type and
    name; ``ValueError`` for text that is not one."""
    steps = _steps(plan_address)
    if len(steps) < 2 or len(steps) % 2:
        raise ValueError("is not a Terraform managed resource address")
    module, resource = steps[:-2], steps[-2:]
    # A module path is ``module.NAME`` steps, each name with its instance key if any; the resource is ``TYPE.NAME``.
    module_steps_valid = all(
        (name == "module") == (number % 2 == 0) and not (key and number % 2 == 0)
        for number, (name, key) in enumerate(module)
    )
    if resource[0][0] == "module" or resource[0][1] or not module_steps_valid:
        raise ValueError("is not a Terraform managed resource address")
    return module, (resource[0][0], resource[1][0])


def trivy_address(plan_address: str) -> str:
    """How Trivy writes the managed resource at ``plan_address``."""
    module, (kind, name) = split_address(plan_address)
    written = f"{kind}.{name}"
    if not module:
        return written
    path = ".".join(f"{name}{key}" for name, key in module)
    return f"{written}_{hashlib.md5(path.encode('utf-8'), usedforsecurity=False).hexdigest()}"


def plan_resource_addresses(plan: object) -> list[str]:
    """Every managed resource instance a Terraform plan (``terraform show -json``) lists, whatever its action,
    sorted."""
    changes = plan.get("resource_changes") if isinstance(plan, dict) else None
    if not isinstance(changes, list):
        raise ValueError("is not a Terraform plan with a list of resource changes")
    addresses = {
        change["address"]
        for change in changes
        if isinstance(change, dict) and change.get("mode") == "managed" and isinstance(change.get("address"), str)
    }
    return sorted(addresses)


# How each tool writes the address of one resource of a plan.
_WRITERS: Mapping[str, Callable[[str], str]] = MappingProxyType(
    {"checkov": lambda address: address, "trivy": trivy_address}
)


def written_address(tool: str, plan_address: str) -> str:
    """The address ``tool`` writes for the resource at ``plan_address``."""
    return _WRITERS[tool](plan_address)


def address_index(tool: str, plan_addresses: Iterable[str]) -> Mapping[str, str | None]:
    """Each address ``tool`` may write for a resource of the plan, and the plan address it names, or None when it
    could name more than one."""
    index: dict[str, str | None] = {}
    for address in plan_addresses:
        written = written_address(tool, address)
        index[written] = None if written in index else address
    return MappingProxyType(index)


def resolve(index: Mapping[str, str | None], scanner_address: str | None) -> tuple[str | None, UnresolvedReason | None]:
    """The plan address ``scanner_address`` resolves to under ``index``, or None with the reason it resolves to none."""
    if scanner_address is None:
        return None, "no_address"
    if scanner_address not in index:
        return None, "not_in_plan"
    plan_address = index[scanner_address]
    return (plan_address, None) if plan_address is not None else (None, "ambiguous")
