"""Which resources of a Terraform plan configure which: read from the plan's own configuration, never guessed by name.

A resource configures another when an argument of its configuration refers to
that other resource (``bucket = aws_s3_bucket.logs.id``), within the same
module. A scanner check that reports on the configuring resource (an S3
bucket's public access block) is then about the resource it configures. Each
instance of the configuring resource configures every instance of the
referred one in the same module instance, so a result can never be credited
to a resource its configuration does not name.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from types import MappingProxyType
from typing import Any

from iltero_schemas.models.iac.scanner_addresses import split_address


def _references(node: Any) -> Iterator[str]:
    """Every reference an argument's expression, or a nested block of them, names."""
    if isinstance(node, dict):
        refs = node.get("references")
        if isinstance(refs, list):
            yield from (ref for ref in refs if isinstance(ref, str))
        for value in node.values():
            if isinstance(value, dict | list):
                yield from _references(value)
    elif isinstance(node, list):
        for value in node:
            yield from _references(value)


def _configured(module: Any, path: str) -> Iterator[tuple[str, str]]:
    """(configuring resource, referred resource) pairs of ``module``'s configuration and its calls, by their
    addresses in the configuration (``module.notify.aws_sns_topic.alerts``), without instance keys."""
    if not isinstance(module, dict):
        return
    prefix = f"{path}." if path else ""
    for resource in module.get("resources", []) or []:
        if not isinstance(resource, dict) or resource.get("mode") != "managed":
            continue
        own = f"{prefix}{resource.get('address')}"
        for ref in _references(resource.get("expressions", {})):
            parts = ref.split(".")
            if len(parts) >= 2 and not ref.startswith(("var.", "local.", "module.", "data.", "each.", "count.")):
                referred = f"{prefix}{parts[0]}.{parts[1]}"
                if referred != own:
                    yield own, referred
    for name, call in (module.get("module_calls", {}) or {}).items():
        if isinstance(call, dict):
            yield from _configured(call.get("module"), f"{prefix}module.{name}")


def _config_address(plan_address: str) -> tuple[str, str]:
    """A plan instance's address in the configuration (no instance keys), and its module instance with keys."""
    module, (kind, name) = split_address(plan_address)
    config = ".".join([*(step for step, _key in module), f"{kind}.{name}"])
    return config, ".".join(f"{step}{key}" for step, key in module)


def plan_configures(plan: object) -> Mapping[str, list[str]]:
    """For each managed resource instance of a Terraform plan (``terraform show -json``), the instances in the same
    module instance whose configuration refers to it, sorted."""
    if not isinstance(plan, dict):
        raise ValueError("is not a Terraform plan")
    configuration = plan.get("configuration")
    root = configuration.get("root_module") if isinstance(configuration, dict) else None
    pairs = set(_configured(root, ""))
    changes = plan.get("resource_changes")
    if not isinstance(changes, list):
        raise ValueError("is not a Terraform plan with a list of resource changes")
    instances: dict[tuple[str, str], list[str]] = {}
    for change in changes:
        address = change.get("address") if isinstance(change, dict) else None
        if isinstance(address, str) and change.get("mode") == "managed":
            instances.setdefault(_config_address(address), []).append(address)
    found: dict[str, set[str]] = {}
    for (config, module_instance), addresses in instances.items():
        for configuring, referred in pairs:
            if referred != config:
                continue
            for other in instances.get((configuring, module_instance), []):
                for address in addresses:
                    found.setdefault(address, set()).add(other)
    return MappingProxyType({address: sorted(others) for address, others in sorted(found.items())})
