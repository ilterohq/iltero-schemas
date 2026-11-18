from __future__ import annotations

import importlib
import pkgutil
from collections import defaultdict

from pydantic import BaseModel

import iltero_schemas


def test_no_two_models_share_a_class_name() -> None:
    # A consumer that builds a JSON Schema per model and merges them by class name would mix up two models of one name.
    defined: dict[str, set[str]] = defaultdict(set)
    for module in pkgutil.walk_packages(iltero_schemas.__path__, f"{iltero_schemas.__name__}."):
        for value in vars(importlib.import_module(module.name)).values():
            if isinstance(value, type) and issubclass(value, BaseModel) and value.__module__ == module.name:
                defined[value.__name__].add(module.name)
    assert {name: modules for name, modules in defined.items() if len(modules) > 1} == {}
