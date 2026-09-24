"""The evaluator's builtin allowlist.

``CAPABILITIES`` is the OPA capabilities file every evaluation runs under: the
builtins a policy may call, enumerated from an empty set for the pinned
release, with nothing that reaches the network, the clock, randomness or the
host. A consumer passes the bytes to ``opa build --capabilities`` and
``opa eval --capabilities`` and records ``CAPABILITIES_DIGEST`` with every
evaluation. ``capabilities.json`` next to this module is the only place the
allowlist is written down.
"""

from __future__ import annotations

from importlib import resources

from iltero_schemas.canonical import digest

CAPABILITIES: bytes = resources.files("iltero_schemas.opa").joinpath("capabilities.json").read_bytes()
CAPABILITIES_DIGEST: str = digest(CAPABILITIES)
