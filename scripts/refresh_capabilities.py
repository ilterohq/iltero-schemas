"""Regenerate the evaluator capabilities allowlist from the pinned OPA binary.

The allowlist is ``src/iltero_schemas/opa/capabilities.json``. Its builtin
*names* are the decision; this script rewrites their declarations from the
binary's own capability report, so a pin bump refreshes signatures without
widening the set. The binary must be the pinned release (its digest is
checked first); a name it no longer offers is an error. The builtins the
release offers that the allowlist leaves out are written to
``src/iltero_schemas/vectors/opa/not_allowed.txt``, so an upgrade shows every
new builtin as a reviewable diff and an explicit decision.

Usage: python scripts/refresh_capabilities.py OPA_BINARY [--check]

``--check`` writes nothing and fails if either file would change.
"""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

from iltero_schemas.opa import PIN, platform_key

ROOT = Path(__file__).resolve().parent.parent
CAPABILITIES = ROOT / "src" / "iltero_schemas" / "opa" / "capabilities.json"
NOT_ALLOWED = ROOT / "src" / "iltero_schemas" / "vectors" / "opa" / "not_allowed.txt"
# Language features the evaluator accepts; nothing here reaches outside the policy.
FEATURES = ["rego_v1", "keywords_in_refs"]


def report_of(opa: Path) -> dict[str, Any]:
    expected = PIN.binaries[platform_key(platform.system(), platform.machine())].sha256
    actual = hashlib.sha256(opa.read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f"{opa} is not the pinned OPA {PIN.version} (sha256 {actual})")
    run = subprocess.run(
        [str(opa), "capabilities", "--current"], capture_output=True, text=True, timeout=60, check=False
    )
    if run.returncode != 0:
        raise SystemExit(f"{opa} capabilities --current failed: {run.stderr.strip()}")
    report: dict[str, Any] = json.loads(run.stdout)
    return report


def render(allowed: list[str], report: dict[str, Any]) -> tuple[str, str]:
    offered: dict[str, dict[str, Any]] = {b["name"]: b for b in report["builtins"]}
    missing = sorted(set(allowed) - set(offered))
    if missing:
        raise SystemExit(f"the binary no longer offers: {', '.join(missing)}")
    document = {
        "builtins": [offered[name] for name in sorted(allowed)],
        "future_keywords": [],
        "features": FEATURES,
    }
    not_allowed = "".join(f"{name}\n" for name in sorted(set(offered) - set(allowed)))
    return json.dumps(document, indent=2) + "\n", not_allowed


def main(argv: list[str]) -> int:
    check = len(argv) == 3 and argv[2] == "--check"
    if len(argv) not in (2, 3) or (len(argv) == 3 and not check):
        print(__doc__, file=sys.stderr)
        return 2
    opa = Path(argv[1])
    if not opa.is_file():
        print(f"{opa}: not a file", file=sys.stderr)
        return 2
    existing = json.loads(CAPABILITIES.read_text(encoding="utf-8"))
    allowed = [b["name"] for b in existing["builtins"]]
    capabilities, not_allowed = render(allowed, report_of(opa))
    print(f"{len(allowed)} builtins allowed; {not_allowed.count(chr(10))} offered by the binary and not allowed")
    outputs = {CAPABILITIES: capabilities, NOT_ALLOWED: not_allowed}
    stale = [p for p, text in outputs.items() if not p.exists() or p.read_text(encoding="utf-8") != text]
    if check:
        for path in stale:
            print(f"out of date for this binary: {path.relative_to(ROOT)}", file=sys.stderr)
        return 1 if stale else 0
    for path in stale:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(outputs[path], encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
