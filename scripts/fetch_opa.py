"""Download the pinned OPA release binary for this host and verify its digest.

Used by CI (and by a developer who wants to run the evaluator-backed tests)
to obtain exactly the binary the contract pins. The download lands in a
temporary file, is refused unless its SHA-256 matches ``PIN.json`` for this
platform, and only then takes its final name. Nothing here runs at
evaluation time.

Usage: python scripts/fetch_opa.py DEST_DIR   (prints the binary's path)
"""

from __future__ import annotations

import hashlib
import os
import platform
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from iltero_schemas.opa import PIN, platform_key

RELEASES = "https://github.com/open-policy-agent/opa/releases/download"
# The largest published OPA binary is well under this; anything bigger is not the release asset.
MAX_ASSET_BYTES = 256 * 1024 * 1024
ATTEMPTS = 3
RETRY_DELAY_S = 5


def _download(url: str, target: Path) -> None:
    last: Exception | None = None
    for attempt in range(ATTEMPTS):
        try:
            with urllib.request.urlopen(url, timeout=120) as response:  # noqa: S310 - fixed https host
                data = response.read(MAX_ASSET_BYTES + 1)
            if len(data) > MAX_ASSET_BYTES:
                raise SystemExit(f"{url}: larger than {MAX_ASSET_BYTES} bytes; not the release asset")
            target.write_bytes(data)
            return
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = exc
            if attempt + 1 < ATTEMPTS:
                time.sleep(RETRY_DELAY_S)
    raise SystemExit(f"{url}: download failed after {ATTEMPTS} attempts: {last}")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        key = platform_key(platform.system(), platform.machine())
    except KeyError as exc:
        print(f"no pinned OPA binary for this host: {exc}", file=sys.stderr)
        return 1
    binary = PIN.binaries[key]
    destination = Path(argv[1]) / ("opa.exe" if key.startswith("windows") else "opa")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        partial = destination.with_suffix(".part")
        _download(f"{RELEASES}/{PIN.release_tag}/{binary.asset}", partial)
        os.replace(partial, destination)
    actual = hashlib.sha256(destination.read_bytes()).hexdigest()
    if actual != binary.sha256:
        destination.unlink()
        print(f"{binary.asset}: sha256 {actual} does not match the pin {binary.sha256}; removed", file=sys.stderr)
        return 1
    destination.chmod(0o755)
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
