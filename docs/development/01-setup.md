# Setup and checks

This page shows how to get a working copy of the package and run the same
checks CI runs. Run them before you open a pull request.

```bash
git clone https://github.com/ilterohq/iltero-schemas.git
cd iltero-schemas
pdm install -G dev --no-isolation
pdm run check
```

`--no-isolation` makes the project's own editable install use the build tools
from the lock file. Each of those tools is pinned by hash, as in CI.

| Command | What it runs |
| --- | --- |
| `pdm run test` | `pytest tests` |
| `pdm run lint` | `ruff check` over `src`, `tests` and `scripts` |
| `pdm run format` | `ruff format --check` over `src`, `tests` and `scripts` |
| `pdm run typecheck` | `mypy` in strict mode over `src`, `tests` and `scripts` |
| `pdm run gate` | `scripts/check-public-surface.sh`, the public-surface gate |
| `pdm run check` | All of the above |

## The public-surface gate

This repository is public. A script, the **public-surface gate**, checks what
would be published and fails when it finds any of these:

- A tracked file outside the path allowlist. The path allowlist is the
  list of folders and files the repository may publish, such as `src/`,
  `docs/` and `README.md`.
- A credential file or a binary.
- Text that contains a credential shape, a personal path, a cloud account id
  or a reference to an internal design section.
- A document that links to a gitignored path.

The rules in the script are generic on purpose. The words that would
themselves reveal internal material are kept apart, as **private patterns**.
Each line of that list is one regular expression. The gate applies each
pattern to every tracked path, to every file's content and to every listing
of the built distributions.

- Locally, the patterns live in the gitignored file
  `scripts/public-surface-private-patterns.txt`.
- In CI, they come from the `PUBLIC_SURFACE_PRIVATE_PATTERNS` repository
  secret. A CI run without them fails.
- A pull request from a fork is the one exception. It cannot read secrets,
  so it runs the generic rules only.

A second list, the token allowlist, holds test values that look like a
credential or an account id but are not real. The gate lets each listed
value pass the generic rules. It accepts a value only if it is a constant in
a tracked file under `src/` or `tests/`.

### For developers

| What | Where |
| --- | --- |
| The gate, with its path allowlist | `scripts/check-public-surface.sh` |
| The token allowlist | `scripts/public-surface-allowlist.txt` |

## Conventions

- Lines are at most 120 characters long.
- `ruff` checks the rule sets `E`, `F`, `I`, `N`, `W`, `UP`, `S`, `T20` and
  `B`.
- Imports go at the top of the module, and every function is annotated.
- Every rule in the code has a named test, written with the code.
- Documentation is part of the change. `docs/usage/` is for consumers and
  `docs/development/` is for contributors. Pages are numbered in reading
  order. `CHANGELOG.md` gets its Unreleased entry.
