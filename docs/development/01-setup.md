# Setup and checks

```bash
git clone https://github.com/ilterohq/iltero-schemas.git
cd iltero-schemas
pdm install -G dev
pdm run check
```

| Command | What it runs |
| --- | --- |
| `pdm run test` | `pytest tests` |
| `pdm run lint` | `ruff check` over `src`, `tests` and `scripts` |
| `pdm run format` | `ruff format --check` |
| `pdm run typecheck` | `mypy --strict` |
| `pdm run gate` | `scripts/check-public-surface.sh`, the pre-publication gate |
| `pdm run check` | All of the above |

## The public-surface gate

This repository is public. `scripts/check-public-surface.sh` fails on a
tracked file outside the allowlist, a credential file or binary, text that
contains a credential shape, a personal path, a cloud account id or a
design-section reference, and a document that links to a gitignored path.

The rules in the script are generic on purpose. The words that would
themselves reveal internal material are the **private patterns**: one regular
expression per line, applied to every tracked path, every file's content and
every distribution listing. Locally they live in the gitignored
`scripts/public-surface-private-patterns.txt`; in CI they come from the
`PUBLIC_SURFACE_PRIVATE_PATTERNS` repository secret, and a CI run without
them fails — except a pull request from a fork, which cannot read secrets
and runs the generic rules only.

## Conventions

- Line length 120; `ruff` rules `E, F, I, N, W, UP, S, T20, B`; imports at
  the top of the module; every function annotated.
- Every rule in the code has a named test written with the code.
- Documentation is part of the change: `docs/usage/` for consumers,
  `docs/development/` for contributors, numbered in reading order;
  `CHANGELOG.md` gets its Unreleased entry.
