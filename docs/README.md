# iltero-schemas documentation

**Using the contract** — `docs/usage/`

- [The OPA pin](usage/01-opa-pin.md) — what `PIN` is, how a consumer verifies an evaluator, how the pin changes

**Developing the contract** — `docs/development/`

- [Setup and checks](development/01-setup.md) — PDM, `pdm run check`, the public-surface gate
- [Versioning](development/02-versioning.md) — exact pins, what counts as a breaking change

Every change that alters behaviour updates the page that describes it, in the
same pull request. `CHANGELOG.md` at the repository root lists what changed per
release.
