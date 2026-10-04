# Development: build, test, release

How `asexec` is set up, checked, built and released. The project uses
[`uv`](https://docs.astral.sh/uv/) and the `uv_build` backend; linting and formatting use
[Ruff](https://docs.astral.sh/ruff/); tests use pytest. Supported Python: 3.11 and 3.12.

## Local setup

```bash
scripts/dev-setup.sh
```

Installs `uv` if missing and runs `uv sync --all-extras --dev`. Run it once per clone, and
again after pulling dependency changes. It does not run lint or tests.

## Everyday commands

| Task | Command |
|---|---|
| Lint, format check and tests (what CI runs) | `scripts/check.sh` |
| Tests only | `uv run pytest` |
| Lint | `uv run ruff check .` |
| Format | `uv run ruff format .` |
| Run the CLI | `uv run asexec --help` |
| Build sdist + wheel into `dist/` | `uv build` |

`scripts/check.sh` runs `ruff check`, `ruff format --check` (no files modified) and
`pytest -v`. Tests are offline: the drand round is baked in as a fixture.

## Continuous integration (`.github/workflows/ci.yml`)

Runs on pushes to `main`, on pull requests, and when called by `publish.yml`. It never
publishes anything.

```
python-matrix -+
               +-> test (per Python version, plus CLI smoke) -> build
lint ----------+
```

- `python-matrix` - the single definition of the supported Python versions (JSON list).
  `test` and the release smoke both read it. To add a Python version, change it here only.
- `lint` - `ruff check` and `ruff format --check`.
- `test` - pytest on each Python version, then a CLI smoke from the source tree
  (`--version`, `keygen`, `prereg`, `verify --tests BDR`).
- `build` - `uv build`, uploaded as the `dist` artifact.

All actions are pinned by full commit SHA with a version comment, and the workflow has
`permissions: contents: read`.

## Releasing

Versions are kept in sync across `src/asexec/__init__.py`, `pyproject.toml` and the git tag
`vX.Y.Z`.

```bash
scripts/release.sh [--no-check] X.Y.Z
```

Run it from an up-to-date `main` (it refuses other branches, but does not check that `main`
is current with `origin`, so `git pull --ff-only` first). It verifies a clean tree and that
the tag doesn't exist, bumps both version declarations, runs `scripts/check.sh` unless
`--no-check`, commits `Release vX.Y.Z` (including `uv.lock` if it changed), creates an
annotated tag, and pushes the branch and tag. It does not build or upload anything; if it
fails before the release commit, the version edits are reverted.

Pushing the tag triggers `.github/workflows/publish.yml`, which publishes with PyPI Trusted
Publishing (OIDC; no tokens or repository secrets).

### Publish pipeline

```
ci -> verify-release -> publish-testpypi -> smoke-testpypi -> publish-pypi -> github-release
                                                                  ^
                                                      manual approval (pypi environment)
```

1. `ci` - reuses `ci.yml` (lint, tests, build), so the published artifact is the one that
   passed.
2. `verify-release` - tag, `pyproject.toml` and `__version__` agree; the tag is annotated
   and its commit is on `main`; `dist` holds exactly one wheel and one sdist (sha256 sums
   in the job summary).
3. `publish-testpypi` - uploads to TestPyPI (environment `testpypi`).
4. `smoke-testpypi` - installs hash-locked dependencies from PyPI, then `asexec==X.Y.Z` from
   TestPyPI with `--no-deps` (dependencies are never resolved from TestPyPI), retrying for
   about 5 minutes for index propagation. Runs the CLI smoke against the installed wheel,
   checks `asexec --version` prints the tag version, on every Python in the `ci.yml` matrix.
5. `publish-pypi` - uploads to PyPI (environment `pypi`). Required reviewers approve here,
   after the TestPyPI smoke passes.
6. `github-release` - `gh release create` with the built files and generated notes.

Each job holds only the permissions it needs (`id-token: write` for the two uploads,
`contents: write` for the release). Attestations are on by default. Runs for the same ref
are serialized and never cancelled.

If TestPyPI or the smoke test misbehaves, do not approve the `pypi` deployment. PyPI version
numbers can never be reused, so fix forward with a new version.
