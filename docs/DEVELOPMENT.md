# Development: build, test, release

How `asexec` is set up, checked, built and released. The project uses
[`uv`](https://docs.astral.sh/uv/) and the `uv_build` backend; linting and formatting use
[Ruff](https://docs.astral.sh/ruff/); tests use pytest. Supported Python: 3.12 through 3.14; CI tests each of them.

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

## Verifier architecture

- [`docs/VERIFICATION.md`](./docs/VERIFICATION.md) is the contract. A model decides whether
  one slice of JSON is well-formed; the verifier decides everything else, including every
  verdict. Each *structural* requirement (types, shapes, literals, hex, pinned constants)
  is a field on a strict pydantic input model in `models.py` (shared field types in
  `fields.py`). Cryptographic, filesystem and cross-manifest checks stay as code that runs
  on the parsed models. A model never returns PASS or FAIL: it parses or raises, and the
  verifier turns that into a FAIL. Malformed input is never an exception.
- Input models are `strict` and `extra="allow"`, so a future field never breaks offline
  verification, and read `null` as absent. Where a writer model describes the same slice, it
  subclasses the input model, forbids extra fields and rejects `None`, so a shape is
  written once.
- `tests/verify/` is a black-box contract test of `VERIFICATION.md`: it calls
  `verify_paths` or the CLI and never imports the input models. Valid inputs come from the
  production writer; invalid ones are written as dotted property paths in the doc's
  notation (`scenario.set(name, "body.anchor.floor.round", "1000")` for a field of the
  decoded body, re-encoded and signed; `scenario.set(name, "dsse.signatures[0].keyid", …)`
  or `"pubkey"` for the file around it), never built with the models, so a wrong model
  cannot produce a matching wrong input. A coverage test requires a failing
  test (`test_<name>__fail__<n>_...`) for every numbered requirement in the doc.

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
  (`--version`, `keygen`, `prereg` with two file subjects, `verify --tests
  format,selfsig,content --artifacts .`).
- `build` - `uv build`, uploaded as the `dist` artifact.

All actions are pinned by full commit SHA with a version comment, and the workflow has
`permissions: contents: read`.

## Releasing

Versions are kept in sync across `src/asexec/__init__.py`, `pyproject.toml` and the git tag
`vX.Y.Z` (or `vX.Y.ZbN` for a beta).

```bash
scripts/release.sh [--no-check] X.Y.Z
scripts/release.sh [--no-check] X.Y.ZbN
```

The version is `X.Y.Z` or a PEP 440 beta `X.Y.ZbN`, in normalized form (no leading zeros, so
the tag matches the built file names). Alphas, release candidates, `.devN`, `.postN`, `X.Y`
and a leading `v` are refused.

Run it from an up-to-date `main` (it refuses other branches, but does not check that `main`
is current with `origin`, so `git pull --ff-only` first). It verifies a clean tree and that
the tag doesn't exist, bumps both version declarations, sets the `payloadType` (below), runs
`scripts/check.sh` unless `--no-check`, commits `Release vX.Y.Z` (including `uv.lock` if it
changed), creates an annotated tag, and pushes the branch and tag. It does not build or
upload anything. If it fails before the release commit, it restores every file it edited:
both version declarations, `uv.lock`, `src/asexec/constants.py` and
`tests/test_constants.py`.

### The `payloadType` a release writes

Each release commit sets the format that release signs. `scripts/release.sh` is the
sanctioned way to change the `MANIFEST_PAYLOAD_TYPE` literal; otherwise the pinning rule in
`tests/test_constants.py` stands. It rewrites the literal in `src/asexec/constants.py` and
the one pinned line in `tests/test_constants.py`
(`assert constants.MANIFEST_PAYLOAD_TYPE == "..."`), and each rewrite must match exactly one
line or the release stops.

- **A beta** writes `application/vnd.asexec.X.Y.ZbN+json`, under the `FORMATS` entry under
  development. That entry is keyed by the name `MANIFEST_PAYLOAD_TYPE`, so its key moves with
  the literal, and the script refuses a beta if there isn't exactly one such entry. A beta is
  of a line's first release (`X.Y.0bN`); `0.4.1b1` is refused. The script does not check that
  a version comes after the last one released.
- **A full release** writes its release line's format, from `RELEASE_PAYLOAD_TYPES` in the
  script: `0.4` → `application/vnd.asexec.v1+json`, so `0.4.0` and its patches write `v1`.
  A full release of a line with no entry (`0.5.0`, say) is refused: add the line once its
  format is decided ([`MULTIVERSION.md`](./MULTIVERSION.md)).
- **The first full release of a line (`X.Y.0`) releases the entry under development**: the
  release commit rewrites its key from the name to the literal (`0.4.0` makes it
  `"application/vnd.asexec.v1+json"`). That key never changes again, so no later release
  commit can re-key the released `v1` entry. It refuses if an entry is already keyed by
  that literal. A later release of the line (`0.4.1`) requires the literal key, and refuses
  if an entry keyed by the name exists, since it would share the key.

**Main keeps the type the last release commit set**, until the next release commit. There is
no revert commit. After `0.4.0b1`, main signs with `application/vnd.asexec.0.4.0b1+json`, so
nothing on main writes the `v1` label before `0.4.0`. Format changes made between betas still
carry the last beta's label. That is harmless: betas are not supported, and main is not
published.

**The frozen vectors** in `tests/test_constants.py` are `v1` files, signed once and never
edited. A `0.4.0` beta build reads only its own beta type, so every test that reads them is
skipped there (the `frozen_v1` mark, reason "a 0.4.0 beta build does not read v1, the frozen
vectors' format (D6b)"). In its place, `test_current_format_sign_then_verify_roundtrip`,
which runs in every build, signs two files under the current entry (one from the production
writer, one signed by hand) and checks through `verify_paths` that they pass `format`,
`selfsig` and `content` (each subject entry read under its own `hash_alg`), and that
copies changed after signing fail `selfsig`. So on main after `0.4.0b1`, the pinned checks
don't run until the `0.4.0` release commit sets `v1` again, and that commit's `check.sh` is
the first to compare format changes made between betas against the frozen vectors.

The skip covers `0.4.0` betas only, built before any format was released. Any later build,
a later line's beta included, must still read `v1`, so the frozen vectors run there. (How
a later line's betas are released is not designed yet: after `0.4.0`, main signs with `v1`,
and a new entry keyed by the name would duplicate that key.) Also never skipped,
`test_v1_is_read_by_every_build_but_a_0_4_0_beta` requires `application/vnd.asexec.v1+json`
to be a `FORMATS` key whenever `MANIFEST_PAYLOAD_TYPE` is not a `0.4.0` beta type.

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
2. `verify-release` - the tag is `vX.Y.Z` or `vX.Y.ZbN`; tag, `pyproject.toml` and
   `__version__` agree; the tag is annotated and its commit is on `main`; `dist` holds exactly
   one wheel and one sdist (sha256 sums in the job summary).
3. `publish-testpypi` - uploads to TestPyPI (environment `testpypi`).
4. `smoke-testpypi` - installs hash-locked dependencies from PyPI, then `asexec==X.Y.Z` from
   TestPyPI with `--no-deps` (dependencies are never resolved from TestPyPI; the exact pin
   selects a beta without `--prerelease`), retrying for about 5 minutes for index
   propagation. Runs the CLI smoke against the installed wheel,
   checks `asexec --version` prints the tag version, on every Python in the `ci.yml` matrix.
5. `publish-pypi` - uploads to PyPI (environment `pypi`). Required reviewers approve here,
   after the TestPyPI smoke passes.
6. `github-release` - `gh release create` with the built files and generated notes, and
   `--prerelease` for a beta tag.

Each job holds only the permissions it needs (`id-token: write` for the two uploads,
`contents: write` for the release). Attestations are on by default. Runs for the same ref
are serialized and never cancelled.

If TestPyPI or the smoke test misbehaves, do not approve the `pypi` deployment. PyPI version
numbers can never be reused, so fix forward with a new version.
