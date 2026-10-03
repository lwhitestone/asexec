# Roadmap

> [!NOTE]
> This file is AI-assisted and is meant as a rough context-setter.
> Treat AI output with due skepticism.

**Ordering logic:** make the current claims true first; then pin down the
invariants and test them; then make every format-breaking change in one
release; then shrink the dependency surface; then freeze the spec. Anything
that changes signed bytes or verify-code semantics lands *before* the spec
freeze, so the format people adopt is the format we can stand behind.
Distribution (PyPI) is cut early to claim the name, with honest caveats.

## Versioning

- **Releases** use `0.MINOR.PATCH`, pre-1.0 alpha.
  - `MINOR`: a change to the manifest format, the signed bytes, or the
    documented meaning of a verify test.
  - `PATCH`: additive or corrective. A fix that brings the implementation in
    line with *already documented* semantics (e.g. `chain` rejecting forks,
    which its docstring always claimed) is a `PATCH`, called out in the
    release notes.
- **Identifiers baked into signed bytes.** `SCHEMA_VERSION`, `PREDICATE_TYPE`,
  and the PAE prefix (`asexec-PAE/v1`) are part of the signing input; changing
  any of them is a deliberate format break, never incidental.
- **The verify-code grammar is versioned separately** (`asexec-verify/N`). The
  promise that "a code means exactly one thing, permanently" holds only if this
  rule holds: **if the documented meaning of an existing test name changes, the
  grammar version bumps.** Adding a new test name does not require a bump.
- **No backward-compatibility guarantee before `1.0.0`.** Any pre-1.0 release
  may change the schema, signed-byte format, verifier output, or CLI without a
  migration path. `1.0.0` is deliberately unassigned; no trigger is defined.

## Version map

| Version | Phase | Theme | Format break? |
|---|---|---|---|
| 0.1.0 – 0.3.11 | — | shipped (see *History*) | — |
| **0.3.12** | Distribution | First PyPI release: tag-triggered trusted publishing; README *Known issues* | no |
| **0.3.13** | 0 — Soundness | Fix the confirmed soundness bugs; correct README overclaims | no (patch fixes to documented semantics) |
| *(no release needed)* | 1 — Invariants | Invariant catalog, test audit, golden vectors, property/mutation testing, CI matrix | no |
| **0.4.0** | 2 — Verify surface | Auditor-facing verify tests + the manifest fields they need; all format fixes batched | **yes** |
| **0.4.x** | 3 — Dependencies | Drop pydantic and blake3; vendor-or-pin BLS; supply-chain hardening | no (golden vectors must not move) |
| **0.5.0** | 4 — Spec freeze | `SPEC.md` normative, golden vectors normative, hardened release pipeline | only corrections found while writing the spec |
| *unversioned* | Later | Per-key index · re-execution mode · cosigners · multi-party · regulatory field | as scheduled |

---

## 0.3.12 — First PyPI release

The `asexec` name is unclaimed on PyPI while the README already says
`pip install asexec`. Claim it with a real (alpha) release, not a placeholder.

- Tag-triggered publish workflow (`.github/workflows/publish.yml`) using PyPI
  Trusted Publishing (OIDC, no long-lived tokens): TestPyPI first, then PyPI
  behind a protected environment. PEP 740 attestations on by default.
- README *Known issues* section listing the confirmed Phase 0 findings, so the
  PyPI page carries the caveats.
- Version numbers on PyPI can never be reused (even after yank/delete), so the
  workflow is proven on TestPyPI before the first real upload.

## 0.3.13 — Phase 0: Soundness patch

Point fixes, each written test-first (a failing test reproducing the bug, then
the fix). No redesign; anything requiring a format change waits for 0.4.0.

| Finding | Fix |
|---|---|
| A forked `prev_hash` chain passes `chain` | Require a single linear chain (each receipt has ≤1 successor) |
| A postreg by **any** key marks a commitment `fulfilled` | A postreg counts toward fulfillment only if validly signed by the prereg's key; others are rendered separately |
| A postreg with an **invalid** signature counts toward `fulfilled` | Same as above |
| README claims a `due` timeliness check that does not exist | Correct the README now; the real check (`timely`) ships in 0.4.0 |
| README claims tail truncation is detectable | Correct the README; close-out manifests (`final`) ship in 0.4.0 |
| Duplicate JSON keys are silently accepted (last wins) | Reject on load (`object_pairs_hook`); manifest is malformed → `BDR=FAIL` |
| Malformed input crashes `verify` (e.g. `JSONDecodeError`) | Malformed manifests are per-file failures, never a crash |
| `content` follows `../` / absolute subject names out of `--artifacts` | Confine resolution to the artifacts directory; escape → mismatch |
| Timezone-less `due` is read in the verifier's local TZ | Require an explicit offset/`Z` at sign time; flag naive values at verify time |
| Unparseable `due` silently renders `open` | Render an explicit `invalid-due` state |
| `keygen` overwrites an existing key file | `O_EXCL`; refuse unless `--force` |
| `--floor` / `--ceiling` fetch failure only warns and signs anyway | Fail by default; opt-in `--best-effort` |
| `--fulfills <typo>` is silently stored as a literal ref | Accept only an existing file or a well-formed `sha-256:<64 hex>` ref |
| Unknown `hash_alg` (e.g. blake3 not installed) crashes `verify` | Content entry fails with "algorithm unavailable" |

Also: refresh stale docstrings/comments (`__init__.py`, the Roughtime
`SERVERS` alpha caveat).

## Phase 1 — Invariant catalog and test audit

The test audit and the code audit are one workstream: decide the invariants,
then make the test suite exactly that set.

- **`INVARIANTS.md`**: numbered invariants (I-1…I-n), each mapped to the
  test(s) that enforce it. Examples: verify never raises on any input; any
  byte change to a signed body → `BDR=FAIL`; fulfillment requires a valid
  same-key postreg; a requested test that applies nowhere is `FAIL`; canonical
  bytes and directory digests are identical across OSes.
- **Audit**: every existing test maps to an invariant or is deleted/merged;
  every invariant without a test gets one.
- **Golden vectors**: a fixed key + fixed bodies with committed hex for
  canonical bytes, `ref`, signature, and directory digest. Guards the
  signed-byte format against accidental drift (and proves Phase 3 changed
  nothing). Becomes the seed of the spec's test vectors.
- **Property tests / fuzzing** (`hypothesis`): canonicalization, the Roughtime
  message parser, `verify_paths` over arbitrary input.
- **Mutation testing** (`mutmut`) over `verifier`, `canonical`, `hashing`,
  `manifest`: a surviving mutant is either an untested invariant or dead code.
- **CLI tests**: exit codes, fail-loud paths, argument validation (`cli.py`
  currently has only the CI smoke run).
- **CI**: add Windows + macOS runners (path/dir-hash determinism) and Python
  3.13/3.14; branch-coverage gate; a job without optional extras.

## 0.4.0 — Phase 2: Verify surface for auditors and governance

Work backwards from what third-party auditors and eval-runner governance need
to check, then add the manifest fields that make it checkable. All
format-breaking changes are batched here.

**New verify tests** (ranked):

1. `signer` — `--signer <keyid>` / `--trusted-keys <file>`: manifests are signed
   by a key the *verifier* chose to trust. Today `BDR` proves only internal
   consistency, never *who* signed.
2. `continuity` — postregs keep the prereg's `target`, and every prereg subject
   reappears in the postreg with the identical digest ("you ran what you
   pre-registered").
3. `order` — prereg ceiling < postreg floor: the only *cryptographic* proof of
   "pre". Buildable from existing anchors; add a CLI shortcut to attach both.
4. `timely` — postreg ceiling (midpoint + radius) ≤ prereg `due`.
5. `frame` — bodies conform to this version's schema (known `phase`,
   `predicateType`, ref formats, TZ-aware `due`); signed-but-unrecognized
   fields are rendered as *unverified content*, never silently ignored.
6. `complete` — a close-out postreg (`final: true`) and optional
   `expected_runs` at prereg make tail truncation detectable (also resolves the
   PRD's runs-vs-window open question).

**Output / trust surface**

- `--json`: a stable, machine-readable report for CI gates.
- Trust roots visible: print the pinned drand/Roughtime set (or its hash);
  `--trust-roots <file>` to let the reader choose which witnesses to trust.

**Format changes**

- `PREDICATE_TYPE` → a URL the project controls (e.g. the repo's `SPEC.md`
  anchor), replacing `https://asexec.dev/manifest`.
- Directory hash v2: unambiguous encoding (length-prefixed, or git-tree
  compatible) — v1 joins `hash  path` lines with `\n`, which a POSIX filename
  can contain, and sorts by hash rather than path.
- Canonicalization: adopt RFC 8785 (JCS) or restrict the value domain (no
  floats/NaN); `json.dumps` behaviour is not a spec.
- Subject `name` carries a relative path (not a basename) plus optional
  `role: input | output`, so `continuity` can match inputs.
- `final`, `expected_runs` (for `complete`).
- Decide at implementation time whether any of this changes the documented
  meaning of an existing test name; if so, bump to `asexec-verify/2`.

Recommended before finalizing the 0.4.0 format: **dogfood** a few real evals
through the full cycle (messy harnesses, non-determinism, disclosure-window
UX). Real transcripts should inform subject roles and the close-out flow.

## 0.4.x — Phase 3: Dependency reduction

Runtime today is 13 packages; `py_ecc` alone roots 10 (`eth-utils`,
`eth-typing`, `eth-hash`, `cytoolz`, `toolz`, and `pydantic` again via
`eth-utils`).

- **Drop pydantic**: it gates construction only, and `model_dump` sits on the
  path to signed bytes (a dependency-driven byte-drift risk). Replace with
  hand-written validation. Golden vectors must be unchanged.
- **BLS (`py_ecc`)**: spike vendoring the minimal verify subset (G1/G2
  decompression *with subgroup checks*, `hash_to_G1`, pairing), tested against
  official drand vectors. If the subset is too large to own, keep `py_ecc`
  exact-pinned with a hash-locked install.
- **Drop the `blake3` extra**: hash-algorithm agility is surface without
  current demand.
- **Keep `pynacl`.** Target end state: `pynacl` → `cffi` → `pycparser`.
- **CI supply chain**: pin all GitHub Actions by commit SHA; least-privilege
  `permissions:` on every workflow.

## 0.5.0 — Phase 4: Spec freeze

- `SPEC.md` becomes normative: canonical bytes, PAE, `ref`, directory hash,
  manifest schema, verify-test semantics, code grammar — consolidating what
  is currently spread across docstrings — with the golden vectors as its
  conformance suite, so a third party can reimplement the verifier.
- Release pipeline hardening: reproducible builds (`SOURCE_DATE_EPOCH`),
  build-provenance attestations, `py.typed`, complete classifiers.
- Optional dogfood: sign each release's artifact hashes with `asexec postreg`.

## Later (unversioned until scheduled)

- **Per-key public index** (`.well-known/asexec-index.json`) — addresses
  selective *non*-registration, the largest remaining completeness gap.
  Convention only, no hosting.
- **Offline identity check** (`verify --wellknown <archived.json>`) and
  **`--as-of`** for reproducible state rendering.
- **Re-execution / determinism mode** — must degrade gracefully for
  legitimately non-deterministic evals; calibrate on dogfooding transcripts.
- **Federated cosigner witnesses** — generalize the ceiling to a k-of-n
  `cosign` witness type the reader chooses to trust. Waits for willing
  witnesses.
- **Multi-party co-signing** at prereg; **structured regulatory
  cross-reference** field — add when a concrete need appears.
- **Process (not releases):** team/customer usage after dogfooding; a
  verification website as a *separate* repo, buildable by anyone from the
  spec alone.

**Explicitly not scheduled:** hosted transparency log, third-party witness
*services* run by this project, identity binding / CA.

---

## Standing design decisions

Kept here so they are not re-litigated:

- **The verify code is named, not scored.** It lists which tests ran, each
  `PASS`/`FAIL`, sorted alphabetically — never a percentage or tier — so a
  code is self-describing and forward-compatible. It is a summary of a
  computation, not a certificate: real verification is reproducing it.
- **Explicit test appetite.** `--tests` is required and must include `BDR`. A
  requested test that applies nowhere is `FAIL`, never a silent omission.
- **Only verifiable claims earn a test.** Self-declarations (e.g. the removed
  `has_run_already` field) belong in free-form `notes`, never beside the
  cryptographic anchors where they would imply they were checked.
- **Floor and ceiling generalize along disjoint axes.** A floor is a public
  beacon (fixed at T, independent of the manifest, embeddable): drand, NIST,
  block hashes. A ceiling is a witness that ingested `ref(payload)` (attached
  after signing, at the envelope): Roughtime, OTS, cosigners. A beacon cannot
  be a ceiling and a witness cannot be a floor.
- **Fail loud.** Ambiguous or unfulfilled states are rendered explicitly
  rather than collapsed into a pass/fail that overclaims.

## History

| Version | Theme |
|---|---|
| 0.1.0 | Core primitive: keygen · preregister · seal · verify · identity; offline verifier; drand freshness |
| 0.2.0 | Schema rebalance (bedrock vs. optional); drand floor + Roughtime ceiling as distinct anchors; canonical verify code |
| 0.3.0 | Vocabulary/type realignment: `prereg`/`postreg`, free-form `target`, optional `due`/`declaration`, opt-in floor, `BDR` token, Pydantic-typed construction |
| 0.3.1 – 0.3.11 | Provenance handoff to hand-curated maintenance; docs polish; ruff, uv, pytest, CI, release scripts; Python ≥ 3.11 |
