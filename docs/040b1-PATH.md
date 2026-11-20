# Path to 0.4.0b1

## Decisions

All decided on 2026-11-18. The issues named here carry each decision in their specs.

### D1. #35: the predicate type path

`https://asexec.org/manifest`, or `https://asexec.org/manifest/v1` following the in-toto
convention. Settle it before #32 regenerates the golden vectors.

- **Decision:** `https://asexec.org/manifest/v1`. It follows the in-toto convention, and it
  gives in-toto consumers, who see `predicateType` but not `payloadType`, a version signal.
  Whether `payloadType` and `schema_id` are versioned to match is D1b.

### D1b. Versioning `payloadType` and `schema_id` to match

- **Decision:**
  - `payloadType` for 0.4.0 is `application/vnd.asexec.v1+json`. A later format is `.v2`, and
    `payloadType` vN goes with `predicateType` vN. Betas keep
    `application/vnd.asexec.0.4.0b1+json`.
  - `schema_id` is dropped from the body. `predicateType` already says the body is an asexec
    manifest, and a third identifier that no test checks could disagree with the other two.
- **Follow-ups:**
  - Update `docs/MULTIVERSION.md` (the example table, and the open question on spelling),
    `docs/FORMAT.md` and `ROADMAP.md` to use `vnd.asexec.v1+json`.
  - Change #30's spec: a release sets `application/vnd.asexec.v1+json`.
  - Widen #35's scope to cover the `payloadType` literal and removing `schema_id`: the
    model, the builders (`_BEDROCK_STRUCTURAL` in `manifest.py`), `MANIFEST_SCHEMA_ID`, the
    pinned constants test, the docs and the README examples. #35 is widened to cover this.

### D2. #44 / #7: whether a prereg with an invalid signature is a commitment

The two issues ask the same thing. The options:
- It is not a commitment, so its postregs are notarization-only.
- It stays a commitment, and the report flags it.

This fixes a verify-code meaning before 0.4.0, and #42's lookup depends on it. Close one
issue as a duplicate of the other.

- **Decision:** a prereg that fails the `BDR` signature or keyid condition is **not a
  commitment**.
  - The report lists it under a new heading, *rejected pre-registrations*, with its reason.
  - A postreg naming it is listed as rejected under it, with the reason that the prereg's
    signature is invalid. It is not notarization-only, because it does name a provided
    prereg.
  - No state, `chain` or `keyconsist` result rests on a keyid that nothing authenticated,
    and a forged copy can't merge into a real commitment with the same `(ref, keyid)`. This
    is the same rule postregs follow (matching condition 2).
  - #44 stays open and carries this decision. #7 is closed as its duplicate (done).
- **Follow-ups:**
  - Add a prereg condition to *Matching postregs to commitments* in `docs/VERIFICATION.md`.
  - Put the rejected pre-registrations section in the report docs.
  - #42 indexes valid preregs only.
  - Add the test #44 asks for: a tampered prereg plus a valid postreg by the same key.

### D3. #26: the new name for `BDR`, and whether it lands before b1

The candidates are `signature`, `signed`, `integrity` and `selfsig`. The new name must stay
distinct from `signer`. The rename has to land before 0.4.0. Doing it just before #32 means
the `BDR` tests are edited once.

**What makes `BDR` fail in practice** (after #31 and #32), roughly from most to least
common:
1. Version skew: an unknown or beta `payloadType`. The file is fine, and the fix is to
   upgrade asexec.
2. Accidental damage, such as truncated or garbled base64 or a bad copy.
3. The body edited after signing and not re-signed.
4. The wrong number of signatures, for example a second one added by other DSSE tooling.
5. Forgery, but only a body changed without re-signing, or a claimed `keyid` that doesn't
   derive from the signing key. A forger who signs with their own key passes. Catching
   that is `signer`'s job.

A signature-flavoured name would make case 1, the most common failure, read as a bad
signature.

#### D3a. Split the format check from the signature check

- **Decision:** `BDR` becomes **two required tests**:
  - A *readable* test (named `format` in D3b). The file can be read as a known format. It fails on an unknown
    `payloadType` and on every malformed case: unreadable, not a JSON object, too deep, a
    duplicate key, a missing frame.
  - An *integrity* test (named `selfsig` in D3b). The file is unchanged since its own key signed it: exactly one
    signature, valid over the PAE by `pubkey`, and a `keyid` that derives from `pubkey`. It
    doesn't examine a file that fails the readable test. If no file is readable, it's
    empty, so it fails.

  Both must be included in `--tests`. Version skew then reads as `format=FAIL` with
  `selfsig=PASS` for the other files, so the code itself tells "upgrade" apart from
  "damaged".
- **Follow-ups:**
  - Change #31: an unknown format fails the readable test, not `BDR`.
  - Change #26: it splits the test as well as renaming it.
  - Update the `--tests` rule and the `REQUIRED_TEST` constant, which become a set.
  - In `docs/VERIFICATION.md`, update the run rules (malformed fails the readable test) and
    add a section for each test.
  - Update `docs/MULTIVERSION.md`, which says an unknown format fails `BDR`.

#### D3b. Names

- **Decision:** `format` and `selfsig`.
  - `format=FAIL` reads directly as "not a format this release can read", which is what
    the common case, version skew, needs to say.
  - `selfsig` is self-certifying, not a trust model. The file carries its own `pubkey`, and
    a pass means only "whoever holds this key signed these bytes, and they haven't changed".
    Nothing is pinned, and verify keeps no state between runs.
  - Trust comes from the other layers. `keyconsist` gives key continuity within one claim,
    with the prereg as first use. `ceiling` pins when that first use happened. `signer`
    checks keys pinned out of band, and `identity match` binds a key to a domain. The
    layers are `format` → `selfsig` → `keyconsist` → `signer`, and `selfsig` names its own
    layer exactly.

#### D3c. Timing

- **Decision:** before #31, in b1. The split lands while it's still a rename plus a split
  over today's checks. #31 then adds the unknown-format failure to `format`, and #32 writes
  its DSSE tests against `selfsig`. Both are written once against the final names, and the
  dry runs and `docs/BETA.md` see the final codes.

### D4. What is in b1 from the roadmap's verify list

| Item | Issue | In b1? |
|---|---|---|
| `timely` and `no-due` | #46 | yes |
| `signer` (`--signer` / `--trusted-keys`) | #47 | later beta |
| `--json` | #48 | later beta |

- **Decision:** only `timely` and `no-due` (#46) go into b1.
  - `complete` (#37) already makes the same ceiling-to-`due` comparison for each item, and
    the dry runs should catch late runs.
  - `signer` waits for a later beta, still before the release gate. One-lab M1 dry runs
    hardly use it, and its trusted-keys file needs designing.
  - `--json` waits for a later beta. It's outside the support promise until 0.5.0, and its
    consumer is M2.
- **Follow-ups:** #47 (`signer`) and #48 (`--json`) are open for 0.4.0. Neither blocks b1, and
  neither is in #40's dependencies.

### D5. #46: the open questions

- What `timely` reports for a prereg without `due`, and for a counted postreg without a
  ceiling.
- Whether a counted postreg that fails `timely` still makes its commitment `fulfilled`.

- **D5a (edge cases):**
  - A prereg with no `due` is not examined, and the report shows it as `no-due`. Its `due`
    is fixed in the signed prereg at commitment time, so it can't be removed once the lab
    knows it'll be late. Failing it would let one open-ended claim fail `timely` for a whole
    mixed run.
  - A counted postreg with no ceiling fails. Its ceiling is chosen at report time, so
    leaving it out must not get around the test.
  - A `due` that can't be parsed fails, with that reason.
  - If no prereg has a `due`, `timely` is empty and fails.
  - The same no-`due` rule applies to `complete` (#37): a prereg with items but no `due`
    isn't examined for timeliness. Record this in #37.
  - "Every claim must have a deadline" is a separate policy question. It isn't decided
    here.
- **D5b (late postreg):** the commitment stays `fulfilled`, `timely=FAIL` carries the
  verdict, and the report marks the postreg as late. States keep meaning "was it reported",
  and tests carry "was it on time". A late report is still an authentic report, and
  counting stays about authentication.

### D6. #30: how the golden vectors survive the beta `payloadType`

`payloadType` is part of the DSSE signing input, so the release commit's change to it
breaks any vector that hardcodes it. The options:
- The vectors derive from the constant.
- The release commit regenerates them.

- **D6a (main's `payloadType`):** main keeps the type the last release commit set, until
  the next release commit. After b1 that's `application/vnd.asexec.0.4.0b1+json`. There's
  no revert commit, and nothing on main writes the `v1` label before 0.4.0, so no
  unsupported file can claim the supported format. Between betas, main's format changes
  still carry the last beta's label. That's harmless, because betas are unsupported and
  main isn't published.
- **D6b (vectors):** the frozen vectors are pinned to the release type (`v1`). They're
  skipped when `MANIFEST_PAYLOAD_TYPE` is a beta type, and a sign-then-verify roundtrip runs
  instead. `release.sh` edits only the constants, as #30 says.
  - What this means: #32 and #33 land before b1, while main still carries `v1`, so they run
    the pinned checks. After b1, main carries a beta type, so the pinned checks don't run on
    main until the 0.4.0 release commit sets `v1` again. A format change made between
    betas is first checked against pinned vectors in that release commit's `check.sh`.
- **Follow-ups:**
  - #30: the skip condition and the roundtrip test.
  - #30: state that main keeps the beta type after a beta release.
  - #32 and #33: regenerate the `v1` vectors as part of their own changes.

## Checklist

- [x] 0. Decisions D1–D6 above; #47 and #48 opened for D4
- [x] 1. #35: predicate type, `payloadType` `v1`, drop `schema_id` (D1, D1b) (on feature/0321)
- [ ] 2. #26: split `BDR` into `format` and `selfsig` (D3)
- [ ] 3. #31: `FORMATS` table; an unknown format fails `format`
- [ ] 4. #30: beta release support (after #31, because it rewrites the `FORMATS` key)
- [ ] 5. #44 (D2), then #42 and #43
- [ ] 6. #32: DSSE envelope
- [ ] 7. #33 → #36 → #46 → #37
- [ ] 8. #34 and #38
- [ ] 9. #45 (after #38)
- [ ] 10. #39 → #40

## Execution brief

Given on 2026-11-19 for checklist items 1 to 9, saved verbatim:

> This is a large and quality-critical task; execution strategy and deliverables are tightly scoped. You will drive autonomously through the checklist (items 1 through 9) in docs/040b1-PATH.md according to the decisions and issues in that document. Perform your development branches feature/0321-checkpointN off feature branch feature/0321, which itself is branched off current main, and **do not merge to main at any point**. Instead, each number in the checklist will be merged from your dev branch feature/0321-checkpointN to the feature branch feature/0321. One dev-subagent -> PR per number in the that list, so for example `7.  #33 → #36 → #46 → #37` implies `7a. branching off feature/0321 to create feature/checkpoint7, spawn subagent that will perform the subsequent implementation steps 7b. Implement #33. 7c. Implement #36. 7d. Implement #46. 7e. Implement #37. 7f. Subagent sends PR and you spawn a new code-review-subagent. 7g. Make fixes. 7h. Loop steps f ang g as needed to deliver intended result and quality but **do not expand scope, instead note down any observations in a running notes section in docs/040b1-PATH.md, organized by checkpoint number.** 7i. Merge to feature branch.`. **GENERAL STRATEGY**: GS1. Correctness is much more important than implementation speed, hence the sequential strategy. Additionally, a TDD approach is recommended to all dev-subagent implementation tasks, given that the tasks are well-scoped and their destinations known in advance. GS2. Use VERIFICATION.md, 040b1-PATH.md, and generally README.md as your decision, verification/deliverable, and ethos guides respectively. GS3. Adhere to existing code conventions, and do not invent new systems/paradigms/dependencies unless absolutely necessary (and if you do, this belongs in the checkpoint notes). This includes but is not limited to: pinning of critical constants, pydantic usage, extremely regimented test and CI structure which validates invariants and input/output contracts over internal logic, preferring fat-structs over OOP classes, to name a few. GS4. Note the commit SHA and branch in the issue once you merge it's implementation onto the feature branch but do not close the issue, which is gated on the implementation landing on main (which is outside your scope). GS5. At each checkpoint, recorded in the -PATH document, keep track of the concrete objective evidence that the implemention is working and that nothing has regressed. Do not overwrite previous checkpoint notes and evidence, this is meant to be a running log. **FINAL DELIVERABLE**: A feature branch feature/0321 that contains all 1-9 checkpoints in the 040b1-PATH.md doc, validated and tested, evidence recorded and ready for Human-In-The-Loop testing as the final gate before we eventually batch the beta release. Save this prompt in 040b1-PATH.md and begin execution.

How it is run:
- Each checkpoint N is developed on `feature/0321-checkpointN`, branched from `feature/0321`,
  and lands there through a PR with base `feature/0321`, merged with a merge commit so each
  issue's own commit keeps its SHA. Nothing is merged to `main`.
- Each PR is reviewed by a separate review agent, and the review-and-fix loop repeats
  until no in-scope finding is left. Anything outside the issue's scope goes in that
  checkpoint's notes below, not in the code.
- Commits and PRs say `Refs #N`, never a closing keyword, so no issue closes before its
  change reaches `main`. After each merge, each issue gets a comment naming the branch and
  the commit.
- Checklist boxes are ticked when the item lands on `feature/0321`, not on `main`.

## Checkpoint notes

A running log, one section per checkpoint, never rewritten. Each section records what
landed, the evidence that it works and that nothing regressed, and observations left out of
scope.

### Baseline (`main` at fd5b038)

- `scripts/check.sh`: ruff check and ruff format check clean; `pytest`: 401 passed.

### Checkpoint 1: #35

**Landed** (branch `feature/0321-checkpoint1`):
- #35, `da7cbb2`: `MANIFEST_PREDICATE_TYPE` is `https://asexec.org/manifest/v1` and
  `MANIFEST_PAYLOAD_TYPE` is `application/vnd.asexec.v1+json`; `MANIFEST_SCHEMA_ID`, the
  `ManifestBody.schema_id` field, its `_BEDROCK_STRUCTURAL` entry and the
  `asexec.MANIFEST_SCHEMA_ID` export are removed. Frozen vectors re-signed under `v1`; README,
  `docs/VERIFICATION.md`, `docs/FORMAT.md`, `docs/MULTIVERSION.md` (example table, `FORMATS`
  key, per-identifier table, spelling question closed) and `ROADMAP.md` (0.4.0 `payloadType`,
  the `schema_id` notes, the tier table) updated.

**Evidence:**
- `scripts/check.sh`: ruff check and format check clean; pytest 401 passed before, 402 after
  (one test removed, two added; see below).
- Red first: with only the tests changed, 9 failed for the expected reasons
  (`MANIFEST_SCHEMA_ID` still defined; `'application/vnd.asexec+json' ==
  'application/...sexec.v1+json'`; `'https://asexec.dev/manifest' == '...g/manifest/v1'`; the
  builder guard's body still had `schema_id`; the pre-`v1` vector still passed). With the
  constants changed, the 4 tests on the frozen vectors failed (`_bdr_passes(...) is False`):
  the signed bytes changed. They passed after re-signing.
- Tests that pin each requirement:
  - `tests/test_constants.py`: `test_signing_pae_version_and_manifest_payload_type` (the `v1`
    literal and the PAE bytes `asexec-PAE/v1 30 application/vnd.asexec.v1+json 31 ...`),
    `test_manifest_predicate_type` (the `/v1` literal; a built body has no `schema_id`),
    `test_every_identifier_is_classified` (`MANIFEST_SCHEMA_ID` is gone from `constants`),
    `test_frozen_manifests_still_verify` (the re-signed vectors), and the new
    `test_manifest_payload_type_change_fails_what_was_signed_before_it` (`PRE_V1_MANIFEST`,
    the same body and key as signed by 0.3.x, fails `BDR`).
    `test_not_enforced_yet__schema_id_and_predicate_type` is now
    `test_not_enforced_yet__predicate_type`.
  - `tests/test_manifest.py::test_predicate_type_is_the_only_format_identifier_in_the_body`.
  - `tests/verify/test_verify_builder_guard.py` (all 4): the writer builds exactly
    `tests/manifest_data.py`'s bodies and envelopes, now without `schema_id` and under `v1`.
  - `tests/verify/test_verify_planted_faults.py::test_fault__signed_body_field_verify_does_not_examine[schema_id-no-longer-written]`:
    a signed body that still carries `schema_id` is an unknown field and gets
    `BDR=PASS chain=PASS keyconsist=PASS`, state `fulfilled`, like a body without it.
- Vectors regenerated by the production signer, not by hand: `manifest.sign(body, bytes(32),
  pub)` with only its bedrock gate stubbed out (the frozen bodies deliberately hold just
  `phase` and `target`). Run on the old code first, the same script printed the old
  signatures exactly (`2e993406…`, `e222249e…`), so it is the method that made them. On the
  new code it printed `payloadType` `application/vnd.asexec.v1+json` and the signatures now
  in the file (`afd85bcb…`, `13dccac3…`).
- Signed before vs after, CLI in a scratch dir (`keygen`, `prereg --target "model m via
  provider p"`, `postreg --fulfills prereg.json [--prev ...]`):
  - Files signed by the pre-change CLI, verified by the new one:
    `asexec verify prereg.json postreg-1.json --tests BDR,chain,keyconsist` prints
    `✗ prereg.json`, `✗ postreg-1.json`, `postreg ... does NOT count toward fulfillment:
    invalid signature`, `asexec-verify/1 BDR=FAIL chain=FAIL keyconsist=FAIL`, exit 2. Their
    bodies hold `"schema_id": "asexec"` and `"predicateType": "https://asexec.dev/manifest"`.
  - Files signed by the new CLI: `asexec verify prereg.json postreg-1.json postreg-2.json
    --tests BDR,chain,keyconsist` prints `[FULFILLED]`, `asexec-verify/1 BDR=PASS
    chain=PASS keyconsist=PASS`, exit 0. The prereg is `{"payload": {"predicateType":
    "https://asexec.org/manifest/v1", "phase": "prereg", "target": "model m via provider p"},
    ..., "payloadType": "application/vnd.asexec.v1+json"}`.
- `uv run python examples/adequacy-test/run.py`: exit 0, output identical before and after
  (it prints no identifiers): `no fault` `BDR=PASS chain=PASS content=PASS keyconsist=PASS`,
  `plants swapped after the run` `content=FAIL` (caught), the other two faults missed as
  before.
- Nothing left behind: `grep -rn -e schema_id -e MANIFEST_SCHEMA_ID -e asexec.dev -e
  'vnd.asexec+json'` over `src`, `tests`, `docs`, `examples`, `scripts`, `.github`,
  `README.md`, `ROADMAP.md` and `prd.md` finds none in `src`, `examples`, `scripts` or
  `.github`. The remaining hits are deliberate: `ROADMAP.md` (the notes saying `schema_id` is
  removed, in the 0.4.0 format list and under the property tables); `docs/040b1-PATH.md` (the
  decisions); `tests/test_constants.py` (`PRE_V1_MANIFEST`, the old type on purpose, and the
  `"schema_id" not in body` assertion); `tests/test_manifest.py` (the same assertion);
  `tests/verify/test_verify_planted_faults.py` (the `schema_id` input case). The *History*
  table in `ROADMAP.md` never named these values, so nothing historical needed keeping.
- CI: see below.

**Release-note entries** (the rule in `tests/test_constants.py`'s header). Release notes are
the GitHub release body (`publish.yml` runs `gh release create --generate-notes`; no
earlier release carries an identifier entry, and `ROADMAP.md`'s *History* is a theme table).
No release exists for this yet, so the entries are drafted here for #40 to paste:

```
Identifier: MANIFEST_PAYLOAD_TYPE, application/vnd.asexec+json -> application/vnd.asexec.v1+json
Impact: BREAKS_USERS
Affected: every manifest signed by 0.3.x: payloadType is in the signed bytes, so their signatures no longer verify
Action: re-sign with this release; 0.3.x manifests are not supported

Identifier: MANIFEST_PREDICATE_TYPE, https://asexec.dev/manifest -> https://asexec.org/manifest/v1
Impact: NEW_OUTPUT
Affected: nothing published (written into new bodies only; verify does not compare it)
Action: none

Identifier: MANIFEST_SCHEMA_ID, asexec -> removed (the body field schema_id is no longer written)
Impact: NEW_OUTPUT
Affected: nothing published (a body that still carries schema_id reads as an unknown field, which nothing examines); the Python export asexec.MANIFEST_SCHEMA_ID is gone
Action: none; read predicateType to identify an asexec body
```

For #40: b1 itself ships `application/vnd.asexec.0.4.0b1+json`, set by `release.sh` (#30,
D6a), so in the b1 notes the new `MANIFEST_PAYLOAD_TYPE` value should be the beta type, with
`v1` named as what 0.4.0 will write. #40's own list adds `SIGNING_PAE_VERSION` (#32) and the
`BDR` split (#26).

**D1b follow-up on #30:** #30's body already says that for 0.4.0 the release commit sets
`application/vnd.asexec.v1+json`, and that a beta sets `application/vnd.asexec.X.Y.ZbN+json`.
Nothing to change.

**Observations (out of scope):**
- `ROADMAP.md:116`: the version map says "current 0.3.19", and *History* stops at 0.3.19,
  though 0.3.20 has shipped.
- `docs/FORMAT.md:55`: the example labelled "today (0.3.x)" now shows the `v1` type, which
  is what this branch writes but not what released 0.3.x writes. The label means the
  pre-DSSE envelope shape; #32 rewrites this section anyway.
- `tests/test_constants.py:248` (`test_not_enforced_yet__envelope_payload_type`): verify
  still never reads the file's `payloadType`; it signs and checks under the constant. A
  0.3.x manifest therefore fails `BDR` as "invalid signature", with no word about the
  format. #31's unknown-format failure is what gives it a clear reason.
- `docs/MULTIVERSION.md:70` still says an unknown `payloadType` fails `BDR`; that is D3's
  follow-up, for #26.
- `src/asexec/manifest.py:150` (`_check_bedrock`): `manifest.sign` checks a hand-built dict
  only for missing fields, so it would still sign one that carries `schema_id` or any other
  extra field. `build_*` can't produce one (the writer model forbids extras).

**Judgement calls:**
- `test_not_enforced_yet__pre_rename_schema_version` (a 0.3.19 manifest with
  `schema_version`) is removed. It passed only while the old `payloadType` was in the
  signed bytes, and 0.3.x is outside the promise. In its place,
  `test_manifest_payload_type_change_fails_what_was_signed_before_it` keeps the 0.3.x
  signature of `FROZEN_MANIFEST` (`PRE_V1_MANIFEST`) and requires it to fail. #26 and #31
  will move this test to `selfsig` / `format`, as they do every `BDR` test.
- The frozen bodies stay `{"phase": "prereg", "target": "m"}`, with no `predicateType`, so
  re-signing them through `manifest.sign` needs its bedrock gate stubbed out. The bytes
  signed are still computed entirely by `manifest.sign`.
- The `docs/VERIFICATION.md` worked examples are rebuilt, not just edited: the old refs
  (`2f4f6ac7…`, `059020b4…`, `86078561…`) were reproduced exactly from the CLI recipe
  above on the old code, then the same recipe was run on the new code with a new key
  (the old one isn't in the repo). Every key, signature and ref prefix in the file was
  replaced to match, as `e6b43e0` did when `schema_version` was renamed. The ceiling
  example's elided `response` is left as it was.
- In `docs/MULTIVERSION.md`'s table of rejected selector fields, the `schema_id` row now
  names `predicateType`, for which the same reason holds.
- The `schema_id` input case went into `test_verify_planted_faults.py`'s
  fields-no-test-examines cases, the existing home of unknown body fields. VERIFICATION.md
  doesn't name `schema_id`: it is covered by the run rules (only *Examines* properties are
  read) and by `BDR`'s *Does not establish* line.
