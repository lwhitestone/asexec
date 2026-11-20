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
- [x] 2. #26: split `BDR` into `format` and `selfsig` (D3) (on feature/0321)
- [x] 3. #31: `FORMATS` table; an unknown format fails `format` (on feature/0321)
- [x] 4. #30: beta release support (after #31, because it rewrites the `FORMATS` key) (on feature/0321)
- [x] 5. #44 (D2), then #42 and #43 (on feature/0321)
- [x] 6. #32: DSSE envelope (on feature/0321)
- [x] 7. #33 → #36 → #46 → #37 (on feature/0321)
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
- CI on PR #50 at `59cf77c` (run 44669645652): lint, python-matrix, test (3.12, 3.13, 3.14)
  and build all pass.

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
Impact: BREAKS_USERS
Affected: a tool that imports asexec.MANIFEST_SCHEMA_ID stops working (ImportError); no published manifest (a body that still carries schema_id reads as an unknown field, which nothing examines)
Action: drop any import of asexec.MANIFEST_SCHEMA_ID; read predicateType to identify an asexec body
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

**Review round 1** (findings on PR #50):
- `docs/FORMAT.md:57`: the example labelled `// today (0.3.x)` showed
  `application/vnd.asexec.v1+json`, a value no 0.3.x release wrote → the line is back to
  `application/vnd.asexec+json`. The PAE line at `FORMAT.md:19` (pinned by
  `test_signing_pae_version_and_manifest_payload_type`) and the 0.4.0 examples keep `v1`.
  This corrects the observation above that #32 rewrites that section: #32's scope doesn't
  include `docs/FORMAT.md`, so nothing later would have corrected it.
- The `MANIFEST_SCHEMA_ID` release-note draft named the removed export under *Affected* but
  said *Action: none* → *Action* now says to drop any import of `asexec.MANIFEST_SCHEMA_ID`
  and read `predicateType`. *Impact* is now `BREAKS_USERS`: the header defines it to cover a
  change that "stops an existing ... tool from working", and an `ImportError` does that,
  even though `ROADMAP.md` doesn't promise the Python API.
- `README.md:210-236` and `:255-282`: the `// always` comment after the longer
  `predicateType` value was off the comment column → the whole column in both examples moves
  three places right, so `predicateType` and `target` now fit with two spaces, as the other
  lines have. `declaration` still runs past the column, as it already did.
- Commits: `50a9054` (README, FORMAT.md); the release-note draft and these notes are
  in the commit that follows it. `scripts/check.sh`: clean, 402 passed. CI: see the PR.

**Merged** (orchestrator): PR #50 merged into `feature/0321` as `f17e083`, a merge commit,
with no further review findings open. The #35 change is `da7cbb2`; the review fixes are
`50a9054` and `04dfe45`. The review agent changed each identifier in turn and saw the
pinned tests fail (payloadType `v2`: 8 tests; the old payloadType: 9; an unversioned
predicateType: 6; `schema_id` back on `ManifestBody`: 6), and it re-derived every frozen
vector with an independent PyNaCl script. Post-merge on `feature/0321` at `f17e083`:
`scripts/check.sh` clean, 402 passed; `examples/adequacy-test/run.py` exit 0. CI on the last
PR push (`04dfe45`, run 44670856152): lint, build, test on 3.12, 3.13 and 3.14 pass.

### Checkpoint 2: #26

**Landed** (branch `feature/0321-checkpoint2`):
- #26, `356b6d5`: `BDR` is split into two required tests, `format` and `selfsig`.
  `verifier.TEST_CATALOG` drops `BDR` and adds both, and `verifier.REQUIRED_TEST` becomes
  the set `REQUIRED_TESTS = frozenset({"format", "selfsig"})`. `--tests` without either is
  a usage error naming what is missing. `verify_signature` is replaced by `verify_format`
  and `verify_selfsig`. Each manifest record now has a `format` slice (`ok`, `errors`) and a
  `selfsig` slice (`examined`, `signature_ok`, `keyid_ok`) in place of `signature`. The
  report prints a malformed file's reason as `✗ format: malformed: …`. The CLI help and
  `models.py` comments are updated. `docs/VERIFICATION.md` has new run rules, a section
  and a summary row for each test, the matching table and every example code and report.
  `README.md`, `ROADMAP.md`, `docs/MULTIVERSION.md`, `docs/DEVELOPMENT.md` and
  `docs/FORMAT.md`, the `ci.yml` and `publish.yml` smoke tests, and
  `examples/adequacy-test` (`run.py`, the README's verify step) use the new names.
  `tests/verify/test_verify_bdr.py` is split into `test_verify_format.py` and
  `test_verify_selfsig.py`, and every other test is moved to the new tokens.

**What the split means in this version** (before #31 and #32):
- `format` examines every manifest file found. Its conditions are #1 (readable, a JSON
  object, at most 64 deep, no duplicate key, an object `payload` and `signature`, canonical
  bytes) and #2 (`signature.pubkey` and `signature.sig` are hex). Together these are exactly
  the malformed rule, which is unchanged. *When empty* is the old `BDR` empty case, with the
  reason `no manifests to verify`. #31's unknown-`payloadType` failure has a marked place in
  `verify_format` and in `format`'s *Does not establish* line, and
  `test_not_enforced_yet__envelope_payload_type` is where it will show up. It is not
  implemented.
- `selfsig` examines only files that pass `format`. Its conditions are #1 (the signature
  verifies over the PAE input by `pubkey`) and #2 (`keyid` derives from `pubkey`), which were
  `BDR` #2 and #3. When no file passes `format` (none found included) it is empty and fails
  with `no manifest passes format`. #32's "exactly one signature" is not added.
- Matching condition 2, `keyconsist`'s condition, the `✓`/`✗` in the manifests block and the
  summary tables now read "the `selfsig` conditions".

**Evidence:**
- `scripts/check.sh`: ruff check and format check clean. pytest: 402 passed before
  (`f88881d`), 414 after. The 24 tests of `test_verify_bdr.py` became 22 in
  `test_verify_format.py` and 6 in `test_verify_selfsig.py` (+4). `test_cli.py` has +6 (the
  two new usage-error cases, the three what-is-missing cases, help text) and
  `test_verify_run_rules.py` +2 (the must-include test is parametrized three ways).
- Red first: with only the tests changed, 258 failed and 156 passed. 232 were
  `KeyError: 'format'` (`verify_paths` produced no such result) and 13 were
  `SystemExit: 64` (`--tests format,selfsig` was an unknown test). The rest were 3
  doc-coverage failures (the doc still listed `BDR` #1-#3 and had no `format` or `selfsig`
  items), 3 `parse_tests` error-text mismatches, the `unknown test(s): selfsig, format`
  dedup failure, and the CLI help and missing-test texts. With `verifier.py` and `cli.py`
  changed, only the 3 doc-coverage tests failed, and they passed once
  `docs/VERIFICATION.md` was rewritten.
- Tests that pin each requirement:
  - `format`: `test_format__pass__all`, `__pass__1_nesting_at_the_limit`,
    `__pass__1_brackets_inside_strings_do_not_nest`,
    `__pass__2_hex_accepts_either_case_and_whitespace`, `__fail__1_well_formed_file` (8
    malformed files: each reads `format=FAIL selfsig=PASS`, and selfsig examines 4 of 5),
    `__fail__1_no_duplicate_keys`, `__fail__1_nested_at_most_64_deep`,
    `__fail__1_payload_has_canonical_bytes` (new),
    `__fail__1_missing_file_is_examined_and_malformed`,
    `__fail__1_unlistable_directory_is_examined_and_malformed`,
    `__fail__2_pubkey_and_sig_are_hex`, `__fail__empty_no_manifests`,
    `__fail__empty_directory_with_no_json_files`.
  - `selfsig`: `test_selfsig__pass__all`, `__fail__1_signature_covers_payload`,
    `__fail__1_signature_by_pubkey`, `__fail__2_keyid_derives_from_pubkey` (each
    `format=PASS selfsig=FAIL`), `__fail__empty_no_manifest_passes_format` (every file has a
    non-hex pubkey: `format=FAIL selfsig=FAIL`, applicable 0, its own reason),
    `__fail__empty_no_manifests`.
  - `--tests`: `test_tests_arg__must_include_format_and_selfsig[neither|no-selfsig|no-format]`
    (the error names the missing test(s)), `test_tests_arg__is_deduplicated_in_catalog_order`,
    `tests/test_cli.py::test_verify_bad_tests_is_a_usage_error[no-required|no-selfsig|no-format|unknown|none]`
    (exit 64, no code), `test_verify_tests_without_a_required_test_names_what_is_missing`,
    `test_verify_help_names_both_required_tests`.
  - Codes sorted by name: `test_code__one_token_per_requested_test_sorted_by_name`
    (`chain=PASS format=PASS keyconsist=PASS selfsig=PASS`, either order of request).
  - Malformed reasons attributed to `format`: `test_verify_exit_codes_and_malformed_file`
    (`    ✗ format: malformed: ` under the file, `format=FAIL selfsig=PASS`).
  - Malformed is examined by no other test, `selfsig` included:
    `test_run__malformed_file_fails_format_and_no_other_test_examines_it` and
    `test_run__file_failing_format_is_examined_by_no_other_test`.
  - `tests/test_constants.py::test_manifest_payload_type_change_fails_what_was_signed_before_it`
    now pins `PRE_V1_MANIFEST` as `format=PASS selfsig=FAIL`. Verify doesn't read
    `payloadType` yet, so the 0.3.x signature fails `selfsig` and not `format`. #31 changes
    this to `format=FAIL`.
- **No other verdict changes (the pin).** A pytest plugin (kept in the session scratchpad,
  not in the repo) wraps `verifier.verify_paths`. Every call, the CLI's included, also runs
  on the other version's `verifier.py`, loaded inside the same package. That gives both
  versions the same files, `now`, pinned Roughtime servers and monkeypatched modules, with
  `BDR` mapped to `format` + `selfsig`. The plugin compares every token except the required
  ones, every other result (`result`, `applicable`, `reason`), every manifest record (path,
  phase, ref, keyid, floor, ceiling, content, the malformed errors, and whether the
  signature and keyid conditions hold), the commitments in full (states, counted and
  rejected postregs with reasons, chain, key checks), notarization-only, ceiling trust and
  `checked_at`. It also requires `BDR == (format AND selfsig)`. `src/` differs between the
  two versions only in `verifier.py`, `cli.py` and comments in `models.py`.
  - The old suite at `f88881d` (402 passed), each call also run by the new verifier: 250
    calls over 243 tests, **0 differences**.
  - The new suite (414 passed), each call also run by the old verifier: 254 calls over 247
    tests, **0 differences**.
  - How `BDR` mapped, new suite: `PASS` → `format=PASS selfsig=PASS` 205 times. `FAIL` →
    `format=FAIL selfsig=PASS` 24, `format=PASS selfsig=FAIL` 14, `format=FAIL
    selfsig=FAIL` 11. The old suite is 204 / 23 / 14 / 9.
  - The plugin catches a real change. With the new verifier altered to examine `floor` on
    malformed files, the old suite gave 2 differences
    (`test_floor__fail__empty_malformed_manifest_not_examined` among them).
  - `uv run python examples/adequacy-test/run.py`: exit 0. The four codes are identical
    before and after except for `BDR=PASS` → `format=PASS … selfsig=PASS`
    (`chain=PASS content=PASS format=PASS keyconsist=PASS selfsig=PASS`, and `content=FAIL`
    for the swapped plants), with the same caught/missed results.
- CLI demonstrations, in a scratch dir (`keygen`; `prereg --target "model m via provider
  p"`; `postreg --fulfills prereg.json [--prev postreg-1.json]`; `truncated.json` is the
  first 120 bytes of `prereg.json`; `tampered.json` is `postreg-1.json` with
  `payload.target` changed):
  - Good pair: `asexec verify prereg.json postreg-1.json --tests format,selfsig` prints
    `✓ format=PASS  (2/2 manifest(s) ok)`, `✓ selfsig=PASS  (2/2 manifest(s) ok)`,
    `asexec-verify/1 format=PASS selfsig=PASS`, exit 0.
  - Malformed beside the pair: `... prereg.json postreg-1.json truncated.json` prints
    `✗ truncated.json  [None]  keyid=None` with `    ✗ format: malformed: Unterminated string
    starting at: line 5 column 15 (char 109)` beneath, `✗ format=FAIL  (1/3 manifest(s)
    failed)`, `✓ selfsig=PASS  (2/2 manifest(s) ok)`, `asexec-verify/1 format=FAIL
    selfsig=PASS`, exit 2. The malformed file alone gives `✗ selfsig=FAIL  (no manifest passes
    format)` and `format=FAIL selfsig=FAIL`.
  - Tampered body: `asexec verify prereg.json tampered.json --tests
    format,selfsig,chain,keyconsist` prints `✗ tampered.json  [postreg]`, `[OPEN]`, `✗ postreg
    sha-256:8f1ec88f… does NOT count toward fulfillment: invalid signature`,
    `✓ format=PASS  (2/2 manifest(s) ok)`, `✗ selfsig=FAIL  (1/2 manifest(s) failed)`,
    `asexec-verify/1 chain=FAIL format=PASS keyconsist=FAIL selfsig=FAIL`, exit 2.
  - Empty directory: `asexec verify empty --tests format,selfsig` prints `✗ format=FAIL  (no
    manifests to verify)`, `✗ selfsig=FAIL  (no manifest passes format)`,
    `asexec-verify/1 format=FAIL selfsig=FAIL`, exit 2.
  - `asexec verify prereg.json --tests chain`: `asexec verify: error: argument --tests:
    missing required test(s) 'format', 'selfsig'; every run must include 'format' and
    'selfsig'`, exit 64, no code.
  - `asexec verify prereg.json --tests format,chain`: `... missing required test(s)
    'selfsig'; ...`, exit 64, no code.
  - `asexec verify prereg.json --tests BDR`: `unknown test(s): BDR; available: ceiling,
    chain, content, floor, format, keyconsist, selfsig`, exit 64 (no alias).
  - The `docs/VERIFICATION.md` examples (the full chain, the truncated file, the tampered
    body) were checked against these runs. Only keys and times differ, and those are
    elided or fixed in the doc.
- Nothing left behind: `git grep -n -e BDR -e bedrock -e Bedrock -e BEDROCK -e
  REQUIRED_TEST` over the whole repo, `docs/040b1-PATH.md` aside, finds:
  - `ROADMAP.md:202` (the new bullet saying `BDR` was split), `:550` (*History* 0.2.0,
    "bedrock vs. optional") and `:551` (*History* 0.3.0, "`BDR` token"). Both history rows
    are kept as history.
  - `examples/adequacy-test/README.md:57`: the *Results on asexec 0.3.19* table, a dated
    record (see observations).
  - `src/asexec/manifest.py` (`_BEDROCK_STRUCTURAL`, `_BEDROCK_SEMANTIC`,
    `_check_bedrock`), `src/asexec/models.py:24,213,217,247-248` (the body's
    structural/semantic "bedrock" comments and `ManifestBody._bedrock`) and
    `tests/test_manifest.py` (its tests). This is the builder's own "bedrock", which
    predates the `BDR` token (0.2.0's schema rebalance). Left alone (judgement call below).
  - `REQUIRED_TESTS` in `verifier.py` and `cli.py`: the new name.
  - No `BDR` in `src`, `tests`, `.github`, `scripts`, `docs/VERIFICATION.md`, `README.md`,
    `docs/MULTIVERSION.md`, `docs/DEVELOPMENT.md` or `docs/FORMAT.md`, and no `#bdr`
    anchor, `_bdr` or `test_verify_bdr` anywhere. In `docs/040b1-PATH.md`, the decisions
    (D2, D3), the checklist item and checkpoint 1's notes keep `BDR` as history.
- CI on PR #51 at `c0b3d2d` (run 44674053256): lint, python-matrix, test (3.12, 3.13, 3.14,
  each with the CLI smoke `verify --tests format,selfsig`) and build all pass.

**Observations (out of scope):**
- `examples/adequacy-test/README.md:53-60`: *Results on asexec 0.3.19* still shows `BDR`
  codes. It is labelled as 0.3.19's results, which did print `BDR`, so it is left as a dated
  record. `run.py` and step 4 of the README now use `format,selfsig`, so a run today prints
  the new codes. The table needs a refresh when the example is ported to the claim record
  (ROADMAP, 0.4.0 *Docs*).
- `src/asexec/verifier.py` (`verify_selfsig`) parses `EnvelopeInput` a second time, after
  `verify_format` has already done so. It's cheap and keeps the report free of pydantic
  objects. #32 rewrites both functions for the DSSE frame anyway.
- `src/asexec/models.py:79` (`SignatureInput`): a `signature` without `pubkey` or `sig`
  fails `format` today, because the input model requires both (no test isolates that case;
  the malformed-file cases miss the whole `payload` or `signature`). #32 moves "a missing
  `pubkey` or `sig`" to `selfsig`, and should add that case to `test_verify_selfsig.py`.
- The `=== manifests ===` line for a file that passes `format` but fails `selfsig` shows only
  `✗`, with no reason beneath it (as `BDR` did). A reason line, e.g. `✗ selfsig: signature
  does not verify` or `keyid does not derive from pubkey`, would make it readable on its own.
  Left as it was.
- `src/asexec/verifier.py:397` (`preregs[(rec["ref"], rec["keyid"])]`): verify raises
  `TypeError: unhashable type: 'dict'` on a prereg whose `signature.keyid` is a JSON object
  (or a list), instead of failing it. It is the same on `main` at `fd5b038` (line 361), so it
  predates this checkpoint. A non-string keyid can never pass `selfsig`, so #44 (checkpoint
  5), which stops a prereg that fails `selfsig` from being a commitment, should close it, and
  should add this input as a test. Not fixed here.

**Judgement calls:**
- **Non-hex `pubkey`/`sig` stays in `format` (as #2).** D3a lists `format`'s malformed
  cases as "unreadable, not a JSON object, too deep, a duplicate key, a missing frame". #32
  says that after the DSSE envelope, "malformed means only a missing frame" and "a missing
  `pubkey` or `sig` fails `selfsig`". That is a change #32 makes when it redefines the frame,
  not one this rename makes. In today's envelope the hex check is part of the malformed rule,
  and D3c says this checkpoint is "a rename plus a split over today's checks". Moving it now
  would also change other verdicts. A file with a non-hex `pubkey` would join commitments, as
  a postreg rejected for `invalid signature` rather than not listed (see
  `test_run__malformed_postreg_joins_no_commitment`). It would also be examined by `floor`,
  `ceiling` and `content` (`test_run__file_failing_format_is_examined_by_no_other_test`).
  The instruction to keep every non-required verdict unchanged rules that out. So the
  malformed rule is unchanged, and `format` = not malformed.
- **`_BEDROCK_STRUCTURAL` and the other builder "bedrock" names are not renamed.** #26's
  scope lists code in `verifier.py`, `cli.py` and `models.py` comments. The builder guard
  in `manifest.py` (and the body's "structural/semantic bedrock" in `models.py`) names the
  mandatory body fields a writer must supply. That concept comes from 0.2.0's schema
  rebalance, not from the `BDR` test, and it never reaches a code, a report or a doc. In
  `models.py` only the comments that cited `BDR` #1-#3 changed (to `format` #1-#2 and
  `selfsig` #2).
- **`REQUIRED_TEST` is renamed `REQUIRED_TESTS`** (a `frozenset`), since it is now a set and
  the old name would read as one test. Nothing outside `verifier.py` and `cli.py` used it.
- **The report record changes shape:** `manifests[].signature` is replaced by
  `manifests[].format` and `manifests[].selfsig`. It is the verifier's internal report, not
  a promised output (`--json` is #48), and only one test read it
  (`entry["format"]["errors"]`, previously `entry["signature"]["errors"]`).
- **Error text:** `missing required test(s) 'selfsig'; every run must include 'format' and
  'selfsig'` names what is missing first and then the rule. An empty `--tests` says
  `no tests requested; --tests must list at least 'format' and 'selfsig'`.
- **Test order in `docs/VERIFICATION.md`:** the `format` and `selfsig` sections, and their
  rows in the summary table, sit in alphabetical order (after `floor` and after
  `keyconsist`), matching `TEST_CATALOG` and the code. A sentence under the summary table
  and the run rules say that both are required and that only files that pass `format` are
  examined by any other test. `selfsig` has a failing example (a tampered body,
  `format=PASS selfsig=FAIL`), and `format` adds a malformed-file example. These show what
  each token tells apart, as D3a intends.
- **`selfsig`'s empty reason** is `no manifest passes format`. It is used both when no file
  passes `format` and when no manifest file is found, since in both cases nothing passes
  `format`.
- **Doc-coverage name pattern** is now `[a-z_]+?` (it was `[A-Za-z_]+?`). Every catalog
  name is lowercase now, and an uppercase name like `test_BDR__…` can't match a doc item.
- The *History* rows in `ROADMAP.md` keep `BDR` and "bedrock". The new *Verify* bullet
  says `BDR` was split, "(Done ahead of 0.4.0.)", like checkpoint 1's `schema_id` bullet.
- `examples/adequacy-test/run.py` and step 4 of its README are outside #26's list, but
  `--tests BDR,...` is now a usage error, so the example would have stopped working.
  `docs/FORMAT.md:25` named `BDR` as the test that checks the signature, and now names
  `selfsig`.

**Review round 1** (findings on PR #51):
- The `✓`/`✗` mark in the manifests block (`src/asexec/cli.py:258-259`) had no test. A
  reviewer changed it to read `m["format"]["ok"]` and all 414 tests still passed. Fixed with
  `tests/test_cli.py::test_verify_marks_each_file_by_format_and_selfsig`, which verifies four
  files: a good prereg, a tampered postreg (`format=PASS selfsig=FAIL`), the prereg with
  another key's `keyid` (signature valid, `selfsig` #2 fails) and a truncated file. It
  requires `✓`, `✗`, `✗`, `✗` on their lines, and the `✗ format: malformed:` line only under
  the truncated file. The fourth file goes beyond the finding, because with three files a
  mark that dropped the keyid check still passed. Run against deliberately broken marks:
  - `OK if m["format"]["ok"]` fails this test (1 failed, 416 passed).
  - `OK if ss["signature_ok"]` fails it (1 failed).
  - `OK if ss["keyid_ok"]` fails it (1 failed).
  - A reason printed without the `format:` prefix fails it and
    `test_verify_exit_codes_and_malformed_file` (2 failed).
  - Restored: 417 passed.
- Nothing pinned that `BDR` is gone. An alias in `parse_tests` passed the suite. Fixed by
  adding `BDR` and `BDR,format,selfsig` cases to
  `test_verify_bad_tests_is_a_usage_error`: exit 64, no code, and `unknown test(s): BDR;` on
  stderr. With an alias mapping `BDR` to `format,selfsig` planted in `parse_tests`, both new
  cases fail (2 failed, 415 passed).
- A non-object `signature.keyid` on a prereg raises `TypeError` at `verifier.py:397`. This
  is out of scope and predates this checkpoint, so it moved to the observations above, for
  #44 to close and test.
- The builder comments at `src/asexec/models.py:213` and `src/asexec/manifest.py:36` called
  `predicateType`/`phase` "the format frame", which now reads like the `format` test. They
  say "body frame" now (comments only, nothing renamed).
- Commit: `b66bd01`. `scripts/check.sh`: clean, 417 passed (414 + 1 mark test + 2 `BDR`
  cases). CI on `b66bd01` (run 44676319652): lint, python-matrix, test (3.12, 3.13, 3.14)
  and build pass.

**Merged** (orchestrator): PR #51 merged into `feature/0321` as `f1f2093`, a merge commit,
with no review findings left open. The #26 change is `356b6d5`, and the review fixes are
`b66bd01`. The review agent ran its own old-vs-new comparison of the installed packages
(`f88881d` vs `89ed95f`): 646 runs of 1 to 6 paths, every optional test on, over valid,
tampered, malformed and missing inputs. Every non-required result, every report block, and
the CLI output and exit status matched, and `BDR` always equalled `format AND selfsig`. It
found the ✓/✗ mark and the `BDR`-is-gone rule unpinned; both are pinned now and shown to
fail when broken. Post-merge on `feature/0321` at `f1f2093`: `scripts/check.sh` clean, 417
passed; `examples/adequacy-test/run.py` exit 0. CI on the last PR push (`ba01f26`, run
44676473727): lint, build, test on 3.12, 3.13 and 3.14 pass. Carried forward: the
non-string `signature.keyid` crash, noted above, goes to checkpoint 5 (#44).

### Checkpoint 3: #31

**Landed** (branch `feature/0321-checkpoint3`):
- #31, `6e6c7cf` (with `80689ab`, test literals): `constants.FORMATS` holds the rules of each
  `payloadType` verify reads, and verify reads each file under its own entry. It has one
  entry, keyed by the name `MANIFEST_PAYLOAD_TYPE`, with `digest_ref_prefix`,
  `signing_key_alg`, `signing_pae_version` and `subject_default_hash_alg`.
  `SIGNING_PAE_VERSION`, `DIGEST_REF_PREFIX` and `SIGNING_KEY_ALG` are removed.
  `SUBJECT_DEFAULT_HASH_ALG` stays, as the signing default only (now `NEW_OUTPUT`). The
  entry's `subject_default_hash_alg` is verify's fallback. `canonical.pae` takes the PAE
  version, and `signing_input`, `manifest.ref` and `keys.keyid_for` take a `payload_type`
  (by default the one signing writes). Verify passes the file's own type to `selfsig`, to
  the ceiling nonce and to `content`'s fallback. `EnvelopeInput` gains `payloadType: str`.
  New `format` #3: a string `payloadType` that is not a `FORMATS` key fails `format`, with
  one of three stable reasons. It is checked before this format's frame. A missing or
  non-string `payloadType` is malformed (#1). `docs/VERIFICATION.md`, `docs/MULTIVERSION.md`
  and `ROADMAP.md` are updated (below).

**How it reads now:**
- `format` #1's frame is an object `payload`, a **string `payloadType`** and an object
  `signature`. A missing or `null` `payloadType` gives `malformed: payloadType: Field
  required`, and one that is not a string gives `malformed: payloadType: Input should be a
  valid string`.
- `format` #3: `payloadType` names a `FORMATS` key, compared exactly. A string that names
  none fails `format` with one of three reasons:
  - `application/vnd.asexec+json` (what 0.2.0 to 0.3.20 wrote): `payloadType names the
    format of asexec before 0.4.0, which is not supported: re-sign with this release`.
  - `application/vnd.asexec.X.Y.ZbN+json`: `payloadType names an asexec beta format, and
    betas are not supported`.
  - Any other string: `payloadType names a format newer than this release: upgrade asexec
    to read it`.

  #3 runs before the frame check. A file of an unknown format is held only to "readable
  JSON object, at most 64 deep, no duplicate key", so a later format that lays its file out
  differently still gets the upgrade reason and not `malformed`. A file that fails #3 is
  treated as a malformed file is: no other test examines it, it joins no commitment, and
  it shows `✗` with the reason beneath.
- `docs/VERIFICATION.md`:
  - *Property paths* names `payloadType`, and a new *Formats* convention gives the v1 rules.
  - The run rules define *malformed* (now including "a string `payloadType`") and *unknown
    format*; both fail `format` and are examined by nothing else.
  - The summary row, *Examines* (`payloadType`), #1, the new #3 and the failure reasons are
    updated. *Does not establish* loses its "does not read `payloadType`" clause, and there
    is a version-skew example.
  - `ceiling`, `content` and `floor` read "a manifest that fails `format`" and "no manifest
    that passes `format`" where they said malformed or well-formed. The matching table's
    first row is "Malformed, or of an unknown format". `selfsig` #1 names the file's
    `payloadType`.
- `docs/MULTIVERSION.md`:
  - Status is "partly built": step 1 is built except its frozen 0.4.0 manifest, which #32
    regenerates. The selector reads the top-level `payloadType` until the DSSE switch.
  - The design block is the built entry, and the unknown-format bullet lists the three
    reasons.
  - Each per-identifier row says where the value now lives.
  - *Testing* and *Plan* step 1 mark what is built. Nothing else is claimed.
- `ROADMAP.md`: the identifiers bullet names the entry's `signing_pae_version`. The support
  section says MULTIVERSION is built in part. The `dsse.payloadType` bullet is marked done
  ahead of 0.4.0 on the top-level `payloadType`.

**Evidence:**
- `scripts/check.sh`: ruff check and format check clean; pytest **417 passed before**
  (`ffbc79c`), **442 after**. By file: `test_verify_format.py` 22 → 38, `test_constants.py`
  15 → 19, `test_verify_run_rules.py` 40 → 44, `test_cli.py` 79 → 81,
  `test_verify_planted_faults.py` 26 → 25 (the `payloadType-missing` case moved to `format`).
- Red first: with only the tests changed, 34 failed and 408 passed. The failures were
  `format=PASS` where `format=FAIL` was expected (14 codes, the CLI exit status), `module
  'asexec.constants' has no attribute 'FORMATS'` (8), `pae() takes 2 positional arguments`
  (2), the doc-coverage test (`('format', 3)` has no doc item), the IMPACT set,
  `PRE_V1_MANIFEST` reading `format=PASS selfsig=FAIL`, and the reason lists. With the code
  in place only the doc-coverage test failed. It passed once `docs/VERIFICATION.md` had #3.
- Tests that pin each requirement:
  - `format` #3: `test_format__fail__3_payload_type_names_a_known_format`, with 9 cases:
    `v2`, `v10`, `not-asexec`, `empty`, `other-case` (the current type in capitals),
    `trailing-space`, `beta` (`0.3.0b1`), `beta-wide` (`1.12.3b20`) and `before-0.4.0`. Each
    gives `format=FAIL selfsig=PASS`, format `1/4 manifest(s) failed`, selfsig applicable 3,
    and its exact reason.
  - `test_format__fail__3_unknown_format_is_not_judged_by_this_formats_frame`: a
    `{payloadType: v2, dsse: …}` file gets the upgrade reason, not `malformed`.
  - `test_format__fail__3_never_falls_back_to_this_releases_rules`: a file signed over
    `asexec-PAE/v1` with the v2 type in its PAE, which a fallback to v1's rules would accept,
    fails `format`.
  - `format` #1: `test_format__fail__1_payload_type_is_a_string` (missing, `null`, number,
    list, object), each with its exact `malformed: payloadType: …` reason.
    `test_format__pass__all` now names #1-#3. The `missing-payload` and
    `missing-signature` malformed files now carry a `payloadType`, so each still lacks only
    the one property.
  - Treated as malformed (run rules):
    - `test_run__malformed_file_fails_format_and_no_other_test_examines_it[unknown-format]`:
      a relabelled copy of the prereg, ceiling and all, gives `ceiling=PASS chain=PASS
      content=PASS format=FAIL keyconsist=PASS selfsig=PASS`.
    - `test_run__file_failing_format_is_examined_by_no_other_test[unknown-format]`: floor,
      ceiling and content are not examined.
    - `test_run__malformed_postreg_joins_no_commitment[newer-format|beta-format]`: neither
      counted nor rejected nor notarization-only, and `keyconsist` applicable 0.
  - The selector itself (`tests/test_constants.py`), with a second entry added through
    `monkeypatch.setitem` whose every rule but `signing_key_alg` (ed25519 in both) differs
    from v1's:
    - `test_formats__a_file_is_read_under_its_own_entry`: `signing_input(…, OTHER)` starts
      `asexec-PAE/other 33 application/vnd.asexec.other+json`. Its file and a v1 file both
      pass `format` and `selfsig` (each PAE and keyid prefix), the refs start `other-256:`
      and `sha-256:`, and `content`'s fallback is per entry (`algorithm unavailable:
      'no-such-alg'` for one, `ok` for the other).
    - `test_formats__payload_type_is_signed_so_relabelling_fails_selfsig`: either file
      relabelled with the other known type gives `format=PASS selfsig=FAIL`
      (MULTIVERSION's *Tampering* test).
    - `test_formats__signing_uses_the_entry_of_manifest_payload_type`: the new entry does not
      change what signing writes.
  - Constants: `test_formats_has_one_entry_keyed_by_manifest_payload_type`
    (`list(FORMATS) == [MANIFEST_PAYLOAD_TYPE]`, and the entry equals a literal dict of all
    four values). `test_signing_pae_version_and_manifest_payload_type`,
    `test_digest_ref_prefix`, `test_signing_key_alg` and the new
    `test_format_subject_default_hash_alg` pin each value again with what it does.
    `test_subject_default_hash_alg` is now the signing default, `NEW_OUTPUT`, and
    `test_every_identifier_is_classified` checks the new IMPACT.
    `test_manifest_payload_type_change_fails_what_was_signed_before_it` now requires
    `PRE_V1_MANIFEST` to give `format=FAIL selfsig=FAIL` with the pre-0.4.0 reason.
    `test_not_enforced_yet__envelope_payload_type` is removed, because it is enforced now.
  - CLI: `tests/test_cli.py::test_verify_version_skew_reads_as_format_not_signature[newer|beta]`
    checks the `✗ <file>  [postreg]  keyid=None` line, the `    ✗ format: <reason>` line
    under it, `✓` for the prereg, `[OPEN]`, `format=FAIL (1/2 …)`, `selfsig=PASS (1/1 …)`
    and exit 2.
  - `tests/test_primitives.py::test_pae_is_unambiguous` covers the three-argument `pae`.
- **Signed bytes unchanged:**
  - The frozen vectors pass unedited (`test_frozen_manifests_still_verify` and the PAE
    literal in `test_signing_pae_version_and_manifest_payload_type`).
  - `git diff ffbc79c -- tests/test_constants.py` doesn't touch a vector. An AST comparison
    of the `FROZEN_KEY`, `FROZEN_BODY`, `FROZEN_MANIFEST`, `FROZEN_NO_HASH_ALG_MANIFEST` and
    `PRE_V1_MANIFEST` assignments at `ffbc79c` and now finds them identical, and no `-`/`+`
    line of the diff holds a signature or key hex.
  - Independently, a script (in the session scratchpad) ran on the pre-change worktree
    (`ffbc79c`) and on this branch. It writes `signing_input`, `manifest.sign`'s envelope and
    `ref` for three bodies (a prereg; one with `due` and a non-ASCII structured
    `declaration`; a postreg with `prev_hash`), with a fixed key, plus `keyid_for` and
    `identity.build_wellknown`. The two outputs are byte-identical (sha256 `90df7f42…` for
    both).
  - Each run imported its own `asexec/constants.py`, checked by whether `FORMATS` exists.
- CLI demonstrations, in a scratch dir. The files:
  - `keygen`; `prereg --target "model m via provider p"`; `postreg --fulfills prereg.json`
    → `postreg-1.json`.
  - `postreg-v2.json` and `postreg-beta.json` are `postreg-1.json` with `payloadType` set to
    `application/vnd.asexec.v2+json` and `application/vnd.asexec.0.4.0b1+json`.
  - `old-0.3.20.json` is a prereg signed by the real 0.3.20 CLI (`git worktree add <scratch>
    v0.3.20`; `asexec --version` printed `asexec 0.3.20`; its `payloadType` is
    `application/vnd.asexec+json`). 0.3.20's own verifier gives it `asexec-verify/1 BDR=PASS`.

  Each command is `asexec verify prereg.json <file> --tests format,selfsig,chain,keyconsist`:
  - With `postreg-v2.json`: `✓ prereg.json  [prereg]  keyid=sha-256:6dd1ef2d…`, then
    `✗ postreg-v2.json  [postreg]  keyid=None` with `    ✗ format: payloadType names a format
    newer than this release: upgrade asexec to read it` beneath. Then `[OPEN] prereg
    sha-256:b17107d0…` (`postregs : 0`), `✗ format=FAIL  (1/2 manifest(s) failed)`,
    `✓ selfsig=PASS  (1/1 manifest(s) ok)` and `asexec-verify/1 chain=FAIL format=FAIL
    keyconsist=FAIL selfsig=PASS`, exit 2.
  - With `postreg-beta.json`: the same, with `    ✗ format: payloadType names an asexec beta
    format, and betas are not supported`.
  - With `old-0.3.20.json`: `✗ old-0.3.20.json  [prereg]  keyid=None` and `    ✗ format:
    payloadType names the format of asexec before 0.4.0, which is not supported: re-sign with
    this release`, then `format=FAIL`, `selfsig=PASS (1/1)`, exit 2.
  - All five files: `[FULFILLED]` by `postreg-1.json`, `✗ format=FAIL  (3/5 manifest(s)
    failed)`, `✓ selfsig=PASS  (2/2 manifest(s) ok)`, `asexec-verify/1 chain=PASS
    format=FAIL keyconsist=PASS selfsig=PASS`, exit 2.
  - The good pair alone: `asexec-verify/1 chain=PASS format=PASS keyconsist=PASS
    selfsig=PASS`, exit 0.

  The same files under the pre-change verifier (`ffbc79c`):
  - `postreg-v2.json` and `postreg-beta.json` **passed everything**: `✓`, keyid shown,
    `chain=PASS format=PASS keyconsist=PASS selfsig=PASS`. Verify checked under the constant,
    so a type changed after signing went unseen.
  - `old-0.3.20.json` gave `format=PASS selfsig=FAIL`, a bad signature, with no word about
    the format.
- Release-commit rehearsal for #30, on a scratch copy and reverted: `sed` on the one line
  `MANIFEST_PAYLOAD_TYPE = "…"` to `application/vnd.asexec.0.4.0b1+json`, with no other edit.
  4 tests failed and 438 passed. The failures were the literal pin
  (`test_signing_pae_version_and_manifest_payload_type`), `test_frozen_manifests_still_verify`,
  `test_not_enforced_yet__predicate_type` and `test_not_enforced_yet__signature_alg`. The
  last three read `FROZEN_MANIFEST` (see observations).
- `uv run python examples/adequacy-test/run.py`: exit 0, the same codes and caught/missed
  results as after checkpoint 2.
- Nothing left behind: `git grep -n -e SIGNING_PAE_VERSION -e DIGEST_REF_PREFIX -e
  SIGNING_KEY_ALG -e 'does not read payloadType' -e envelope_payload_type -e
  payloadType-missing` outside `docs/040b1-PATH.md` finds only the three rows of
  `docs/MULTIVERSION.md`'s per-identifier table, which name the old identifiers on purpose
  and say where each now lives. `keys.py` keeps a private `_ALG` read from the signing entry.
- CI on PR #52 at `d8d8c80` (run 44679335086): lint, python-matrix, test (3.12, 3.13, 3.14)
  and build pass.

**Observations (out of scope):**
- For #30:
  - `release.sh` needs to rewrite only the one `MANIFEST_PAYLOAD_TYPE = "…"` line in
    `src/asexec/constants.py`. `FORMATS` is keyed by that name, so its key follows.
  - In `tests/test_constants.py`, the literals it must rewrite (or the D6b skip must cover)
    are all in `test_signing_pae_version_and_manifest_payload_type`: the type, the PAE
    bytes, and `_signed_prereg()["payloadType"]`.
  - The D6b skip must also cover `test_not_enforced_yet__predicate_type` and
    `test_not_enforced_yet__signature_alg` (`tests/test_constants.py:372-381`). They verify
    `FROZEN_MANIFEST`, a v1 file, which a beta build reads as an unknown format.
  - `docs/VERIFICATION.md` (*Formats*, `format` #3) names `application/vnd.asexec.v1+json`
    as the one format read. On main after b1 that is the beta type (D6a), so the doc will
    describe 0.4.0, not main.
- For #32:
  - Its scope names "the `SIGNING_PAE_VERSION` literal". That literal is now
    `FORMATS[MANIFEST_PAYLOAD_TYPE]["signing_pae_version"]` in `src/asexec/constants.py`.
  - `verify_format` (`src/asexec/verifier.py:224`) reads the top-level `payloadType`, and
    `EnvelopeInput.payloadType` (`src/asexec/models.py:92`) is its frame field. Both move to
    `dsse.payloadType`. The #3 check should still come before the new frame, so a later
    format keeps the upgrade reason.
  - `tests/manifest_data.py` `sign_labelled` hardcodes `b"asexec-PAE/v1"`.
- The manifests block still shows `payload.phase` for a file of an unknown format (`[postreg]`
  in the demos), read from a body this release can't interpret. It is display only and no
  verdict depends on it, and malformed files show it the same way. Left as it is, since the
  checkpoint says to treat them exactly as malformed files are.
- `signing_key_alg` is data only on the verify side. `keys.verify` is ed25519 whatever the
  entry says, and `signature.alg` is still not read (`test_not_enforced_yet__signature_alg`).
  With one algorithm there is nothing to dispatch on, so a second algorithm needs a dispatch
  in `keys.verify`.
- The "newer" reason covers every unrecognised string, including ones that are not asexec
  types at all (`application/something-else`). #31 specifies two kinds of reason, and a
  fourth, "not an asexec type", wasn't added.

**Judgement calls / new paradigms:**
- **Entry structure:** a plain `dict[str, dict]`, the convention of `drand.CHAINS` and
  `roughtime.SERVERS`. It is not a class or a `NamedTuple`. The field names are the old
  constant names in lowercase, so each value can be traced to the identifier it replaced
  (and to the release notes). `docs/MULTIVERSION.md`'s example now shows the built shape.
- **The key is the name, not a second literal.** `FORMATS = {MANIFEST_PAYLOAD_TYPE: {...}}`
  keeps one definition of the type, which is `constants.py`'s rule. #30 then rewrites one
  line, and the key can't disagree with the constant.
  `test_formats_has_one_entry_keyed_by_manifest_payload_type` pins both the one entry and the
  key. `FORMATS` therefore sits just after `MANIFEST_PAYLOAD_TYPE`, out of alphabetical
  order, and its comment says why. The name key is only for the entry under development:
  the 0.4.0 release commit (at the latest, before any later release commit) makes the `v1`
  key its literal (corrected in review round 1, below).
- **`SUBJECT_DEFAULT_HASH_ALG` split, not removed.** `docs/MULTIVERSION.md` says to split it.
  The entry holds verify's fallback, and the constant stays as the signing default
  (`hashing`, `manifest._build`, the CLI's `--hash-alg`), reclassified `NEW_OUTPUT`: signing
  always writes `hash_alg` beside a subject, so changing it alters only new files. The other
  three constants are removed. Their signing-side readers (`keys`, `identity`, the writer
  `Signature` model, the CLI's `REF_RE`, `manifest.ref`) now read the newest entry. That
  goes beyond #31's listed files, but it is what "replaces the single constants" requires.
- **Absent and non-string `payloadType` are malformed (#1), not #3.** This is the
  conservative reading: they fail `format`, and nothing falls back. They belong to the
  frame, as D3a's "a missing frame" and #32/ROADMAP's malformed rule ("`dsse` with
  `payloadType`") put it, and they read like a missing `payload`. Their reasons are
  pydantic's, as for every frame field, and the tests pin them exactly, so a pydantic upgrade
  that rewords them fails a test.
- **A pre-0.4.0 reason of its own.** The upgrade reason would be wrong for a 0.3.x file, since
  upgrading can't help. The verifier recognises the one type 0.2.0 to 0.3.20 wrote, checked
  in the tags, only to give the reason. It is a private literal in `verifier.py`, not a
  `constants.py` identifier, because nothing writes it.
- **Reasons are fixed strings with no file content**, like `REASON_INVALID_SIGNATURE`, so
  nothing from the file reaches the terminal. They start with `payloadType`, without
  `malformed:`, because the file is not damaged.
- **#3 before the frame** (above): otherwise a future format with another layout would read
  as `malformed`, which is what D3 is meant to prevent.
- **`tests/manifest_data.py` signs with `MANIFEST_PAYLOAD_TYPE`** rather than its own copy of
  the literal. Verify now reads that field, so a copy would break every verify test under
  #30's beta type. The literal stays pinned in `tests/test_constants.py`. For the same
  reason (`80689ab`), the new tests take the current type from the constant, and use the
  beta `0.3.0b1`, which no release reads, rather than `0.4.0b1`, which b1 will read.

**Release-note entries** (for #40, in the `tests/test_constants.py` header format):

```
Identifier: SIGNING_PAE_VERSION, DIGEST_REF_PREFIX, SIGNING_KEY_ALG -> removed from asexec.constants; now FORMATS[<payloadType>]["signing_pae_version" | "digest_ref_prefix" | "signing_key_alg"], values unchanged
Impact: BREAKS_USERS
Affected: a tool that imports these names from asexec.constants (ImportError); no published manifest (signed bytes, refs and keyids are unchanged)
Action: read constants.FORMATS[constants.MANIFEST_PAYLOAD_TYPE][...] instead

Identifier: FORMATS (new), the rules of each payloadType verify reads; verify now reads payloadType
Impact: BREAKS_USERS
Affected: a manifest whose payloadType is not a FORMATS key now fails format with a reason (0.3.x manifests: format=FAIL "... before 0.4.0 ... re-sign", where selfsig=FAIL before); a manifest with no string payloadType is malformed
Action: re-sign 0.3.x manifests with this release

Identifier: SUBJECT_DEFAULT_HASH_ALG, sha-256 (unchanged), reclassified BREAKS_USERS -> NEW_OUTPUT
Impact: NEW_OUTPUT
Affected: nothing published (verify's fallback is now FORMATS[...]["subject_default_hash_alg"])
Action: none
```

**Review round 1** (findings on PR #52):
1. `selfsig` reads `payloadType` (the PAE input and the keyid prefix), and `content` reads it
   for its default `hash_alg`, but neither listed it under *Examines* → added to both
   sections and to both summary rows. `selfsig` #2 now notes that `sha-256:` is the format's
   prefix. Commit `514ba6c`.
2. `README.md:202-203` says fields marked `required` are the ones without which a file is
   malformed, but `payloadType` wasn't marked → both envelope examples mark it
   `// required: the format; must be one this release reads`. Commit `58ce175`.
3. A prereg that fails `format` makes a postreg naming it notarization-only, and neither the
   doc nor a test said so. *Matching postregs to commitments* now defines a **provided
   prereg** as one that passes `format`, and adds that a prereg failing it is no commitment,
   so a postreg naming it is notarization-only. The run rule says "as a prereg it is no
   commitment, and as a postreg it is neither counted nor rejected". Test:
   `test_run__prereg_failing_format_is_not_a_provided_prereg[bad-hex|newer-format]` (no
   commitment, the postreg notarization-only with its `fulfills`, `keyconsist` applicable 0,
   `selfsig` applicable 1). The behaviour already held, so the test was checked against a
   planted change in `verify_paths` that keeps a prereg failing `format` as a commitment.
   Both cases failed under it and passed once it was reverted. Commit `514ba6c`.
4. The name key contradicted "existing entries are never edited", and its trigger ("when a
   second format is added") was too late. After 0.4.0, any release commit that rewrites the
   type would re-key the released `v1` entry. The reviewer showed it: a `sed` to
   `application/vnd.asexec.0.5.0b1+json` makes `FROZEN_MANIFEST` fail with "newer than
   this release" → the `constants.py` comment, the
   `test_formats_has_one_entry_keyed_by_manifest_payload_type` comment and
   `docs/MULTIVERSION.md` (*Verifier design*, *New format*) now say that only the entry
   under development has the name key. They also say the 0.4.0 release commit (at the
   latest, before any later release commit rewrites the literal) makes the key the literal
   `application/vnd.asexec.v1+json`, which never changes after that. The judgement call
   above is corrected to match. #30 is not implemented here (see observations). Commit
   `58ce175`.
5. #40's release-note list names `SIGNING_PAE_VERSION`, which no longer exists → moved to
   observations (below).
6. `tests/test_constants.py` and these notes said every `OTHER_RULES` rule differs from
   v1's, but `signing_key_alg` is `ed25519` in both → both reworded. Commit `58ce175`.
7. The malformed definition ("lacks an object `payload`") also fits a later format's file
   with another layout → the run rule now says a readable JSON object with an unknown
   `payloadType` is judged by #3 instead of the rest of #1 and #2, so it is of an unknown
   format and never malformed. Commit `514ba6c`.
8. The `docs/MULTIVERSION.md` banner still called the whole document a proposal → it now
   says the *Status* line marks which part describes current behavior. Commit `58ce175`.

`scripts/check.sh`: clean, 444 passed (442 + the 2 new run-rule cases). CI on `3f62b80`
(run 44681321756): lint, python-matrix, test (3.12, 3.13, 3.14) and build pass.

**Observations added in review round 1 (out of scope):**
- **#44 (checkpoint 5), an intended contrast:** a prereg that fails `format` is not a provided
  prereg, so a postreg naming it is notarization-only (finding 3). Under D2, a prereg that
  passes `format` but fails `selfsig` is also not a commitment, but it is listed under
  *rejected pre-registrations*, and a postreg naming it is listed as rejected under it, not
  as notarization-only. The difference is intended. A file that fails `format` can't be read
  under any rules this release has, so nothing can be said about what it names. One that
  passes `format` is readable, and only its signature is in question.
- **#30 (checkpoint 4), the frozen-vector skip:** D6b's skip ("when `MANIFEST_PAYLOAD_TYPE`
  is a beta type") should apply only while it is a 0.4.0 beta, that is, before any format
  has been released. Otherwise, after 0.4.0, a beta release commit would skip every test
  that guards the `v1` entry, at the same time as it could be re-keying that entry. With a
  `0.5.0b1` type, all four tests that read the frozen `v1` vectors would be skipped. An
  alternative is a pin that `application/vnd.asexec.v1+json` is a `FORMATS` key whenever
  the type is not a 0.4.0 beta. #30 should also make the `v1` key a literal in the 0.4.0
  release commit (finding 4), or say which step does.
- **#40:** its body has the release notes name `SIGNING_PAE_VERSION` (#32's change). That
  constant no longer exists. Its value is `FORMATS[MANIFEST_PAYLOAD_TYPE]["signing_pae_version"]`,
  so the release-note entry for the PAE prefix should name that field.

**Merged** (orchestrator): PR #52 merged into `feature/0321` as `0c9c580`, a merge commit,
with no review findings left open. The #31 change is `6e6c7cf` and `80689ab`, and the review
fixes are `514ba6c` and `58ce175`. The review agent reverted each per-file rule to the global
default in turn (PAE type, keyid prefix, ref prefix, `content`'s default `hash_alg`, the #3
check, its order before the frame, normalising `payloadType` with `.strip()`): a test caught
every one. The only exception is the ceiling nonce, where the prefix has no effect because
Roughtime binds the hex. It also ran about 25 junk or near-miss `payloadType` values through
`verify_paths` and the CLI, and none raised. Post-merge on `feature/0321` at `0c9c580`:
`scripts/check.sh` clean, 444 passed; `examples/adequacy-test/run.py` exit 0. CI on the last
PR push (`f12368c`, run 44681499571): lint, build, test on 3.12, 3.13 and 3.14 pass.
Carried forward to checkpoint 4 (#30): limit the frozen-vector skip to 0.4.0 betas, or pin
that the `v1` key exists, as the review round 1 notes above say.

### Checkpoint 4: #30

**Landed** (branch `feature/0321-checkpoint4`):
- #30, `da4a4c2`: `scripts/release.sh` accepts `X.Y.Z` and the PEP 440 beta `X.Y.ZbN`, and
  its release commit sets the `payloadType`. `.github/workflows/publish.yml` creates a beta's
  GitHub release with `--prerelease`, and `verify-release` admits only those two tag forms.
  In `tests/test_constants.py`, the frozen `v1` vectors are skipped in a `0.4.0` beta build
  only, a sign-then-verify roundtrip runs in every build, and a never-skipped test pins the
  `v1` key. `docs/DEVELOPMENT.md` documents all of it. The `src/asexec/constants.py`
  comments now name `release.sh` as what rewrites the literal and the key.

**How it works now:**
- **Versions:** `^N\.N\.N(bN)?$`, where `N` is `0|[1-9][0-9]*`. `X.Y.ZaN`, `rcN`, `.devN`,
  `.postN`, `X.Y`, a leading `v`, `-b1`, `B1` and leading zeros are refused (exit 2) before
  anything is touched. Every earlier safeguard stays: clean tree, `main` only, versions
  agree and are new, no local or remote tag, the check script, `git diff --check`, the tag
  points at the release commit, and the remote tag is verified.
- **The rewrite:** one Python step computes every edit, and writes nothing unless all of
  them match:
  - `__version__` and `version` (as before);
  - `^MANIFEST_PAYLOAD_TYPE = "…"$` in `src/asexec/constants.py`;
  - `^    assert constants\.MANIFEST_PAYLOAD_TYPE == "…"$` in `tests/test_constants.py`,
    which is now the one line in that file that holds the literal.

  Each rewrite must match exactly one line, or the release stops. The type:
  - A beta: `application/vnd.asexec.X.Y.ZbN+json`. There must be exactly one `FORMATS`
    entry keyed by the name (`^    MANIFEST_PAYLOAD_TYPE: \{$`), the entry under
    development the beta signs with. Its key moves with the literal, and is not edited.
  - A full release: `RELEASE_PAYLOAD_TYPES = {"0.4": "application/vnd.asexec.v1+json"}`. A
    line with no entry (`0.5.0`, `1.0.0`) is refused.
  - The first full release of a line, `X.Y.0` (so `0.4.0`), also rewrites the name key to
    the literal (`    "application/vnd.asexec.v1+json": {`). A later `X.Y.Z` requires the
    literal key exactly once and no name-keyed entry.
- **Cleanup:** `git restore` now covers `src/asexec/constants.py` and
  `tests/test_constants.py` as well as `__init__.py`, `pyproject.toml` and `uv.lock`, and
  the release commit adds the two payloadType files.
- **The skip** (`frozen_v1` mark): `_is_0_4_0_beta(MANIFEST_PAYLOAD_TYPE)`, a full match of
  `application/vnd\.asexec\.0\.4\.0b[0-9]+\+json`. The reason is "a 0.4.0 beta build does
  not read v1, the frozen vectors' format (D6b)". It marks every test that reads a frozen
  vector under the `v1` entry:
  - `test_frozen_manifests_still_verify`;
  - `test_signing_input_of_the_frozen_v1_vector` (new: the `v1` PAE literal, moved out of
    `test_signing_pae_version_and_manifest_payload_type` so the pinned type is one line);
  - `test_not_enforced_yet__predicate_type`;
  - `test_not_enforced_yet__signature_alg`.

  The other readers of the vectors don't need the `v1` entry, and pass in a beta build
  (shown below):
  - `test_manifest_payload_type_change_fails_what_was_signed_before_it` compares payloads and
    verifies `PRE_V1_MANIFEST`.
  - `test_formats__payload_type_is_signed_so_relabelling_fails_selfsig` relabels
    `FROZEN_MANIFEST` to the test's own second format.
  - `test_formats__a_file_is_read_under_its_own_entry` takes only a payload, and signs it
    under the current type.
- **The roundtrip:** `test_current_format_sign_then_verify_roundtrip` runs in every build. It
  takes a prereg from the production writer (`build_prereg` with a `build_subject` subject,
  then `manifest.sign`), and a body with no `hash_alg` signed under `MANIFEST_PAYLOAD_TYPE`
  with the entry's default digest. Through `verify_paths` with `content,format,selfsig`, both
  must pass, with `2/2 manifest(s) ok` for `format` and `selfsig`, `content` `ok` for each,
  and the entry's prefix on every ref and keyid. The same two files with `target` changed
  after signing give `format=PASS selfsig=FAIL` (`2/2 manifest(s) failed`).
- **The invariant:** `test_v1_is_read_by_every_build_but_a_0_4_0_beta`, never skipped:
  `_is_0_4_0_beta(MANIFEST_PAYLOAD_TYPE) or "application/vnd.asexec.v1+json" in FORMATS`.
  `test_frozen_v1_vectors_are_skipped_only_in_a_0_4_0_beta` pins the predicate on 8 strings:
  `0.4.0b1` and `0.4.0b12` are skipped; `v1`, `0.5.0b1`, `0.4.1b1`, `10.4.0b1`, `0.4.0rc1`
  and `0.4.0b1` with a trailing space are not.
- **publish.yml:**
  - `verify-release` fails a tag that is not `vX.Y.Z` or `vX.Y.ZbN`, before any upload. The
    trigger glob `v[0-9]*.[0-9]*.[0-9]*` also matches `rc`, `a` and `.dev` tags.
  - `github-release` adds `--prerelease` for `^v[0-9]+\.[0-9]+\.[0-9]+b[0-9]+$`.
  - Nothing else needed changing for a beta:
    - The trigger glob matches `v0.4.0b1`.
    - The tag/version equality compares the same strings `release.sh` wrote.
    - `uv build` names the files `asexec-0.4.0b1-py3-none-any.whl` and
      `asexec-0.4.0b1.tar.gz`, which the `dist` globs expect, because the version is
      normalized.
    - `uv pip install "asexec==0.4.0b1"` selects the beta without `--prerelease`, since an
      exact pin names a prerelease explicitly.
    - `asexec --version` prints `asexec 0.4.0b1`, which contains the tag version.
    - The CLI smoke signs and verifies under the beta's own type.

**Evidence:**
- `scripts/check.sh`: ruff check and format check clean; pytest **444 passed before**
  (`9a71e7f`), **455 after**. `tests/test_constants.py` went from 19 to 30: the PAE vector
  test, the invariant, 8 predicate cases and the roundtrip.
- Red first:
  - The old `release.sh` in the throwaway clone: `scripts/release.sh --no-check 0.4.0b1` →
    `Error: version must look like X.Y.Z`, exit 2.
  - The old tests, under a release commit made by hand (`sed` on the two literal lines to
    `0.4.0b1`): 4 failed, 440 passed. The failures were
    `test_frozen_manifests_still_verify`, `test_signing_pae_version_and_manifest_payload_type`
    (its PAE literal), `test_not_enforced_yet__predicate_type` and
    `test_not_enforced_yet__signature_alg`.
  - The new tests under the same edit: 451 passed and 4 skipped, each with the D6b reason.
- **Rehearsals.** A script in the session scratchpad clones this repo (`--no-tags`) at
  `da4a4c2` into a throwaway directory. It points `origin` (fetch and push) at a local
  `git init --bare` repo, creates `main` there and pushes it. Before every `release.sh` run
  it aborts unless `origin` is the only remote and both its URLs are the bare repo, and it
  prints `git remote -v`. Nothing ran in this checkout or against GitHub, and no tag left
  the scratch directory.
  - **Rejected:** `0.4.0a1`, `0.4.0rc1`, `0.4.0.dev1`, `0.4.0.post1`, `0.4`, `v0.4.0b1`,
    `0.4.0b01`, `00.4.0`, `0.4.0-b1` and `0.4.0B1` each give `Error: version must look like
    X.Y.Z or X.Y.ZbN (a PEP 440 beta), with no leading zeros`, exit 2. The tree stays clean
    and no tag is made.
  - **Induced failure, after every edit:** a committed test that fails and prints
    `git status --porcelain` from inside `check.sh`. `release.sh 0.4.0b1` printed
    `payloadType: application/vnd.asexec.0.4.0b1+json` and the four-file diff. The failing
    test showed ` M pyproject.toml`, ` M src/asexec/__init__.py`,
    ` M src/asexec/constants.py`, ` M tests/test_constants.py` and ` M uv.lock`, then
    `1 failed, 451 passed, 4 skipped`, exit 1. Afterwards:
    - `git status --porcelain` and `git diff HEAD` were empty, HEAD was unchanged, and there
      was no tag here or on `origin`;
    - the files read `MANIFEST_PAYLOAD_TYPE = "application/vnd.asexec.v1+json"`, the pin
      `…== "application/vnd.asexec.v1+json"`, `__version__ = "0.3.20"`, `version =
      "0.3.20"`, and `uv.lock`'s asexec `version = "0.3.20"`.
  - **Induced failure, before any edit:** the pinned line duplicated in a commit →
    `Error: tests/test_constants.py: expected exactly one pinned MANIFEST_PAYLOAD_TYPE
    literal, found 2`, exit 1, with nothing written.
  - **`0.4.0b1`:** exit 0. The release commit `Release v0.4.0b1` changes 5 files, one line
    each:
    - `pyproject.toml` and `__init__.py`: `0.3.20` → `0.4.0b1`;
    - `constants.py`: `MANIFEST_PAYLOAD_TYPE = "application/vnd.asexec.v1+json"` →
      `"application/vnd.asexec.0.4.0b1+json"`;
    - `tests/test_constants.py`: `assert constants.MANIFEST_PAYLOAD_TYPE == "…v1+json"` →
      `"…0.4.0b1+json"`;
    - `uv.lock`: asexec `0.3.20` → `0.4.0b1`.

    The tag object is `type commit`, `tag v0.4.0b1`, message `Release v0.4.0b1`, and
    `v0.4.0b1^{commit}` and the remote `refs/tags/v0.4.0b1^{}` both equal the release commit.
  - **`check.sh` after the `0.4.0b1` commit:** lint and format clean. `451 passed, 4
    skipped`: the four `frozen_v1` tests, each `SKIPPED … a 0.4.0 beta build does not read
    v1, the frozen vectors' format (D6b)`. `test_current_format_sign_then_verify_roundtrip`
    and `test_v1_is_read_by_every_build_but_a_0_4_0_beta` passed, and so did the 8 predicate
    cases.
  - **Built from the `0.4.0b1` commit:** `uv build` gives `dist/asexec-0.4.0b1.tar.gz` and
    `dist/asexec-0.4.0b1-py3-none-any.whl`. Into a fresh venv, the hash-locked dependencies
    from `uv export` went in first, then `uv pip install --no-deps --no-index --find-links
    dist "asexec==0.4.0b1"` (no `--prerelease`): `+ asexec==0.4.0b1`, exit 0.
    `asexec --version` printed `asexec 0.4.0b1`.
  - **`0.4.0b2` after it:** the commit `Release v0.4.0b2` changes the same 5 lines,
    `0.4.0b1` → `0.4.0b2` and `…0.4.0b1+json` → `…0.4.0b2+json`, and is tagged `v0.4.0b2`.
  - **`0.4.0`:** `payloadType: application/vnd.asexec.v1+json`. The commit `Release v0.4.0`
    changes 5 files, 6 lines: the two version lines and `uv.lock` (`0.4.0b2` → `0.4.0`), the
    two literals (`…0.4.0b2+json` → `application/vnd.asexec.v1+json`), and in `FORMATS`
    `    MANIFEST_PAYLOAD_TYPE: {` → `    "application/vnd.asexec.v1+json": {`. It is tagged
    `v0.4.0`.
  - **`check.sh` after the `0.4.0` commit:** clean, `455 passed`, no skips. The four frozen
    `v1` tests ran and passed, and so did the roundtrip and the invariant.
  - **After `0.4.0`:**
    - `--no-check 0.5.0b1`: `Error: src/asexec/constants.py: a beta writes the FORMATS entry
      under development, but there is not exactly one keyed by MANIFEST_PAYLOAD_TYPE`.
    - `--no-check 0.5.0`: `Error: no payloadType is set for full releases of 0.5; add it to
      RELEASE_PAYLOAD_TYPES in scripts/release.sh`.
    - Both exit 1, leaving the tree clean and no tag.
    - `--no-check 0.4.1`: `payloadType: application/vnd.asexec.v1+json`, and the commit
      changes only `pyproject.toml` and `__init__.py`.
  - **The re-key the never-skipped test catches.** On the `0.4.0` tree, a hand edit sets the
    `v1` key back to the name and both literals to `0.5.0b1`: the case the checkpoint 3
    review raised. `pytest tests/test_constants.py` gives 5 failed and 25 passed:
    `test_frozen_manifests_still_verify`, `test_signing_input_of_the_frozen_v1_vector`,
    `test_v1_is_read_by_every_build_but_a_0_4_0_beta` and both `not_enforced_yet` tests.
    Under D6b's unnarrowed wording ("a beta type"), the four vector tests would have been
    skipped.
- **publish.yml:**
  - `actionlint` 1.7.12 (`uvx --from actionlint-py`) on `publish.yml` and `ci.yml`: exit 0.
  - With `shellcheck` 0.11.0 (`-shellcheck`): one warning, SC2055 on the existing
    `if [[ "$ver" != "$py_ver" || "$ver" != "$init_ver" ]]` (observations). It is present on
    `9a71e7f` too.
  - `shellcheck scripts/release.sh`: clean.
  - The workflow parsed with PyYAML. A script in the scratchpad ran `verify-release`'s
    tag-form check and the `github-release` step with a stub `gh` that prints its
    arguments:
    - `v0.4.0b1` → `gh release create v0.4.0b1 dist/… --repo OWNER/REPO --verify-tag
      --generate-notes --prerelease`, and the same for `v0.4.0b12`.
    - `v0.4.0` → `gh release create v0.4.0 dist/… --repo OWNER/REPO --verify-tag
      --generate-notes`, and the same for `v0.4.1`.
    - `v0.4.0rc1`, `v0.4.0a1`, `v0.4.0.dev1` and `v0.04.0` →
      `::error::tag … is not vX.Y.Z or vX.Y.ZbN`, exit 1, in `verify-release`, so they never
      reach the release step.
- `uv run python examples/adequacy-test/run.py`: exit 0 on this branch. At the rehearsal's
  `v0.4.0b1` it also exits 0, and its output is the same once refs and uv's build lines are
  removed.
- Nothing left behind: no other test or example holds the `v1` literal. `git grep -n
  'vnd\.asexec'` outside the docs finds:
  - the one `MANIFEST_PAYLOAD_TYPE` line and two comments in `src/asexec/constants.py`;
  - in `tests/test_constants.py`, the frozen vectors, `V1_PAYLOAD_TYPE`, the pinned line,
    the predicate cases and comments;
  - the docstring example in `src/asexec/manifest.py:6` (observations);
  - the pre-0.4.0 type in `src/asexec/verifier.py`;
  - the made-up `v2`, `v10`, `other` and `0.3.0b1` types in the verify, CLI and selector
    tests.
- CI on PR #53 at `dd45abf` (run 44684208161): lint, python-matrix, test (3.12, 3.13, 3.14)
  and build pass.

**Observations (out of scope):**
- `--no-check` leaves `uv.lock`'s asexec version at the previous release. `uv.lock` changes
  only when `check.sh`'s `uv run` re-locks, and the rehearsed `0.4.1 --no-check` commit
  changed only the two version files. This is how it worked before (`scripts/release.sh`,
  the `LOCK_FILE` handling).
- SC2055 on `publish.yml` `verify-release` (the `"$ver" != "$py_ver" || "$ver" !=
  "$init_ver"` test) is a false positive: "fail if either differs" is the intent. It
  predates this checkpoint.
- The CLI smoke's `--version` check is a substring match (`*"$expected"*`), so `0.4.0`
  would also match `asexec 0.4.0b1`. The exact `==` install pin makes that unreachable
  today. Not changed, because a beta doesn't need it.
- `scripts/dev-setup.sh:52` prints `scripts/release.sh X.Y.Z` and doesn't mention betas.
- `src/asexec/manifest.py:6` (docstring) and `docs/VERIFICATION.md` (*Formats*, `format` #3)
  show `application/vnd.asexec.v1+json`. On main after b1 the type is the beta's (D6a), so
  they describe 0.4.0, not main (as checkpoint 3 noted for VERIFICATION.md).
- `docs/MULTIVERSION.md` (*Verifier design*) still says the `0.4.0` release commit makes the
  key a literal "at the latest". That is still accurate, but it could now name
  `release.sh`.
- A patch release (`0.4.Z`, `Z > 0`) cut from main while a new format's entry is under
  development there is refused: the name-keyed entry would collide with the literal `v1`
  key. How patches are released alongside a new format (a release branch, say) isn't
  designed yet. Refusing is the conservative outcome.
- **Open design question for after 0.4.0, which the human tester should see: there is no
  workable path to a `0.5.0b1` yet** (review round 1, finding 5). The beta guard needs a
  `FORMATS` entry keyed by the name `MANIFEST_PAYLOAD_TYPE`. After `0.4.0`, main keeps
  `MANIFEST_PAYLOAD_TYPE = "application/vnd.asexec.v1+json"` (D6a), so a new
  `MANIFEST_PAYLOAD_TYPE: {...}` entry would have the same key as the literal `v1` entry.
  Ruff flags that (F601), and at runtime the later entry would replace `v1`'s rules. How a
  later line's betas are developed and released, and the patch case above, need designing
  together before the first post-0.4.0 format change. This is not a b1 problem: every
  `0.4.0` beta and `0.4.0` itself work, as rehearsed. `docs/DEVELOPMENT.md` no longer
  promises the `0.5.0b1` workflow.

**Judgement calls / new paradigms:**
- **Full releases use an explicit table.** `RELEASE_PAYLOAD_TYPES = {"0.4": v1}` covers
  `0.4.0` and its patches. A full release of any other line is refused until its format is
  decided and added, rather than guessed (for example as `v<minor-3>`).
- **`release.sh` makes the `v1` key a literal at `0.4.0`.** It is not left to #40. #30's
  scope says the script "sets ... its `FORMATS` key", and this way the step can't be
  forgotten. The rule is general: the first full release of a line (`X.Y.0`) releases the
  entry under development, and later releases of the line require the literal key and no
  name-keyed entry. The never-skipped invariant test backs it up.
- **Guards beyond the four rewrites.** A beta requires exactly one name-keyed entry, and a
  patch requires the literal key and no name key. Without them, `--no-check` could release
  a build whose signing entry is missing, or one that has two entries under the `v1` key,
  where the later silently wins. They are also checked before anything is written.
- **The skip is narrowed to `0.4.0` betas**, against D6b's wording ("when
  `MANIFEST_PAYLOAD_TYPE` is a beta type"), as the checkpoint 3 review asked. While no format
  has been released, a beta build reads only its own type. From `0.4.0` on, every build,
  `0.5.0b1` included, must read `v1`, so its vectors must run, and a `0.5.0b1` release commit
  that re-keyed `v1` is caught (shown above).
- **The roundtrip runs in every build**, not only when the vectors are skipped. It costs
  nothing, it is exercised on main and in CI today rather than only after b1, and it checks
  the current entry in a `v1` build as well.
- **One pinned line.** The `v1` PAE literal moved to its own `frozen_v1` test, and
  `_signed_prereg()["payloadType"]` is compared against the constant, which the line above
  pins. Otherwise the release commit would have to rewrite a PAE literal with its length
  prefix. Nothing is weaker in a `v1` build: the type is pinned, the PAE literal for `v1` is
  pinned, and the default PAE equals the one for the pinned type.
- **Normalized versions only.** Leading zeros, which the old `^[0-9]+…$` accepted, are now
  refused, because PEP 440 normalizes them away and `verify-release`'s `dist` globs would
  then not match. `b0` is accepted, as PEP 440 allows.
- **`verify-release` checks the tag form.** That goes slightly beyond adding `--prerelease`.
  The trigger glob admits `rc`, alpha and `.dev` tags, which the prerelease test would have
  published as full releases. The check fails them before any upload, and it accepts the
  same forms as `release.sh`.

**Review round 1** (findings on PR #53):
1. should-fix: the failure cleanup did nothing if `git commit` itself failed. `git restore --
   files` restores from the index, which `git add` had already updated. With a failing
   pre-commit hook, `--no-check 0.4.0b1` exited 1 and left `pyproject.toml`, `__init__.py`,
   `constants.py` and `tests/test_constants.py` staged with the beta type, against
   `docs/DEVELOPMENT.md`, the script header and these notes. → The cleanup is now
   `git restore --source=HEAD --staged --worktree -- <the five files>`. Commit `395e15b`.
   Rehearsed in a fresh throwaway clone (local bare `origin`, guarded as before) at
   `395e15b`:
   - Before the fix (at `67ccca4`), the hook case reproduced the finding: `git status
     --porcelain` showed `M ` for the four files, and `git diff --cached` held the beta
     literals.
   - After the fix, the hook case (`induced pre-commit hook failure`, exit 1) leaves
     `git status --porcelain`, `git diff HEAD` and `git diff --cached` all empty, with HEAD
     unchanged and no tag here or on `origin`.
   - The induced `check.sh` failure: the failing test printed ` M` for all five files, then
     `1 failed, 451 passed, 4 skipped`, exit 1. Afterwards `git status --porcelain`,
     `git diff HEAD` and `git diff --cached` are all empty, and the five files hold their
     `v1` / `0.3.20` values.
2. nit: the `X.Y.0` branch turned the name key into the literal without checking that the
   literal key was absent, so a stray `"application/vnd.asexec.v1+json": {...}` entry
   became a duplicate key. → It now refuses if the literal key exists. Rehearsed on the
   `0.4.0b2` tree with a stray `v1` entry committed: `--no-check 0.4.0` → `Error:
   src/asexec/constants.py: an entry is already keyed by application/vnd.asexec.v1+json, so
   releasing the entry under development would duplicate that key`, exit 1, clean tree,
   index empty, no `v0.4.0` tag. At `67ccca4` the same run exited 0 and tagged `v0.4.0`.
   Commit `395e15b`.
3. nit: a beta of a patch was accepted (`--no-check 0.4.1b1` committed and tagged). → A beta
   whose `Z` is not `0` is refused before anything is touched: `0.4.1b1` and `1.2.3b1` →
   `Error: a beta must be of an X.Y.0 release (X.Y.0bN), not of a patch`, exit 2. Commit
   `395e15b`. Version ordering is not checked, as was already the case before this PR, so
   `0.5.0b1` before `0.4.0` still passes the version check. The script header and
   `docs/DEVELOPMENT.md` say so.
4. nit: two `docs/DEVELOPMENT.md` lines were not wrapped (131 and 143 characters), and one
   had back-to-back parentheticals. → The parentheticals are merged and every touched line
   is wrapped at 95. Only line 5, an earlier line, is longer. Commit `395e15b`.
5. out of scope: no workable path to a `0.5.0b1` after `0.4.0`. → Recorded prominently in
   the observations above, beside the patch-during-development one, as an open design
   question for after 0.4.0. The `docs/DEVELOPMENT.md` wording is softened: a later line's
   beta "must still read `v1`", and how those betas are released "is not designed yet".
   Commit `395e15b`.
6. The reviewer's assessment, recorded: the `X.Y.0` rule, the beta and patch guards and the
   `verify-release` tag-form check are mild, documented, harmless creep, and the rest is
   within scope. No code change.

The rest of the fixed rehearsal at `395e15b` matches the first one:
- `0.4.0b1`, `0.4.0b2` and `0.4.0` give the same 5-file commits, with 5, 5 and 6 lines.
- `check.sh` gives `451 passed, 4 skipped` after b1 and `455 passed` after 0.4.0.
- After `0.4.0`, `0.5.0b1` and `0.5.0` are refused and `0.4.1` passes.
- The re-key case gives 5 failed.

`scripts/check.sh` on `395e15b`: clean, 455 passed. `shellcheck scripts/release.sh`: clean.
CI: run 44728436229 on `395e15b` and run 44728921686 on `0a3065b`, lint, python-matrix, test
(3.12, 3.13, 3.14) and build pass.

**Merged** (orchestrator): PR #53 merged into `feature/0321` as `fcba9ae`, a merge commit,
with no review findings left open. The #30 change is `da4a4c2`, and the review fixes are
`395e15b`. `scripts/release.sh` was only ever run in throwaway clones whose sole remote was a
local bare repo. The review agent's own rehearsal: b1 → b2 → 0.4.0 → 0.4.1; every listed
refusal; SIGINT, SIGTERM and SIGHUP during `check.sh`, each leaving the tree restored. It
found that a failing `git commit` left the release edits staged, which is now fixed and
rehearsed with a failing pre-commit hook. After the merge, `git ls-remote --tags origin` has
no `v0.4*` tag, and the latest GitHub release is still v0.3.20. Post-merge on `feature/0321`
at `fcba9ae`: `scripts/check.sh` clean, 455 passed; `examples/adequacy-test/run.py` exit 0.
CI on the last PR push (`7c3b0b4`, run 44729179505): lint, build, test on 3.12, 3.13 and
3.14 pass. **Open for the human gate:** after 0.4.0 there's no workable path to a 0.5.0
beta, nor to a patch release while a new format is in development (see the observations
above). Neither blocks b1.

### Checkpoint 5: #44, #42, #43

**Landed** (branch `feature/0321-checkpoint5`):
- #44 (D2), `60c5ffa`: a prereg that passes `format` but fails a `selfsig` condition is no
  commitment. `verify_paths` keeps commitments for preregs that meet the `selfsig`
  conditions only, and lists the others in a new `rejected_preregs` list, each with the
  reason `invalid signature` and the postregs rejected under it. A postreg that counts toward
  no commitment of its ref is listed under each rejected pre-registration of that ref with
  the new reason `the pre-registration's signature is invalid`. The report prints a
  `=== rejected pre-registrations ===` block. `keyconsist`'s empty reason is now `requested
  but no validly signed postreg names a commitment`. The `TypeError` on a non-string
  `signature.keyid` (checkpoint 2's carry-forward) is gone. `docs/VERIFICATION.md` (the
  three terms, matching condition 4, a prereg table, the postreg table, *Output*, `chain`'s
  and `keyconsist`'s conditions and empty cases, `selfsig`, *Commitment states*, an
  example), `README.md` (*What `asexec` always proves*, key consistency, *Verification
  output*) and the verifier docstring are updated.
- #42, `9dafde1`: postregs are matched by direct lookup. The commitments are indexed by
  `(ref, keyid)` (valid preregs only) and by `ref`, and the rejected pre-registrations by
  `ref`. `_get_postreg_rejection_reason` is folded into the loop. Report and verdicts
  unchanged (differential below); `tests/verify/test_verify_matching.py` is not touched by
  the commit.
- #43, `b4bfad1`: the matching loop sets the commitment's `different_key` flag when it
  rejects a postreg there as signed by a different key. `key_checked` (`counted_postregs` or
  the flag) is keyconsist's scope and `not different_key` its verdict, defined once where the
  commitment record is built, beside the flag. `key_consistent` is removed from the report
  dict, and `_evaluate`'s comment and the module docstring no longer restate the rule. No
  verdict reads a reason string. Report text and verdicts unchanged (differential below).

**How matching reads now** (`docs/VERIFICATION.md`, *Matching postregs to commitments*):
- **Provided prereg** (passes `format`) → **commitment** (also meets the `selfsig`
  conditions; keyed by `ref` and `signature.keyid`) → **rejected pre-registration** (passes
  `format`, fails `selfsig`). Matching gains condition 4: `R` meets the `selfsig` conditions.
  Conditions 1-3 keep their numbers, so D2's "matching condition 2" still reads right.
- A postreg that names a provided prereg and counts toward no commitment of that ref is
  rejected under each commitment of the ref (`invalid signature` or `signed by a different
  key than the pre-registration`) and under each rejected pre-registration of the ref (`the
  pre-registration's signature is invalid`). A postreg naming only rejected preregs is not
  notarization-only. "Notarization-only" still means "names no provided prereg".

**Evidence:**
- `scripts/check.sh`: ruff check and format check clean. pytest **455 passed before**
  (`e60cd1c`), **477 after #44**, 477 after #42, 477 after #43. The 22 new tests:
  `test_verify_matching.py` +11, `test_verify_run_rules.py` +6, `test_verify_keyconsist.py`
  +2, `test_verify_chain.py` +1, `tests/test_cli.py` +2.
- Red first (#44, the `tests/verify` tests only, against `e60cd1c`'s verifier): 20 failed,
  260 passed. The failures were `TypeError: unhashable type: 'dict'` and `'list'` (the keyid
  inputs as a prereg), `KeyError: 'rejected_preregs'` (6), codes with `chain=PASS` or
  `keyconsist=PASS` where `FAIL` was expected (3), 6 where the broken prereg was still a
  commitment (a commitment or postregs under it where none were expected, the number keyid
  among them; `applicable` 1 for 0; two commitments for one), the old keyconsist empty
  reason (2),
  and the doc-coverage test (`('matching', 4)` has no doc item). With `verifier.py` changed,
  only the doc-coverage test and one case with a bug of its own failed (the
  `keyid-does-not-derive` case generated a new keyid on every write; the test now uses one
  fixed `OTHER_KEYID`). The CLI tests, written next, failed on the missing block until
  `cli.py` printed it, and the doc-coverage test passed once `VERIFICATION.md` had #4.
- Tests that pin each requirement (#44):
  - The tampered prereg plus valid postregs by the same key (#44's own case):
    `test_matching__fail__4_prereg_meets_selfsig_conditions[signature-does-not-verify|keyid-does-not-derive]`:
    `chain=FAIL format=PASS keyconsist=FAIL selfsig=FAIL`, no commitment, no
    notarization-only, one rejected pre-registration (its `ref`, claimed keyid, `invalid
    signature`), and all three postregs under it with the prereg's reason; `chain` and
    `keyconsist` applicable 0.
  - (a) `test_matching__postreg_counted_by_a_commitment_is_not_rejected_under_a_rejected_copy[same-keyid|other-keyid]`:
    the commitment stays `fulfilled` with 3 counted, the broken copy is listed as rejected
    with no postregs, `chain=PASS keyconsist=PASS selfsig=FAIL`.
    `test_matching__forged_copy_claiming_a_key_does_not_make_that_key_a_signer`: a copy
    relabelled with key B's `pubkey` and `keyid` is rejected; B's valid postreg is rejected
    under the real commitment as a different key (`keyconsist=FAIL`) and listed under the
    copy with the prereg's reason. `test_matching__postreg_rejected_under_a_commitment_is_also_rejected_under_a_copy`.
  - (b) `test_matching__postreg_naming_only_rejected_preregs_is_rejected_under_each`: two
    rejected copies with different keyids, each listing all three postregs (one of them
    itself tampered) with the prereg's reason; not notarization-only.
  - (c) `test_matching__copies_of_a_rejected_prereg_are_listed_once` (three copies, two ways
    broken, one entry with 3 postregs); `test_matching__rejected_preregs_do_not_depend_on_file_order`.
  - (d) `test_keyconsist__fail__empty_prereg_fails_selfsig`,
    `test_keyconsist__fail__empty_postreg_by_another_key_naming_a_rejected_prereg` (the new
    reason, applicable 0), `test_chain__fail__empty_prereg_fails_selfsig`; the `EMPTY`
    constant in `test_verify_keyconsist.py` pins the changed reason for every empty case.
  - `test_matching__prereg_with_body_changed_after_signing_is_rejected_and_named_by_none`
    and `test_matching__valid_prereg_has_no_rejected_preregs`.
  - The carry-forward crash: `test_never_raises__keyid_not_a_string[prereg|postreg0 ×
    object|list|number]`: `format=PASS selfsig=FAIL`, never raises; as a prereg it is a
    rejected pre-registration with that keyid, as a postreg it is rejected for `invalid
    signature`.
  - Report: `tests/test_cli.py::test_verify_lists_rejected_preregistrations` (the exact
    block: `✗ prereg <ref> is NOT a commitment: invalid signature`, `keyid        : <keyid>`,
    the postreg line with the prereg's reason; the commitments line; no notarization-only
    block) and `test_verify_prints_no_rejected_preregistrations_block_when_none`.
- **#42 and #43 change nothing visible (the differential).** A pytest plugin and a corpus
  script (session scratchpad, not in the repo) load the other version's `verifier.py` inside
  the `asexec` package, so both versions share every other module, the files, `now`, the
  pinned servers and monkeypatches. Each `verify_paths` call (the CLI's included) runs on
  both. The two report dicts are compared in full, and each is rendered through
  `cli.cmd_verify` (with `verify_paths` stubbed to return it) and the text and exit status
  compared. For #43 the comparison maps each commitment's key fields to what they mean
  (key-checked, consistent), since `key_consistent` is replaced by `different_key`; every
  other field is compared as is.
  - #42 (`60c5ffa` vs `9dafde1`), the suite: 305 calls over 295 tests, 34 distinct codes,
    **0 differences**. The suite is the same at both commits.
  - #43 (`9dafde1` vs `b4bfad1`): the new suite, 305 calls, **0 differences**; the old suite
    (a worktree at `9dafde1`, its own package checked by path), each call also run by the
    new verifier: 305 calls, **0 differences**.
  - The corpus: 218 files from 12 bodies (two preregs with and without an elapsed or
    unparseable `due`, a 3-link chain and a fork, cross-ref, unknown-ref and junk-link
    postregs) × 13 variants (keys A/B/C, broken sig, another key's keyid, a forged B
    pubkey+keyid, keyid as object/list/number/missing, body tampered, `v2` format, bad hex),
    plus a truncated file, a missing path and byte copies. 6,494 runs: every file alone,
    1,500 seeded random subsets and their reverses, 14 hand-built sets and their reverses
    and the directory, each with every catalog test and with `chain,format,keyconsist,selfsig`.
    26 distinct codes; runs with a rejected pre-registration 4,664, with a postreg under one
    3,522, with a different-key rejection 1,204, with an invalid-signature rejection 2,010,
    with two commitments of one ref 194, with notarization-only 5,370, with a counted postreg
    870, all `PASS` 6. **0 differences** for #42 and for #43. Nothing raised in either
    version.
  - The harness catches real changes: with the reason order swapped in a copy of the #44
    verifier, the suite gave 6 differences and the corpus 1,870; with
    `key_checked` reduced to the flag alone in a copy of the #43 verifier, the suite gave 200
    and the corpus 418. The corpus compared against itself: 0.
  - Timing, 3,000 preregs and 3,000 postregs (one each per ref): 1.68 s before #42, 1.28 s
    after. Signature checks dominate; the matching itself was the 0.4 s difference.
- CLI demonstrations, in a scratch dir (`keygen` twice; `prereg --target "model m via
  provider p"`; `postreg --fulfills prereg.json [--prev postreg-1.json]`; `postreg-other.json`
  by the second key; `prereg-badsig.json` with one byte of `signature.sig` changed;
  `prereg-forged.json` with the second key's `pubkey` and `keyid`; `prereg-keyid-object.json`
  with `"keyid": {"a": 1}`). Each with `--tests format,selfsig,chain,keyconsist`:
  - `prereg-badsig.json postreg-1.json postreg-2.json`: `(no commitments: no
    pre-registration provided is validly signed)`, then `=== rejected pre-registrations ===`,
    `✗ prereg sha-256:b17107d0… is NOT a commitment: invalid signature`, `keyid        :
    sha-256:3b317472…`, and both postregs `does NOT count toward fulfillment: the
    pre-registration's signature is invalid`; `chain=FAIL (requested but no commitment has
    counted postregs to chain-check)`, `keyconsist=FAIL (requested but no validly signed
    postreg names a commitment)`, `asexec-verify/1 chain=FAIL format=PASS keyconsist=FAIL
    selfsig=FAIL`, exit 2. On `e60cd1c`: `[FULFILLED]` with 2 postregs, `chain=PASS
    format=PASS keyconsist=PASS selfsig=FAIL`.
  - `prereg.json prereg-forged.json postreg-1.json postreg-2.json postreg-other.json`: one
    `[FULFILLED]` commitment (signer `sha-256:3b317472…`, 2 postregs) with `postreg-other`
    rejected as `signed by a different key than the pre-registration`; the forged copy listed
    as rejected (keyid `sha-256:ce694ad4…`) with `postreg-other` under it;
    `asexec-verify/1 chain=PASS format=PASS keyconsist=FAIL selfsig=FAIL`, exit 2. On
    `e60cd1c` the forged copy was a second `[FULFILLED]` commitment, signer
    `sha-256:ce694ad4…`, and the code was `chain=PASS format=PASS keyconsist=PASS
    selfsig=FAIL`: the key that never signed passed `keyconsist`.
  - `prereg-keyid-object.json postreg-1.json`: `✗ prereg-keyid-object.json  [prereg]
    keyid={'a': 1}`, the rejected block with `keyid        : {'a': 1}`, `chain=FAIL
    format=PASS keyconsist=FAIL selfsig=FAIL`, exit 2. On `e60cd1c`: `TypeError: cannot use
    'tuple' as a dict key (unhashable type: 'dict')`.
- `uv run python examples/adequacy-test/run.py`: exit 0 after each commit.
- Nothing left behind: `git grep -n -e _get_postreg_rejection_reason -e key_consistent -e
  other_key -e "names a provided prereg" -e "a provided pre-registration with that"` outside
  this file finds only `other_keyid` test variables and the new matching sentence ("A postreg
  that names a provided prereg (condition 1) …"), which is meant.
- CI on PR #54 at `a3c58bb` (run 44732983336): lint, python-matrix, test (3.12, 3.13, 3.14)
  and build pass.

**Observations (out of scope):**
- For #46 and #37 (checkpoint 7): `timely` and `complete` should read commitments only, so
  a rejected pre-registration's `due` and items are not examined. D5a's "if no prereg has a
  `due`, `timely` is empty" should say "no commitment".
- For #32 (checkpoint 6): "exactly one signature" becomes a `selfsig` condition, so a prereg
  with two signatures will be a rejected pre-registration, and a missing `pubkey` or `sig`
  (checkpoint 2's note) too. #32's matching tests should cover one such prereg.
- A prereg whose body changed after signing has a new `ref`, so the postregs that name the
  signed body are notarization-only, and its rejected entry lists none of them
  (`test_matching__prereg_with_body_changed_after_signing_is_rejected_and_named_by_none`).
  This follows from refs being of the body as given. A hint in the report ("a rejected
  pre-registration with no postregs may have been edited after signing") would help a
  reader, but isn't specified.
- The rejected reason is `invalid signature` for both `selfsig` conditions, as for postregs.
  A distinct reason for a keyid that does not derive would match checkpoint 2's observation
  that the manifests block's `✗` has no reason line.
- `src/asexec/cli.py` shows a non-string keyid as its Python repr (`{'a': 1}`), in the
  manifests block as before and now in the rejected block. Display only.
- The `=== commitments ===` block's empty line now has two texts: the old `(no
  pre-registrations among the provided manifests)` when no prereg passes `selfsig` and none
  is rejected (that is, none passes `format`), and `(no commitments: no pre-registration
  provided is validly signed)` when some are rejected. The old text is wrong-ish for a run
  whose only prereg failed `format`, as before this checkpoint.

**Judgement calls / new paradigms:**
- **(a) A postreg that counts toward a commitment is not listed under the ref's rejected
  pre-registrations**, whatever keyid the broken copy claims. **Needs the human's
  confirmation:** this narrows D2's literal text ("a postreg naming it is listed as rejected
  under it"); review round 1 judged it safe and order-independent. This is the existing rule ("a
  postreg that counts toward one commitment of a `ref` is not rejected under the others")
  carried to rejected copies. Listing it would show one postreg as counted and as rejected
  for the same ref, and would let anyone add rejection lines to a valid commitment's postregs
  by supplying a broken copy.
- **Under a rejected pre-registration, the reason is always `the pre-registration's signature
  is invalid`** (condition 4), even when the postreg's own signature is also invalid, and
  the postreg's keyid is never compared with the prereg's. D2 gives that reason, and the
  claimed keyid is exactly what must not decide anything. The postreg's own failure still
  shows as `✗` and in `selfsig`, and as `invalid signature` under any commitment of the ref.
  Such a rejection never fails `keyconsist`.
- **(b) A postreg naming only rejected pre-registrations** is rejected under each of them and
  is not notarization-only (D2: it names a provided prereg). With no commitment, `chain` and
  `keyconsist` are empty for it.
- **(c) Rejected copies are deduplicated by `(ref, keyid)`** (the keyid compared as JSON
  text since review round 1, as a keyid may be unhashable), however each copy is broken; their single reason is the same. A
  valid prereg and a broken copy with the same `(ref, keyid)` are a commitment plus a
  rejected pre-registration, never merged, as a broken copy of a postreg is judged on its own.
- **(d) `keyconsist`'s empty reason changes** from `… names a provided prereg` to `requested
  but no validly signed postreg names a commitment`, since a valid postreg naming a rejected
  pre-registration does name a provided prereg. Its condition now says "of a commitment with
  that `ref`", and its scope (counted, or rejected as a different key) can only ever include
  commitments. `chain`'s empty reason already said "commitment" and is unchanged; a sentence
  says a rejected pre-registration is never chain-checked.
- **Condition 4, not a renumbering.** The prereg condition is matching #4 so 1-3, the tests
  named after them and D2's reference to "condition 2" stay valid.
- **The rejected prereg's own reason is `REASON_INVALID_SIGNATURE`**, the postregs' constant,
  for both `selfsig` conditions. The postreg reason under it is a new constant,
  `REASON_PREREG_INVALID_SIGNATURE`.
- **Report shape.** `rejected_preregs` is a new top-level list (`ref`, `keyid`, `reason`,
  `rejected_postregs`). The CLI block prints `is NOT a commitment: <reason>` (parallel to the
  postreg lines' `does NOT count toward fulfillment: <reason>`) and `keyid` rather than
  `signer`, since nothing authenticated it. The `due` is not shown, since it has no state.
- **#43 keeps `key_checked`, drops `key_consistent`**, and adds the flag `different_key` to
  the commitment dict. The scope rule is written once, as a comment on `key_checked` where
  the commitment record is built, and the flag's initialiser points to it. The module
  docstring now says `keyconsist` "applies to the commitments `verify_paths` marks
  `key_checked`". The two keyconsist tests that read `key_consistent` now check the
  documented result reason and the rejected postreg's reason, black-box.
- No new dependency, system or paradigm.

**Review round 1** (findings on PR #54):
1. should-fix: `docs/VERIFICATION.md:704` said a rejected pre-registration "fails `selfsig`,
   which is its only failure", but in the doc's own example the run also gives `chain=FAIL
   keyconsist=FAIL` (both empty) → it now says that of the tests it fails only `selfsig`,
   and that with no commitment `chain` and `keyconsist` may be empty and `FAIL`, as in the
   example (whose code already shows `chain=FAIL format=PASS keyconsist=FAIL
   selfsig=FAIL`). The *What affects a verdict* paragraph says the same. Commit `390a5b3`.
2. nit: rejected pre-registrations were deduplicated with Python equality
   (`verifier.py:463`), so keyids `1`, `1.0` and `true` merged into one entry whose printed
   keyid depended on file order → they are keyed by `(ref, json.dumps(keyid,
   sort_keys=True))` (`_json_value`). Test first:
   `test_matching__rejected_preregs_with_json_distinct_keyids_are_not_merged` (three copies
   claiming `1`, `1.0` and `true`; both file orders give the same three entries, each with
   its own keyid). It failed on `f81ce35` (one merged entry, a different keyid per order)
   and passes now. The adversarial corpus, `f81ce35` vs `6a6e947`: 6,494 runs, 0
   differences (its only number keyid is `7`). Commit `6a6e947`.
3. nit: the `key_checked` comment said keyconsist's "scope and verdict, defined here only",
   but the verdict is computed in `_evaluate` → it defines the scope there and names the
   verdict, `not different_key`. Commit `f81ce35`.
4. nit: `README.md:173` was not rewrapped → rewrapped. Commit `390a5b3`.
5. out of scope → observation below (for the human gate).
6. → judgement call (a) above is marked as needing the human's confirmation, and (d) is
   recorded below as an FYI.

`scripts/check.sh`: clean, 478 passed (477 + the new matching test). CI on `9b73d55` (run
44735722972): lint, python-matrix, test (3.12, 3.13, 3.14) and build pass.

**Observations added in review round 1 (out of scope):**
- **For the human gate: unauthenticated `signature.keyid` strings are printed raw.** The
  new rejected block (`src/asexec/cli.py:321`) prints a rejected pre-registration's keyid,
  and the manifests block's `keyid=` line already printed every file's. A keyid holding
  newlines can therefore forge report lines: the reviewer printed a fake `[FULFILLED]`
  commitment this way. The code line and the exit status are unaffected. Suggested later
  fix: one display escape (for example `json.dumps` or `repr`) for every unauthenticated
  value the report prints. Not fixed here.
- Postreg entries (counted, rejected under a commitment or a rejected pre-registration, and
  notarization-only) are still deduplicated by `_add_once`, with Python equality, so two
  copies of a postreg whose keyids are `1` and `true` are listed once, under the first
  file's keyid. This predates the checkpoint (it holds for commitments and notarization-only
  on `e60cd1c`); such postregs always fail `selfsig`, so no verdict depends on it. The same
  `_json_value` key would fix it.
- **FYI for the human gate (judgement call (d)):** `keyconsist`'s empty reason changed
  from `requested but no validly signed postreg names a provided prereg` to `requested but
  no validly signed postreg names a commitment`. It is a reason the doc lists, so scripts
  that matched the old text would need the new one.

**Merged** (orchestrator): PR #54 merged into `feature/0321` as `310fa16`, a merge commit,
with no review findings left open. The changes: #44 is `60c5ffa`, with the review fixes
`390a5b3` and `6a6e947`; #42 is `9dafde1`; #43 is `b4bfad1`, with the review fix
`f81ce35`. The review agent checked the verifier against its own oracle for D2's commitment
set and keyconsist scope: it matched in 4,110 runs, while the base verifier disagreed in 86.
It then compared #44, #42 and #43 pairwise on 9,192 runs in both file orders and found no
difference. Post-merge on `feature/0321` at `310fa16`: `scripts/check.sh` clean, 478 passed;
`examples/adequacy-test/run.py` exit 0. CI on the last PR push (`fa25c7d`, run 44735932121):
lint, build, test on 3.12, 3.13 and 3.14 pass. **Open for the human gate:** judgement call
(a), which narrows D2's literal text, and the forgeable report lines from an
unauthenticated keyid (see the observations above).

### Checkpoint 6: #32

**Landed** (branch `feature/0321-checkpoint6`):
- #32, `b0abfdb`: the DSSE envelope. A file is `{dsse: {payloadType, payload, signatures:
  [{keyid, sig}]}, pubkey, ceiling}`, with `dsse.payload` the strict base64 of the body bytes.
  The PAE is DSSE's (`FORMATS[...]["signing_pae_version"]` is now `b"DSSEv1"`), over
  `dsse.payloadType` and the body bytes as stored, and `ref` is their sha-256; verify
  re-serializes nothing. Signing still writes the canonical serialization
  (`canonical_bytes`), once. Malformed is only what stops verify reading a manifest, and the
  signature fields moved to `selfsig`. Every reader moved: `verifier.py`, `cli.py`
  (prereg/postreg writing, `--fulfills`/`--prev` refs and inheritance from the decoded prereg
  body, the report), `manifest.py` (`sign`, `ref(bytes)`, new `read_body` and `parse_body`;
  `get_body` removed), `models.py` (`DsseInput`, `EnvelopeInput`, `SignatureInput`,
  `KeyInput`; writers `Dsse`, `Manifest`, `Signature`, which lose `alg` and `payload`),
  `canonical.py` (`signing_input` takes bytes; new strict `b64encode`/`b64decode`),
  `fields.py` (`Base64`), `constants.py` (comments), and the tests. `keys.py` and
  `identity.py` needed no change. `docs/VERIFICATION.md`, `README.md` (*Manifest at a
  glance*, its legend, the integrity bullet), `ROADMAP.md` (done-ahead marks),
  `docs/MULTIVERSION.md`, `docs/DEVELOPMENT.md` and `docs/FORMAT.md` (minimal) are updated.

**How it reads now** (`docs/VERIFICATION.md`):
- **Paths** (*Conventions*, *Property paths*): `body.<path>` is a field of the body, inside the
  decoded `dsse.payload` (`body.phase`, `body.anchor.floor.round`). Any other path is from the
  file's root, outside the body (`dsse.payloadType`, `dsse.signatures[0].keyid`, `pubkey`,
  `ceiling.nonce`). Applied to every path in the doc, and the same notation drives
  `tests/verify/conftest.py`. New conventions: *Base64* (strict: standard alphabet, padded, no
  whitespace, the one spelling of its bytes) and, under *JSON*, the body rules.
- **`format`**: #1 the file is readable, a JSON object, at most 64 deep, no duplicate key,
  holding an object `dsse` with a string `dsse.payloadType` and an array `dsse.signatures`.
  #2 `dsse.payload` is strict base64, and the body bytes are the UTF-8 JSON text of an
  object, at most 64 deep counted from the body's own outermost object, with no duplicate
  key. #3 `dsse.payloadType` names a known format, checked before the rest of the frame (so
  a file of an unknown format is held only to "readable object, ≤64, no duplicate key, an
  object `dsse` with a string `dsse.payloadType`"). A file in 0.3.x's layout (no `dsse`, a
  top-level `payloadType` of `application/vnd.asexec+json`) keeps the pre-0.4.0 reason.
- **`selfsig`**: #1 `dsse.signatures` holds exactly one entry, an object (D3a). #2 `pubkey` and
  `dsse.signatures[0].sig` are present and hex. #3 the signature verifies by `pubkey` over
  the PAE of `dsse.payloadType` and the body bytes. #4 `dsse.signatures[0].keyid` derives
  from `pubkey`. So a missing or non-hex `pubkey` or `sig`, a missing `keyid`, zero or two
  signatures, and an entry that is not an object fail `selfsig`, not `format`.
- **#44's rule re-checked:** such a prereg passes `format`, so it is a provided prereg and,
  failing `selfsig`, a rejected pre-registration, listed with `dsse.signatures[0].keyid` as
  the keyid it claims (`None` if it has no entry). A postreg with the same faults is read and
  rejected under the commitment it names, for `invalid signature`. Before this change a
  non-hex `pubkey` was malformed, so such a postreg joined nothing and such a prereg made
  its postregs notarization-only (checkpoint 2's prediction).
- **Decided body cases:** body bytes that are not UTF-8 (Latin-1, an encoded surrogate, a byte
  order mark, UTF-16) are malformed (#2), as is JSON that is not an object (`[1]`, `"x"`,
  `null`, `1`) and empty bytes. A lone surrogate escape (`"\ud800"`) is valid JSON, and the
  bytes are never re-encoded, so it passes `format` and `selfsig`. It is the string it spells:
  it equals no `ref` (a `fulfills` holding one is notarization-only), parses as no time
  (`invalid-due`), and as a subject name names no artifact (content #4, `artifact not found`,
  as a NUL now does too). The report prints it as `\ud800` (`cli._show`, `backslashreplace`
  on every report line). The writer refuses a body with such a string (`ManifestError: the
  body has a string with no UTF-8 form`), so `postreg --fulfills` inheriting one from a
  prereg exits 1 with that error.
- The manifests block shows `[None]  keyid=None` for every file that fails `format`, unknown
  formats included: its body is not read (checkpoint 3's observation that it showed
  `payload.phase` of a body this release can't interpret no longer applies).

**Evidence:**
- `scripts/check.sh`: ruff check and format check clean. pytest **478 passed before**
  (`c08ad59`), **620 after** (`b0abfdb`). By file: `test_verify_format.py` 38 → 83,
  `test_verify_selfsig.py` 6 → 30, `test_verify_run_rules.py` 52 → 76,
  `test_verify_matching.py` 29 → 34, `test_verify_planted_faults.py` 25 → 30, `test_cli.py`
  83 → 90, `test_manifest.py` 25 → 40, `test_primitives.py` 10 → 26, `test_constants.py`
  30 → 31; the rest unchanged.
- Red first: with only the tests changed, 296 failed, 144 passed and 4 test files failed to
  collect. 267 failures were `TypeError: Object of type bytes is not JSON serializable`
  (`signing_input` re-serialized whatever it was given, so it could not take body bytes), 14
  `manifest has no attribute 'read_body'`, 8 `KeyError: 'dsse'`, and the collection errors
  were `cannot import name 'Dsse'` / `'b64decode'`. The rest: `b'asexec-PAE/v1' ==
  b'DSSEv1'`, the `FORMATS` literal, the ref literal, the doc-coverage test. With the code in
  place only the frozen-vector tests (placeholders) and the doc-coverage test failed; they
  passed once the vectors were regenerated and `docs/VERIFICATION.md` rewritten.
- Tests that pin each requirement:
  - `format` #1: `test_format__fail__1_well_formed_file` (10 files, now with `missing-dsse`,
    `dsse-not-object`, `missing-signatures`, `missing-payload`),
    `__fail__1_no_duplicate_keys` (a repeated `pubkey`), `__fail__1_nested_at_most_64_deep`,
    `__fail__1_dsse_is_an_object` (4), `__fail__1_payload_type_is_a_string` (5, exact reasons
    `malformed: dsse.payloadType: …`, with a top-level `payloadType` present that is not
    read), `__fail__1_signatures_is_an_array` (4), `__pass__1_nesting_at_the_limit`,
    `__pass__1_brackets_inside_strings_do_not_nest`.
  - `format` #2: `test_format__fail__2_payload_is_strict_base64` (15: missing, null, number,
    list, padding dropped/short/extra, newline/space inside, newline after, `-`, `_`, `!`, a
    non-ASCII letter, unused bits set), `__fail__2_payload_has_one_spelling_per_byte_string`
    (`e31=`, `e32=`, `e33=` all decode to `{}` beside a passing `e30=`),
    `__fail__2_body_is_utf8` (4), `__fail__2_body_is_a_json_object` (8),
    `__fail__2_body_has_no_duplicate_keys` (exact reason `malformed: body: duplicate JSON key
    'phase'`), `__fail__2_duplicate_key_nested_in_the_body`,
    `__fail__2_body_nested_at_most_64_deep` (a body 65 deep in a file 3 deep),
    `__pass__2_body_nesting_is_counted_in_the_body_alone` (64 deep passes),
    `__pass__2_brackets_inside_body_strings_do_not_nest`,
    `__pass__2_body_bytes_are_read_as_stored` (spaced, reordered bytes pass, and the reported
    `ref` is the sha-256 of exactly those bytes), `__pass__2_lone_surrogate_escape_in_the_body_is_valid_json`,
    `__pass__2_small_body_as_signed`.
  - `format` #3: the 9 `payloadType` cases now set `dsse.payloadType`;
    `__fail__3_unknown_format_is_not_judged_by_this_formats_frame` (no signatures, payload
    `"?"`: the upgrade reason), `__fail__3_never_falls_back_to_this_releases_rules`,
    `__fail__3_file_laid_out_before_0_4_0` (0.3.x layout: pre-0.4.0 reason under the 0.3.x
    type, `malformed: dsse: Field required` under the current one).
  - `selfsig`: `test_selfsig__fail__1_exactly_one_signature` (none, two copies of the valid
    one, a junk second, an empty first, a string, `null`, an array entry),
    `__fail__2_pubkey_and_sig_are_hex` (10: missing, null, non-hex, odd length, number,
    array, object), `__pass__2_hex_accepts_either_case_and_whitespace` (moved from format),
    `__fail__3_signature_covers_the_body_bytes`,
    `__fail__3_signature_covers_the_bytes_not_the_json` (the same JSON respaced fails),
    `__fail__3_signature_by_pubkey`, `__fail__4_keyid_derives_from_pubkey` (missing, null,
    another key's, number, object). Each asserts `format=PASS`, `4/4 manifest(s) ok`, and
    `selfsig` `1/4 manifest(s) failed`.
  - #44 under the new counting:
    `test_matching__fail__4_prereg_meets_selfsig_conditions` gains `two-signatures`,
    `two-valid-signatures`, `pubkey-missing`, `pubkey-not-hex` and `sig-missing` (each a
    rejected pre-registration whose keyid is `dsse.signatures[0].keyid`, all three postregs
    under it, no commitment, no notarization-only);
    `test_run__postreg_failing_only_selfsig_is_rejected_under_its_commitment` (6: non-hex or
    missing `pubkey`, missing `sig`, missing `keyid`, no signature, two signatures).
  - Run rules: `test_run__malformed_file_fails_format_and_no_other_test_examines_it` gains
    `duplicate-key-in-body` (validly signed, ceiling kept) and `not-base64`;
    `test_run__file_failing_format_is_examined_by_no_other_test` (a body with a floor and a
    subject that fails on a duplicate key, on not being an object, or on an unknown format);
    `__malformed_postreg_joins_no_commitment` and `__prereg_failing_format_is_not_a_provided_prereg`
    use frame faults instead of the old non-hex case.
  - Never raises: `test_never_raises__lone_surrogate_escape_in_the_body` (10 body strings, with
    ceiling, chain, content and keyconsist), `__subject_named_as_no_path_can_be` (a lone
    surrogate and a NUL: `artifact not found`), `__lone_surrogate_escape_as_due_or_link`
    (`invalid-due`; notarization-only with that `fulfills`),
    `__lone_surrogate_escape_as_a_claimed_keyid` (a rejected pre-registration with that
    keyid). `test_cli.py::test_verify_shows_lone_surrogates_escaped` checks the report prints
    `due          : \ud800`, `(fulfills \udfff)` and `✗ \ud801: artifact not found`.
  - Planted faults: unknown fields of the file, of `dsse` and of the signature entry
    (`alg`), and a top-level `payloadType`, are not read; `test_fault__body_not_an_object`,
    `__payload_as_json_rather_than_base64` (0.3.x's object payload),
    `__very_deep_body_fails_format_everywhere` (100,000 levels, signed),
    `__postreg_with_a_duplicate_key_in_the_body_joins_no_commitment`.
  - Writer: `tests/test_manifest.py::test_sign_writes_a_dsse_envelope_in_the_wrapper` (exact
    keys and order, payload = base64 of the canonical bytes, one `{keyid, sig}`),
    `test_read_body_refuses_what_is_not_a_body` (7), `test_sign_refuses_a_body_with_no_utf8_form`,
    `test_writer_writes_exactly_one_signature[0|2]`, `test_writer_payload_is_strict_base64`,
    `test_writer_pubkey_rejects_non_lowercase_hex`; `tests/test_primitives.py` strict base64
    round trip (5) and one-spelling (11).
  - CLI: `test_postreg_inherits_target_due_and_declaration_from_the_prereg_body`,
    `test_fulfills_is_the_digest_of_the_prereg_bytes_as_stored` (a prereg whose stored bytes
    are spaced and unordered: `fulfills` is their sha-256, and verify gives `[FULFILLED]`),
    `test_fulfills_file_with_no_readable_body_is_a_clean_error` (3),
    `test_postreg_inheriting_a_string_with_no_utf8_form_is_a_clean_error` (exit 1),
    `test_verify_version_skew_reads_as_format_not_signature` (now `[None]`).
  - Constants: `test_signing_pae_version_and_manifest_payload_type` (`b"DSSEv1"`),
    `test_formats_has_one_entry_keyed_by_manifest_payload_type`,
    `test_signing_input_of_the_frozen_v1_vector` (the literal
    `b'DSSEv1 30 application/vnd.asexec.v1+json 31 {"phase":"prereg","target":"m"}'`, and
    `FROZEN_MANIFEST`'s payload decodes to those 31 bytes), the new
    `test_ref_of_the_frozen_v1_vector_is_the_digest_of_its_stored_body_bytes` (literal
    `sha-256:2e2ecfe5…48e53e`, through `manifest.ref` and through verify's report),
    `test_signing_key_alg` (the algorithm is in key files and identity documents; a
    manifest's signature entry is exactly `{keyid, sig}`), `test_not_enforced_yet__signature_alg`
    (an `alg` in the entry is not read), the roundtrip (refs equal the stored bytes' digest).
- **Frozen vectors regenerated by the production signer.** A script in the session scratchpad
  calls `manifest.sign(body, bytes(32), pub)` with only its bedrock gate stubbed out (the
  frozen bodies hold just `phase` and `target`, and a subject), as checkpoint 1 did. Run on a
  worktree at `c08ad59` first, it printed the vectors then in the file exactly (`afd85bcb…`,
  `13dccac3…`), so it is the method that made them. On this branch it printed the DSSE files
  now in `tests/test_constants.py`: `FROZEN_MANIFEST` payload
  `eyJwaGFzZSI6InByZXJlZyIsInRhcmdldCI6Im0ifQ==`, sig `39bf368a…08a60f`;
  `FROZEN_NO_HASH_ALG_MANIFEST` sig `32b453cc…cf120b`. `FROZEN_KEY` loses `alg`, the keyid
  and pubkey are unchanged. `PRE_V1_MANIFEST`, the genuine 0.3.x file, is unedited and gives
  `format=FAIL selfsig=FAIL` with the pre-0.4.0 reason.
- **Interop, independent of asexec** (a scratchpad script that imports only `json`,
  `base64`, `binascii`, `hashlib` and PyNaCl, run with `python -I`): it builds the PAE by hand
  from the DSSE protocol (`"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`), decodes the
  payload with `binascii.a2b_base64(strict_mode=True)` and requires it to re-encode to the
  same string, verifies the signature with `nacl.signing.VerifyKey` directly, checks the
  keyid, computes `ref = sha256(base64decode(payload))` and checks each `fulfills`/`prev_hash`
  against those refs. On CLI-produced `prereg.json`, `postreg-1.json`, `postreg-2.json`:
  `sig=OK keyid=OK` for all three, refs `b17107d0…`, `da0adf83…`, `ae569ef2…` (the CLI printed
  the same), PAEs starting `DSSEv1 30 application/vnd.asexec.v1+json 101 {"phase":"prere…`,
  every link names a file given, `ALL OK`, exit 0. On the two frozen vectors: `ALL OK`. On the
  edited-body and relabelled files below: `sig=BAD`, exit 1.
- CLI demonstrations, in a scratch dir (`keygen`; `prereg --target "model m via provider p"`;
  `postreg --fulfills prereg.json [--prev postreg-1.json]`). The cases are `postreg-1.json`
  edited by hand as JSON (a scratchpad script that does not import asexec). Each is
  `asexec verify prereg.json <case> --tests format,selfsig,chain,keyconsist`.
  - Good chain: the three files give `[FULFILLED]` (`postregs : 2`), `asexec-verify/1
    chain=PASS format=PASS keyconsist=PASS selfsig=PASS`, exit 0. `prereg.json`:
    ```
    {"dsse": {"payloadType": "application/vnd.asexec.v1+json",
              "payload": "eyJwaGFzZSI6InByZXJlZyIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL2FzZXhlYy5vcmcvbWFuaWZlc3QvdjEiLCJ0YXJnZXQiOiJtb2RlbCBtIHZpYSBwcm92aWRlciBwIn0=",
              "signatures": [{"keyid": "sha-256:bc5627006c7d…66f9945c", "sig": "7a816afd…3d8600"}]},
     "pubkey": "91230c4ebff9…a9f86c58"}
    ```
  - Malformed, each `✗ <file>  [None]  keyid=None`, `[OPEN]` with `postregs : 0`, `format=FAIL
    (1/2 manifest(s) failed)`, `selfsig=PASS (1/1 manifest(s) ok)`, code `chain=FAIL
    format=FAIL keyconsist=FAIL selfsig=PASS`, exit 2, with the reason:
    - bad base64 (a `!` in it): `✗ format: malformed: dsse.payload: Value error, not strict
      base64 (the standard alphabet, padded, no whitespace, one spelling per byte string)`;
    - non-canonical base64 (`…BwIn0=` → `…BwIn1=`, the same bytes): the same reason;
    - body not an object (`[` + body + `]`, re-encoded): `✗ format: malformed: body: the body
      must be a JSON object`;
    - duplicate key inside the body: `✗ format: malformed: body: duplicate JSON key 'phase'`;
    - missing signatures: `✗ format: malformed: dsse.signatures: Field required`.
  - `selfsig`, each `✗ <file>  [postreg]  keyid=…` with no reason line, `[OPEN]` with `✗ postreg
    sha-256:da0adf83… does NOT count toward fulfillment: invalid signature`, `format=PASS
    (2/2 manifest(s) ok)`, `selfsig=FAIL (1/2 manifest(s) failed)`, code `chain=FAIL
    format=PASS keyconsist=FAIL selfsig=FAIL`, exit 2: zero signatures (`keyid=None`), two
    signatures (two copies of the valid one), missing `pubkey`, missing `sig`, non-hex
    `pubkey`, non-hex `sig` (the last four `keyid=sha-256:bc562700…`).
  - Edited body (decoded, `target` changed, re-encoded, signature kept): `✗ e-edited-body.json
    [postreg]`, `✗ postreg sha-256:25640381… does NOT count toward fulfillment: invalid
    signature` (a new ref, as it is a new body), `format=PASS selfsig=FAIL`, exit 2.
  - Relabelled, unknown (`dsse.payloadType` → `application/vnd.asexec.v2+json`): `✗
    r-relabelled-v2.json  [None]  keyid=None`, `✗ format: payloadType names a format newer
    than this release: upgrade asexec to read it`, `format=FAIL selfsig=PASS`, exit 2.
  - Relabelled, known (signed by the same key over the PAE of the `v2` type, then labelled
    `v1`, the one type this release reads): read as `v1`, `invalid signature`, `format=PASS
    selfsig=FAIL`, exit 2.
  - A prereg with two signatures (`p-prereg-two-signatures.json`) beside both postregs: `(no
    commitments: no pre-registration provided is validly signed)`, `=== rejected
    pre-registrations ===`, `✗ prereg sha-256:b17107d0… is NOT a commitment: invalid
    signature`, `keyid : sha-256:bc562700…`, both postregs `does NOT count toward fulfillment:
    the pre-registration's signature is invalid`, `chain=FAIL format=PASS keyconsist=FAIL
    selfsig=FAIL`.
  - The `docs/VERIFICATION.md` examples were rebuilt from these runs: refs are unchanged (the
    stored bytes are the old canonical bytes), the key is new (`7bc19c1d…` → `bc562700…`),
    and the truncated file's reason is now `Unterminated string starting at: line 4 column 16
    (char 82)`.
- `uv run python examples/adequacy-test/run.py`: exit 0, and its output is **byte-identical**
  before (`c08ad59`) and after (`diff` empty): `no fault` `chain=PASS content=PASS format=PASS
  keyconsist=PASS selfsig=PASS`, swapped plants `content=FAIL` (caught), the other two faults
  missed as before. Its faults never edit a manifest (they re-run the CLI or edit artifacts),
  so nothing in it needed to decode or re-sign a body, and no code changed.
- The pre-existing NUL crash: on a worktree at `c08ad59`, a validly signed prereg with subject
  name `a\x00b` made `verify_paths` raise `ValueError: lstat: embedded null character in path`
  with `--tests format,selfsig,content`. It now fails content #4.
- Nothing left behind: `git grep -n -e 'signature\.pubkey' -e 'signature\.sig' -e
  'signature\.keyid' -e '"signature"' -e 'asexec-PAE' -e canonical -e get_body -e
  'signature\.alg'` outside this file finds only:
  - `"signature"` of drand floors (`drand.py`, `body.anchor.floor.signature` in tests, the
    README and VERIFICATION examples), a different field;
  - the old layout on purpose: `PRE_V1_MANIFEST` and its comment, the 0.3.x-layout inputs in
    `test_verify_format.py` and `test_manifest.py`, `docs/FORMAT.md`'s 0.3.x bullet and
    example, `ROADMAP.md`'s identifiers bullet ("`asexec-PAE/v1` before the DSSE envelope") and
    MULTIVERSION's rejected-selector row for `signature.alg`;
  - `asexec-PAE/other`, the test-only second format of the selector tests;
  - `canonical_bytes`, kept as signing's serialization (writer, `tests/manifest_data.py`, and
    the tests that build signed files), `canonical.py` itself, and unrelated uses ("canonical
    verify code", Roughtime's canonical tag order, `ROADMAP.md`'s JCS item and history).

  No verification path canonicalizes: `signing_input` and `manifest.ref` take bytes, and
  `verifier.py` imports `b64decode` and `signing_input` from `canonical.py`, not
  `canonical_bytes`. The top-level `signature` and `payloadType` are gone from every model and
  writer; `Signature.alg`, `EnvelopeInput.payload`/`payloadType`/`signature` and
  `manifest.get_body` are removed.
- CI on PR #55 at `618be15` (run 44741202075): lint, python-matrix, test (3.12, 3.13, 3.14)
  and build pass.

**Release-note entries** (for #40, in the `tests/test_constants.py` header format):

```
Identifier: FORMATS[MANIFEST_PAYLOAD_TYPE]["signing_pae_version"], asexec-PAE/v1 -> DSSEv1
Impact: BREAKS_USERS
Affected: every manifest signed before this change: the PAE prefix is in the signed bytes (and the file layout changed too, below)
Action: re-sign with this release

Identifier: the manifest file layout (no constant): {payloadType, payload: <object>, signature: {alg, keyid, pubkey, sig}} -> {dsse: {payloadType, payload: <base64 of the body bytes>, signatures: [{keyid, sig}]}, pubkey}
Impact: BREAKS_USERS
Affected: every manifest written before this change is malformed ("dsse: Field required"), except a 0.3.x file, which fails format with the pre-0.4.0 reason; tools that read payload or signature.* from a file; the Python API (manifest.get_body removed, manifest.ref takes the body bytes, canonical.signing_input takes bytes, models.Signature has no alg or pubkey)
Action: re-sign with this release; read the body by base64-decoding dsse.payload, and the key from pubkey and dsse.signatures[0]
```

**Observations (out of scope):**
- **For the human gate: hex `sig` is not standard DSSE.** The DSSE envelope spec gives `sig` as
  base64 of the signature (and allows standard or URL-safe base64 for `payload`). This
  checkpoint follows its brief: `sig` and `pubkey` are hex, judged by `selfsig` #2, and
  `payload` must be standard padded base64. `ROADMAP.md` (*Wrapper*) says `dsse` is "a
  standard envelope that DSSE and in-toto tooling can lift out and verify unchanged": with a
  hex `sig`, standard tooling would base64-decode the hex string and fail. Either `sig`
  becomes base64 (another format change, before 0.4.0 fixes the format) or the ROADMAP claim
  is narrowed. Our strict `payload` rule is a subset of DSSE's, so an envelope another DSSE
  tool writes with URL-safe base64 would be malformed here.
- The manifests block still gives no reason for a file that passes `format` and fails
  `selfsig` (checkpoint 2's observation). With four `selfsig` conditions it would help more:
  "two signatures" reads very differently from "signature does not verify". Every failure
  is still `invalid signature` in the commitment and rejected-pre-registration blocks.
- Checkpoint 5's open item stands: unauthenticated strings (a claimed keyid, `body.fulfills`,
  a subject name) are printed raw apart from `cli._show`'s escape of characters with no UTF-8
  form, so a newline in one can still forge report lines.
- `tests/verify/test_verify_format.py` pins pydantic's text for a non-object `dsse` (`Input
  should be a valid dictionary or instance of DsseInput`), which shows a class name in a
  user-facing reason, and the base64 reason carries pydantic's `Value error, ` prefix. Both are
  stable across the supported pydantic, but a reason of asexec's own would read better.
- `src/asexec/manifest.py` `get_ceiling` is used only by `tests/test_manifest.py` (it predates
  this checkpoint).
- For #33 (checkpoint 7): `FROZEN_NO_HASH_ALG_MANIFEST` relies on the body-level `hash_alg`
  fallback, which #33 removes, and D6 has #33 regenerate the vectors again; the regeneration
  script and the interop script from this checkpoint (session scratchpad) can be reused.
- For #34: nothing here reads an unknown top-level key; they are ignored as before
  (`test_fault__unsigned_envelope_field_verify_does_not_examine`), and #34 puts them under
  *untrusted*.

**Judgement calls / new paradigms:**
- **Path notation `body.<path>`**, chosen over keeping `payload.<path>`: `dsse.payload` is now a
  base64 string, so `payload.phase` would read as a member of a string. Every path that does
  not start `body.` is from the file's root. Defined once under *Conventions*.
- **`format` numbering:** #1 the file and frame (`dsse`, `dsse.payloadType`,
  `dsse.signatures`), #2 the payload and body, #3 the type, so #3 keeps its number and tests.
  "A `payload` that strict-decodes to a JSON object" is #2 rather than part of #1 because it
  is the one frame rule with its own rules (base64, UTF-8, the body's JSON rules).
- **`selfsig` numbering:** #1 one entry, #2 hex, #3 the signature, #4 the keyid, so each of the
  brief's selfsig cases fails exactly one item.
- **Body depth is counted in the body alone**, from its own outermost object. The file holds
  it as a string, so a body's depth is the same in any file, and the limit means what it says
  for both.
- **Body bytes must be UTF-8, without a BOM** (RFC 8259 §8.1): `json.loads(bytes)` would
  otherwise auto-detect UTF-16/32, and two verifiers could read different text from the same
  signed bytes. JSON that is not an object, and empty bytes, are malformed (#2, "decodes to a
  JSON object").
- **A lone surrogate escape is valid** (it does not stop verify reading the manifest, which is
  now all that "malformed" means): it passes `format` and `selfsig`, and every reader treats
  it as an ordinary string. The report escapes it with `backslashreplace` on every line,
  rather than a per-field escape; this changes nothing for any other text. A subject name
  that no path can have (`ValueError` from `realpath`: a NUL, or a surrogate the filesystem
  encoding can't encode) is `artifact not found` (content #4), the item about whether the
  artifact exists.
- **0.3.x files keep their reason.** Checkpoint 3 gave genuine 0.3.x files the pre-0.4.0
  reason; with the selector moved into `dsse`, a 0.3.x file has no `dsse.payloadType`, so
  `verify_format` also recognizes 0.3.x's own layout (no `dsse`, top-level `payloadType ==
  "application/vnd.asexec+json"`). Any other `dsse`-less file is malformed. Documented in
  `format` #3.
- **The claimed keyid is `dsse.signatures[0].keyid`**, whatever the number of entries, and
  `None` if the list is empty or its first entry is not an object (#44's rule: "postregs
  follow the same matching conditions with `dsse.signatures[0].keyid` as signer").
- **Strict base64 lives in `fields.Base64`** (a structural rule, like `Hex`, so the writer's
  `Dsse` model uses it too), and the body's JSON rules are code (`manifest.parse_body`), beside
  `manifest.load` and sharing its parser. The base64 reason is asexec's own fixed text,
  so it does not change with the Python version's `binascii` messages.
- **`verify_format` returns the body bytes and body**, which `verify_paths` pops before the
  record goes into the report, so the report's `manifests[].format` slice keeps its shape and
  carries no body.
- **The writer refuses a string with no UTF-8 form** (`canonical_bytes` raises
  `ManifestError`), so the CLI prints an error and exits 1 instead of a traceback.
- **`canonical.py` is kept and repurposed** ("the body bytes signing writes, their one base64
  spelling, and the PAE signing input") rather than splitting base64 into a new module.
- **`docs/FORMAT.md`** (not in #32's list): the banner now says the DSSE envelope is built and
  `untrusted` is not; the PAE example uses `DSSEv1`; "Today (0.3.x)" is "0.3.x". Nothing else.
  `docs/MULTIVERSION.md` and `docs/DEVELOPMENT.md` (also not listed) had sentences this made
  false (the selector "reads the top-level `payloadType` until the DSSE switch", the PAE
  comment, the `signature.alg` rows, the test-path example); only those are changed.
- No new dependency, system or paradigm.

**Change before review: `sig` is base64** (the orchestrator's instruction on PR #55, commit
`f639dd4`):
- **Judgement call, for the human gate:** the orchestrator decided that
  `dsse.signatures[].sig` is base64, as DSSE has it (`Base64(SIGNATURE)`), to keep
  `ROADMAP.md`'s *Wrapper* promise that `dsse` is a standard envelope DSSE and in-toto
  tooling can lift out and verify unchanged. #32 builds the envelope "as in ROADMAP.md". The
  alternative was to keep the hex `sig` the original brief asked for and narrow that promise.
  This resolves the first observation above.
- What changed:
  - `sig` is the same strict base64 as `dsse.payload`: the standard alphabet, padded, no
    whitespace, one spelling. It must also be of 64 bytes, an ed25519 signature's length.
    That is `fields.SignatureBase64`, used by `SignatureInput` and by the writer's
    `Signature`.
  - A missing, non-string or non-base64 `sig`, and one of another length, fail `selfsig` #2
    (now "`pubkey` is hex, and `dsse.signatures[0].sig` is strict base64 of 64 bytes"),
    never `format`.
  - `pubkey` stays hex: it is in the wrapper, outside `dsse`, and the keyid is still
    `sha-256:` + sha256 of its bytes.
  - `manifest.sign` writes `b64encode(sig)`, and `verify_selfsig` decodes it with
    `canonical.b64decode`.
- `payload` stays standard-alphabet strict base64, which is stricter than DSSE verifiers
  (they also accept URL-safe). The promise is that DSSE tools read asexec's `dsse`, which
  this keeps. This is said in `docs/VERIFICATION.md` (*Base64*, and the conventions' file
  description), the README (after the examples), `ROADMAP.md` (*Wrapper*) and
  `docs/FORMAT.md` (the DSSE paragraph). The README examples show base64 `sig` values.
- Red first: with only the tests changed, 367 failed and 270 passed. Every valid file read
  `selfsig=FAIL`, because the verifier still parsed `sig` as hex. After the code changed,
  only the three frozen-vector tests failed, on their placeholders.
- `scripts/check.sh`: clean, 638 passed (620 before this change).
- Tests:
  - `test_selfsig__fail__2_pubkey_is_hex_and_sig_is_present` (11): `sig` missing, null, a
    number, an object, not base64.
  - `test_selfsig__fail__2_sig_is_strict_base64_of_64_bytes` (10): hex as before, padding
    dropped or extra, a newline inside, a space after, the URL-safe alphabet, an unused bit
    set, 63 bytes, 65 bytes, empty. The test asserts that postreg0's signature holds both
    `+` and `/`, so the URL-safe case really differs.
  - `test_selfsig__pass__2_pubkey_hex_accepts_either_case_and_whitespace`. `sig` has no
    pass branch: it has one spelling.
  - `test_matching__fail__4_prereg_meets_selfsig_conditions[sig-as-hex]`: a prereg with a hex
    `sig` is a rejected pre-registration.
  - `test_fault__signature_fields_of_the_wrong_shape` gains `sig-65-bytes` and `sig-as-hex`.
  - `tests/test_manifest.py::test_writer_signature_is_strict_base64_of_64_bytes` (6).
  - `test_signing_key_alg` checks that the written entry is `{keyid, sig}` with `sig` the
    base64 of 64 bytes.
  - Test helpers use `manifest_data.b64` and `ZERO_SIG` (base64 of 64 zero bytes, a
    well-formed signature that no key made) where they used `"00" * 64`.
- Frozen vectors regenerated by `manifest.sign` with the same scratchpad script:
  - On `618be15` (hex) it printed the vectors then in the file exactly (`39bf368a…`,
    `32b453cc…`).
  - On this branch it prints `Ob82ilGMEivKXPiY/S76…LwimDw==` and
    `MrRTzCmZpaeniNSl87Vq…Cs8SCw==`.
  - These decode to the same 64 bytes: ed25519 is deterministic and the PAE did not change,
    so only the spelling changed. The payloads are unchanged.
- Interop script: its hand-written DSSE check now base64-decodes `sig` per the spec
  (`signatures[].sig = Base64(SIGNATURE)`) and requires 64 bytes before
  `nacl.signing.VerifyKey.verify`.
  - Re-run on CLI-made `prereg.json`, `postreg-1.json` and `postreg-2.json` (signed by the
    same key as before): `sig=OK keyid=OK` for all three, the same refs, every link found,
    `ALL OK`, exit 0.
  - On the two regenerated frozen vectors: `ALL OK`, exit 0.
- CLI:
  - The good chain gives `chain=PASS format=PASS keyconsist=PASS selfsig=PASS`, and its
    prereg's entry is `{"keyid": "sha-256:bc5627006c7d…", "sig":
    "eoFq/aI9/hpjhouo+Zow2HJf…Sz2GAA=="}`.
  - `postreg-1.json` with its `sig` respelled as hex (`s-hex-sig.json`), as URL-safe base64
    (`s-urlsafe-sig.json`), or cut to 63 bytes (`s-63-byte-sig.json`): each shows `✗
    <file>  [postreg]  keyid=sha-256:bc562700…`, `format=PASS (2/2 manifest(s) ok)`,
    `selfsig=FAIL (1/2 manifest(s) failed)`.
  - The earlier `selfsig` demos (zero or two signatures, missing `pubkey` or `sig`,
    non-hex `pubkey`) are unaffected. The "non-hex `sig`" demo now reads as "not base64",
    with the same result.
  - The `docs/VERIFICATION.md` format example shows `"sig": "eoFq/aI9/hpjhouo…"`.
- `examples/adequacy-test/run.py`: exit 0, output byte-identical to the pre-checkpoint run.
- Nothing left behind: `git grep -i` for `sig` near `hex` in `src`, `tests` and the docs finds
  only `pubkey`'s hex and the deliberate hex-`sig` failure cases.
- The two open items above (no reason line for a `selfsig` failure; forgeable report lines)
  stay as observations, as instructed.

**Review round 1** (findings on PR #55; the reviewer also checked DSSE conformance with its
own PyNaCl script and with securesystemslib's `dsse.Envelope.verify`, under which every
CLI-made file verified unchanged, and caught 17 mutants):
1. should-fix: nothing pinned that a ceiling binds to the stored-bytes `ref`. Every ceiling
   test signed canonical bytes, so a mutant that computed the ceiling nonce as
   `manifest.ref(canonical_bytes(body))`, falling back to `fmt["ref"]` when that raised,
   passed all 638 tests. → Two tests in `tests/verify/test_verify_ceiling.py`, each with the
   prereg's body stored validly signed with non-canonical spacing (`edit_body_bytes`):
   - `test_ceiling__pass__2_nonce_is_ref_of_the_stored_bytes`: a ceiling for those bytes
     passes (`verified`), and the reported `ref` is their sha-256.
   - `test_ceiling__fail__2_nonce_is_not_ref_of_a_reserialized_body`: a genuine ceiling for
     the canonical re-serialization of the same JSON value fails (`invalid`).

   With the reviewer's mutant planted in `verify_paths`, the suite gave 2 failed and 638
   passed, the two new tests. Reverted, it gave 640 passed. Commit `be12c3c`.
2. should-fix (docs): `docs/VERIFICATION.md` (*Base64*) and the README read as if the
   URL-safe alphabet were the only way asexec is stricter than DSSE (v1.0.2). → The same
   four ways are now stated once each in VERIFICATION.md (*Base64*), the README (after the
   examples), `ROADMAP.md` (*Wrapper*) and `docs/FORMAT.md` (the DSSE paragraph). No code
   change. Commit `2d28e91`. The four ways:
   - standard base64 only, a deliberate departure from DSSE's "verifiers MUST accept
     either alphabet";
   - padding required, where DSSE is silent;
   - a required `keyid` that must be `sha-256:` of `pubkey`, where DSSE has it optional,
     an unauthenticated hint;
   - exactly one signature, where DSSE allows several with a threshold.
3. nit: some docstrings still used the old notation. → `src/asexec/models.py` (the floor,
   ceiling nonce, subject, link and due slices), `src/asexec/fields.py` (`Link`) and
   `src/asexec/roughtime.py` (the module docstring and check 6) now say `body.*` and `ref`.
   Commit `81fb889`.
4. out of scope → observation below.

`scripts/check.sh`: clean, 640 passed. CI: see the PR.

**Observation added in review round 1 (out of scope):**
- **One file, two codes on one machine:** a validly signed body with a 5000-digit integer
  gives `format=FAIL` by default and `PASS` with `PYTHONINTMAXSTRDIGITS=0`.
  - Reproduced: `sign_bytes(b'{"phase":"prereg","notes":' + b"1" * 5000 + b"}")` gives
    `✗ format: malformed: body: Exceeds the limit (4300 digits) for integer string
    conversion: value has 5000 digits; …` and `format=FAIL selfsig=FAIL`, and with
    `PYTHONINTMAXSTRDIGITS=0`, `format=PASS selfsig=PASS`.
  - This breaks the *JSON* convention's "every supported Python version reads a file the
    same way": the verdict depends on an environment variable, and on interpreters that
    have no such limit.
  - It predates this PR at the file level (`manifest.load`, any number in the file), and
    #32 extends it to the body.
  - Suggested fix for later: a fixed rule checked before `json.loads`, beside the nesting
    check, such as "a number of more than N digits is malformed". It would make the limit
    asexec's own rather than the interpreter's. Not fixed here.

**Merged** (orchestrator): PR #55 merged into `feature/0321` as `ac5c6b8`, a merge commit,
with no review findings left open. The #32 change is `b0abfdb` plus `f639dd4` (`sig` in
base64). The review fixes are `be12c3c`, `2d28e91` and `81fb889`. The review agent checked
DSSE conformance without asexec code, with a hand-built PAE verified by PyNaCl and with
securesystemslib's `dsse.Envelope.verify`: all five CLI-made files verified unchanged. A
hand-built spec-conformant envelope passes `format` and `selfsig`. It also tried about 27
tricky base64 spellings, 38 hand-signed body cases and 29 frame cases, and ran every order
of a 6-file mix (720 orders) with identical reports. Each of 18 plausible wrong versions is
caught by a test, the last one after the review fix. With the b1 release-commit edit applied:
633 passed, 5 skipped with the D6b reason, roundtrip passing. Post-merge on `feature/0321` at
`ac5c6b8`: `scripts/check.sh` clean, 640 passed; `examples/adequacy-test/run.py` exit 0. CI on
the last PR push (`aad9918`, run 44773957313): lint, build, test on 3.12, 3.13 and 3.14 pass.
**Open for the human gate:** the orchestrator's choice of a base64 `sig`, to keep ROADMAP's
standard-envelope promise; the four documented ways asexec is stricter than DSSE; and the
verify result that depends on `PYTHONINTMAXSTRDIGITS` (see the observations above).

### Checkpoint 7: #33, #36, #46, #37

Written issue by issue as each landed (the brief asks for a log that is complete even if
the work is interrupted). Baseline: `feature/0321-checkpoint7` at `18c0955`, `scripts/check.sh`
clean, **640 passed**.

#### #33: subjects as explicit file lists

**Landed:** `18e63bf`. A subject entry is `{name, hash_alg, digest}`: `name` is the file's
normalized relative path, `hash_alg` is the entry's own. `hashing.build_subject` (with the new
`entry_name`, `build_entry`, `build_entries`, which #36 reuses) refuses a directory, anything
else that is not a regular file, an absolute path, a `..` component, a backslash and two paths
with one name (`ManifestError`, so the CLI exits 1 with `error: …`). `hash_dir`,
`_iter_files` and `digest_path` are removed. `models.SubjectEntryInput` now has `hash_alg:
str` (the `context={"hash_alg": …}` mechanism is gone), the writer's `SubjectItem.name` is
`fields.NormalName`, `ManifestBody` has no body-level `hash_alg` and refuses repeated names,
and `manifest.sign`'s dict gate refuses an entry without `hash_alg` or a repeated name.
`build_prereg`/`build_postreg` take no `hash_alg`. `FORMATS[...]["subject_default_hash_alg"]`
is removed. `content` has nine items. Docs: `docs/VERIFICATION.md` (*Formats*, the summary
row, the `content` section and example, the *Hex* convention's item number), `README.md`
(usage, both body examples, the *Known issues* section removed), `ROADMAP.md` (done-ahead
marks), `docs/MULTIVERSION.md` (the entry, the known-format bullet, the per-identifier row),
`docs/DEVELOPMENT.md` (the roundtrip). `examples/adequacy-test/run.py` signs in its artifacts
directory with relative names.

**What was settled (judgement calls):**
- **Relative to what:** the directory signing runs in; the name is the path as given, so
  verify's `--artifacts` must stand for that directory. Normalization is lexical: `.`
  components, repeated and trailing separators are dropped (`./b//run.py` → `b/run.py`), and
  on Windows `\` becomes `/`.
- **Refused at signing:** an absolute path (also a Windows drive path), rather than made
  relative to the current directory: there is no "relative path as given", and resolving it
  against a possibly symlinked current directory could silently pick another name. Any `..`
  component, even one that normalizes away (`d/../c.txt`): lexical collapse can name another
  file than the OS does when `d` is a symlink. A backslash where it is not a separator: it is a
  separator on Windows, so the same name would be two files. Two paths that normalize to one
  name (`c.txt` and `./c.txt`, or the same path twice).
- **`hash_alg` is required per entry, and has no default.** ROADMAP says "No property has a
  default", gives `subject[].hash_alg` the default "none", and *Dependencies sit with what
  they qualify* says each digest carries its own `hash_alg`. So the FORMATS field kept for the
  fallback (checkpoint 3) is removed, consistently: from `constants.py`, the pinned literal
  (`test_formats_has_one_entry_keyed_by_manifest_payload_type`), the selector test's second
  format, `docs/MULTIVERSION.md` and `docs/VERIFICATION.md`. `SUBJECT_DEFAULT_HASH_ALG` stays
  as the signing default (NEW_OUTPUT). An entry without its own `hash_alg` fails content #1
  (`malformed subject entry`), and so does a non-string one (it was #2 before).
- **content's items** (renumbered, since the section is rewritten; reasons in brackets):
  1. a non-empty array of objects with a string `name`, a string `hash_alg` and a hex
     `digest[hash_alg]` (`malformed subject entry`);
  2. `hash_alg` available (`algorithm unavailable: <alg>`);
  3. `name` in normal form: `/`-separated segments, none empty, `.` or `..`, no backslash
     (`name is not a normalized relative path`), so `./a`, `a//b`, `a/`, `a/../b`, `/a`,
     `a\b` fail, even when they would resolve to the right file;
  4. no other entry of the same list has the same `name` (`duplicate name`, on each of them);
  5. resolves inside `--artifacts` (symlinks followed);
  6. exists;
  7. **a regular file** (`artifact is not a file`): a directory, a symlink to one, a FIFO, a
     socket or a device fails and is never opened. Before, verify opened a FIFO and blocked
     forever (the red run below had to deselect that case);
  8. readable;
  9. digest equals.
- **Duplicates are per list:** the same name in two manifests, or (from #36) in `subject` and
  `evidence`, is not a duplicate.
- **postreg no longer inherits the prereg's `hash_alg`:** there is no body-level one to
  inherit. `postreg --hash-alg` now defaults to `sha-256`, like `prereg --hash-alg`.
- **Frozen vectors (D6):** `FROZEN_NO_HASH_ALG_MANIFEST` is replaced by
  `FROZEN_SUBJECT_MANIFEST` (an entry with its own `hash_alg`; sig `s/vhj6pty0QZTW…3ki7BQ==`),
  regenerated by `manifest.sign` with only its bedrock gate stubbed (script in the session
  scratchpad, `cp7/regen_vectors.py`). The same script printed `FROZEN_MANIFEST` and the old
  no-`hash_alg` vector byte for byte as they were in the file, so it is the method that made
  them. The old vector is kept as `NO_HASH_ALG_MANIFEST`, and
  `test_subject_entry_hash_alg_has_no_fallback` pins that it now fails content #1 (as
  `PRE_V1_MANIFEST` pins the payloadType change).

**Evidence:**
- Red first: with only the tests changed, the full suite hung on
  `test_content__fail__7_artifact_is_a_file[fifo]` (the old `digest_path` opened the FIFO and
  blocked). With the two FIFO tests deselected: **59 failed, 634 passed**. The failures were
  the new refusals (`build_subject` accepting a directory, an absolute path, `..`, a backslash,
  duplicates; the CLI exiting 0 for them), `pydantic ValidationError` from `ManifestBody`
  (entries now carry `hash_alg`, which the old writer forbade), content still reading the
  body-level `hash_alg`, content passing non-normal names, duplicates and directories, the
  FORMATS literal, and the doc-coverage test (`content` #7-#9 had no doc item).
- `scripts/check.sh` after: clean, **695 passed** (640 before).
- Tests that pin each requirement:
  - content: `test_content__pass__all`; `__fail__1_entry_is_well_formed` (11 cases, among
    them `hash_alg-missing`, `hash_alg-null`, `hash_alg-number`, `hash_alg-list`,
    `digest-not-object`); `__fail__1_subject_is_a_non_empty_array`;
    `__pass__1_body_level_hash_alg_is_not_read` (`blake9`, a number, `null`);
    `__fail__2_hash_alg_is_available`; `__fail__3_name_is_a_normalized_relative_path` (10:
    absolute, `./`, `/./`, `//`, trailing `/`, `..` inside and first, backslash, empty, `.`);
    `__fail__4_names_are_unique` (same and different digests: both entries fail);
    `__pass__4_the_same_name_in_two_manifests_is_not_a_duplicate`;
    `__fail__5_name_resolves_inside_artifacts` (an escaping symlink);
    `__pass__5_symlink_inside_is_hashed_through_to_its_target`;
    `__fail__6_artifact_exists` (deleted, dangling symlink); `__fail__7_artifact_is_a_file`
    (a directory given its old v1 hash, a symlink to a directory, a FIFO);
    `__fail__8_artifact_is_readable`; `__fail__9_digest_equals_recomputed`;
    `__pass__9_digest_hex_accepts_either_case_and_whitespace`; the four empty cases.
  - Planted: `test_fault__hash_alg_only_at_the_body_level` (0.3.x's layout fails content).
  - Never raises: `SIGNED_JUNK` gains `entry-hash_alg`, `entry-hash_alg-obj`,
    `entry-name-list`; the lone-surrogate case moves to `body.subject.0.hash_alg`;
    `test_never_raises__subject_named_as_no_path_can_be` uses `harness\x00.py` (content #6).
  - Writer: `tests/test_primitives.py::test_directory_hashing_is_gone`,
    `test_build_subject_names_each_file_by_its_normalized_relative_path`,
    `test_build_subject_hashes_a_symlink_through_to_its_target`,
    `test_build_subject_refuses_what_content_would_fail` (8),
    `test_build_subject_refuses_a_backslash_in_a_name`,
    `test_build_subject_refuses_what_is_not_a_regular_file` (FIFO),
    `test_build_subject_of_a_missing_file_raises_os_error`; `tests/test_manifest.py::
    test_subject_entry_requires_its_own_hash_alg`, `test_builders_take_no_body_level_hash_alg`,
    `test_writer_subject_entry_requires_hash_alg`, `test_writer_refuses_duplicate_subject_names`,
    `test_sign_refuses_a_hand_built_body_with_duplicate_subject_names`,
    `test_writer_refuses_a_name_that_is_not_a_normalized_relative_path` (8).
  - CLI: `test_errors_exit_EXIT_ERROR_with_a_message_not_a_traceback` gains
    `subject-directory`, `subject-absolute`, `subject-dotdot`, `subject-twice`,
    `postreg-subject-directory`; `test_subjects_are_files_named_by_their_relative_paths`.
  - Constants: the FORMATS literal (three fields), `test_frozen_manifests_still_verify`
    (`FROZEN_SUBJECT_MANIFEST` decodes to `FROZEN_SUBJECT_BODY`, `content=PASS`),
    `test_subject_entry_hash_alg_has_no_fallback`, the roundtrip (a writer file and a hand-signed
    file, each entry under its own `hash_alg`).
- CLI demonstrations (scratch dir `art/` with `a/run.py`, `b/run.py`, `harness/eval.py`; run
  inside `art/`):
  - `prereg --subject harness` → `error: 'harness' is a directory; list its files, or pack it
    (a tar, say) and list that`, exit 1. An absolute path → `error: '…/art/a/run.py' is an
    absolute path; name a file by its path relative to the current directory (verify looks it
    up under --artifacts)`, exit 1. `../art/a/run.py` → `… has a '..' component; name the
    file without it`, exit 1. `a/run.py ./a//run.py` → `'a/run.py' and './a//run.py' both
    name 'a/run.py': a file is listed twice`, exit 1. Nothing written in each case.
  - `prereg --subject a/run.py b/run.py harness/eval.py`: the body holds
    `"subject":[{"digest":{"sha-256":"2c8b08da…"},"hash_alg":"sha-256","name":"a/run.py"},
    {…"name":"b/run.py"},{…"name":"harness/eval.py"}]` and no body-level `hash_alg`; `verify
    pre.json --tests format,selfsig,content --artifacts art` → `✓ content hashes ok`,
    `content=PASS format=PASS selfsig=PASS`, exit 0.
  - A hand-signed body (`cp7/handsign.py`, which signs any body as anyone with a key could)
    naming `harness`, `a/run.py` twice, `harness/../a/run.py`, `a\\run.py`, and `b/run.py`
    without `hash_alg`, beside a body-level `hash_alg`: `✗ harness: artifact is not a file`,
    `✗ a/run.py: duplicate name` (twice), `✗ harness/../a/run.py: name is not a normalized
    relative path`, `✗ a\\run.py: name is not a normalized relative path`, `✗ b/run.py:
    malformed subject entry`, `content=FAIL format=PASS selfsig=PASS`.
- `uv run python examples/adequacy-test/run.py`: exit 0, the same codes, states and
  caught/missed results as before (`run.py` now runs signing with `cwd=<artifacts>` and
  relative names, since an absolute `--subject` is refused).
- Nothing left behind: `git grep -n -e hash_dir -e digest_path -e subject_default_hash_alg
  -e 'body\.hash_alg' -e '"harness/"'` outside this file finds only `ROADMAP.md:167` (the
  bullet saying to remove `hash_dir`), `docs/MULTIVERSION.md:105` and
  `docs/VERIFICATION.md:329` (saying the field and the body-level `hash_alg` are gone),
  `tests/test_constants.py` (`test_subject_default_hash_alg`, the constant that stays, and the
  no-fallback test's comment) and `tests/test_primitives.py` (the assertions that both
  functions are gone).

**Observations (out of scope):**
- On a case-insensitive filesystem, `A.txt` and `a.txt` are two names for one file: content #4
  compares names exactly, so it does not see them as duplicates (each still hashes the one
  file). A name holding `:` (`C:x`) is relative on POSIX but drive-relative on Windows, where
  content #5 then fails it, so the verdict on such a name can differ between systems.
- `prd.md:48` still describes the harness hash as "directory tree hash, e.g., a Merkle tree
  over files". `prd.md` is the original brief and no issue covers it.
- `ROADMAP.md` says a body-level `hash_alg` is "shown as unknown and unchecked"; showing
  unknown fields is #34's (checkpoint 8). It is read by nothing now.

#### #36: the claim record

**Landed:** `5ac205f`. Body fields, all optional: a prereg's `plan` (`name`, `hash_alg`,
`digest`, `media_type`, `label`) and `items[]` (`id`, `kind`); a postreg's `item_id`, `status`
and `evidence[]` (`name`, `hash_alg`, `digest`, `media_type`, `uri`). Writer models `Plan`
and `EvidenceItem` subclass `SubjectEntryInput`, and `Item` subclasses the new input model
`ItemInput` (`id: str`, for #37); `ManifestBody` gains the five fields (`status` is
`Literal["reported", "excluded", "blocked"]`, `models.STATUSES`; `evidence` has at least one
entry). `content` examines `body.subject`, `body.plan` and `body.evidence`: each entry through
the same nine items, each report entry tagged with its `field`. CLI: prereg `--plan` /
`--plan-file` and `--items` / `--items-file`; postreg `--item-id`, `--status` (argparse
`choices`) and `--evidence` / `--evidence-file`. `_get_arg_or_file` takes a `parse_value`
callable (`json.loads` here) for the inline value. `hashing.build_entries` hashes each plan
and evidence file as a subject file is, so the same refusals apply. `docs/VERIFICATION.md`:
the `content` section and summary row, a new *TrustedDeclared* section. `README.md` (the two
body examples, which say "every field filled in") and `ROADMAP.md` (done-ahead mark).

**Judgement calls:**
- **Signing validates `status` and item ids:** `status` must be `reported`, `excluded` or
  `blocked` (a usage error at the CLI, a `ValidationError` in the writer), item ids are
  strings and unique within a prereg (a repeated id would fail `complete`), and evidence is a
  non-empty list with unique names (content #1, #4). Signing does **not** check `--item-id`
  against the prereg's items: a postreg can be signed from a literal ref, with no prereg body
  to check against, and `complete` (#37) reports an `item_id` that names no item.
- **asexec fills in `hash_alg` and `digest`; the user may not.** A `--plan` or `--evidence`
  entry holding either is refused (exit 1, "asexec hashes the file and fills in hash_alg and
  digest (choose the algorithm with --hash-alg)"); the algorithm is `--hash-alg`, shared with
  `--subject`. Unknown keys are refused, naming what an entry may hold.
- **Exit statuses:** inline JSON that does not parse is a usage error (64: only the argument
  is wrong); a value that parses but cannot be signed (wrong shape, a directory, a missing
  file, repeated ids or names) exits 1 with `error: …`, wherever the JSON came from; a
  `--…-file` that is not JSON exits 1, as `--target-file` already does. Writer-model
  refusals reached from the CLI are turned into `ManifestError` (`cli._built`), so they print
  one line rather than a traceback.
- **Stage is not enforced by the writer:** the CLI offers `--plan` and `--items` on `prereg`
  and the rest on `postreg`, and `content` checks a plan or evidence wherever it is. A
  postreg does not inherit the prereg's `plan` or `items`.
- **Duplicates are per list:** a file may be a subject and evidence at once.
- **content's empty reason changes** to `requested but no content could be checked (need
  --artifacts and a manifest with a subject, plan or evidence)`, since a plan or evidence
  alone is examined. Its malformed reasons name the list: `malformed plan entry`,
  `malformed evidence`, `malformed evidence entry`.
- **`items`, `items[].id`, `item_id` and `status` are listed, at this commit, as read by no
  test**; #37 moves them under `complete`'s *Examines*.
- **`Scenario.set` deep-copies its value** (`tests/verify/conftest.py`): two new tests
  shared `manifest_data.EVIDENCE` and a later path edit changed it for the next test.

**Evidence:**
- Red first: the tests were written first, but the first run was taken after the code; to
  show red, `src/` was stashed (back to `18e63bf`'s code) and the new suite run against it:
  **91 failed, 672 passed**. The failures: the CLI options did not exist (usage errors and
  `unrecognized arguments`), the writer refused `plan`/`items`/`item_id`/`status`/`evidence`
  as extra fields, the builder guard's two claim bodies, and every content test, which now
  reads each entry's `field` (`KeyError`) or the new empty reason. With the code, 6 failed:
  the CLI's `plan`/`evidence` prefix in the report (not yet printed), the never-raises
  expectation without `field`, and the shared-fixture mutation above. All fixed.
- `scripts/check.sh`: clean, **763 passed** (695 after #33).
- Tests that pin each requirement:
  - content (`tests/verify/test_verify_content.py`):
    `test_content__pass__1_plan_and_evidence_are_checked_like_subject_entries` (fields
    `evidence`, `plan`, `subject`, all `ok`), `__pass__1_a_plan_or_evidence_alone_is_examined`,
    `__fail__1_plan_is_a_well_formed_entry` (string, list, no `hash_alg`, non-hex digest),
    `__fail__1_evidence_is_a_non_empty_array_of_entries` (4),
    `__fail__3_plan_and_evidence_names_are_normalized`,
    `__fail__4_evidence_names_are_unique`,
    `__pass__4_a_name_in_subject_and_evidence_is_not_a_duplicate`,
    `__fail__7_plan_and_evidence_name_a_file`, `__fail__9_plan_and_evidence_digests`.
  - Never raises: `SIGNED_JUNK` gains 13 cases: `plan` not an object, a list, junk fields;
    `items` not a list, junk entries, an object; `item_id` an object, a list; `status` a
    number, a list; `evidence` not a list, junk entry fields, an object. Each is set on the
    prereg and a postreg and run with `ceiling,chain,content,floor,keyconsist`.
  - Builder guard: `CLAIM_PREREG` and `CLAIM_POSTREG` (`tests/manifest_data.py`) are built
    by the writer byte for byte, and verify alike (all `PASS`).
  - Writer: `tests/test_manifest.py::test_claim_record_fields_are_written_as_given`,
    `test_writer_refuses_a_claim_record_content_or_complete_would_fail` (11).
  - CLI: `test_prereg_writes_plan_and_items`, `test_plan_items_and_evidence_from_files`,
    `test_postreg_writes_item_id_status_and_evidence` (and verify `content=PASS`, then
    `✗ plan plan.md: digest mismatch` and `✗ evidence results/s1.json: digest mismatch`
    after both files change), `test_claim_record_argument_errors_are_usage_errors` (7),
    `test_claim_record_value_errors_exit_EXIT_ERROR` (12).
- CLI demonstrations (scratch `art/` with `plan.md` and `results/r1.json`, signing inside it):
  - `prereg --due 2099-01-01T00:00:00Z --plan '{"name":"plan.md","media_type":"text/markdown",
    "label":"the plan"}' --items '[{"id":"R1","kind":"run"},{"id":"R2","kind":"ablation"}]'`
    → body `"items":[{"id":"R1","kind":"run"},{"id":"R2","kind":"ablation"}]`,
    `"plan":{"digest":{"sha-256":"98acf32e…"},"hash_alg":"sha-256","label":"the plan",
    "media_type":"text/markdown","name":"plan.md"}`.
  - `postreg --fulfills pre.json --item-id R1 --status reported --evidence
    '[{"name":"results/r1.json","media_type":"application/json","uri":"https://lab.example/r1"}]'`
    → `"evidence":[{"digest":{"sha-256":"6a50a1d7…"},"hash_alg":"sha-256",
    "media_type":"application/json","name":"results/r1.json","uri":"https://lab.example/r1"}]`,
    `"item_id":"R1"`, `"status":"reported"`.
  - `verify pre.json post.json --tests format,selfsig,content --artifacts art` → `content=PASS`;
    with both files changed → `✗ plan plan.md: digest mismatch`, `✗ evidence
    results/r1.json: digest mismatch`, `content=FAIL format=PASS selfsig=PASS`.
  - `--plan '{nope'` → `asexec prereg: error: argument --plan: not valid JSON: Expecting
    property name enclosed in double quotes: line 1 column 2 (char 1)`, exit 64. A plan with a
    `digest` → `error: --plan: asexec hashes the file and fills in hash_alg and digest
    (choose the algorithm with --hash-alg)`, exit 1. Repeated item ids → `error: body: Value
    error, items list the id 'R1' twice`, exit 1. `--status done` → `argument --status:
    invalid choice: 'done' (choose from 'reported', 'excluded', 'blocked')`, exit 64.
- `examples/adequacy-test/run.py`: exit 0, unchanged output (not ported to the claim record,
  as ROADMAP puts that at the release gate).

**Observations (out of scope):**
- `content`'s pass and fail counts say `subject(s)` (`2/2 subject(s) ok`), though the units
  are manifests and now cover plan and evidence too. Kept, since the doc's examples and the
  other tests use it.
- The usage error for bad inline JSON prints no `usage:` line, unlike argparse's own; the
  exit status is the same.

#### #46: `timely` and the `no-due` state

**Landed:** `c101617`. `timely` is in `TEST_CATALOG`. Per commitment, `verify_paths` collects
the ceiling of every counted copy of each counted postreg and, when the prereg's `due`
parses, gives each counted postreg a `timeliness` entry (`ref`, `status`: `on-time`, `late`,
`no-ceiling` or `invalid-ceiling`, and `no_later_than`) from **`verifier._on_time`, the one
ceiling-to-`due` comparison** (#37 reuses it). Each commitment gets a `timely` record
(`examined`, `ok`, `reason`), `due_present` and `due_invalid`. A verified ceiling record gains
`no_later_than` (`_no_later_than`: `midpoint + radius` from the verified response). State
`no-due` replaces `open` for a commitment with no counted postreg and no `due`. CLI: `[NO-DUE]`;
with `timely` requested, one `✗ postreg <ref> …` line under its commitment per counted postreg
not shown on time; the unparseable-`due` line in every state; the ceiling trust line adds `so
no later than <T>`. Docs: `docs/VERIFICATION.md` (a `timely` section with example, the summary
row, *Output*, *Commitment states*, the version-skew example's `[NO-DUE]`, *Not in this
version*), `README.md` (the state list and the timeliness caveat, a new *On time* bullet),
`ROADMAP.md` (done-ahead marks), the verifier docstring.

**`timely`'s items** (for each commitment with a `body.due` and a counted postreg):
1. `body.due` parses (naive read as UTC), else the commitment fails with `due is not a
   parseable ISO-8601 timestamp` (D5a);
2. each counted postreg has a `ceiling` (D5a: no ceiling fails);
3. that ceiling meets the `ceiling` conditions #1-#5;
4. its time T is at or before `due`.

**The two settled points (as the brief asked):**
- **Which time a ceiling gives:** T = `SREP.MIDP + SREP.RADI`, the later end of the interval
  the witness signed, read from the verified response by `roughtime.verify_ceiling`, never
  from the file's unsigned `ceiling.midpoint`/`ceiling.radius`. This is the conservative
  "existed no later than" time, and the ceiling trust block now prints it beside `midpoint ±
  radius`. Pinned by `test_timely__fail__4_ceiling_at_or_before_due[2023-11-14T22:13:20Z]`
  (a due at the midpoint, one radius before T, fails), `test_timely__pass__4_ceiling_exactly_at_due`
  (T itself passes) and `test_timely__fail__4_the_unsigned_midpoint_and_radius_are_not_read`.
- **A ceiling that fails the `ceiling` conditions is not on time:** it is treated like a
  missing one (`invalid-ceiling`), whatever time it claims. Pinned by
  `test_timely__fail__3_ceiling_meets_the_ceiling_conditions` (an unpinned witness, a genuine
  ceiling of another body, a genuine response for another nonce, a non-roughtime type, a
  `ceiling.pubkey` that is not the pinned key, a junk string).

**Judgement calls:**
- **Commitments only** (checkpoint 5's note): a rejected pre-registration's `due` is never
  read (`test_timely__fail__empty_a_rejected_preregistration_is_not_examined`). D5a's "no
  prereg has a due" is read as "no commitment with a due has a counted postreg", which is
  also the empty reason: `requested but no commitment with a due has a counted postreg`. A
  commitment with a `due` and no counted postreg is not examined either (the issue's
  *Examines*: "at least one counted postreg"); its state says it was not reported.
- **Copies:** a postreg is its `ref`. With several counted copies, it is on time when any
  counted copy carries a ceiling that meets the conditions and is on time, and its time is the
  earliest such T. A ceiling binds the body, not the copy, so any genuine witness of the body
  shows it existed. The counted entries are unchanged (still deduplicated), so `chain` and
  `keyconsist` see exactly what they saw before.
- **Report marks are shown with `timely` requested only**, so a run that never asks about
  timeliness (and has no ceilings) gets no `✗` lines for it; the report dict has the
  `timeliness` entries either way. The unparseable-`due` line is now shown in every state (it
  was shown for `invalid-due` only), since `timely` fails on it.
- A late or unwitnessed postreg is reported as "not shown on time", not as "created after
  due": the ceiling is the only evidence of time, and one fetched late shows only that.

**Evidence:**
- Red first: with only the tests changed, **63 failed, 737 passed**: `timely` was no test
  (`KeyError: 'timely'` through `verify_paths`; every `test_verify_timely.py` test, the
  never-raises cases that now request `timely`), `[OPEN]` where `[NO-DUE]` was expected (the
  states tests, the CLI), the CLI's missing marks and trust-block time, and doc coverage
  (`timely` #1-#4). With the code, 5 failed: the version-skew test's `[OPEN]` (now `[NO-DUE]`,
  intended), doc coverage until the section was written, and one test whose tampering (the
  response's last byte to `00`) changed nothing; it now uses a genuine response for another
  nonce.
- `scripts/check.sh`: clean, **800 passed** (763 after #36).
- Tests (`tests/verify/test_verify_timely.py`, new): `test_timely__pass__all` (3 on time,
  `no_later_than` = 2023-11-14T22:13:21Z), `__pass__1_due_without_offset_is_read_as_utc`,
  `__fail__1_due_is_parseable` (5: text, number, list, empty, zero; still `fulfilled`),
  `__fail__2_counted_postreg_has_a_ceiling`, `__fail__3_ceiling_meets_the_ceiling_conditions`
  (6), `__fail__4_ceiling_at_or_before_due` (2: well before, and at the midpoint; still
  `fulfilled` with 3 counted, each `late`), `__pass__4_ceiling_exactly_at_due`,
  `__fail__4_the_unsigned_midpoint_and_radius_are_not_read`,
  `__pass__2_any_counted_copy_with_a_verified_ceiling_shows_it`,
  `__pass__all_a_prereg_without_due_is_not_examined` (a mixed run, applicable 1),
  `__fail__empty_no_prereg_has_a_due` (missing, null),
  `__fail__empty_due_but_no_counted_postreg`,
  `__fail__empty_a_rejected_preregistration_is_not_examined`.
  States: `test_state__open__no_counted_postreg_and_due_in_the_future`,
  `test_state__no_due__no_counted_postreg_and_no_due` (absent, null),
  `test_state__fulfilled__with_no_due`, `test_state__fulfilled__a_late_postreg_still_fulfills`.
  Never raises: `test_never_raises__junk_ceiling_on_a_counted_postreg` (5, with `ceiling` and
  `timely`), and `test_never_raises__validly_signed_junk_in_a_body_field` (now 39 cases, among
  them `due-not-string`) runs with `timely`. CLI:
  `test_verify_marks_each_counted_postreg_not_shown_on_time` (on time, late, no ceiling; no
  marks without `timely`), `test_verify_ceiling_trust_names_the_time_timely_compares`,
  `test_verify_renders_no_due`, `test_verify_flags_an_unparseable_due_on_a_fulfilled_commitment`.
- CLI demonstrations, in a scratch dir, through `cp7/witness_cli.py` (session scratchpad): it
  runs `asexec` in-process with a pinned synthetic Roughtime witness (MIDP
  2023-11-14T22:13:20Z, RADI 1 s) standing in for the network for `--ceiling`; nothing else
  changes. `prereg --target "model m via provider p" --due …`, `postreg --fulfills … [--ceiling]`:
  - **On time** (`--due 2099-01-01T00:00:00Z`, postreg with `--ceiling`): `[FULFILLED] prereg
    sha-256:b74ae2db…`, `postregs : 1`, no mark, `✓ timely=PASS (1/1 commitment(s) ok)`, trust
    line `ceiling witnessed by synthetic at 1700000000.0 (±1.0s), so no later than
    2023-11-14T22:13:21Z - you are trusting synthetic …`, `asexec-verify/1 format=PASS
    selfsig=PASS timely=PASS`, exit 0.
  - **Late but fulfilled** (`--due 2000-01-01T00:00:00Z`): `[FULFILLED] prereg
    sha-256:daa96b3a…`, `postregs : 1`, `✗ postreg sha-256:5006f81b… is late: its ceiling (no
    later than 2023-11-14T22:13:21Z) is after due`, `✗ timely=FAIL (1/1 commitment(s)
    failed)`, exit 2.
  - **No ceiling**: `[FULFILLED]`, `✗ postreg sha-256:6d17348b… is not shown on time: it has no
    ceiling`, `timely=FAIL`.
  - **Forged ceilings:** the late postreg with its unsigned `ceiling.midpoint` edited to
    2020-01-01 and `radius` to 0 still reads `is late: … (no later than 2023-11-14T22:13:21Z)`;
    with `witness_id` changed to `made-up`: `✗ ceiling witness (no pinned long-term key for
    witness 'made-up'; …)` and `✗ postreg sha-256:5006f81b… is not shown on time: its ceiling
    does not verify`, `ceiling=FAIL … timely=FAIL`; the on-time postreg's genuine ceiling
    copied onto another postreg: `✗ ceiling witness (ceiling nonce does not bind to this
    manifest (nonce != ref))`, `its ceiling does not verify`, `ceiling=FAIL … timely=FAIL`.
  - **No-due**: a prereg with no `--due`: `[NO-DUE] prereg sha-256:b17107d0…`, `due : (none
    declared)`, `postregs : 0`, `✗ timely=FAIL (requested but no commitment with a due has a
    counted postreg)`.
  - The `docs/VERIFICATION.md` `timely` examples use these refs (b74ae2db…, daa96b3a…,
    5006f81b…), which depend only on the bodies, with the witness and times elided.
- `examples/adequacy-test/run.py`: exit 0, unchanged (it does not request `timely`; its
  prereg has a `due` but its postregs have no ceiling, so `timely` would fail every run).
- Nothing left behind: `git grep -n "Timeliness (a postreg created before"` and `git grep -n
  "arrives in 0.4.0"` find nothing; `timely` is gone from *Not in this version*.

**Observations (out of scope):**
- The manifests block's ceiling line still prints `created no later than 1700000000.0
  ±1.0s` (epoch seconds), while the new marks and the trust block print ISO times.
- `examples/adequacy-test` signs a `due` but no ceiling, so once ported it will need
  `--ceiling` on each postreg for `timely` (and `complete`'s deadline part) to pass.

#### #37: `complete`

**Landed:** `d10957d`. `complete` is in `TEST_CATALOG`. `verify_paths` keeps, per commitment,
the prereg's `body.items` and each counted postreg's `body.item_id` and `body.status`, and
`verifier._complete` gives each commitment a `complete` record (`examined`, `ok`, `reason`,
`items`: per item `id`, `ok`, `statuses`, `reason`; `unlisted`: counted postregs whose
`item_id` names no listed item). The deadline part calls `_on_time`, the function `timely`
uses. `models.ItemsInput` (a strict array) is new beside `ItemInput`. The CLI prints, under a
commitment whose prereg lists items, `items : N` and one `✓ <id>: <statuses>` or `✗ <id>: …`
line per item, a `✗` line for repeated or malformed items, and `✗ postreg <ref> names item
'<id>', which the prereg does not list`. Docs: `docs/VERIFICATION.md` (a `complete` section
with an example, the summary row, *Output*, *Commitment states*, `chain`'s *Does not
establish*, `timely`'s link, *TrustedDeclared*'s last line, *Not in this version*), `README.md`
(an *Every item accounted for* bullet, the `chain` caveat), `ROADMAP.md` (done-ahead mark), the
verifier docstring.

**`complete`'s items** (for each commitment whose prereg's `body.items` is present and not
`[]`):
1. `body.items` is an array of objects with a string `id` (`items is not an array of objects
   with a string id`);
2. no two ids repeat (`item ids repeat: '<id>'`), even if every item is accounted for;
3. each item has a counted postreg with `body.item_id` equal to its id and `body.status` one
   of `reported`, `excluded`, `blocked` (item reasons `no counted postreg names it`, `no
   counted postreg for it has a status of reported, excluded or blocked`);
4. a present `body.due` parses (`due is not a parseable ISO-8601 timestamp`);
5. with a `due`, one postreg meeting #3 is on time by `_on_time` (item reasons `not shown on
   time: its postreg is late` / `has no ceiling` / `'s ceiling does not verify`).

**Settled and pinned (judgement calls):**
- **Several counted postregs for one item: any qualifying one satisfies it**
  (`test_complete__pass__3_any_qualifying_postreg_accounts_for_an_item`: S2 with an unknown
  status and a `reported` one passes; `__pass__5_any_qualifying_postreg_on_time_accounts_for_an_item`:
  one without a ceiling and one on time passes). `complete` asks whether each item was
  accounted for; a second, worse postreg for an item does not undo that, and a late one still
  fails `timely`. The item line lists the statuses of the postregs that satisfy it.
- **A postreg whose `item_id` is not in `items` accounts for nothing and fails nothing**; it is
  listed (`unlisted`, and the `✗ … names item 'Z9', which the prereg does not list` line)
  (`test_complete__pass__3_a_postreg_for_an_unlisted_item_is_shown_not_failed`,
  `tests/test_cli.py::test_verify_shows_a_postreg_for_an_unlisted_item`). `complete` judges
  the promised list; an extra postreg is visible, but no promise is broken by it.
- **A postreg with an `item_id` but a missing or unknown status** does not account for the
  item, which fails #3 unless another postreg does
  (`test_complete__fail__3_each_item_has_a_counted_postreg_with_its_id_and_a_status`:
  missing, `done`, `Reported` (case matters), a list; and an `item_id` of another case or a
  list names no item). A counted postreg with no `item_id` is not read (the `summary`
  postreg in the unlisted test).
- **`items: []` is not examined** ("a prereg without items"), like an absent or `null` one;
  a present non-array is examined and fails #1.
- **Commitments only** (checkpoint 5's note): a rejected pre-registration's items are never
  read (`test_complete__fail__empty_a_rejected_preregistration_is_not_examined`); a postreg
  that does not count (signed by another key) accounts for no item
  (`test_complete__fail__3_a_postreg_that_does_not_count_accounts_for_nothing`).
- **The item lines are always shown** (the issue: "The commitments block shows each item's
  status"), with the deadline part when the prereg has a parseable `due`. The per-postreg
  timeliness marks stay with `timely` requested only, since an item line already says when
  its postreg is late.
- An unparseable `due` fails the commitment (#4) but leaves each item's line judged on #3
  alone; the `due` line under the commitment says why.

**Evidence:**
- Red first: with only the tests changed, **68 failed, 774 passed**: every
  `tests/verify/test_verify_complete.py` test (`complete` was no test: `KeyError`), the
  never-raises cases that now request `complete` (27), the CLI item lines (4) and doc coverage
  (`complete` #1-#5). With the code, 3 failed: doc coverage until the section was written and
  the `--help` catalog list, now pinned in full (it had been passing on a prefix since #46
  appended `timely`).
- `scripts/check.sh`: clean, **842 passed** (800 after #46).
- Tests (`tests/verify/test_verify_complete.py`, new; the scenario lists S1-S3 with due 2099
  and one witnessed `reported` postreg each): `test_complete__pass__all`,
  `__pass__3_each_status_accounts_for_an_item` (excluded, blocked),
  `__fail__1_items_is_an_array_of_objects_with_string_ids` (6), `__pass__1_kind_is_not_read`,
  `__fail__2_item_ids_are_unique`, **`__fail__3_a_dropped_item`** (`chain=PASS complete=FAIL`,
  still `fulfilled`), `__fail__3_each_item_has_a_counted_postreg_with_its_id_and_a_status` (6),
  `__fail__3_a_postreg_that_does_not_count_accounts_for_nothing`,
  `__pass__3_any_qualifying_postreg_accounts_for_an_item`,
  `__pass__3_a_postreg_for_an_unlisted_item_is_shown_not_failed`, `__fail__4_due_is_parseable`
  (3), **`__fail__5_each_item_is_accounted_for_on_time`** (late, no ceiling, invalid ceiling;
  still `fulfilled`), `__pass__5_any_qualifying_postreg_on_time_accounts_for_an_item`,
  **`__pass__4_items_under_a_prereg_without_due`** (missing, null; no ceilings needed),
  `__fail__3_a_dropped_item_under_a_prereg_without_due`,
  `__pass__all_a_prereg_without_items_is_not_examined`,
  `__fail__empty_no_commitment_lists_items` (missing, null, `[]`),
  `__fail__empty_a_rejected_preregistration_is_not_examined`. Never raises: `SIGNED_JUNK`
  gains `items-repeat-and-junk` and `items-nul-id`, and the whole list (41 cases) now runs
  with `complete` and `timely`. CLI: `test_verify_shows_each_items_status` (complete,
  dropped item, late items), `test_verify_shows_a_postreg_for_an_unlisted_item`,
  `test_verify_help_names_both_required_tests` (the full catalog).
- CLI demonstrations (scratch dir, `cp7/witness_cli.py` for `--ceiling`; `prereg --target
  "model m via provider p" --due … --items '[{"id": "R1", "kind": "run"}, {"id": "R2",
  "kind": "run"}]'`; `postreg --fulfills … --item-id … --status … [--prev …] --ceiling`):
  - **Dropped item** (only R1's postreg): `[FULFILLED] prereg sha-256:4c78c886…`, `postregs :
    1`, `items : 2`, `✓ R1: reported`, `✗ R2: no counted postreg names it`, `✓ chain=PASS`,
    `✗ complete=FAIL (1/1 commitment(s) failed)`, `asexec-verify/1 chain=PASS complete=FAIL
    format=PASS selfsig=PASS`.
  - **Complete claim** (R1 `reported`, R2 `excluded`, chained): `✓ R1: reported`, `✓ R2:
    excluded`, `asexec-verify/1 chain=PASS complete=PASS format=PASS selfsig=PASS
    timely=PASS`.
  - **Late items** (`--due 2000-01-01T00:00:00Z`): `[FULFILLED]`, the two `is late` marks
    (with `timely` requested), `✗ R1: reported, but not shown on time: its postreg is late`,
    the same for R2, `asexec-verify/1 complete=FAIL format=PASS selfsig=PASS timely=FAIL`.
  - **No due, no ceilings**, R1 `blocked` plus a postreg for `Z9`: `due : (none declared)`,
    `✓ R1: blocked`, `✗ postreg sha-256:cfa32c49… names item 'Z9', which the prereg does not
    list`, `asexec-verify/1 complete=PASS format=PASS selfsig=PASS`.
- **`examples/adequacy-test`'s "dropped S2" under `complete`.** `run.py` itself is unchanged
  and exits 0 (it is ported to the claim record at the release gate, ROADMAP). A scratch port
  (`cp7/run_ported.py`: `--items` on the prereg, `--item-id`/`--status` on each postreg,
  `complete` added to its tests) shows:
  - As the example is today, with `--due 2099-01-01T00:00:00Z` and no ceilings, `complete`
    fails **every** run, the baseline included: each item reads `✗ S1: reported, but not shown
    on time: its postreg has no ceiling`. With a `due`, the deadline part needs a ceiling on
    every postreg, so the ported example must add `--ceiling` (network) or drop `--due`.
  - Without `--due` (`cp7/run_ported_nodue.py`): the baseline is `chain=PASS complete=PASS
    content=PASS …`, and **dropping S2 reads `✓ S1: reported`, `✗ S2: no counted postreg names
    it`, `✓ A1: reported`, `chain=PASS complete=FAIL`**, still `[FULFILLED]`: caught, where
    today's run reports "missed: needs `items` and `complete`". The swapped plants are still
    caught by `content` only, and the late plants still missed (needs `order`).
- Nothing left behind: `git grep` for `timely`, `complete` and "planned" finds no claim that
  either is unbuilt outside this file; *Not in this version* now names `signer` and `order`.
  `ROADMAP.md:459,462` (`due` and `ceiling` TrustedTested by `timely` and `complete`) are now
  true.

**Observations (out of scope):**
- **For the release-gate port of `examples/adequacy-test`:** with a `due`, every postreg needs
  a ceiling for `complete` and `timely` to pass (see above). Its README's *Results* table and
  its "missed: needs `items` and `complete`" label will change.
- `--item-id` is not checked against the prereg's items at signing (#36's call), so a typo is
  only seen at verify, as an unlisted item and a missing one.
- An item id is compared exactly, as a string (`S2` ≠ `s2`); ids that differ only by Unicode
  normalization are different ids.

#### Checkpoint 7 summary

**Landed** (branch `feature/0321-checkpoint7`, each issue's change with its notes commit):
- #33, `18e63bf` (notes `8c474e9`): subjects are explicit file lists, named by normalized
  relative path, each entry with its own `hash_alg`; no directory hash, no default algorithm.
- #36, `5ac205f` (notes `fcd60da`): the claim record (`plan`, `items`, `item_id`, `status`,
  `evidence`), its CLI options, and `content` over `plan` and `evidence`.
- #46, `c101617` (notes `990ba8f`): `timely` and the `no-due` state; `verifier._on_time` is the
  one ceiling-to-`due` comparison.
- #37, `d10957d` (notes `9daf183`): `complete`, reusing `_on_time`.

**pytest counts:** 640 (baseline `18c0955`) → 695 (#33) → 763 (#36) → 800 (#46) → 842 (#37),
`scripts/check.sh` clean after each. `examples/adequacy-test/run.py` exits 0 after each.

**Release-note entries** (for #40, in the `tests/test_constants.py` header format):

```
Identifier: FORMATS[MANIFEST_PAYLOAD_TYPE]["subject_default_hash_alg"], sha-256 -> removed
Impact: BREAKS_USERS
Affected: a manifest whose subject entry has no hash_alg of its own (every manifest written before this change: hash_alg was body-level) now fails content as "malformed subject entry"; a tool that reads the field (KeyError)
Action: re-sign; each subject, plan and evidence entry carries its own hash_alg

Identifier: the subject entry (no constant): {name: <basename, "/" for a directory>, digest} + body-level hash_alg -> {name: <normalized relative path of one file>, hash_alg, digest}
Impact: BREAKS_USERS
Affected: every manifest with a subject written before this change (see above); directory subjects fail content ("artifact is not a file"); the Python API (hashing.hash_dir and digest_path removed; build_prereg/build_postreg take no hash_alg)
Action: re-sign, listing files (or an archive) instead of directories, named relative to where you sign and verified with --artifacts at that directory

Identifier: the commitment state "open" (no constant): no counted postreg and no due -> the new state "no-due"; "open" now means a due in the future
Impact: NEW_OUTPUT
Affected: the report only (states are never part of the code); scripts that read "[OPEN]" for a commitment with no due
Action: none
```

**Judgement calls needing the human's eye** (each detailed in its issue's notes above):
- #33: absolute paths and any `..` are refused at signing (not made relative); `hash_alg` is
  required per entry and the FORMATS fallback is removed; content #7 requires a regular
  file (a FIFO used to hang verify).
- #36: signing validates `status` and unique item ids, not `--item-id` against the prereg;
  bad inline JSON is a usage error (64), a parsed value that cannot be signed exits 1.
- #46: T is `MIDP + RADI`; a ceiling failing the `ceiling` conditions counts as none; marks are
  shown with `timely` requested only; any counted copy's valid ceiling counts.
- #37: any qualifying postreg satisfies an item; unlisted `item_id`s are shown, not failed;
  `items: []` is not examined.

**CI round 1** (PR #56, run 44782181471): lint passed, and pytest passed on 3.12, 3.13 and
3.14 (842 each), but each `test` job's CLI smoke failed: `.github/workflows/ci.yml` ran
`asexec prereg --subject src`, a directory, and #33 refuses it (`error: 'src' is a directory;
list its files, or pack it (a tar, say) and list that`, exit 1). #33's leftover grep had
covered `src`, `tests`, `docs`, `examples` and the READMEs but not `.github`. → The smoke now
signs two files (`--subject src/asexec/__init__.py src/asexec/verifier.py`) and verifies them
with `--tests format,selfsig,content --artifacts .`, and `docs/DEVELOPMENT.md` says so.
Rehearsed locally (`content=PASS format=PASS selfsig=PASS`); `actionlint` clean.
`publish.yml`'s release smoke already signs a file (`ci.key.pub`). `git grep -n -- '--subject'
.github scripts` finds no other directory subject.
CI on PR #56 at `ea3afa2` (run 44793807989): lint, python-matrix, test (3.12, 3.13, 3.14,
each with the new CLI smoke) and build pass. `scripts/check.sh` locally: clean, 842 passed.

**Review round 1** (findings on PR #56; the reviewer found the forged-ceiling attacks,
D5a/D5b, about 30 junk `complete` cases, the #33 refusals and a differential of base-CLI
manifests all correct):
1. **OPEN FOR THE HUMAN GATE (decision, no behaviour change).** From 0.4.0, changing any of
   these changes a test's documented meaning, so it needs a code-grammar bump
   (`asexec-verify/2`):
   - (a) Under `complete`, a counted postreg whose `item_id` names no listed item fails
     nothing: items S1, S2 and postregs for S1, S2 and S3 give `complete=PASS`, with S3 shown
     as unlisted.
   - (b) Contradictory statuses for one item pass: S1 with one postreg `reported` and another
     `excluded` gives `complete=PASS`, shown as `✓ S1: reported, excluded`. It follows from
     "any qualifying postreg satisfies an item".
   - (c) D5b's "the report marks the postreg as late" holds only when `timely` is requested
     (the report dict has the `timeliness` entries in every run).

   All three follow the spec text as written and are kept. `ROADMAP.md`'s sentence that
   presented (a) and the "any qualifying postreg" rule as settled is removed; it now reads
   "(`complete` done ahead of 0.4.0.)". Commit `6962caa`.
2. should-fix (#46): `T ≤ due` compared floats (`MIDP / 1e6 + RADI / 1e6` against
   `datetime.timestamp()`), so a `due` equal to T to the microsecond read as late in about
   one case in eight. Example: MIDP 2553427865607787, RADI 4273949, due
   `2050-11-30T13:31:09.881736Z`. → `roughtime.verify_response` and `verify_ceiling` also return
   the signed integers (`midpoint_us`, `radius_us`); `_no_later_than` is `midpoint_us +
   radius_us`; `_parse_due` also returns the due as integer microseconds since the epoch
   (`(dt - epoch) // 1 µs`); `_on_time` compares those. `no_later_than` in the report is now
   microseconds. `docs/VERIFICATION.md` `timely` #4 says the comparison is exact, in whole
   microseconds. Tests first: `test_timely__pass__4_compared_in_whole_microseconds` (the
   reviewer's exact case; it also asserts the float sum exceeds the due's float) failed on
   the old code (`timely=FAIL`), and `test_timely__fail__4_one_microsecond_after_due_is_late`
   (MIDP + 1 µs) passes either way. Commit `ab1bd9f`.
3. should-fix (#36): inline values that are wrong on their own exited 1, against README's
   *Exit status* (64: the arguments themselves are wrong), while `--status done` exited 64. →
   Each of `--plan`, `--items`, `--evidence` is parsed and held to its shape inside
   `_get_arg_or_file`'s inline parser (`cli._shaped_arg_or_file`): an inline value that fails
   it exits 64 with `asexec <cmd>: error: argument --<flag>: <reason>`; the same value from a
   `--…-file` exits 1 (`error: <reason>`); what the named files are (a directory, missing, two
   paths for one name, a `..` path) exits 1, as for `--subject`. The shape now also requires
   string `media_type`, `label`, `uri` and `kind` (or none), and refuses unknown item fields
   in the CLI rather than through the writer model. Tests first:
   `test_claim_record_argument_errors_are_usage_errors` (now 28 cases, among them the
   reviewer's five: `--items '{"id":"R1"}'`, `'[{"id":5}]'`, repeated ids, `'[{"id":"R1",
   "foo":1}]'`, `--plan '[]'`), `test_claim_record_file_content_errors_exit_EXIT_ERROR` (19:
   the same shapes from a file, exit 1), `test_claim_record_value_errors_exit_EXIT_ERROR` (4).
   Red: 27 failed. README's *Exit status* row for 64 names these. Commit `0d2df7f`.
4. should-fix (#46): "a commitment with no due stays open" left in `README.md:264`, `:312`
   (`// deadline; none = stays open` → `none = no-due`), `:374` (the lose-the-key bullet now
   names `no-due`), `src/asexec/manifest.py:45`, `src/asexec/models.py:29` and the
   `tests/test_cli.py:388` docstring; `docs/VERIFICATION.md:906` now lists `open`,
   `elapsed-no-postreg` or `invalid-due`. `git grep` for "stays open" / "stays `open`" now
   finds nothing outside this file. Commit `ab1bd9f`.
5. nit (#46): a witness-signed time past year 9999 (MIDP 2^62) raised `ValueError: year must
   be in 1..9999` in `_utc_ceil`. → `_utc_ceil` falls back to `<seconds> (epoch seconds)`.
   Tests first: `test_never_raises__witness_time_past_year_9999` (through `verify_paths`, with
   `ceiling`, `complete`, `timely`) and `tests/test_cli.py::
   test_verify_shows_a_witness_time_past_year_9999_as_epoch_seconds` (the late mark and the
   trust line show `4611686018429 (epoch seconds)`); both raised before. Commit `ab1bd9f`.
6. nit: quadratic `.count()` in `_complete`, `_repeated_names`, the `ManifestBody` validator
   and `manifest._check_entries`, and `_complete` matched each item against every counted
   postreg. → `collections.Counter`, and `_complete` indexes counted postregs by `item_id` and
   the ids by a set. Timed with 20,000 items, 20,000 subject names and 20 postregs
   (`cp7/perf.py`): `build_prereg` 6.9 s → 0.11 s, `sign` 3.44 s → 0.04 s, `verify_paths`
   7.97 s → 0.98 s, the same code. Commit `70b606e`, which was committed with one failing test
   (my mistake: the commit was chained after `check.sh | tail`, which hid its status). A
   validly signed entry whose `name` is a list is unhashable for `Counter`, and
   `test_never_raises__validly_signed_junk_in_a_body_field[entry-name-list]` caught it. Fixed
   in `720efc3` (count string names only), pushed straight after; `check.sh` clean since.
7. nit (#46): the `timely` doc example named `int08h-Roughtime` and `±1.0s`, but was made with a
   synthetic witness. → The trust line now reads `ceiling witnessed by … at … (±…s), so no
   later than … - you are trusting …`. Commit `ab1bd9f`.
8. nit (#33): `hashing.py`'s docstring said signing refuses what `content` would fail, but a
   symlink resolving outside `--artifacts` is signed. → The docstring says signing refuses what
   `content` fails in any manifest, and that such a symlink is signed and fails content #5
   there. No refusal added. Commit `70b606e`.
9. nit (#36): `--plan '{"name":"plan.md","name":"k.key"}'` hashed `k.key`. → Inline JSON with a
   duplicate key is refused, exit 64 (`duplicate JSON key 'name'`; cases `plan-duplicate-key`,
   `item-duplicate-key`). Commit `0d2df7f`. `cli._load_json` (every `--…-file`, `--target-file`
   included) has the same gap and predates this PR: observation below.
10. nit (#33): `build_prereg(subject=[])` wrote `"subject": []`, which content #1 fails. →
    `ManifestBody.subject` has `min_length=1`, like `evidence`. Test first:
    `tests/test_manifest.py::test_writer_refuses_an_empty_entry_list[subject|evidence]` (the
    `subject` case failed). Commit `70b606e`.
11. The README plan label "refusal study plan" is generic: kept.

`scripts/check.sh`: clean, 878 passed (842 before the round).

**Observations added in review round 1 (out of scope):**
- `asexec verify <fifo>` and any `--…-file <fifo>` block forever (`open` on a FIFO); the same on
  the base. content #7 covers FIFOs named as artifacts only.
- Item ids are printed raw in the commitments block (`✓ <id>: …`, `names item '<id>'`), so an
  id holding a newline can fake report lines: the same class as checkpoint 5's unauthenticated
  keyid. The code line and exit status are unaffected.
- `cli._load_json` accepts duplicate JSON keys in `--…-file` contents (`--target-file`,
  `--declaration-file`, `--notes-file`, and now `--plan-file`, `--items-file`,
  `--evidence-file`); predates this PR.
- `test_timely__pass__1_due_without_offset_is_read_as_utc` does not pin a local timezone. Low
  risk, since `_parse_due` is TZ-pinned by `test_due__without_offset_is_read_as_utc_and_flagged`.

**Review round 2** (PR #56; the reviewer re-checked round 1's fixes and found them correct):
1. nit (#36): `--plan-file`, `--items-file` and `--evidence-file` content still accepted
   duplicate JSON keys (`{"name":"plan.md","name":"k.key"}` hashed `k.key`, and
   `[{"id":"R1","id":"R2"}]` wrote `R2`). → `_shaped_arg_or_file`'s file loader now parses with
   the same duplicate-key hook as the inline value, so such a file exits 1 (`error:
   <path>: duplicate JSON key 'name'`), its content being no argument. Bad JSON in those files
   still exits 1 (`<path> must contain valid JSON: …`). Test first:
   `tests/test_cli.py::test_claim_record_file_with_a_duplicate_key_exits_EXIT_ERROR`
   (`plan-file`, `items-file`, `evidence-file`; all three failed, exit 0). Commit `c8a03e1`.
   **Remaining pre-existing gap:** `cli._load_json`, used by `--target-file`,
   `--declaration-file` and `--notes-file`, still accepts a repeated key (left alone, as
   instructed).
2. nit (#46): `no_later_than` (on a verified ceiling record and in each `timeliness` entry)
   was integer microseconds beside float-second `midpoint`/`radius`. → Renamed
   `no_later_than_us`, with its readers (`verifier`'s trust line, `cli._NOT_ON_TIME`, the
   tests). No output text changes. Test first:
   `test_timely__pass__all_the_report_names_the_unit_of_its_times` (an `int` under
   `no_later_than_us` in both places, and no `no_later_than` key). Commit `c5ebcc9`. The #46
   and round 1 notes above say `no_later_than`; they are kept as written at the time.
   - **Mistake:** the `cli.py` reader rename went into `c8a03e1`, one commit before the
     verifier's, so `c8a03e1` alone fails two CLI tests (the late mark and the year-9999 mark
     read `no_later_than_us` before the verifier wrote it; checked in a worktree at
     `c8a03e1`: 2 failed, 160 passed in `tests/test_cli.py`). `c5ebcc9` completes the rename.
     It is green, and so is every commit after it. The pushed history is not rewritten.

`scripts/check.sh` (run in full, its exit status checked before each commit): clean, 882
passed.

**Merged** (orchestrator): PR #56 merged into `feature/0321` as `8d97b34`, a merge commit,
after two review rounds and a re-review of the round 1 fixes, with no in-scope findings left
open. Code commits by issue:
- #33: `18e63bf`, `ea3afa2`, `720efc3`.
- #36: `5ac205f`, `0d2df7f`, `c8a03e1`.
- #46: `c101617`, `ab1bd9f`, `c5ebcc9`.
- #37: `d10957d`, `6962caa` (notes and ROADMAP only).
- `70b606e` spans #33, #36 and #37.

The review agent checked these cases:
- **`timely` forgeries:** a valid response for another nonce, an unpinned witness, a wrong
  key, a ceiling copied onto another postreg, edited unsigned midpoint or radius. Each counts
  as no ceiling, and `timely` fails.
- **Boundaries:** 300 random ceilings at microsecond precision. A due equal to T passes and
  T−1 µs is late, every time. The first version used floats and got about 1 in 8 wrong.
- **Junk:** about 30 `complete` cases, and a 400-run fuzz of unhashable values in every new
  field. Nothing raised.
- **Differential:** manifests written by the base CLI give the same codes on both branches.
  The one change is `[OPEN]` → `[NO-DUE]`, which #46 intends.

Two intermediate commits are red on their own: `70b606e` (fixed by `720efc3`) and `c8a03e1`
(fixed by `c5ebcc9`), as the review notes above record. Pushed history wasn't rewritten.
Post-merge on `feature/0321` at `8d97b34`: `scripts/check.sh` clean, 882 passed;
`examples/adequacy-test/run.py` exit 0. CI on the last PR push (`479bddc`, run 44822032611):
lint, build, test on 3.12, 3.13 and 3.14 pass.

**Open for the human gate**, since `complete`'s meaning is fixed at 0.4.0:
- a postreg for an unlisted item fails nothing;
- contradictory statuses for one item pass;
- D5b's late mark shows only when `timely` is requested.

The adequacy example, as it stands, has a `due` and no ceilings, so once it is ported to the
claim record, `complete` would fail every run, the baseline included. The release-gate port
needs `--ceiling` on each postreg, or no `--due`.

### Checkpoint 8: #34, #38

Written issue by issue as each landed. Baseline: `feature/0321-checkpoint8` at `bd82d93`,
`scripts/check.sh` clean, **882 passed**.

#### #34: the untrusted section

**Landed:** `5b97649`. Signing writes `untrusted.asexec_version` (`asexec.__version__`) in the
wrapper (`models.Untrusted`, a writer model only, and `Manifest.untrusted`), so a file is
`{dsse, pubkey, untrusted}` plus a ceiling if one is attached. For each file that passes
`format`, the report record gains `untrusted` (the section, then each key outside the body
the format does not define) and `unknown` (each body field the format does not define), each
a list of `{path, value}`, the path a list of keys and indexes from the file's root. The CLI
prints them under two headings after the manifests block, `=== untrusted (unsigned, and read
by no test: nothing here was checked) ===` and `=== unknown fields (signed, but this format
does not define them: nothing here was checked) ===`, each only if a file has entries. No test
reads either. Docs: `docs/VERIFICATION.md` (*Property paths*, two *Output* rows, the *Output*
and version-skew examples, a new *Untrusted* section with an example), `README.md` (the
verification output list, both envelope examples, the paragraph after them),
`docs/FORMAT.md` (banner), `ROADMAP.md` (done-ahead marks), the `manifest.py`, `models.py`
and `verifier.py` docstrings.

**Settled (judgement calls):**
- **Which fields are known: what the writer models can write**, `models.BODY_FIELDS` and
  `WRAPPER_FIELDS`, derived from `ManifestBody` and `Manifest`/`Ceiling` by walking their
  fields (`known_fields`), so a field added to a writer model is known in the same change. The
  input models alone would not do: they define only what tests read, so `target`,
  `declaration`, `notes` and every other *TrustedDeclared* field would read as unknown. The
  derived tables are pinned as literals in
  `tests/test_manifest.py::test_known_fields_are_what_the_writer_models_define`.
- **Unknown keys nested in a known object are listed too**, in the body (an extra key in a
  subject, plan or evidence entry, an item, `anchor` or `anchor.floor`) and outside it
  (inside `dsse`, a signature entry or `ceiling`). An extra `anchor.floor.time` is exactly
  what a reader could take for checked. **Not** inside a free-form value (`target`,
  `declaration`, `notes`, `identity`, `repro_recipe`, a `digest` object): what it holds is its
  value. **Not** inside a known field of the wrong shape (a string `subject`): the tests judge
  that field. Outside the body, ROADMAP named only top-level keys; nested wrapper keys are
  listed the same way for consistency (`dsse.signatures[0].alg`, as 0.3.x wrote, is one).
- **A null is absent** (Run rules), so an unknown key whose value is `null`, and an
  `untrusted` of `null`, are not listed.
- **Only files that pass `format`** are shown: no other file is read past `format`. A file of
  an unknown format is not shown, though its `untrusted.asexec_version` would say which release
  wrote it (observation below).
- **`untrusted` and the file's JSON rules.** `untrusted` may hold any value, of any type and
  size, without changing a verdict. But it is part of the file, so the file's JSON rules hold
  inside it: a duplicate key in `untrusted` makes the whole file malformed, as a duplicate key
  anywhere does, and so does nesting that takes the file past 64 deep. That is `format`'s rule
  about reading the file at all (a parser could otherwise read a different file), not a
  reading of `untrusted`, and the *Untrusted* section says so. Pinned by
  `test_untrusted__is_held_to_the_file_json_rules` and
  `test_untrusted__deeper_than_the_file_limit_makes_the_file_malformed`.
- **Display:** the blocks sit between the manifests block and the commitments block, so every
  doc example shown "from `=== commitments ===` on" stays complete. Within a file,
  `untrusted` comes first, then the unknown keys in file order; body fields in body order.
  Each value is `json.dumps(value, ensure_ascii=True)` and each path is the doc's notation
  with any non-plain key as JSON (`body["a\nb"]`, `["k\n…"]`), so no newline, control or
  non-ASCII character reaches the report from either. Values are printed whole, not truncated.
- The doc examples show `"asexec_version": "0.4.0"`, as the doc describes 0.4.0 (as it does
  for the `v1` type). A source checkout writes `__version__`, `0.3.20` today.

**Evidence:**
- Red first: with only the tests changed, **53 failed, 808 passed, 1 collection error**
  (`tests/test_manifest.py`: `cannot import name 'BODY_FIELDS'`). The failures:
  `KeyError: 'untrusted'` / `'unknown'` (the new verify tests), the writer's file without
  `untrusted` (the 5 builder-guard cases, the CLI signing test), the missing CLI blocks, and
  10 where my test compared refs after a signed body edit (a test bug: an edited body is a new
  body; those now compare the code, every result and every state). With the code in place,
  one existing test failed:
  `tests/test_cli.py::test_verify_marks_each_file_by_format_and_selfsig` took everything
  before `=== commitments ===` as the manifests block, which now includes the untrusted
  block; it now takes the manifests block up to its blank line.
- `scripts/check.sh` after: clean, **933 passed** (882 before).
- Tests (`tests/verify/test_verify_untrusted.py`, new, 45 cases; the fixture puts a ceiling on
  every manifest, a plan and items on the prereg, an item and evidence on a postreg):
  - `test_untrusted__shown_for_each_file_and_read_by_no_test` (every catalog test: the code,
    every result, every commitment and rejected pre-registration identical with and without
    it); `test_untrusted__any_value_changes_no_verdict` (12: a string, a number, `false`, a
    list, `{}`, `NaN`, a non-string `asexec_version`, a 1 MB string, a 100,000-element list,
    10,000 keys, nested to the file's limit, a lone surrogate with NUL and a bidi override);
    `test_untrusted__null_is_absent`; `test_untrusted__is_not_part_of_ref` (every ref, and
    `ceiling` and `chain`, unchanged); `test_untrusted__is_held_to_the_file_json_rules` (a
    duplicate key: `malformed: duplicate JSON key 'a'`, the file joins nothing);
    `test_untrusted__deeper_than_the_file_limit_makes_the_file_malformed`;
    `test_untrusted__not_shown_for_a_file_that_fails_format`.
  - `test_untrusted__unknown_keys_outside_the_body_are_shown_with_it` (top level, a top-level
    `payloadType`, `dsse.extra`, `dsse.signatures[0].alg`, `ceiling.extra`, a key holding a
    newline; each with every verdict unchanged),
    `test_untrusted__the_section_comes_first_then_the_keys_in_file_order`,
    `test_untrusted__known_keys_are_not_listed` (a ceiling's unsigned `midpoint`/`radius`
    included).
  - `test_unknown__signed_fields_this_format_does_not_define_are_shown` (10: top level,
    body-level `hash_alg`, `schema_id`, in a subject entry, `anchor`, a verified floor, the
    plan, an item, an evidence entry, a key holding a newline; the code, results and states
    unchanged), `test_unknown__every_field_the_format_defines_is_known` (a body with every
    field, the free-form ones holding nested objects, and a digest with two algorithms:
    nothing listed), `test_unknown__a_known_field_of_the_wrong_shape_has_no_fields_to_list`
    (5), `test_unknown__a_null_field_is_absent`, `test_unknown__fields_are_listed_in_body_order`,
    `test_unknown__shown_for_postregs_and_rejected_preregs_alike`.
  - Writer: `tests/test_manifest.py::test_sign_writes_a_dsse_envelope_in_the_wrapper` (keys
    `dsse, pubkey, untrusted`; `untrusted == {"asexec_version": asexec.__version__}`),
    `test_known_fields_are_what_the_writer_models_define`; the builder guard compares the
    writer's file with the raw one plus `untrusted`.
  - CLI: `test_signing_writes_untrusted_asexec_version[prereg|postreg]` (not in the body),
    `test_verify_shows_untrusted_and_unknown_fields_under_their_own_headings` (the exact block
    lines, their place between the manifests and commitments blocks, the same code with and
    without them), `test_verify_prints_untrusted_and_unknown_values_json_escaped` (below),
    `test_verify_prints_no_untrusted_or_unknown_block_when_none`.
- CLI demonstrations, in a scratch dir (`keygen`; `prereg --target "model m via provider p"`;
  `postreg --fulfills prereg.json [--prev postreg-1.json]`; the edits by a scratchpad script
  that does not import asexec; the unknown body fields re-signed with the key, as anyone
  holding it could). Each `verify … --tests format,selfsig,chain,keyconsist` with
  `postreg-1.json postreg-2.json`:
  - Baseline: `asexec-verify/1 chain=PASS format=PASS keyconsist=PASS selfsig=PASS`. The
    prereg file is `{"dsse": {…}, "pubkey": "34dba806…", "untrusted": {"asexec_version":
    "0.3.20"}}`.
  - With `untrusted.host`, a top-level `surprise` and `dsse.signatures[0].alg` added:
    ```
    === untrusted (unsigned, and read by no test: nothing here was checked) ===
      pre-extras.json
        untrusted = {"asexec_version": "0.3.20", "host": "ci-7"}
        dsse.signatures[0].alg = "ed25519"
        surprise = [1, null]
      postreg-1.json
        untrusted = {"asexec_version": "0.3.20"}
      postreg-2.json
        untrusted = {"asexec_version": "0.3.20"}
    ```
    and the same code as the baseline.
  - `untrusted` edited to `{"asexec_version": "9.9.9", "note": "edited after signing"}`, and
    replaced by `["not", "an", "object", 5]`: each shown as it is, and the same code as the
    baseline, `chain=PASS format=PASS keyconsist=PASS selfsig=PASS`.
  - The injection attempt (`untrusted.note` and a top-level key and value holding `\n  [FULFILLED]
    prereg sha-256:fff…`, an `\x1b[2J` and a `\r`):
    ```
        untrusted = {"note": "a\n  [FULFILLED] prereg sha-256:ffff…ffff\n\u001b[2J"}
        ["k\n  [FULFILLED] prereg sha-256:ffff…ffff"] = "\r  [FULFILLED] prereg sha-256:ffff…ffff"
    ```
    No report line is the forged one.
  - Unknown body fields (`colour`, a body-level `hash_alg`, a key holding a forged line),
    re-signed: `body.colour = "red"`, `body.hash_alg = "sha-256"`, `body["x\n  [FULFILLED]
    prereg sha-256:ffff…"] = "v"` under the unknown-fields heading, and `asexec-verify/1
    format=PASS selfsig=PASS`.
  - `untrusted` edited to `{"a": 1, "a": 2}`: `✗ pre-dup.json  [None]  keyid=None`, `✗
    format: malformed: duplicate JSON key 'a'`, `format=FAIL selfsig=FAIL` (the file JSON
    rule).
- `uv run python examples/adequacy-test/run.py`: exit 0, the same codes and caught/missed
  results.
- Nothing left behind: `git grep` for "untrusted … not built", "not yet … untrusted",
  "except `untrusted`" and "except the showing" outside this file finds nothing. Verify reads
  `untrusted` only in `verifier._untrusted`, for the report; no input model has the field.

**Observations (out of scope):**
- **ROADMAP's tier check is not built** (*Tests*: every property the signing models can write
  appears under some test's *Examines*, *TrustedDeclared* or *Untrusted*, else CI fails).
  `models.BODY_FIELDS`/`WRAPPER_FIELDS` list exactly those properties, so the check could
  walk them against `docs/VERIFICATION.md`. Today it would fail: VERIFICATION.md's
  *TrustedDeclared* lists only the claim record's declared fields, not `predicateType`,
  `target`, `declaration`, `identity`, `provenance`, `repro_recipe` or `notes`, which ROADMAP
  puts in that tier.
- **Other report text is still printed raw** (checkpoints 5, 6, 7): a claimed keyid, an item
  id, `body.fulfills` in the notarization-only block, and file paths. The new blocks print
  the file path raw too, as the manifests block does (a path comes from the command line or a
  directory listing, not the file). Unchanged here, as instructed.
- A file of an unknown format is not shown; its `untrusted.asexec_version` would tell a reader
  which release to upgrade to. `format`'s upgrade reason says to upgrade, without a version.
- `BODY_FIELDS` and `WRAPPER_FIELDS` are the current format's. When a second `FORMATS` entry
  arrives, the known fields need to be per entry (`docs/MULTIVERSION.md`).
- `untrusted` holding an integer of more than 4,300 digits makes the file malformed, by
  default, as anywhere in the file (checkpoint 6's `PYTHONINTMAXSTRDIGITS` observation).
- `manifest.sign` still signs a hand-built body with an extra field (checkpoint 1's
  observation); verify now shows such a field as unknown.
