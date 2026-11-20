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
  pre-registrations**, whatever keyid the broken copy claims. This is the existing rule ("a
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
- **(c) Rejected copies are deduplicated by `(ref, keyid)`** (whole-entry equality, since a
  keyid may be unhashable), however each copy is broken; their single reason is the same. A
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
