# Roadmap

> [!NOTE]
> This file is AI-assisted and is meant as a rough context-setter.
> Treat AI output with due skepticism.

## Milestones

- **M1:** the 0.4.0 core format, then an end-to-end test drive on one run-level study: a
  2×2 model × harness matrix with pre-registered ablations, committed before the runs and
  accounted for afterwards → asexec 0.4.x.
- **M2:** a second claim on the same schema (the adequacy test below, if assessors confirm
  the need), in-toto export, and live export of per-item statuses to a claim-graph
  display; the format freezes here → asexec 0.5.0.
- **M3:** a two-sided pilot (the assessor signs its plan and the lab signs the monitor run),
  then lab disclosure promises, self-signed and outsider-extracted side by side
  → asexec 0.5.x.

M1 is a test drive, not a schema design. The study first runs on the 0.4.0 core alone,
with its item list in `declaration`. The 0.4.x fields and tests are candidates, each
tied to the gap it would close, and one ships only if the test drive hits that gap.

The adequacy test is the one in Apollo Research's [*Principles for Embedded
Evaluations*](https://www.apolloresearch.ai/blog/principles-for-embedded-evaluations): to
back a universal-negative claim ("models never attempted to evade their monitoring"),
realistic evasion attempts are planted in transcripts and the monitor's catch rate decides
between *Verified* and *Unrefuted*. Today nothing proves the plants and the plan were fixed
before the run, or that no item was dropped. asexec reports per-item statuses; verdicts
belong to the assessor or the display layer, not to asexec.

No registry is planned. asexec-registry is built only if M2 shows that a claim-graph
display can't show records publicly. Anything not needed for M1–M3 moves to 0.6.0 or
later. A test is added only once dogfooding or user feedback shows it is needed.

**Ordering logic:** make the current claims true first; then make every format-breaking
change in one release; then freeze the format at M2, after M1 dogfooding. Anything
that changes signed bytes or verify-code semantics lands *before* the freeze,
so the format people adopt is the format we can stand behind.
Distribution (PyPI) is cut early to claim the name, with honest caveats.

## Versioning

- **Releases** use `0.MINOR.PATCH`, pre-1.0 alpha.
  - `MINOR`: a change to the manifest format, the signed bytes, or the
    documented meaning of a verify test.
  - `PATCH`: additive or corrective. A fix that brings the implementation in
    line with *already documented* semantics (e.g. `chain` rejecting forks,
    which its docstring always claimed) is a `PATCH`, called out in the
    release notes.
  - **Until `0.4.0`:** a `MINOR` change may ship as a `0.3.x` `PATCH` instead, with the break
    called out in the release notes. From `0.4.0`, it needs a `MINOR`.
- **Identifiers baked into signed bytes.** `SIGNING_PAE_VERSION` (`asexec-PAE/v1`) and
  `MANIFEST_PAYLOAD_TYPE` are in the signing input, and `MANIFEST_SCHEMA_ID` and
  `MANIFEST_PREDICATE_TYPE` are written into the signed body. Changing any of them is a
  deliberate format change, never incidental. The full list, and how each may change, is
  in [`tests/test_constants.py`](tests/test_constants.py).
- **The verify-code grammar is versioned separately** (`asexec-verify/N`). The
  promise that "a code means exactly one thing, permanently" holds only if this
  rule holds: **if the documented meaning of an existing test name changes, the
  grammar version bumps.** Adding a new test name does not require a bump. The rule applies
  from `0.4.0`, which keeps `asexec-verify/1` and fixes its meaning. Codes printed by `0.3.x`
  also say `/1` but aren't covered.
- **Backward compatibility starts at `0.4.0`.** Until then, any release may change the
  schema, signed-byte format, verifier output, or CLI without a migration path. From
  `0.4.0`, manifests stay verifiable: a format change adds a new format version and keeps
  accepting the old ones. Manifests from `0.3.x` are not supported.
  See [`docs/MULTIVERSION.md`](docs/MULTIVERSION.md) for the verifier design, which isn't
  built yet.
  `1.0.0` is deliberately unassigned; no trigger is defined.

## Version map

| Version | Scope | Milestone |
|---|---|---|
| 0.3.x | shipped (current 0.3.19; see *History*) | — |
| **0.4.0** | slim verify surface + every core format change (below) | M1 |
| **0.4.x** | the run-level test drive; the candidate fields and tests it shows are needed, under an experimental `payloadType`; patches from dogfooding | M1 |
| **0.5.0** | format freeze: wire format + golden vectors become normative; `asexec export --in-toto`; second claim (the adequacy test, if confirmed) | M2 |
| **0.5.x** | two-sided pilot; lab disclosure promises (`origin`: `self` \| `extracted`) | M3 |
| **0.6.0+** | everything deferred (below) | — |

---

## 0.4.0 — M1: Slim verify surface and format changes

**Format**

- DSSE envelope: `payload` is base64 of the exact signed bytes; the PAE prefix is
  `DSSEv1`; `signatures: [...]` (one entry for now). The verifier checks the stored
  bytes and never re-canonicalizes. `ref` = digest of the payload bytes.
- The file is an asexec wrapper around that standard envelope: `dsse`, plus the unsigned
  `ceiling` and `pubkey` (see *Wrapper* below).
- `MANIFEST_PREDICATE_TYPE` → a URL the project controls.
- Body field `schema_version` is now `schema_id`, since its value has no version in it.
  (Done ahead of 0.4.0.)
- `dsse.payloadType` selects the format version, and unknown values fail `BDR`
  ([`docs/MULTIVERSION.md`](docs/MULTIVERSION.md)).
- `hash_alg` moves into each subject entry, and the body-level field becomes invalid.
- Subjects are an explicit list of files, each hashed exactly as listed, because directory
  hash v1 is ambiguous and skips what it can't encode.
  - An entry's `name` is the relative path as given (normalized, `/`-separated), not its
    basename, so two files with the same basename stay distinct. Duplicate names are
    refused.
  - Signing refuses a directory, and `content` fails one, so a hand-built manifest can't
    rely on the old hash. To commit to a tree, list its files, or pack it (a tar, for
    example) and list the archive. Remove `hash_dir`.
  - A listed symlink is hashed as the bytes read through it; `content` already fails one
    that resolves outside `--artifacts`.
  - The README examples change to match. Nothing is kept for compatibility with
    directory subjects.
- Convention: one prereg per commitment (a promise, or an assessment's plan). No
  list-level schema.

**PAE vs DSSE.** PAE (pre-authentication encoding) is the rule for which bytes get
signed:

```
PAE(type, body) = prefix SP len(type) SP type SP len(body) SP body
```

`SP` is a single ASCII space and `len` is the byte length in ASCII decimal. With today's
prefix, a small body encodes as:

```
asexec-PAE/v1 27 application/vnd.asexec+json 31 {"phase":"prereg","target":"m"}
```

The signature therefore covers the payload's type as well as its body, and the length
fields keep the boundaries unambiguous even when a value contains spaces. PAE is used only
to sign and verify a signature. `ref` hashes the body bytes without it, and the verify code
does not contain it: `BDR` checks the signature, and the code reports only that result.

DSSE is the envelope built around PAE: `payloadType`, `payload` as base64 of the exact
signed bytes, and a `signatures` list.

- **Today (0.3.x):** asexec uses PAE with its own prefix, `asexec-PAE/v1`, but not the DSSE
  envelope. Canonicalization is a separate step before PAE: `payload` is stored as a JSON
  object, so signer and verifier must each re-derive the same body bytes (sorted keys,
  compact separators, UTF-8), and `ref` depends on them too. Any difference in
  serialization (another language's JSON encoder, number formatting, a library change)
  breaks signatures and refs.
- **0.4.0:** full DSSE. The verifier checks the stored bytes as they are, so
  canonicalization no longer matters for verification. The `DSSEv1` prefix lets standard
  DSSE and in-toto tooling read asexec envelopes (groundwork for M2's export). The
  `signatures` list keeps one entry: a second party signs its own record (see *0.4.x*),
  not the same body. The cost: a format break, regenerated
  golden vectors, and a payload that must be decoded to be read.

How the pieces relate. Only the body bytes are fixed; the PAE is rebuilt by signer and
verifier and never stored:

```
body bytes = {"phase":"prereg","target":"model m via provider p",…}   ← the "exact stored bytes"
payload    = base64(body bytes)                                       ← what the file holds
PAE        = "DSSEv1 <len> application/vnd.asexec+json <len> " + body bytes
sig        = ed25519_sign(private key, PAE)
ref        = sha-256(body bytes)
```

```jsonc
// today (0.3.x)
{
  "payloadType": "application/vnd.asexec+json",
  "payload": { "phase": "prereg", … },           // a JSON object
  "signature": { "alg": "ed25519", "keyid": "…", "pubkey": "…", "sig": "…" },
  "ceiling": { … }                               // optional, unsigned
}

// 0.4.0 (asexec wrapper around a standard DSSE envelope)
{
  "dsse": {
    "payloadType": "application/vnd.asexec+json",
    "payload": "eyJwaGFzZSI6InByZXJlZyIs…",      // base64 of the body bytes
    "signatures": [ { "keyid": "…", "sig": "…" } ]
  },
  "ceiling": { … },                              // optional, unsigned; nonce = ref
  "pubkey": "…"                                  // unsigned; must derive signatures[0].keyid
}
```

Rules that follow:

- Decode `payload` with strict base64, so each set of body bytes has one spelling.
- Read every field the tests check from the verified body bytes, never from another copy in
  the file.
- Keep rejecting duplicate JSON keys in the decoded body: parsers disagree on which value
  wins, so two verifiers could read different fields from the same signed bytes.

**Wrapper.** DSSE defines only `payloadType`, `payload` and `signatures`, so what asexec
adds sits outside it, in the wrapper:

- `dsse` is a standard envelope that DSSE and in-toto tooling can lift out and verify
  unchanged, which keeps the M2 export simple.
- `ceiling` cannot be inside the body (its nonce is the body's own hash). In the wrapper
  it can still be attached after signing; it is bound by `nonce == ref` and authenticated
  by the witness's own signature.
- `pubkey` needs no signature: `BDR` requires `signatures[0].keyid` to derive from it, so
  a substituted key fails. With `signer`, `--trusted-keys` additionally decides which
  keys are accepted.

**Verify**

- `signer`: `--signer` / `--trusted-keys <file>`.
- `timely`: postreg ceiling ≤ prereg `due`.
- New commitment state `no-due`, separate from `open`. This changes what `open` means, but
  the code grammar stays `asexec-verify/1`, because the bump rule starts at `0.4.0`.
- `--json`: a stable report (the claim-graph export reads it).
- Unknown signed fields are shown as unverified content, never dropped.

**Tests:** golden vectors, regenerated for the DSSE format, plus tests for the items
above. No broader test program.

**Release:** once `0.4.0` is on PyPI, yank every `0.3.x` release, so a plain
`pip install asexec` never picks unsupported alpha code. Yank rather than delete, because
deletion is permanent and gains nothing. Yank reason: "pre-0.4.0 alpha, unsupported; use
>=0.4.0".

## 0.4.x — M1: The run-level test drive

One run-level study, end to end: a 2×2 matrix (two models × two harnesses, so model and
harness effects can be told apart), plus ablations, each committed before any run. The
study integrates against a 0.4.0 pre-release. 0.4.0 is cut after its first end-to-end dry
run and before any run meant for publication, so the study's feedback can still change
the core format cheaply and its published records are on a supported one.

The integration (an adapter from the study's runner to asexec) lives in the study's repo,
not here. Where it hooks in waits on the study's choice of runner.

**Starting point: the 0.4.0 core alone.** One prereg lists the cells and ablations in
`declaration`, with the harness and its inputs as subjects. Each run gets a postreg,
chained, with its logs as subjects. Each run fetches a drand round when it starts and uses
it (for example as its seed), and its postreg carries that round as its floor. (Today
`--floor` fetches the latest round at signing, so signing needs a way to pass in a round
fetched earlier.) A reader checks two things by hand: that every listed cell and ablation
was reported, and that the prereg's ceiling precedes each postreg's floor.

**Candidates**, each shipped only if the test drive hits its gap, under an experimental
`payloadType` (spelling not decided). That format is outside the backward-compatibility
promise until 0.5.0 promotes it to a frozen one; until then a release may change or drop
it, and its manifests then fail `BDR` as an unknown format
([`docs/MULTIVERSION.md`](docs/MULTIVERSION.md)). The core format of 0.4.0 is unaffected.

| Candidate | Gap it closes |
|---|---|
| `items` in the prereg; `status` (`reported` \| `excluded` \| `blocked`) and `evidence` digests in each postreg; `complete`: every committed item has a postreg by `due` | A cell or ablation silently dropped; today the reader compares `declaration` with the postregs by hand |
| `order`: the prereg's ceiling precedes the floor of each of its postregs | The plan was fixed before the runs; today `floor` alone does not establish it ([`docs/VERIFICATION.md`](docs/VERIFICATION.md#floor)) |
| One item per repetition, or a declared count per cell | A cell run n times and only the best run reported |

`order` bounds a run only as tightly as the run's use of its drand round: a round the run
merely records proves nothing about when the run started. Using it as a seed lets a
re-execution check it.

**Tests:** a fault suite for each candidate that ships, each fault with its expected code:
an item silently dropped; a late item; a silent amendment (an ablation redefined after
the results); a run whose floor precedes the prereg's ceiling; a record signed with an
untrusted key. Plus one synthetic worked example in the same shape, a 2×2 matrix with
ablations, through commit, run and verify.

## 0.5.0 — M2: Second claim and format freeze

- A second claim on the same schema: the commit-reveal adequacy test (below), if the
  assessor calls confirm the need. If they don't, the next user's claim.
- The wire format and the golden vectors become normative, including the fields 0.4.x
  promoted from experimental. A field the second claim adds freezes only if a dry run has
  exercised it; otherwise it stays experimental past 0.5.0.
- `asexec export --in-toto`.
- Live export of per-item statuses (`verify --json`) to a claim-graph display.
  asexec-registry is built only if that display can't show records publicly.

**The adequacy test.** The assessor commits, before access and before the lab's monitor
runs, to its plan and a plant set; the lab's monitor runs over transcripts with the plants
in them; the assessor then accounts for every item. Beyond the M1 candidates, it needs:

- Prereg fields: `plan` (an opaque digest), a plant-set commitment (salted-hash root and
  count), and `presented_by`.
- Plant-set root: an unambiguous encoding (length-prefixed leaves, or a Merkle tree with
  domain separation), specified before anyone commits to a root. Directory hash v1 is the
  counterexample.
- Lab run record: its own envelope, signed by the lab's key, with `attests: <prereg ref>`,
  the run's output digest, and its own floor and ceiling. It is a new record kind, not a
  postreg, so the counting rule never puts it under the assessor's commitment, and the lab
  can't block the assessor's report by withholding a signature. The adequacy item's
  postreg points at it by `ref`.
- Reveal sample: a drand round issued after the run selects which plants are revealed, so
  the assessor can't pick the published sample.
- Key list with roles (assessor, lab) at a well-known path: a file convention, not a
  registry. It feeds `signer`, and `presented_by` must match it; otherwise `presented_by`
  is an unchecked self-label.
- Verify: `order` extended to the plant-set commitment's ceiling preceding the lab run
  record's floor, and the lab run record validly signed by a key the key list gives the
  lab role.
- Faults: plants swapped after the run (0.3.19 catches only this one), and plants
  committed after the run.

**Open until assessors answer:** whether adequacy tests use planted counterexamples today
(how many, and whether the lab sees them before the run); whether the lab can sign the
run; whether publishing the plant set teaches evasion, and whether a count plus a random
sample is enough.

## 0.5.x — M3: Two-sided pilot, then lab promises

- Pilot with one assessor and one lab: the assessor signs its plan, the lab signs the
  monitor run.
- Lab disclosure promises, self-signed and outsider-extracted side by side. New optional
  body field `origin`: `self` | `extracted`. Extracted records carry the source snapshot as
  a subject (digest + URL) and put the quoted passage in `notes`. Not `provenance`, which
  already means `asserted` | `reproducible`.

## Deferred to 0.6.0+

- `continuity` + subject `role`: matching runs to their inputs; the test drive starts without it.
- `final` / `expected_runs` for tail truncation beyond a declared item list: `complete` would cover the test drive, whose items are listed up front.
- `--trust-roots`: the pinned drand and Roughtime set is enough until readers ask to choose their own.
- [JCS (RFC 8785)](https://www.rfc-editor.org/rfc/rfc8785) canonicalization: DSSE verifies the stored bytes, so canonical form no longer matters for verification (worth adopting for multiple writers to produce byte-identical bodies, and therefore identical refs, from the same data).
- Phase 1 invariant catalog, property/mutation testing, extra CI matrix: tests are added only when dogfooding or feedback shows a need.
- Phase 3 dependency reduction (pydantic, blake3, BLS vendoring, Actions pinning): worthwhile, but not needed for M1–M3.
- Full normative `SPEC.md`: M2 freezes the wire format and vectors; a complete spec can follow adoption.
- Release-pipeline hardening (reproducible builds, build provenance): the current trusted-publishing pipeline is adequate for alpha.

## Later (unversioned until scheduled)

- **Per-key public index** (`.well-known/asexec-index.json`) — addresses
  selective *non*-registration, the largest remaining completeness gap.
  Convention only, no hosting. (The role key list in 0.5.0 is narrower: it lists keys,
  not records.)
- **Offline identity check** (`verify --wellknown <archived.json>`) and
  **`--as-of`** for reproducible state rendering.
- **Re-execution / determinism mode** — must degrade gracefully for
  legitimately non-deterministic evals; calibrate on dogfooding transcripts.
- **Federated cosigner witnesses** — generalize the ceiling to a k-of-n
  `cosign` witness type the reader chooses to trust. Waits for willing
  witnesses.
- **Multi-party co-signing** at prereg (several keys over one body; the adequacy test doesn't
  need it, since each party signs its own record); **structured regulatory
  cross-reference** field — add when a concrete need appears.
- **Roughtime interop beyond int08h.** Keys for four IETF-Roughtime servers are pinned
  from the ecosystem list, but the wire format is reconciled only against a live
  `int08h-Roughtime` capture (baked as an offline fixture). The other three were
  unreachable during capture (UDP egress, not a known format mismatch), so their interop is
  expected but unproven; `--ceiling` fails safe if a server's variant differs.
- **Opt-in verifier signatures.** Let a verifier sign the verify code and report time with
  their own key, so a published result shows who reproduced it. Opt-in, because anyone
  with the same inputs gets the same code, so a verifier's identity matters less than a
  practitioner's.
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
- **Subjects are explicit.** A subject lists files, each hashed exactly as listed. No
  directory hash infers what a tree contains, so a manifest claims only what it names.
- **Fail loud.** Ambiguous or unfulfilled states are rendered explicitly
  rather than collapsed into a pass/fail that overclaims.

## History

| Version | Theme |
|---|---|
| 0.1.0 | Core primitive: keygen · preregister · seal · verify · identity; offline verifier; drand freshness |
| 0.2.0 | Schema rebalance (bedrock vs. optional); drand floor + Roughtime ceiling as distinct anchors; canonical verify code |
| 0.3.0 | Vocabulary/type realignment: `prereg`/`postreg`, free-form `target`, optional `due`/`declaration`, opt-in floor, `BDR` token, Pydantic-typed construction |
| 0.3.1 – 0.3.11 | Provenance handoff to hand-curated maintenance; docs polish; ruff, uv, pytest, CI, release scripts; Python ≥ 3.11 |
| 0.3.12 | Roadmap reset: the version-keyed plan from 0.3.12 on |
| 0.3.13 | First PyPI release: tag-triggered Trusted Publishing (TestPyPI, then PyPI behind approval); README *Known issues* |
| 0.3.14 | Soundness patch: a single linear `prev_hash` chain; a postreg counts only if validly signed by the prereg's key; duplicate keys and malformed input fail per file; `content` confined to `--artifacts`; timezone-explicit `due` and an `invalid-due` state; `keygen` never overwrites; fail-loud `--floor` / `--ceiling` / `--fulfills` |
| 0.3.15 | Verifier and CLI soundness patch; `docs/VERIFICATION.md` catalog of every verify test; Termux development setup |
| 0.3.16 | Strict input models for the verifier, with "absent means missing or null"; the verify suite becomes a black-box contract test of `VERIFICATION.md`; `chain` and `floor` validation fixes |
| 0.3.17 | Python 3.12–3.14 (3.11 dropped); README restructured around what `asexec` proves, keys and non-repudiation |
| 0.3.19 | Verify report drops the printed non-claims and disclaimer and ends with the verification time; `VERIFICATION.md` worked examples and output reference; TestPyPI smoke-test retry fix |
