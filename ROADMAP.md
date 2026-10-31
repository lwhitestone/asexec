# Roadmap

> [!NOTE]
> This file is AI-assisted and is meant as a rough context-setter.
> Treat AI output with due skepticism.

## Milestones

- **M1:** a narrow slice of disclosure promises: one record format tested on two sources (Anthropic's RSP promises; an assessor source TBD), hardened against tampering and repudiation → asexec 0.4.x.
- **M2:** promises already made in public are seeded into a registry, with in-toto export; the format freezes here → asexec 0.5.0.
- **M3:** parties sign their own commitments, with assessor co-signing → asexec 0.5.x.

The registry is a separate project, asexec-registry, and is not planned here. Anything not
needed for M1–M3 moves to 0.6.0 or later. A test is added only once dogfooding or user
feedback shows it is needed.

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

| Version | Scope | Milestone |
|---|---|---|
| 0.3.x | shipped (current 0.3.19; see *History*) | — |
| **0.4.0** | slim verify surface + format changes (below) | M1 |
| **0.4.x** | patches found while dogfooding M1 | M1 |
| **0.5.0** | format freeze: wire format + golden vectors become normative; `asexec export --in-toto` | M2 |
| **0.5.x** | `cosign` verify test (additive, since `signatures` is already a list) | M3 |
| **0.6.0+** | everything deferred (below) | — |

---

## 0.4.0 — M1: Slim verify surface and format changes

**Format**

- DSSE envelope: `payload` is base64 of the exact signed bytes; the PAE prefix is
  `DSSEv1`; `signatures: [...]` (one entry for now). The verifier checks the stored
  bytes and never re-canonicalizes. `ref` = digest of the payload bytes.
- The file is an asexec wrapper around that standard envelope: `dsse`, plus the unsigned
  `ceiling` and `pubkey` (see *Wrapper* below).
- `PREDICATE_TYPE` → a URL the project controls.
- New optional body field `origin`: `self` | `extracted`. Extracted records carry the
  source snapshot as a subject (digest + URL) and put the quoted passage in `notes`. Not
  `provenance`, which already means `asserted` | `reproducible`.
- Strict lowercase hex.
- Convention: one prereg per promise. No list-level schema.

**PAE vs DSSE.** PAE (pre-authentication encoding) is the rule for which bytes get
signed: `PAE(type, body) = prefix SP len(type) SP type SP len(body) SP body`, so a
signature is bound to the payload's type and length. DSSE is the envelope built around it:
`payloadType`, `payload` as base64 of the exact signed bytes, and a `signatures` list.

- **Today (0.3.x):** asexec uses PAE alone, with its own prefix `asexec-PAE/v1`, in a
  bespoke envelope. `payload` is stored as a JSON object, so signer and verifier must each
  re-derive the same canonical bytes (sorted keys, compact separators, UTF-8), and `ref`
  depends on them too. Any difference in serialization (another language's JSON encoder,
  number formatting, a library change) breaks signatures and refs.
- **0.4.0:** full DSSE. The verifier checks the stored bytes as they are, so
  canonicalization no longer matters for verification. The `DSSEv1` prefix lets standard
  DSSE and in-toto tooling read asexec envelopes (groundwork for M2's export), and the
  `signatures` list makes M3 co-signing additive. The cost: a format break, regenerated
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
- New commitment state `no-due`, separate from `open`. This changes what `open` means, so
  the code grammar bumps to `asexec-verify/2`.
- `--json`: a stable report (the registry reads it).
- Unknown signed fields are shown as unverified content, never dropped.

**Tests:** golden vectors, regenerated for the DSSE format, plus tests for the items
above. No broader test program.

## 0.5.0 — M2: Format freeze

- The wire format and the golden vectors become normative.
- `asexec export --in-toto`.

## 0.5.x — M3: Co-signing

- `cosign` verify test. Additive: `signatures` is already a list from 0.4.0.

## Deferred to 0.6.0+

- `continuity` + subject `role` / relative paths: matching runs to their inputs; disclosure promises don't need it.
- `order`: the cryptographic proof of "pre"; consider bringing it back with M3 co-signing.
- `complete` + `final` / `expected_runs`: tail-truncation detection; no M1 source needs it yet.
- `--trust-roots`: the pinned drand and Roughtime set is enough until readers ask to choose their own.
- Directory hash v2, as a new `hash_alg` label: M1 records hash snapshots, not trees, and a new label leaves v1 digests valid.
- JCS canonicalization: DSSE verifies the stored bytes, so canonical form no longer matters for verification.
- Phase 1 invariant catalog, property/mutation testing, extra CI matrix: tests are added only when dogfooding or feedback shows a need.
- Phase 3 dependency reduction (pydantic, blake3, BLS vendoring, Actions pinning): worthwhile, but not needed for M1–M3.
- Full normative `SPEC.md`: M2 freezes the wire format and vectors; a complete spec can follow adoption.
- Release-pipeline hardening (reproducible builds, build provenance): the current trusted-publishing pipeline is adequate for alpha.

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
- **Fail loud.** Ambiguous or unfulfilled states are rendered explicitly
  rather than collapsed into a pass/fail that overclaims.

## History

| Version | Theme |
|---|---|
| 0.1.0 | Core primitive: keygen · preregister · seal · verify · identity; offline verifier; drand freshness |
| 0.2.0 | Schema rebalance (bedrock vs. optional); drand floor + Roughtime ceiling as distinct anchors; canonical verify code |
| 0.3.0 | Vocabulary/type realignment: `prereg`/`postreg`, free-form `target`, optional `due`/`declaration`, opt-in floor, `BDR` token, Pydantic-typed construction |
| 0.3.1 – 0.3.11 | Provenance handoff to hand-curated maintenance; docs polish; ruff, uv, pytest, CI, release scripts; Python ≥ 3.11 |
| 0.3.13 | First PyPI release: tag-triggered Trusted Publishing (TestPyPI, then PyPI behind approval); README *Known issues* |
| 0.3.14 | Soundness patch: a single linear `prev_hash` chain; a postreg counts only if validly signed by the prereg's key; duplicate keys and malformed input fail per file; `content` confined to `--artifacts`; timezone-explicit `due` and an `invalid-due` state; `keygen` never overwrites; fail-loud `--floor` / `--ceiling` / `--fulfills` |
