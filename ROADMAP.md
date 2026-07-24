# Roadmap

The canonical, version-keyed backlog for `asexec`. Scope is checked against
[`NORTH_STAR.md`](./NORTH_STAR.md) — read it before proposing anything that
expands the surface. The deeper design rationale is kept in the maintainer's
local design notes.

**Ordering logic:** cheap-and-sharp gaps first; items that form one coherent
release ship together; completeness/adoption-adjacent work sits behind core
correctness; anything needing outside cooperation or heavy new infra is pushed
to the back since it's lowest-control.

## Versioning

- **Releases** use `0.MINOR.PATCH`, pre-1.0 alpha. A `MINOR` bump is a
  meaningful format or verifier-output change; a `PATCH` is additive/small.
- **Some identifiers are baked into signed bytes.** `SCHEMA_VERSION`
  (`asexec`), the predicate type (`.../manifest`), and the PAE prefix
  (`asexec-PAE/v1`) are part of the signing input, so changing any of them
  changes what verifies — a deliberate format break, never incidental. (The
  `asexec-PAE/v1` prefix versions the signing *construction* itself; it is not
  a roadmap version and stays fixed unless the construction changes.) These are
  plain format identifiers, not a parallel release-numbering scheme.
- **`1.0.0` is deliberately unassigned.** No trigger is defined yet — it is not
  tied to dogfooding, team usage, or any other indicator. Leave it open until
  there's a concrete reason to fix it.
- **No backward-compatibility guarantee before `1.0.0`.** While the project is
  pre-1.0 alpha, any release may change the manifest schema, the signed-byte
  format, the verifier output, or the CLI surface without a migration path —
  old manifests may stop verifying against a newer build. (0.2.0's schema
  rebalance is the first example: no back-compat, by design.) A stability
  commitment only begins at `1.0.0`, which is itself neither defined nor
  planned yet.

## Version map

| Version | Status | Theme | Backlog items |
|---|---|---|---|
| **0.1.0** | shipped (alpha) | Core primitive: keygen · preregister · seal · verify · identity; offline verifier; drand freshness | — |
| **0.2.0** | shipped (alpha) | Schema rebalance + freshness/ceiling anchors + verifier redesign | #1–#6 |
| **0.2.1** | next | AI-assisted-prototype handoff — provenance reset; AI assistance considered on a case-by-case basis from here on | — |
| **0.3.0** | planned | Completeness: per-key public index convention | #10 |
| **0.4.0** | planned | Re-execution / determinism mode | #12 |
| *unversioned* | opportunistic | Federated cosigner witnesses · multi-party co-signing · regulatory cross-reference field | #15, #13, #14 |
| *unversioned* | process (not a release) | Dogfooding · land design docs · team/customer usage | #7, #8, #9 |
| *separate repo* | not core `asexec` | Verification website | #11 |
| — | explicitly not scheduled | Third-party witness services · hosted transparency log · identity binding / CA | — |

---

## 0.2.0 — schema rebalance, freshness anchors, verifier redesign  *(shipped)*

Items #1, #3–#6 are one coherent release and ship together: #1 defines the
field taxonomy, #3–#5 populate it, and #6 is the verifier that reads all of it.
The mandatory-set change and the new verifier output are what make this a
`MINOR` bump. (#2 was dropped — see below.)

1. **Schema rebalance: bedrock vs. recommended-optional vs. free-form**
   - Confirm/enforce only `disclosure_window` and target/`model_identity` as
     mandatory (bedrock) — verifiability of the central
     commitment→fulfillment claim breaks without these.
   - Everything else (drand floor, ceiling witness, sequence/supersedes,
     free-text) becomes fully optional, individually.
   - Publish a documented "recommended bundle" (not enforced) consisting of:
     drand floor + ceiling witness.

2. ~~**Q1-equivalent field** (`has_run_already`)~~ — **REMOVED INDEFINITELY
   (2026-07-22).** A self-declaration is not a verifiable claim, so it doesn't
   belong in the 0.2.0 verifier model, whose contract is that *every entry in
   the canonical code is something the tool actually verifies*. A presence/enum
   check would only test our own input validation, and a structured field
   adjacent to the cryptographic anchors would imply it was checked when it
   can't be (an overclaim). The capability survives as free-form `notes`, which
   correctly files it as unverifiable context. Not mirroring AsPredicted Q1 is
   deliberate: AsPredicted is a human-read form; asexec is a verifier.

3. **Drand floor** — reference a drand round at/before manifest creation time in
   `preregister`; proves creation **at or after** that round. Ships as part of
   the recommended bundle, not bedrock.

4. **Ceiling witness (Roughtime)** — an *external witness* proving creation
   **no later than** time T. NOTE: a "drand ceiling" is unsound — embedding a
   drand round only ever proves *no earlier than* (a floor); drand carries no
   user data, so it can't witness `hash(M)`. A ceiling needs an artifact that
   (1) provably existed by T and (2) commits to `hash(M)`. 0.2.0 uses
   **Roughtime**: a server signs `(nonce=hash(M), midpoint T, radius)` under a
   long-lived, pinnable key → standalone, offline-verifiable like a drand round;
   instant (no OTS-style confirmation wait); free; no account. The verifier
   surfaces the trust class explicitly (signature-witness = "trust these signers
   about time," a different class than the floor). Full analysis:
   [`crystallize/02-brainstorm.md`](./crystallize/02-brainstorm.md) "0.2.0
   addendum — the ceiling witness". Floor and ceiling stay **distinct fields**.

5. **Anchor field made extensible, not hardcoded to one mechanism** —
   `anchor.floor` and `anchor.ceiling` are separate, each carrying a `*_type`
   (floor: `drand | none`; ceiling: witness-typed `roughtime | ots | cosign |
   none`), so OTS (PoW) and cosigners (#15) slot into the same ceiling shape
   later. drand (floor) and Roughtime (ceiling) ship as the documented defaults;
   nothing in the schema privileges them structurally.
   - **Floor and ceiling generalize along *disjoint* axes — do not merge them.**
     A floor source is a public randomness **beacon** (a value fixed at T,
     independent of `M`, hence *embeddable*): drand, NIST beacon, Bitcoin
     block-hash, ETH RANDAO. A ceiling source is a **witness** that ingested
     `hash(M)` and attested a time (hence *attach-after-only*): Roughtime, OTS,
     cosigners. More floor `floor_type`s = "more beacons" (a separate, low-value
     axis; drand quicknet is already free + offline-verifiable). More ceiling
     `ceiling_type`s = #15 (federated cosigner **witnesses**). A cosigner cannot
     be a floor (its attestation is *about* `M`), and a beacon cannot be a
     ceiling (it never sees `M`) — conflating them repeats the unsound
     "drand ceiling" category error (#4).

6. **Verifier redesign: point-by-point tests → canonical plaintext code output**
   - Output is a canonical code naming exactly which tests ran, each `PASS`/`FAIL`
     — **never a percentage or tier.** Tests not in the code were not run — never
     implied as failed. Only *verifiable* claims earn an entry — no
     self-declarations (see #2, removed).
   - **Why the code, not a score — forward compatibility (the strongest
     property):** because the code *names* which tests ran, adding a test in a
     later version can never silently change the meaning of an earlier code. A
     code means exactly one thing, permanently, regardless of what tests exist
     when someone reads it later. A percentage/tier is meaningless without the
     denominator *at the version that produced it* (an old "87%" needs a
     version-lookup table to interpret). The code is self-describing; a score
     never is. This dissolves the dashboarding/lemons problem.
   - **The code is NOT a certificate.** It is a summary of a computation, not a
     credential. Real verification = *run the tool against the manifests +
     artifacts and get this code* — reproducible by anyone with the files.
     Publishing just the code (typed in a README, a tweet) is a claim with the
     evidentiary weight of "trust me, it passed" — zero. The tool prints a fixed
     disclaimer alongside every code: *"this code is only meaningful if
     reproduced — do not treat a quoted code as proof."*
   - **Canonical serialization (spec'd in the format doc, not left to
     convention):** `asexec-verify/1 ` + `name=RESULT` tokens (`RESULT ∈
     {PASS,FAIL}`), **names sorted alphabetically**, single-space delimited, per
     test. So the same result is byte-identical everywhere (`bedrock=PASS
     floor=PASS`, never `floor=PASS bedrock=PASS`). Preserves "distinct
     verifications → distinct codes, forever."
   - **Test set is explicit and required (no implicit default):** `verify`
     requires a `--tests` list; **`bedrock` must be in it or `verify` errors.**
     `bedrock` is the mandatory minimum (sig + keyid); everything else is opt-in
     on top. Requesting only `bedrock` yields `bedrock=PASS` — a complete,
     honest statement of exactly what was checked, implying nothing about what
     wasn't. A requested test that applies nowhere (e.g. `ceiling` with no
     ceilings present) is `FAIL` (requested-but-absent), never a silent omission.

## 0.2.1 — AI-assisted-prototype handoff  *(next release)*

Marks the transition from AI-assisted prototyping to hand-curated maintenance.
The git history and contributor provenance are reset to a single authored
baseline; AI assistance is considered on a case-by-case basis from here on. No
format, schema, or verifier-output change — a `PATCH` bump that records the
provenance handoff, not new capability.

## 0.3.0 — per-key public index convention

10. **Per-key public index convention** (`.well-known/asexec-index.json` or
    similar) — addresses the completeness/selective-non-registration gap (the
    highest-leverage remaining hole per the market-for-lemons argument).
    Convention-only, no hosting required.

## 0.4.0 — re-execution / determinism mode

12. **Re-execution/determinism mode** — needs to degrade gracefully for
    legitimately non-deterministic evals or it will cry wolf. Wait for real
    transcripts from dogfooding (#7) to calibrate against.

## Opportunistic (unversioned until scheduled)

These are real features that would land as a `MINOR`/`PATCH` bump when a
concrete need appears; not on a timeline.

15. **Federated cosigner witnesses (ceiling generalization)** — generalize the
    0.2.0 ceiling slot (#4) from Roughtime to a `cosign` `witness_type`: a
    generic `{witness_id, pubkey, signed_time, signature}` that the evaluator
    collects *k-of-n* from parties the **reader** independently trusts (an
    auditor, a journal-equivalent, peer labs). Same `anchor.ceiling` shape, many
    producers; the reader prices the trust (no CA, pseudonymous). Subsumes
    Roughtime (a Roughtime server is one cosigner) and dovetails with the
    web-of-trust item. Needs willing witnesses, so it waits for demand. See
    [`crystallize/02-brainstorm.md`](./crystallize/02-brainstorm.md) Fork B.
    Scope: this is a **ceiling/witness** generalization only. Generalizing the
    *floor* (more beacons: NIST/Bitcoin-hash/RANDAO) is a distinct axis — see #5
    — and must not be folded in here (beacon ≠ witness).

13. **Multi-party co-signing** (optional second signer at pre-registration) —
    cheap to spec, low urgency until requested.

14. **Structured regulatory cross-reference field** (e.g., SB-53/RAISE-Act
    filing ID) — adoption hook more than technical gap; add opportunistically if
    a real compliance use case appears.

## Process milestones (not tied to a release)

These gate the release work but are not themselves versioned artifacts.

7. **Dogfooding: run your own evals through the full cycle**, using the
   rebalanced schema (0.2.0) and new verifier output. Gates everything after it
   — surfaces rough edges no design discussion catches (messy harnesses,
   non-determinism, disclosure-window UX, whether the recommended bundle is
   actually usable in practice).

8. **Land `NORTH_STAR.md` and the design-rationale doc in the repo** — commit
   before wider external visibility so early readers get honest scope up front.
   (`NORTH_STAR.md` and this `ROADMAP.md` are in-repo; deeper rationale is kept
   in local design notes.)

9. **Team/customer-facing usage** — first test of the social-contract thesis
   under real, if modest, stakes. Depends on dogfooding (#7) going reasonably
   smoothly.

## Separate deliverable (not core `asexec`)

11. **Verification website** — explicitly *not* core `asexec`; its own
    repo/deliverable with its own versioning. Lowers the barrier for
    non-technical reviewers. Designed so anyone could build a competing instance
    from the open manifest + code spec alone — not owned long-term by the core
    project.

## Explicitly not scheduled

Third-party witness services, hosted transparency log, identity binding / CA.
All reintroduce trust/infra layers the project was built to avoid (see
[`NORTH_STAR.md`](./NORTH_STAR.md)). Revisit only if a specific, concrete need
forces the question — not on a timeline.
