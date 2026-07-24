# PRD: AsExecuted (`asexec`) — A Pre-Registration & Notarization Primitive for AI Evaluations

## 1. One-line pitch

Pre-registered trials for AI evals: a local-first, pseudonymous, cryptographic primitive that lets an evaluator commit to running an eval *before* the results are known, and then publish tamper-evident, independently-verifiable receipts of what actually happened — so that silence, after a public commitment, becomes visible evidence of non-disclosure.

## 2. Problem statement

Frontier AI safety frameworks (RSPs, Preparedness Frameworks, Frontier Safety Frameworks) rely on capability evaluations to trigger safety mitigations. These evals are self-reported: labs run their own tests, on their own schedule, and publish what they choose to publish.

This creates a **selective-disclosure problem structurally identical to publication bias in clinical trials**: if a lab can run an eval multiple times and publish only the favorable run, a signed "receipt" proving *that run happened and wasn't altered* has no power to distinguish an honest, fully-disclosed evaluator from a dishonest, cherry-picking one. Both produce equally valid-looking receipts. This is a market-for-lemons failure — the signal collapses to zero discriminating value, and rational actors converge toward minimal disclosure.

A notarization-only tool (proving a receipt wasn't tampered with *after* publication) does not solve this. The missing piece is a **pre-commitment mechanism**: proof of what was *promised*, independent of what was later disclosed, so that gaps between promise and disclosure are detectable without requiring a trusted third party.

## 3. Goals

- **G1**: Let an evaluator cryptographically pre-register an eval run (harness, target, declared disclosure window) before results exist.
- **G2**: Let an evaluator publish a signed, content-addressed receipt of an eval's inputs and outputs after the run.
- **G3**: Let any third party verify, entirely offline, that a receipt matches a prior pre-registration and hasn't been altered since publication.
- **G4**: Make gaps between pre-registration and disclosure structurally visible — silence is evidence, not just absence of proof.
- **G5**: Require no hosted service, no CA, and no identity-verification layer to produce a functioning 0.1 release.

## 4. Non-goals (explicitly out of scope)

- **Not solving identity/trust.** Keys are pseudonymous. Binding a key to a real-world entity (a specific lab) is left to whoever consumes receipts — via `.well-known`-style self-assertion, social proof, or an out-of-band channel. This project does not run or become a CA.
- **Not solving capability elicitation quality.** This project does not judge whether an eval is well-designed, whether a benchmark is a good proxy for real-world capability, or whether elicitation was sufficiently adversarial (the "sandbagging" question). It only makes the *process* — commit, run, disclose — auditable.
- **Not a hosted transparency log.** No shared server. Receipts and pre-registrations are files; where they're published (a repo, a website, IPFS, wherever) is the evaluator's choice. (Explicitly not scheduled — see [`ROADMAP.md`](./ROADMAP.md).)
- **Not solving closed-weight model hashing yet.** The initial release targets local/open-weight models where checkpoint hashing is straightforward. API-based/closed models (hashed only by provider + model ID + timestamp, which is a weaker binding) are a documented later-release extension.
- **Not preventing a bad-faith evaluator from never pre-registering at all.** The mechanism only bites once a lab chooses to participate and make public commitments. It cannot compel participation — its value is reputational and voluntary, same as clinical trial pre-registration.

## 5. Core concepts

| Term | Definition |
|---|---|
| **Pre-registration** | A signed manifest, published *before* an eval run begins, declaring: harness identity (hash), eval/benchmark identity (hash), target model identity (hash or model ID), and a **disclosure commitment** (see §6.3). |
| **Receipt** | A signed manifest, published *after* a run completes, containing content hashes of the harness, eval set, model identity, and raw output/transcript, plus a reference back to the pre-registration it fulfills. |
| **Key** | A pseudonymous keypair generated and held by the evaluator. No CA, no identity binding required. Compromise/secrecy is the evaluator's standard key-management responsibility (out of scope to solve — this is ordinary signing-key hygiene). |
| **Disclosure commitment** | The specific promise made at pre-registration time about what will be published and by when. This is the mechanism that makes gaps detectable (§6.3). |
| **Timestamp anchor** | A method of proving a manifest existed at or before a certain point in time, without trusting a third-party timestamp authority — done by embedding a recent public-randomness value (e.g., a blockchain block hash or NIST randomness beacon output) into the signed manifest. |

## 6. Functional requirements

### 6.1 Key management
- `asexec keygen` — generates a new pseudonymous keypair, stored locally (standard key file, e.g., ed25519).
- No registration, no identity binding, no network call required to generate or use a key.

### 6.2 Content hashing
- Deterministic hashing of: harness source (directory tree hash, e.g., a Merkle tree over files), eval/benchmark dataset, and raw model output/transcript.
- Model identity handling forks by type:
  - **Local/open-weight**: hash the weight files directly.
  - **API-based**: record provider name, model ID/version string, and API endpoint — flagged in the receipt schema as a weaker identity binding than a weight hash (documented limitation, not silently glossed over).

### 6.3 Pre-registration and disclosure commitment
- `asexec preregister` — before running an eval, the evaluator signs and publishes a pre-registration manifest containing:
  - Harness hash, eval hash, target model identity.
  - A **declared disclosure window**: a plain-language + machine-readable commitment of what will be disclosed and by when (e.g., "all runs against this harness/eval pair completed within 30 days of this manifest will be published as receipts, in full, regardless of outcome").
  - A timestamp anchor (§6.5).
- This is the artifact that gives absence-of-a-later-receipt its evidentiary weight. Without it, a missing receipt proves nothing; with it, a missing receipt against a declared window is a visible, checkable gap.

> **Naming note**: "AsExecuted" pairs deliberately with [AsPredicted](https://aspredicted.org/) (the pre-registration platform used in behavioral science) — pre-registration is "as predicted," the signed receipt is "as executed." It also borrows the legal-document sense of "as executed" (a signed, final, binding version of a document, as opposed to a draft), which maps well onto turning a promise into a verifiable record. Confirmed unclaimed as of this writing on npm, PyPI, crates.io, and GitHub (handle and repo name).

### 6.4 Receipt generation and publication
- `asexec seal` — after a run, the evaluator signs a receipt manifest: content hashes (per §6.2), a reference (hash) back to the pre-registration it fulfills, and a timestamp anchor.
- Receipts are plain files. Publication location is the evaluator's choice (repo, website, wherever) — the tool does not host anything.

### 6.5 Timestamp anchoring (no trusted third party)
- Each manifest (pre-registration and receipt) embeds a recent public-randomness value not controllable by the evaluator (e.g., a recent block hash from a public blockchain, or a NIST randomness beacon pulse) at signing time.
- This proves the manifest was created *at or after* that value existed, without requiring trust in any single timestamp authority or platform. (Precedent: OpenTimestamps uses the same technique.)

### 6.6 Verification
- `asexec verify` — a standalone verifier (library + CLI) that, given a pre-registration, zero or more receipts, and the original artifacts, can confirm, fully offline:
  - Signatures are valid and self-consistent (same key across pre-registration and its receipts).
  - Content hashes in each receipt match the actual artifacts provided.
  - The timestamp anchor is consistent with the claimed ordering (pre-registration before receipt).
  - Whether the declared disclosure window has elapsed and, if so, surfaces this plainly as **"commitment fulfilled" / "commitment open" / "commitment window elapsed with no receipt"** — the tool renders the gap; it does not adjudicate intent.

### 6.7 Explicit non-claims (surfaced in tooling output, not just docs)
- The verifier must not imply it has proven "completeness" beyond what a disclosure commitment was scoped to cover. If no pre-registration exists for a receipt, the tool should label it clearly as **notarization-only** (proves non-tampering after the fact, proves nothing about selective disclosure) — distinct from a receipt that fulfills a pre-registration.

## 7. Design principles (carried from earlier scoping discussion)

- **Primitive, not platform.** Ship `asexec` as a signing/verification library + thin CLI. No dashboard, no hosted aggregator, no leaderboard. Anything resembling a shared service is a later, out-of-scope decision, made only if a real need appears (see [`ROADMAP.md`](./ROADMAP.md)).
- **No new trust required beyond what's declared.** No CA, no identity system, no dependency on any single company's servers or logs for the core guarantee to hold.
- **Local-first and offline-verifiable.** Verification must work with nothing but the manifest files, the original artifacts, and public keys already in hand.
- **Fail loud, not silent.** Ambiguous or unfulfilled states (missing receipt, expired window, no pre-registration) should be surfaced explicitly rather than defaulted to a pass/fail binary that overclaims.

## 8. Success criteria for 0.1

- An evaluator can, using only the CLI, pre-register an eval, run it, and publish a receipt, in under some low number of manual steps (target: no more than a handful of commands).
- A third party with no prior relationship to the evaluator can verify a full commit-then-reveal cycle offline, using only published files and a public key, with no network access and no involvement from this project's authors.
- The tool correctly and legibly flags at least these three states in test cases: (a) fulfilled commitment, (b) tampered/altered receipt, (c) elapsed window with no receipt.
- Documentation states plainly, in the first page, what this does *not* prove (identity, eval quality, elicitation rigor) — so the project cannot be reasonably misrepresented as solving more than it does.

## 9. Open questions to resolve during design

- Should the disclosure commitment specify an exact number of runs in advance (stronger, but rigid — evaluators may not know eval flakiness upfront) or a declared time window covering all runs (more realistic, but reopens a narrower version of the same gap if an evaluator runs outside the declared window)?
- What's the minimal viable timestamp-anchor source — is a public blockchain block hash acceptable dependency-wise, or does a randomness beacon (e.g., NIST) better match the "no crypto-culture baggage" positioning this project might want?
- Directory/file hashing convention for harnesses — reuse an existing standard (e.g., git tree hashing) rather than inventing a new Merkle scheme, to maximize compatibility with tooling evaluators already use.

## 10. Prior art to draw from, explicitly

- **Sigstore / in-toto / SLSA** — supply chain attestation patterns (though this project deliberately skips their identity/OIDC layer).
- **OpenTimestamps** — trustless timestamp anchoring via blockchain.
- **Clinical trial pre-registration (e.g., ClinicalTrials.gov)** — the direct conceptual ancestor of the commit-then-reveal mechanism; useful as a one-line explanation when pitching the project to non-technical audiences.
- **Certificate Transparency** — append-only, publicly auditable log design, relevant only if a shared transparency log is ever pursued (explicitly not scheduled — see [`ROADMAP.md`](./ROADMAP.md)).