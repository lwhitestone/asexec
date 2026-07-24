# asexec — AsExecuted

> Part of the work at **[lukewhitest.one](https://lukewhitest.one/)** — AI infrastructure & risk stewardship.

**Pre-registered trials for AI evals.** A local-first, pseudonymous, offline-verifiable
cryptographic primitive: an evaluator commits to running an eval *before* the results are
known, then publishes tamper-evident, independently-verifiable receipts of what actually
happened — so that **silence, after a public commitment, becomes visible evidence of
non-disclosure.**

It is the "as executed" counterpart to pre-registration ("as predicted"), borrowing the
commit-then-reveal mechanism from clinical-trial pre-registration and applying it to the
selective-disclosure problem in AI safety evaluations.

> **A primitive, not a platform.** A signing/verification library + thin CLI. No hosted
> service, no CA, no leaderboard. Publish the files wherever you like (a public git repo is
> the intended home).

---

## What this does — and, plainly, what it does NOT prove

**It proves:**
- A manifest (pre-registration or receipt) was not altered after signing.
- A receipt references a specific prior pre-registration, and a receipt sequence wasn't
  silently truncated/reordered (a `prev_hash` chain).
- Whether a declared disclosure window has elapsed and whether matching receipts exist —
  rendered as an explicit state (`fulfilled` / `open` / `elapsed-no-receipt` /
  `notarization-only`).
- (Optional drand **floor**) that a manifest was created no earlier than a public moment —
  **freshness**, not backdating-resistance.
- (Optional Roughtime **ceiling**) that a manifest was created no later than time T — but
  only by *trusting the named witness about time* (a signature-witness, not proof-of-work).

**It does NOT prove** (surfaced in `verify` output, not just here):
- **Identity.** Keys are pseudonymous. Binding a key to a real entity is a separate,
  optional `.well-known` check — asexec is not a CA.
- **That the pre-registration truly preceded the run ("pre") — cryptographically, in the
  general case.** A drand **floor** only proves *no earlier than* (freshness); on its own it
  cannot bound backdating. An optional Roughtime **ceiling** proves *no later than* T, but in
  a **different trust class**: you trust the named signer(s) to be honest about time, not the
  trustless proof-of-work of an OpenTimestamps/Bitcoin ceiling. Without a ceiling, the "pre"
  is *social* — it rests on publication to a **watched public repo** before the run.
- **Provenance.** Content hashes prove a transcript wasn't *altered*; they do **not** prove
  it is the output of the named harness+model (asserted by the signer, not re-executed).
- **Completeness.** It renders only the manifests you give it; it cannot prove a lab
  pre-registered every eval it should have (selective pre-registration).
- **Eval quality / elicitation rigor / sandbagging.** Entirely out of scope — this makes the
  *process* auditable, not the science.
- **A quoted verify code is not proof.** The code is a summary of a computation, not a
  certificate — meaningful only when *you* reproduce it from the files (see below).

---

## Install

```bash
pip install asexec          # ed25519 (PyNaCl) + BLS verification for drand (py_ecc)
```

Python ≥ 3.9. `verify` is fully offline; only the sign-time drand/ceiling fetches and
`identity verify` touch the network.

## Quickstart (the full commit-then-reveal cycle)

```bash
# 1. one-time: generate a pseudonymous keypair (no CA, no registration)
asexec keygen --out lab.key

# 2. BEFORE the run: pre-register the harness + a disclosure deadline
asexec preregister --key lab.key \
    --subject ./harness \
    --target-provider anthropic --target-model claude-opus-4-8 \
    --window 2026-08-30T00:00:00Z \
    --declares "all runs of this harness against this model, in full" \
    --out preregistration.json --commit

# 3. AFTER each run: seal a receipt of the inputs + transcript
asexec seal --key lab.key --fulfills preregistration.json \
    --subject ./transcript.txt ./harness \
    --out receipt.json --commit

# 4. ANYONE, offline: verify the cycle + render the commitment state.
#    --tests names exactly which checks to run; 'bedrock' (sig + keyid) is required.
asexec verify preregistration.json receipt.json \
    --tests bedrock,content,chain,keyconsist --artifacts .
```

Publish `preregistration.json` and `receipt.json` to a public repo. A third party clones it
and runs step 4 with no network and no involvement from you.

### The verify code (what step 4 emits)

`verify` runs the tests you name and prints one **canonical code**, never a percentage or
tier:

```
asexec-verify/1 bedrock=PASS chain=PASS content=PASS keyconsist=PASS
```

Grammar (`asexec-verify/1` versions the *code format* itself): the literal prefix, then one
`name=RESULT` token per requested test (`RESULT ∈ {PASS, FAIL}`), **sorted alphabetically**,
single-space delimited. So the same result set is byte-identical everywhere.

- **You declare your appetite.** `--tests` is required and must include `bedrock` (the
  mandatory minimum: signature + keyid). Everything else is opt-in: `content` (subject
  digests vs. `--artifacts`), `chain` (`prev_hash` integrity), `keyconsist` (receipts share
  the prereg's key), `floor` (drand freshness), `ceiling` (Roughtime witness).
- **Named, not scored — so it's forward-compatible.** Because the code *names* which tests
  ran, adding a test in a later version can never change the meaning of an older code. A code
  means exactly one thing, permanently; a percentage would need its version's denominator to
  interpret.
- **A requested test that applies *nowhere* is `FAIL`**, never a silent omission (e.g.
  `--tests bedrock,ceiling` on manifests with no ceiling → `ceiling=FAIL`).
- **The code is not a certificate.** A quoted or typed code carries the weight of "trust me,
  it passed" — zero. Real verification = you run the tool against the files and get the code.
  The tool prints that disclaimer with every code.

Attach a Roughtime **ceiling** witness at sign time with `--ceiling` on `preregister`/`seal`
(one network round trip; proves *created no later than* T). Omit `--no-drand` to keep the
default drand **floor** (*created no earlier than*). The two are disjoint mechanisms — a
public-randomness *beacon* (floor, embeddable) vs. an external *witness* over `hash(M)`
(ceiling, envelope-level).

## Identity (optional, no CA)

```bash
# a domain owner asserts which keys speak for it:
asexec identity emit --key lab.key --domain lab.example --out asexec.json
#   -> publish at https://lab.example/.well-known/asexec.json

# anyone checks the binding (point-in-time; a domain can rotate keys):
asexec identity verify --domain lab.example --key lab.key
```

## Manifest at a glance

Bespoke signed JSON, signed over a DSSE-style PAE input (borrows in-toto field names, not the
tooling). The **bedrock** (mandatory) set is deliberately small — the fields whose absence
would break verifiability of *commitment → fulfillment/gap*:

- **semantic:** `target_identity` (what was committed to) + `disclosure_window` (by when it
  must be disclosed);
- **structural:** the format frame — `schema_version`, `predicateType`, `phase`.

Everything else is individually optional: `subject` + `hash_alg` (conditionally paired —
`hash_alg` is required *iff* a `subject` is present; a pre-registration may commit to a
target + window before any harness exists to hash), `anchor.floor` (drand, default-on),
`identity`, `provenance` + `repro_recipe`, free-form `notes`. Specificity is a trust gradient
the reader prices.

The **ceiling** witness (Roughtime) lives at the *envelope* level, beside `payload` and
`signature` — not inside the signed body, because its nonce is the body's own hash
(`ref(payload)`), which can't be embedded in the thing it hashes. It is self-authenticated by
the witness signature and binds to the manifest via `nonce == ref(payload)`.

## Design & rationale

The full design record (context, blind-spots, brainstorm, interview, plan) is kept
in the maintainer's local design notes. Prior art:
AsPredicted / OSF pre-registration, ClinicalTrials.gov + the FDAAA TrialsTracker,
OpenTimestamps, in-toto / DSSE, drand / League of Entropy.

**Scope & philosophy:** [`NORTH_STAR.md`](./NORTH_STAR.md) — what this project is for, and
(deliberately) what it is *not* chasing. Read it before proposing scope expansions: this is a
primitive dogfooded honestly at small scale, not a platform or an adoption play.

## Status

**0.2.0 — alpha.** Rebalances the schema (smaller bedrock set), splits the freshness anchor
into a typed `anchor.floor` (drand) + an external-witness `ceiling` (Roughtime), and replaces
the verifier's pass/fail with the canonical `asexec-verify/1` code. See
[`ROADMAP.md`](./ROADMAP.md) for the version-keyed backlog — including later items
(per-key public index, re-execution/determinism mode) and what is *explicitly not
scheduled* (hosted transparency log, identity binding / CA).

> **Ceiling — status:** the Roughtime verification protocol (delegation chain, Merkle path,
> validity window) is fully implemented and offline-verifiable. Long-term keys for four public
> IETF-Roughtime servers are pinned from the official ecosystem list, and the wire format is
> reconciled against a **live `int08h-Roughtime` capture** baked as an offline fixture. The
> other three servers weren't reachable during capture (UDP egress, not a known format
> mismatch), so end-to-end interop is proven for int08h and expected-but-unproven for the
> rest. `--ceiling` fetch fails safe if a server's variant differs.

> **No backward-compatibility guarantee before `1.0.0`.** This is pre-1.0 alpha: any release
> may change the manifest schema, the signed-byte format, the verifier output, or the CLI
> without a migration path — manifests signed by an older build may stop verifying against a
> newer one. (0.2.0 rebalanced the schema in a breaking way by design.) Stability begins at
> `1.0.0`, which is neither defined nor planned yet.

## License

Apache-2.0.
