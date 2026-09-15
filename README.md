# asexec - AsExecuted

**Pre-registered trials for AI executions.** A local-first, pseudonymous, offline-verifiable
cryptographic primitive: a practitioner commits to running a test *before* the results are
known, then publishes tamper-evident, independently-verifiable receipts of what actually
happened, so that silence after public commitment becomes visible evidence of
non-disclosure.

It is the "as executed" counterpart to pre-registration ("as predicted"), borrowing the
commit-then-reveal mechanism from clinical-trial pre-registration and applying it to the
selective-disclosure problem in AI safety.

`asexec` is a primitive, not a platform. It offers a signing/verification library and a thin CLI.
There is no hosted service, no CA, no leaderboard, etc, in the core product. Publish the files
wherever you like according to how you wish to disclose.

---

## What does `asexec` prove?

What a particular execution cycle's manifest proves is up to the practitioner (who can
choose what to disclose) and the verifier (who can choose what to check). Proof comes
in the form of `asexec verify` providing a code regarding the checks applied.

**`asexec` can prove:**
- A manifest (pre-registration or post-registration) was not altered after signing.
- A post-registration references a specific prior pre-registration, and a sequence wasn't
  silently truncated/reordered (a `prev_hash` chain).
- A declared disclosure deadline (`due`) did not expire prior to post-registration (rendered
  as an explicit state `fulfilled`/`open`/`elapsed-no-receipt`/`notarization-only`).
- A manifest was created no earlier than a public moment (floor "freshness" check, offered by
  `drand`).
- A manifest was created no later than time T (ceiling "witness" check offered by `Roughtime`;
  a signature-witness, not proof-of-work).

**`asexec` does not prove**:
- Provenance. Content hashes prove a transcript wasn't altered; they do not prove it is the
  output of the named harness+model (asserted by the signer, not re-executed).
- Completeness. It renders only the manifests you give it; it cannot prove a lab pre-registered
  every eval it should have (selective pre-registration). However, just like practitioners are not
  forced to `asexec prereg` all their testing, verifiers are not forced to trust results that were
  telegraphed less than they could have been. It is a signal of good faith to pre-register as much
  as you can!
- Qualities of the science of evals, including eval quality, elicitation rigor, sandbagging, etc.
  `asexec` aims to make the process of AI testing auditable, but does not make claims about the
  science itself.
- Anti-forgery of verify codes. The code is a summary of a computation, not a certificate. It is
  meaningful to verifiers only when produced from the registration files. In other words, don't
  blindly trust a verify code handed to you; see if you can reproduce it!

---

## Install

```bash
pip install asexec # ed25519 (PyNaCl) + BLS verification for drand (py_ecc)
```

## Quickstart (the full commit-then-reveal cycle)

```bash
# 1. Practitioner, one-time: generate a pseudonymous keypair (no CA, no registration)
asexec keygen --out lab.key

# 2. Practitioner, BEFORE the run: pre-register the target
asexec prereg --key lab.key \
    --subject ./harness \
    --target "claude-opus-4-8 via the anthropic API" \
    --due 2026-08-30T00:00:00Z \
    --declaration "all runs of this harness against this model, in full" \
    --out preregistration.json

# 3. Practitioner, AFTER each run: post-register a receipt of the inputs
asexec postreg --key lab.key --fulfills preregistration.json \
    --subject ./transcript.txt ./harness \
    --out postregistration.json

# 4. Any verifier, anytime: verify the cycle and render the commitment state.
#    --tests names exactly which checks to run; 'BDR' (sig + keyid) is required.
asexec verify preregistration.json postregistration.json \
    --tests BDR,content,chain,keyconsist --artifacts .
```

For a detailed look at parameters and options, see: `asexec --help`.

### The verify code (what step 4 produces)

`verify` runs the tests you name and prints one canonical code, e.g.:

```
asexec-verify/1 BDR=PASS chain=PASS content=PASS keyconsist=PASS
```

Grammar (`asexec-verify/1` versions the code format): the literal prefix, then one
`name=RESULT` token per requested test (`RESULT ∈ {PASS, FAIL}`), sorted alphabetically,
single-space delimited. The same result set is byte-identical everywhere.

- You declare your appetite. `--tests` is required and must include `BDR` (bedrock - the
  mandatory minimum: signature + keyid). Everything else is opt-in: `content` (subject
  digests vs. `--artifacts`), `chain` (`prev_hash` integrity), `keyconsist` (postregs share
  the prereg's key), `floor` (drand freshness), `ceiling` (Roughtime witness).
- Named, not scored, so it's forward-compatible. Because the code names which tests
  ran, adding a test in a later version can never change the meaning of an older code. A code
  means exactly one thing, permanently.
- A requested test that applies nowhere is `FAIL`, never a silent omission (e.g.
  `--tests BDR,ceiling` on manifests with no ceiling -> `ceiling=FAIL`).
- The code is not a certificate. Real verification comes from the verifier running the tool
  against the files and get the code.

## Identity (optional domain control check, no CA)

```bash
# A domain owner asserts which keys speak for it:
asexec identity emit --key lab.key --domain lab.example --out asexec.json
#   -> publish at https://lab.example/.well-known/asexec.json

# Anyone checks the binding (point-in-time; a domain can rotate keys):
asexec identity verify --domain lab.example --key lab.key
#   -> GET https://lab.example/.well-known/asexec.json
#   -> returns bound==True iff specified key exists there.
```

## Network requirements

Most `asexec` functionality is fully offline, which serves to drastically reduce the trust
serface. This includes all `asexec verify` operations, which are 100% offline by design;
everything needed to perform a verification is baked-in to the prereg/postreg manifests.

There are a few opt-in registration paths that use a network connection:

- `prereg/postreg --drand`: Fetches a distributed randomness beacon round from `api.drand.sh`
  (or a fallback) at sign-time.
- `prereg/postreg --ceiling`: Makes a UDP socket call (with server-list fallbacks) to a
  Roughtime server at sign-time.

The `asexec identity` check loop is also network-dependent, as it is explicitly a domain-
ownership check. It exists outside registration verification as an opt-in helper.

## Manifest at a glance

Bespoke signed JSON, signed over a DSSE-style PAE input (borrows in-toto field names, not the
tooling). The bedrock (mandatory) set is deliberately small - the fields whose absence
would break verifiability of commitment -> fulfillment/gap:

- semantic: `target` (what was committed to - plain text or structured JSON). This is the
  only mandatory claim.
- structural: the format frame - `schema_version`, `predicateType`, `phase`
  (`prereg` | `postreg`).

Everything else is individually optional: `due` (the disclosure deadline — a commitment
without one simply stays `open`), `declaration` (plain-language or structured commitment
text), `subject` + `hash_alg` (conditionally paired - `hash_alg` is required iff a
`subject` is present; a pre-registration may commit to a target before any harness exists to
hash), `anchor.floor` (drand, opt-in via `--drand`), `identity`, `provenance` +
`repro_recipe`, free-form `notes`. Specificity is a trust gradient the reader prices.

The ceiling witness (Roughtime) lives at the envelope level, beside `payload` and
`signature` - not inside the signed body, because its nonce is the body's own hash
(`ref(payload)`), which can't be embedded in the thing it hashes. It is self-authenticated by
the witness signature and binds to the manifest via `nonce == ref(payload)`. This is a purposeful
asymmetry between floor and ceiling, because the proof of floor requires a piece of information
to be embedded in the manifest, while the ceiling proof requires the payload to be referenced
by an external witness.

## Prior art and related projects 

AsPredicted/OSF pre-registration, ClinicalTrials.gov + the FDAAA TrialsTracker,
OpenTimestamps, in-toto/DSSE, drand/League of Entropy.

## Author

Designed by Luke Whitestone. Check out my other projects at: **[lukewhitest.one](https://lukewhitest.one/)**.

## Status

Currently: **0.3.x - alpha.** Realigns the vocabulary and hardens the types (breaking, no back-compat):
`prereg`/`postreg` commands + phases, a free-form `target` (the only mandatory claim), an
optional `due` deadline + `declaration`, opt-in drand `--drand`, the `BDR` bedrock code
token, and Pydantic-typed manifest construction. Builds on 0.2.0's schema rebalance + typed
`anchor.floor` (drand) / external-witness `ceiling` (Roughtime) + canonical
`asexec-verify/1` code. See [`ROADMAP.md`](./ROADMAP.md) for the version-keyed backlog —
including later items (per-key public index, re-execution/determinism mode) and what is
explicitly not scheduled (hosted transparency log, identity binding/CA).

> Ceiling — status: the Roughtime verification protocol (delegation chain, Merkle path,
> validity window) is fully implemented and offline-verifiable. Long-term keys for four public
> IETF-Roughtime servers are pinned from the official ecosystem list, and the wire format is
> reconciled against a live `int08h-Roughtime` capture baked as an offline fixture. The
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
