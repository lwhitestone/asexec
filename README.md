# asexec - AsExecuted

**Pre-registered attestations for AI executions. Tamper-evident and independently verifiable.**

**How it works in a nutshell:**

A practitioner attests to invoking AI *before* the outcome is known,
then publishes records of what actually happened. Anyone with the records can verify nothing was
changed and whether any assertions hold up.

**Benefits:**
- As a practitioner, using `asexec` signals intellectual honesty, transparency, and a commitment to
responsible disclosure, as you can no longer withhold results (which might not appear favorable on
their own) without your non-disclosure becoming public. This makes any results you publish more
meaningful to your audience, who can now "trust, but verify" your claims.
- As a watchdog, you now have the power to pressure-test claims that controllers of generative AI
systems may make. A practitioner refusing to pre-register their executions serves as its own red
flag.
- As a consumer, you now have increased confidence that quality and safety problems are caught,
because practitioners are more transparent with watchdogs, who actually have the incentive to
notify you when issues arise.

**As predicted... for AI:**

It is the "as executed" counterpart to pre-registration ([as predicted](https://aspredicted.org)),
borrowing the commit-then-reveal mechanism from clinical-trial pre-registration and applying it to
similar transparency problems in AI safety, including selective disclosure and lack of oversight.

**Opinionated about verification, but everything else is up to you:**

`asexec` is a primitive, not a platform. It offers a signing/verification library and a thin CLI.
There is no hosted service, no CA, no leaderboard, etc, in the core product. Choose what you wish
to disclose, and publish the records wherever you like. Verifiers choose what tests to run.

---

## What does `asexec` prove?

What a particular execution cycle's manifest proves is up to the practitioner (who can
choose what to disclose) and the verifier (who can choose what to check). Proof comes
in the form of `asexec verify` providing a code regarding the checks applied.

**`asexec` can prove:**
- A manifest (pre-registration or post-registration) was not altered after signing.
- A post-registration references a specific prior pre-registration, and the post-registrations
  of a commitment form a single linear `prev_hash` chain (one root, no gaps, no forks). A
  post-registration counts toward fulfilling a pre-registration only if it is validly signed by
  that pre-registration's key. *Dropping the last post-registration(s) of a chain is **not**
  detectable yet; close-out manifests (`final`) arrive in 0.4.0.*
- The state of each commitment, rendered as an explicit `fulfilled`/`open`/`elapsed-no-receipt`/
  `invalid-due`/`notarization-only`. The declared disclosure deadline (`due`) is *displayed and
  used to tell `open` from `elapsed-no-receipt`*, but `asexec` does **not** check that a
  post-registration was created before `due`; that check (`timely`) arrives in 0.4.0.
- A manifest was created no earlier than a public moment (floor "freshness" check, offered by
  `drand`).
- A manifest was created no later than time T (ceiling "witness" check, offered by `Roughtime`;
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

## Installation

```bash
pip install asexec # ed25519 (PyNaCl) + BLS verification for drand (py_ecc)
```

## Usage

```bash
# 1. Practitioner, one-time: generate a pseudonymous keypair (no CA, no registration)
asexec keygen --out lab.key   # refuses to overwrite an existing key unless --force

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

`--due` must carry an explicit UTC offset or `Z` (`2026-08-30T00:00:00Z`); a timezone-less
deadline is rejected. `--fulfills` and `--prev` take an existing manifest file or a literal
`sha-256:<64 hex>` ref; anything else is an error.

For a detailed look at parameters and options, see: `asexec --help`.

### Verification output

What each test examines, its exact pass criteria, and what it does not establish are
specified in the [verification catalog](./docs/VERIFICATION.md).

`verify` runs the tests you name and prints one canonical code, e.g.:

```
asexec-verify/1 BDR=PASS chain=PASS content=PASS keyconsist=PASS
```

Grammar (`asexec-verify/1` versions the code format): the literal prefix, then one
`name=RESULT` token per requested test (`RESULT ∈ {PASS, FAIL}`), sorted alphabetically,
single-space delimited. The same result set is byte-identical everywhere.

- You declare your appetite. `--tests` is required and must include
  [`BDR`](./docs/VERIFICATION.md#bdr) (bedrock - the mandatory minimum: signature + keyid).
  Everything else is opt-in: [`content`](./docs/VERIFICATION.md#content) (subject digests
  vs. `--artifacts`), [`chain`](./docs/VERIFICATION.md#chain) (`prev_hash` integrity),
  [`keyconsist`](./docs/VERIFICATION.md#keyconsist) (postregs share the prereg's key),
  [`floor`](./docs/VERIFICATION.md#floor) (drand freshness),
  [`ceiling`](./docs/VERIFICATION.md#ceiling) (Roughtime witness).
- Named, not scored, so it's forward-compatible. Because the code names which tests
  ran, adding a test in a later version can never change the meaning of an older code. A code
  means exactly one thing, permanently.
- A requested test that applies nowhere is `FAIL`, never a silent omission (e.g.
  `--tests BDR,ceiling` on manifests with no ceiling -> `ceiling=FAIL`).
- The code is not a certificate. Real verification comes from the verifier running the tool
  against the files and get the code.

## Manifest at a glance

A post-registration with every field filled in. Fields marked `required` must be present;
everything else is optional, and how much to disclose is the practitioner's call.

```jsonc
{
  "payloadType": "application/vnd.asexec+json",
  "payload": {                                       // required: the signed body
    "schema_version": "asexec",                      // required
    "predicateType": "https://asexec.dev/manifest",  // required
    "phase": "postreg",                              // required: prereg | postreg
    "target": "claude-opus-4-8 via the anthropic API", // required: text or JSON
    "due": "2026-08-30T00:00:00Z",                   // deadline; none = stays open
    "declaration": "all runs of this harness against this model, in full", // text or JSON
    "subject": [                                     // artifacts, hashed
      { "name": "transcript.txt", "digest": { "sha-256": "9f86d081…" } },
      { "name": "harness/", "digest": { "sha-256": "2c26b46b…" } }
    ],
    "hash_alg": "sha-256",                           // required with subject
    "fulfills": "sha-256:4be1c1f8…",                 // required in a postreg
    "prev_hash": "sha-256:07ad3b2e…",                // previous postreg
    "anchor": {
      "floor": {                                     // drand (--floor): not before
        "floor_type": "drand",
        "chain_hash": "52db9ba7…",
        "round": 21543210,
        "signature": "8d2f1c3a…",
        "randomness": "c3d4e5f6…"
      }
    },
    "identity": ["lab.example"],                     // free-form list
    "provenance": "reproducible",                    // asserted | reproducible
    "repro_recipe": { "seed": 42, "decode": "greedy", "runtime": "vllm 0.9" },
    "notes": "free-form text or JSON"
  },
  "signature": {                                     // required
    "alg": "ed25519",
    "keyid": "sha-256:8f3e0a91…",                    // required: sha-256 of pubkey
    "pubkey": "d75a9801…",                           // required
    "sig": "e5564300…"                               // required
  },
  "ceiling": {                                       // Roughtime (--ceiling): not after
    "ceiling_type": "roughtime",
    "witness_id": "int08h-Roughtime",
    "pubkey": "016e6e02…",
    "nonce": "5e9a7c44…",                            // = ref(payload)
    "midpoint": 1787234400.0,
    "radius": 1.0,
    "response": "0400000040…"
  }
}
```

`sig` signs a DSSE-style PAE encoding of `payload` (in-toto field names, not the tooling). A
prereg has the same shape without `fulfills` and `prev_hash`. The ceiling sits outside the
signed `payload` because its nonce is the payload's own hash; the floor sits inside it,
because a value fixed before signing can be signed.

## Identity (optional domain control check, no CA)

```bash
# A domain owner asserts which keys speak for it:
asexec identity emit --key lab.key --domain lab.example --out asexec.json
#   -> publish at https://lab.example/.well-known/asexec.json

# Anyone checks the binding for a match (point-in-time; a domain can rotate keys):
asexec identity match --domain lab.example --key lab.key
#   -> GET https://lab.example/.well-known/asexec.json
#   -> returns bound==True iff specified key exists there.
```

## Network requirements

Most `asexec` functionality is offline, which serves to drastically reduce the trust
surface. This includes all `asexec verify` operations, which are 100% offline by design;
everything needed to perform a verification is baked-in to the prereg/postreg manifests.

There are a few opt-in registration paths that use a network connection:

- `prereg/postreg --floor`: Fetches a distributed randomness beacon round from `api.drand.sh`
  (or a fallback) at sign-time.
- `prereg/postreg --ceiling`: Makes a UDP socket call (with server-list fallbacks) to a
  Roughtime server at sign-time.

If a requested `--floor`/`--ceiling` fetch fails, signing fails and nothing is written.
Pass `--best-effort` to warn and sign without the anchor instead.

The `asexec identity` check loop is also network-dependent, as it is explicitly a domain-
ownership check. It exists outside registration verification as an opt-in helper.

## Prior art and related projects 

AsPredicted/OSF pre-registration, ClinicalTrials.gov + the FDAAA TrialsTracker,
OpenTimestamps, in-toto/DSSE, drand/League of Entropy.

## Development and Releases

Local setup, checks, CI, and the tag-triggered release pipeline (TestPyPI, then PyPI after
manual approval) are documented in [`docs/DEVELOPMENT.md`](./docs/DEVELOPMENT.md).

Quick start:

```bash
scripts/dev-setup.sh   # one-time setup
scripts/check.sh       # lint + format check + tests
```

How the verifier is built, and how to change it:

- [`docs/VERIFICATION.md`](./docs/VERIFICATION.md) is the contract. A model decides whether
  one slice of JSON is well-formed; the verifier decides everything else, including every
  verdict. Each *structural* requirement (types, shapes, literals, hex, pinned constants)
  is a field on a strict pydantic input model in `models.py` (shared field types in
  `fields.py`). Cryptographic, filesystem and cross-manifest checks stay as code that runs
  on the parsed models. A model never returns PASS or FAIL: it parses or raises, and the
  verifier turns that into a FAIL. Malformed input is never an exception.
- Input models are `strict` and `extra="allow"`, so a future field never breaks offline
  verification, and read `null` as absent. Where a writer model describes the same slice, it
  subclasses the input model, forbids extra fields and rejects `None`, so a shape is
  written once.
- `tests/verify/` is a black-box contract test of `VERIFICATION.md`: it calls
  `verify_paths` or the CLI and never imports the input models. Valid inputs come from the
  production writer; invalid ones are written as dotted property paths
  (`scenario.set("payload.anchor.floor.round", "1000")`), never built with the models, so a
  wrong model cannot produce a matching wrong input. A coverage test requires a failing
  test (`test_<name>__fail__<n>_...`) for every numbered requirement in the doc.

## Author

Designed by Luke Whitestone. Check out my other projects at: **[lukewhitest.one](https://lukewhitest.one/)**.

## Status

Currently: **0.3.x - alpha.** Realigns the vocabulary and hardens the types (breaking, no back-compat):
`prereg`/`postreg` commands + phases, a free-form `target` (the only mandatory claim), an
optional `due` deadline + `declaration`, opt-in drand `--floor`, the `BDR` bedrock code
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

## Known issues

Fixed issues are listed in [`ROADMAP.md`](./ROADMAP.md). The following remain (format-level
fixes arrive in 0.4.0). Until then, treat `asexec verify` output with these caveats:

**Commitment state and chain**
- Dropping the *last* receipt(s) of a chain is undetectable, and timeliness is not checked:
  a post-registration created after `due` still renders `fulfilled`.
- A manifest whose `due` has no timezone (the writer no longer produces one) is read as UTC
  and flagged in the report.

**Input handling**
- `BDR` checks only the envelope (an object `payload` and a `signature` with hex `pubkey`
  and `sig`) and the signature. Any validly signed payload object passes, whether or not it
  is a well-formed asexec manifest body; the body is checked only slice by slice, by the
  tests that examine it.
- Hex is lenient: any spelling `bytes.fromhex` accepts (either case, whitespace between
  bytes) is read as hex. This tool writes only lowercase; strict lowercase arrives in 0.4.0.
- Directory hashing (v1) is ambiguous on POSIX: a filename containing a newline can make two
  different trees hash identically. Symlinks are skipped silently.

## License

Apache-2.0.
