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

### What `asexec` always proves

Every `verify` run checks [`BDR`](./docs/VERIFICATION.md#bdr) and renders the state of each
commitment:

- **Integrity.** A manifest (pre-registration or post-registration) was not altered after
  signing, and was signed by the key its `keyid` names.
- **What was committed to.** Every manifest carries a `target`, and every post-registration
  names the pre-registration it `fulfills`.
- **Commitment state.** Each pre-registration is rendered as `fulfilled`, `open`,
  `elapsed-no-receipt` or `invalid-due`; a post-registration whose pre-registration was not
  provided is `notarization-only`. A post-registration counts toward fulfilling a
  pre-registration only if it is validly signed by that pre-registration's key. The declared
  deadline (`due`) is *displayed and used to tell `open` from `elapsed-no-receipt`*, but
  `asexec` does **not** check that a post-registration was created before `due`; that check
  (`timely`) arrives in 0.4.0.

### What `asexec` can prove (optional fields and tests)

Each of these holds only when the practitioner includes the field and the verifier names the
test:

- **Content** (`subject`; [`content`](./docs/VERIFICATION.md#content) with `--artifacts`). The
  artifacts the verifier holds match the digests a manifest records.
- **Chain** (`prev_hash`; [`chain`](./docs/VERIFICATION.md#chain)). The post-registrations of a
  commitment form a single linear chain: one root, no gaps, no forks. *Dropping the last
  post-registration(s) of a chain is **not** detectable yet; close-out manifests (`final`)
  arrive in 0.4.0.*
- **Key consistency** ([`keyconsist`](./docs/VERIFICATION.md#keyconsist)). Every validly
  signed post-registration of a commitment uses the pre-registration's key.
- **Created no earlier than** (`anchor.floor`; [`floor`](./docs/VERIFICATION.md#floor)). A
  manifest was created after a public moment: a [drand](https://drand.love/) beacon round it
  embeds.
- **Created no later than** (`ceiling`; [`ceiling`](./docs/VERIFICATION.md#ceiling)). A
  manifest existed by time T: a
  [Roughtime](https://datatracker.ietf.org/doc/draft-ietf-ntp-roughtime/) server signed its
  hash (a signature-witness, not proof-of-work).

### What `asexec` cannot prove

- **Who signed.** A key is pseudonymous: `asexec` proves which key signed, not whose it is.
  The optional [identity check](#identity-optional-domain-control-check-no-ca) ties a key to
  a domain, outside `verify`.
- **Provenance.** Content hashes prove a transcript wasn't altered; they do not prove it is the
  output of the named harness+model (asserted by the signer, not re-executed).
- **Completeness.** It renders only the manifests you give it; it cannot prove a lab pre-registered
  every eval it should have (selective pre-registration). However, just like practitioners are not
  forced to `asexec prereg` all their testing, verifiers are not forced to trust results that were
  telegraphed less than they could have been. It is a signal of good faith to pre-register as much
  as you can!
- **The science of evals.** Eval quality, elicitation rigor, sandbagging, etc. `asexec` aims
  to make the process of AI testing auditable, but does not make claims about the science
  itself.
- **Anti-forgery of verify codes.** The code is a summary of a computation, not a certificate. It is
  meaningful to verifiers only when produced from the registration files. In other words, don't
  blindly trust a verify code handed to you; see if you can reproduce it!

---

## Installation

Requires Python 3.12 or later.

```bash
pip install asexec            # ed25519 (PyNaCl) + BLS verification for drand (py_ecc)
pip install 'asexec[blake3]'  # optional: blake3 as a content-hash algorithm
```

## Usage

```bash
# 1. Practitioner, one-time: generate a pseudonymous keypair (no CA, no registration)
asexec keygen --out lab.key   # refuses to overwrite an existing key unless --force

# 2. Practitioner, BEFORE the run: pre-register the target
asexec prereg --key lab.key \
    --subject ./harness \
    --target "claude-opus-4-8 via the anthropic API" \
    --due 2099-01-01T00:00:00Z \
    --declaration "all runs of this harness against this model, in full" \
    --out preregistration.json

# 3. Practitioner, AFTER each run: post-register a receipt of the run
asexec postreg --key lab.key --fulfills preregistration.json \
    --subject ./transcript.txt ./harness \
    --out postregistration.json

# 4. Any verifier, anytime: verify the cycle and render the commitment state.
#    --tests names exactly which checks to run; 'BDR' (sig + keyid) is required.
asexec verify preregistration.json postregistration.json \
    --tests BDR,content,chain,keyconsist --artifacts .
```

`--due` must carry an explicit UTC offset or `Z` (`2099-01-01T00:00:00Z`); a timezone-less
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
  [`BDR`](./docs/VERIFICATION.md#bdr); every other test is opt-in (see
  [What `asexec` can prove](#what-asexec-can-prove-optional-fields-and-tests)).
- Named, not scored, so it's forward-compatible. Because the code names which tests
  ran, adding a test in a later version can never change the meaning of an older code. A code
  means exactly one thing, permanently.
- A requested test that applies nowhere is `FAIL`, never a silent omission (e.g.
  `--tests BDR,ceiling` on manifests with no ceiling -> `ceiling=FAIL`).
- The code is not a certificate. Real verification comes from the verifier running the tool
  against the files and getting the code.

## Manifest at a glance

A pre-registration and a post-registration that fulfills it, as would be built by
`asexec prereg` and `asexec postreg`, with every field filled in. Fields marked `required`
will always be present; everything else is optional, and how much to disclose is the
practitioner's call.

**Pre-registration**

```jsonc
{
  "payloadType": "application/vnd.asexec+json",
  "payload": {                                       // required: the signed body
    "schema_version": "asexec",                      // required
    "predicateType": "https://asexec.dev/manifest",  // required
    "phase": "prereg",                               // required: prereg | postreg
    "target": "claude-opus-4-8 via the anthropic API", // required: text or JSON
    "due": "2099-01-01T00:00:00Z",                   // deadline; none = stays open
    "declaration": "all runs of this harness against this model, in full", // text or JSON
    "subject": [                                     // artifacts, hashed
      { "name": "harness/", "digest": { "sha-256": "2c26b46b…" } }
    ],
    "hash_alg": "sha-256",                           // required with subject
    "anchor": {
      "floor": {                                     // drand (--floor): not before
        "floor_type": "drand",
        "chain_hash": "52db9ba7…",
        "round": 21102400,
        "signature": "b7e04a19…",
        "randomness": "1f0c9d2e…"
      }
    },
    "identity": ["lab.example"],                     // free-form list
    "notes": "hypothesis: refusal rate under 2%"     // text or JSON
  },
  "signature": {                                     // required
    "alg": "ed25519",
    "keyid": "sha-256:8f3e0a91…",                    // required: sha-256 of pubkey
    "pubkey": "d75a9801…",                           // required
    "sig": "3a91c0de…"                               // required
  },
  "ceiling": {                                       // Roughtime (--ceiling): not after
    "ceiling_type": "roughtime",
    "witness_id": "int08h-Roughtime",
    "pubkey": "016e6e02…",
    "nonce": "4be1c1f8…",                            // = ref(payload)
    "midpoint": 1785911400.0,
    "radius": 1.0,
    "response": "0400000040…"
  }
}
```

**Post-registration**

```jsonc
{
  "payloadType": "application/vnd.asexec+json",
  "payload": {                                       // required: the signed body
    "schema_version": "asexec",                      // required
    "predicateType": "https://asexec.dev/manifest",  // required
    "phase": "postreg",                              // required: prereg | postreg
    "target": "claude-opus-4-8 via the anthropic API", // required: text or JSON
    "due": "2099-01-01T00:00:00Z",                   // deadline; none = stays open
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
  }
  // "signature" (required) and "ceiling": same shape as in the prereg
}
```

`sig` signs a [DSSE](https://github.com/secure-systems-lab/dsse)-style [PAE](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md#signature-definition)
(pre-authentication encoding) of `payload`, borrowing [in-toto](https://in-toto.io/) field names.
A postreg carries its prereg's `target`, `due` and `declaration`, links back with `fulfills`
(the prereg's ref, which is also its ceiling `nonce`) and `prev_hash`, and, from the CLI,
adds `provenance` and `repro_recipe`. The ceiling sits outside the signed `payload` because
its nonce is the payload's own hash; the floor sits inside it, because a value fixed before
signing can be signed.

## Keys

`asexec keygen --out lab.key` writes two files:

| File | Contains | Secret? |
|---|---|---|
| `lab.key` | ed25519 private key (hex, **unencrypted**), public key, `keyid` | **Yes.** Written mode `0600` on Unix |
| `lab.key.pub` | public key and `keyid` (`sha-256:` of the public key) | No. It is also in every manifest you sign |

### Impact

A post-registration counts toward a pre-registration only if both were signed with the same
private key. So:

- **Lose the private key** and your open commitments can never be fulfilled: they stay `open`,
  or turn `elapsed-no-receipt` once `due` passes. Back up `lab.key` offline (e.g. in an
  encrypted password manager or vault) before you pre-register.
- **Leak the private key** and anyone can sign pre- and post-registrations as you, including
  post-registrations that count toward your commitments. `asexec` has no revocation: stop
  using the key pair, say so publicly, and remove its public key from your
  [identity](#identity-optional-domain-control-check-no-ca) `.well-known` file.

### Handling

- Never commit the private key file (`*.key` in `.gitignore`) or print it in logs. In CI,
  keep it in the secret store and write it to a `0600` file only for the signing step.
- On Windows, file modes are not applied; restrict the private key file's ACL yourself.
- `keygen` refuses to overwrite an existing key pair; `--force` replaces it and the old
  private key is gone.
- Your public key (and its `keyid`) is your pseudonym: every manifest it verifies is linkable
  to the others. Use separate key pairs for identities you want kept apart.

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

`asexec identity` is network-dependent too, since it checks domain ownership; it is an
opt-in helper outside `verify`.

## Prior art and related projects

- [AsPredicted](https://aspredicted.org), [OSF](https://osf.io/) (pre-registration)
- [ClinicalTrials.gov](https://clinicaltrials.gov/) and the
  [FDAAA TrialsTracker](https://fdaaa.trialstracker.net/)
- [OpenTimestamps](https://opentimestamps.org/)
- [in-toto](https://in-toto.io/) and [DSSE](https://github.com/secure-systems-lab/dsse)
- [drand](https://drand.love/) and the
  [League of Entropy](https://www.cloudflare.com/leagueofentropy/)

## Development and releases

Local setup, checks, CI, and the tag-triggered release pipeline (TestPyPI, then PyPI after
manual approval) are documented in [`docs/DEVELOPMENT.md`](./docs/DEVELOPMENT.md).

Quick start:

```bash
scripts/dev-setup.sh   # one-time setup
scripts/check.sh       # lint + format check + tests
```

How the verifier is built, and how to change it, is in
[`docs/DEVELOPMENT.md`](./docs/DEVELOPMENT.md#verifier-architecture).

## Author

Designed by Luke Whitestone. Check out my other projects at: **[lukewhitest.one](https://lukewhitest.one/)**.

## Status

**Alpha.** [`ROADMAP.md`](./ROADMAP.md) has the release history, what is planned, and what is
explicitly not.

> **No backward-compatibility guarantee before `1.0.0`.** This is pre-1.0 alpha: any release
> may change the manifest schema, the signed-byte format, the verifier output, or the CLI
> without a migration path — manifests signed by an older build may stop verifying against a
> newer one. (0.2.0 rebalanced the schema in a breaking way by design.) Stability begins at
> `1.0.0`, which is neither defined nor planned yet.

## Known issues

Where `asexec` deviates from the [verification contract](./docs/VERIFICATION.md) (fixes
arrive in 0.4.0):

- **Directory hashes (v1) are ambiguous**, so `content` can pass for a different tree: a
  filename containing a newline can make two trees hash identically, and symlinks inside a
  directory are skipped silently.

## License

Apache-2.0.
