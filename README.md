# asexec - AsExecuted

**Pre-registered attestations for AI executions: tamper-evident, non-repudiable, and
independently verifiable.**

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

Every `verify` run checks [`format`](./docs/VERIFICATION.md#format) and
[`selfsig`](./docs/VERIFICATION.md#selfsig), and renders the state of each commitment (a
validly signed pre-registration and its signer):

- **Integrity and non-repudiation.** A manifest (pre-registration or post-registration) was
  not altered after signing, and was signed by the private key whose public key its `keyid`
  names, so the holder of that key cannot later deny signing it.
- **What was committed to.** The signature covers the whole body, the bytes `dsse.payload`
  stores, exactly as stored: its `target` (which `asexec prereg` and `postreg` always
  write) and, in a post-registration, the pre-registration it `fulfills`.
- **Commitment state.** Each commitment is rendered as `fulfilled`, `no-due`, `open`,
  `elapsed-no-postreg` or `invalid-due`. A post-registration that names a pre-registration
  counts toward fulfilling it only if validly signed by that pre-registration's private key;
  otherwise it is listed under it as *rejected*, with the reason. A pre-registration whose
  own signature is invalid is no commitment, so it has no state and nothing counts toward
  it: it is listed as a *rejected pre-registration*, and each post-registration that names
  it is listed beneath it as rejected. A post-registration whose pre-registration was not
  provided belongs to no commitment, so it has no state: it is listed as
  *notarization-only*. Silence is on the record too: a pre-registration with no
  counted post-registration reads `elapsed-no-postreg` once its deadline (`due`) passes, and
  `no-due` if it declared none. A state says only whether it was reported: a late
  post-registration still turns it `fulfilled`, and whether it came before `due` is the
  [`timely`](./docs/VERIFICATION.md#timely) test's to say (below).

### What `asexec` can prove (optional fields and tests)

Each of these holds only when the practitioner includes the field and the verifier names the
test:

- **Content** (`subject`; [`content`](./docs/VERIFICATION.md#content) with `--artifacts`). The
  artifacts the verifier holds match the digests a manifest records.
- **Chain** (`prev_hash`; [`chain`](./docs/VERIFICATION.md#chain)). The counted
  post-registrations of a commitment form a single linear chain: one root, no gaps, no
  forks. *Dropping the last post-registration(s) of a chain is **not** detectable by
  `chain`; close-out manifests (`final`) are deferred to 0.7.0 or later. A claim that lists
  its items can use `complete` (below).*
- **Every item accounted for** (`items` in the pre-registration, `item_id` and `status` in
  each post-registration; [`complete`](./docs/VERIFICATION.md#complete)). Each item the
  pre-registration lists has a counted post-registration with its `item_id` and a status of
  `reported`, `excluded` or `blocked`, and, if the pre-registration has a `due`, one that is
  on time as `timely` judges it. A dropped item fails it.
- **Key consistency** ([`keyconsist`](./docs/VERIFICATION.md#keyconsist)). Every validly
  signed post-registration that names a commitment was signed with the key of a validly
  signed pre-registration with that body.
- **Created no earlier than** (`anchor.floor`; [`floor`](./docs/VERIFICATION.md#floor)). A
  manifest was created after a public moment: a [drand](https://drand.love/) beacon round it
  embeds. `--floor` fetches the latest round when signing; `--floor-round` signs with a round
  fetched earlier, such as the one a run fetched when it started.
- **Created no later than** (`ceiling`; [`ceiling`](./docs/VERIFICATION.md#ceiling)). A
  manifest existed by time T: a
  [Roughtime](https://datatracker.ietf.org/doc/draft-ietf-ntp-roughtime/) server signed its
  hash (a signature-witness, not proof-of-work).
- **On time** (`due` and a `ceiling` on each post-registration;
  [`timely`](./docs/VERIFICATION.md#timely)). Each counted post-registration existed by its
  pre-registration's `due`: its ceiling verifies, and the latest time the witness allows
  (`midpoint + radius`) is at or before `due`. A post-registration without a valid ceiling
  is not shown on time. A pre-registration with no `due` is not examined.
- **Pre-registered before the post-registration was made** (a `ceiling` on the
  pre-registration, an `anchor.floor` on each post-registration;
  [`order`](./docs/VERIFICATION.md#order)). The pre-registration's ceiling (the latest time
  the witness allows) is before each counted post-registration's floor round, so the
  pre-registration existed before the post-registration was made. *It bounds the run only as
  tightly as the run's use of that round: a round the run fetched when it started and used
  (as its seed, say) lets a re-execution check it; a round it merely records, or one
  `--floor` fetched at signing, proves nothing about when the run started.*

### What `asexec` cannot prove

- **Who signed.** Non-repudiation stops at the key. A key pair is pseudonymous: `asexec`
  proves which private key signed, not whose it is, so a signer can still claim "that's not
  my key" or "my key was stolen". The optional
  [identity check](#identity-optional-domain-control-check-no-ca) ties a public key to a
  domain, outside `verify`; a ceiling witness shows a manifest existed before any claimed
  theft. There is no key revocation (see [Keys](#keys)).
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

# 2. Practitioner, BEFORE the run: pre-register the target. A subject lists files (no
#    directories), each named by its path relative to the current directory.
asexec prereg --key lab.key \
    --subject harness/run.py harness/config.yaml \
    --target "claude-opus-4-8 via the anthropic API" \
    --due 2099-01-01T00:00:00Z \
    --declaration "all runs of this harness against this model, in full" \
    --out preregistration.json

# 3. Practitioner, AFTER each run: post-register the run
asexec postreg --key lab.key --fulfills preregistration.json \
    --subject transcript.txt harness/run.py harness/config.yaml \
    --out postregistration.json

# 4. Any verifier, anytime: verify the cycle and render the commitment state.
#    --tests names exactly which checks to run; 'format' (the file can be read) and
#    'selfsig' (sig + keyid) are required. --artifacts is the directory the subjects'
#    names are relative to.
asexec verify preregistration.json postregistration.json \
    --tests format,selfsig,content,chain,keyconsist --artifacts .
```

To show the run came after the pre-registration ([`order`](./docs/VERIFICATION.md#order)),
pre-register with `--ceiling`, and have the run fetch a drand round when it starts, use it
(as its seed, say), and save the response; then sign its post-registration with that round:

```bash
# when the run starts: the latest round of the quicknet chain, which --floor uses too
curl -s https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/public/latest > round.json
#   -> {"round": 31036100, "randomness": "c3d4e5f6…", "signature": "8d2f1c3a…"}

asexec postreg --key lab.key --fulfills preregistration.json \
    --floor-round-file round.json --out postregistration.json
```

`--floor-round` takes the same JSON inline. The round must be exactly what drand's HTTP API
returns for a round (`round`, `randomness`, `signature`, of the chain `--floor` uses); it is
verified at signing, offline, and a round that does not verify is refused. It excludes
`--floor`.

For a detailed look at parameters and options, see: `asexec --help`.

For a worked end-to-end run, with faults replayed against the verifier, see
[`examples/adequacy-test`](examples/adequacy-test): `python examples/adequacy-test/run.py`.

### Exit status

| Status | Meaning |
|---|---|
| `0` | Success. For `verify`, every requested test is `PASS`; for `identity match`, the key is bound to the domain. |
| `1` | Error: the arguments are valid, but the command could not complete with the files or network they name, e.g. a missing or invalid key file; an unreadable `--subject`; a `--…-file` that is missing, not a regular file, or does not hold what its option takes (UTF-8 JSON text with no repeated key, nested at most 64 deep, of the option's shape: a non-empty JSON object or string for `--target-file`, `--declaration-file` and `--notes-file`, a round that verifies for `--floor-round-file`); a `--fulfills` file that fails `format` or `selfsig` (a postreg fulfilling it could never count), or that has no target to inherit when none is given; a key file it refuses to overwrite; a failed `identity match` fetch, or a document there that is not an identity document; or a failed `--floor`/`--ceiling` fetch without `--best-effort`. One `error: ...` line is printed (after any `--best-effort` warning), never a traceback. |
| `2` | `verify`: at least one requested test is `FAIL`. `identity match`: the key is not bound. |
| `64` | Usage error: the arguments themselves are wrong, whatever the files hold. For example: an unknown command or option; a missing argument; an empty value, for any option or path; two that exclude each other, such as `--target` and `--target-file`, or `--floor` and `--floor-round`; a `--due` that is not an ISO-8601 time with an explicit offset; a `--tests` that names an unknown test, names none, or omits `format` or `selfsig`; an inline `--plan`, `--items`, `--evidence`, `--floor-round` or `--repro-recipe` value that is not JSON, repeats a key, nests more than 64 deep, or is not of its shape (`--repro-recipe` is an object), or an inline `--floor-round` that does not verify (`--best-effort` does not sign without it); a `--status` other than `reported`, `excluded` or `blocked`; a `--domain` holding whitespace or a control character; or for `identity match`, not exactly one of `--keyid`, `--pubkey` and `--key`. Usage is printed and nothing runs (`verify` prints no code). |

For `verify`, malformed manifest input is a `FAIL`, never an error. Its exit status is its
verdict even when stdout closes before the report is printed, as in
`asexec verify … | head -1`.

### Verification output

What each test examines, its exact pass criteria, and what it does not establish are
specified in the [verification catalog](./docs/VERIFICATION.md).

`verify` runs the tests you name and prints a report for people to read (each manifest; what
nothing checked, under its own headings: each file's unsigned `untrusted` section and any
key outside the body the format does not define, and any body field it does not define; each
commitment with its state, any rejected pre-registrations, any notarization-only
post-registrations, and each test's result with a short reason), then one canonical code,
then `Checked at <time>` (UTC, the moment commitment states were judged against), e.g.:

```
asexec-verify/1 chain=PASS content=PASS format=PASS keyconsist=PASS selfsig=PASS
Checked at 2026-12-31T23:59:59Z
```

Only the code line and the [exit status](#exit-status) are stable to script against.
Commitment states never affect either.

Grammar (`asexec-verify/1` versions the code format): the literal prefix, then one
`name=RESULT` token per requested test (`RESULT ∈ {PASS, FAIL}`), sorted alphabetically,
single-space delimited. The same result set is byte-identical everywhere.

- You declare your appetite. `--tests` is required and must include
  [`format`](./docs/VERIFICATION.md#format) and
  [`selfsig`](./docs/VERIFICATION.md#selfsig); every other test is opt-in (see
  [What `asexec` can prove](#what-asexec-can-prove-optional-fields-and-tests)).
- Named, not scored, so it's forward-compatible. Because the code names which tests
  ran, adding a test in a later version can never change the meaning of an older code. A code
  means exactly one thing, permanently, from `0.4.0`; until then a test's documented meaning
  may still be corrected (see [Status](#status)).
- A requested test with nothing to examine is *empty* and `FAIL`, never a silent omission
  or a pass (e.g. `--tests format,selfsig,ceiling` on manifests with no ceiling -> `ceiling=FAIL`).
- The code is not a certificate. Real verification comes from the verifier running the tool
  against the files and getting the code.

## Manifest at a glance

A pre-registration and a post-registration that fulfills it, as would be built by
`asexec prereg` and `asexec postreg`, with every field filled in. Each file is a standard
[DSSE](https://github.com/secure-systems-lab/dsse) envelope, `dsse`, in an asexec wrapper.
The signed body is stored as bytes: `dsse.payload` is their base64, and the body is the JSON
object they hold, shown decoded below each file. Fields marked `required` are the only ones
`verify` needs to read a manifest at all; without one, or with a `payload` that is not
strict base64 of a JSON object, the file is malformed. Every other field is optional to
read: leaving it out is structurally fine, and whether a manifest meets a bar is up to the
[tests](#what-asexec-can-prove-optional-fields-and-tests) you request (the required
[`selfsig`](./docs/VERIFICATION.md#selfsig) needs `pubkey` and the one signature's `keyid`
and `sig`). Fields marked `always` are always written by `asexec prereg` or
`asexec postreg`; the rest are the practitioner's call.

**Pre-registration**

```jsonc
{
  "dsse": {                                             // required: the DSSE envelope
    "payloadType": "application/vnd.asexec.v1+json",    // required: the format; must be one this release reads
    "payload": "eyJhbmNob3IiOnsiZmxvb3IiOnsiY2hh…",     // required: base64 of the body bytes, below
    "signatures": [                                     // required: always exactly one
      {
        "keyid": "sha-256:8f3e0a91…",                   // always: sha-256 of pubkey
        "sig": "OpHA3nT0…"                              // always: base64, over DSSE's PAE of the body bytes
      }
    ]
  },
  "pubkey": "d75a9801…",                                // always: hex
  "ceiling": {                                          // Roughtime (--ceiling): not after
    "ceiling_type": "roughtime",
    "witness_id": "int08h-Roughtime",
    "pubkey": "016e6e02…",
    "nonce": "4be1c1f8…",                               // = ref, the sha-256 of the body bytes
    "midpoint": 1785911400.0,
    "radius": 1.0,
    "response": "0400000040…"
  },
  "untrusted": {                                        // always written; unsigned, never tested
    "asexec_version": "0.4.0"                           // always: the release that wrote it
  }
}
```

The body (`dsse.payload` decoded):

```jsonc
{
  "predicateType": "https://asexec.org/manifest/v1",    // always
  "phase": "prereg",                                    // always: prereg | postreg
  "target": "claude-opus-4-8 via the anthropic API",    // always: text or JSON
  "due": "2099-01-01T00:00:00Z",                        // deadline; none = no-due
  "declaration": "all runs of this harness against this model, in full", // text or JSON
  "subject": [                                          // files, each hashed as listed
    { "name": "harness/run.py", "hash_alg": "sha-256", "digest": { "sha-256": "2c26b46b…" } }
  ],
  "plan": {                                             // the plan (--plan), hashed
    "name": "plan.md", "hash_alg": "sha-256", "digest": { "sha-256": "5d41402a…" },
    "media_type": "text/markdown", "label": "refusal study plan" // declared, never tested
  },
  "items": [                                            // what each postreg accounts for
    { "id": "R1", "kind": "run" },                      // kind: declared, never tested
    { "id": "R2", "kind": "ablation" }
  ],
  "anchor": {
    "floor": {                                          // drand (--floor): not before
      "floor_type": "drand",
      "chain_hash": "52db9ba7…",
      "round": 21102400,
      "signature": "b7e04a19…",
      "randomness": "1f0c9d2e…"
    }
  },
  "identity": ["lab.example"],                          // free-form list
  "notes": "hypothesis: refusal rate under 2%"          // text or JSON
}
```

**Post-registration**

```jsonc
{
  "dsse": {                                             // required, as in the prereg
    "payloadType": "application/vnd.asexec.v1+json",
    "payload": "eyJhbmNob3IiOnsiZmxvb3IiOnsiY2hh…",     // base64 of the body bytes, below
    "signatures": [ { "keyid": "sha-256:8f3e0a91…", "sig": "XA9+IVq1…" } ]
  },
  "pubkey": "d75a9801…",
  // "ceiling": same shape as in the prereg
  "untrusted": { "asexec_version": "0.4.0" }            // always written; unsigned, never tested
}
```

The body (`dsse.payload` decoded):

```jsonc
{
  "predicateType": "https://asexec.org/manifest/v1",    // always
  "phase": "postreg",                                   // always: prereg | postreg
  "target": "claude-opus-4-8 via the anthropic API",    // always: text or JSON
  "due": "2099-01-01T00:00:00Z",                        // deadline; none = no-due
  "declaration": "all runs of this harness against this model, in full", // text or JSON
  "subject": [                                          // files, each hashed as listed
    { "name": "transcript.txt", "hash_alg": "sha-256", "digest": { "sha-256": "9f86d081…" } },
    { "name": "harness/run.py", "hash_alg": "sha-256", "digest": { "sha-256": "2c26b46b…" } }
  ],
  "fulfills": "sha-256:4be1c1f8…",                      // always in a postreg
  "prev_hash": "sha-256:07ad3b2e…",                     // previous postreg
  "item_id": "R1",                                      // the prereg's item it accounts for
  "status": "reported",                                 // reported | excluded | blocked
  "evidence": [                                         // files that back it (--evidence)
    { "name": "results/r1.json", "hash_alg": "sha-256", "digest": { "sha-256": "7c211433…" },
      "media_type": "application/json", "uri": "https://lab.example/r1" } // declared
  ],
  "anchor": {
    "floor": {                                          // drand (--floor): not before
      "floor_type": "drand",
      "chain_hash": "52db9ba7…",
      "round": 31036100,
      "signature": "8d2f1c3a…",
      "randomness": "c3d4e5f6…"
    }
  },
  "identity": ["lab.example"],                          // free-form list
  "provenance": "reproducible",                         // asserted | reproducible
  "repro_recipe": { "seed": 42, "decode": "greedy", "runtime": "vllm 0.9" },
  "notes": "free-form text or JSON"
}
```

`sig` signs the [DSSE](https://github.com/secure-systems-lab/dsse)
[PAE](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md#signature-definition)
(pre-authentication encoding) of `payloadType` and the body bytes, `DSSEv1 <len> <type>
<len> <body>`, and `dsse` is a standard DSSE envelope that DSSE tooling can verify as it is.
asexec reads only a subset of DSSE envelopes, being stricter than DSSE in four ways: only
standard base64 (DSSE verifiers must also accept URL-safe; asexec departs from that on
purpose), with padding (DSSE is silent), a required `keyid` that must be `sha-256:` of
`pubkey` (optional in DSSE, an unauthenticated hint), and exactly one signature (DSSE allows
several, with a threshold). Verify checks the bytes the file stores, exactly as stored, and never
re-serializes them, so a body written by another tool, spaced or ordered differently,
verifies the same way. The body borrows [in-toto](https://in-toto.io/) field names. A
postreg carries its prereg's `target`, `due` and `declaration`, links back with `fulfills`
(the prereg's ref, the sha-256 of its body bytes, which is also its ceiling `nonce`) and
`prev_hash`, and, from the CLI, adds `provenance` and `repro_recipe`. The ceiling and
`pubkey` sit outside the signed body: the ceiling's nonce is the body's own hash, and
`selfsig` requires the signature's `keyid` to derive from `pubkey`, so a substituted key
fails. The floor sits inside the body, because a value fixed before signing can be signed.
`untrusted` is the one section of the file nothing checks: unsigned, read by no test and
never part of `ref`, so anyone can edit it after signing. (The ceiling's own `midpoint` and
`radius` only restate its signed response, and are not read either.) `verify` shows it, and any field the
format does not define, under headings saying nothing in them was checked (see
[Untrusted](./docs/VERIFICATION.md#untrusted)).

## Keys

`asexec keygen --out lab.key` writes two files:

| File | Contains | Secret? |
|---|---|---|
| `lab.key` | ed25519 private key (hex, **unencrypted**), public key, `keyid` | **Yes.** Written mode `0600` on Unix |
| `lab.key.pub` | public key and `keyid` (`sha-256:` of the public key) | No. It is also in every manifest you sign |

### Impact

A post-registration counts toward a pre-registration only if both were signed with the same
private key. So:

- **Lose the private key** and your unfulfilled commitments can never be fulfilled: they stay
  `open` (or `no-due`, if they declared no `due`), or turn `elapsed-no-postreg` once `due`
  passes. Back up `lab.key` offline (e.g. in an
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
  (or a fallback) at sign-time. `--floor-round` / `--floor-round-file` take a round fetched
  earlier instead, and verify it offline.
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

> **Backward compatibility starts at `0.4.0`.** Until then, this is alpha: any release may
> change the manifest schema, the signed-byte format, the verifier output, or the CLI without
> a migration path — manifests signed by an older build may stop verifying against a newer
> one. (0.2.0 rebalanced the schema in a breaking way by design.) From `0.4.0`, manifests stay
> verifiable: a format change adds a new format version and keeps accepting the old ones.
> Manifests from `0.3.x` are not supported. The verifier support for this is
> [designed](./docs/MULTIVERSION.md) but not built yet.

## License

Apache-2.0.
