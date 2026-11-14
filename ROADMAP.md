# Roadmap

> [!NOTE]
> This file is AI-assisted and is meant as a rough context-setter.
> Treat AI output with due skepticism.

## Milestones

- **M1:** the claim record on the 0.4.0 core format: a P3 claim with a `plan` and an item
  list, one postreg per item, and the `complete` and `order` tests. A run-level study
  test-drives it end to end, recorded as a claim whose items are its runs and ablations.
  The test drive runs on 0.4.0 betas; the format freezes at 0.4.0 → asexec 0.4.0.
- **M2:** a second claim on the same record, the adequacy test below (if assessors
  confirm the need), with the plant-set commitment as the first format version after
  0.4.0; in-toto export; and live export of per-item statuses to a claim-graph display
  → asexec 0.5.0.
- **M3:** a two-sided pilot (the assessor signs its plan and the lab signs the monitor run),
  then lab disclosure promises, self-signed and outsider-extracted side by side
  → asexec 0.6.0.

M1 is designed for P3 and tested on P2. The record's fields take their shapes from the
adequacy test, so it fits the frozen format without a structural change. The run-level
study tests how they work in real use; it doesn't set their design. P2 alone needs
nothing beyond the core: a prereg with its `target`, `declaration` and subjects, and a
postreg with the results.

The adequacy test is the one in Apollo Research's [*Principles for Embedded
Evaluations*](https://www.apolloresearch.ai/blog/principles-for-embedded-evaluations): to
back a universal-negative claim ("models never attempted to evade their monitoring"),
realistic evasion attempts are planted in transcripts and the monitor's catch rate decides
between *Verified* and *Unrefuted*. Today nothing proves the plants and the plan were fixed
before the run, or that no item was dropped. asexec reports per-item statuses; verdicts
belong to the assessor or the display layer, not to asexec.

No registry is planned. asexec-registry is built only if M2 shows that a claim-graph
display can't show records publicly. Anything not needed for M1–M3 moves to 0.7.0 or
later. A test is added only once dogfooding or user feedback shows it is needed.

**Ordering logic:** make the current claims true first; then make every format-breaking
change in one release; then freeze the format at 0.4.0, after the M1 test drive on its
betas. Anything that changes signed bytes or verify-code semantics lands *before* the
freeze, so the format people adopt is the format we can stand behind.
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
- **Every format version ships first as betas** (`0.4.0b1`, `0.4.0b2`, …), and is
  released only after its first user has done an end-to-end dry run on one. Each beta
  writes its own `payloadType` (for example `application/vnd.asexec.0.4.0b1+json`), so a
  release rejects a beta's manifests as an unknown format rather than misreading them.
  Beta manifests are never supported. There is no experimental format: what a release
  ships, it supports.

## Version map

| Version | Scope | Milestone |
|---|---|---|
| 0.3.x | shipped (current 0.3.19; see *History*) | — |
| **0.4.0b*N*** | slim verify surface + every core format change (below); the claim record; the run-level test drive | M1 |
| **0.4.0** | format freeze: wire format + golden vectors become normative | M1 |
| **0.4.x** | patches; no format changes | — |
| **0.5.0** | second claim (the adequacy test, if confirmed) as the second format version; `asexec export --in-toto`; display export | M2 |
| **0.6.0** | two-sided pilot: lab run record; lab disclosure promises (`origin`: `self` \| `extracted`) | M3 |
| **0.7.0+** | everything deferred (below) | — |

## Promise levels

| Level | Promise | Risk it addresses | Served by |
|---|---|---|---|
| P1 | Invocation-level: which model calls count | Cherry-picking the best invocations | Not targeted: too granular, and no public evidence of the risk |
| P2 | Run-level: one run, its parameters and guardrails, declared before it runs | Re-running on the same data, swapping the grader, or tweaking parameters until the result looks good | The core format: prereg (`target`, `declaration`, subjects) and postreg (results) |
| P3 | Claim-level: a broader statement, and the evals or evidence that will decide it, declared up front | Dropping or redefining the evidence that didn't support the claim | The claim record (M1), the adequacy test (M2) |
| P4 | Governance: a recurring disclosure, such as a periodic report | Quietly missing or diluting a promised disclosure | Lab disclosure promises (M3) |

## New properties

Every property is optional unless the table says otherwise. *Required* means `verify`
treats a manifest without it as malformed, so only the frame `verify` needs to read a
manifest at all is required (see *Structure is minimal* under *Standing design
decisions*). An absent property, or an empty list, is structurally fine; whether a manifest
meets a stated bar is up to the tests requested. No property has a default. Body paths
are within the decoded `dsse.payload`; envelope paths start at the file root. "All" means
the property is part of the format at every level.

*Tier* gives each property's trust tier (see *Three trust tiers*): *TrustedTested*, with
the tests that read it; *TrustedDeclared* (signed and shown, never tested); or *Untrusted*
(unsigned, never tested).

**0.4.0: core format**

| Property | Description | Stage | Path | Required | Default | Tier | Lands | Real use | Level |
|---|---|---|---|---|---|---|---|---|---|
| `dsse` | The standard DSSE envelope: the signed body and its signatures | all | envelope | required | none | TrustedTested: `BDR` | 0.4.0 | M1 | all |
| `payloadType` | Selects the format version; covered by the signature | all | `dsse.payloadType` | required | none | TrustedTested: `BDR` | 0.4.0 | M1 | all |
| `payload` | Strict base64 of the exact signed body bytes, which decode to a JSON object | all | `dsse.payload` | required | none | TrustedTested: `BDR` | 0.4.0 | M1 | all |
| `signatures` | Signatures over the body; `BDR` passes only with exactly one valid entry | all | `dsse.signatures[]` | required | none | TrustedTested: `BDR` | 0.4.0 | M1 | all |
| `keyid` | `sha-256:` plus the hash of the signer's public key | all | `dsse.signatures[].keyid` | optional | none | TrustedTested: `BDR`, `chain`, `keyconsist`, `signer` | 0.4.0 | M1 | all |
| `sig` | ed25519 signature over the PAE of the body bytes | all | `dsse.signatures[].sig` | optional | none | TrustedTested: `BDR` | 0.4.0 | M1 | all |
| `pubkey` | The signer's public key, unsigned; `BDR` requires `keyid` to derive from it | all | envelope | optional | none | TrustedTested: `BDR`, `signer` | 0.4.0 | M1 | all |
| `hash_alg` | The algorithm of this entry's digest | all | `subject[].hash_alg` | optional | none | TrustedTested: `content` | 0.4.0 | M1 | all |
| `untrusted` | Metadata that nothing checks: unsigned, never tested, never part of `ref` | all | envelope | optional | none | Untrusted | 0.4.0 | M1 | all |
| `asexec_version` | The asexec release that wrote the manifest, for diagnostics only | all | `untrusted.asexec_version` | optional | none | Untrusted | 0.4.0 | M1 | all |

Changed in 0.4.0: `payloadType` and `payload` move into `dsse`; `signature` is replaced
by `dsse.signatures[]` and `pubkey`; `ceiling` moves to the wrapper; body-level `hash_alg`
is no longer read; `subject[].name` becomes a relative path to one file.

**0.4.0: the claim record**

| Property | Description | Stage | Path | Required | Default | Tier | Lands | Real use | Level |
|---|---|---|---|---|---|---|---|---|---|
| `plan` | The plan the claim will be tested against, by digest; asexec never parses it | prereg | `plan` | optional | none | TrustedTested: `content` | 0.4.0 | M1 | P2, P3 |
| `name` | The plan document's relative path, resolved under `--artifacts` | prereg | `plan.name` | optional | none | TrustedTested: `content` | 0.4.0 | M1 | P2, P3 |
| `digest` | The plan document's digest, in the subject entry's form | prereg | `plan.digest` | optional | none | TrustedTested: `content` | 0.4.0 | M1 | P2, P3 |
| `hash_alg` | The algorithm of `plan.digest` | prereg | `plan.hash_alg` | optional | none | TrustedTested: `content` | 0.4.0 | M1 | P2, P3 |
| `media_type` | The plan document's media type | prereg | `plan.media_type` | optional | none | TrustedDeclared | 0.4.0 | M1 | P2, P3 |
| `label` | A human-readable name for the plan | prereg | `plan.label` | optional | none | TrustedDeclared | 0.4.0 | M1 | P2, P3 |
| `items` | What the claim commits to deliver, each accounted for by a postreg | prereg | `items[]` | optional | none | TrustedTested: `complete` | 0.4.0 | M1 | P3 |
| `id` | The item's identifier, matched by a postreg's `item_id` | prereg | `items[].id` | optional | none | TrustedTested: `complete` | 0.4.0 | M1 | P3 |
| `kind` | Free-text kind (a run, an ablation, a search) | prereg | `items[].kind` | optional | none | TrustedDeclared | 0.4.0 | M1 | P3 |
| `item_id` | Which committed item this postreg accounts for | postreg | `item_id` | optional | none | TrustedTested: `complete` | 0.4.0 | M1 | P3 |
| `status` | `reported` \| `excluded` \| `blocked`: what happened to the item | postreg | `status` | optional | none | TrustedTested: `complete` | 0.4.0 | M1 | P3 |
| `evidence` | Digests of what backs this postreg | postreg | `evidence[]` | optional | none | TrustedTested: `content` | 0.4.0 | M1 | P2, P3 |
| `name` | This evidence's relative path, resolved under `--artifacts` | postreg | `evidence[].name` | optional | none | TrustedTested: `content` | 0.4.0 | M1 | P2, P3 |
| `digest` | This evidence's digest, in the subject entry's form | postreg | `evidence[].digest` | optional | none | TrustedTested: `content` | 0.4.0 | M1 | P2, P3 |
| `hash_alg` | The algorithm of this entry's digest | postreg | `evidence[].hash_alg` | optional | none | TrustedTested: `content` | 0.4.0 | M1 | P2, P3 |
| `media_type` | This evidence's media type | postreg | `evidence[].media_type` | optional | none | TrustedDeclared | 0.4.0 | M1 | P2, P3 |
| `uri` | Where this evidence can be fetched, if anywhere | postreg | `evidence[].uri` | optional | none | TrustedDeclared | 0.4.0 | M1 | P2, P3 |

`content` checks `plan` and each `evidence` entry the way it checks a subject entry: by
`name` under `--artifacts`, against `digest` under the entry's own `hash_alg`.

**0.5.0 and later**

| Property | Description | Stage | Path | Required | Default | Tier | Lands | Real use | Level |
|---|---|---|---|---|---|---|---|---|---|
| `plants` | A commitment to a hidden set of planted counterexamples | prereg | `commitments.plants` | optional | none | TrustedTested: a reveal test (not named) | 0.5.0 | M2 | P3 |
| `alg` | The commitment's encoding (spelling not decided) | prereg | `commitments.plants.alg` | optional | none | TrustedTested: a reveal test | 0.5.0 | M2 | P3 |
| `root` | The root over the plants' salted hashes | prereg | `commitments.plants.root` | optional | none | TrustedTested: a reveal test | 0.5.0 | M2 | P3 |
| `count` | How many plants are committed | prereg | `commitments.plants.count` | optional | none | TrustedTested: a reveal test | 0.5.0 | M2 | P3 |
| `presented_by` | Who presents the claim; checked against the key list's roles | prereg | `presented_by` | optional | none | TrustedTested: `signer`, with the key list | 0.5.0 | M2 | P3 |
| Lab run record: a new `phase` value, not decided; may be outside asexec scope | A lab's own signed record of its monitor run | run record | `phase` | optional | none | TrustedTested: `order`, extended | 0.6.0 | M3 | P3 |
| `attests` | Part of the lab run record: the `ref` of the prereg the run was performed under | run record | `attests` | optional | none | TrustedTested: `order`, extended | 0.6.0 | M3 | P3 |
| `origin` | `self` \| `extracted`: whether the promiser or an outsider wrote the record | prereg | `origin` | optional | none | TrustedDeclared | 0.6.0 | M3 | P4 |

Not properties: the reveal sample is chosen by a rule, not a field; and the role key list
is a file beside the manifests.

**Existing properties, by tier (from 0.4.0)**

| Property | Tier |
|---|---|
| `phase` | TrustedTested: `chain`, `keyconsist`, `complete` (which manifests join a commitment) |
| `fulfills` | TrustedTested: `chain`, `keyconsist`, `complete` |
| `prev_hash` | TrustedTested: `chain` |
| `due` | TrustedTested: `timely`, `complete` |
| `subject`, `subject[].name`, `subject[].digest` | TrustedTested: `content` |
| `anchor`, `anchor.floor` and its fields | TrustedTested: `floor`, `order` |
| `ceiling` and its fields (envelope) | TrustedTested: `ceiling`, `order`, `timely`, `complete` |
| `schema_id`, `predicateType`, `target`, `declaration`, `identity`, `provenance`, `repro_recipe`, `notes` | TrustedDeclared |

**Tests**

| Test | Checks | Lands | Real use | Level |
|---|---|---|---|---|
| `complete` | For each prereg with at least one item: every item has a counted postreg with its `item_id`, a `status` of `reported`, `excluded` or `blocked`, and a ceiling at or before `due`. A prereg whose item `id`s repeat fails. A prereg without items isn't examined | 0.4.0 | M1 | P3 |
| `order` | The prereg's ceiling precedes the floor of each of its counted postregs | 0.4.0 | M1 | P2, P3 |
| `order`, extended | The plant-set commitment's ceiling precedes the lab run record's floor | 0.6.0 | M3 | P3 |

---

## 0.4.0 — M1: Slim verify surface and format changes

**Format**

- DSSE envelope: `payload` is base64 of the exact signed bytes; the PAE prefix is
  `DSSEv1`; `signatures: [...]` (one entry for now). The verifier checks the stored
  bytes and never re-canonicalizes. `ref` = digest of the payload bytes.
- The file is an asexec wrapper around that standard envelope: `dsse`, plus the unsigned
  `ceiling`, `pubkey` and `untrusted` (see *Wrapper* below).
- `untrusted`: a section for metadata nothing checks, starting with `asexec_version`.
- `MANIFEST_PREDICATE_TYPE` → a URL the project controls.
- Body field `schema_version` is now `schema_id`, since its value has no version in it.
  (Done ahead of 0.4.0.)
- `dsse.payloadType` selects the format version, and unknown values fail `BDR`
  ([`docs/MULTIVERSION.md`](docs/MULTIVERSION.md)).
- `hash_alg` moves into each subject entry. A body-level `hash_alg` is no longer read, and is
  shown as unverified content like any unknown field.
- Subjects are an explicit list of files, each hashed exactly as listed, because directory
  hash v1 is ambiguous and skips what it can't encode.
  - An entry's `name` is the relative path as given (normalized, `/`-separated), not its
    basename, so two files with the same basename stay distinct. Signing refuses duplicate
    names, and `content` fails them.
  - Signing refuses a directory, and `content` fails one, so a hand-built manifest can't
    rely on the old hash. To commit to a tree, list its files, or pack it (a tar, for
    example) and list the archive. Remove `hash_dir`.
  - A listed symlink is hashed as the bytes read through it; `content` already fails one
    that resolves outside `--artifacts`.
  - The README examples change to match. Nothing is kept for compatibility with
    directory subjects.
- The claim record: `plan`, `items`, and per-postreg `item_id`, `status` and `evidence`
  (see *New properties*).
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
  `signatures` list keeps one entry: a second party signs its own record (see *0.6.0*),
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
  "pubkey": "…",                                 // unsigned; must derive signatures[0].keyid
  "untrusted": { "asexec_version": "0.4.0" }     // optional, unsigned, never tested
}
```

Rules that follow:

- Decode `payload` with strict base64, so each set of body bytes has one spelling.
- Read every field the tests check from the verified body bytes, never from another copy in
  the file, and never from `untrusted`.
- Keep rejecting duplicate JSON keys in the decoded body: parsers disagree on which value
  wins, so two verifiers could read different fields from the same signed bytes. The
  decoded body is held to the same JSON rules as the file, nesting limit included.

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
- `untrusted` is neither signed nor bound: anyone can edit it after signing. That is
  what it is for. Unsigned isn't the same as untrusted, though: `ceiling` and `pubkey` are
  unsigned but checked, by the witness's signature and by `keyid`. `untrusted` is the one
  part of the file that nothing checks.

**Verify**

- `signer`: `--signer` / `--trusted-keys <file>`.
- `timely`: postreg ceiling ≤ prereg `due`.
- New commitment state `no-due`, separate from `open`. This changes what `open` means, but
  the code grammar stays `asexec-verify/1`, because the bump rule starts at `0.4.0`.
- `complete` and `order` (see *New properties*).
- Malformed means only what stops `verify` reading a manifest: not valid JSON, nested too
  deep, a duplicate key, or a missing frame (`dsse` with `payloadType`, a `payload` that
  decodes to a JSON object, and a `signatures` list). Everything else is judged by tests.
- `--json`: a stable report (the claim-graph export reads it).
- Unknown signed fields are shown as unverified content, never dropped.
- `untrusted` is printed under its own heading saying nothing in it was checked. No test
  reads it, and it never affects `ref` or the verify code.

**Docs:** `docs/VERIFICATION.md` gains a *TrustedDeclared* list (signed properties that are
shown but never tested) and an *Untrusted* section.

**Tests:** golden vectors, regenerated for the DSSE format, plus tests for the items
above. A tier check: every property the signing models can write appears in
`docs/VERIFICATION.md`: under some test's *Examines* (*TrustedTested*), in
*TrustedDeclared*, or in *Untrusted*. A property nothing accounts for fails CI. No broader
test program.

**Release:** betas first (see *0.4.0 betas* below). Once `0.4.0` is on PyPI, yank every
`0.3.x` release and every `0.4.0` beta, so a plain `pip install asexec` never picks
unsupported code. Yank rather than delete, because deletion is permanent and gains
nothing. Yank reason: "pre-0.4.0, unsupported; use >=0.4.0".

## 0.4.0 betas — M1: The claim record, test-driven

One run-level study, end to end: a matrix of runs (for example, models × harnesses, so
their effects can be told apart), plus ablations. It is recorded as a claim: the prereg
carries the study's `plan` and lists each run and ablation in `items`, and each run gets a
postreg with its `item_id`, `status` and `evidence`. The study integrates against a 0.4.0
beta.

The claim record's fields (see *New properties*) are in the first beta, in the adequacy
test's shapes. The 0.3.19 run of the adequacy test already shows the gaps they close: an
item silently dropped still showed `[FULFILLED]`, and plants committed after the run
couldn't be checked.

**Release gate.** 0.4.0 is released after two dry runs on a beta, before any run meant for
publication:
1. The run-level study's first end-to-end dry run.
2. The adequacy-test example, re-run on the beta format: a check that the claim record
   still fits P3.

The integration (an adapter from the study's runner to asexec) lives in the study's repo,
not here. Where it hooks in waits on the study's choice of runner.

Each run fetches a drand round when it starts and uses it (for example as its seed), and
its postreg carries that round as its floor. Today `--floor` fetches the latest round at
signing, so signing needs a way to pass in a round fetched earlier. `order` bounds a run
only as tightly as the run's use of that round: a round the run merely records proves
nothing about when the run started. Using it as a seed lets a re-execution check it.

**Open for the test drive:** one item per repetition, or a declared count per cell. This
closes the gap of a cell run n times with only the best run reported. If it needs a
property, it goes into a later beta.

**Tests:** a fault suite, each fault with its expected code: an item silently dropped; a
late item; a silent amendment (an ablation redefined after the results); a run whose
floor precedes the prereg's ceiling; a record signed with a key not in `--trusted-keys`. Plus one
synthetic worked example in the same shape, a small matrix with ablations, through
commit, run and verify.

## 0.5.0 — M2: Second claim

- A second claim on the same record: the commit-reveal adequacy test (below), if
  assessors confirm the need. If they don't, the next user's claim.
- The fields it adds make the first format version after 0.4.0, so the multi-version
  verifier ([`docs/MULTIVERSION.md`](docs/MULTIVERSION.md), steps 2 to 4) lands first. Like
  0.4.0, it ships as betas, and a field is released only once a dry run has exercised it.
- `asexec export --in-toto`.
- Live export of per-item statuses (`verify --json`) to a claim-graph display.
  asexec-registry is built only if that display can't show records publicly.

**The adequacy test.** The assessor commits, before access and before the lab's monitor
runs, to its plan and a plant set; the lab's monitor runs over transcripts with the plants
in them; the assessor then accounts for every item. Beyond the claim record, it needs:

- A plant-set commitment (salted-hash root and count) and `presented_by` in the prereg.
- Plant-set root: an unambiguous encoding (length-prefixed leaves, or a Merkle tree with
  domain separation), specified before anyone commits to a root. Directory hash v1 is the
  counterexample.
- Reveal sample: a drand round issued after the run selects which plants are revealed, so
  the assessor can't pick the published sample.
- Key list with roles at a well-known path: a file convention, not a registry. It feeds
  `signer`, and `presented_by` must match it; otherwise `presented_by` is an unchecked
  self-label.
- Faults: plants swapped after the run (0.3.19 catches only this one), and a dropped
  adequacy item.

Until the lab signs its own run record (M3), the adequacy test is one-sided: it catches
swapped plants and dropped items, but not plants committed after the monitor ran.

**Open until assessors answer:** whether adequacy tests use planted counterexamples today
(how many, and whether the lab sees them before the run); whether the lab can sign the
run; whether publishing the plant set teaches evasion, and whether a count plus a random
sample is enough.

## 0.6.0 — M3: Two-sided pilot, then lab promises

- Pilot with one assessor and one lab: the assessor signs its plan, the lab signs the
  monitor run.
- Lab run record (a new `phase` value, not decided; may be outside asexec scope): its own
  envelope, signed by the lab's key, with `attests: <prereg ref>`, the run's output
  digest, and its own floor and ceiling. It is a new record kind, not a
  postreg, so the counting rule never puts it under the assessor's commitment, and the lab
  can't block the assessor's report by withholding a signature. The adequacy item's
  postreg points at it by `ref`. The key list gains the lab role.
- Verify: `order` extended to the plant-set commitment's ceiling preceding the lab run
  record's floor, and the lab run record validly signed by a key the key list gives the
  lab role. Fault: plants committed after the run.
- Lab disclosure promises (P4), self-signed and outsider-extracted side by side. New
  optional body field `origin`: `self` | `extracted`. Extracted records carry the source
  snapshot as a subject (digest + URL) and put the quoted passage in `notes`. Not
  `provenance`, which already means `asserted` | `reproducible`.

## Deferred to 0.7.0+

- `continuity` + subject `role`: matching runs to their inputs; the test drive starts without it.
- `final` / `expected_runs` for tail truncation beyond a declared item list: `complete` would cover the test drive, whose items are listed up front.
- `--trust-roots`: the pinned drand and Roughtime set is enough until readers ask to choose their own.
- [JCS (RFC 8785)](https://www.rfc-editor.org/rfc/rfc8785) canonicalization: DSSE verifies the stored bytes, so canonical form no longer matters for verification (worth adopting for multiple writers to produce byte-identical bodies, and therefore identical refs, from the same data).
- Phase 1 invariant catalog, property/mutation testing, extra CI matrix: tests are added only when dogfooding or feedback shows a need.
- Phase 3 dependency reduction (pydantic, blake3, BLS vendoring, Actions pinning): worthwhile, but not needed for M1–M3.
- Full normative `SPEC.md`: 0.4.0 freezes the wire format and vectors; a complete spec can follow adoption.
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
- **Only verifiable claims earn a test.** A self-declaration (e.g. the removed
  `has_run_already` field) is *TrustedDeclared*: listed as such in
  `docs/VERIFICATION.md` and shown as unchecked in the report, so sitting beside tested
  fields never implies it was checked.
- **Floor and ceiling generalize along disjoint axes.** A floor is a public
  beacon (fixed at T, independent of the manifest, embeddable): drand, NIST,
  block hashes. A ceiling is a witness that ingested `ref(payload)` (attached
  after signing, at the envelope): Roughtime, OTS, cosigners. A beacon cannot
  be a ceiling and a witness cannot be a floor.
- **Subjects are explicit.** A subject lists files, each hashed exactly as listed. No
  directory hash infers what a tree contains, so a manifest claims only what it names.
- **Three trust tiers.** Every property is exactly one of:
  - *TrustedTested*: listed under a test's *Examines* in `docs/VERIFICATION.md`. Most
    are signed; the envelope's `signatures`, `pubkey` and `ceiling` aren't, but tests
    bind them to the signed body.
  - *TrustedDeclared*: signed and shown, never tested; what was promised, which no test
    judges yet. "Trusted" here means attributable to the signer, not true. The long-term
    goal is to shrink this tier: a declaration that gains a test moves to
    *TrustedTested*. Until then, every member is listed explicitly.
  - *Untrusted*: in the unsigned `untrusted` section, never tested, never part of `ref`.

  A new property names the test that reads it, or joins the *TrustedDeclared* list. The
  manifest stays organized by meaning, not by test:
  tests and properties are many-to-many, and keying the format by test would make every
  new test a format change.
- **Structure is minimal; tests set the bar.** `verify` treats a manifest as malformed
  only when it can't read it. Every property past that frame is optional: absent, or an
  empty list, is structurally fine, and no property is conditional on another. Whether
  manifests meet a stated bar is what `verify --tests` decides. Signing may still refuse to
  write a manifest without, say, a `target`; that is the signer's choice, not a rule of the
  format.
- **Dependencies sit with what they qualify.** A property's meaning comes from its own
  object: each digest carries its own `hash_alg`, rather than pointing at a value
  elsewhere in the manifest. Repetition is preferred to cross-references.
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
