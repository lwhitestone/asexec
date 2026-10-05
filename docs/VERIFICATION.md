# Verification catalog

Reference for every test accepted by `asexec verify --tests`. Authoritative implementation:
`src/asexec/verifier.py`. Describes 0.3.15.

```
asexec verify <manifest|dir>... --tests <name>[,<name>...] [--artifacts <dir>]
```

## Conventions

**Property paths.** A manifest file is an envelope with three top-level members: `payload`
(the signed body), `signature`, and optionally `ceiling`. Properties are written as dotted
paths from the envelope root, e.g. `payload.anchor.floor.round`, `signature.keyid`,
`ceiling.nonce`. `[]` denotes array elements: `payload.subject[].name`.

**Roles.** A *prereg* is a manifest with `payload.phase == "prereg"`; a *postreg* has
`payload.phase == "postreg"`. `ref(m)` is `sha-256:<hex>` over the canonical bytes of
`m.payload`.

**Result.** Each requested test yields exactly one of `PASS` / `FAIL`. There is no third
value and no error state. Malformed input is never an exception: it is a failure of the
tests that examine it.

**Code.** One token `<name>=<RESULT>` per requested test, sorted by name, after the prefix
`asexec-verify/1`. Exit status is `0` if every token is `PASS`, else `2`.

**Run rules.**
- `--tests` is required, must name only catalog tests, and must include `BDR`.
- A test passes iff **all** of its *Passes when all* requirements hold for **every** manifest
  or commitment that has the *Examines* properties, and at least one such manifest or
  commitment exists.
- (\*) If no provided manifest or commitment has the examined properties, the test is
  vacuous and is judged `FAIL`. One that lacks them is not examined and cannot fail the
  test; it also does not count toward passing.
- Verification is offline.
- A file that cannot be read, is not a JSON object, or contains a duplicate JSON key at any
  level is malformed: it fails `BDR`, and no other test examines it.

## Summary

| Test | Examines (\*) | Passes when all |
|---|---|---|
| [`BDR`](#bdr) | `payload`<br>`signature.pubkey`<br>`signature.sig`<br>`signature.keyid` | file is well-formed JSON<br>`signature.sig` verifies over `payload`<br>`signature.keyid` derives from `signature.pubkey` |
| [`ceiling`](#ceiling) | `ceiling.ceiling_type`<br>`ceiling.nonce`<br>`ceiling.witness_id`<br>`ceiling.pubkey`<br>`ceiling.response`<br>`payload` | `ceiling.ceiling_type` is `roughtime`<br>`ceiling.nonce` equals `ref(payload)`<br>`ceiling.witness_id` has a pinned key<br>`ceiling.pubkey`, if present, equals the pinned key<br>`ceiling.response` verifies against the pinned key |
| [`chain`](#chain) | `payload.phase`<br>`payload.fulfills`<br>`payload.prev_hash`<br>`signature.pubkey`<br>`signature.sig`<br>`signature.keyid` | exactly one counted postreg has no `payload.prev_hash`<br>every other `payload.prev_hash` is the `ref` of a counted postreg<br>no `ref` is the `payload.prev_hash` of more than one counted postreg |
| [`content`](#content) | `payload.subject[].name`<br>`payload.subject[].digest`<br>`payload.hash_alg`<br>`--artifacts` | each `subject[]` entry is well-formed<br>`payload.hash_alg` is available<br>`name` resolves inside `--artifacts`<br>the artifact exists and is readable<br>recomputed digest equals `digest[hash_alg]` |
| [`floor`](#floor) | `payload.anchor.floor.floor_type`<br>`payload.anchor.floor.chain_hash`<br>`payload.anchor.floor.round`<br>`payload.anchor.floor.signature`<br>`payload.anchor.floor.randomness` | `floor_type` is `drand`<br>`chain_hash` is pinned<br>`randomness`, if present, equals `sha256(signature)`<br>`signature` BLS-verifies for `round` under the pinned key |
| [`keyconsist`](#keyconsist) | `payload.phase`<br>`payload.fulfills`<br>`signature.pubkey`<br>`signature.sig`<br>`signature.keyid` | every validly signed postreg referencing the prereg has the prereg's `signature.keyid` |

(\*) per [Run rules](#conventions): examined properties absent from every manifest or
commitment make the test vacuous, judged `FAIL`.

---

## Tests

### `BDR`

Bedrock. Mandatory in every run.

**Examines (\*)**
- `payload`
- `signature.pubkey`
- `signature.sig`
- `signature.keyid`

**Passes when all**
1. The file is a JSON object with no duplicate keys, containing `payload` and `signature`.
2. `signature.pubkey` and `signature.sig` are hex and `signature.sig` is a valid ed25519
   signature by `signature.pubkey` over the PAE signing input of the canonical bytes of
   `payload`.
3. `signature.keyid == "sha-256:" + sha256(bytes.fromhex(signature.pubkey)).hexdigest()`.

**Vacuous reason:** `no manifests to verify`.

**Does not establish:** who signed (internal consistency only); that `payload` is a
well-formed asexec body (any signed JSON passes).

---

### `ceiling`

Roughtime witness: the manifest was created no later than time T.

**Examines (\*)**
- `ceiling.ceiling_type`
- `ceiling.nonce`
- `ceiling.witness_id`
- `ceiling.pubkey`
- `ceiling.response`
- `payload`

**Passes when all**
1. `ceiling.ceiling_type == "roughtime"`.
2. `ceiling.nonce` equals the hex of `ref(payload)`.
3. `ceiling.witness_id` names a witness whose long-term key is pinned in the verifier. The
   key is never taken from the file.
4. If `ceiling.pubkey` is present, it equals the pinned long-term key.
5. `ceiling.response` is a valid IETF-Roughtime response, in which:
   - `CERT.SIG` verifies `DELE` under the pinned long-term key;
   - `SIG` verifies `SREP` under `DELE.PUBK`;
   - the Merkle path (`PATH`, `INDX`) roots `ceiling.nonce` at `SREP.ROOT`;
   - `DELE.MINT <= SREP.MIDP <= DELE.MAXT`.

**Vacuous reason:** `requested but no manifest carries a ceiling witness`.

**Not examined:** a manifest that is malformed (see Run rules).

**Trust class:** signature-witness. Passing means the named server signed that time; it is
not proof-of-work. Interop is proven for `int08h-Roughtime` and expected, not proven, for
the other pinned servers.

---

### `chain`

Linearity of a commitment's postreg chain.

A postreg is **counted** for a prereg if it meets the [counting rule](#counting-rule).

**Examines (\*)**
- `payload.phase`
- `payload.fulfills`
- `payload.prev_hash`
- `signature.pubkey`
- `signature.sig`
- `signature.keyid`

(The three `signature.*` properties decide only whether a postreg is counted.)

**Passes when all** (for each prereg that has at least one counted postreg)
1. Exactly one counted postreg has no `payload.prev_hash`.
2. Every other counted postreg's `payload.prev_hash` equals the `ref` of a counted postreg
   of the same prereg (no gaps).
3. No `ref` appears as `payload.prev_hash` of more than one counted postreg (no forks).

**Vacuous reason:** `requested but no commitment has receipts to chain-check`.

**Does not establish:** completeness. Dropping the last postreg(s) of a chain is not
detectable.

---

### `content`

Subject digests recomputed from the original artifacts.

**Examines (\*)**
- `payload.subject[].name`
- `payload.subject[].digest`
- `payload.hash_alg` (default `sha-256` if absent)
- `--artifacts`

**Passes when all** (for each `payload.subject[]` entry of each manifest that has one)
1. `name` is a string and `digest[hash_alg]` is a string.
2. `hash_alg` is available in this install: `sha-256` always, `blake3` only if installed.
3. `name` (trailing `/` removed) resolved with symlinks against `--artifacts` is the
   `--artifacts` directory or beneath it. `..` components, absolute names, and symlinks
   that point outside fail here.
4. The resolved path exists.
5. The resolved path is readable.
6. The recomputed digest of the file or directory under `hash_alg` equals
   `digest[hash_alg]`.

**Vacuous reason:** `requested but no content could be checked (need --artifacts and a
manifest with a subject)`.

**Entry failure reasons** (shown per entry in the report): `malformed subject entry`,
`algorithm unavailable: <alg>`, `path resolves outside --artifacts`, `artifact not found`,
`artifact unreadable: <error>`, or a digest mismatch with `expected`/`actual`.

**Not examined:** a manifest that is malformed; any manifest when `--artifacts` is absent.

**Does not establish:** provenance. A match shows the artifact was not altered, not that it
is the output of the named harness and model.

---

### `floor`

drand beacon: the manifest was created no earlier than time T.

**Examines (\*)**
- `payload.anchor.floor.floor_type`
- `payload.anchor.floor.chain_hash`
- `payload.anchor.floor.round`
- `payload.anchor.floor.signature`
- `payload.anchor.floor.randomness`

**Passes when all**
1. `payload.anchor.floor` is an object and `floor_type == "drand"`.
2. `chain_hash` (default: the pinned quicknet chain) is a chain the verifier pins.
3. `round` is an integer and `signature` is hex.
4. If `randomness` is present, it equals `sha256(signature)` in hex.
5. `signature` is a valid BLS12-381 signature over `sha256(round as 8-byte big-endian)`
   under the pinned group public key.

**Vacuous reason:** `requested but no manifest carries an anchor.floor`.

**Not examined:** a manifest that is malformed.

**Does not establish:** that the pre-registration preceded the run. A floor bounds
freshness (anti-precomputation), not backdating.

---

### `keyconsist`

Whether a prereg's postregs were signed by the prereg's own key.

**Examines (\*)**
- `payload.phase`
- `payload.fulfills`
- `signature.pubkey`
- `signature.sig`
- `signature.keyid`

**Passes when all** (for each prereg referenced by at least one postreg, counted or not)
1. Every postreg whose `payload.fulfills` equals `ref(prereg)` and whose signature is valid
   (the `BDR` signature and keyid conditions) has `signature.keyid` equal to the
   prereg's `signature.keyid`.

A postreg with an invalid signature is not judged here (it fails `BDR`).

**Vacuous reason:** `requested but no commitment has receipts to key-check`.

---

## Counting rule

A postreg `P` **counts** toward prereg `R` iff all hold:
1. `P.payload.phase == "postreg"` and `P.payload.fulfills == ref(R)`.
2. `P` meets the `BDR` signature and keyid conditions.
3. `P.signature.keyid == R.signature.keyid`.

A postreg that references `R` but fails 2 or 3 is **rejected**. It is listed under `R` with
its reason (`invalid signature`, or `signed by a different key than the pre-registration`),
and is never counted toward fulfillment or `chain`.

## Commitment states

Rendered in the human report, one per prereg. Never part of the verify code.

| State | Condition |
|---|---|
| `fulfilled` | at least one counted postreg |
| `open` | no counted postreg, and `payload.due` is absent or in the future |
| `elapsed-no-receipt` | no counted postreg, and `payload.due` is at or before now |
| `invalid-due` | no counted postreg, and `payload.due` is present but not a parseable ISO-8601 string |
| `notarization-only` | (postreg-side) a postreg whose `payload.fulfills` matches no provided prereg |

A `payload.due` without a UTC offset or `Z` is read as UTC, never in the verifier's local
timezone, and is flagged in the report. Timeliness (a postreg created before `due`) is not
checked in this version.

## Not in this version

`signer`, `continuity`, `order`, `timely`, `frame` and `complete` are planned for 0.4.0
(see [`ROADMAP.md`](../ROADMAP.md)). Adding a test name never changes the meaning of an
existing code. Changing the documented meaning of an existing name bumps the code grammar
(`asexec-verify/N`).

The statements a passing code does not support are printed with every `verify` run and
summarized in the [README](../README.md#what-does-asexec-prove).
