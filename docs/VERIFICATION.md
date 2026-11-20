# Verification catalog

Reference for every test accepted by `asexec verify --tests`. Authoritative implementation:
`src/asexec/verifier.py`. Structural requirements (types and shapes) are implemented as the
input models in `src/asexec/models.py`; everything else, and every verdict, is in the
verifier and the modules it calls.

```
asexec verify <manifest|dir>... --tests <name>[,<name>...] [--artifacts <dir>]
```

## Conventions

**Property paths.** A manifest file is an envelope with four top-level members:
`payloadType` (its format), `payload` (the signed body), `signature`, and optionally
`ceiling`. Properties are written as dotted paths from the envelope root, e.g.
`payload.anchor.floor.round`, `signature.keyid`, `ceiling.nonce`. `[]` denotes array
elements: `payload.subject[].name`.

**Formats.** A file's `payloadType` names its format, and every test reads the file under
that format's rules only, never another format's. This release reads one format,
`application/vnd.asexec.v1+json`, and this document gives its rules: the PAE signing input
starts `asexec-PAE/v1`, `ref` and `keyid` start `sha-256:`, and a subject with no
`payload.hash_alg` is read as `sha-256`. A file whose `payloadType` names any other format
fails [`format`](#format) #3.

**Phases.** A manifest's phase is its `payload.phase`. A *prereg* is a manifest with
`payload.phase == "prereg"`; a *postreg* has `payload.phase == "postreg"`. `ref(m)` is
`sha-256:<hex>` over the canonical bytes of `m.payload`.

**Hex.** A value required to be hex is a string that `bytes.fromhex` accepts: an even number
of hex digits in either case, with ASCII whitespace allowed around and between bytes.
Content #6 compares the bytes a digest's hex decodes to, so any such spelling matches.
Ceiling #2 and floor #4 compare exactly against the lowercase hex of the digest.

**JSON.** Valid JSON is what Python's `json.load` accepts (so `NaN` and `Infinity` are
allowed), nested at most 64 deep: each array or object adds a level, and the outermost
object is level 1. A deeper file is malformed, so every supported Python version reads a
file the same way.

**Result.** Each requested test yields exactly one of `PASS` / `FAIL`. There is no third
value and no error state. Malformed input is never an exception: it is a failure of the
tests that examine it.

**Code.** One token `<name>=<RESULT>` per requested test, sorted by name, after the prefix
`asexec-verify/1`. Exit status is `0` if every token is `PASS`, else `2`. A usage error
(see Run rules) exits `64`, prints no code and verifies nothing. Every exit status is listed
in the README's [Exit status](../README.md#exit-status).

**Run rules.**
- `--tests` is required, must name only catalog tests, and must include both
  [`format`](#format) and [`selfsig`](#selfsig). Otherwise the run is a usage error: it
  exits `64` and nothing is verified.
- A test passes iff **all** of its *Passes when all* requirements hold for **every** manifest
  or commitment that has the *Examines* properties, and at least one such manifest or
  commitment exists.
- A property is **absent** iff its key is missing or its value is `null`. Any other value,
  including `{}`, `[]`, `""`, `false` and `0`, is present. A property whose path runs
  through a present non-object (e.g. `payload.anchor` is `[]`) is present, and malformed.
- (\*) A test is **empty** if no provided manifest or commitment has the properties it
  examines. An empty test has nothing to examine and is judged `FAIL`. Each test's *When
  empty* line gives the exact condition and the reason the report shows. A manifest or
  commitment that lacks the examined properties is not examined and cannot fail the test;
  it also does not count toward passing.
- Verification is offline.
- A file is **malformed** if it cannot be read, is not a JSON object, nests more than 64
  deep, contains a duplicate JSON key at any level, lacks an object `payload`, a string
  `payloadType` or an object `signature`, has a `payload` with no canonical bytes (a string
  in it, key or value, holds an unpaired surrogate escape such as `"\ud800"`, which has no
  UTF-8 encoding), or its `signature.pubkey` and `signature.sig` are not both hex
  ([`format`](#format) #1 and #2). A file is of an **unknown format** if its `payloadType`
  is a string that names no format this release reads ([`format`](#format) #3). A readable
  JSON object with such a `payloadType` is judged by #3 instead of the rest of #1 and #2,
  so it is of an unknown format and never malformed, whatever else it holds.
- A file that is malformed or of an unknown format fails [`format`](#format), and no other
  test examines it, `selfsig` included. It takes no part in any commitment: as a prereg it
  is no commitment, and as a postreg it is neither counted nor rejected (see
  [Matching postregs to commitments](#matching-postregs-to-commitments)).

## Output

`asexec verify` prints a report for people to read, then the code, then when the run
happened. Only the code line and the exit status are stable to script against. The
report's wording may change, except for the reasons this document lists.

| Block | Printed | Shows |
|---|---|---|
| `=== manifests ===` | always | One line per file: `✓` if it passes `format` and meets `selfsig`'s conditions (else `✗`), the path, `payload.phase` and `signature.keyid`. Indented beneath: why a file fails `format` (`format: malformed: …`, or the [reason](#format) for an unknown format), and one line each for a floor, a ceiling and content hashes when the manifest has them. |
| `=== commitments ===` | always | One entry per commitment (a prereg's `ref` and signer): its [state](#commitment-states), `ref`, signer keyid, `due`, the number of counted postregs, a chain problem if any, and each rejected postreg with its reason. |
| `=== notarization-only … ===` | if any | Each [notarization-only](#matching-postregs-to-commitments) postreg: one whose `payload.fulfills` matches no provided prereg. |
| `=== tests ===` | always | One line per requested test: its result and a short reason. |
| `=== ceiling trust … ===` | if a ceiling verified | Which witness you are trusting, and for what time. |
| code | always | The [code](#conventions). |
| `Checked at <time>` | always | When the run happened, in UTC to the second: the moment commitment states were judged against. Not part of the code. |

Exit status is `0` if every token in the code is `PASS`, else `2`; a usage error exits `64`
with no report. Commitment states never affect either: a run can show `ELAPSED-NO-POSTREG`
and still exit `0`.

**Example.** The three files from the [`chain` example](#chain), checked with
`format`, `selfsig`, `chain` and `keyconsist`. Hashes are shortened with `…`.

```console
$ asexec verify prereg.json postreg-1.json postreg-2.json --tests format,selfsig,chain,keyconsist
=== manifests ===
✓ prereg.json  [prereg]  keyid=sha-256:7bc19c1d…
✓ postreg-1.json  [postreg]  keyid=sha-256:7bc19c1d…
✓ postreg-2.json  [postreg]  keyid=sha-256:7bc19c1d…

=== commitments ===
  [FULFILLED] prereg sha-256:b17107d0…
    signer       : sha-256:7bc19c1d…
    due          : (none declared)
    postregs     : 2

=== tests ===
  ✓ chain=PASS  (1/1 chain(s) ok)
  ✓ format=PASS  (3/3 manifest(s) ok)
  ✓ keyconsist=PASS  (1/1 commitment(s) ok)
  ✓ selfsig=PASS  (3/3 manifest(s) ok)

asexec-verify/1 chain=PASS format=PASS keyconsist=PASS selfsig=PASS
Checked at 2026-12-31T23:59:59Z
```

## Summary

| Test | Examines (\*) | Passes when all |
|---|---|---|
| [`ceiling`](#ceiling) | • `ceiling.ceiling_type`<br>• `ceiling.nonce`<br>• `ceiling.witness_id`<br>• `ceiling.pubkey`<br>• `ceiling.response`<br>• `payload` | 1. `ceiling.ceiling_type` is `roughtime`<br>2. `ceiling.nonce` equals `ref(payload)`<br>3. `ceiling.witness_id` has a pinned key<br>4. `ceiling.pubkey`, if present, equals the pinned key<br>5. `ceiling.response` verifies against the pinned key |
| [`chain`](#chain) | • `payload.phase`<br>• `payload.fulfills`<br>• `payload.prev_hash`<br>• `signature.pubkey`<br>• `signature.sig`<br>• `signature.keyid` | 1. exactly one counted postreg has no `payload.prev_hash`<br>2. every other `payload.prev_hash` is the `ref` of a counted postreg<br>3. no `ref` is the `payload.prev_hash` of more than one counted postreg |
| [`content`](#content) | • `payload.subject`<br>• `payload.subject[].name`<br>• `payload.subject[].digest`<br>• `payload.hash_alg`<br>• `payloadType`<br>• `--artifacts` | 1. `payload.subject` is a non-empty array of well-formed entries<br>2. `payload.hash_alg` is available<br>3. `name` resolves inside `--artifacts`<br>4. the artifact exists<br>5. the artifact is readable<br>6. recomputed digest equals `digest[hash_alg]` |
| [`floor`](#floor) | • `payload.anchor.floor.floor_type`<br>• `payload.anchor.floor.chain_hash`<br>• `payload.anchor.floor.round`<br>• `payload.anchor.floor.signature`<br>• `payload.anchor.floor.randomness` | 1. `floor_type` is `drand`<br>2. `chain_hash` is pinned<br>3. `round` is an integer and `signature` is hex<br>4. `randomness`, if present, equals `sha256(signature)`<br>5. `signature` BLS-verifies for `round` under the pinned key |
| [`format`](#format) | • the file<br>• `payloadType`<br>• `payload`<br>• `signature`<br>• `signature.pubkey`<br>• `signature.sig` | 1. file is a well-formed JSON envelope<br>2. `signature.pubkey` and `signature.sig` are hex<br>3. `payloadType` names a format this release reads |
| [`keyconsist`](#keyconsist) | • `payload.phase`<br>• `payload.fulfills`<br>• `signature.pubkey`<br>• `signature.sig`<br>• `signature.keyid` | 1. every validly signed postreg naming the prereg's `ref` has the `signature.keyid` of a provided prereg with that `ref` |
| [`selfsig`](#selfsig) | • `payloadType`<br>• `payload`<br>• `signature.pubkey`<br>• `signature.sig`<br>• `signature.keyid` | 1. `signature.sig` verifies over `payload` by `signature.pubkey`<br>2. `signature.keyid` derives from `signature.pubkey` |

Condition numbers match each test's *Passes when all* list below; the table shortens them.
`format` and `selfsig` are required in every run. `selfsig` examines only files that pass
`format`, and so does every other test, each under the rules of the file's format.

(\*) per [Run rules](#conventions): if no manifest or commitment has these properties, the
test is empty and judged `FAIL` (see each test's *When empty* line).

---

## Tests

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

**When empty:** if no manifest that passes `format` has a `ceiling`, the test has nothing to
examine and is `FAIL`, with the reason `requested but no manifest carries a ceiling witness`.

**Not examined:** a manifest that fails `format` (see Run rules).

**Trust class:** signature-witness. Passing means the named server signed that time; it is
not proof-of-work. Interop is proven for `int08h-Roughtime` and expected, not proven, for
the other pinned servers.

**Example** (all requirements pass)

```console
$ asexec verify prereg.json --tests format,selfsig,ceiling
```

`prereg.json` (unexamined fields elided):

```jsonc
{
  "payload": { … },                              // ref(payload) = sha-256:b17107d0…
  "signature": { … },
  "ceiling": {
    "ceiling_type": "roughtime",
    "nonce": "b17107d0…",                        // = ref(payload), without the prefix
    "witness_id": "int08h-Roughtime",
    "pubkey": "016e6e02…",                       // the pinned int08h key
    "response": "06000000400000006000…"
  }
}
```

Output (from `=== tests ===` on), exit status `0`:

```
=== tests ===
  ✓ ceiling=PASS  (1/1 ceiling(s) ok)
  ✓ format=PASS  (1/1 manifest(s) ok)
  ✓ selfsig=PASS  (1/1 manifest(s) ok)

=== ceiling trust (what you are accepting) ===
  - prereg.json: ceiling witnessed by int08h-Roughtime at … - you are trusting …

asexec-verify/1 ceiling=PASS format=PASS selfsig=PASS
Checked at 2026-12-31T23:59:59Z
```

---

### `chain`

Linearity of a commitment's postreg chain.

A postreg is **counted** for a prereg if it meets the
[conditions for counting](#matching-postregs-to-commitments).

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

**When empty:** if no commitment has a counted postreg, the test has nothing to examine and
is `FAIL`, with the reason `requested but no commitment has counted postregs to
chain-check`.

**Does not establish:** completeness. Dropping the last postreg(s) of a chain is not
detectable.

**Example** (all requirements pass)

```console
$ asexec verify prereg.json postreg-1.json postreg-2.json --tests format,selfsig,chain
```

The three files (unexamined fields elided; all three are signed by the same key):

```jsonc
// prereg.json: ref = sha-256:b17107d0…
{ "payload": { "phase": "prereg", … }, "signature": { "keyid": "sha-256:7bc19c1d…", … } }

// postreg-1.json: ref = sha-256:da0adf83…, the root (no prev_hash)
{ "payload": { "phase": "postreg", "fulfills": "sha-256:b17107d0…", … },
  "signature": { "keyid": "sha-256:7bc19c1d…", … } }

// postreg-2.json: links to postreg-1
{ "payload": { "phase": "postreg", "fulfills": "sha-256:b17107d0…",
               "prev_hash": "sha-256:da0adf83…", … },
  "signature": { "keyid": "sha-256:7bc19c1d…", … } }
```

Output (from `=== tests ===` on), exit status `0`:

```
=== tests ===
  ✓ chain=PASS  (1/1 chain(s) ok)
  ✓ format=PASS  (3/3 manifest(s) ok)
  ✓ selfsig=PASS  (3/3 manifest(s) ok)

asexec-verify/1 chain=PASS format=PASS selfsig=PASS
Checked at 2026-12-31T23:59:59Z
```

---

### `content`

Subject digests recomputed from the original artifacts.

**Examines (\*)**
- `payload.subject`
- `payload.subject[].name`
- `payload.subject[].digest`
- `payload.hash_alg` (if absent, the default of the format `payloadType` names: `sha-256`)
- `payloadType` (only for that default)
- `--artifacts`

**Passes when all** (for each manifest that has a `payload.subject`, and each of its entries)
1. `payload.subject` is a non-empty array, and each entry's `name` is a string and
   `digest[hash_alg]` is hex.
2. `hash_alg` is available in this install: `sha-256` always, `blake3` only if installed.
3. `name` (trailing `/` removed) resolved with symlinks against `--artifacts` is the
   `--artifacts` directory or beneath it. `..` components, absolute names, and symlinks
   that point outside fail here.
4. The resolved path exists.
5. The resolved path is readable.
6. The recomputed digest of the file or directory under `hash_alg` equals the bytes of
   `digest[hash_alg]`, in either hex case.

**When empty:** if `--artifacts` is not given or is empty (`--artifacts ""`), or no
manifest that passes `format` has a `payload.subject`, the test has nothing to examine and is
`FAIL`, with the reason `requested but no content could be checked (need --artifacts and a
manifest with a subject)`.

**Entry failure reasons** (shown per entry in the report): `malformed subject entry`,
`algorithm unavailable: <alg>`, `path resolves outside --artifacts`, `artifact not found`,
`artifact unreadable: <error>`, or a digest mismatch with `expected`/`actual`.

**Not examined:** a manifest that fails `format`; any manifest when `--artifacts` is absent.

**Does not establish:** provenance. A match shows the artifact was not altered, not that it
is the output of the named harness and model.

**Example** (all requirements pass)

```console
$ asexec verify prereg.json --tests format,selfsig,content --artifacts artifacts
```

`artifacts/transcript.txt` contains `hello` and a newline. `prereg.json` (unexamined fields
elided):

```jsonc
{
  "payload": {
    "subject": [
      {
        "name": "transcript.txt",
        "digest": { "sha-256": "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03" }
      }
    ],
    "hash_alg": "sha-256",
    …
  },
  "signature": { … }
}
```

Output (from `=== tests ===` on), exit status `0`:

```
=== tests ===
  ✓ content=PASS  (1/1 subject(s) ok)
  ✓ format=PASS  (1/1 manifest(s) ok)
  ✓ selfsig=PASS  (1/1 manifest(s) ok)

asexec-verify/1 content=PASS format=PASS selfsig=PASS
Checked at 2026-12-31T23:59:59Z
```

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

**When empty:** if no manifest that passes `format` has a `payload.anchor.floor`, the test
has nothing to examine and is `FAIL`, with the reason `requested but no manifest carries an
anchor.floor`.

**Not examined:** a manifest that fails `format`.

**Does not establish:** that the pre-registration preceded the run. A floor bounds
freshness (anti-precomputation), not backdating.

**Example** (all requirements pass)

```console
$ asexec verify prereg.json --tests format,selfsig,floor
```

`prereg.json` (unexamined fields elided):

```jsonc
{
  "payload": {
    "anchor": {
      "floor": {
        "floor_type": "drand",
        "chain_hash": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
        "round": 33394706,
        "signature": "9791d98e2e577017…",
        "randomness": "8442c678de44756b…"       // = sha256(signature)
      }
    },
    …
  },
  "signature": { … }
}
```

Output (from `=== tests ===` on), exit status `0`:

```
=== tests ===
  ✓ floor=PASS  (1/1 floor(s) ok)
  ✓ format=PASS  (1/1 manifest(s) ok)
  ✓ selfsig=PASS  (1/1 manifest(s) ok)

asexec-verify/1 floor=PASS format=PASS selfsig=PASS
Checked at 2026-12-31T23:59:59Z
```

---

### `format`

Whether the file can be read as a manifest of a format this release reads. Required in
every run.

**Examines (\*)**
- every manifest file found, as a whole
- `payloadType`
- `payload`
- `signature`
- `signature.pubkey`
- `signature.sig`

**Passes when all**
1. The file can be read, and is a JSON object, nested at most 64 deep, with no duplicate
   keys, containing an object `payload`, a string `payloadType` and an object `signature`,
   and `payload` has canonical bytes (no string in it, key or value, holds an unpaired
   surrogate escape).
2. `signature.pubkey` and `signature.sig` are hex.
3. `payloadType` names a format this release reads, compared exactly: in this release,
   `application/vnd.asexec.v1+json` (see [Formats](#conventions)). A file that names
   another format is never read under this one's rules instead. Such a file is held only to
   the part of #1 that comes before any format: it can be read, and is a JSON object,
   nested at most 64 deep, with no duplicate keys. The rest of #1, and #2, are this
   format's rules, and a newer format may lay its file out differently.

A file that fails #1 or #2 is malformed, and one that fails #3 is of an unknown format (see
[Run rules](#conventions)). Either way no other test examines it.

**Failure reasons** (shown under the file in the report):
- #1 and #2: `malformed: ` and what is wrong. A `payloadType` that is absent (missing or
  `null`) is `malformed: payloadType: Field required`, and one that is not a string is
  `malformed: payloadType: Input should be a valid string`.
- #3, by what `payloadType` names:
  - `application/vnd.asexec+json`, the format of asexec before 0.4.0: `payloadType names
    the format of asexec before 0.4.0, which is not supported: re-sign with this release`.
  - A beta's format, `application/vnd.asexec.X.Y.ZbN+json` (for example
    `application/vnd.asexec.0.4.0b1+json`): `payloadType names an asexec beta format, and
    betas are not supported`.
  - Any other: `payloadType names a format newer than this release: upgrade asexec to read
    it`.

**When empty:** if no manifest file is found (every path given is a directory with no
`*.json` file in it), `format` has nothing to examine and is `FAIL`, with the reason
`no manifests to verify`. A path that is not a directory is always examined, even if it
does not exist (it is malformed), and so is a directory that cannot be listed.

**Does not establish:** that the signature is valid (that is [`selfsig`](#selfsig)), which
also covers `payloadType`; that `payload` is a well-formed asexec body (any object `payload`
passes, whatever it holds).

**Example** (all requirements pass)

```console
$ asexec verify prereg.json --tests format,selfsig
```

`prereg.json`:

```jsonc
{
  "payloadType": "application/vnd.asexec.v1+json",
  "payload": {
    "predicateType": "https://asexec.org/manifest/v1",
    "phase": "prereg",
    "target": "model m via provider p"
  },
  "signature": {
    "pubkey": "0743f489…",
    "sig": "89ccc62e…",
    "keyid": "sha-256:7bc19c1d…"
  }
}
```

Output (from `=== tests ===` on), exit status `0`:

```
=== tests ===
  ✓ format=PASS  (1/1 manifest(s) ok)
  ✓ selfsig=PASS  (1/1 manifest(s) ok)

asexec-verify/1 format=PASS selfsig=PASS
Checked at 2026-12-31T23:59:59Z
```

A malformed file beside it, here `truncated.json` (the first 120 bytes of `prereg.json`),
fails `format` and is not examined by `selfsig`, which still passes for `prereg.json`. The
reason is shown under the file. Exit status `2`:

```console
$ asexec verify prereg.json truncated.json --tests format,selfsig
```

```
=== manifests ===
✓ prereg.json  [prereg]  keyid=sha-256:7bc19c1d…
✗ truncated.json  [None]  keyid=None
    ✗ format: malformed: Unterminated string starting at: line 5 column 15 (char 109)
…
=== tests ===
  ✗ format=FAIL  (1/2 manifest(s) failed)
  ✓ selfsig=PASS  (1/1 manifest(s) ok)

asexec-verify/1 format=FAIL selfsig=PASS
```

Version skew: `postreg-v2.json` is `postreg-1.json` from the [`chain` example](#chain) with
its `payloadType` changed to `application/vnd.asexec.v2+json`, as a later release would
label its own files. It fails `format` with the upgrade reason, not as a bad signature, and
`selfsig` still passes for `prereg.json`. It takes no part in the commitment, which stays
open. Exit status `2`:

```console
$ asexec verify prereg.json postreg-v2.json --tests format,selfsig
```

```
=== manifests ===
✓ prereg.json  [prereg]  keyid=sha-256:7bc19c1d…
✗ postreg-v2.json  [postreg]  keyid=None
    ✗ format: payloadType names a format newer than this release: upgrade asexec to read it

=== commitments ===
  [OPEN] prereg sha-256:b17107d0…
…
=== tests ===
  ✗ format=FAIL  (1/2 manifest(s) failed)
  ✓ selfsig=PASS  (1/1 manifest(s) ok)

asexec-verify/1 format=FAIL selfsig=PASS
```

---

### `keyconsist`

Whether a commitment's postregs were signed by its own key.

**Examines (\*)**
- `payload.phase`
- `payload.fulfills`
- `signature.pubkey`
- `signature.sig`
- `signature.keyid`

**Passes when all** (for each commitment with a counted postreg or a postreg rejected as
`signed by a different key than the pre-registration`; see
[Matching postregs to commitments](#matching-postregs-to-commitments))
1. Every postreg whose `payload.fulfills` equals the commitment's `ref` and whose signature
   is valid (it meets the [`selfsig`](#selfsig) conditions) has the `signature.keyid` of a
   provided prereg with that `ref`.

A postreg with an invalid signature is not judged here (it fails `selfsig`), so a commitment
whose only postregs have invalid signatures has no key to check and is not examined.

**When empty:** if no validly signed postreg names a provided prereg, the test has nothing
to examine and is `FAIL`, with the reason `requested but no validly signed postreg names a
provided prereg`.

**Example** (all requirements pass)

```console
$ asexec verify prereg.json postreg.json --tests format,selfsig,keyconsist
```

The two files (unexamined fields elided):

```jsonc
// prereg.json: ref = sha-256:b17107d0…
{ "payload": { "phase": "prereg", … }, "signature": { "keyid": "sha-256:7bc19c1d…", … } }

// postreg.json: same keyid as the prereg
{ "payload": { "phase": "postreg", "fulfills": "sha-256:b17107d0…", … },
  "signature": { "keyid": "sha-256:7bc19c1d…", … } }
```

Output (from `=== tests ===` on), exit status `0`:

```
=== tests ===
  ✓ format=PASS  (2/2 manifest(s) ok)
  ✓ keyconsist=PASS  (1/1 commitment(s) ok)
  ✓ selfsig=PASS  (2/2 manifest(s) ok)

asexec-verify/1 format=PASS keyconsist=PASS selfsig=PASS
Checked at 2026-12-31T23:59:59Z
```

---

### `selfsig`

Whether the file is unchanged since its own key signed it. Required in every run.

`selfsig` is self-certifying: the file carries its own `signature.pubkey`, so a pass means
only that whoever holds that key signed these bytes, and that they have not changed since.
Nothing is pinned, and verify keeps no state between runs. Trust comes from the other
layers: [`keyconsist`](#keyconsist) gives key continuity within one claim, and
[`ceiling`](#ceiling) pins when the prereg was signed.

**Examines (\*)**
- `payloadType` (it is in the signing input, and names the format whose rules apply)
- `payload`
- `signature.pubkey`
- `signature.sig`
- `signature.keyid`

**Passes when all** (for each manifest that passes [`format`](#format), under the rules of
its format)
1. `signature.sig` is a valid ed25519 signature by `signature.pubkey` over the PAE signing
   input of the file's `payloadType` and the canonical bytes of `payload`.
2. `signature.keyid == "sha-256:" + sha256(bytes.fromhex(signature.pubkey)).hexdigest()`,
   where `sha-256:` is the format's prefix.

**When empty:** if no manifest passes `format` (including when no manifest file is found),
`selfsig` has nothing to examine and is `FAIL`, with the reason
`no manifest passes format`.

**Not examined:** a manifest that fails `format`.

**Does not establish:** who signed (internal consistency only). A body changed and
re-signed with another key, under that key's `keyid`, passes.

**Example** (a body edited after signing). `tampered.json` is `postreg-1.json` from the
[`chain` example](#chain) with its `payload.target` changed afterwards:

```console
$ asexec verify prereg.json tampered.json --tests format,selfsig
```

Output (from `=== tests ===` on), exit status `2`:

```
=== tests ===
  ✓ format=PASS  (2/2 manifest(s) ok)
  ✗ selfsig=FAIL  (1/2 manifest(s) failed)

asexec-verify/1 format=PASS selfsig=FAIL
Checked at 2026-12-31T23:59:59Z
```

With every requirement holding, `selfsig` prints `✓ selfsig=PASS`, as in the
[`format` example](#format).

---

## Matching postregs to commitments

A **commitment** is a prereg's `ref` together with its signer, `signature.keyid`. The body
holds no key, so the same body signed by two keys has one `ref` but is two commitments, each
judged on its own.

A **provided prereg** is a prereg among the files given that passes [`format`](#format). A
prereg that fails `format` (malformed, or of an unknown format) is not a provided prereg and
is no commitment, so a postreg that names it is notarization-only.

A postreg `P` **counts** toward the commitment of prereg `R` iff all hold:
1. `P.payload.phase == "postreg"` and `P.payload.fulfills == ref(R)`.
2. `P` meets the [`selfsig`](#selfsig) conditions.
3. `P.signature.keyid == R.signature.keyid`.

A commitment is keyed by its signer, so a postreg counts toward at most one commitment: the
one with its `payload.fulfills` as `ref` and its own `signature.keyid` as signer.

A postreg that names a prereg (condition 1) but counts toward no commitment with that `ref`
is **rejected**. It is left out of fulfillment and of `chain`, and is listed under each
commitment with that `ref` with the reason it fails there: `invalid signature` (condition 2)
or `signed by a different key than the pre-registration` (condition 3). A postreg that
counts toward one commitment of a `ref` is not rejected under the others. If one prereg body
is signed by keys A and B, a postreg signed by A counts toward A's commitment and is not
listed under B's.

A postreg that fails condition 1 for every provided prereg names none of them. It is
**notarization-only**: there is no commitment to list it under, so it has no
[state](#commitment-states) and is listed in its own block, whether or not its signature is
valid.

**In summary**, by kind of file:

| Postreg situation | `format` | `selfsig` | Outcome | In the report |
|---|---|---|---|---|
| Malformed, or of an unknown format (see [Run rules](#conventions)) | `FAIL` | not examined | none: not treated as a postreg | not listed under any commitment |
| Passes `format`, fails a `selfsig` condition, `fulfills` a provided prereg | `PASS` | `FAIL` | not counted: `invalid signature` | **rejected** |
| Valid signature by a key that signed no provided prereg with that `ref`, `fulfills` a provided prereg | `PASS` | `PASS` | not counted: `signed by a different key than the pre-registration` | **rejected**; also fails `keyconsist` |
| Valid signature by the key of a provided prereg with that `ref` | `PASS` | `PASS` | **counted** toward that prereg's commitment | listed as a counted postreg of that commitment only |
| Passes `format`, `fulfills` matches no provided prereg | `PASS` | `PASS` if the signature is valid, else `FAIL` | not counted: names no provided prereg | **notarization-only** |

**What affects a verdict.** Only the tests produce `PASS` or `FAIL`. *Counted* matters
because `chain` examines counted postregs only. `keyconsist` fails a commitment only for a
postreg rejected under it as `signed by a different key than the pre-registration`; a
counted postreg, one rejected for `invalid signature` and a notarization-only postreg never
fail it, and a commitment whose postregs all have invalid signatures is not examined.
*Rejected* and *notarization-only* are only groupings in the report and add no failure of
their own. The failures in the table come from `format` (the first row), `selfsig` (the
second row, and the last row when the signature is invalid) and `keyconsist` (the third
row).

A manifest is identified by its `ref`. Copies of a postreg, with the same `ref` and
`signature.keyid`, are listed once per outcome, however many are provided. Copies usually
share an outcome, so they are counted, rejected or notarization-only once. A copy whose
signature does not verify is judged on its own: it fails `selfsig` and, if it names a
provided prereg, is listed as rejected for `invalid signature` beside the valid copy's
outcome (so a broken copy of a counted postreg shows the same `ref` as counted and as
rejected). Copies of a prereg, with the same `ref` and `signature.keyid`, are one
commitment.

## Commitment states

One per commitment, shown in the `=== commitments ===` block of the report (see
[Output](#output)). Never part of the verify code, and never affects the exit status.

| State | Condition |
|---|---|
| `fulfilled` | at least one counted postreg |
| `open` | no counted postreg, and `payload.due` is absent or in the future |
| `elapsed-no-postreg` | no counted postreg, and `payload.due` is at or before now |
| `invalid-due` | no counted postreg, and `payload.due` is present but not a parseable ISO-8601 string |

A [notarization-only](#matching-postregs-to-commitments) postreg belongs to no commitment,
so it has no state.

A `payload.due` without a UTC offset or `Z` is read as UTC, never in the verifier's local
timezone, and is flagged in the report. Timeliness (a postreg created before `due`) is not
checked in this version.

**Example** (`fulfilled`). A prereg signed with `--due 2099-01-01T00:00:00Z`, and two
chained postregs as in the [`chain` example](#chain):

```
=== commitments ===
  [FULFILLED] prereg sha-256:b74ae2db…
    signer       : sha-256:7bc19c1d…
    due          : 2099-01-01T00:00:00Z
    postregs     : 2
```

Each entry is the state in capitals and the prereg's `ref`, then its signer's keyid, `due`
(or `(none declared)`) and the number of counted postregs. Problems follow as `✗` lines: a
`due` without a timezone, an unparseable `due`, a chain problem (on the `postregs` line), or
a rejected postreg and why it does not count.
[`notarization-only`](#matching-postregs-to-commitments) postregs are listed in their own
block, since they have no prereg to sit under.

## Not in this version

`signer`, `timely`, `complete` and `order` are planned for 0.4.0, and `continuity` is
deferred to 0.7.0 or later (see [`ROADMAP.md`](../ROADMAP.md)). Adding a test name never
changes the meaning of an existing code. From 0.4.0, changing the documented meaning of an
existing name bumps the code grammar (`asexec-verify/N`); 0.4.0 itself keeps `/1`.

What a passing code does not establish is stated under each test (*Does not establish*)
and summarized in the [README](../README.md#what-does-asexec-prove).
