# Verification catalog

Reference for every test accepted by `asexec verify --tests`. Authoritative implementation:
`src/asexec/verifier.py`. Structural requirements (types and shapes) are implemented as the
input models in `src/asexec/models.py`; everything else, and every verdict, is in the
verifier and the modules it calls.

```
asexec verify <manifest|dir>... --tests <name>[,<name>...] [--artifacts <dir>]
```

## Conventions

**Property paths.** A manifest file is a JSON object: an asexec wrapper around a standard
[DSSE](https://github.com/secure-systems-lab/dsse) envelope. This format defines three
top-level members: `dsse`, the envelope, which holds `dsse.payloadType` (the format),
`dsse.payload` (the base64 of the signed body bytes) and `dsse.signatures` (a list of
`{keyid, sig}`, `sig` the base64 of the signature, as DSSE has it); `pubkey`, the signing
key, in hex; and optionally `ceiling` and `untrusted` (see [Untrusted](#untrusted)). The
**body bytes** are
what `dsse.payload` decodes to, and the **body** is the JSON object they hold: the signed
claim. Properties are written as dotted paths of two kinds:
- `body.<path>` is inside the body, the decoded `dsse.payload`: `body.phase`,
  `body.anchor.floor.round`.
- Any other path is from the file's root, outside the body: `dsse.payloadType`,
  `dsse.signatures[0].keyid`, `pubkey`, `ceiling.nonce`. None of these is in the body. Of
  them, only `dsse.payloadType`, which the PAE signing input holds, is covered by the
  signature.

`[]` denotes array elements (`body.subject[].name`), and `[0]` the first.

**Formats.** A file's `dsse.payloadType` names its format, and every test reads the file
under that format's rules only, never another format's. This release reads one format,
`application/vnd.asexec.v1+json`, and this document gives its rules: the PAE signing input
is DSSE's, `DSSEv1 SP len(type) SP type SP len(body) SP body` over `dsse.payloadType` and
the body bytes; and `ref` and `keyid` start `sha-256:`. A file whose `dsse.payloadType`
names any other format fails [`format`](#format) #3.

**Phases.** A manifest's phase is its `body.phase`. A *prereg* is a manifest with
`body.phase == "prereg"`; a *postreg* has `body.phase == "postreg"`. `ref(m)` is
`sha-256:<hex>` of the sha-256 of `m`'s body bytes, exactly as stored. Nothing re-serializes
them: the signature and `ref` are of the same bytes, so the same JSON value spelled another
way (other spacing, other key order) is another body, with another `ref`.

**Hex.** A value required to be hex is a string that `bytes.fromhex` accepts: an even number
of hex digits in either case, with ASCII whitespace allowed around and between bytes.
Content #9 compares the bytes a digest's hex decodes to, so any such spelling matches.
Ceiling #2 and floor #4 compare exactly against the lowercase hex of the digest.

**Base64.** A value required to be strict base64 is a string in the standard alphabet
(`A`-`Z`, `a`-`z`, `0`-`9`, `+`, `/`), padded with `=` to a multiple of 4 characters, with no
whitespace or other character, and in the one spelling that base64 encoding gives its bytes:
no unused bit of the last character is set. So each byte string has exactly one spelling.
`dsse.payload` and `dsse.signatures[].sig` are strict base64. Every `dsse` asexec writes is
a standard DSSE envelope (protocol v1.0.2) that DSSE tooling can verify as it is, but asexec
reads only a subset of DSSE envelopes, being stricter than DSSE in four ways: it reads only
standard, padded base64 (DSSE says verifiers must accept the URL-safe alphabet too, which
asexec departs from on purpose, and is silent on padding); it requires a `keyid`, which must
be `sha-256:` of `pubkey` (in DSSE it is optional, an unauthenticated hint); and it requires
exactly one signature (DSSE allows several, with a threshold). An envelope another tool
wrote outside these rules is malformed here (its `payload`) or fails `selfsig`.

**JSON.** Valid JSON is what Python's `json.load` accepts (so `NaN` and `Infinity` are
allowed), nested at most 64 deep: each array or object adds a level, and the outermost
object is level 1. A deeper file is malformed, so every supported Python version reads a
file the same way. The body is held to the same rules on its own: its bytes are UTF-8 JSON
text (no byte order mark), and its depth is counted from its own outermost object, level 1,
whatever depth the file holds it at (in the file it is a string). A lone surrogate escape,
such as `"\ud800"`, is valid JSON: the body bytes are read as stored, so a body may hold one.
It is read as the string it spells, which equals no `ref` or `keyid`, parses as no time
and names no file, and the report shows it escaped, as `\ud800`.

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
  through a present non-object (e.g. `body.anchor` is `[]`) is present, and malformed.
- (\*) A test is **empty** if no provided manifest or commitment has the properties it
  examines. An empty test has nothing to examine and is judged `FAIL`. Each test's *When
  empty* line gives the exact condition and the reason the report shows. A manifest or
  commitment that lacks the examined properties is not examined and cannot fail the test;
  it also does not count toward passing.
- Verification is offline.
- A file is **malformed** if verify cannot read it as a manifest: it cannot be read, is not
  a JSON object, nests more than 64 deep, contains a duplicate JSON key at any level, or
  lacks the frame. The frame is an object `dsse` holding a string `dsse.payloadType`, an
  array `dsse.signatures`, and a `dsse.payload` that is strict base64 of body bytes that
  are the UTF-8 JSON text of an object, nested at most 64 deep, with no duplicate key
  ([`format`](#format) #1 and #2). Nothing else makes a file malformed. A missing or
  non-hex `pubkey`, a missing or non-base64 `sig`, a missing `keyid`, and other than
  exactly one signature are judged by [`selfsig`](#selfsig). A file is of an **unknown format** if its
  `dsse.payloadType` is a string that names no format this release reads
  ([`format`](#format) #3). A readable JSON object with such a `dsse.payloadType` is judged
  by #3 instead of the rest of #1 and #2, so it is of an unknown format and never
  malformed, whatever else it holds.
- A file that is malformed or of an unknown format fails [`format`](#format), and no other
  test examines it, `selfsig` included. It takes no part in any commitment: as a prereg it
  is no commitment, and as a postreg it is neither counted nor rejected (see
  [Matching postregs to commitments](#matching-postregs-to-commitments)).

## Output

`asexec verify` prints a report for people to read, then the code, then when the run
happened. Only the code line and the exit status are stable to script against. The
report's wording may change, except for the reasons this document lists.

In anything the report prints from a file or a file's name, a control character, a line or
paragraph separator, a bidirectional control and a lone surrogate are each shown escaped
(`\n`, `\x1b`, `\u2028`, `\ud800`). So no manifest can start a line: the code is the one line
that starts with `asexec-verify/`. Match it at the start of a line, since a manifest's text
can still hold those characters further along one.

| Block | Printed | Shows |
|---|---|---|
| `=== manifests ===` | always | One line per file: `✓` if it passes `format` and meets `selfsig`'s conditions (else `✗`), the path, `body.phase` and `dsse.signatures[0].keyid` (`None` for a file that fails `format`, whose body is not read). Indented beneath: why a file fails `format` (`format: malformed: …`, or the [reason](#format) for an unknown format), and one line each for a floor, a ceiling and content hashes when the manifest has them. |
| `=== untrusted … ===` | if any | For each file that passes `format`: its [`untrusted`](#untrusted) section, and each key outside the body that this format does not define, each as its path and its value in JSON. The heading says nothing in it was checked. |
| `=== unknown fields … ===` | if any | For each file that passes `format`: each body field this format does not define, as its path (`body.…`) and its value in JSON (see [Untrusted](#untrusted)). The heading says nothing in it was checked. |
| `=== commitments ===` | always | One entry per [commitment](#matching-postregs-to-commitments) (a validly signed prereg's `ref` and signer): its [state](#commitment-states), `ref`, signer keyid, `due` (and a line if it is not parseable), the number of counted postregs, a chain problem if any, with [`timely`](#timely) requested each counted postreg not shown on time and why, with [`order`](#order) requested a prereg whose ceiling gives no time and each counted postreg not shown after the prereg and why, if its prereg lists items each item with its status or why [`complete`](#complete) does not count it as accounted for (and each counted postreg whose `item_id` names no listed item), and each rejected postreg with its reason. |
| `=== rejected pre-registrations ===` | if any | Each [rejected pre-registration](#matching-postregs-to-commitments) (a prereg that passes `format` but fails a `selfsig` condition, so is no commitment): its `ref` and its reason, `invalid signature`; the `dsse.signatures[0].keyid` it claims, which nothing authenticated; and each postreg rejected under it, with the reason `the pre-registration's signature is invalid`. It has no state. |
| `=== notarization-only … ===` | if any | Each [notarization-only](#matching-postregs-to-commitments) postreg: one whose `body.fulfills` matches no provided prereg. |
| `=== tests ===` | always | One line per requested test: its result and a short reason. |
| `=== ceiling trust … ===` | if a ceiling verified | Which witness you are trusting, and for what time: the signed `midpoint ± radius`, and the "no later than" time, `midpoint + radius`, that [`timely`](#timely) compares. |
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
✓ prereg.json  [prereg]  keyid=sha-256:bc562700…
✓ postreg-1.json  [postreg]  keyid=sha-256:bc562700…
✓ postreg-2.json  [postreg]  keyid=sha-256:bc562700…

=== untrusted (unsigned, and read by no test: nothing here was checked) ===
  prereg.json
    untrusted = {"asexec_version": "0.4.0"}
  postreg-1.json
    untrusted = {"asexec_version": "0.4.0"}
  postreg-2.json
    untrusted = {"asexec_version": "0.4.0"}

=== commitments ===
  [FULFILLED] prereg sha-256:b17107d0…
    signer       : sha-256:bc562700…
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
| [`ceiling`](#ceiling) | • `ceiling.ceiling_type`<br>• `ceiling.nonce`<br>• `ceiling.witness_id`<br>• `ceiling.pubkey`<br>• `ceiling.response`<br>• `dsse.payload` | 1. `ceiling.ceiling_type` is `roughtime`<br>2. `ceiling.nonce` equals `ref`<br>3. `ceiling.witness_id` has a pinned key<br>4. `ceiling.pubkey`, if present, equals the pinned key<br>5. `ceiling.response` verifies against the pinned key |
| [`chain`](#chain) | • `body.phase`<br>• `body.fulfills`<br>• `body.prev_hash`<br>• `pubkey`<br>• `dsse.signatures`<br>• `dsse.signatures[0].sig`<br>• `dsse.signatures[0].keyid` | 1. exactly one counted postreg has no `body.prev_hash`<br>2. every other `body.prev_hash` is the `ref` of a counted postreg<br>3. no `ref` is the `body.prev_hash` of more than one counted postreg |
| [`complete`](#complete) | • `body.items`<br>• `body.items[].id`<br>• `body.due` (of the prereg)<br>• `body.item_id` and `body.status`, of each counted postreg<br>• which postregs are counted, and their `ceiling` (as for `timely`) | (for each commitment whose prereg lists at least one item)<br>1. `body.items` is an array of objects with string ids<br>2. no two items have the same `id`<br>3. each item has a counted postreg with its `item_id` and a `status` of `reported`, `excluded` or `blocked`<br>4. a `body.due`, if present, is parseable<br>5. with a `due`, such a postreg is on time, as `timely` judges it |
| [`content`](#content) | • `body.subject`<br>• `body.subject[].name`<br>• `body.subject[].hash_alg`<br>• `body.subject[].digest`<br>• `body.plan` and its `name`, `hash_alg`, `digest`<br>• `body.evidence` and each entry's `name`, `hash_alg`, `digest`<br>• `--artifacts` | 1. `body.subject` and `body.evidence` are non-empty arrays, and `body.plan` an object, of well-formed entries<br>2. the entry's `hash_alg` is available<br>3. `name` is a normalized relative path<br>4. no other entry of the list has the same `name`<br>5. `name` resolves inside `--artifacts`<br>6. the artifact exists<br>7. the artifact is a regular file<br>8. the artifact is readable<br>9. recomputed digest equals `digest[hash_alg]` |
| [`floor`](#floor) | • `body.anchor.floor.floor_type`<br>• `body.anchor.floor.chain_hash`<br>• `body.anchor.floor.round`<br>• `body.anchor.floor.signature`<br>• `body.anchor.floor.randomness` | 1. `floor_type` is `drand`<br>2. `chain_hash` is present and pinned<br>3. `round` is an integer and `signature` is hex<br>4. `randomness`, if present, equals `sha256(signature)`<br>5. `signature` is 48 bytes, in G1, and BLS-verifies for `round` under the pinned key |
| [`format`](#format) | • the file<br>• `dsse`<br>• `dsse.payloadType`<br>• `dsse.signatures`<br>• `dsse.payload` | 1. file is a well-formed JSON object with the `dsse` frame<br>2. `dsse.payload` is strict base64 of a well-formed JSON object<br>3. `dsse.payloadType` names a format this release reads |
| [`keyconsist`](#keyconsist) | • `body.phase`<br>• `body.fulfills`<br>• `pubkey`<br>• `dsse.signatures`<br>• `dsse.signatures[0].sig`<br>• `dsse.signatures[0].keyid` | 1. every validly signed postreg naming the commitment's `ref` has the `dsse.signatures[0].keyid` of a commitment with that `ref` |
| [`order`](#order) | • `ceiling` and its fields, of the prereg<br>• which postregs are counted (as for `chain`)<br>• `body.anchor.floor` and its fields, of each counted postreg | (for each commitment with a counted postreg)<br>1. the prereg has a `ceiling`<br>2. that ceiling meets the `ceiling` conditions<br>3. each counted postreg has a `body.anchor.floor`<br>4. that floor meets the `floor` conditions<br>5. the ceiling's time, `MIDP + RADI`, is strictly before the floor's round time |
| [`selfsig`](#selfsig) | • `dsse.payloadType`<br>• `dsse.payload`<br>• `dsse.signatures`<br>• `dsse.signatures[0].sig`<br>• `dsse.signatures[0].keyid`<br>• `pubkey` | 1. `dsse.signatures` has exactly one entry, an object<br>2. `pubkey` is hex, and `dsse.signatures[0].sig` is strict base64 of 64 bytes<br>3. `dsse.signatures[0].sig` verifies over the PAE of the body bytes by `pubkey`<br>4. `dsse.signatures[0].keyid` derives from `pubkey` |
| [`timely`](#timely) | • `body.due` (of the prereg)<br>• which postregs are counted (as for `chain`)<br>• `ceiling` and its fields, of each counted postreg | (for each commitment with a `body.due` and a counted postreg)<br>1. `body.due` is a parseable ISO-8601 string<br>2. each counted postreg has a `ceiling`<br>3. that ceiling meets the `ceiling` conditions<br>4. its time, `MIDP + RADI`, is at or before `due` |

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
- `dsse.payload` (the body bytes, whose digest is `ref`)

**Passes when all**
1. `ceiling.ceiling_type == "roughtime"`.
2. `ceiling.nonce` equals the hex of `ref`, the sha-256 of the body bytes.
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
  "dsse": { … },                                 // ref = sha-256:b17107d0…
  "pubkey": "91230c4e…",
  "ceiling": {
    "ceiling_type": "roughtime",
    "nonce": "b17107d0…",                        // = ref, without the prefix
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
- `body.phase`
- `body.fulfills`
- `body.prev_hash`
- `pubkey`
- `dsse.signatures`
- `dsse.signatures[0].sig`
- `dsse.signatures[0].keyid`

(`pubkey` and the `dsse.signatures` properties, the [`selfsig`](#selfsig) conditions,
decide only whether a postreg is counted.)

**Passes when all** (for each prereg that has at least one counted postreg)
1. Exactly one counted postreg has no `body.prev_hash`.
2. Every other counted postreg's `body.prev_hash` equals the `ref` of a counted postreg
   of the same prereg (no gaps).
3. No `ref` appears as `body.prev_hash` of more than one counted postreg (no forks).

**When empty:** if no commitment has a counted postreg, the test has nothing to examine and
is `FAIL`, with the reason `requested but no commitment has counted postregs to
chain-check`. A rejected pre-registration is no commitment, so its postregs are never
chain-checked.

**Does not establish:** completeness. Dropping the last postreg(s) of a chain is not
detectable by `chain`; when the prereg lists its items, [`complete`](#complete) detects a
dropped item.

**Example** (all requirements pass)

```console
$ asexec verify prereg.json postreg-1.json postreg-2.json --tests format,selfsig,chain
```

The three files' bodies (unexamined fields elided). All three are signed by the same key,
so each has `dsse.signatures[0].keyid` `sha-256:bc562700…`:

```jsonc
// prereg.json: ref = sha-256:b17107d0…
{ "phase": "prereg", … }

// postreg-1.json: ref = sha-256:da0adf83…, the root (no prev_hash)
{ "phase": "postreg", "fulfills": "sha-256:b17107d0…", … }

// postreg-2.json: links to postreg-1
{ "phase": "postreg", "fulfills": "sha-256:b17107d0…", "prev_hash": "sha-256:da0adf83…", … }
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

### `complete`

Whether every item a commitment promised is accounted for by a postreg that counts toward it
(and, if the prereg has a `due`, in time).

A prereg's `body.items` lists what the claim commits to deliver, each with an `id`; a postreg
accounts for one with its `body.item_id` and `body.status`. A postreg is **counted** for a
prereg if it meets the [conditions for counting](#matching-postregs-to-commitments).

**Examines (\*)**
- `body.items`, `body.items[].id` and `body.due` (of the prereg)
- `body.item_id` and `body.status` (of each counted postreg)
- `body.phase`, `body.fulfills`, `pubkey`, `dsse.signatures`, `dsse.signatures[0].sig`,
  `dsse.signatures[0].keyid` (which postregs are counted)
- with a `body.due`: `ceiling` and its fields, of each counted postreg (as for
  [`timely`](#timely))

**Passes when all** (for each commitment whose prereg's `body.items` is present and not an
empty array)
1. `body.items` is an array of objects, each with a string `id`.
2. No two items have the same `id`.
3. Each item has a counted postreg whose `body.item_id` equals its `id` exactly and whose
   `body.status` is `reported`, `excluded` or `blocked`.
4. If `body.due` is present, it is a parseable ISO-8601 string (one without an offset is
   read as UTC).
5. If `body.due` is present, for each item one of the postregs that meet #3 for it is shown
   on time, by [`timely`](#timely)'s comparison: it has a ceiling that meets the
   [`ceiling`](#ceiling) conditions, and its ceiling time T is at or before `due`. A postreg
   with no ceiling, or one that fails a ceiling condition, is not on time.

Several counted postregs for one item: any one that meets #3 (and, with a `due`, #5)
accounts for it, and the others neither help nor fail it. A counted postreg whose
`body.item_id` names no listed item accounts for nothing and fails nothing; the report lists
it. A counted postreg with no `body.item_id` is not read. A postreg that does not count (a
rejected one, or one naming another prereg) accounts for no item. With no `body.due`, items
are checked for a counted postreg and a status only (#4 and #5 do not apply), as `timely`
does not examine such a prereg.

**When empty:** if no commitment's prereg has a `body.items` with at least one entry (an
absent, `null` or empty `body.items` is not examined; one that is present but not an array
is, and fails #1), the test has nothing to examine and is `FAIL`, with the reason `requested
but no commitment lists items`. A [rejected pre-registration](#matching-postregs-to-commitments)
is no commitment, so its items are never read.

**Failure reasons:** a commitment fails with `items is not an array of objects with a string
id` (#1), `item ids repeat: '<id>'` (#2), `due is not a parseable ISO-8601 timestamp` (#4) or
`an item is not accounted for` (#3, #5). Each item's line in the report gives its status, or
`no counted postreg names it` or `no counted postreg for it has a status of reported, excluded
or blocked` (#3), or its status and `but not shown on time: its postreg is late`, `… its
postreg has no ceiling` or `… its postreg's ceiling does not verify` (#5).

**Does not establish:** that an item was carried out, or that its status is true (`reported`
and `excluded` are the signer's word); that the item list is the whole of what should have
been promised; that a postreg's evidence backs its status ([`content`](#content) checks only
that the evidence files are the ones named).

**Example** (a dropped item). `prereg.json` is signed with `--due 2099-01-01T00:00:00Z
--items '[{"id": "R1", "kind": "run"}, {"id": "R2", "kind": "run"}]'`, and `post-R1.json` with
`--fulfills prereg.json --item-id R1 --status reported --ceiling` (both with `--target "model
m via provider p"`); no postreg accounts for R2:

```console
$ asexec verify prereg.json post-R1.json --tests format,selfsig,chain,complete
```

Output (from `=== commitments ===` on), exit status `2`:

```
=== commitments ===
  [FULFILLED] prereg sha-256:4c78c886…
    signer       : sha-256:bc562700…
    due          : 2099-01-01T00:00:00Z
    postregs     : 1
    items        : 2
      ✓ R1: reported
      ✗ R2: no counted postreg names it

=== tests ===
  ✓ chain=PASS  (1/1 chain(s) ok)
  ✗ complete=FAIL  (1/1 commitment(s) failed)
  ✓ format=PASS  (2/2 manifest(s) ok)
  ✓ selfsig=PASS  (2/2 manifest(s) ok)
…
asexec-verify/1 chain=PASS complete=FAIL format=PASS selfsig=PASS
```

With a postreg for R2 as well (`--item-id R2 --status excluded --prev post-R1.json
--ceiling`), the items read `✓ R1: reported` and `✓ R2: excluded`, and `complete=PASS`. Under
a prereg whose `due` has passed when the ceilings were fetched, each item reads `✗ R1:
reported, but not shown on time: its postreg is late`, and `complete=FAIL`.

---

### `content`

Digests recomputed from the original artifacts: a manifest's subject, and the claim record's
plan and evidence.

A subject is an explicit list of files. Each entry names one file by its relative path under
`--artifacts` and carries its own `hash_alg`; there is no default algorithm, and a
body-level `body.hash_alg` (where asexec before 0.4.0 wrote it) is not read. Nothing hashes
a directory: to commit to a tree, list its files, or pack it (a tar, for example) and list
the archive. A prereg's `body.plan` (the plan document) is one entry of the same shape, and
a postreg's `body.evidence` a list of them, each checked the way a subject entry is. Their
`media_type`, `label` and `uri` are declared and not read (see
[TrustedDeclared](#trusteddeclared)). asexec never parses the plan or the evidence.

**Examines (\*)**
- `body.subject`
- `body.subject[].name`
- `body.subject[].hash_alg`
- `body.subject[].digest`
- `body.plan`
- `body.plan.name`
- `body.plan.hash_alg`
- `body.plan.digest`
- `body.evidence`
- `body.evidence[].name`
- `body.evidence[].hash_alg`
- `body.evidence[].digest`
- `--artifacts`

**Passes when all** (for each manifest that has a `body.subject`, a `body.plan` or a
`body.evidence`, and each entry: each entry of `body.subject` and of `body.evidence`, and
`body.plan` itself)
1. `body.subject` and `body.evidence`, where present, are non-empty arrays, `body.plan`,
   where present, is an object, and each entry is an object whose `name` is a string, whose
   own `hash_alg` is a string, and whose `digest[hash_alg]` is hex. An entry without a
   `hash_alg` fails here.
2. `hash_alg` is available in this install: `sha-256` always, `blake3` only if installed.
3. `name` is a relative path in normal form: segments separated by `/`, none of them empty,
   `.` or `..`, and no backslash. So an absolute name, `./a.txt`, `a//b.txt`, `a/`,
   `a/../b.txt` and `a\b.txt` fail, and one file has exactly one name on every system.
4. No other entry of the same list (`body.subject`, or `body.evidence`) has the same
   `name`. Each entry that shares its name fails. A file may be both a subject and evidence.
5. `name` resolved with symlinks against `--artifacts` is the `--artifacts` directory or
   beneath it. A symlink that points outside fails here.
6. The resolved path exists. A `name` that no path on this system can have (one holding a
   NUL, or a lone surrogate the filesystem cannot encode) names no artifact.
7. The resolved path is a regular file. A directory, or a FIFO, socket or device, fails and
   is never read. A listed symlink to a file is hashed as the bytes read through it.
8. The file is readable.
9. The recomputed digest of the file under `hash_alg` equals the bytes of
   `digest[hash_alg]`, in either hex case.

**When empty:** if `--artifacts` is not given or is empty (`--artifacts ""`), or no
manifest that passes `format` has a `body.subject`, a `body.plan` or a `body.evidence`, the
test has nothing to examine and is `FAIL`, with the reason `requested but no content could
be checked (need --artifacts and a manifest with a subject, plan or evidence)`.

**Entry failure reasons** (shown per entry in the report, after `plan` or `evidence` for
those entries), by item: `malformed subject entry`, `malformed plan entry` or `malformed
evidence entry` (or `malformed subject` or `malformed evidence` for a list that is no
non-empty array) (#1), `algorithm unavailable: <alg>` (#2), `name is not a normalized
relative path` (#3), `duplicate name` (#4), `path resolves outside --artifacts` (#5),
`artifact not found` (#6), `artifact is not a file` (#7), `artifact unreadable: <error>`
(#8), or a digest mismatch with `expected`/`actual` (#9).

**Not examined:** a manifest that fails `format`; any manifest when `--artifacts` is absent.

**Does not establish:** provenance. A match shows the artifact was not altered, not that it
is the output of the named harness and model.

**Example** (all requirements pass)

```console
$ asexec verify prereg.json --tests format,selfsig,content --artifacts artifacts
```

`artifacts/runs/transcript.txt` contains `hello` and a newline. `prereg.json` was signed
from the directory `artifacts` stands for, with `asexec prereg --subject
runs/transcript.txt …`. Its body (unexamined fields elided):

```jsonc
{
  "subject": [
    {
      "name": "runs/transcript.txt",
      "hash_alg": "sha-256",
      "digest": { "sha-256": "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03" }
    }
  ],
  …
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
- `body.anchor.floor.floor_type`
- `body.anchor.floor.chain_hash`
- `body.anchor.floor.round`
- `body.anchor.floor.signature`
- `body.anchor.floor.randomness`

**Passes when all**
1. `body.anchor.floor` is an object and `floor_type == "drand"`.
2. `chain_hash` is present and names a chain the verifier pins. An absent one (missing or
   `null`) fails: verify never picks a chain for a manifest.
3. `round` is an integer and `signature` is hex.
4. If `randomness` is present, it equals `sha256(signature)` in hex.
5. `signature` is a valid BLS12-381 signature over `sha256(round as 8-byte big-endian)`
   under that chain's pinned group public key: exactly 48 bytes, the compressed encoding of a
   point in G1. So a round has one valid signature, and one `randomness`.

**When empty:** if no manifest that passes `format` has a `body.anchor.floor`, the test
has nothing to examine and is `FAIL`, with the reason `requested but no manifest carries an
anchor.floor`.

**Not examined:** a manifest that fails `format`.

**Does not establish:** that the pre-registration preceded the run. A floor bounds
freshness (anti-precomputation), not backdating. [`order`](#order) compares a postreg's floor
with its prereg's ceiling.

**Example** (all requirements pass)

```console
$ asexec verify prereg.json --tests format,selfsig,floor
```

The body of `prereg.json` (unexamined fields elided):

```jsonc
{
  "anchor": {
    "floor": {
      "floor_type": "drand",
      "chain_hash": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
      "round": 33394706,
      "signature": "9791d98e2e577017…",
      "randomness": "8442c678de44756b…"         // = sha256(signature)
    }
  },
  …
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
- `dsse`
- `dsse.payloadType`
- `dsse.signatures` (only that it is an array)
- `dsse.payload`, and the body bytes it decodes to

**Passes when all**
1. The file can be read, and is a JSON object, nested at most 64 deep, with no duplicate
   keys, holding an object `dsse` that holds a string `dsse.payloadType` and an array
   `dsse.signatures`.
2. `dsse.payload` is a string of strict base64 (see [Base64](#conventions)), and the body
   bytes it decodes to are the UTF-8 JSON text of an object, held to the file's JSON rules
   on its own: nested at most 64 deep, counted from the body's own outermost object, with
   no duplicate keys.
3. `dsse.payloadType` names a format this release reads, compared exactly: in this release,
   `application/vnd.asexec.v1+json` (see [Formats](#conventions)). A file that names
   another format is never read under this one's rules instead. Such a file is held only to
   the part of #1 that comes before any format: it can be read, and is a JSON object,
   nested at most 64 deep, with no duplicate keys, holding an object `dsse` with a string
   `dsse.payloadType`. The rest of #1, and #2, are this format's rules, and a newer format
   may lay out the rest of its file differently. A file laid out as asexec wrote it before
   0.4.0 (no `dsse`, and a top-level `payloadType` of `application/vnd.asexec+json`, the
   type those releases wrote) also fails #3, with that format's reason.

A file that fails #1 or #2 is malformed, and one that fails #3 is of an unknown format (see
[Run rules](#conventions)). Either way no other test examines it. That is all `format`
judges: what `dsse.signatures` holds, and `pubkey`, are [`selfsig`](#selfsig)'s.

**Failure reasons** (shown under the file in the report):
- #1 and #2: `malformed: ` and what is wrong, naming the property. For example, a `dsse`
  that is absent (missing or `null`) is `malformed: dsse: Field required`, a
  `dsse.payloadType` that is absent is `malformed: dsse.payloadType: Field required` and one
  that is not a string `malformed: dsse.payloadType: Input should be a valid string`. A
  `dsse.payload` that is not strict base64 is `malformed: dsse.payload: Value error, not
  strict base64 (the standard alphabet, padded, no whitespace, one spelling per byte
  string)`. Body bytes that fail #2 are `malformed: body: ` and what is wrong, e.g.
  `malformed: body: duplicate JSON key 'phase'` or `malformed: body: the body must be a
  JSON object`.
- #3, by what `dsse.payloadType` names:
  - A format of asexec before 0.4.0, `application/vnd.asexec+json` (up to 0.3.20) or
    `application/vnd.asexec.0.3.N+json` (a later 0.3.x's own): `payloadType names
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

**Does not establish:** that the file has one valid signature (that is
[`selfsig`](#selfsig)), which also covers `dsse.payloadType`; that the body is a
well-formed asexec body (any JSON object passes, whatever it holds).

**Example** (all requirements pass)

```console
$ asexec verify prereg.json --tests format,selfsig
```

`prereg.json`, and the body its `dsse.payload` decodes to:

```jsonc
{
  "dsse": {
    "payloadType": "application/vnd.asexec.v1+json",
    "payload": "eyJwaGFzZSI6InByZXJlZyIsInByZWRpY2F0ZVR5cGUiOiJodHRwczovL2FzZXhlYy5vcmcvbWFu…",
    "signatures": [
      { "keyid": "sha-256:bc562700…", "sig": "eoFq/aI9/hpjhouo…" }
    ]
  },
  "pubkey": "91230c4e…"
}

// the body bytes it decodes to:
// {"phase":"prereg","predicateType":"https://asexec.org/manifest/v1","target":"model m via provider p"}
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
✓ prereg.json  [prereg]  keyid=sha-256:bc562700…
✗ truncated.json  [None]  keyid=None
    ✗ format: malformed: Unterminated string starting at: line 4 column 16 (char 82)
…
=== tests ===
  ✗ format=FAIL  (1/2 manifest(s) failed)
  ✓ selfsig=PASS  (1/1 manifest(s) ok)

asexec-verify/1 format=FAIL selfsig=PASS
```

Version skew: `postreg-v2.json` is `postreg-1.json` from the [`chain` example](#chain) with
its `dsse.payloadType` changed to `application/vnd.asexec.v2+json`, as a later release would
label its own files. It fails `format` with the upgrade reason, not as a bad signature, and
`selfsig` still passes for `prereg.json`. Its body is not read, so it shows no phase, and it
takes no part in the commitment, which has no counted postreg (and, as its prereg has no
`body.due`, is `no-due`). Exit status `2`:

```console
$ asexec verify prereg.json postreg-v2.json --tests format,selfsig
```

```
=== manifests ===
✓ prereg.json  [prereg]  keyid=sha-256:bc562700…
✗ postreg-v2.json  [None]  keyid=None
    ✗ format: payloadType names a format newer than this release: upgrade asexec to read it

=== untrusted (unsigned, and read by no test: nothing here was checked) ===
  prereg.json
    untrusted = {"asexec_version": "0.4.0"}

=== commitments ===
  [NO-DUE] prereg sha-256:b17107d0…
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
- `body.phase`
- `body.fulfills`
- `pubkey`
- `dsse.signatures`
- `dsse.signatures[0].sig`
- `dsse.signatures[0].keyid`

**Passes when all** (for each commitment with a counted postreg or a postreg rejected as
`signed by a different key than the pre-registration`; see
[Matching postregs to commitments](#matching-postregs-to-commitments))
1. Every postreg whose `body.fulfills` equals the commitment's `ref` and whose signature
   is valid (it meets the [`selfsig`](#selfsig) conditions) has the
   `dsse.signatures[0].keyid` of a commitment with that `ref`.

A postreg with an invalid signature is not judged here (it fails `selfsig`), so a commitment
whose only postregs have invalid signatures has no key to check and is not examined. A
[rejected pre-registration](#matching-postregs-to-commitments) is no commitment, so it is
never examined, and its `dsse.signatures[0].keyid`, which nothing authenticated, is
compared with no postreg's.

**When empty:** if no validly signed postreg names a commitment (its `body.fulfills` is
the `ref` of no commitment; a postreg that names only rejected pre-registrations names
none), the test has nothing to examine and is `FAIL`, with the reason `requested but no
validly signed postreg names a commitment`.

**Example** (all requirements pass)

```console
$ asexec verify prereg.json postreg.json --tests format,selfsig,keyconsist
```

The two files' bodies (unexamined fields elided). Both have `dsse.signatures[0].keyid`
`sha-256:bc562700…`, the prereg's:

```jsonc
// prereg.json: ref = sha-256:b17107d0…
{ "phase": "prereg", … }

// postreg.json
{ "phase": "postreg", "fulfills": "sha-256:b17107d0…", … }
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

### `order`

Whether each postreg that counts toward a commitment is shown to have been made after its
prereg existed: the prereg's ceiling precedes the floor of each counted postreg.

A postreg is **counted** for a prereg if it meets the
[conditions for counting](#matching-postregs-to-commitments). The prereg's **ceiling time**
Tc is the later end of the interval its Roughtime witness signed, `SREP.MIDP + SREP.RADI` of
the verified `ceiling.response`, as for [`timely`](#timely): the prereg existed no later than
Tc. A postreg's **floor time** Tf is the time of its drand round on the pinned chain, the
chain's genesis plus `round - 1` periods (quicknet: genesis `1692803367`, a period of 3
seconds): the round's signature was not known before Tf, so the postreg was made no earlier
than Tf. Neither is ever taken from what the file states about time (`ceiling.midpoint` and
`ceiling.radius` are not signed, and a floor holds no time). If Tc is before Tf, the prereg
existed before the postreg was made.

**Examines (\*)**
- `ceiling.ceiling_type`, `ceiling.nonce`, `ceiling.witness_id`, `ceiling.pubkey`,
  `ceiling.response` and `dsse.payload` (the [`ceiling`](#ceiling) conditions), of the prereg
- `body.phase`, `body.fulfills`, `pubkey`, `dsse.signatures`, `dsse.signatures[0].sig`,
  `dsse.signatures[0].keyid` (which postregs are counted)
- `body.anchor.floor.floor_type`, `body.anchor.floor.chain_hash`, `body.anchor.floor.round`,
  `body.anchor.floor.signature` and `body.anchor.floor.randomness` (the [`floor`](#floor)
  conditions), of each counted postreg

**Passes when all** (for each commitment that has at least one counted postreg)
1. The prereg has a `ceiling`.
2. That ceiling meets the [`ceiling`](#ceiling) conditions (#1 to #5). A ceiling that fails
   one is no time at all, since anyone can write one, so the commitment fails as if it had
   none.
3. Each counted postreg has a `body.anchor.floor`.
4. That floor meets the [`floor`](#floor) conditions (#1 to #5): a pinned chain, an integer
   round, `randomness` equal to `sha256(signature)`, and a BLS signature for that round under
   the pinned key. A floor that fails one is no time at all: a postreg claiming a later round
   than the one its signature is for fails here.
5. Tc is strictly before Tf, for each counted postreg. Both are compared exactly, in whole
   microseconds since the epoch (`MIDP` and `RADI` are signed integers in microseconds, and Tf
   is whole seconds), so a ceiling time equal to the floor's does not precede it.

The prereg is identified by its `ref` and signer: if several copies of a commitment's prereg
are given, its time is the earliest Tc among the copies whose ceiling meets #2, and a copy
with no ceiling, or a later one, does not undo it. A counted postreg's floor is in its body,
so every copy of it carries the same floor.

A postreg that is not shown after its prereg still counts: its commitment stays `fulfilled`
(see [Commitment states](#commitment-states)), and `order=FAIL` carries the verdict.

**When empty:** if no commitment has a counted postreg, the test has nothing to examine and
is `FAIL`, with the reason `requested but no commitment has a counted postreg`. A commitment
with no counted postreg is not examined (its state says it was not reported). A
[rejected pre-registration](#matching-postregs-to-commitments) is no commitment, so neither
its ceiling nor the floors of the postregs naming it are read.

**Failure reasons:** a commitment fails with `the pre-registration has no ceiling` (#1), `the
pre-registration's ceiling does not verify` (#2) or `a counted postreg is not shown after the
pre-registration` (#3 to #5). With `order` requested, the report marks under the commitment
a prereg whose ceiling gives no time, `the pre-registration is not shown before its postregs:
it has no ceiling` (#1) or `… its ceiling does not verify` (#2), and each counted postreg not
shown after it: `is not shown after the pre-registration: it has no floor` (#3), `… its floor
does not verify` (#4), or `… its floor (no earlier than <Tf>) is not after the
pre-registration's ceiling (no later than <Tc>)` (#5; Tf rounded down and Tc rounded up to the
second).

**Does not establish:** when the run happened. It shows that the prereg existed before each
postreg was made, no more. A postreg signed with `--floor` carries the round current when it
was signed, which orders the postreg, not the run, after the prereg. A run that fetches a
round when it starts, and is signed with it (`asexec postreg --floor-round`), is bounded by
it only as tightly as the run's use of that round: a round the run merely records proves
nothing about when the run started, while one it uses (as its seed, say) lets a re-execution
check it. The signer also chooses the round: any real round after Tc passes, and a round's
randomness is public once it exists, so a seed taken from it can be picked for a favourable
result, by trying many rounds. Nor does it establish when the prereg was made, only that it
existed by Tc. Passing
trusts the Roughtime witness about Tc (see `ceiling`'s trust class) and drand about Tf.

**Example** (all requirements pass). `prereg.json` is signed with `--target "model m via
provider p" --ceiling`, its witness signing a time just before quicknet round 1000. The run
saved round 1000 as drand's HTTP API returned it, to `round.json`, and `postreg.json` is
signed with `--fulfills prereg.json --floor-round-file round.json`:

```console
$ asexec verify prereg.json postreg.json --tests format,selfsig,order
```

Output (from `=== tests ===` on), exit status `0`:

```
=== tests ===
  ✓ format=PASS  (2/2 manifest(s) ok)
  ✓ order=PASS  (1/1 commitment(s) ok)
  ✓ selfsig=PASS  (2/2 manifest(s) ok)

=== ceiling trust (what you are accepting) ===
  - prereg.json: ceiling witnessed by … at … (±…s), so no later than 2023-08-23T15:59:01Z - you are trusting …

asexec-verify/1 format=PASS order=PASS selfsig=PASS
Checked at 2026-12-31T23:59:59Z
```

With a prereg signed with `--due 2099-01-01T00:00:00Z` as well (so another body, with
another `ref`) and a ceiling fetched later (here, three months after the round), the run's
floor precedes the prereg's ceiling. The postreg still counts, so the commitment is
`fulfilled`, and the report marks it. Exit status `2`:

```
=== commitments ===
  [FULFILLED] prereg sha-256:b74ae2db…
    signer       : sha-256:bc562700…
    due          : 2099-01-01T00:00:00Z
    postregs     : 1
    ✗ postreg sha-256:cf9877b8… is not shown after the pre-registration: its floor (no earlier than 2023-08-23T15:59:24Z) is not after the pre-registration's ceiling (no later than 2023-11-14T22:13:21Z)

=== tests ===
  ✓ format=PASS  (2/2 manifest(s) ok)
  ✗ order=FAIL  (1/1 commitment(s) failed)
  ✓ selfsig=PASS  (2/2 manifest(s) ok)
…
asexec-verify/1 format=PASS order=FAIL selfsig=PASS
```

---

### `selfsig`

Whether the file is unchanged since its own key signed it. Required in every run.

`selfsig` is self-certifying: the file carries its own `pubkey`, so a pass means only that
whoever holds that key signed these bytes, and that they have not changed since. Nothing is
pinned, and verify keeps no state between runs. Trust comes from the other layers:
[`keyconsist`](#keyconsist) gives key continuity within one claim, and
[`ceiling`](#ceiling) pins when the prereg was signed.

**Examines (\*)**
- `dsse.payloadType` (it is in the signing input, and names the format whose rules apply)
- `dsse.payload` (the body bytes)
- `dsse.signatures`
- `dsse.signatures[0].sig`
- `dsse.signatures[0].keyid`
- `pubkey`

**Passes when all** (for each manifest that passes [`format`](#format), under the rules of
its format)
1. `dsse.signatures` holds exactly one entry, and it is an object. None, two (even two
   copies of one valid signature) and an entry that is not an object fail.
2. `pubkey` is present and hex (see [Hex](#conventions)), and `dsse.signatures[0].sig` is
   present and strict base64 (see [Base64](#conventions)) of 64 bytes, an ed25519
   signature's length. A hex `sig`, a `sig` in URL-safe base64 or with whitespace, and one
   of another length fail.
3. `dsse.signatures[0].sig` is a valid ed25519 signature by `pubkey` over the PAE signing
   input of the file's `dsse.payloadType` and its body bytes, exactly as stored:
   `DSSEv1 SP len(type) SP type SP len(body) SP body`.
4. `dsse.signatures[0].keyid == "sha-256:" + sha256(bytes.fromhex(pubkey)).hexdigest()`,
   where `sha-256:` is the format's prefix. A missing `keyid` fails.

**When empty:** if no manifest passes `format` (including when no manifest file is found),
`selfsig` has nothing to examine and is `FAIL`, with the reason
`no manifest passes format`.

**Not examined:** a manifest that fails `format`.

A prereg that passes `format` but fails `selfsig` is a
[rejected pre-registration](#matching-postregs-to-commitments), not a commitment.

**Does not establish:** who signed (internal consistency only). A body changed and
re-signed with another key, under that key's `keyid`, passes.

**Example** (a body edited after signing). `tampered.json` is `postreg-1.json` from the
[`chain` example](#chain) with its `body.target` changed afterwards: the body decoded,
edited, and stored again as `dsse.payload`, with the old signature kept:

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

### `timely`

Whether each postreg that counts toward a commitment is shown to have existed by the
prereg's `due`.

A postreg is **counted** for a prereg if it meets the
[conditions for counting](#matching-postregs-to-commitments). Its **ceiling time** T is the
later end of the interval its Roughtime witness signed: `SREP.MIDP + SREP.RADI` of the
verified `ceiling.response`, the "no later than" time the ceiling trust block reports
(`midpoint ± radius`). It is never taken from the file's own `ceiling.midpoint` and
`ceiling.radius`, which nothing signs.

**Examines (\*)**
- `body.due` (of the prereg)
- `body.phase`, `body.fulfills`, `pubkey`, `dsse.signatures`, `dsse.signatures[0].sig`,
  `dsse.signatures[0].keyid` (which postregs are counted)
- `ceiling.ceiling_type`, `ceiling.nonce`, `ceiling.witness_id`, `ceiling.pubkey`,
  `ceiling.response` and `dsse.payload` (the [`ceiling`](#ceiling) conditions), of each
  counted postreg

**Passes when all** (for each commitment whose prereg has a `body.due` and that has at
least one counted postreg)
1. `body.due` is a parseable ISO-8601 string. One without a UTC offset or `Z` is read as
   UTC, as for [commitment states](#commitment-states).
2. Each counted postreg has a `ceiling`.
3. That ceiling meets the [`ceiling`](#ceiling) conditions (#1 to #5): its type, a nonce
   equal to the postreg's `ref`, a pinned witness and a response that verifies. A ceiling
   that fails one is no time at all, since anyone can write one, so it is treated as no
   ceiling: never as on time.
4. Its ceiling time T is at or before `body.due`. Both are compared exactly, in whole
   microseconds since the epoch (`MIDP` and `RADI` are signed integers in microseconds, and
   `due` is read to the microsecond), so a `due` equal to T is on time.

A postreg is identified by its `ref`: if several copies of one counted postreg are given, it
is on time when any counted copy carries a ceiling that meets #3 and #4, and its time is the
earliest such T.

A late postreg still counts: its commitment stays `fulfilled` (see
[Commitment states](#commitment-states)), and `timely=FAIL` carries the verdict. States say
whether a commitment was reported, and `timely` says whether on time.

**When empty:** if no commitment has both a `body.due` and a counted postreg, the test has
nothing to examine and is `FAIL`, with the reason `requested but no commitment with a due
has a counted postreg`. A commitment whose prereg has no `body.due` is not examined, so one
open-ended claim does not fail `timely` for a whole run; one with a `due` and no counted
postreg is not examined either (its state, `open`, `elapsed-no-postreg` or `invalid-due`,
says it was not reported). A [rejected pre-registration](#matching-postregs-to-commitments) is no
commitment, so its `due` is never read.

**Failure reasons:** a commitment fails with `due is not a parseable ISO-8601 timestamp`
(#1) or `a counted postreg is not shown on time` (#2 to #4). With `timely` requested, the
report marks each counted postreg not shown on time, under its commitment: `is late: its
ceiling (no later than <T>) is after due` (#4; T rounded up to the second, or as epoch
seconds if it has no ISO-8601 form), `is not shown on time: it has no ceiling`
(#2), or `is not shown on time: its ceiling does not verify` (#3). An unparseable `due` is
flagged under its commitment in every state.

**Does not establish:** when the postreg was created, only that it existed by T. A ceiling
fetched after `due` for a postreg created before it fails, because the ceiling is the only
evidence of time. Nor that every promised postreg was made: states show a commitment with
none, and [`complete`](#complete) checks each item.

**Example** (all requirements pass). `prereg.json` is signed with `--target "model m via
provider p" --due 2099-01-01T00:00:00Z`, and `postreg.json` with `--fulfills prereg.json
--ceiling`:

```console
$ asexec verify prereg.json postreg.json --tests format,selfsig,timely
```

Output (from `=== commitments ===` on), exit status `0`:

```
=== commitments ===
  [FULFILLED] prereg sha-256:b74ae2db…
    signer       : sha-256:bc562700…
    due          : 2099-01-01T00:00:00Z
    postregs     : 1

=== tests ===
  ✓ format=PASS  (2/2 manifest(s) ok)
  ✓ selfsig=PASS  (2/2 manifest(s) ok)
  ✓ timely=PASS  (1/1 commitment(s) ok)

=== ceiling trust (what you are accepting) ===
  - postreg.json: ceiling witnessed by … at … (±…s), so no later than … - you are trusting …

asexec-verify/1 format=PASS selfsig=PASS timely=PASS
Checked at 2026-12-31T23:59:59Z
```

Signed the same way but with `--due 2000-01-01T00:00:00Z`, the postreg is late. It still
counts, so the commitment is `fulfilled`, and the report marks it. Exit status `2`:

```
=== commitments ===
  [FULFILLED] prereg sha-256:daa96b3a…
    signer       : sha-256:bc562700…
    due          : 2000-01-01T00:00:00Z
    postregs     : 1
    ✗ postreg sha-256:5006f81b… is late: its ceiling (no later than …) is after due

=== tests ===
  ✓ format=PASS  (2/2 manifest(s) ok)
  ✓ selfsig=PASS  (2/2 manifest(s) ok)
  ✗ timely=FAIL  (1/1 commitment(s) failed)
…
asexec-verify/1 format=PASS selfsig=PASS timely=FAIL
```

---

## Matching postregs to commitments

Three terms, each narrower than the one before:
- A **provided prereg** is a prereg among the files given that passes [`format`](#format). A
  prereg that fails `format` (malformed, or of an unknown format) is not a provided prereg:
  nothing can be said about what it names, so a postreg that names it is notarization-only.
- A **commitment** is a provided prereg that also meets the [`selfsig`](#selfsig)
  conditions, identified by its `ref` together with its signer, `dsse.signatures[0].keyid`.
  The body
  holds no key, so the same body signed by two keys has one `ref` but is two commitments,
  each judged on its own.
- A **rejected pre-registration** is a provided prereg that fails a `selfsig` condition: it
  has other than exactly one signature, its `pubkey` is missing or not hex, its `sig` is
  missing or not strict base64 of 64 bytes, its
  signature does not verify, or its `dsse.signatures[0].keyid` does not derive from its
  `pubkey`. So nothing authenticated the keyid it claims, its `dsse.signatures[0].keyid`
  (absent if it has no signature entry). It is no commitment: it
  has no [state](#commitment-states), no postreg counts toward it, and `chain` and
  `keyconsist` never examine it, so no state and no `chain` or `keyconsist` result rests on
  its keyid. It is listed under its own heading, *rejected pre-registrations*, with the
  reason `invalid signature`. Of the tests, it fails only `selfsig`. With no commitment,
  `chain` and `keyconsist` may then have nothing to examine, and so be empty and `FAIL`, as
  in the example below.

| Prereg situation | `format` | `selfsig` | Outcome | In the report |
|---|---|---|---|---|
| Malformed, or of an unknown format | `FAIL` | not examined | not a provided prereg | the manifests block only; a postreg naming it is notarization-only |
| Passes `format`, fails a `selfsig` condition | `PASS` | `FAIL` | a **rejected pre-registration**: no commitment, no state | *rejected pre-registrations*, with `invalid signature` |
| Passes `format` and `selfsig` | `PASS` | `PASS` | a **commitment** | *commitments*, with its state |

A postreg `P` **counts** toward the commitment of prereg `R` iff all hold:
1. `P.body.phase == "postreg"` and `P.body.fulfills == ref(R)`.
2. `P` meets the [`selfsig`](#selfsig) conditions.
3. `P.dsse.signatures[0].keyid == R.dsse.signatures[0].keyid`.
4. `R` meets the [`selfsig`](#selfsig) conditions: `R` is a commitment, not a rejected
   pre-registration. This is condition 2 for the prereg, so a postreg is never matched to
   a keyid that nothing authenticated.

A commitment is keyed by its signer, so a postreg counts toward at most one commitment: the
one with its `body.fulfills` as `ref` and its own `dsse.signatures[0].keyid` as signer. A
copy of a prereg that fails `selfsig` is a rejected pre-registration even when it claims
the commitment's own `dsse.signatures[0].keyid`, so it never merges into that commitment,
and one that claims another key's `dsse.signatures[0].keyid` does not make that key a
signer.

A postreg that names a provided prereg (condition 1) but counts toward no commitment with
that `ref` is **rejected**. It is left out of fulfillment and of `chain`, and is listed with
the reason it fails there:
- under each commitment with that `ref`: `invalid signature` (condition 2) or `signed by a
  different key than the pre-registration` (condition 3);
- under each rejected pre-registration with that `ref`: `the pre-registration's signature is
  invalid` (condition 4), whatever the postreg's own signature. Its keyid is compared with
  nothing there, so this rejection never fails `keyconsist`.

A postreg that counts toward one commitment of a `ref` is not rejected under the others, nor
under the rejected pre-registrations of that `ref`. If one prereg body is signed by keys A
and B, a postreg signed by A counts toward A's commitment and is not listed under B's. If
the same body also comes as a copy whose signature is broken, the postreg is not listed
under the copy either.

A postreg that fails condition 1 for every provided prereg names none of them. It is
**notarization-only**: there is no commitment to list it under, so it has no
[state](#commitment-states) and is listed in its own block, whether or not its signature is
valid. A postreg that names only rejected pre-registrations does name a provided prereg, so
it is not notarization-only: it is rejected under each of them.

**In summary**, by kind of postreg:

| Postreg situation | `format` | `selfsig` | Outcome | In the report |
|---|---|---|---|---|
| Malformed, or of an unknown format (see [Run rules](#conventions)) | `FAIL` | not examined | none: not treated as a postreg | not listed under any commitment |
| Passes `format`, fails a `selfsig` condition, `fulfills` a commitment's `ref` | `PASS` | `FAIL` | not counted: `invalid signature` | **rejected** |
| Valid signature by a key that signed no commitment with that `ref`, `fulfills` a commitment's `ref` | `PASS` | `PASS` | not counted: `signed by a different key than the pre-registration` | **rejected**; also fails `keyconsist` |
| Valid signature by the key of a commitment with that `ref` | `PASS` | `PASS` | **counted** toward that commitment | listed as a counted postreg of that commitment only |
| Passes `format`, counts toward no commitment, `fulfills` the `ref` of a rejected pre-registration | `PASS` | `PASS` if the signature is valid, else `FAIL` | not counted: `the pre-registration's signature is invalid` | **rejected** under each rejected pre-registration of that `ref` (and under each commitment of it, as in the rows above) |
| Passes `format`, `fulfills` matches no provided prereg | `PASS` | `PASS` if the signature is valid, else `FAIL` | not counted: names no provided prereg | **notarization-only** |

**What affects a verdict.** Only the tests produce `PASS` or `FAIL`. *Counted* matters
because `chain` examines counted postregs only. `keyconsist` fails a commitment only for a
postreg rejected under it as `signed by a different key than the pre-registration`; a
counted postreg, one rejected for `invalid signature`, one rejected under a rejected
pre-registration and a notarization-only postreg never fail it, and a commitment whose
postregs all have invalid signatures is not examined. *Rejected*, *rejected
pre-registration* and *notarization-only* are only groupings in the report and add no
failure of their own. The failures in the postreg table come from `format` (the first row),
`selfsig` (the second row, and the last two rows when the signature is invalid) and
`keyconsist` (the third row). A rejected pre-registration fails `selfsig`; it may also leave
`chain` and `keyconsist` empty, since it is no commitment.

A manifest is identified by its `ref`. Copies of a postreg, with the same `ref` and
`dsse.signatures[0].keyid`, are listed once per outcome, however many are provided. Copies
usually share an outcome, so they are counted, rejected or notarization-only once. A copy
whose signature does not verify is judged on its own: it fails `selfsig` and, if it names a
commitment, is listed as rejected for `invalid signature` beside the valid copy's outcome
(so a broken copy of a counted postreg shows the same `ref` as counted and as rejected).
Copies of a prereg, with the same `ref` and `dsse.signatures[0].keyid`, are one commitment
if they meet the `selfsig` conditions. A copy that does not is judged on its own, as a rejected
pre-registration beside the commitment. Copies of a rejected pre-registration, with the
same `ref` and `dsse.signatures[0].keyid`, are listed once, however each is broken.

**Example** (a rejected pre-registration). `prereg-badsig.json` is `prereg.json` from the
[`chain` example](#chain) with one byte of `dsse.signatures[0].sig` changed, checked with
the two postregs that name it. A prereg with two signatures, or none, or no `pubkey`, reads
the same way:

```console
$ asexec verify prereg-badsig.json postreg-1.json postreg-2.json --tests format,selfsig,chain,keyconsist
```

Output (from `=== commitments ===` on), exit status `2`:

```
=== commitments ===
  (no commitments: no pre-registration provided is validly signed)

=== rejected pre-registrations ===
  ✗ prereg sha-256:b17107d0… is NOT a commitment: invalid signature
    keyid        : sha-256:bc562700…
    ✗ postreg sha-256:da0adf83… does NOT count toward fulfillment: the pre-registration's signature is invalid
    ✗ postreg sha-256:ae569ef2… does NOT count toward fulfillment: the pre-registration's signature is invalid

=== tests ===
  ✗ chain=FAIL  (requested but no commitment has counted postregs to chain-check)
  ✓ format=PASS  (3/3 manifest(s) ok)
  ✗ keyconsist=FAIL  (requested but no validly signed postreg names a commitment)
  ✗ selfsig=FAIL  (1/3 manifest(s) failed)

asexec-verify/1 chain=FAIL format=PASS keyconsist=FAIL selfsig=FAIL
Checked at 2026-12-31T23:59:59Z
```

## Commitment states

One per commitment, shown in the `=== commitments ===` block of the report (see
[Output](#output)). Never part of the verify code, and never affects the exit status.

| State | Condition |
|---|---|
| `fulfilled` | at least one counted postreg, on time or not (that is [`timely`](#timely)'s) |
| `no-due` | no counted postreg, and `body.due` is absent: it can never elapse |
| `open` | no counted postreg, and `body.due` is present and in the future |
| `elapsed-no-postreg` | no counted postreg, and `body.due` is at or before now |
| `invalid-due` | no counted postreg, and `body.due` is present but not a parseable ISO-8601 string |

A [notarization-only](#matching-postregs-to-commitments) postreg belongs to no commitment,
so it has no state, and a
[rejected pre-registration](#matching-postregs-to-commitments) is no commitment, so it has
none either.

A `body.due` without a UTC offset or `Z` is read as UTC, never in the verifier's local
timezone, and is flagged in the report. Whether a counted postreg came before `due` is not a
state: a late postreg still makes its commitment `fulfilled`, and [`timely`](#timely) is the
test that judges it.

**Example** (`fulfilled`). A prereg signed with `--due 2099-01-01T00:00:00Z`, and two
chained postregs as in the [`chain` example](#chain):

```
=== commitments ===
  [FULFILLED] prereg sha-256:b74ae2db…
    signer       : sha-256:bc562700…
    due          : 2099-01-01T00:00:00Z
    postregs     : 2
```

Each entry is the state in capitals and the prereg's `ref`, then its signer's keyid, `due`
(or `(none declared)`) and the number of counted postregs. Problems follow as `✗` lines: a
`due` without a timezone, an unparseable `due` (in any state), a chain problem (on the
`postregs` line), with `timely` requested each counted postreg not shown on time, with
`order` requested a prereg whose ceiling gives no time and each counted postreg not shown
after it, or a rejected postreg and why it does not count. If the prereg lists items, an `items` line
follows, with one line per item: `✓` and its status, or `✗` and why
[`complete`](#complete) does not count it as accounted for.
[`notarization-only`](#matching-postregs-to-commitments) postregs are listed in their own
block, since they have no prereg to sit under.

## TrustedDeclared

Signed properties that the report may show but no test reads. "Trusted" means only that the
signer is accountable for them, not that they are true; a passing code says nothing about
them. A declaration that gains a test moves to that test's *Examines* list.

The claim record's (ROADMAP, *New properties*):
- `body.plan.media_type`: the plan document's media type.
- `body.plan.label`: a human-readable name for the plan.
- `body.items[].kind`: what kind of item it is (a run, an ablation, a search), free text.
- `body.evidence[].media_type`: an evidence file's media type.
- `body.evidence[].uri`: where an evidence file can be fetched, if anywhere. `content`
  hashes the file at `name` under `--artifacts`, never what `uri` names.

The claim record's `body.items[].id`, `body.item_id` and `body.status` are read by
[`complete`](#complete).

## Untrusted

What a file holds that nothing checks, and how the report shows it.

**`untrusted`** is an optional member of the file, beside `dsse`, `pubkey` and `ceiling`: a
section for metadata that nothing checks. Signing writes `untrusted.asexec_version`, the
asexec release that wrote the file, for diagnostics only. It is outside the body, so it is
neither signed nor part of `ref` (the digest of the body bytes), and anyone can edit it after
signing: that is what it is for. Unsigned is not the same as untrusted: `ceiling` and
`pubkey` are unsigned too, but checked, by the witness's signature and by `selfsig` #4.
`untrusted` is the one section of the file that nothing checks. (The ceiling's own
`ceiling.midpoint` and `ceiling.radius` are unsigned and not read either: they only restate
the signed response, whose `MIDP` and `RADI` every test and the report read instead.) Its
tier is *Untrusted* (ROADMAP, *Three trust tiers*).
- No test reads `untrusted`, and it is never part of `ref` or the code. It may hold any value
  the file's [JSON](#conventions) rules accept, of any type and size: none makes a file
  malformed or changes a result.
- It is part of the file, so the file's JSON rules hold inside it as everywhere: a duplicate
  key in it, nesting that takes the file past 64 deep, or an integer of more than 4,300
  digits (Python's default limit for reading one) makes the whole file malformed, as it would
  anywhere in the file. That is `format`'s rule about reading the file, not a reading of
  `untrusted`.
- An `untrusted` that is absent (missing or `null`) is not shown.

**Unknown keys outside the body.** A key outside the body that this format does not define is
treated like `untrusted`: unsigned, read by no test, and shown with it. The keys this format
defines outside the body are `dsse` (`dsse.payloadType`, `dsse.payload` and
`dsse.signatures`, each entry `keyid` and `sig`), `pubkey`, `ceiling` (`ceiling_type`,
`witness_id`, `pubkey`, `nonce`, `midpoint`, `radius`, `response`) and `untrusted` (shown
whole). Any other key, at the top level or inside `dsse`, a signature entry or `ceiling`, is
an unknown key (for example a top-level `payloadType`, as asexec wrote before 0.4.0, or
`dsse.signatures[0].alg`).

**Unknown fields.** A body field this format does not define is shown as unknown and
unchecked, never dropped. It is signed, so the signer is accountable for it, but no test
reads it, and a passing code says nothing about it. The fields this format defines are those
the asexec writer can write: `body.predicateType`, `phase`, `target`, `due`, `declaration`,
`subject` (each entry `name`, `hash_alg`, `digest`), `fulfills`, `prev_hash`, `plan`
(`name`, `hash_alg`, `digest`, `media_type`, `label`), `items` (each `id`, `kind`),
`item_id`, `status`, `evidence` (each entry `name`, `hash_alg`, `digest`, `media_type`,
`uri`), `anchor` (`anchor.floor`: `floor_type`, `chain_hash`, `round`, `signature`,
`randomness`), `provenance`, `repro_recipe` and `notes`.
- An unknown field is listed at the top of the body or inside an object the format defines,
  or an object in an array of them: an extra key in a subject entry (`body.subject[0].colour`),
  in `body.anchor` or `body.anchor.floor`, in the plan, an item or an evidence entry. A
  body-level `body.hash_alg` (where asexec before 0.4.0 wrote it) is an unknown field, and so
  is `body.identity`, which earlier writers accepted.
- What a free-form field holds (`target`, `declaration`, `notes`, `repro_recipe`, and a
  `digest` object, keyed by algorithm) is its value, not fields: nothing in it is listed.
- A field the format defines that holds a value of the wrong shape (a `body.subject` that is
  not an array, say) is judged by the tests that examine it, and nothing inside it is listed.
- A field whose value is `null` is absent, and is not listed.

Both are shown only for a file that passes [`format`](#format): no other file is read past
`format`. Each is shown under its own heading after the manifests block (see
[Output](#output)), one line per path, with the file's path above them. A path is written as
this document writes paths (`body.subject[0].colour`), with any key that is not a plain name
shown as JSON (`body["a b"]`). Each value is shown as one line of JSON in ASCII, every
newline, control character and non-ASCII character escaped: `untrusted` and unknown fields
are the least checked text in a file, and so cannot forge a line of the report.

**Example.** `prereg.json` from the [`chain` example](#chain), re-signed with a body field
`colour`, and edited after signing to add `untrusted.host` and a top-level `surprise`:

```console
$ asexec verify prereg.json --tests format,selfsig
```

Output (the two blocks), exit status `0`, with the code it gives without them:

```
=== untrusted (unsigned, and read by no test: nothing here was checked) ===
  prereg.json
    untrusted = {"asexec_version": "0.4.0", "host": "ci-7"}
    surprise = [1, null]

=== unknown fields (signed, but this format does not define them: nothing here was checked) ===
  prereg.json
    body.colour = "red"
…
asexec-verify/1 format=PASS selfsig=PASS
```

## Not in this version

`signer` is planned for 0.4.0, and `continuity` is
deferred to 0.7.0 or later (see [`ROADMAP.md`](../ROADMAP.md)). Adding a test name never
changes the meaning of an existing code. From 0.4.0, changing the documented meaning of an
existing name bumps the code grammar (`asexec-verify/N`); 0.4.0 itself keeps `/1`.

What a passing code does not establish is stated under each test (*Does not establish*)
and summarized in the [README](../README.md#what-does-asexec-prove).
