# Design: strict input models for the verifier

Status: implemented (this PR). Follows PR #13 (verify test reorganization). Target: 0.3.16.

## Problem

The verifier reads manifests as raw dicts and checks their shape by hand, condition by
condition. Two consequences:

- **Shape bugs slip through.** Both bugs fixed in #13 were type errors the hand-written
  checks missed: `anchor.floor.round` was coerced with `int()` (so `"1000"` and `1000.7`
  verified as round 1000), and a non-string `payload.prev_hash` crashed `chain` or, if
  falsy, counted as a chain root.
- **Two code paths describe one schema.** Writer models in `models.py` define what this
  tool produces; the verifier separately re-derives what it accepts.

The writer models also have the same coercion bug today: `models.Floor(round="1000").round
== 1000`, because pydantic's default (lax) mode coerces.

## Goals

1. Every *structural* "Passes when all" condition in `docs/VERIFICATION.md` is a field type
   or validator on a strict pydantic **input model**, not hand-written code.
2. Malformed input stays a test failure, never an exception (the doc's Result rule).
3. **Black-box refactor.** The `tests/verify/` suite tests the contract in
   `VERIFICATION.md` through `verify_paths` and the CLI, and does not know which module
   decides what. Apart from the intended changes below, the refactor does not change any
   test assertion.
4. **No verdict changes** for any input except those listed under Behavior changes, each of
   which brings behavior in line with the doc. The code grammar stays `asexec-verify/1`.

## Non-goals

- Moving crypto or filesystem checks into models (signatures, keyid derivation, BLS,
  Roughtime, path resolution, existence, readability, digests). These are facts about the
  world, not shapes; they stay as code that runs on already-parsed inputs.
- **Failure reasons.** Reason wording, verbose output and its schema are issue #8. This
  design neither specifies nor relies on reason strings. The reasons `VERIFICATION.md`
  documents are contract and are kept verbatim; every other reason is unspecified, and
  this refactor may change it.
- Changing the report shape or CLI output format.

## Design

### 1. Ownership

**A model decides whether one slice of JSON is well-formed. The verifier decides
everything else, including every verdict.** A model never returns PASS or FAIL: it returns
a parsed object or raises `ValidationError`, which the verifier turns into a FAIL.

| Owner | Owns |
|---|---|
| Input models (`models.py`, `types.py`) | Conditions decidable from one slice alone: types, required fields, literals, hex format, membership in constants fixed at import time |
| Domain modules (`keys`, `drand`, `roughtime`, `hashing`) | Cryptographic and digest checks on parsed values |
| Verifier (`verifier.py`) | Run rules (examined / absent / vacuous, malformed files); slicing and parsing; checks across slices (ceiling #2), across manifests (`chain`, `keyconsist`, counting rule), and on the run or install (ceiling #3 pin lookup, content #2–#6); verdicts and the code |

How the rule sorts the borderline cases:

- **Pinned chain vs pinned witness.** Floor #2 is a model type (`PinnedChain`) because
  `drand.CHAINS` is a constant. The ceiling #3 witness lookup stays in the verifier because
  the witness map is a `verify_paths` parameter (section 5).
- **Absence is a Run-rules question**, so the verifier owns it (section 3). Models never
  see a missing slice.
- **`due`** is checked as a string by its model. The ISO-8601 parse stays in the verifier,
  because it also produces the naive-timezone flag the commitment states use.

### 2. Two model families, shared field types

| | Writer models (exist) | Input models (new) |
|---|---|---|
| Purpose | gate what this tool writes | parse what the verifier reads |
| `extra` | `forbid` (a stray field is a caller bug) | `allow` (a future field must never break offline verification) |
| `strict` | **`True`** (new; fixes writer coercion) | `True` |
| Used by | `manifest.build_*`, CLI | `verifier` |

They share constrained field types from a new `asexec/types.py`, so a constraint is
written once:

```python
StrictInt = Annotated[int, Strict()]  # floor #3; rejects bool, "1000", 1000.7
Hex = Annotated[str, AfterValidator(_fromhex_ok)]  # accepts exactly what bytes.fromhex accepts
Ref = str  # links are compared by string equality, not parsed (chain #2)
```

- **`Hex` keeps today's acceptance set**: upper or lower case, ASCII whitespace between
  byte pairs, even length. It stays a `str` (it is not converted to bytes) so string
  comparisons such as floor #4's `randomness` check behave as today. Strict lowercase
  (`^(?:[0-9a-f]{2})*$`) is a 0.4.0 change.
- **No `ge=1` on `round`.** Floor #3 says "is an integer", and the model enforces exactly
  that. Rounds below 1 already fail BLS (#5).

Where a writer model and an input model describe the same slice (e.g. the floor), the
writer model subclasses the input model with `extra="forbid"`. One class per slice, one
config difference. Today's writer `Floor` uses `extra="allow"` "to keep future beacon
fields"; `floor_record` writes only known fields, so `forbid` is safe, and this design
makes that change on purpose.

Before writer models go strict, the CLI paths that build them from user-supplied JSON
(`declaration`, `due`, `target`) are checked: strict mode also rejects coercions such as a
tuple for a list.

### 3. Input models, one per examined slice

Each model covers exactly one test's *Examines* list. Each field carries a comment naming
the doc condition it encodes:

```python
class FloorInput(InputModel):  # VERIFICATION.md ### floor
    floor_type: Literal["drand"]  # floor #1
    chain_hash: PinnedChain = QUICKNET_HASH  # floor #2
    round: StrictInt  # floor #3
    signature: Hex  # floor #3
    randomness: Hex | None = None  # floor #4 (shape)
```

| Model | Slice | Structural conditions it encodes | Stays as code |
|---|---|---|---|
| `EnvelopeInput` | file top level | BDR #1 (object, `payload` and `signature` present and objects), BDR #2 hex shape | BDR #2 signature, #3 keyid |
| `FloorInput` | `payload.anchor.floor` | floor #1, #2, #3, #4 shape | floor #4 equality, #5 BLS |
| `CeilingInput` | `ceiling` | ceiling #1, #3 shape (`witness_id` is a string), #4 shape | ceiling #2 binding, #3 pin lookup, #4 equality, #5 response |
| `SubjectInput` (a `TypeAdapter`) | `payload.subject` | content #1 (a non-empty array) | |
| `SubjectEntryInput` | `payload.subject[]` | content #1 (validated with `context={"hash_alg": ...}`) | content #2–#6 |
| `LinkInput` | `payload.phase`, `fulfills`, `prev_hash` | chain #2 (a link is a string or absent) | chain #1–#3 graph checks |
| `DueInput` | `payload.due` | `invalid-due` (a string) | ISO-8601 parse, timezone rule |

### 4. Layered parsing in the verifier

A junk floor must fail only `floor`, never `BDR` or `chain`. So nothing parses the whole
body strictly. The flow per file:

1. Read bytes and decode JSON with the duplicate-key hook (as today). Failure: BDR #1,
   file not examined by other tests.
2. `EnvelopeInput.model_validate(obj)`. Failure: BDR #1/#2, file not examined by other
   tests (matches today's "malformed" path). `payload` stays a `dict`.
3. Signature and keyid checks (code), as today.
4. For each requested test that examines this file, apply the absence rule, then parse the
   slice: `FloorInput.model_validate(floor)`, and so on. A `ValidationError` marks that
   unit FAIL.
5. Code checks (BLS, Roughtime, digests, graph) run on the parsed models only.

**Absence rule.** A property is absent iff its key is missing or its value is `null`. An
absent property is not examined (Run rules, (\*)). Every other value is examined and either
parses or fails. If an intermediate object along the path, such as `payload.anchor`, is
present but not an object, the property is examined and fails.

Today the code tests truthiness instead (`if not floor`, `if not ceiling`,
`if not subject`, `not r["prev_hash"]`), so falsy values such as `{}`, `[]`, `""`, `false`
and `0` count as absent. See Behavior changes.

The rule applies at every level: the input models read a `null` field as absent too, so
`chain_hash: null` takes its default and `randomness: null` / `ceiling.pubkey: null` are
not checked. `payload.hash_alg: null` defaults to `sha-256`.

`verify_paths` keeps its return shape; per-manifest `floor` / `ceiling` / `content` records
keep their `status` values. A wrong `floor_type` / `ceiling_type` is still `unsupported`;
any other model failure is `invalid`.

### 5. Ceiling model and the `servers` seam

- New `models.Ceiling` (writer) and `CeilingInput` (verifier). `roughtime.fetch_ceiling`
  builds a `Ceiling`. This removes the only shape currently defined twice in `src/`.
- `verify_paths(..., servers=None)` forwards to `roughtime.verify_ceiling`, which already
  takes `servers`. Default stays the pinned `roughtime.SERVERS`. This is an environment
  seam, not an internal one: offline tests cannot get a real Roughtime response for an
  arbitrary nonce, so they pass a map of test witnesses instead of monkeypatching the
  module global.

### 6. Tests

**The contract suite is a black box.** `tests/verify/` builds inputs, calls `verify_paths`
or the CLI, and asserts verdicts, codes, report fields the doc defines, and reasons the
doc documents. It never imports the input models.

- **Valid inputs** come from the production writer (`manifest.build_*`), as in #13.
  Producing a valid signed manifest is a job the tool does.
- **Invalid inputs** are written in the doc's own terms, as dotted property paths:
  `scenario.set("payload.anchor.floor.round", "1000")`. The models are never used to build
  bad inputs: a wrong model would then produce a matching wrong input, and the test would
  pass anyway.
- **Raw bytes** remain for BDR #1 file-level cases (non-JSON, binary, duplicate key,
  non-object).

**Doc coverage test.** One test parses the numbered *Passes when all* conditions from
`VERIFICATION.md` (the `` ### `name` `` sections) and the suite's
`test_<name>__fail__<n>_...` test names. It asserts that every condition has at least one
failing-case test, and that every such test name points at a condition that exists.

**Tests that reach into internals today** are rewritten to work through `verify_paths`:

- `test_never_raises__floor_verifier_exception` patches `drand.verify_floor` and asserts
  undocumented wording. It is replaced by signed junk floors through `verify_paths`, in the
  style of `SIGNED_JUNK` and `test_never_raises__junk_ceiling_member`.
- `test_never_raises__ceiling_on_a_manifest_without_payload` calls `verify_ceiling` with an
  input `verify_paths` cannot deliver. It is deleted.
- Assertions on undocumented reasons (`"1/4 subject(s) failed"`,
  `"malformed anchor.floor: ..."`, `"malformed manifest: ..."`) become verdict assertions.

**Internals tests are extra and sparing.** Where a domain module has logic worth testing
directly (Roughtime response parsing, drand BLS against known vectors), tests for it live
outside `tests/verify/` and do not count toward doc coverage. The input models get no
dedicated unit tests: their behavior is covered as BDR, floor and ceiling contract cases.

## Behavior changes

Intended (each brings behavior in line with the doc):

- **Writer:** `models.Floor` (and every writer model) rejects coerced values. A
  caller passing `round="1000"` now gets a `ValidationError` instead of a silently fixed
  manifest. `floor_record` already passes an `int`.
- **Absence rule (section 4).** A falsy but non-null value is present and examined:
  - `payload.anchor.floor` of `{}`, `false`, `""`, `0` or `[]`, or a falsy non-object
    `payload.anchor` such as `[]`: `floor` FAIL (floor #1). Today these count as absent.
  - `ceiling` of `{}`, `[]`, `""`, `false` or `0`: `ceiling` FAIL (ceiling #1).
  - `payload.prev_hash` of `""` is a link, not a root, so a postreg with it fails chain #2,
    and if it was the only root, chain #1 too.
  - `payload.subject` of `[]` or `{}`: `content` FAIL (content #1: a subject is a non-empty
    array). Today it is skipped.
  - `payload.due` of `""`, `0` or `false`: state `invalid-due`. Today `open`.
- **`null` is absent inside a slice (section 4).** Two cases that failed today now take
  their documented default:
  - `anchor.floor.chain_hash: null` means the quicknet chain: `floor` can PASS (was FAIL).
  - `payload.hash_alg: null` means `sha-256`: `content` can PASS (was FAIL, each
    entry a `malformed subject entry`).

  Both loosen a verdict, so they are worth a second look. Neither value is something this
  tool writes. The alternative is to read `null` as absent only for whole slices, and
  as a present, failing value inside them.
- **Report detail (not contract):** undocumented `error` strings change. A missing or
  non-string `ceiling.witness_id` is now status `invalid` instead of `unpinned`.

Not intended, and covered by the contract suite: every other verdict and code for every
input the suite builds. Commit 3's new contract tests, run against commit 2's `src/`, fail
on exactly the cases listed above (19 of 170) and nowhere else.

- **Writer test data:** `test_manifest.py`'s floor used `chain_hash: "ab"` as filler; the
  strict writer refuses an unpinned chain, so it now uses the quicknet hash.

## Doc changes (`VERIFICATION.md`)

- Header: "Authoritative implementation: `src/asexec/verifier.py`. Structural conditions
  (types and shapes) are implemented as input models in `src/asexec/models.py`; everything
  else, and every verdict, is in the verifier and the modules it calls. Describes 0.3.16."
- Conventions, **Hex**: hex is what `bytes.fromhex` accepts, which makes the 0.3.x
  leniency explicit; comparisons with a computed digest stay exact. Contract tests pin it
  for BDR #2, floor #3 and ceiling #4/#5: a valid value in uppercase, with spaces, passes.
- Run rules: state the absence rule, including that `null` is absent.
- Content #1: `payload.subject` is a non-empty array, and each entry's `name` is a string
  and `digest[hash_alg]` is a string. `payload.subject` joins content's *Examines* list.

## Rollout

One PR: the design, then three commits, each green:

1. **Contract suite, against current code.** `scenario.set` by property path; the doc
   coverage test; the internals tests rewritten or deleted; reason assertions limited to
   documented reasons; hex leniency contract tests. No `src/` changes.
2. **Input models.** `types.py` and input models; verifier parses through them; writer
   models go strict; `Ceiling` model; `verify_paths(servers=...)`; doc header. The suite
   from commit 1 passes with assertions unchanged (the `servers` fixture switches from
   monkeypatch to the parameter).
3. **Absence rule.** Verifier change, the Run-rules doc update, and contract tests for each
   case under Behavior changes.

## Decisions

Resolved during review:

- **Hex:** lenient (`bytes.fromhex`) in 0.3.x, strict lowercase in 0.4.0.
- **Model location:** input models in `models.py`, grouped by family; shared types in
  `types.py`.
- **Coverage:** checked against test names parsed from `VERIFICATION.md`, not against
  model metadata.
- **Doc pointer:** the header names both `verifier.py` and the input models (Doc changes).
- **Failure reasons:** deferred to issue #8.
- **`payload.subject: []`:** examined, and fails content #1.
- **`null`:** absent, the same as a missing key. This tool never writes `null`
  (`exclude_none=True`).
