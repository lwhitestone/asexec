# Multi-version support

> [!NOTE]
> This is a design, built only in part: the *Status* line below says which part describes
> current behavior, and the rest is a proposal. It is AI-assisted, so treat it with due
> skepticism.

Starting with `0.4.0`, a format change adds a new version and keeps accepting the old ones
([`ROADMAP.md`](../ROADMAP.md#versioning)). This document covers what the verifier needs in
order to keep that promise.

**Status: partly built.** Step 1 of the [Plan](#plan) is built except its frozen `0.4.0`
manifest: the verifier selects a file's rules by its `payloadType` from a `FORMATS` table in
[`constants.py`](../src/asexec/constants.py), which has one entry, and an unknown format fails
`format`. The selector reads `dsse.payloadType`. A second entry, `--code-version` and
withdrawal are not built. The promise costs nothing until the first format change after
`0.4.0`, and the rest of this work has to land before that change does.

## Goal

- A manifest signed by `0.4.0` or later gets the verify result `docs/VERIFICATION.md`
  specifies for it from every later release, except for the withdrawals below ([`ROADMAP.md`](../ROADMAP.md#support-from-040) lists
  what the promise covers).
- A manifest is read only under its own format's rules. A field a later format defines is
  never read from an earlier format's manifest.
- Manifests from `0.3.x` are out of scope and not supported.
- An older verifier can't understand a newer format. It must fail clearly rather than
  misread the manifest, and users upgrade to verify it.

## Which field selects the version

The verifier has to decide which rules apply before it can trust anything, so the field it
selects on must be covered by the signature. Otherwise an attacker could edit it to choose
weaker rules.

**Use `dsse.payloadType`.** From `0.4.0` it is part of the PAE input, so editing it makes the
signature fail. Format N is spelled `vN`, and goes with the `predicateType`
`https://asexec.org/manifest/vN` in the body. A beta is spelled by its version:

```
application/vnd.asexec.v1+json          the 0.4.0 format
application/vnd.asexec.v2+json          the next format
application/vnd.asexec.0.4.0b1+json     a beta: never accepted by a release
```

The other candidates don't work:

| Field | Problem |
|---|---|
| PAE prefix | It becomes the fixed `DSSEv1`, which standard tooling requires. asexec can no longer version it, so a `/vN` bump stops being available at `0.4.0`. |
| `predicateType` | It's inside the payload, so the verifier would have to decode the body before knowing how to read it. |
| `signature.alg` | It was unsigned, and the DSSE `signatures` entries don't have it at all. |

Each `payloadType` value then fixes all the format rules: PAE prefix, hash, signature
algorithm and body schema. There are no separate per-identifier versions that could combine
in ways nobody tested.

## Verifier design

A table replaces the single constants the verifier used. Each entry is a plain dict, like
the pinned drand chains and Roughtime servers, and is keyed by `payloadType`. As built:

```python
FORMATS: dict[str, dict] = {
    MANIFEST_PAYLOAD_TYPE: {  # "application/vnd.asexec.v1+json"
        "digest_ref_prefix": "sha-256:",
        "signing_key_alg": "ed25519",
        "signing_pae_version": b"DSSEv1",
        "subject_default_hash_alg": "sha-256",
    },
}
```

Only the entry under development, which no release has shipped yet, is keyed by the name
`MANIFEST_PAYLOAD_TYPE`. Until `0.4.0` that is the one entry, so each beta's release commit,
which rewrites that literal to the beta's own type, re-keys it. The `0.4.0` release commit
(at the latest, before any later release commit rewrites the literal) makes the entry's key
the literal `application/vnd.asexec.v1+json`, which never changes after that. Otherwise the
next release commit would re-key the released `v1` entry, and every `v1` manifest would
read as an unknown format.

- **Known `payloadType`:** verify under that entry's rules: the PAE signing input, the prefix
  of `ref` and `keyid`, and the `hash_alg` a subject without one is read with.
- **Unknown `payloadType`:** `format=FAIL`, with a reason that says what the type is: a
  format newer than this release (upgrade), a beta's (unsupported), or the format asexec
  wrote before `0.4.0` (unsupported, re-sign). Never fall back to another entry. `selfsig`
  does not examine that file, so it still passes for the others: the code tells "upgrade"
  apart from "damaged". A missing or non-string `payloadType` is malformed, which also fails
  `format`.
- **New format:** add an entry, keyed by `MANIFEST_PAYLOAD_TYPE` while it is under
  development. A released entry is never edited or re-keyed.

Signing always uses the newest entry. There is no option to write an older format.

## Per-identifier behavior

Names are the identifiers [`constants.py`](../src/asexec/constants.py) defined before the
selector. The per-format ones are now fields of a `FORMATS` entry.

| Identifier | Under multi-version support |
|---|---|
| `SIGNING_PAE_VERSION` | Built: the entry's `signing_pae_version`, now `DSSEv1`, which DSSE fixes. |
| `MANIFEST_PAYLOAD_TYPE` | Built: the selector, and the key of the entry signing uses. Signing uses the newest value. |
| `DIGEST_REF_PREFIX` | Built: the entry's `digest_ref_prefix`. A format's refs and keyids must all use its prefix. |
| `SUBJECT_DEFAULT_HASH_ALG` | Built, split in two: the entry's `subject_default_hash_alg` is the verify fallback and never changes, and `SUBJECT_DEFAULT_HASH_ALG` stays as the signing default, which can, because signing always writes `hash_alg`. |
| `SIGNING_KEY_ALG` | Built: the entry's `signing_key_alg`, which avoids selecting an algorithm from an unsigned field. A manifest names no algorithm, and ed25519 is the only algorithm verify checks. Existing key files keep working only if the format still uses their algorithm, so signing with a new algorithm needs a new key. |
| `VERIFY_CODE_VERSION` | Independent of the manifest format. See below. |
| `IDENTITY_WELL_KNOWN_PATH` | Not manifest format. Fetch the new path, then fall back to the old one. |
| `MANIFEST_PREDICATE_TYPE`, `IDENTITY_DOCUMENT_VERSION` | Written to new output only. A future test of these fields would check them per format. |

## Verify codes

A published code should stay reproducible, but a new tool printing `asexec-verify/2` can't
byte-match a published `asexec-verify/1` code. So `verify` keeps every grammar shipped since
`0.4.0`, starting with `/1`. Codes printed by `0.3.x` also say `/1`, but they follow the
earlier meanings and are out of scope.

```bash
asexec verify prereg.json --tests format,selfsig --code-version 1
```

Without the flag it prints the newest grammar. Because a bump can also mean a test's documented
meaning changed, each grammar has to keep its old meaning, not only its old layout. That makes a
bump expensive, so it should stay rare; adding a test name still needs no bump.

## Withdrawing a version

Accepting a version forever is wrong if its hash or signature algorithm is broken. A format can
be marked as withdrawn, with a reason:

- `format` fails for that format, and the report states which format was withdrawn and why.
- It never silently passes, and never fails without explaining why.
- The entry stays in the table, so the verifier can still identify the format.

A pinned trust root can be withdrawn the same way, for example a compromised drand or
Roughtime key. `floor` or `ceiling` then fails for manifests that rely on it, with a reason
naming the withdrawn root.

Withdrawal, of a format or a trust root, is the one permitted exception to the promise, and
it needs a release note.

## Testing

- **Frozen manifests:** keep at least one for each format, and never edit or regenerate them.
  Every release must verify all of them. [`test_constants.py`](../tests/test_constants.py) is
  where these live today.
- **Tampering:** changing `payloadType` to another known format must fail `selfsig`. Tested
  today with a second entry added only for the test.
- **Unknown format:** an unrecognized `payloadType` fails with the upgrade reason (tested).
- **Old grammars:** each supported `--code-version` matches a frozen expected code.
- **Withdrawal:** a withdrawn format fails with its reason.

## Plan

1. **In `0.4.0`:** ship `payloadType` as the selector, with one `FORMATS` entry and the
   unknown-format failure (built). Add the first frozen `0.4.0` manifest (not yet: format
   changes before `0.4.0` still regenerate the frozen vectors). Doing this with the DSSE switch
   means `0.4.0` verifiers already reject newer formats clearly.
2. **Before the first later format change:** add the second entry and its frozen manifest.
3. **Before the first grammar bump after `0.4.0`:** add `--code-version`.
4. **When first needed:** add withdrawal support.

## Open questions

- **Key files:** should a key file record which formats it can sign, or is `alg` enough?
- **Mixed commitments:** a prereg and its postregs could use different formats after an
  upgrade. `chain` and `keyconsist` compare refs and keyids, so the rules for comparing them
  across formats need deciding, especially if the digest prefix differs.
