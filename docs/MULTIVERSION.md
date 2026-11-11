# Multi-version support

> [!NOTE]
> This is a design proposal, not a description of current behavior. It is AI-assisted, so
> treat it with due skepticism.

Starting with `0.4.0`, a format change adds a new version and keeps accepting the old ones
([`ROADMAP.md`](../ROADMAP.md#versioning)). This document covers what the verifier needs in
order to keep that promise.

**Status: not built.** The verifier accepts one value of each identifier. The promise costs
nothing until the first format change after `0.4.0`, and this work has to land before that
change does.

## Goal

- A manifest signed by `0.4.0` or later gets the same verify result from every later release.
- Manifests from `0.3.x` are out of scope and not supported.
- An older verifier can't understand a newer format. It must fail clearly rather than
  misread the manifest, and users upgrade to verify it.

## Which field selects the version

The verifier has to decide which rules apply before it can trust anything, so the field it
selects on must be covered by the signature. Otherwise an attacker could edit it to choose
weaker rules.

**Use `dsse.payloadType`.** From `0.4.0` it is part of the PAE input, so editing it makes the
signature fail. For example:

```
application/vnd.asexec+json      the 0.4.0 format
application/vnd.asexec.v2+json   a later format
```

The other candidates don't work:

| Field | Problem |
|---|---|
| PAE prefix | It becomes the fixed `DSSEv1`, which standard tooling requires. asexec can no longer version it, so a `/vN` bump stops being available at `0.4.0`. |
| `schema_id` | It's inside the payload, so the verifier would have to decode the body before knowing how to read it. |
| `signature.alg` | It's unsigned today, and the planned `0.4.0` `signatures` entries don't have it at all. |

Each `payloadType` value then fixes all the format rules: PAE prefix, hash, signature
algorithm and body schema. There are no separate per-identifier versions that could combine
in ways nobody tested.

## Verifier design

A table replaces the single constants the verifier uses today:

```python
FORMATS = {
    "application/vnd.asexec+json": Format(
        pae_version=b"DSSEv1",
        digest_ref_prefix="sha-256:",
        default_hash_alg="sha-256",
        signing_alg="ed25519",
    ),
}
```

- **Known `payloadType`:** verify under that entry's rules.
- **Unknown `payloadType`:** `BDR=FAIL`, with a reason saying the format is newer than this
  release and to upgrade. Never fall back to another entry.
- **New format:** add an entry. Existing entries are never edited.

Signing always uses the newest entry. There is no option to write an older format.

## Per-identifier behavior

Names are from [`constants.py`](../src/asexec/constants.py).

| Identifier | Under multi-version support |
|---|---|
| `SIGNING_PAE_VERSION` | A per-format entry. Fixed to `DSSEv1` from `0.4.0`. |
| `MANIFEST_PAYLOAD_TYPE` | The selector. Signing uses the newest value. |
| `DIGEST_REF_PREFIX` | A per-format entry. A format's refs and keyids must all use its prefix. |
| `SUBJECT_DEFAULT_HASH_ALG` | Split in two: the per-format verify fallback never changes, and the signing default can, because signing always writes `hash_alg`. |
| `SIGNING_KEY_ALG` | A per-format entry, which avoids selecting an algorithm from an unsigned field. Existing key files keep working only if the format still uses their algorithm, so signing with a new algorithm needs a new key. |
| `VERIFY_CODE_VERSION` | Independent of the manifest format. See below. |
| `IDENTITY_WELL_KNOWN_PATH` | Not manifest format. Fetch the new path, then fall back to the old one. |
| `MANIFEST_SCHEMA_ID`, `MANIFEST_PREDICATE_TYPE`, `IDENTITY_DOCUMENT_VERSION` | Written to new output only. A future test of these fields would check them per format. |

## Verify codes

A published code should stay reproducible, but a new tool printing `asexec-verify/2` can't
byte-match a published `asexec-verify/1` code. So `verify` keeps every grammar shipped since
`0.4.0`, starting with `/1`. Codes printed by `0.3.x` also say `/1`, but they follow the
earlier meanings and are out of scope.

```bash
asexec verify prereg.json --tests BDR --code-version 1
```

Without the flag it prints the newest grammar. Because a bump can also mean a test's documented
meaning changed, each grammar has to keep its old meaning, not only its old layout. That makes a
bump expensive, so it should stay rare; adding a test name still needs no bump.

## Withdrawing a version

Accepting a version forever is wrong if its hash or signature algorithm is broken. A format can
be marked as withdrawn, with a reason:

- `BDR` fails for that format, and the report states which format was withdrawn and why.
- It never silently passes, and never fails without explaining why.
- The entry stays in the table, so the verifier can still identify the format.

Withdrawal is the one permitted exception to the promise, and it needs a release note.

## Testing

- **Frozen manifests:** keep at least one for each format, and never edit or regenerate them.
  Every release must verify all of them. [`test_constants.py`](../tests/test_constants.py) is
  where these live today.
- **Tampering:** changing `payloadType` to another known format must fail `BDR`.
- **Unknown format:** an unrecognized `payloadType` fails with the upgrade reason.
- **Old grammars:** each supported `--code-version` matches a frozen expected code.
- **Withdrawal:** a withdrawn format fails with its reason.

## Plan

1. **In `0.4.0`:** ship `payloadType` as the selector, with one `FORMATS` entry and the
   unknown-format failure. Add the first frozen `0.4.0` manifest. Doing this with the DSSE
   switch means `0.4.0` verifiers already reject newer formats clearly.
2. **Before the first later format change:** add the second entry and its frozen manifest.
3. **Before the first grammar bump after `0.4.0`:** add `--code-version`.
4. **When first needed:** add withdrawal support.

## Open questions

- **Spelling of later `payloadType` values:** `vnd.asexec.v2+json` is an example, not a decision.
  Whichever form is chosen, it should be settled before `0.5.0` freezes the format.
- **Key files:** should a key file record which formats it can sign, or is `alg` enough?
- **Mixed commitments:** a prereg and its postregs could use different formats after an
  upgrade. `chain` and `keyconsist` compare refs and keyids, so the rules for comparing them
  across formats need deciding, especially if the digest prefix differs.
