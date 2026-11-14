# The 0.4.0 envelope

> [!NOTE]
> This describes the format planned for `0.4.0`, not current behavior. It is AI-assisted, so
> treat it with due skepticism. The rules that follow from it are in
> [`ROADMAP.md`](../ROADMAP.md#040--m1-the-first-supported-format).

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
  DSSE and in-toto tooling read asexec envelopes (groundwork for the in-toto export in
  0.5.0). The `signatures` list keeps one entry: a second party signs its own record (see
  0.6.0 in [`ROADMAP.md`](../ROADMAP.md)), not the same body. The cost: a format break,
  regenerated golden vectors, and a payload that must be decoded to be read.

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
