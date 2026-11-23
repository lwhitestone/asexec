# The 0.4.0 betas

The betas carry the format that 0.4.0 will freeze, for dry runs before it does. Each one is a
prerelease: `pip install asexec` keeps choosing the latest 0.3.x, so install a beta by its
exact version.

```bash
pip install asexec==0.4.0b1
```

**Beta manifests are never supported.** Each beta signs with a `payloadType` of its own
(`application/vnd.asexec.0.4.0b1+json`) and reads only that, as 0.3.21 and 0.3.22 do with
theirs. A manifest signed by one beta fails `format` in any other release, 0.4.0 included.
Use the same beta from prereg through verify, and nothing signed with it in a record meant to
last. The format is the same as 0.3.22's under another label, so a later beta changes it only
where its release notes say.

## What changed from 0.3.20

- **The file is a DSSE envelope:** `dsse` (`payloadType`, the body bytes in base64 as
  `payload`, one signature) beside `pubkey`, an optional `ceiling`, and `untrusted`, which
  nothing checks. Verify checks the stored bytes and never re-serializes them.
- **The claim record:** a prereg can carry a `plan` (a file) and `items` (what it commits to
  deliver). Each postreg can carry an `item_id`, a `status` (`reported`, `excluded` or
  `blocked`) and `evidence` (files).
- **Subjects are files**, each named by its path relative to where you sign, with its own
  `hash_alg`. Directories are refused: list their files, or an archive.
- **`BDR` is now `format` and `selfsig`**, both required in every run. Version skew reads as
  `format=FAIL` with `selfsig` passing for the other files, and a bad signature as
  `selfsig=FAIL`.
- **New tests:** `timely` (each counted postreg's ceiling at or before `due`), `complete` (each
  item accounted for), and `order` (the prereg's ceiling before each postreg's drand round).

## A claim with two runs

Sign from the directory that holds your artifacts. Names are relative to it, and verify finds
them under `--artifacts`.

```bash
asexec keygen --out lab.key

asexec prereg --key lab.key --target "models A and B on harness X" \
  --due 2099-01-01T00:00:00Z --plan '{"name": "plan.md"}' \
  --items '[{"id": "R1", "kind": "run"}, {"id": "R2", "kind": "run"}]' \
  --ceiling --out prereg.json

asexec postreg --key lab.key --fulfills prereg.json --item-id R1 --status reported \
  --evidence '[{"name": "runs/R1.json"}]' --ceiling --out post-R1.json

asexec postreg --key lab.key --fulfills prereg.json --prev post-R1.json \
  --item-id R2 --status reported --evidence '[{"name": "runs/R2.json"}]' \
  --ceiling --out post-R2.json

asexec verify prereg.json post-R1.json post-R2.json \
  --tests format,selfsig,chain,content,keyconsist,complete,timely,ceiling --artifacts .
```

`--ceiling` asks a Roughtime server to witness each file after signing (UDP, network). The
report ends with the code:

```console
=== commitments ===
  [FULFILLED] prereg sha-256:2468203f…
    signer       : sha-256:7e7b6977…
    due          : 2099-01-01T00:00:00Z
    postregs     : 2
    items        : 2
      ✓ R1: reported
      ✓ R2: reported
…
asexec-verify/1 ceiling=PASS chain=PASS complete=PASS content=PASS format=PASS keyconsist=PASS selfsig=PASS timely=PASS
```

Leave out `post-R2.json`, and `complete` catches the dropped item:

```console
      ✗ R2: no counted postreg names it
asexec-verify/1 complete=FAIL format=PASS selfsig=PASS
```

To show a run came after its prereg (`order`), have the run fetch a drand round when it
starts, use it (as its seed, say), and sign its postreg with that round: `--floor-round-file
round.json`. The README's *Usage* has the command.

## More

- Every test, what it examines and its failure reasons: [`VERIFICATION.md`](./VERIFICATION.md).
- Every option: `asexec <command> --help`. Exit statuses: the README's *Exit status*.
- What 0.4.0 will promise, and what the betas are for: [`ROADMAP.md`](../ROADMAP.md).
