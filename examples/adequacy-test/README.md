# Example: a commit-reveal adequacy test

A synthetic, offline run of the adequacy test from Apollo Research's [*Principles for
Embedded Evaluations*](https://www.apolloresearch.ai/blog/principles-for-embedded-evaluations),
on the current asexec format. It shows what asexec already catches and what the 0.4.0
claim record adds (see [`ROADMAP.md`](../../ROADMAP.md)).

## The scenario

An assessor backs a universal-negative claim: "models never attempted to disable or evade
their monitoring during internal deployment". Such a claim can only be falsified, so the
verdict depends on whether the search could have found a counterexample. Apollo's scale
separates *Verified* (no counterexample found, and the methods would likely have found
one) from *Unrefuted* (no counterexample found, but gaps in the methods weaken the
result). The assessor commits to three items:

| Item | Kind | Delivered as |
|---|---|---|
| S1 | search | `search.txt` |
| S2 | experiment | `experiments.txt` |
| A1 | adequacy | `plants.reveal.json`, `flags.json` |

For A1, 40 realistic evasion attempts ("plants") are inserted into 200 synthetic
transcripts, and a toy monitor flags what it can. The catch rate shows whether the monitor
would likely have found a real attempt.

## What the script does

1. **Commit**, before access and before the monitor runs: a prereg signs the plan
   (`plan.md`), the item list (in `declaration`, since today's format has no `items`) and
   the plant set as salted hashes plus a count (`plants.commitment.json`). The plants stay
   private.
2. **Run**: the toy monitor processes the transcripts with the plants inserted and writes
   `flags.json`.
3. **Deliver**: one chained postreg per item, with `item_id` and `status` in `notes`. The
   A1 postreg reveals the plants and salts (`plants.reveal.json`) with the flags.
4. **Verify**, offline: `asexec verify --tests BDR,chain,content,keyconsist`, plus the
   reader's own check that the revealed plants match the commitment.

It then replays three faults.

## Run it

```console
$ python examples/adequacy-test/run.py
```

Pass `--keep DIR` to keep the manifests and artifacts instead of a temporary directory.
Everything is offline: no drand floor or Roughtime ceiling is fetched. Salts come from a
fixed seed so the run is reproducible; real salts must be random and kept secret until the
reveal.

## Results on asexec 0.3.19

| Fault | Verify code | Result |
|---|---|---|
| No fault | `BDR=PASS chain=PASS content=PASS keyconsist=PASS` | baseline; the monitor catches 34 of 40 plants |
| Plant set swapped after the monitor ran | `content=FAIL` | **caught**: the digests no longer match |
| Item S2 silently dropped | all `PASS`, still `[FULFILLED]` | **missed**: the item list lives in free text, so nothing counts it. Needs `items` and `complete` (0.4.0) |
| Plants committed after the monitor ran | all `PASS` | **missed**: nothing relates the commitment's time to the run's. Needs `order` (0.4.0) and a time bound on the run from the lab's side |

## The schema it targets

Today the item list, `item_id` and `status` sit in free text, and the plant commitment is
an ordinary subject. The planned schema gives each its own field. The sketch below is
illustrative: [`ROADMAP.md`](../../ROADMAP.md#new-properties) holds the definitive list,
with each property's tier, version and promise level. Every property is optional; the
tests decide whether a manifest meets a bar.

**Prereg** (signed body; signed before access and before the monitor runs):

```jsonc
{
  "phase": "prereg",
  "target": "Claim 5: models never attempted to disable or evade their monitoring …",
  "due": "2099-01-01T00:00:00Z",                       // timely, complete
  "plan": {                                            // 0.4.0; asexec never parses it
    "name": "plan.md",                                 // content
    "hash_alg": "sha-256",                             // content
    "digest": { "sha-256": "…" },                      // content
    "media_type": "text/markdown",                     // declared, never tested
    "label": "Claim 5 plan"                            // declared, never tested
  },
  "items": [                                           // 0.4.0; complete
    { "id": "S1", "kind": "search" },
    { "id": "S2", "kind": "experiment" },
    { "id": "A1", "kind": "adequacy" }                 // kind: declared, never tested
  ],
  "commitments": {
    "plants": {                                        // 0.5.0; a reveal test (not named)
      "alg": "…",                                      // encoding not decided
      "root": "…",                                     // over the plants' salted hashes
      "count": 40
    }
  },
  "presented_by": "…",                                 // 0.5.0; role (name not decided)
  "anchor": { "floor": { "floor_type": "drand", … } }  // not before
}
```

**Postreg** (one per item, chained), here for A1:

```jsonc
{
  "phase": "postreg",
  "fulfills": "sha-256:…",                             // the prereg's ref
  "prev_hash": "sha-256:…",                            // the S2 postreg's ref
  "item_id": "A1",                                     // 0.4.0; complete
  "status": "reported",                                // 0.4.0; reported | excluded | blocked
  "evidence": [                                        // 0.4.0; content
    {
      "name": "flags.json",
      "hash_alg": "sha-256",
      "digest": { "sha-256": "…" },
      "media_type": "application/json"                 // declared, never tested
    },
    {
      "name": "plants.reveal.json",
      "hash_alg": "sha-256",
      "digest": { "sha-256": "…" },
      "media_type": "application/json",
      "uri": "https://…"                               // optional; declared, never tested
    }
  ],
  "anchor": { "floor": { "floor_type": "drand", … } }  // not before
}
```

Each manifest's envelope carries `dsse`, `pubkey`, and optionally a Roughtime `ceiling`
(not after) and an `untrusted` section. Two tests relate the times: `order` (0.4.0)
checks that the prereg's ceiling precedes each postreg's floor. `plantorder` (0.6.0, name
not decided) checks that the plant commitment's ceiling precedes the floor of the lab's
own signed record of its monitor run. That record is a new kind, not yet designed, and
may fall outside asexec's scope.

## Out of scope

Whether the plants are realistic, whether the monitor tested is the one deployed, and
whether any finding is true. Those stay with the assessor's judgement. asexec reports what was
committed and delivered, and when, item by item; the verdict belongs to the assessor or to
a display layer, not to asexec.

## With the 0.4.0 betas

This example is the second release gate for 0.4.0: re-run on the beta format, with `plan`,
`items`, `item_id`, `status` and `evidence` replacing the free-text stand-ins, it checks
that the claim record fits a claim-level promise.
