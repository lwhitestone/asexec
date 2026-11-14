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
| None (honest run) | `BDR=PASS chain=PASS content=PASS keyconsist=PASS` | baseline; the monitor catches 34 of 40 plants |
| Plant set swapped after the monitor ran | `content=FAIL` | **caught**: the digests no longer match |
| Item S2 silently dropped | all `PASS`, still `[FULFILLED]` | **missed**: the item list lives in free text, so nothing counts it. Needs `items` and `complete` (0.4.0) |
| Plants committed after the monitor ran | all `PASS` | **missed**: nothing relates the commitment's time to the run's. Needs `order` (0.4.0) and a time bound on the run from the lab's side |

## Out of scope

Whether the plants are realistic, whether the monitor tested is the one deployed, and
whether any finding is true. Those stay with the assessor's judgement. asexec reports what was
committed and delivered, and when, item by item; the verdict belongs to the assessor or to
a display layer, not to asexec.

## With the 0.4.0 betas

This example is the second release gate for 0.4.0: re-run on the beta format, with `plan`,
`items`, `item_id`, `status` and `evidence` replacing the free-text stand-ins, it checks
that the claim record fits a claim-level promise.
