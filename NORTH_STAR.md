# North Star

*The outward case for `asexec` — what it does and how to verify it — is the [README](./README.md). This is the inward one: the scope guardrail. It exists so that six months from now, without any adoption pressure in sight, there's something concrete to check scope decisions against instead of re-litigating them from memory.*

## What this project is for

`asexec` exists to make one specific claim checkable: that an evaluation was committed to *before* the result was known, and that what was later disclosed (or not disclosed) can be verified against that commitment without trusting the evaluator's continued good behavior, a platform, or a third party.

That's the whole thesis. Everything else — richer schemas, nicer tooling, wider adoption — is in service of that claim staying checkable, not a goal in its own right.

## What I'm optimizing for

- **A primitive that's correct and honest about its own limits.** The tool should never claim to prove more than it does. "Notarization-only" vs. "fulfilled commitment" vs. "elapsed with no receipt" stay visibly distinct, always. If a gap in the guarantee exists (backdating, selective non-registration, key compromise), it gets named in the docs, not smoothed over.
- **Small-scale, honest usage — starting with myself.** Using `asexec` on my own evals, including the ones I'd rather not publish, is the actual test of whether the tool does anything. This comes before any effort on outside adoption.
- **Team and customer-facing disclosure norms.** Extending real usage to my team and the people we work with is the first test of the social-contract thesis under real (if modest) stakes — not hypothetical adversarial-lab stakes, but real enough that an unfavorable result or an elapsed window is a genuine test of whether the norm holds.
- **Solving the surfacing/verification problem as a separate, unowned layer.** A verification website or dashboard is worth building, but deliberately *not* as something only I can run or control. If the manifest format is a real primitive, anyone should be able to build a competing verifier from the spec alone, without my involvement. The moment the primitive's author becomes its only consumer-facing surface, this has quietly become the platform it was never supposed to be.

## What I'm explicitly not chasing

- **Lab adoption as a near-term goal.** The parties with the strongest incentive to look transparent are the parties with the weakest incentive to accept a tool that makes selective disclosure legibly costly. That incentive gap doesn't close because the tool is well-built. It closes (if it ever does) through some combination of regulatory mandate, gatekeeper pressure (a journal-equivalent, a safety-framework auditor), or industry-wide norm shift — none of which I control, and none of which are worth designing the tool around in the meantime.
- **Growth or evangelism as a scheduled workstream.** Time spent on marketing a primitive that hasn't survived one honest usage cycle is time misallocated. Adoption effort comes after the tool has been dogfooded, not instead of it — which is why the [roadmap](./ROADMAP.md) carries no adoption/growth release.
- **Owning the surfacing layer long-term.** Building a reference verifier is fine; becoming the permanent, sole home for verification is scope creep back toward "another layer on top of the pool," which was the thing this project was started to avoid.
- **Solving problems that aren't mine to solve.** Identity binding, capability-elicitation quality, sandbagging detection, and regulatory mandate are all real gaps this project doesn't close. Naming them clearly and moving on is preferable to quietly overclaiming or spending effort chasing them out of scope.

## The honest bet

This is a well-scoped primitive for a real, correctly-diagnosed gap. Whether it matters at scale depends on adoption dynamics that are almost entirely outside my control. That makes it worth building on its own merits — the artifact has value even at small scale, and the alternative (nothing exists that makes this claim checkable at all) is worse than a primitive that stays niche. It does not make wide adoption a reasonable thing to plan around, promise, or optimize my own effort toward.

If this note is being reread and the temptation is to expand scope in pursuit of adoption that hasn't materialized — that's the signal to stop and re-read this section, not to rewrite it.

---

*Related: the [README](./README.md) (what it does + quickstart), [`ROADMAP.md`](./ROADMAP.md) (version-keyed backlog). A stakeholder-facing pitch exists in the internal campaign notes; it is deliberately the outward twin of this doc — where it invites adoption, this doc is the reminder that adoption is not the near-term goal and not to be designed around.*
