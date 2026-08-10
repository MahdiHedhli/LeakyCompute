# Spec: <feature>

**Status:** draft | accepted | shipped · **Date:** YYYY-MM-DD

> Proposal, not ceremony. Write a spec when a change has a decision in it that
> would be expensive to reverse — a new probe, a new discovery source, a new
> class of identifier, a new public claim. Skip it for mechanical work.

## Problem

What is wrong or missing today. One paragraph. No solution.

## Constitution check

**This section is the point of the spec.** Answer against
[SECURITY.md](../SECURITY.md); cite invariants by number.

| Question | Answer |
|---|---|
| Which invariants could this break? | *e.g. I-2, I-14 — or "none, because…"* |
| Every new request a read-only GET to a metadata endpoint? (I-1, I-2) | |
| Widens the port allowlist? If so, why is each port a known AI port? (I-5) | |
| Introduces a new class of identifier? (I-14, Q-1) | |
| Increases active probe volume? What is the cap? (I-18) | |
| Indistinguishable from NadMesh on the wire? (§0) | |

Any open question in SECURITY.md §6 this depends on: ______
**If it depends on an unsettled question, settle it here or don't ship.**

## Proposal

What changes. Include the data shape if there is one.

## Out of scope

What this deliberately does not do. Prevents scope drift in review.

## Verification

How we know it works, and which claims are machine-checked vs review-only.
New invariants need new tests, or an explicit note that they don't have them.

## Limitations

What a user could wrongly conclude from the output, and what the UI says to
prevent that. (I-8: a clean result is never proof of safety.)
