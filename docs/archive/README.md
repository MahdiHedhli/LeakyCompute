# Archive

Material that was written during the build and is no longer part of the product:
session handoffs, publication scaffolding, planning prose. It is kept because some
of it records *why* a decision was made, and that reasoning is hard to reconstruct.

**Nothing in this directory is authoritative.** These files were accurate when
written and have not been maintained since. Where one contradicts
[`../SECURITY.md`](../SECURITY.md), the constitution wins — without exception. Do
not cite a number, a query, or an invariant from here; check it against the code
or the constitution first.

| File | What it was | Why it is here |
|---|---|---|
| [`HANDOFF_TIER1.md`](HANDOFF_TIER1.md) | Handoff prompt — tier-1 multi-service checker | Session artifact. Its contract is now in `../API.md` and enforced by `npm test`. |
| [`HANDOFF_DISCOVERY.md`](HANDOFF_DISCOVERY.md) | Handoff prompt — discovery expansion, fingerprint validation | Session artifact. It says of itself that its content "exists inside a handoff document, which will rot." It did. |
| [`post-notes.md`](post-notes.md) | Severity hook, narrative order, sources to cite | Write-up scaffolding that had been living inside the discovery model doc. Predates the three-number framing and the four gates. |

## Deciding what to do with it

Three outcomes, per file. Promote anything still true into a maintained doc;
delete anything the code now says better; leave the rest here rather than
half-maintaining it in `docs/`. The handoffs are closest to deletion — both
describe work that shipped.
