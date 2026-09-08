# Governed discovery schedule diagnostic — 3 September 2026

## Technical summary

All five scheduled discovery runs completed their preflight, nomination, probe,
and aggregate-publication jobs successfully. The rolling retained-host count
increased from 1,413 after the 2 September canary to 1,467 after the final run,
so discovery and ingestion were operating.

Two independent freshness problems made the public counters look stuck:

1. GitHub delayed every scheduled event by roughly two to four hours. The
   nominal 22:13 UTC catch-up began at 00:01 UTC on 4 September, after Workers
   KV reset, so it spent the new day's allowance instead of the unused prior-day
   capacity.
2. The governed all-lane nominator measured 22,116 public-index records but
   labeled every successful nomination run `candidate_feed_only`. Ingest
   therefore preserved the 19,376-record measurement from 27 August. The fix
   reuses the existing complete-all-lane publication gate; subset or failed-lane
   runs still cannot overwrite the last complete measurement.

## Every scheduled run completed, but not at its nominal time

Times and delays are UTC. A table is more useful than a chart for this five-run
audit because the exact run link and each gate outcome are the evidence.

| Nominal | Started | Delay | Nominated | Leased | Exposed outcome | Result |
|---|---:|---:|---:|---:|---:|---|
| 05:43 | 10:04 | 4h 21m | 74 | 16 | 12 | [success](https://github.com/MahdiHedhli/LeakyCompute/actions/runs/33742293546) |
| 09:43 | 13:51 | 4h 08m | 75 | 52 | 15 | [success](https://github.com/MahdiHedhli/LeakyCompute/actions/runs/33763484425) |
| 13:43 | 17:14 | 3h 31m | 70 | 7 | 4 | [success](https://github.com/MahdiHedhli/LeakyCompute/actions/runs/33783342333) |
| 17:43 | 20:07 | 2h 24m | 47 | 18 | 0 | [success](https://github.com/MahdiHedhli/LeakyCompute/actions/runs/33800446759) |
| 22:13 | 00:01 next day | 1h 48m | 150 | 19 | 13 | [success](https://github.com/MahdiHedhli/LeakyCompute/actions/runs/33820041291) |

The large nominated-to-leased gap is expected enforcement, not silent failure.
The Durable Object skipped candidates under the 14-day host interval and the
per-neighborhood or per-ASN rate gates. A successful job can therefore publish
fresh aggregates without increasing every public number.

## Metric and evidence definitions

- **Nominated** means a fresh public-index tuple was accepted into the immutable
  nomination ledger. It does not mean target traffic was sent.
- **Leased** means the strong control plane found the tuple eligible and issued
  a one-time permit after exclusions, provenance, interval, and rate checks.
- **Exposed outcome** means the bounded read-only target check answered with the
  reviewed exposure signal. It is not demonstrated exploitability.
- **Rolling retained hosts** is the authoritative 180-day corpus count. It is a
  distinct-host measure and is not additive with exposure-class pairs.
- **Public-index records** is the sum of overlapping per-lane index totals from
  a complete all-lane measurement. It is not a deduplicated host count.

Evidence came from GitHub Actions run metadata and public-safe step summaries,
the authenticated preflight budget snapshots, the private manifest's
aggregate-only metadata, and the public `/v1/stats` response. No address-level
artifact, credential, researcher identity, or target detail was copied here.

## Corrective controls

- Move the adaptive catch-up from 22:13 to 18:13 UTC, leaving a 5h 47m buffer
  before reset. Concurrency remains serialized, and packet-free preflight still
  clamps or skips against both KV and Shodan headroom.
- Publish `indexed_observed` only when the requested and completed lane sets
  exactly equal the reviewed lane registry and every lane supplied a total.
- Keep independent lane cursors and failure isolation: a failed lane advances
  nothing and contributes neither a false zero nor a partial census value.

GitHub explicitly documents that scheduled Actions can be delayed under load
and may even be dropped; cron time is therefore a request, not a deadline:
[GitHub schedule event documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule).

## Post-repair production verification — 4 September 2026 UTC

The packet-free preflight for a manually dispatched 425-candidate ceiling found
916 Shodan source units and 964 governed KV operations available. The all-lane
run nominated 212 candidates; the strong control plane leased 26, safely gated
186 under interval or rate controls, confirmed 12 exposure outcomes, and
published a new authoritative aggregate generation. The
[run completed successfully](https://github.com/MahdiHedhli/LeakyCompute/actions/runs/33827429330).

A second all-lane run from the repaired revision used a 10-candidate ceiling.
It nominated 10, leased seven, safely gated three, found no new exposure
outcomes, and published successfully. Its complete 14-lane manifest measured
21,970 public-index records with no failed lanes. The public API then reported
exactly 21,970 records with a fresh observation time and 1,479 rolling retained
hosts. This proves both the complete-measurement publication gate and the
observation-only ingest path in production. The
[validation run completed successfully](https://github.com/MahdiHedhli/LeakyCompute/actions/runs/33828078913).

The social-preview hook ran after aggregate publication, rendered the same
19,348 archive, 21,970 public-index, and 1,479 rolling re-verification values,
and triggered the public-site deployment.

## Limitations and follow-up

Four complete days now confirm that GitHub's schedule delay is persistent, not
an isolated event. The largest observed delay was 5h 31m. The 18:13 catch-up
still completed before the 00:00 UTC reset on every complete day reviewed, but
the remaining margin is not large enough to treat the trigger as a deadline. If
the catch-up begins crossing reset, move it outside GitHub Actions or add an
independent scheduler rather than weakening the budget or safety gates.

## Multi-day operations review — 4–8 September 2026 UTC

### Result

Governed discovery is running, ingestion is advancing, and the public counter
pipeline is current. From the 4 September post-repair baseline to the 8
September review, public-index observations increased from 21,970 to 22,397,
rolling retained hosts increased from 1,479 to 1,611, and exposure pairs
increased from 1,484 to 1,620. The social preview displays the same 19,348
archive, 22,397 public-index, and 1,611 rolling re-verification values.

Across all repository workflows from 4 September through the review, CI,
public-site deployment, the lab gate, social-preview refresh, and dependency
maintenance had no failed runs. Governed discovery had one failed run followed
by a successful all-lane recovery; every other governed-discovery run
completed successfully.

### Daily governed-discovery throughput

The 8 September row is partial because only the first two delayed scheduled
runs had started when this review closed.

| UTC date | Successful scheduled runs | Nominated | Leased | Exposure outcomes | Final exact KV use | Shodan source units |
|---|---:|---:|---:|---:|---:|---:|
| 5 Sep | 5/5 | 474 | 123 | 48 | 149/990 | 36 |
| 6 Sep | 5/5 | 447 | 145 | 30 | 173/990 | 36 |
| 7 Sep | 5/5 | 432 | 136 | 32 | 165/990 | 36 |
| 8 Sep, partial | 2/2 | 141 | 64 | 12 | 44/990 before the second run | 12 |

The 5–7 September catch-ups completed with 82.5%–84.9% of the configured KV
allowance unused. Raising only the probe ceiling will not consume that headroom:
the nominator currently supplies roughly 200 candidates to a complete all-lane
pass, and the strong control plane correctly rejects many of them under the
14-day host interval and rate gates.

### One safe zero-work run was reported as a failure

The only governed-discovery failure in the review window occurred on 4
September when three passive lanes completed successfully but no candidate
survived the provenance and authority gates. No target traffic was authorized.
The workflow then treated the empty durable nomination set as an exception.
The next all-lane catch-up succeeded. This is fail-closed and safe, but it is a
false operational alarm: a healthy zero-work shard should commit its successful
cursors, publish any permitted observation-only aggregate, and exit as a
successful no-op.

Evidence: [zero-work failure](https://github.com/MahdiHedhli/LeakyCompute/actions/runs/33913341645),
[recovery catch-up](https://github.com/MahdiHedhli/LeakyCompute/actions/runs/33917561879).

### Shodan traversal is not yet a lossless backlog

Every lane completed at least one page-cursor cycle by 6 September, but this
does **not** mean the candidate list is complete. Search lanes can pull up to
100 rows from a page and retain only their 20–40 candidate lane ceiling before
advancing the page cursor. A complete 7 September all-lane run pulled 936 rows
but committed 198 candidates. Depending on stable result ordering, rows beyond
the per-lane slice may never be durably queued.

For that reason, neither 1,611 divided by 22,397 nor cursor wrap count is a
valid completion percentage. The public-index total is overlapping per-lane
observations; the retained count is deduplicated distinct hosts; and the
current cursor is a sampled traversal rather than a lossless work ledger. The
present system can report that one sampled sweep completed, but it cannot yet
state how close it is to exhausting the Shodan candidate set.

The longest current lane has advanced through approximately five of 20 pages
in its new cycle. At the observed two passes per day it should wrap again in
roughly seven to eight days, but that wrap remains a sampling milestone rather
than backlog completion.

### Recommended repairs and optimizations

1. Make a successful empty nomination manifest a successful no-op while
   preserving fail-closed lane, cursor, and authorization behavior.
2. Replace page-only progress with a durable page-and-offset cursor or candidate
   queue. Do not advance a source page until every eligible row on it has been
   durably queued; persist an offset when a ceiling cuts through a page.
3. Allocate nominations fairly across lanes so a high-volume early lane cannot
   starve later lanes.
4. Let the final daily catch-up execute additional bounded waves. Before each
   wave, re-read the strong KV and paced-source ledgers and stop on the first of:
   the safety reserve, source budget, empty queue, or an operational wall-clock
   limit. This makes unused daily allowance recoverable without weakening the
   per-target controls.
5. Add aggregate-only counts for contained platform errors and deferred retries
   to the run summary. The reviewed period saw one or two contained platform
   errors in several catch-ups, none in the two latest runs; they did not abort
   other lanes.
6. Keep monitoring actual schedule delay. The schedule delivered all five
   expected runs on 5, 6, and 7 September, but start delays ranged from roughly
   1h 47m to 5h 31m.

The social-preview hook is functioning as designed. It produced 35 successful
refreshes and 35 successful public deployments in the review window, plus 22
counter-only commits after the prior production baseline. Coalescing these into
fewer deployments could reduce Actions and history churn, but it is lower
priority than making source traversal lossless and would change the current
update-on-counter-change behavior.
