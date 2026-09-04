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

One day of delay observations is enough to prove that 22:13 is unsafe, but not
to characterize GitHub's long-run delay distribution. Monitor actual versus
nominal start time for seven days. If an 18:13 catch-up ever crosses reset, move
the trigger outside GitHub Actions or add an independent scheduler rather than
weakening the budget or safety gates.
