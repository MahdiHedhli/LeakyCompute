# Disclosure engagement plan

**Status:** first-contact draft; no host-identifying data sent

The policy is I-27: notify before any host-identifying publication, wait 90 days,
and keep aggregates ungated. This document starts the relationship needed to
make that policy operational without turning LeakyCompute into a mass-mailing
system.

## Confirmed Shadowserver entry point

Shadowserver's current guidance says it is open to security-incident data from
collaborators and directs prospective contributors to its
[contact form](https://www.shadowserver.org/contact/). The form explicitly says
not to include operationally sensitive information. Its public documentation
describes downstream reports as CSV, normally containing the IP, UTC timestamp,
and incident metadata needed for remediation:

- [Sharing data with Shadowserver](https://www.shadowserver.org/faq/can-i-share-data-with-you-what-kind-and-how/)
- [Report contents](https://www.shadowserver.org/faq/what-information-do-you-include-in-your-reports/)
- [Official report-schema repository](https://github.com/The-Shadowserver-Foundation/report_schema)

There is no documented public API for a new contributor to upload observations.
The published REST API and `report-manager` tooling are for vetted recipients to
retrieve reports. Do not repurpose them as an ingest path.

## First contact — no operational data

Use the official contact form and choose the closest partnership or data-sharing
category if the form offers one. Do not mark the inquiry urgent, and do not
include IP addresses, hostnames, corpus samples, credentials, or unpublished
counts.

**Subject:** Data-sharing inquiry: remediation for exposed AI services

> Hello Shadowserver team,
>
> I maintain LeakyCompute, a non-commercial defensive research project studying
> publicly indexed, internet-exposed AI services such as Ollama, Ray, and
> Jupyter. The project publishes aggregate measurements and local defensive
> tooling. Fresh public-index nominations may receive bounded, read-only daily
> verification under durable exclusions, cooldowns, rate limits, and one-time
> address-pinned permits. Daily work is split into small lane shards with an
> adaptive pre-reset catch-up pass. A separate Turnstile-gated hosted check lets
> an operator assess only the public address making the request.
>
> We are looking for a responsible way to help network owners and national
> CSIRTs remediate these exposures without publishing host-identifying data or
> building our own bulk-contact system. Before sharing any operational data, I
> would like to ask whether Shadowserver would be interested in either:
>
> 1. adding our reviewed, read-only service fingerprints to Shadowserver's own
>    scanning/reporting pipeline; or
> 2. evaluating a minimized observation feed from LeakyCompute over a private
>    transfer channel you specify.
>
> Could you advise whether either model fits your contributor program, who the
> appropriate technical contact is, and what freshness, schema, provenance,
> secure-transfer, opt-out/deletion, and attribution requirements you would
> expect? We can first provide methodology and a synthetic CSV containing no
> real hosts.
>
> Project: https://github.com/MahdiHedhli/LeakyCompute
> Security and ethics policy:
> https://github.com/MahdiHedhli/LeakyCompute/blob/main/docs/SECURITY.md
>
> Thank you,
> Mahdi Hedhli

The maintainer should edit this in their own voice before sending. The project
must retain a dated copy of the final text and Shadowserver's response, but not
publish private contact details or transfer credentials.

## Questions that must be answered before automation

1. Will Shadowserver add these fingerprints to its own collection, accept an
   external feed, or neither?
2. What observation freshness and confidence are required? Passive index
   records must never be described as LeakyCompute-confirmed exposure.
3. What exact report type, CSV fields, severity vocabulary, and UTC timestamp
   format should be used?
4. What private transport, encryption, authentication, acknowledgement, retry,
   and deletion process is required?
5. How should network-owner opt-outs, corrected false positives, and source-data
   deletions propagate?
6. May LeakyCompute be credited, or should the feed be anonymous?
7. Will Shadowserver accept data derived from a third-party index, or should it
   independently observe every reported endpoint?

## Censys licensing gate

Censys' current Platform API is the supported route for scripted access, but its
research terms prohibit redistributing Censys data to a third party without
prior written consent. Therefore:

- keep Censys records source-labeled and separate from historical direct
  observations;
- do not transmit raw Censys-derived IPs, hostnames, service records, or a
  reconstructable substitute to Shadowserver without written Censys consent;
- prefer asking Shadowserver to implement the public fingerprints in its own
  scanners, which avoids redistributing Censys data;
- publish only the source-specific aggregate and comparative research allowed by
  the applicable account terms, with required attribution.

References:

- [Censys Platform API](https://docs.censys.com/reference/get-started)
- [Censys research access](https://docs.censys.com/docs/research-access-to-censys-data)
- [Censys Terms of Service](https://censys.com/terms-of-service)

## Candidate handoff schema — synthetic until accepted

Do not implement or populate this with real data until Shadowserver specifies
its format and the source license permits transfer.

```csv
timestamp_utc,ip,protocol,port,service,observation_type,source,source_observed_at,severity,remediation_url
2026-01-01T00:00:00Z,192.0.2.10,tcp,11434,ollama,synthetic,synthetic,2026-01-01T00:00:00Z,high,https://example.invalid/remediation
```

Deliberately omitted unless requested and justified: hostname, organization,
geolocation, model names, job data, response bodies, credentials, exploitability
claims, and proof-of-impact actions. Shadowserver can enrich routing fields from
the IP; LeakyCompute should not duplicate identifying data by default.

## Automation only after acceptance

A future exporter must run privately and fail closed. It should:

1. select only an accepted source and freshness window;
2. apply current IP/CIDR/ASN exclusions immediately before export;
3. distinguish passive index observations from historical direct observations;
4. emit an allowlisted, deterministic schema with no extra retained fields;
5. encrypt/sign and transfer only over Shadowserver's specified channel;
6. persist a non-sensitive receipt, record count, source window, and content
   digest—never the exported host rows in CI logs or artifacts;
7. retry without duplicating a batch and support correction/deletion receipts.

Until those requirements are agreed, “programmatic disclosure” means generating
synthetic fixtures and validating field minimization—not sending real records.
