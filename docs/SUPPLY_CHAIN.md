# Supply-chain baseline

**Reviewed:** 2026-08-25

This file records what was pinned and how to update it. A version label is useful
for humans; the immutable SHA or digest is what execution trusts.

## GitHub Actions

Each reference was resolved from its official `actions/*` release tag. GitHub's
commit API reported a valid verification signature, and the action metadata uses
Node 24 (or is a composite action whose nested upload action is itself SHA
pinned).

| Action | Release | Commit |
|---|---:|---|
| `actions/checkout` | 7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `actions/setup-node` | 7.0.0 | `820762786026740c76f36085b0efc47a31fe5020` |
| `actions/setup-python` | 7.0.0 | `5fda3b95a4ea91299a34e894583c3862153e4b97` |
| `actions/github-script` | 9.0.0 | `3a2844b7e9c422d3c10d287c895573f7108da1b3` |
| `actions/upload-pages-artifact` | 5.0.0 | `fc324d3547104276b827a68afc52ff2a11cc49c9` |
| `actions/deploy-pages` | 5.0.0 | `cd2ce8fcbc39b97be8ca5fce6e763baed58fa128` |

Workflows use `ubuntu-24.04`, not the cross-release `ubuntu-latest` alias.
Checkout credentials are not persisted in jobs that do not push.

## npm and Wrangler

- Node in CI: `24.19.0` (Krypton LTS).
- Python in the passive planner workflow: `3.12.14`.
- Wrangler: `4.126.0`, exact in `package.json` and integrity locked by
  `package-lock.json`.
- CI installs with `npm ci --ignore-scripts` before running `npm test`.
- Worker deployment continues to use the minimal-scope local OAuth procedure in
  [`DEPLOY.md`](DEPLOY.md); pinning does not change deployment ownership.

## Local fingerprint-lab images

These are multi-architecture registry manifest digests resolved on the review
date. Keeping the human-readable tag makes the upstream channel visible, but the
digest prevents that tag from changing what runs.

| Image reference | Manifest digest |
|---|---|
| `ollama/ollama:latest` | `sha256:57d60e686821ea81a7748a3ec8141308c8b8f95b27105713954abf7a6529e700` |
| `quay.io/jupyter/base-notebook:latest` | `sha256:23fbe16371af3c0fdc833fa0962b42fd07811e152b821ff51d19a8d6e9cc86cf` |
| `rayproject/ray:latest` | `sha256:61fee5839b2c5e640059a132be3312019c61badbb2396b513d8536b6db82ac4d` |
| `ghcr.io/open-webui/open-webui:main` | `sha256:c792953395b43d4f49085fa4026850c5e923578345ebeaf56eabd980bcfc273a` |
| `ghcr.io/mlflow/mlflow:latest` | `sha256:9f9276e57cda1593cfa0fe8519145cd49328e119e85951851b9244e82e3769be` |
| `python:3.11-slim` | `sha256:be1575ed968de893bd54f4c56315ff7c4736ce522c1bca08fd521731aafc0d76` |

The two Jupyter services intentionally share one image digest. The TensorBoard
container installs `tensorboard==2.21.0` and all twelve transitive packages from
an exact, SHA-256-locked requirements file covering the Linux x86_64 and aarch64
wheels. It is a manual, loopback-only validation fixture and never runs in CI or
production.

## Update procedure

1. Start from a Dependabot PR or an upstream release—not a floating major tag.
2. Read the release notes and inspect action metadata, image provenance, and any
   permission/runtime changes.
3. Replace the immutable SHA/digest and its adjacent human-readable version
   together.
4. Run `npm ci --ignore-scripts`, `npm audit`, `npm test`, and
   `docker compose -f scripts/discovery/local-lab/docker-compose.yml config`.
5. For image changes, start only the affected loopback-bound fixture and verify
   the expected fingerprint before accepting the update.

## Remaining repository setting

The `CI / Invariant suite` workflow exists, but `main` currently has no branch
protection or ruleset. Making that check mandatory changes the repository from
the current direct-push workflow to a protected merge workflow and therefore
requires an explicit maintainer decision; a YAML file cannot safely make that
choice on its own.
