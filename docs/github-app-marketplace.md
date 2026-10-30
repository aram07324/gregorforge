# GitHub Action and App product scaffold

This repository contains an experimental GitHub integration. It is not a
released GitHub Action, a hosted scanning service, or a Marketplace-ready
product.

## Checks and scanning boundaries

- Pull requests that touch the integration policy run the allowlist-policy unit
  tests and publish a check summary. The PR job has read-only repository
  permissions, does not persist its checkout token, and does not receive
  repository variables or secrets.
- A manually dispatched workflow checks that one HTTPS origin exactly matches
  the repository variable `GREGORFORGE_AUTHORIZED_TARGETS`, formatted as a JSON
  array, for example `["https://staging.example.com"]`.
- The composite action can be reused to perform this same preflight.
- A separate **manual** preview workflow can scan an already-deployed preview
  after a protected-environment reviewer approves the run and a trusted
  provider attests to its exact PR commit and origin. It sends one `HEAD /`
  request and reports security-header and cookie-attribute checks as a GitHub
  Check Run.

The PR-triggered workflow and the basic preflight are intentionally
non-networking. **No `pull_request` event starts a scan.** Manual preview
scanning is fail-closed and is skipped unless both
`GREGORFORGE_PREVIEW_CHECK_ENABLED` and `GREGORFORGE_PREVIEW_EGRESS_LOCKED`
repository variables are exactly `true`.

The preview check is deliberately small and non-exploitative: it does not
follow redirects, send a request body, submit credentials, crawl links, or retain
response bodies. It checks HSTS `max-age`, presence of CSP,
`X-Content-Type-Options`, `Referrer-Policy`, frame protection, and the Secure,
HttpOnly, and SameSite attributes on response cookies. These are basic
header checks, not a full CSP or application-policy review. A passing result is not proof of
ownership, legal authorization, or overall security.

## GitHub Action setup

1. In repository or organization Actions variables, set
   `GREGORFORGE_AUTHORIZED_TARGETS` to a JSON array of exact HTTPS origins.
   Wildcards, paths, query strings, and non-HTTPS URLs are rejected.
2. Run **GitHub integration preflight** from the Actions tab and provide an
   origin that is in that configured list.
3. Use pull-request runs to test policy changes. Do not add secrets or scanner
   execution to the `pull_request` job.

## Protected preview-check setup

The preview scanner is **not safe to enable on a general-purpose runner**.
Before enabling it:

1. Provision an ephemeral, single-job Linux runner labelled
   `gregorforge-preview-scan`. It must have no Docker socket, cloud metadata
   access, persistent credentials, or shared workspace with other jobs.
2. Enforce default-deny egress outside the workflow. Permit only the GitHub
   Actions control plane and endpoints required to download the pinned actions
   and Python runtime, the GitHub API, the configured preview-provider API,
   DNS required by those services, and the exact attested preview origin on
   HTTPS. The runner/network boundary must
   prevent private, loopback, link-local, and metadata destinations even if
   application-level checks fail. The workflow variable
   `GREGORFORGE_PREVIEW_EGRESS_LOCKED=true` is an operator assertion, not a
   firewall and not proof that egress is restricted.
3. Configure the `preview-scan` GitHub Environment with required reviewers,
   prevent self-review where possible, and allow deployment only from the
   protected `main` branch. Do not place these secrets in repository-wide
   secrets or PR-triggered workflows.
4. Configure repository variables:
   - `GREGORFORGE_PREVIEW_CHECK_ENABLED=true`
   - `GREGORFORGE_PREVIEW_EGRESS_LOCKED=true` only after testing the network
     boundary
   - `GREGORFORGE_PREVIEW_PROVIDER_URL=https://<trusted-provider-origin>`
   - `GREGORFORGE_AUTHORIZED_TARGETS` as a JSON array containing the exact
     preview origins that provider is allowed to attest
5. Add Environment secrets:
   - `GREGORFORGE_PREVIEW_PROVIDER_TOKEN`: read-only credential for the
     provider's one-preview lookup endpoint
   - `GREGORFORGE_PREVIEW_ATTESTATION_KEY`: random key with at least 32 bytes
     of entropy, shared securely with the provider. Rotate it if exposed.
6. Dispatch **Authorized preview security check** from `main`, enter an open
   PR number, and approve the `preview-scan` environment deployment. The job
   verifies the PR base, open/non-draft state, current head commit, attestation
   signature/expiry, exact origin allowlist, and PR head again immediately
   before connecting.

### Preview-provider contract

`GET /v1/previews/github/{owner}/{repo}/{pull_request}` must return a bounded
JSON object containing exactly these fields:

```json
{
  "repository": "owner/repo",
  "pull_request": 42,
  "head_sha": "<40- or 64-character commit SHA>",
  "preview_id": "preview-42",
  "origin": "https://preview.example.com",
  "expires_at": "2030-01-01T00:10:00+00:00",
  "status": "ready",
  "signature": "<lowercase hex HMAC-SHA256>"
}
```

The signature is HMAC-SHA256 over UTF-8/ASCII bytes of the seven unsigned
fields (`expires_at`, `head_sha`, `origin`, `preview_id`, `pull_request`,
`repository`, `status`) serialized as JSON with sorted keys, separators
`(",", ":")`, and `ensure_ascii=true`. The provider must bind the preview to the
actual PR head commit, set expiry no more than 15 minutes ahead, and only attest
to previews it created in an isolated environment. The check independently
compares the attestation against GitHub's PR API and operator allowlist.

Provider tokens and signing keys must not be sent to a preview. Do not let PR
code choose provider endpoints, network destinations, attestation fields, or
workflow secrets. For high-assurance deployments, replace shared HMAC with a
rotatable asymmetric signing key and pin the provider's public key.

The preview check creates a GitHub Check Run on the PR head (`checks: write`),
then completes it with a summary. It never includes the target URL, raw
response headers, or response body in the check output. A non-2xx response,
redirect, stale attestation, missing header, or incomplete trust configuration
fails the check. If the runner disappears before completion, the Check Run may
remain in progress; monitor and expire abandoned runs operationally.

Example composite-action use:

```yaml
- uses: aram07324/gregorforge/.github/actions/authorized-target-preflight@main
  with:
    target: https://staging.example.com
    authorized-targets: '["https://staging.example.com"]'
```

Pin a reviewed commit SHA instead of `@main` in production workflows.

## GitHub App scaffold

`.github/github-app-manifest.json` is a permission-minimal draft manifest. Before
creating an App, replace both `example.invalid` callback and webhook URLs with
the HTTPS endpoints of a deployed service. A backend is not included: webhook
signature validation, delivery replay protection, installation-token handling,
check-run publishing, storage, and operational monitoring still need design and
implementation. Keep PR payloads as untrusted input and never run code supplied
by a pull request in a privileged App worker.

## Hosted service and Marketplace path

The likely paid product is a hosted GitHub App that publishes check runs and
team reports, with the local CLI remaining available under its existing
license. This repository does not implement Marketplace billing, subscriptions,
entitlements, accounts, or a hosted API. Marketplace publication requires a
working service, a reviewed GitHub App, support and privacy policies, and
completion of GitHub's then-current Marketplace requirements.

This preview check is not the full GregorForge scanner and does not execute
MCP workflows. Before adding broader active scanning, require verified
authorization and a customer-controlled, explicitly configured target scope.
Run scanners in isolated workers with narrow egress controls, quotas,
cancellation, audit logs, and human approval. A hostname allowlist alone is not
proof of authorization or a sufficient network boundary.

The project is GPLv3. Selling access or hosted services does not remove
obligations that apply when distributing GPL-covered software. Get legal advice
before adding proprietary components or distributing modified binaries.
