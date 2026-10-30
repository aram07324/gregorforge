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

### Create the Vercel preview target and provider

The repository includes a small static preview target and a Vercel Function at
`preview-site/api/v1/previews/github/[owner]/[repo]/[pull_request].js`. The
function asks the Vercel API for ready deployments of the current GitHub PR
head SHA, requires the repository and PR metadata to match, and signs the
deployment URL and commit SHA. It never accepts a target URL from the request.
The scanner separately compares the attested SHA against GitHub's current PR
head.

1. Import `aram07324/gregorforge` as a Vercel project. Set the project **Root
   Directory** to `preview-site`, the production branch to `main`, and enable
   GitHub Preview deployments. Use the `Other` framework preset if prompted.
2. Deploy `main` and confirm that the static page and API function are
   available on the production deployment. The provider route is
   `https://<production-origin>/api/v1/previews/github/aram07324/gregorforge/<PR-number>?head_sha=<current-PR-SHA>`.
3. Add these variables/secrets to the Vercel project's **Production** environment
   only. Do not expose them to Preview deployments:
   - `GREGORFORGE_PREVIEW_PROVIDER_TOKEN`: a newly generated random bearer token
     of at least 32 bytes.
   - `GREGORFORGE_PREVIEW_ATTESTATION_KEY`: a separate random key with at least
     32 bytes of entropy.
   - `VERCEL_TOKEN`: a dedicated Vercel API token for the account/team that
     owns the project. Restrict its access as much as Vercel allows.
   - `VERCEL_TEAM_ID`: the owning team ID when this is a team project; omit for
     a personal project.
4. Enable Vercel's **System Environment Variables** setting so the function can
   read the automatically populated `VERCEL_PROJECT_ID`. Redeploy Production
   after adding the variables. Keep the provider tokens and
   signing key out of Git, Vercel Preview environment variables, and pull
   requests. Configure the matching provider token and signing key later as
   `preview-scan` GitHub Environment secrets.

Each Vercel deployment has a unique origin. For each manual scan, set
`GREGORFORGE_AUTHORIZED_TARGETS` to a JSON array containing the exact origin
for that PR's completed Vercel Preview deployment, for example
`["https://project-git-feature-aram07324.vercel.app"]`. Do not use wildcard
domains. If Vercel returns a new deployment origin, update the exact allowlist
before dispatching the check.

### Provision and isolate the runner

1. Provision an ephemeral, single-job Linux runner labelled
   `gregorforge-preview-scan`. It must have no Docker socket, cloud metadata
   access, persistent credentials, or shared workspace with other jobs.
2. Register it only to this repository (or a runner group restricted to this
   repository), with the exact labels `self-hosted`, `linux`, `x64`, and
   `gregorforge-preview-scan`. Configure the runner as ephemeral and single-use.
   GitHub warns that self-hosted runners on public repositories can be exposed
   to dangerous code from pull requests. This workflow checks out only trusted
   `main` code and has no PR trigger, but the runner must still never be shared
   with builds or arbitrary repository workflows.
3. Put the VM in a private subnet with no inbound public SSH. Enforce outbound
   traffic at the OCI network boundary (for example through an OCI Network
   Firewall and a default-deny route); do not rely only on host firewall rules
   or the workflow's variables. Allow only the GitHub Actions control plane and
   action/runtime download endpoints, GitHub API, this Vercel provider origin,
   DNS needed for those services, and HTTPS to the exact preview origin being
   scanned. Block private, loopback, link-local, and cloud metadata destinations
   independently of the Python scanner. Test the controls from the runner.
   OCI egress allowlists must account for GitHub's changing service IP ranges;
   maintain the rules as those ranges change.
4. Configure the `preview-scan` GitHub Environment with required reviewers,
   prevent self-review, and allow deployment only from the `main` branch.
   Verify the protection rule is active before adding secrets. Do not place
   these secrets in repository-wide
   secrets or PR-triggered workflows.
5. Configure repository variables:
   - `GREGORFORGE_PREVIEW_CHECK_ENABLED=true`
   - `GREGORFORGE_PREVIEW_EGRESS_LOCKED=true` only after testing the network
     boundary
   - `GREGORFORGE_PREVIEW_PROVIDER_URL=https://<production-origin>` with no
     path or trailing slash
   - `GREGORFORGE_AUTHORIZED_TARGETS` as a JSON array containing only the exact
     Vercel Preview origin for the PR being checked
6. Add Environment secrets:
   - `GREGORFORGE_PREVIEW_PROVIDER_TOKEN`: read-only credential for the
     provider's one-preview lookup endpoint
   - `GREGORFORGE_PREVIEW_ATTESTATION_KEY`: random key with at least 32 bytes
     of entropy, shared securely with the provider. Rotate it if exposed.
7. Dispatch **Authorized preview security check** from `main`, enter an open
   PR number, and approve the `preview-scan` environment deployment. The job
   verifies the PR base, open/non-draft state, current head commit, attestation
   signature/expiry, exact origin allowlist, and PR head again immediately
   before connecting.

The repository is public. Do not treat the self-hosted runner as a general
CI worker. If OCI cannot provide independently enforced egress restrictions
and a one-job runner lifecycle, leave `GREGORFORGE_PREVIEW_CHECK_ENABLED`
unset and do not register the runner.

### Preview-provider contract

`GET /v1/previews/github/{owner}/{repo}/{pull_request}?head_sha={current_sha}`
must return a bounded JSON object containing exactly these fields:

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
