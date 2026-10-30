# GitHub Action and App product scaffold

This repository contains an early integration scaffold, not a released GitHub
Action, a hosted scanning service, or a Marketplace-ready product.

## What works today

- Pull requests that touch the integration policy run the allowlist-policy unit
  tests.
- A manually dispatched workflow checks that one HTTPS origin exactly matches
  the repository variable `GREGORFORGE_AUTHORIZED_TARGETS`, formatted as a JSON
  array, for example `["https://staging.example.com"]`.
- The composite action can be reused to perform this same preflight.

The preflight is intentionally non-networking: it performs no DNS lookup,
connection, scan, or exploitation. Passing the check is not proof of ownership
or legal authorization. It is an operator-configured scope check only. No PR
event triggers a scan, and no scanner is currently connected to this workflow.

## GitHub Action setup

1. In repository or organization Actions variables, set
   `GREGORFORGE_AUTHORIZED_TARGETS` to a JSON array of exact HTTPS origins.
   Wildcards, paths, query strings, and non-HTTPS URLs are rejected.
2. Run **GitHub integration preflight** from the Actions tab and provide an
   origin that is in that configured list.
3. Use pull-request runs to test policy changes. Do not add secrets or scanner
   execution to the `pull_request` job.

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

Before adding active scanning, require verified authorization and a
customer-controlled, explicitly configured target scope. Run scanners in
isolated workers with narrow egress controls, quotas, cancellation, audit logs,
and human approval. A hostname allowlist alone is not proof of authorization or
a sufficient network boundary.

The project is GPLv3. Selling access or hosted services does not remove
obligations that apply when distributing GPL-covered software. Get legal advice
before adding proprietary components or distributing modified binaries.
