# Security gap analysis

Reviewed against source in the current working tree on 2026-10-30. This is a
source-level readiness review, not a penetration test or a claim that runtime
controls were exercised. No targets were scanned.

## Controls present in source

- The model-facing executor now permits only `which` lookups, fixed `df` and
  `free` diagnostics, and version checks for four diagnostic tools. Shells,
  interpreters, executable paths, caller-supplied working directories, and
  environment overrides are denied at the Docker client boundary.
- MCP `run_workflow` returns an audited refusal without invoking workflow code.
  Direct calls to `GenericExecutor`, `execute_script`, workflow methods, and
  `WorkflowRegistry.run_workflow` still converge on the DockerClient policy;
  bypassing the higher-level validator does not enable active commands.
- A separate dry-run authorization tool checks only loopback HTTP(S) targets,
  explicit ports, methods, expiry/revocation, DNS answers, record structure,
  and a matching creation audit event. It never contacts a target or enables
  execution. A successful authorization remains insufficient to run a scan.
- The operator helper writes authorization records to a host directory mounted
  read-only into the MCP service. The MCP service writes a separate local audit
  file. Both files are coordinated by a cross-process lock stored next to the
  writable audit file. This is not a two-file transaction: a grant whose
  creation audit event is absent fails closed, and a persisted revocation stays
  revoked if the audit write fails. The audit is local and tamperable.
- OpenCode no longer has the Docker socket. A separate MCP service holds it on
  an internal-only Compose network; the toolbox is on a distinct internal
  network, read-only apart from bounded tmpfs mounts, and has all Linux
  capabilities dropped.
- The privacy gateway tokenizes configured values and sanitizes tool output.
  The OpenCode plugin uses a shared local Unix socket for pre-model prompt
  tokenization and fails closed if it is unavailable.

These are source-level controls, not a general sandbox or runtime assurance.
The MCP service still holds a host-administrator Docker socket, and the local
operator attestation does not independently prove ownership of a target.
The release Compose socket mount uses `:ro`, but this only marks the socket
filesystem mount read-only; Docker API requests remain capable of changing
daemon state. The development Compose mount is writable. Either grants
host-administrator-equivalent Docker access and permits bypassing this Python
boundary if the MCP process is compromised.

## Gaps and priorities

| Priority | Gap | Evidence / consequence |
|---|---|---|
| **P0 — before active assessment** | There is no supported active-execution path yet. | Commands outside the diagnostic set are denied at the DockerClient boundary; direct executor/workflow calls and MCP tools cannot invoke a scanner. The helper supports only loopback operator attestations and records never enable scanning. |
| **P0 — before deployment** | The MCP service still holds the Docker Engine socket. | Docker socket access is effectively host-administrator access. The OpenCode service no longer mounts it and the MCP HTTP endpoint is confined to an internal network, but compromise of the MCP service remains a host-level risk. |
| **P0 — before relying on proxy isolation** | `docker-compose.socket-proxy.yml` does not connect MCP to the socket proxy. | The overlay replaces MCP's socket bind with a newly created empty named volume mounted at `/var/run/docker.sock`, and sets `DOCKER_HOST=unix:///var/run/docker.sock`. It does not point the Docker SDK at the proxy service's TCP API (normally `tcp://socket-proxy:2375` on the shared Compose network). Compose syntax validation does not test connectivity. This overlay currently provides no usable socket isolation and must not be represented as a mitigation. |
| **P1 — deployment hardening** | Services run as root and resource use is not bounded. | Toolbox explicitly sets `user: "0:0"`; MCP and OpenCode inherit root from the runtime image. Toolbox and MCP drop capabilities, but OpenCode does not. No service sets CPU, memory, or PID limits. |
| **P1 — writable host data** | MCP and OpenCode share writable host bind directories. | Settings, reports, and sessions are mounted read-write; MCP also mounts workflow sources read-only and authorization registry read-only. Compromise of either process can modify the writable host-side data. Several configured bind paths were absent during inspection and may be created automatically by Compose. |
| **P1 — readiness checks** | Current healthchecks can report incorrect status. | Release MCP Compose uses exec-form `CMD` with literal `|| exit 1`; shell operators are not interpreted. Toolbox's image healthcheck invokes shell builtin `command` as an executable. Development MCP inherits an OpenCode-binary existence check rather than checking MCP readiness. |
| **P2 — mutable image supply chain** | Release Compose uses `latest` with `pull_policy: always`. | A future start can pull changed image contents without a source revision change. Pin reviewed image digests for reproducibility and update them deliberately. |
| **P2 — build network scope** | Development image builds use `build.network: host`. | This is build-time networking, not runtime `network_mode: host`; it grants the build process host-network reachability during dependency downloads. Keep builds from untrusted Dockerfiles off the host network where possible. |
| **P0 — before active assessment** | Target/redirect enforcement is not integrated with a network worker. | Authorization is a dry run. The parser accepts only loopback HTTP(S), validates explicit ports/methods, expiry/revocation, and pinned DNS; no scanner or HTTP client follows redirects through it. Public/private-network targets and cloud metadata are rejected. |
| **P0 — manual bypass paths** | Some developer lab scripts used raw Docker exec and shell commands outside the MCP boundary. | `tools/lab-tests/run-lab-tests.sh` and `pr42-repro/reproduce.sh` now stop before Docker access. `privacy-e2e-campaign.py` uses the diagnostic-only policy and structured argv; scanner attempts are denied. The local privacy-gateway harness only uses a temporary loopback listener and local temp files. |
| **P1** | Active workers are disabled, so rate/concurrency and full cancellation remain unimplemented. | A pre-start cancellation event is honored by the DockerClient API, but MCP has no cancellation endpoint and running execution cannot be cancelled reliably. Any future worker needs request budgets, per-target limits, and tested in-flight cancellation. |
| **P1** | Registry and audit are separate JSON files, not a crash-atomic transaction. | Per-file atomic replace and a cross-process lock prevent concurrent lost updates. A missing creation event makes a record unusable; revocation is persisted before its audit write. A process crash can still leave orphan audit events or an unusable grant, and local audit data is not tamper-evident. |
| **P1 — before enabling a worker** | No active operation/request binding exists because active execution is not supported. | Dry-run checks are correlated with request IDs in the audit log. A future worker must bind authorization ID, operation, canonical target, port, resolved destination, and redirect handling at the actual connection boundary; it must not trust a preflight Boolean. |
| **P1** | The internal MCP HTTP transport has no authentication. | Compose attaches only OpenCode and MCP to an internal-only network and publishes no MCP port. Do not attach untrusted containers or publish the service without authentication and access controls. |
| **P1 — credentials** | `mcp/.env` was tracked and modified at the start of this work, and `Dockerfile.opencode` copies the `mcp` tree into the image. | The file is now removed from the Git index while the local copy remains ignored; this stages a deletion but does not rewrite history. A new `.dockerignore` excludes env files from future image build contexts. Its contents were intentionally not read. If it contains real secrets, rotate them and follow repository policy for historical removal. |
| **P1 — CI runner** | The image workflow purges Docker resources before building. | The step removes all containers, images, volumes, non-default networks, and builder cache on its self-hosted runner. The workflow currently gates execution to `aram07324/gregorforge-prod`; keep that runner dedicated and verify the gate before enabling the workflow elsewhere. |
| **P2** | Runtime behavior is unverified. | Compose syntax and focused unit tests pass, but Docker was not started; container startup, the read-only toolbox, the split MCP transport, and the shared tokenization socket have not been exercised. |

The toolbox runtime does not use host networking, has no Docker-socket mount,
and receives no added capabilities. `docker-compose-dev.yml` does set
`build.network: host`, which is build-time only. The audit log is local and
writable, not tamper-proof. Docker Desktop was running, but no GregorForge
service was started in the Phase 4 review.

## Phase 4 container and provider readiness

Compose validation passed for the release, development, and combined
socket-proxy overlay. Validation was syntax/interpolation only. Compose
publishes no host ports; the OpenCode service is a terminal CLI, and MCP's
HTTP listener is internal-only on port 8181. The toolbox and MCP are on
separate internal networks. OpenCode additionally joins the default
egress-capable network. No service has resource limits, and no active scans
or targets were used.

The Windows host has 8 GiB RAM, 25.78 GiB free disk, and about 0.87 GiB free
RAM at inspection. Docker Desktop assigns 4 GiB to its Linux VM. Docker
reports 12.47 GB of images and 22.91 GB of build cache; no cleanup was run.
Both GregorForge release images are absent. The toolbox build is especially
heavy because it compiles toolchains from a CUDA development image and fetches
security tools and wordlists. Defer local builds until substantially more
memory is available; do not prune cache to make room.

The `.opencode.env` file exists but has comments only. The cloud setup path
requires an API key; OpenRouter free model variants, Gemini's limited free
API, and Groq's rate-limited API all still require provider credentials.
OpenRouter's free models may change, may be rate-limited, and may not support
the tool use required by OpenCode; avoid any paid fallback if a strict zero
cost is required. Gemini's current free-tier terms state that content may be
used to improve products. Do not send sensitive assessment data to any free
cloud tier without reviewing the terms. No provider request was made.

Relevant non-starting validation:

```powershell
docker compose -f docker-compose.yml config --quiet
docker compose -f docker-compose-dev.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.socket-proxy.yml config --quiet
```

The combined overlay check emits a warning that its top-level `version` field
is obsolete. Relative host bind directories for settings, reports, sessions,
workflows, and authorization state are absent. Compose may create them during
startup; review and deliberately prepare them before any launch.

The socket-proxy overlay mounts a new empty named volume over the MCP socket
path and sets `DOCKER_HOST=unix:///var/run/docker.sock`, rather than directing
the SDK to the proxy service's TCP API (normally `tcp://socket-proxy:2375` on
the shared network). Its `EXEC: 1` and `POST: 0` settings also need
endpoint/method-level verification against the Docker SDK's exec calls before
an allowlisted broker design can work. Do not rely on this overlay for
isolation.

## Required gates before scanning

1. Keep active execution disabled until a restricted broker replaces
   host-administrator Docker socket access and shell-string dispatch.
2. Design a worker that binds authorization ID, operation, canonical target,
   port, DNS-pinned address, expiry/revocation, and every redirect at connection
   time. Do not extend loopback-only grants to public targets by inference.
3. Add per-target request/concurrency budgets and reliable cancellation before
   any worker is enabled.
4. Migrate registry and audit state to one transactional store only with an
   explicit compatibility/migration plan; then add tamper evidence and verified
   operator authority.
5. Test the split services and Unix-socket handoff with local fixtures before
   considering any active workflow.

Keep active assessments disabled. No container, model provider, or target was
started or contacted during this work.

## License note

The repository is GPL-3.0. Preserve license and attribution notices. A
commercial product may use GPL software, but distributing a derivative or
combined work can require corresponding source and GPL rights; obtain legal
advice before selecting a packaging model.
