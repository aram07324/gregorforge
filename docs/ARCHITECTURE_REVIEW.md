# Architecture review

Reviewed against the current working tree on 2026-10-30. This is a source review,
not confirmation that the containers or an assessment run successfully.

## Components and data flow

```text
Operator / terminal
  -> gregorforge.sh
  -> OpenCode CLI and agent prompts
  -> MCP service / FastMCP tool entry points
  -> GenericExecutor or direct workflow calls
  -> DockerClient command policy
  -> Docker SDK / toolbox container (diagnostics only)
  -> tool output -> privacy gateway -> model
  -> local JSON campaign data and reports
```

- **CLI and AI orchestration:** [`gregorforge.sh`](../gregorforge.sh) launches
  the OpenCode-based CLI. Specialist prompts live in [`conf/agents/`](../conf/agents/).
  There is no web dashboard in this open-source checkout; the README identifies
  that as a paid Pro feature.
- **MCP server:** [`mcp/src/server.py`](../mcp/src/server.py) exposes health,
  diagnostics, generic execution, workflow discovery, a dry-run authorization
  check, and report-export tools. `run_workflow` returns an audited refusal and
  does not invoke the registry. MCP uses stdio by default; optional
  Streamable HTTP/SSE mode is configured in the server. This is not a REST
  application API.
- **Execution:** [`mcp/src/docker_client.py`](../mcp/src/docker_client.py)
  is the source-code boundary for Docker `exec_create`/`exec_start`.
  [`mcp/src/execution_policy.py`](../mcp/src/execution_policy.py) accepts only
  fixed read-only diagnostics. Shell operators, interpreters, executable paths,
  workdir/environment overrides, and active tool arguments are denied before
  the Docker container is looked up. [`mcp/src/tools/core/executor.py`](../mcp/src/tools/core/executor.py)
  has its own allowlist, but `skip_validation` and `execute_script` do not
  bypass the DockerClient policy. Diagnostic execution has a container-side
  timeout and a 1 MiB output cap; a pre-start cancellation event is honored,
  but MCP exposes no cancellation endpoint and running process cancellation is
  not implemented.
- **Workflows:** [`mcp/src/tools/workflows/`](../mcp/src/tools/workflows/)
  contains port scan, web crawl, vulnerability scan, subdomain discovery,
  Active Directory enumeration, and Kubernetes audit workflows. Their methods
  can be called directly and build shell command strings, but those commands
  reach the same DockerClient boundary and are rejected by the diagnostic-only
  policy. A direct `WorkflowRegistry.run_workflow` call is not a safe bypass.
- **Authorization:** [`mcp/src/authorization.py`](../mcp/src/authorization.py)
  only provides local-loopback grant management and dry-run scope decisions.
  It does not authorize or enable a scan. Public, private-network, link-local,
  and cloud-metadata targets are rejected; redirects are not wired to an HTTP
  client because network execution is disabled.
- **Privacy:** [`mcp/src/privacy/`](../mcp/src/privacy/) implements reversible
  tokenization and output sanitization. The OpenCode privacy plugin
  ([`conf/plugins/gregorforge-privacy.ts`](../conf/plugins/gregorforge-privacy.ts))
  sends user prompts to a local Unix socket for pre-model tokenization and
  replaces the prompt with a marker on failure by default. This is present in
  source but was not runtime-tested.
- **Persistence and reports:** [`mcp/api/json_storage.py`](../mcp/api/json_storage.py)
  stores project, target, campaign, infrastructure, vulnerability, and report
  records as local JSON. [`mcp/api/live_push.py`](../mcp/api/live_push.py)
  generates report content and reads OpenCode's local SQLite session database.
  No separate database service is configured.
- **Containers:** [`Dockerfile`](../Dockerfile) builds a Linux toolbox;
  [`Dockerfile.opencode`](../Dockerfile.opencode) packages OpenCode, agents,
  plugins, and the MCP runtime. Compose runs MCP separately from OpenCode. The
  MCP service still has the Docker socket, which is effectively
  host-administrator access; the source policy does not constrain a
  compromised MCP process using the socket directly. The release Compose file
  pulls published `latest` images; development Compose builds both images
  from the repository root. No service publishes a host port. OpenCode is a
  CLI, not a local browser UI.
- **CI:** [`.github/workflows/tests.yml`](../.github/workflows/tests.yml) runs a
  focused pytest regression test on Python 3.11. The
  [image workflow](../.github/workflows/build-and-push.yml) is gated to the
  `aram07324/gregorforge-prod` mirror; its self-hosted runner step removes all
  containers, images, volumes, and non-default networks on that runner before
  building. It was not run during this setup.

## Verified capabilities and limits

## Execution-path map

| Entry point | Requested operation | Authorization / scope checks | Execution and audit | Cancellation |
|---|---|---|---|---|
| MCP `check_target_authorization` | Check a local URL/method | Loopback URL, exact origin, pinned addresses, port, method, expiry/revocation, and creation-audit presence; dry-run only | Audit record with request ID; no HTTP/Docker operation | Not applicable |
| MCP `execute_command` | Tool command | DockerClient `evaluate_command`; only exact diagnostic forms pass. Denials with HTTP URLs attempt the dry-run authorization check; other denials are audited | Docker exec only after diagnostic allowlist; active scans are denied | Pre-start internal event supported; no MCP cancellation |
| GenericExecutor / `execute_script` direct call | Arbitrary command or shell script | Generic validation may be skipped, but DockerClient policy still denies shells, scripts, and active tools | Docker exec is never reached for denied requests; request ID is audited | Active execution disabled |
| Direct workflow method / `BaseWorkflow.execute_step` | Scan/crawl/enumeration | No workflow-level authorization; command reaches DockerClient, which rejects non-diagnostic command strings | No scanner operation; denial audit at DockerClient | Workflow retry code is unreachable for a successful scan; no running cancellation |
| Direct `WorkflowRegistry.run_workflow` | Invoke workflow method | Registry itself is not a trust boundary; lower DockerClient gate remains authoritative | Any generated active command is denied | None |
| MCP `run_workflow` | Run named workflow | Refuses before registry invocation | Refusal is audited with request ID | None |
| Manual lab harnesses | Direct Docker/scanner probes | `run-lab-tests.sh` and `pr42-repro/reproduce.sh` are hard-disabled; the Python E2E campaign applies the diagnostic-only policy and uses structured argv | No active scanner call; the privacy-gateway harness remains limited to its own loopback listener/temp files | Harness-specific |
| Docker socket / external host tooling | Direct Docker API or shell command | Outside the in-process authorization boundary | Can bypass source-level enforcement if MCP or host is compromised | Outside application control |

Authorization files remain split into a registry JSON file and a separate
audit JSON file. Writes use atomic replacement per file and a shared
cross-process audit-path lock. This is **not a cross-file transaction**. A
crash between grant and audit replacement leaves a registry record that is
denied because its creation audit event is absent; a revocation is persisted
before its audit write, so an audit failure cannot reactivate it. The audit is
local and tamperable; records are not cryptographically tamper-evident.

Source and tests support the existence of MCP tools, workflow registration,
privacy tokenization, local JSON report storage, and timeout handling. The
README's claims about coverage across infrastructure types describe intended
tooling, not a capability verified by this setup. No AI request, MCP service,
database initialization, API health endpoint, web interface, container health,
or security assessment was exercised.

The only CI workflow inspected for tests runs a focused pytest regression file
on Python 3.11. There is no root `pyproject.toml`, `package.json`, or Python
project manifest; MCP dependencies are listed in
[`mcp/requirements.txt`](../mcp/requirements.txt). Node.js is used inside the
image, not as a host frontend build.

## Host compatibility and resource fit

The app and toolbox are Linux containers. Bash scripts, Unix sockets, Docker
socket mounts, and Docker Desktop's Linux VM make WSL2/Docker Desktop the
Windows route; this Compose configuration does not use host networking for
service runtime. The host has 8 GB RAM, no dedicated GPU, and 25.78 GB free on
C:. Docker's VM has 4 GiB assigned, and the host had about 0.87 GiB free at
Phase 4 inspection. Docker reports 12.47 GB of images and 22.91 GB of build
cache. The two GregorForge images are absent, all runtime bind-mount
directories are missing, and `.opencode.env` has comments only. No
GregorForge container was built or started.

The toolbox is the heavy service: the Dockerfile builds on a CUDA development
image, compiles toolchains, downloads scanners and large wordlists. The
OpenCode image clones and compiles OpenCode. Compose defines no memory, CPU,
or PID limits. On this host, prefer prebuilt images to avoid build pressure,
do not run local inference, and do not start MCP until its daemon access has
been restricted. A full initial build is not currently resource-ready.

For a free, non-sensitive development smoke test, OpenRouter `:free` models
fit the existing `OPENROUTER_PROVIDER`, `OPENCODE_MODEL`, and
`OPENROUTER_API_KEY` path, but require an account/key and have varying
availability, rate limits, and tool-call support. Google Gemini has a
key-required limited free tier and can use the generic OpenAI-compatible
endpoint, but that route is not runtime-verified and Google's free-tier terms
allow content use to improve products. GroqCloud requires a key and documents
rate limits; a free inference allowance was not verified. Free service does
not mean private: inspect provider data policies. Local inference better
protects prompts but is constrained by this host's memory.

## GregorForge recommendation

- **Reuse selectively:** the MCP workflow interface, JSON report schema,
  agent-authored methodology as reference material, and privacy gateway after
  independent testing.
- **Keep separate:** preserve upstream attribution and license notices; do not
  treat this repository as a production-ready assessment service.
- **Wrap or replace before deployment:** replace the generic shell executor
  with narrowly typed operations behind a centralized authorization/scope
  policy; isolate execution from the host Docker daemon; put target validation,
  audit records, rate/concurrency limits, and cancellation in the trusted
  control plane.
- **Stage the work:** (1) establish a reproducible, least-privilege local
  baseline; (2) build and test target authorization against local fixtures;
  (3) add auditability and reliable cancellation; (4) only then evaluate
  authorized assessments; (5) develop SentinelForge as a separate application
  around reviewed components.

The repository is GPL-3.0. If GregorForge distributes a modified or combined
GPL-covered derivative, source, license, and notice obligations may apply.
Have counsel review the intended packaging and distribution model.

## Phase 4 Compose and container review (2026-10-30)

Non-starting Compose configuration validation passed for release, development,
and release-plus-socket-proxy overlay. It validates parsing, not runtime
behavior or provider readiness. The release and development files define
`gregorforge`, `mcp`, and `opencode`; only MCP depends on the toolbox, using
short-form `depends_on` (container started, not healthy). No host port is
published. MCP HTTP uses internal network port 8181; OpenCode also joins the
default egress-capable network. The toolbox and MCP are on separate internal
networks, and the toolbox network is isolated from external networks.

Security posture: no `privileged: true`, runtime `network_mode: host`,
`NET_ADMIN`, or `NET_RAW` is configured. The development file uses
`build.network: host`, which applies to image build networking only. The
toolbox runs explicitly as UID 0 with all capabilities dropped and a read-only
root filesystem plus bounded tmpfs. MCP and OpenCode default to UID 0; MCP
drops capabilities but retains the Docker socket, while OpenCode has no
capability drop or read-only root setting. MCP and OpenCode have writable host
binds for settings, reports, and sessions; MCP also mounts workflow files
read-only and authorization records read-only. The release socket mount is
marked `:ro`; Docker API access itself remains writable and effectively
privileged. Development mounts the socket without `:ro`.

The socket-proxy overlay is not a functioning proxy: it mounts a newly declared
empty named volume at MCP's socket path and sets a Unix-socket `DOCKER_HOST`.
It does not direct the Docker SDK to the proxy service's TCP API. Do not rely
on this overlay for isolation. It also emits an obsolete Compose `version`
warning.

The release MCP healthcheck uses exec-form `CMD` with literal `||` and `exit`
arguments, so no shell interprets the condition. The toolbox Dockerfile
healthcheck invokes `command -v` as an executable although `command` is
normally a shell builtin. Development services inherit image healthchecks;
the MCP image's inherited check only verifies that the OpenCode binary exists,
not that MCP is serving. Compose has no CPU, memory, or PID limits. The
declared `gregorforge_opencode` named volume is unused.

Compose syntax checks that were run:

```powershell
docker compose -f docker-compose.yml config --quiet
docker compose -f docker-compose-dev.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.socket-proxy.yml config --quiet
```

The `.opencode.env` env-file exists but contains comments only. Relative bind
directories `gregorforge-settings`, `reports`, `sessions`, `workflows`, and
`gregorforge-authorizations` do not yet exist; short bind syntax may create
them during startup. The Linux Docker socket source path was not verified from
Windows. Release images `aram07324/gregorforge:latest` and
`aram07324/opencode-gregorforge:latest` are absent locally and use
`pull_policy: always`. Development build contexts and Dockerfiles exist.
No service was started, image pulled/built, API key loaded, or provider API
contacted.
