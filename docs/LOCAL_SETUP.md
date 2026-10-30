# Local setup (Windows)

## Status (2026-10-30, Phase 4 inspection)

Docker Desktop 29.9.2 is running with an 8-CPU, 4-GiB Linux VM. The host has
about 8 GiB RAM, with roughly 0.87 GiB free at inspection, and 25.78 GiB free
on C:. No GregorForge containers are running and neither GregorForge image is
present locally. The only running container belongs to a separate `openagent`
project; it was left untouched.

The root `.opencode.env` exists but contains comments only. No provider or
credential was configured, read, created, or changed. Docker currently reports
12.47 GB of images and 22.91 GB of build cache; nothing was pruned. The
development image build is substantial and the current memory headroom is not
sufficient to recommend starting it.

The project is a Linux-container stack with Bash installation scripts. Windows
setup is not documented as a native PowerShell workflow; use Docker Desktop with
WSL2 integration and a Bash shell if you proceed.

## Provider choices

The current cloud configuration path in `conf/apply-settings.sh` and
`install.sh` uses these exact variables:

```env
OPENROUTER_PROVIDER=openrouter
OPENCODE_MODEL=<catalog-model-id>:free
OPENROUTER_API_KEY=<key-created-by-you>
```

`OPENROUTER_PROVIDER` is used as the OpenCode provider ID (the setup script
also accepts `anthropic` and `openai`); it does not force all traffic through
OpenRouter. Cloud credentials are required by the setup flow. There is no
anonymous cloud-provider configuration in this code path. Select a current
OpenRouter catalog ID that offers `:free`; exact model availability changes.

For a no-cost development smoke test, OpenRouter offers catalog models with a
`:free` variant. Use the exact currently available model ID and do not configure
a paid fallback. Free-model availability and rate limits can change, and
tool-calling support varies by model. OpenRouter sends prompts to the selected
upstream model provider; do not send real targets, secrets, or sensitive
assessment data to a free tier without reviewing that provider's data policy.
See the [OpenRouter free variant docs](https://openrouter.ai/docs/guides/routing/model-variants/free)
and [privacy FAQ](https://openrouter.ai/docs/faq).

Google Gemini Developer API also has a limited, key-required free tier. Its
OpenAI-compatible endpoint can be configured through the repository's generic
custom-compatible-provider path (the variable names say `LOCAL`, but the URL
may be remote):

```env
OPENCODE_LOCAL_MODE=true
OPENCODE_LOCAL_PROVIDER_ID=gemini
OPENCODE_LOCAL_PROVIDER_NAME=Gemini API
OPENCODE_LOCAL_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai/
OPENCODE_LOCAL_MODEL=<currently-supported-gemini-model-id>
OPENCODE_LOCAL_API_KEY=<Google-AI-Studio-key>
```

The Gemini API requires a key, offers free access only to certain models under
account/region quotas, and Google's current pricing page says free-tier content
may be used to improve products. This generic OpenCode integration is not
runtime-tested here. Review [pricing](https://ai.google.dev/gemini-api/docs/pricing),
[API keys](https://ai.google.dev/gemini-api/docs/api-key), and
[OpenAI compatibility](https://ai.google.dev/gemini-api/docs/openai).

Other compatible cloud APIs still require keys:

- GroqCloud: OpenAI-compatible API requiring a Groq API key; model and
  organization rate limits apply. The current source review did not verify a
  free inference allowance, so do not assume Groq is free. It is not a
  dedicated installer option and would need to be configured/tested through
  the generic compatible endpoint. See [Groq OpenAI compatibility](https://console.groq.com/docs/openai)
  and [rate limits](https://console.groq.com/docs/rate-limits).

The generic OpenAI-compatible endpoint variables are:

```env
OPENCODE_LOCAL_MODE=true
OPENCODE_LOCAL_PROVIDER_ID=<provider-id>
OPENCODE_LOCAL_PROVIDER_NAME=<display-name>
OPENCODE_LOCAL_BASE_URL=<endpoint-base-url>
OPENCODE_LOCAL_MODEL=<served-model-id>
# OPENCODE_LOCAL_API_KEY=<optional-key-for-local-or-remote-endpoint>
```

Despite the `LOCAL` variable names, this path accepts a custom base URL; a
remote compatible provider still requires its key and sends prompts off-host.
For sensitive work, a local model avoids a cloud provider, but local inference
is not recommended on this 8-GiB host until resources are evaluated. Do not use
the on-prem Anthropic-compatible key-optional setting as a claim of anonymous
cloud access. A local Ollama/llama.cpp endpoint commonly needs no API key; this
is local-server authentication, not an anonymous cloud service.

The installer's on-prem Anthropic-compatible path uses
`ANTHROPIC_BASE_URL=<Anthropic-Messages-compatible-URL>` and
`ANTHROPIC_MODEL=<recognized-Claude-model-id>`. `ANTHROPIC_API_KEY` is optional
only for a keyless endpoint; the installer writes a placeholder value when
left blank. It is not a free public inference provider.

**Practical choice:** OpenRouter with a single explicitly selected `:free`
model is the least-friction free cloud development path because it maps to the
existing cloud variables. It still needs an account/key, has changing limits
and model capabilities, and is unsuitable for sensitive target data unless
the operator accepts the upstream handling. A local provider is preferable
for sensitive prompts but is resource-constrained here.

The Windows host currently has Git 2.48.1, Docker 29.9.2, Compose 5.5.1,
Python 3.13.4, and Node.js 22.16/npm 10.9. The host does not need Python or
Node.js for the documented container workflow; those runtimes are included in
the images. Python is useful for running MCP tests.

## Secrets and configuration

Compose expects the root `.opencode.env` file, which currently has comments
only. Its formats are documented in [the full guide](./full.md#ii3-configuration-of-environment-variables)
and above. Configure it yourself only after selecting a provider. The file is
ignored by Git. Never paste credentials into chat, commit them, or include
them in logs.

`mcp/.env` was tracked and modified at the start of this setup despite the root
`*.env` ignore rule. It has now been removed from the Git index while its local
copy remains on disk and is ignored; the removal is staged for a future commit.
The new root `.dockerignore` also excludes environment files from image build
contexts. Neither action removes earlier commits. Do not put credentials in
the local file; if it contains a real credential, assume it may have been
committed and rotate it. The file was not opened during this inspection.

## Important installer warning

Do **not** run `./install.sh`, `./install.sh --init`, or `./install-dev.sh` as a
setup shortcut. These paths stop the stack, remove Compose volumes (and, for
`install.sh`, images), delete local data/configuration/workflow directories,
prune Docker build cache, then rebuild or pull and start containers. This is
destructive to local state.

Compose does not set `privileged: true`, runtime host networking, `NET_ADMIN`,
or `NET_RAW`. The development file's `build.network: host` applies to image
build networking only, not service runtime networking. However, the toolbox,
MCP, and OpenCode run as root (the toolbox explicitly uses `0:0`), and the MCP
service mounts the Docker Engine socket. Marking that socket mount `:ro` in the
release Compose file does **not** make Docker API requests read-only; a process
with socket access can control the host daemon. The dev Compose mount is
writable. Treat both as host-administrator access, not as a safe scan sandbox.
The separate `docker-compose.socket-proxy.yml` currently does not work as a
proxy: it mounts an empty named volume over the MCP socket path and configures
`DOCKER_HOST` as a Unix socket instead of pointing the SDK at the proxy service.
Do not use it as a security control until corrected and tested.

There are no host `ports:` mappings in the GregorForge Compose files. MCP's
HTTP service is internal-only on port 8181; OpenCode is a terminal application,
not a browser UI. Do not expect this stack to serve a website on localhost.

The `gregorforge-settings`, `reports`, `sessions`, `workflows`, and
`gregorforge-authorizations` host bind directories are currently absent.
Compose's short bind syntax may create them on startup; inspect and create
required directories deliberately before launch. The Docker socket source path
is Linux-specific and was not verified on this Windows host because no
GregorForge container was started.

## Commands and current blockers

Non-starting Compose validation passed for the release, development, and
socket-proxy-overlay files. This validates syntax/interpolation only; it does
not verify provider completeness, image availability, mount usability, health,
or startup. The socket-proxy overlay emits a deprecated `version` warning.

```powershell
docker compose -f docker-compose.yml config --quiet
docker compose -f docker-compose-dev.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.socket-proxy.yml config --quiet
docker compose -f docker-compose.yml config --images
docker compose -f docker-compose-dev.yml config --services
```

| Service / option | Role | Resource / risk class | Phase 4 disposition |
|---|---|---|---|
| `gregorforge` toolbox | MCP command target | Essential for intended tool integration; heavy to build; unsafe for active scans by default | Root UID, all capabilities dropped, read-only root plus tmpfs; active execution remains disabled. |
| `mcp` | Tool API and Docker client | Essential; unsafe by default while it holds Docker socket access | Root UID; capability drop does not restrict Docker API operations. |
| `opencode` | User-facing CLI / model client | Essential for interactive use; cloud calls need provider configuration | Root UID; no capability drop or read-only root; not a web service. |
| GPU Compose overlay | GPU passthrough | Optional and hardware-specific | Do not use without supported GPU/runtime; no dedicated GPU was reported. |
| Socket-proxy overlay | Intended Docker API restriction | Optional, security-sensitive | Currently miswired and ineffective; do not use until corrected and integration-tested. |
| Local model server | External model provider | Optional and heavy on this 8-GiB host | Not included as a Compose service; no local model is configured. |
| Separate `openagent` registry | Unrelated service | Not part of GregorForge | Left running and untouched. |

Release Compose references `aram07324/gregorforge:latest` and
`aram07324/opencode-gregorforge:latest`, both absent locally and configured with
`pull_policy: always`. Dev Compose uses the repository root as the build
context; both Dockerfiles exist. Runtime bind directories listed above are
missing. There are no published service ports, so no GregorForge host-port
collision exists in this configuration. `mcp` depends on `gregorforge`, but the
short-form dependency waits only for container start, not health.

All three services lack memory, CPU, and PID limits. The toolbox image is the
heavy service: its build compiles multiple toolchains, downloads large security
tools and wordlists, and uses a CUDA development base. OpenCode image build
clones and compiles OpenCode. On this 8-GiB Windows host, avoid local builds
until the Docker VM and host have substantially more free memory. For minimal
development, prefer prebuilt release images where possible and avoid local
model inference. The current stack has no Compose profiles to omit services,
and MCP depends on the toolbox, so an integrated CLI needs all three services.
Keep MCP disabled until its Docker API access is constrained; that requires an
architectural change, not just a Compose setting.

Do **not** run the installer scripts as a shortcut. `install.sh`,
`install-dev.sh`, and the added `startup.sh` include stack-down actions; the
installers also remove volumes/data, images, or build cache. They were not run.

After provider configuration, resource review, and explicit Docker-socket
approval, the non-destructive start command to consider is:

```powershell
docker compose -f docker-compose-dev.yml up -d --build
docker compose -f docker-compose-dev.yml ps
docker compose -f docker-compose-dev.yml logs --tail=100
```

These commands have **not** been run. To stop services without deleting
persistent state, after an approved launch:

```powershell
docker compose -f docker-compose-dev.yml stop
```

Avoid `down --volumes`, `--rmi all`, and Docker prune commands unless you have
reviewed the exact data loss first.

## Troubleshooting and open checks

- Docker CLI errors connecting to `dockerDesktopLinuxEngine`: start Docker
  Desktop, then check `docker info`.
- Blank `.opencode.env`: configure a provider using the full guide; do not
  copy a real credential into tracked files.
- Low memory: defer image builds until enough memory is available; do not
  attempt local inference on this 8 GB, GPU-less host without evaluating a
  suitably small quantized model.
- MCP Docker healthcheck in release Compose is an exec-form `CMD` list that
  includes literal `|| exit 1`; exec form does not interpret shell operators.
  Correct it to a valid shell-form check and confirm the route/method before
  relying on health status. The Dockerfile toolbox healthcheck also invokes
  `command -v` as an executable, although `command` is normally a shell
  builtin. OpenCode's image healthcheck only checks that its binary exists,
  not that the model provider or TUI is ready.
- No provider credential or model was tested. No images were pulled/built and
  no services were started in the Phase 4 inspection.
- Active assessment must remain disabled until target authorization and
  execution-safety controls in [the gap analysis](./SECURITY_GAP_ANALYSIS.md)
  are implemented and tested.
