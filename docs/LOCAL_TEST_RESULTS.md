# Local test results

Inspection date: 2026-10-29. These results apply to the current working tree,
including the pre-existing local changes. No credentials were read or printed.

| Status | Command / check | Result |
|---|---|---|
| PASS | `git switch -c sentinelforge/local-setup` | Created the requested branch. Existing changes were preserved; approximately 150 paths remain modified. |
| PASS | `git rm --cached -f -- mcp/.env` | Removed only the tracked file from the Git index; verified the local file remains present and ignored. This stages a deletion and does not rewrite history. |
| PASS | `git --version`; `docker --version`; `docker compose version`; `python --version`; `node --version`; `npm --version` | Git 2.48.1, Docker 29.7.2, Compose 5.5.1, Python 3.13.4, Node 22.16.0, npm 10.9.0. |
| BLOCKED | `docker info --format '{{.ServerVersion}}'` | Docker Desktop is installed, but the Linux engine pipe is unavailable because the daemon is not running. |
| BLOCKED | `docker compose -f docker-compose-dev.yml config --quiet` | Compose requires the absent root `.opencode.env`. No file was fabricated. |
| PASS | `python -m pytest tests/test_live_push_fixes.py -v -p no:cacheprovider` (from `mcp`, isolated temporary venv) | 4 passed. |
| PASS | `python -m pytest tests/test_live_push_fixes.py tests/test_growth.py tests/test_tool_whitelist.py -q -p no:cacheprovider` (from `mcp`, isolated temporary venv) | 28 passed after correcting a stale test assertion to the repository URL used when that test was run. |
| PASS | `python -m pytest tests/test_workflow_validator.py -q -p no:cacheprovider` (from `mcp`, isolated temporary venv with existing system `pydantic` on `PYTHONPATH`) | 2 passed; pytest emitted one deprecation warning from the system `anyio` plugin. |
| BLOCKED | `python -m pytest tests -q -p no:cacheprovider` (from `mcp`, isolated temporary venv) | Collection stopped on missing declared dependencies (`pydantic`, `docker`) in that isolated environment. No project dependency install was completed. |
| PASS | `python -m compileall -q mcp` with `PYTHONPYCACHEPREFIX` pointed outside the repository | MCP Python sources compile. |
| BLOCKED | Docker build/start, container health, API/MCP, database, and model-provider checks | Not attempted: daemon unavailable, `.opencode.env` absent, current free RAM about 787 MB, and Compose grants host-level access. |
| NOT APPLICABLE | Frontend build, REST API health, database service, GPU validation | No frontend/REST service/database container is present; host has no dedicated GPU. |
| NOT RUN | Active scans or public-target testing | No assessment was run. Active commands remain disabled; authorization is a loopback-only dry run and does not enable execution. |

`pytest` was not installed on the host. A temporary venv and pytest 9.2.0 were
used outside the repository for the focused tests. Package-index DNS retries
occurred; pytest was available from the local package cache. No project
requirements were installed.

## Remaining blockers

1. Start Docker only after freeing sufficient host memory and reviewing the
   Compose privileges and network exposure.
2. Configure an LLM provider in a local, ignored `.opencode.env`; do not share
   the API key.
3. Inspect the retained local `mcp/.env` without printing it; rotate any real
   credentials it may contain because prior Git history was not rewritten.
4. Install the declared MCP dependencies in an isolated environment if the
   complete pytest suite is required.
5. Keep active execution disabled until authorization is bound to the actual network operation and worker isolation is verified.

## Phase 3 execution-boundary verification

These checks were run locally with mocks and temporary directories. No Docker
daemon, scanner, external target, or paid API was used.

| Status | Command / check | Observed result |
|---|---|---|
| PASS | `python mcp/tests/test_execution_safety.py` | 15 passed. Covered diagnostic allowlist, malformed targets/scope, DNS changes, expiry/revocation, missing creation-audit event, audit write failure, and cross-process audit locking. |
| PASS | `python mcp/tests/test_execution_boundaries.py` | 19 passed. Covered DockerClient, GenericExecutor, scripts, direct workflow and registry invocation, MCP tool entry points, preflight-to-revocation changes, audit failure, metadata target rejection, redirects, pre-start cancellation, and manual lab scanner refusal. |
| PASS | PowerShell here-string piped to `python -`; imported `test_execution_boundaries` stubs, then ran zero-argument tests from `test_port_scan_workflow`, `test_workflow_privacy`, `test_tool_whitelist`, `test_session_privacy`, and `test_workflow_validator` | 34 passed (7 port-scan workflow, 9 workflow privacy, 2 tool whitelist, 14 session privacy, 2 validator); local only, no Docker or network. |
| BLOCKED | `python -m pytest ...` | `pytest` is not installed in the selected Python environment. No global installation was performed. |
| PASS | `python -m py_compile mcp\\src\\authorization.py mcp\\src\\docker_client.py mcp\\src\\tools\\core\\executor.py mcp\\src\\server.py mcp\\tests\\test_execution_safety.py mcp\\tests\\test_execution_boundaries.py tools\\lab-tests\\privacy-e2e-campaign.py` with `PYTHONPYCACHEPREFIX` outside the repository | All listed files compiled successfully. |
| FAIL | `git diff --check` | Reports one trailing-whitespace line at `mcp/tests/test_session_privacy.py:15` in an unrelated dirty-worktree change; left untouched. The scoped Phase 3 diff check and `git diff --cached --check` pass. Git also emits existing line-ending conversion warnings. |
| NOT RUN | Docker, live lab scripts, scanners, external HTTP targets, and MCP runtime | Explicitly not run. `run-lab-tests.sh` and `pr42-repro/reproduce.sh` now stop before Docker access; the Python E2E lab applies the diagnostic-only policy. |

### Execution-path disposition

- MCP `execute_command`, direct `GenericExecutor` calls, `execute_script`,
  workflow methods, and direct `WorkflowRegistry.run_workflow` all converge on
  the DockerClient command policy. Only exact read-only diagnostics can reach
  Docker exec; active scanners and shell composition are denied.
- MCP `run_workflow` refuses before registry invocation and records a denial.
- `check_target_authorization` is dry-run only. A successful local grant does
  not authorize a Docker command or scan.
- `AuthorizationStore` reads/writes share a cross-process lock stored next to
  the writable audit file. Registry and audit remain separate JSON files, so
  replacement is not a cross-file transaction. Authorization fails closed if
  its creation event is absent; revocation persists before an audit failure.
- Mid-process cancellation is not available from MCP; the internal cancellation
  event prevents an operation only if it is set before Docker exec begins.
- The MCP container's Docker socket remains an out-of-process trust boundary:
  direct Docker API use after MCP compromise could bypass Python policy.

## Follow-up verification (2026-10-30)

The test runner is constrained to pytest 8 because the installed AnyIO pytest
plugin imports a deprecated pytest 9 compatibility alias. Install test
dependencies with `python -m pip install -r mcp/requirements-test.txt`.

| Status | Command / check | Observed result |
|---|---|---|
| PASS | `cd mcp; python -m pytest tests -q` | 155 passed with pytest 8.4.2; no warnings. |
| PASS | In-memory build checks for `container-registry` and `github` profiles | Read-only registry output omits active-assessment, scanner, dashboard-push, and shell-execution blocks; the normal profile retains them. |

## Phase 4 system and Compose inspection (2026-10-30)

Inspection only: no Compose `up`, image pull/build, container lifecycle
operation, prune, model request, provider API call, or target test was run.
The Docker Desktop engine was already running; it was not started or stopped
during this phase. Provider policy references below were read from official
documentation only.

| Status | Command / check | Observed result |
|---|---|---|
| PASS | `docker info --format 'Server={{.ServerVersion}} OS={{.OperatingSystem}} CPUs={{.NCPU}} MemoryBytes={{.MemTotal}} DockerRoot={{.DockerRootDir}}'` | Docker 29.9.2, Docker Desktop Linux engine, 8 CPUs, about 4 GiB daemon memory. |
| PASS | `docker ps -a --format ...`; `docker compose ls --format json` | Only `openagent-registry-1` was running and healthy on port 5000, owned by a separate `openagent` project. No GregorForge service was running. Existing container was not changed. |
| PASS | Read-only host/daemon resource checks (`Get-CimInstance`, `Get-Volume`, `docker system df`) | About 0.87 GiB host RAM free, 25.78 GiB C: free; latest check reports 12.47 GB images and 22.91 GB build cache. No cache/images/volumes were deleted. |
| PASS | Parse-only `.opencode.env` inspection | File exists and contains comments only; no variable names or credentials were present. File was not modified. |
| PASS | `docker compose -f docker-compose.yml config --quiet` | Release configuration parse/interpolation passed. |
| PASS | `docker compose -f docker-compose-dev.yml config --quiet` | Development configuration parse/interpolation passed. |
| PASS WITH WARNING | `docker compose -f docker-compose.yml -f docker-compose.socket-proxy.yml config --quiet` | Parse/interpolation passed; Compose reports the overlay's top-level `version` attribute is obsolete. |
| PASS | `docker compose ... config --format json` parsed in memory and summarized without printing environment values | No host port mappings; all services lack CPU/memory/PID limits. Release images absent locally; dev build contexts and Dockerfiles exist. Host bind directories for settings, reports, sessions, workflows, and authorization state are absent. |
| FAIL — configuration finding | Review of `docker-compose.socket-proxy.yml` effective config | Overlay mounts an empty named volume over the MCP socket and sets a Unix-socket `DOCKER_HOST`; it does not point the SDK to the proxy TCP endpoint. It is not a working isolation control. |
| PASS | `python tools/agent-build/test_profiles.py -v` | 2 profile-generation/validation tests passed. |
| PASS | `cd mcp; python -m pytest tests -q` | 155 passed, no warnings. |
| NOT RUN | Docker Compose startup, builds, model-provider request, container health, scans, or target traffic | Explicitly excluded by Phase 4 scope and resource/security blockers. |

Official provider documentation reviewed:

- [OpenRouter free model variant](https://openrouter.ai/docs/guides/routing/model-variants/free)
  documents free model variants, varying rate limits/availability, and warns
  that paid fallbacks incur charges. [OpenRouter FAQ](https://openrouter.ai/docs/faq)
  describes upstream provider routing and privacy options.
- [Gemini API pricing](https://ai.google.dev/gemini-api/docs/pricing) documents
  limited free model access and says free-tier content may be used to improve
  products; [API keys](https://ai.google.dev/gemini-api/docs/api-key) requires
  authentication.
- [Groq OpenAI compatibility](https://console.groq.com/docs/openai) requires
  an API key; [rate limits](https://console.groq.com/docs/rate-limits) shows
  organization/model request and token limits.

No anonymous cloud inference option was confirmed in the project's provider
configuration path. OpenRouter is the lowest-friction no-cost development
option in the existing cloud config, with a selected `:free` model and no
paid fallback; do not use it with sensitive target data without accepting the
upstream provider's data handling. For sensitive work, local inference is
preferable in principle but the 8-GiB host has insufficient current headroom.
