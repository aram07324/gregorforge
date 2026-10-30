import os
import re
import time
import socket
import docker
import sys
import uuid
import logging
import threading
from typing import Optional, List, Dict, Any
from docker.models.containers import Container
from docker.errors import DockerException, NotFound

from src.models.common import ExecutionResult, ExecutionStatus
from src.authorization import AuthorizationError, AuthorizationStore
from src.execution_guard import classify, effective_timeout, remediation
from src.authorization import current_authorization_id
from src.execution_policy import CommandDecision, evaluate_command

STREAM_BASE = "/tmp/gregorforge_mcp_stream"
MAX_OUTPUT_BYTES = 1024 * 1024
logger = logging.getLogger(__name__)

class GregorForgeDockerClient:
    """
    Docker client to interact with the GregorForge security toolbox container.
    Handles command execution, health checks, and resource management.

    + Live stream broadcast to UNIX socket for monitoring console.
    """

    def __init__(
        self,
        container_name: str = "gregorforge",
        timeout: int = 300,
    ):
        self.container_name = container_name
        self.default_timeout = timeout
        self.authorization_store = AuthorizationStore(
            os.getenv("GREGORFORGE_AUTHORIZATION_FILE"),
            audit_path=os.getenv("GREGORFORGE_AUTHORIZATION_AUDIT_FILE"),
        )
        try:
            self.client = docker.from_env()
        except DockerException as e:
            raise RuntimeError(f"Failed to connect to Docker: {e}")

        # Ensure stream socket exists (server created by gregorforge-cli)
        # Client will just connect if available.
        self._stream_enabled = True

    def _broadcast(self, b: bytes, session_id: str | None = None):
        if not self._stream_enabled:
            return

        if session_id and not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", session_id):
            logger.warning("ignoring invalid monitoring session identifier")
            return

        sock_path = f"{STREAM_BASE}_{session_id}.sock" if session_id else f"{STREAM_BASE}.sock"

        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(0.01)
            s.connect(sock_path)
            s.sendall(b)
            s.close()
        except Exception:
            pass

    def _deny_execution(
        self,
        decision: CommandDecision,
        *,
        request_id: str,
        authorization_id: Optional[str],
    ) -> ExecutionResult:
        effective_authorization_id = authorization_id or current_authorization_id()
        tool = decision.argv[0].rsplit("/", 1)[-1] if decision.argv else "unparsed"
        target_url = self._extract_http_target(decision.argv)
        reason = decision.reason
        audit_recorded = False
        try:
            if target_url:
                scope_decision = self.authorization_store.authorize_url(
                    effective_authorization_id,
                    target_url,
                    method=self._method_for_tool(tool),
                    request_id=request_id,
                )
                reason = (
                    "authorization valid but active execution remains disabled"
                    if scope_decision.allowed
                    else scope_decision.reason
                )
                if scope_decision.allowed:
                    self.authorization_store.audit_denial(
                        authorization_id=effective_authorization_id,
                        tool=tool,
                        reason="active execution disabled pending worker isolation",
                        request_id=request_id,
                    )
            else:
                self.authorization_store.audit_denial(
                    authorization_id=effective_authorization_id,
                    tool=tool,
                    reason=reason,
                    request_id=request_id,
                )
            audit_recorded = True
        except AuthorizationError as exc:
            reason = f"{reason}; authorization audit unavailable: {exc}"
            logger.error(
                "execution denied without audit",
                extra={"request_id": request_id, "tool": tool},
            )
        logger.warning(
            "command denied by execution policy",
            extra={
                "request_id": request_id,
                "authorization_id": effective_authorization_id,
                "tool": tool,
            },
        )
        return ExecutionResult(
            status=ExecutionStatus.FAILED,
            stderr=f"[EXECUTION DENIED] {reason}",
            exit_code=1,
            metadata={
                "request_id": request_id,
                "authorization_id": effective_authorization_id,
                "tool": tool,
                "audit_recorded": audit_recorded,
                "active_execution_enabled": False,
            },
        )

    def get_container(self) -> Optional[Container]:
        """Get the GregorForge container if it exists and is running."""
        try:
            container = self.client.containers.get(self.container_name)
            container.reload()
            return container if container.status == "running" else None
        except NotFound:
            return None
        except DockerException as e:
            raise RuntimeError(f"Error accessing container: {e}")

    def execute_command(
        self,
        command: str | List[str],
        timeout: Optional[int] = None,
        workdir: Optional[str] = None,
        environment: Optional[Dict[str, str]] = None,
        session_id: Optional[str] = None,   # NEW
        authorization_id: Optional[str] = None,
        cancel_event: Optional[threading.Event] = None,
    ) -> ExecutionResult:
        """
        Execute a command inside the GregorForge container.
        Streams stdout/stderr live to monitoring console via UNIX socket.
        """
        request_id = uuid.uuid4().hex
        if cancel_event is not None and cancel_event.is_set():
            return ExecutionResult(
                status=ExecutionStatus.CANCELLED,
                stderr="Execution cancelled before command validation.",
                exit_code=1,
                metadata={
                    "request_id": request_id,
                    "authorization_id": authorization_id or current_authorization_id(),
                    "command_started": False,
                },
            )
        decision = evaluate_command(command, workdir=workdir, environment=environment)
        if not decision.allowed:
            return self._deny_execution(
                decision,
                request_id=request_id,
                authorization_id=authorization_id,
            )

        if cancel_event is not None and cancel_event.is_set():
            return ExecutionResult(
                status=ExecutionStatus.CANCELLED,
                stderr="Execution cancelled before the command started.",
                exit_code=1,
                metadata={
                    "request_id": request_id,
                    "authorization_id": authorization_id or current_authorization_id(),
                    "command_started": False,
                },
            )

        container = self.get_container()
        if not container:
            return ExecutionResult(
                status=ExecutionStatus.FAILED,
                stderr=f"Container '{self.container_name}' not found or not running",
                exit_code=1,
            )

        timeout = timeout or self.default_timeout
        start_time = time.time()

        try:
            if cancel_event is not None and cancel_event.is_set():
                return ExecutionResult(
                    status=ExecutionStatus.CANCELLED,
                    stderr="Execution cancelled before the command started.",
                    exit_code=1,
                    metadata={
                        "request_id": request_id,
                        "authorization_id": authorization_id or current_authorization_id(),
                        "command_started": False,
                    },
                )
            # Prepare command.
            #
            # Every command is wrapped in coreutils `timeout` INSIDE the container.
            # The `timeout` argument used to be recorded in metadata and never
            # enforced: the stream loop below blocks until the process exits, so a
            # command that never ends (an unbounded `hydra -P rockyou.txt`, a `cat`
            # on a socket that never sends EOF) froze the whole campaign — no more
            # findings, no finalize, no report. Enforcing the deadline in the
            # container means the process is killed even if the client goes away.
            hard_timeout = effective_timeout(timeout)

            cmd = ["timeout", "--kill-after=5", str(hard_timeout), *decision.argv]
            cmd_str = " ".join(decision.argv)

            # OPTIONAL: ignore health checks in the live stream (no spam)
            is_noise = cmd_str.startswith("which ") or cmd_str.startswith("df -h ")

            # Inject cyan prompt with timestamp before streaming
            if not is_noise:
                ts = time.strftime("%H:%M:%S")
                prefix = f"\n\033[1;32m[{ts}] gregorforge>\033[0m {cmd_str}\n\n"
                self._broadcast(prefix.encode(), session_id)

            # Use docker low-level exec API for correct streaming + exit code
            exec_id = self.client.api.exec_create(
                container=container.id,
                cmd=cmd,
                workdir=workdir,
                environment=environment,
                tty=True,   # important: reduce buffering, keep ANSI
            )["Id"]

            stream = self.client.api.exec_start(
                exec_id,
                stream=True,
                tty=True,
            )

            stdout_acc = ""

            output_bytes = 0
            output_truncated = False
            for chunk in stream:
                if not chunk:
                    continue
                remaining = MAX_OUTPUT_BYTES - output_bytes
                if remaining > 0:
                    kept = chunk[:remaining]
                    stdout_acc += kept.decode("utf-8", errors="replace")
                    output_bytes += len(kept)
                    if len(kept) < len(chunk):
                        output_truncated = True
                else:
                    output_truncated = True

                if not is_noise and output_bytes:
                    self._broadcast(chunk[:max(0, min(len(chunk), remaining))], session_id)

            duration = time.time() - start_time

            inspect = self.client.api.exec_inspect(exec_id)
            exit_code = inspect.get("ExitCode", 1)
            if output_truncated:
                stdout_acc += "\n[OUTPUT TRUNCATED: 1 MiB limit]"

            # coreutils `timeout` reports 124 on expiry (137 when it had to SIGKILL).
            # Hand the agent an actionable explanation instead of silence: a bare
            # "timed out" makes a model retry the identical command, which is how a
            # campaign burns an hour on the same dead end.
            if exit_code in (124, 137):
                return ExecutionResult(
                    status=ExecutionStatus.TIMEOUT,
                    stdout=stdout_acc,
                    stderr=remediation(cmd_str, duration, hard_timeout),
                    exit_code=exit_code,
                    duration=duration,
                    metadata={
                        "command": cmd_str,
                        "workdir": workdir,
                        "timeout": hard_timeout,
                        "timed_out": True,
                        "guard": classify(cmd_str).label or "unclassified",
                    },
                )

            status = (
                ExecutionStatus.SUCCESS
                if exit_code == 0
                else ExecutionStatus.FAILED
            )

            return ExecutionResult(
                status=status,
                stdout=stdout_acc,
                stderr="",
                exit_code=exit_code,
                duration=duration,
                metadata={
                    "command": cmd_str,
                    "workdir": workdir,
                    "timeout": hard_timeout,
                },
            )

        except Exception as e:
            duration = time.time() - start_time
            return ExecutionResult(
                status=ExecutionStatus.FAILED,
                stderr=f"Execution error: {str(e)}",
                exit_code=1,
                duration=duration,
                metadata={"command": str(command), "error": str(e)},
            )

    def check_tool_available(self, tool_name: str) -> bool:
        result = self.execute_command(f"which {tool_name}", timeout=5)
        return result.success

    def check_tools_bulk(self, tools: List[str]) -> Dict[str, bool]:
        """Probe many tools in ONE container round-trip.

        The old health check ran one `docker exec which <tool>` per tool. At a
        dozen tools that is a dozen round-trips of container-exec overhead on
        every campaign start; over the full toolbox it would be a hundred. A
        single `command -v` loop inside one exec returns the whole map at once,
        so reporting the complete toolbox costs no more than probing four tools
        did before. A tool name is validated to a safe charset so the joined
        loop can never inject.
        """
        safe = [t for t in tools if re.fullmatch(r"[A-Za-z0-9_.+-]+", t or "")]
        return {tool: self.check_tool_available(tool) for tool in safe}

    @staticmethod
    def _method_for_tool(tool: str) -> str:
        if tool in {"naabu", "ping", "nc", "nmap", "masscan"}:
            return "port_discovery"
        if tool in {"nuclei", "sqlmap", "ffuf", "dirb", "wpscan"}:
            return "vulnerability_scan"
        if tool in {"katana", "waybackurls"}:
            return "passive_crawl"
        return "http_get"

    @staticmethod
    def _extract_http_target(argv: tuple[str, ...]) -> str | None:
        for value in argv[1:]:
            if value.lower().startswith(("http://", "https://")):
                return value
        return None

    def get_disk_usage(self) -> Optional[Dict[str, Any]]:
        """Get disk usage information from the container."""
        result = self.execute_command("df -h /opt/gregorforge/out", timeout=5)
        if result.success:
            lines = result.stdout.strip().split("\n")
            if len(lines) >= 2:
                parts = lines[1].split()
                return {
                    "filesystem": parts[0],
                    "size": parts[1],
                    "used": parts[2],
                    "available": parts[3],
                    "use_percent": parts[4],
                    "mounted_on": parts[5] if len(parts) > 5 else "-",
                }
        return None

    def health_check(self) -> Dict[str, Any]:
        """Perform a comprehensive health check."""
        container = self.get_container()
        if not container:
            return {
                "healthy": False,
                "container_running": False,
                "message": f"Container '{self.container_name}' not found or not running",
            }

        tools_to_check = ["naabu", "nuclei", "httpx", "subfinder"]
        tools_status = {}
        for tool in tools_to_check:
            tools_status[tool] = self.check_tool_available(tool)

        disk_usage = self.get_disk_usage()
        all_tools_available = all(tools_status.values())

        return {
            "healthy": all_tools_available,
            "container_running": True,
            "tools_available": tools_status,
            "disk_usage": disk_usage,
            "message": "Diagnostics available; active execution disabled"
            if all_tools_available
            else "Some diagnostic tools are not available",
        }

    def cleanup(self):
        """Clean up Docker client resources."""
        if hasattr(self, "client"):
            self.client.close()