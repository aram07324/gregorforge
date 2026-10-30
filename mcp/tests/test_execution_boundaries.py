"""Local tests for fail-closed execution entry points."""

import importlib
import importlib.util
import json
import os
import sys
import tempfile
import threading
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.authorization import AuthorizationError, AuthorizationStore  # noqa: E402
from src.models.common import ExecutionStatus  # noqa: E402


def _load_execution_modules():
    if "src.server" in sys.modules and "src.docker_client" in sys.modules:
        return (
            sys.modules["src.docker_client"],
            sys.modules["src.tools.core.executor"],
            sys.modules["src.tools.workflows.port_scan"],
            sys.modules["src.tools.workflows.list_workflows"],
            sys.modules["src.server"],
        )

    fake_modules = {}
    try:
        docker = importlib.import_module("docker")
    except ModuleNotFoundError:
        docker = types.ModuleType("docker")
        docker.from_env = MagicMock(return_value=MagicMock())
        docker_errors = types.ModuleType("docker.errors")
        docker_errors.DockerException = type("DockerException", (Exception,), {})
        docker_errors.NotFound = type("NotFound", (Exception,), {})
        docker_models = types.ModuleType("docker.models")
        docker_containers = types.ModuleType("docker.models.containers")
        docker_containers.Container = type("Container", (), {})
        fake_modules.update({
            "docker": docker,
            "docker.errors": docker_errors,
            "docker.models": docker_models,
            "docker.models.containers": docker_containers,
        })

    try:
        importlib.import_module("fastmcp")
    except ModuleNotFoundError:
        class FastMCP:
            def __init__(self, _name):
                pass

            def tool(self):
                return lambda function: function

            def add_middleware(self, _middleware):
                pass

        fastmcp = types.ModuleType("fastmcp")
        fastmcp.__path__ = []
        fastmcp.FastMCP = FastMCP
        fastmcp_server = types.ModuleType("fastmcp.server")
        fastmcp_server.__path__ = []
        fastmcp_middleware = types.ModuleType("fastmcp.server.middleware")
        fastmcp_middleware.Middleware = type("Middleware", (), {})
        fastmcp_exceptions = types.ModuleType("fastmcp.exceptions")
        fastmcp_exceptions.ToolError = type("ToolError", (Exception,), {})
        fake_modules.update({
            "fastmcp": fastmcp,
            "fastmcp.server": fastmcp_server,
            "fastmcp.server.middleware": fastmcp_middleware,
            "fastmcp.exceptions": fastmcp_exceptions,
        })

    sys.modules.update(fake_modules)

    def import_application_modules():
        docker_client = importlib.import_module("src.docker_client")
        executor = importlib.import_module("src.tools.core.executor")
        port_scan = importlib.import_module("src.tools.workflows.port_scan")
        workflows = importlib.import_module("src.tools.workflows.list_workflows")
        for module_name in (
            "ad_enumeration",
            "kubernetes_audit",
            "subdomain_discovery",
            "vulnerability_scan",
            "web_crawler",
        ):
            importlib.import_module(f"src.tools.workflows.{module_name}")
        server = importlib.import_module("src.server")
        return docker_client, executor, port_scan, workflows, server

    if "docker" in fake_modules:
        return import_application_modules()
    with patch.object(docker, "from_env", return_value=MagicMock()):
        return import_application_modules()


(
    docker_client_module,
    executor_module,
    port_scan_module,
    workflow_registry_module,
    server_module,
) = _load_execution_modules()
LAB_E2E_PATH = (
    Path(__file__).resolve().parents[2]
    / "tools"
    / "lab-tests"
    / "privacy-e2e-campaign.py"
)
LAB_E2E_SPEC = importlib.util.spec_from_file_location(
    "gregorforge_privacy_e2e_campaign", LAB_E2E_PATH
)
if LAB_E2E_SPEC is None or LAB_E2E_SPEC.loader is None:
    raise RuntimeError("could not load the local lab campaign module")
lab_e2e_module = importlib.util.module_from_spec(LAB_E2E_SPEC)
LAB_E2E_SPEC.loader.exec_module(lab_e2e_module)


class ExecutionBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.previous_server_client = server_module.docker_client
        self.previous_server_executor = server_module.executor
        self.tempdir = tempfile.TemporaryDirectory()
        self.registry_path = os.path.join(self.tempdir.name, "authorizations.json")
        self.audit_path = os.path.join(self.tempdir.name, "audit.json")
        self.now = [datetime(2026, 10, 29, tzinfo=timezone.utc)]
        self.store = AuthorizationStore(
            self.registry_path,
            audit_path=self.audit_path,
            resolver=lambda _host: ("127.0.0.1",),
            clock=lambda: self.now[0],
        )
        self.client = docker_client_module.GregorForgeDockerClient.__new__(
            docker_client_module.GregorForgeDockerClient
        )
        self.client.container_name = "test-toolbox"
        self.client.default_timeout = 10
        self.client.authorization_store = self.store
        self.client.client = MagicMock()
        self.client._stream_enabled = False
        self.client.get_container = MagicMock(
            side_effect=AssertionError("container lookup is an execution precursor")
        )
        self.executor = executor_module.GenericExecutor(self.client)

    def tearDown(self):
        server_module.docker_client = self.previous_server_client
        server_module.executor = self.previous_server_executor
        self.tempdir.cleanup()

    def grant(self):
        return self.store.create_local_authorization(
            "http://localhost:8080",
            ports=[8080],
            methods=["http_get", "vulnerability_scan"],
            operator="test-operator",
            confirm_authority=True,
            ttl_seconds=60,
        )

    def assert_no_docker_execution(self):
        self.client.get_container.assert_not_called()
        self.client.client.api.exec_create.assert_not_called()
        self.client.client.api.exec_start.assert_not_called()

    def test_execution_request_without_authorization_is_never_invoked(self):
        result = self.client.execute_command(
            "nuclei -u http://localhost:8080",
        )
        self.assertEqual(result.status, ExecutionStatus.FAILED)
        with open(self.audit_path, encoding="utf-8") as audit_file:
            audit = json.load(audit_file)
        self.assertEqual(
            audit["events"][-1]["request_id"], result.metadata["request_id"]
        )
        self.assert_no_docker_execution()

    def test_valid_authorization_still_does_not_enable_active_execution(self):
        record = self.grant()

        result = self.client.execute_command(
            "nuclei -u http://localhost:8080",
            authorization_id=record["id"],
        )

        self.assertEqual(result.status, ExecutionStatus.FAILED)
        self.assertIn("active execution remains disabled", result.stderr)
        self.assert_no_docker_execution()

    def test_expired_authorization_does_not_enable_execution(self):
        record = self.grant()
        self.now[0] += timedelta(seconds=61)

        result = self.client.execute_command(
            "nuclei -u http://localhost:8080",
            authorization_id=record["id"],
        )
        self.assertEqual(result.status, ExecutionStatus.FAILED)
        self.assert_no_docker_execution()

    def test_revoked_authorization_does_not_enable_execution(self):
        record = self.grant()
        self.store.revoke(
            record["id"], operator="test-operator", confirm=True
        )

        result = self.client.execute_command(
            "nuclei -u http://localhost:8080",
            authorization_id=record["id"],
        )
        self.assertEqual(result.status, ExecutionStatus.FAILED)
        self.assert_no_docker_execution()

    def test_unauthorized_hostname_is_never_contacted(self):
        result = self.client.execute_command(
            "curl -I http://example.com",
            authorization_id="auth_00000000000000000000000000000000",
        )
        self.assertEqual(result.status, ExecutionStatus.FAILED)
        self.assert_no_docker_execution()

    def test_out_of_scope_port_is_never_contacted(self):
        record = self.grant()

        result = self.client.execute_command(
            "curl -I http://localhost:8081",
            authorization_id=record["id"],
        )
        self.assertEqual(result.status, ExecutionStatus.FAILED)
        self.assert_no_docker_execution()

    def test_prohibited_operation_cannot_be_run_as_a_shell(self):
        result = self.client.execute_command(
            "bash -c 'nuclei -u http://localhost:8080'"
        )
        self.assertEqual(result.status, ExecutionStatus.FAILED)
        self.assert_no_docker_execution()

    def test_direct_executor_and_script_calls_cannot_bypass_the_boundary(self):
        result = self.executor.execute(
            "nuclei -u http://localhost:8080",
            skip_validation=True,
        )
        self.assertEqual(result.execution_result.status, ExecutionStatus.FAILED)

        script_result = self.executor.execute_script("echo unsafe")
        self.assertEqual(
            script_result.execution_result.status, ExecutionStatus.FAILED
        )
        self.assert_no_docker_execution()

    def test_direct_workflow_invocation_cannot_bypass_the_boundary(self):
        workflow = port_scan_module.PortScanWorkflow(self.client)
        result = workflow.scan_ports("localhost")

        self.assertFalse(result["steps"]["port_scan"]["success"])
        self.assert_no_docker_execution()

    def test_direct_workflow_registry_invocation_cannot_bypass_the_boundary(self):
        registry = workflow_registry_module.WorkflowRegistry(self.client)
        result = registry.run_workflow(
            "port_scan",
            "scan_ports",
            {"target": "localhost"},
        )

        self.assertFalse(result["steps"]["port_scan"]["success"])
        self.assert_no_docker_execution()

    def test_direct_mcp_execution_tool_cannot_bypass_the_boundary(self):
        server_module.docker_client = self.client
        server_module.executor = self.executor
        server_module._vaults.clear()

        result = server_module.execute_command(
            "nuclei -u http://localhost:8080"
        )
        self.assertIn("[EXECUTION DENIED]", result)
        self.assert_no_docker_execution()

    def test_direct_mcp_workflow_tool_refuses_without_calling_registry(self):
        server_module.docker_client = self.client
        with patch.object(
            server_module.workflow_registry,
            "run_workflow",
            side_effect=AssertionError("workflow registry must not be invoked"),
        ) as registry_call:
            result = server_module.run_workflow(
                "port_scan", "scan_ports", {"target": "localhost"}
            )
        self.assertFalse(result["success"])
        self.assertTrue(result["audit_recorded"])
        registry_call.assert_not_called()
        self.assert_no_docker_execution()

    def test_mcp_workflow_refusal_reports_audit_failure(self):
        server_module.docker_client = self.client
        with patch.object(
            self.store,
            "_save_audit",
            side_effect=AuthorizationError("audit unavailable"),
        ):
            result = server_module.run_workflow(
                "port_scan", "scan_ports", {"target": "localhost"}
            )

        self.assertFalse(result["success"])
        self.assertFalse(result["audit_recorded"])
        self.assertIn("denial audit failed", result["error"])
        self.assert_no_docker_execution()

    def test_manual_e2e_lab_scanner_is_blocked_before_docker_exec(self):
        campaign = lab_e2e_module.Campaign("test-toolbox")
        with patch.object(lab_e2e_module.subprocess, "run") as docker_exec:
            step = campaign.run(
                "local test scan", "nuclei -u http://127.0.0.1:8080"
            )

        self.assertTrue(step["blocked"])
        docker_exec.assert_not_called()

    def test_revocation_between_preflight_and_execution_still_denies(self):
        record = self.grant()
        preflight = self.store.authorize_url(
            record["id"], "http://localhost:8080", method="http_get"
        )
        self.assertTrue(preflight.allowed)
        self.store.revoke(
            record["id"], operator="test-operator", confirm=True
        )

        result = self.client.execute_command(
            "curl -I http://localhost:8080",
            authorization_id=record["id"],
        )
        self.assertEqual(result.status, ExecutionStatus.FAILED)
        self.assert_no_docker_execution()

    def test_audit_write_failure_is_fail_closed(self):
        with patch.object(
            self.store,
            "_save_audit",
            side_effect=AuthorizationError("audit unavailable"),
        ):
            result = self.client.execute_command(
                "nuclei -u http://localhost:8080"
            )

        self.assertEqual(result.status, ExecutionStatus.FAILED)
        self.assertFalse(result.metadata["audit_recorded"])
        self.assert_no_docker_execution()

    def test_redirect_outside_scope_is_rejected_without_network_execution(self):
        record = self.grant()
        decision = self.store.authorize_url(
            record["id"],
            "http://169.254.169.254/latest/meta-data/",
            method="http_get",
            redirect=True,
        )

        self.assertFalse(decision.allowed)
        self.assert_no_docker_execution()

    def test_cancelled_execution_is_not_started(self):
        cancel_event = threading.Event()
        cancel_event.set()

        result = self.client.execute_command(
            "df -h", cancel_event=cancel_event
        )

        self.assertEqual(result.status, ExecutionStatus.CANCELLED)
        self.assertFalse(result.metadata["command_started"])
        self.assert_no_docker_execution()

    def test_failed_authorization_lookup_does_not_execute(self):
        with patch.object(
            self.store,
            "_load",
            side_effect=AuthorizationError("authorization store unavailable"),
        ):
            result = self.client.execute_command(
                "curl -I http://localhost:8080",
                authorization_id="auth_00000000000000000000000000000000",
            )

        self.assertEqual(result.status, ExecutionStatus.FAILED)
        self.assertFalse(result.metadata["audit_recorded"])
        self.assert_no_docker_execution()


if __name__ == "__main__":
    unittest.main()
