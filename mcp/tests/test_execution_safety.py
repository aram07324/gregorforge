"""Tests for fail-closed diagnostics and local authorization records."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.authorization import (  # noqa: E402
    AuthorizationError,
    AuthorizationStore,
    parse_local_target,
)
from src.execution_policy import evaluate_command  # noqa: E402


class ExecutionPolicyTests(unittest.TestCase):
    def test_only_read_only_diagnostics_are_allowed(self):
        allowed = (
            "which nuclei",
            "df -h",
            "df -h /opt/gregorforge/out",
            "free -h",
            "nuclei --version",
            ["httpx", "--version"],
        )
        for command in allowed:
            with self.subTest(command=command):
                self.assertTrue(evaluate_command(command).allowed)

    def test_active_commands_and_shell_forms_are_denied(self):
        denied = (
            "nuclei -u http://127.0.0.1:8080",
            "curl -I http://127.0.0.1:8080",
            "bash -c 'echo unsafe'",
            "python3 -c 'print(1)'",
            "nuclei --version; whoami",
            "./nuclei --version",
            "/root/.config/opencode/nuclei --version",
        )
        for command in denied:
            with self.subTest(command=command):
                self.assertFalse(evaluate_command(command).allowed)

    def test_context_overrides_are_denied(self):
        self.assertFalse(
            evaluate_command("nuclei --version", workdir="/tmp").allowed
        )
        self.assertFalse(
            evaluate_command("nuclei --version", environment={}).allowed
        )


class AuthorizationStoreTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 29, tzinfo=timezone.utc)
        self.addresses = ("127.0.0.1",)
        self.tempdir = tempfile.TemporaryDirectory()
        self.registry_path = os.path.join(self.tempdir.name, "authorizations.json")
        self.audit_path = os.path.join(self.tempdir.name, "audit.json")
        self.store = AuthorizationStore(
            self.registry_path,
            audit_path=self.audit_path,
            resolver=lambda _host: self.addresses,
            clock=lambda: self.now,
        )

    def tearDown(self):
        self.tempdir.cleanup()

    def create_record(self):
        return self.store.create_local_authorization(
            "http://localhost:8080",
            ports=[8080],
            methods=["http_get"],
            operator="local-test",
            confirm_authority=True,
            ttl_seconds=60,
        )

    def test_matching_local_authorization_is_audited_without_execution(self):
        record = self.create_record()
        decision = self.store.authorize_url(
            record["id"],
            "http://localhost:8080/path",
            method="http_get",
            request_id="request-123",
        )
        self.assertTrue(decision.allowed)

        registry = json.loads(Path(self.registry_path).read_text(encoding="utf-8"))
        audit = json.loads(Path(self.audit_path).read_text(encoding="utf-8"))
        self.assertNotIn("audit", registry)
        self.assertEqual(audit["events"][-1]["action"], "use")
        self.assertEqual(audit["events"][-1]["request_id"], "request-123")

    def test_out_of_scope_target_and_dns_change_are_denied(self):
        record = self.create_record()
        outside_port = self.store.authorize_url(
            record["id"],
            "http://localhost:8081",
            method="http_get",
        )
        self.assertFalse(outside_port.allowed)

        self.addresses = ("127.0.0.2",)
        changed_dns = self.store.authorize_url(
            record["id"],
            "http://localhost:8080",
            method="http_get",
        )
        self.assertFalse(changed_dns.allowed)
        self.assertIn("DNS resolution changed", changed_dns.reason)

    def test_expiry_and_revocation_are_enforced(self):
        record = self.create_record()
        self.now += timedelta(seconds=61)
        expired = self.store.authorize_url(
            record["id"],
            "http://localhost:8080",
            method="http_get",
        )
        self.assertFalse(expired.allowed)
        self.assertIn("expired", expired.reason)

        self.now -= timedelta(seconds=61)
        self.store.revoke(record["id"], operator="local-test", confirm=True)
        revoked = self.store.authorize_url(
            record["id"],
            "http://localhost:8080",
            method="http_get",
        )
        self.assertFalse(revoked.allowed)
        self.assertIn("revoked", revoked.reason)

    def test_non_loopback_and_zero_port_are_rejected(self):
        with self.assertRaises(ValueError):
            parse_local_target("http://example.org:8080")
        with self.assertRaises(ValueError):
            parse_local_target("http://127.0.0.1:0")

    def test_invalid_resolver_answers_and_resolver_failures_are_rejected(self):
        for resolver in (
            lambda _host: ("192.0.2.1",),
            lambda _host: ("not-an-ip",),
            lambda _host: (_ for _ in ()).throw(OSError("resolver unavailable")),
        ):
            with self.subTest(resolver=resolver):
                with self.assertRaises(AuthorizationError):
                    parse_local_target("http://localhost:8080", resolver)

    def test_malformed_grant_inputs_are_rejected(self):
        invalid_grants = (
            {"ports": [True, 8080]},
            {"ttl_seconds": True},
            {"operator": None},
            {"methods": ["http_get", None]},
        )
        for overrides in invalid_grants:
            with self.subTest(overrides=overrides):
                arguments = {
                    "ports": [8080],
                    "methods": ["http_get"],
                    "operator": "local-test",
                    "confirm_authority": True,
                    "ttl_seconds": 60,
                }
                arguments.update(overrides)
                with self.assertRaises(AuthorizationError):
                    self.store.create_local_authorization(
                        "http://localhost:8080", **arguments
                    )

    def test_failed_grant_audit_rolls_back_registry_change(self):
        with patch.object(
            self.store,
            "_save_audit",
            side_effect=AuthorizationError("audit write failed"),
        ):
            with self.assertRaisesRegex(AuthorizationError, "grant was rolled back"):
                self.create_record()

        self.assertEqual(self.store.list_authorizations(), [])

    def test_registry_record_without_creation_audit_is_not_authorized(self):
        record = self.create_record()
        audit = json.loads(Path(self.audit_path).read_text(encoding="utf-8"))
        audit["events"] = [
            event for event in audit["events"] if event["action"] != "created"
        ]
        Path(self.audit_path).write_text(json.dumps(audit), encoding="utf-8")

        decision = self.store.authorize_url(
            record["id"], "http://localhost:8080", method="http_get"
        )
        self.assertFalse(decision.allowed)
        self.assertIn("creation audit event is missing", decision.reason)

    def test_malformed_persisted_scope_is_not_authorized(self):
        record = self.create_record()
        registry = json.loads(Path(self.registry_path).read_text(encoding="utf-8"))
        registry["authorizations"][0]["ports"] = [True]
        Path(self.registry_path).write_text(
            json.dumps(registry), encoding="utf-8"
        )

        decision = self.store.authorize_url(
            record["id"], "http://localhost:8080", method="http_get"
        )
        self.assertFalse(decision.allowed)
        self.assertIn("scope data is malformed", decision.reason)

    def test_failed_revocation_audit_reports_revocation_and_remains_denied(self):
        record = self.create_record()
        with patch.object(
            self.store,
            "_save_audit",
            side_effect=AuthorizationError("audit write failed"),
        ):
            with self.assertRaisesRegex(AuthorizationError, "was revoked"):
                self.store.revoke(
                    record["id"], operator="local-test", confirm=True
                )

        decision = self.store.authorize_url(
            record["id"], "http://localhost:8080", method="http_get"
        )
        self.assertFalse(decision.allowed)
        self.assertIn("revoked", decision.reason)

    def test_audit_writes_are_serialized_across_processes(self):
        script = (
            "import sys; "
            "sys.path.insert(0, sys.argv[1]); "
            "from src.authorization import AuthorizationStore; "
            "store = AuthorizationStore(sys.argv[2], audit_path=sys.argv[3]); "
            "store.audit_denial(authorization_id=None, tool='test', reason=sys.argv[4])"
        )
        processes = [
            subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    script,
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    self.registry_path,
                    self.audit_path,
                    str(index),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for index in range(4)
        ]
        for process in processes:
            _stdout, stderr = process.communicate(timeout=20)
            self.assertEqual(process.returncode, 0, stderr)

        audit = json.loads(Path(self.audit_path).read_text(encoding="utf-8"))
        self.assertEqual(
            sorted(event["reason"] for event in audit["events"]),
            ["0", "1", "2", "3"],
        )

    def test_redirect_must_remain_on_the_authorized_origin(self):
        record = self.create_record()
        decision = self.store.authorize_url(
            record["id"],
            "http://127.0.0.2:8080/path",
            method="http_get",
            redirect=True,
        )
        self.assertFalse(decision.allowed)
        self.assertIn("outside the authorized origin", decision.reason)


if __name__ == "__main__":
    unittest.main()
