import datetime as dt
import hashlib
import hmac
import json
import unittest
from unittest.mock import patch

import run_preview_check
from preview_scan import CheckResult, Finding, PreviewScanError, check_preview_origin
from run_preview_check import (
    MAX_ATTESTATION_TTL,
    SIGNED_FIELDS,
    PreviewCheckError,
    _provider_endpoint,
    verify_attestation,
)


class FakeResponse:
    def __init__(self, status, headers=()):
        self.status = status
        self._headers = headers

    def getheaders(self):
        return self._headers


class FakeConnection:
    def __init__(self, status=200, headers=()):
        self.status = status
        self.headers = headers
        self.requests = []
        self.closed = False

    def request(self, method, path, headers):
        self.requests.append((method, path, headers))

    def getresponse(self):
        return FakeResponse(self.status, self.headers)

    def close(self):
        self.closed = True


def signed_attestation(now=None):
    current = now or dt.datetime.now(dt.timezone.utc)
    key = "test-signing-key-that-is-at-least-32-bytes"
    attestation = {
        "repository": "owner/repo",
        "pull_request": 42,
        "head_sha": "a" * 40,
        "preview_id": "preview-42",
        "origin": "https://preview.example.com",
        "expires_at": (current + MAX_ATTESTATION_TTL).isoformat(),
        "status": "ready",
    }
    payload = {field: attestation[field] for field in SIGNED_FIELDS}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    attestation["signature"] = hmac.new(
        key.encode(),
        canonical.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return attestation, key, current


class PreviewScanTests(unittest.TestCase):
    def test_sends_only_one_head_request_to_root_and_closes(self):
        connection = FakeConnection(
            headers=[
                ("Strict-Transport-Security", "max-age=31536000"),
                ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
                ("X-Content-Type-Options", "nosniff"),
                ("Referrer-Policy", "no-referrer"),
            ],
        )
        pinned = []

        def resolver(host, port):
            self.assertEqual((host, port), ("preview.example.com", 443))
            return ["93.184.216.34"]

        def connection_factory(host, port, address, timeout):
            pinned.append((host, port, address, timeout))
            return connection

        result = check_preview_origin(
            "https://preview.example.com/",
            resolver=resolver,
            connection_factory=connection_factory,
        )

        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.findings, ())
        self.assertEqual(len(connection.requests), 1)
        method, path, _headers = connection.requests[0]
        self.assertEqual((method, path), ("HEAD", "/"))
        self.assertEqual(pinned[0][:3], ("preview.example.com", 443, "93.184.216.34"))
        self.assertTrue(connection.closed)

    def test_reports_missing_security_headers(self):
        connection = FakeConnection(headers=[("Server", "test")])
        result = check_preview_origin(
            "https://preview.example.com",
            resolver=lambda _host, _port: ["93.184.216.34"],
            connection_factory=lambda *_args: connection,
        )
        codes = {finding.code for finding in result.findings}
        self.assertEqual(
            codes,
            {
                "invalid-hsts",
                "missing-csp",
                "missing-nosniff",
                "missing-referrer-policy",
                "missing-frame-protection",
            },
        )

    def test_flags_invalid_hsts_and_wildcard_frame_ancestors(self):
        connection = FakeConnection(
            headers=[
                ("Strict-Transport-Security", "max-age=0"),
                ("Content-Security-Policy", "default-src 'self'; frame-ancestors *"),
                ("X-Content-Type-Options", "nosniff"),
                ("Referrer-Policy", "no-referrer"),
            ],
        )
        result = check_preview_origin(
            "https://preview.example.com",
            resolver=lambda _host, _port: ["93.184.216.34"],
            connection_factory=lambda *_args: connection,
        )
        self.assertEqual(
            {finding.code for finding in result.findings},
            {"invalid-hsts", "missing-frame-protection"},
        )

    def test_handles_oversized_hsts_numeric_value_as_invalid(self):
        connection = FakeConnection(
            headers=[
                ("Strict-Transport-Security", f"max-age={'9' * 5000}"),
                ("Content-Security-Policy", "default-src 'self'"),
            ],
        )
        result = check_preview_origin(
            "https://preview.example.com",
            resolver=lambda _host, _port: ["93.184.216.34"],
            connection_factory=lambda *_args: connection,
        )
        self.assertIn("invalid-hsts", {finding.code for finding in result.findings})

    def test_checks_cookie_attributes_without_reporting_cookie_values(self):
        connection = FakeConnection(
            headers=[
                ("Strict-Transport-Security", "max-age=31536000"),
                ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'"),
                ("X-Content-Type-Options", "nosniff"),
                ("Referrer-Policy", "strict-origin"),
                ("Set-Cookie", "session=secret-value; Path=/"),
            ],
        )
        result = check_preview_origin(
            "https://preview.example.com",
            resolver=lambda _host, _port: ["93.184.216.34"],
            connection_factory=lambda *_args: connection,
        )
        codes = {finding.code for finding in result.findings}
        self.assertEqual(
            codes,
            {
                "cookie-missing-secure",
                "cookie-missing-httponly",
                "cookie-missing-samesite",
            },
        )
        self.assertNotIn("secret-value", repr(result.findings))

    def test_secure_samesite_none_cookie_has_no_cookie_findings(self):
        connection = FakeConnection(
            headers=[
                ("Strict-Transport-Security", "max-age=31536000"),
                ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
                ("X-Content-Type-Options", "nosniff"),
                ("Referrer-Policy", "no-referrer"),
                ("Set-Cookie", "session=x; Secure; HttpOnly; SameSite=None"),
            ],
        )
        result = check_preview_origin(
            "https://preview.example.com",
            resolver=lambda _host, _port: ["93.184.216.34"],
            connection_factory=lambda *_args: connection,
        )
        self.assertEqual(result.findings, ())

    def test_duplicate_security_headers_are_not_silently_accepted(self):
        connection = FakeConnection(
            headers=[
                ("Strict-Transport-Security", "max-age=31536000"),
                ("Strict-Transport-Security", "max-age=0"),
                ("Content-Security-Policy", "default-src 'self'"),
                ("X-Content-Type-Options", "nosniff"),
                ("X-Content-Type-Options", "invalid"),
                ("Referrer-Policy", "no-referrer"),
            ],
        )
        result = check_preview_origin(
            "https://preview.example.com",
            resolver=lambda _host, _port: ["93.184.216.34"],
            connection_factory=lambda *_args: connection,
        )
        codes = {finding.code for finding in result.findings}
        self.assertIn("invalid-hsts", codes)
        self.assertIn("missing-nosniff", codes)

    def test_rejects_non_public_dns_before_connecting(self):
        for address in ("127.0.0.1", "10.1.2.3", "169.254.169.254", "192.0.2.1"):
            with self.subTest(address=address):
                called = []
                with self.assertRaises(PreviewScanError):
                    check_preview_origin(
                        "https://preview.example.com",
                        resolver=lambda _host, _port: [address],
                        connection_factory=lambda *_args: called.append(True),
                    )
                self.assertEqual(called, [])

    def test_rejects_private_literal_before_dns(self):
        with self.assertRaises(PreviewScanError):
            check_preview_origin(
                "https://127.0.0.1",
                resolver=lambda *_args: self.fail("literal private IP must be rejected before DNS"),
                connection_factory=lambda *_args: self.fail("must not connect"),
            )

    def test_literal_ip_must_match_resolver_answer(self):
        with self.assertRaisesRegex(PreviewScanError, "did not match"):
            check_preview_origin(
                "https://93.184.216.34",
                resolver=lambda _host, _port: ["1.1.1.1"],
                connection_factory=lambda *_args: self.fail("must not connect"),
            )

    def test_revalidates_attestation_after_dns_and_before_connect(self):
        order = []

        def revalidate():
            order.append("attestation")

        def connect(*_args):
            order.append("connect")
            return FakeConnection(
                headers=[
                    ("Strict-Transport-Security", "max-age=31536000"),
                    ("Content-Security-Policy", "frame-ancestors 'none'"),
                    ("X-Content-Type-Options", "nosniff"),
                    ("Referrer-Policy", "no-referrer"),
                ],
            )

        check_preview_origin(
            "https://preview.example.com",
            resolver=lambda _host, _port: (order.append("dns") or ["93.184.216.34"]),
            before_connect=revalidate,
            connection_factory=connect,
        )
        self.assertEqual(order, ["dns", "attestation", "connect"])

    def test_failed_preconnect_revalidation_never_connects(self):
        with self.assertRaisesRegex(PreviewCheckError, "expired"):
            check_preview_origin(
                "https://preview.example.com",
                resolver=lambda _host, _port: ["93.184.216.34"],
                before_connect=lambda: (_ for _ in ()).throw(
                    PreviewCheckError("preview attestation expired")
                ),
                connection_factory=lambda *_args: self.fail("must not connect"),
            )

    def test_rejects_mixed_public_and_private_dns_answers(self):
        with self.assertRaises(PreviewScanError):
            check_preview_origin(
                "https://preview.example.com",
                resolver=lambda _host, _port: ["93.184.216.34", "10.0.0.5"],
                connection_factory=lambda *_args: self.fail("must not connect"),
            )

    def test_rejects_redirect_without_following_it(self):
        connection = FakeConnection(status=302, headers=[("Location", "https://other.example.com")])
        with self.assertRaisesRegex(PreviewScanError, "redirect"):
            check_preview_origin(
                "https://preview.example.com",
                resolver=lambda _host, _port: ["93.184.216.34"],
                connection_factory=lambda *_args: connection,
            )
        self.assertEqual(len(connection.requests), 1)
        self.assertTrue(connection.closed)

    def test_rejects_unexpected_status(self):
        with self.assertRaises(PreviewScanError):
            check_preview_origin(
                "https://preview.example.com",
                resolver=lambda _host, _port: ["93.184.216.34"],
                connection_factory=lambda *_args: FakeConnection(status=503),
            )

    def test_rejects_non_origin_url(self):
        with self.assertRaises(PreviewScanError):
            check_preview_origin(
                "https://preview.example.com/anything",
                resolver=lambda *_args: self.fail("must reject before DNS"),
                connection_factory=lambda *_args: self.fail("must reject before connect"),
            )


class AttestationTests(unittest.TestCase):
    def test_provider_endpoint_accepts_only_an_https_origin(self):
        self.assertEqual(
            _provider_endpoint("https://provider.example/", "owner/repo", 42, "a" * 40),
            f"https://provider.example/v1/previews/github/owner/repo/42?head_sha={'a' * 40}",
        )
        for value in (
            "http://provider.example",
            "https://provider.example/path",
            "https://user:pass@provider.example",
            "https://provider.example?debug=1",
        ):
            with self.subTest(value=value), self.assertRaises(PreviewCheckError):
                _provider_endpoint(value, "owner/repo", 42, "a" * 40)

    def test_accepts_valid_short_lived_attestation(self):
        attestation, key, now = signed_attestation()
        origin = verify_attestation(
            attestation,
            repository="owner/repo",
            pull_request=42,
            head_sha="a" * 40,
            signing_key=key,
            authorized_targets='["https://preview.example.com"]',
            now=now,
        )
        self.assertEqual(origin, "https://preview.example.com")

    def test_rejects_signature_or_scope_tampering(self):
        for field, value in (
            ("origin", "https://attacker.example.com"),
            ("head_sha", "b" * 40),
            ("preview_id", "other-preview"),
        ):
            attestation, key, now = signed_attestation()
            attestation[field] = value
            with self.subTest(field=field), self.assertRaises(PreviewCheckError):
                verify_attestation(
                    attestation,
                    repository="owner/repo",
                    pull_request=42,
                    head_sha="a" * 40,
                    signing_key=key,
                    authorized_targets='["https://preview.example.com"]',
                    now=now,
                )

    def test_rejects_mismatched_pull_request_repository_and_commit(self):
        cases = (
            {"repository": "other/repo"},
            {"pull_request": 43},
            {"head_sha": "b" * 40},
        )
        for updates in cases:
            attestation, key, now = signed_attestation()
            attestation.update(updates)
            with self.subTest(updates=updates), self.assertRaises(PreviewCheckError):
                verify_attestation(
                    attestation,
                    repository="owner/repo",
                    pull_request=42,
                    head_sha="a" * 40,
                    signing_key=key,
                    authorized_targets='["https://preview.example.com"]',
                    now=now,
                )

    def test_rejects_expired_or_long_lived_attestation(self):
        for delta in (
            dt.timedelta(seconds=-1),
            MAX_ATTESTATION_TTL + dt.timedelta(seconds=1),
        ):
            now = dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)
            attestation, key, _ = signed_attestation(now)
            attestation["expires_at"] = (now + delta).isoformat()
            payload = {field: attestation[field] for field in SIGNED_FIELDS}
            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            attestation["signature"] = hmac.new(
                key.encode(), canonical.encode("ascii"), hashlib.sha256
            ).hexdigest()
            with self.subTest(delta=delta), self.assertRaises(PreviewCheckError):
                verify_attestation(
                    attestation,
                    repository="owner/repo",
                    pull_request=42,
                    head_sha="a" * 40,
                    signing_key=key,
                    authorized_targets='["https://preview.example.com"]',
                    now=now,
                )

    def test_rejects_unallowlisted_origin(self):
        attestation, key, now = signed_attestation()
        with self.assertRaises(PreviewCheckError):
            verify_attestation(
                attestation,
                repository="owner/repo",
                pull_request=42,
                head_sha="a" * 40,
                signing_key=key,
                authorized_targets='["https://other.example.com"]',
                now=now,
            )


class FakeAPIResponse:
    def __init__(self, value, status=200):
        self.status = status
        self.payload = json.dumps(value).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, size=-1):
        return self.payload if size < 0 else self.payload[:size]


class FakeGitHubAndPreviewAPI:
    def __init__(self, attestation, head_sha="a" * 40):
        self.attestation = attestation
        self.head_sha = head_sha
        self.requests = []
        self.change_head_after_provider = None

    def open(self, request, timeout):
        method = request.get_method()
        self.requests.append((method, request.full_url, request))
        if "/pulls/42" in request.full_url:
            return FakeAPIResponse({
                "number": 42,
                "state": "open",
                "draft": False,
                "base": {"ref": "main", "repo": {"full_name": "owner/repo"}},
                "head": {"sha": self.head_sha},
            })
        if method == "POST" and request.full_url.endswith("/check-runs"):
            return FakeAPIResponse({"id": 123}, status=201)
        if "/v1/previews/github/owner/repo/42" in request.full_url:
            if self.change_head_after_provider is not None:
                self.head_sha = self.change_head_after_provider
            return FakeAPIResponse(self.attestation)
        if method == "PATCH" and "/check-runs/123" in request.full_url:
            return FakeAPIResponse({"id": 123})
        raise AssertionError(f"Unexpected API request: {method} {request.full_url}")


class WorkflowIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.attestation, self.key, _ = signed_attestation()
        self.api = FakeGitHubAndPreviewAPI(self.attestation)
        self.environment = patch.dict(
            "os.environ",
            {
                "GITHUB_TOKEN": "test-token",
                "GITHUB_REPOSITORY": "owner/repo",
                "GREGORFORGE_AUTHORIZED_TARGETS": '["https://preview.example.com"]',
                "GREGORFORGE_PREVIEW_PROVIDER_URL": "https://provider.example",
                "GREGORFORGE_PREVIEW_PROVIDER_TOKEN": "provider-token",
                "GREGORFORGE_PREVIEW_ATTESTATION_KEY": self.key,
            },
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.opener_patch = patch("run_preview_check._https_opener", return_value=self.api)
        self.opener_patch.start()
        self.addCleanup(self.opener_patch.stop)

    def test_creates_and_completes_pr_check_run(self):
        result = CheckResult(
            200,
            (Finding("missing-csp", "medium", "Content-Security-Policy header is missing"),),
        )
        with patch("run_preview_check.check_preview_origin", return_value=result) as scan:
            actual = run_preview_check.run_check(42)

        self.assertEqual(actual, result)
        scan.assert_called_once()
        self.assertEqual(scan.call_args.args[0], "https://preview.example.com")
        self.assertTrue(callable(scan.call_args.kwargs["before_connect"]))
        requests = self.api.requests
        self.assertEqual([method for method, _url, _request in requests], [
            "GET", "POST", "GET", "GET", "PATCH",
        ])
        self.assertEqual(
            [request.get_header("Authorization") for _method, _url, request in requests],
            [
                "Bearer test-token",
                "Bearer test-token",
                "Bearer provider-token",
                "Bearer test-token",
                "Bearer test-token",
            ],
        )
        start_payload = json.loads(requests[1][2].data)
        finish_payload = json.loads(requests[-1][2].data)
        self.assertEqual(start_payload["head_sha"], "a" * 40)
        self.assertEqual(finish_payload["conclusion"], "failure")
        self.assertNotIn("preview.example.com", finish_payload["output"]["summary"])

    def test_tampered_attestation_fails_check_without_network_scan(self):
        self.attestation["origin"] = "https://attacker.example"
        with patch("run_preview_check.check_preview_origin") as scan:
            with self.assertRaises(PreviewCheckError):
                run_preview_check.run_check(42)

        scan.assert_not_called()

    def test_pr_head_change_after_attestation_prevents_scan(self):
        self.api.change_head_after_provider = "b" * 40
        with patch("run_preview_check.check_preview_origin") as scan:
            with self.assertRaisesRegex(PreviewCheckError, "changed during"):
                run_preview_check.run_check(42)
        scan.assert_not_called()
        finish_payload = json.loads(self.api.requests[-1][2].data)
        self.assertEqual(finish_payload["conclusion"], "failure")

    def test_stale_preview_commit_is_not_scanned(self):
        self.api.head_sha = "b" * 40
        with patch("run_preview_check.check_preview_origin") as scan:
            with self.assertRaisesRegex(PreviewCheckError, "commit does not match"):
                run_preview_check.run_check(42)
        scan.assert_not_called()


if __name__ == "__main__":
    unittest.main()
