import unittest

from authorize_target import TargetPolicyError, authorize_target, normalize_origin


class NormalizeOriginTests(unittest.TestCase):
    def test_normalizes_case_default_port_and_trailing_slash(self):
        self.assertEqual(
            normalize_origin("HTTPS://Staging.Example.COM:443/"),
            "https://staging.example.com",
        )

    def test_normalizes_ipv6(self):
        self.assertEqual(
            normalize_origin("https://[2001:0db8::1]:8443"),
            "https://[2001:db8::1]:8443",
        )

    def test_rejects_non_origin_urls(self):
        for value in (
            "http://staging.example.com",
            "https://user:pass@staging.example.com",
            "https://staging.example.com/path",
            "https://staging.example.com?debug=1",
            "https://staging.example.com#section",
            "https://*.example.com",
            "https://staging.example.com:",
        ):
            with self.subTest(value=value), self.assertRaises(TargetPolicyError):
                normalize_origin(value)


class AuthorizeTargetTests(unittest.TestCase):
    def test_requires_exact_origin_allowlist_match(self):
        self.assertEqual(
            authorize_target(
                "https://STAGING.example.com/",
                '["https://staging.example.com"]',
            ),
            "https://staging.example.com",
        )

    def test_rejects_subdomain_and_port_mismatch(self):
        for target in (
            "https://admin.staging.example.com",
            "https://staging.example.com:8443",
        ):
            with self.subTest(target=target), self.assertRaises(TargetPolicyError):
                authorize_target(target, '["https://staging.example.com"]')

    def test_rejects_invalid_allowlists(self):
        for allowlist in ("", "{}", '["https://example.com/path"]', '["*.example.com"]'):
            with self.subTest(allowlist=allowlist), self.assertRaises(TargetPolicyError):
                authorize_target("https://staging.example.com", allowlist)


if __name__ == "__main__":
    unittest.main()
