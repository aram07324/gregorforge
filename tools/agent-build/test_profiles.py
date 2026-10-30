#!/usr/bin/env python3
"""Regression tests for generated and validated agent profiles."""

import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)

import generate  # noqa: E402
import validate  # noqa: E402


class ProfileGenerationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        canonical = os.path.join(REPO, "conf", "agents", "graphql.md")
        cls.spine = generate.extract_spine(generate.read_lines(canonical))
        cls.banner = cls.spine["status_banner"]

    def load_profile(self, name):
        path = os.path.join(HERE, "profiles", f"{name}.json")
        with open(path, encoding="utf-8") as profile_file:
            return json.load(profile_file)

    def validate_generated(self, profile):
        generated = generate.build_agent(profile, self.spine)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", suffix=".md", delete=False
        ) as output_file:
            output_file.write(generated)
            output_path = output_file.name
        try:
            return generated, validate.validate(output_path, self.banner)
        finally:
            os.unlink(output_path)

    def test_container_registry_profile_generates_valid_read_only_agent(self):
        profile = self.load_profile("container-registry")
        self.assertIs(profile.get("read_only"), True)

        generated, errors = self.validate_generated(profile)

        self.assertEqual(errors, [])
        self.assertIn("read_only: true", generated)
        self.assertIn("Do not retrieve manifests, blobs, layers, or image contents.", generated)
        for forbidden in (
            "ANTI-BRUTEFORCE & FIREWALL PROTECTION RULES",
            "SCANNER CONTROL BLOCK",
            "BLACKBOX MODE:",
            "DASHBOARD REAL-TIME PUSH (MANDATORY)",
            "EXECUTION SAFETY — EVERY COMMAND MUST RETURN",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, generated)

    def test_regular_profile_keeps_standard_conformance_requirements(self):
        generated, errors = self.validate_generated(self.load_profile("github"))

        self.assertEqual(errors, [])
        self.assertNotIn("read_only: true", generated)
        self.assertIn("DASHBOARD REAL-TIME PUSH (MANDATORY)", generated)


if __name__ == "__main__":
    unittest.main()
