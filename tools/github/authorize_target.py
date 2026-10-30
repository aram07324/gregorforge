#!/usr/bin/env python3
"""Check a target origin against an operator-maintained exact-match allowlist.

This is a policy preflight only. It performs no DNS lookup, connection, or scan.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from urllib.parse import urlsplit


class TargetPolicyError(ValueError):
    """Raised when a target or allowlist entry is malformed or unauthorized."""


def normalize_origin(value: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise TargetPolicyError("target must be a non-empty URL without surrounding whitespace")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise TargetPolicyError("target contains control characters")

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise TargetPolicyError("target has an invalid URL authority or port") from exc

    if parsed.scheme.lower() != "https":
        raise TargetPolicyError("only HTTPS target origins are accepted")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise TargetPolicyError("target must contain a hostname and no embedded credentials")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise TargetPolicyError("target must be an origin without a path, query, or fragment")
    if parsed.netloc.endswith(":"):
        raise TargetPolicyError("target has an empty port")
    if port is not None and not 1 <= port <= 65535:
        raise TargetPolicyError("target port is outside the valid range")

    host = parsed.hostname.rstrip(".")
    if not host:
        raise TargetPolicyError("target hostname is malformed")

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            ascii_host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise TargetPolicyError("target hostname is malformed") from exc
        labels = ascii_host.split(".")
        if any(
            not label
            or len(label) > 63
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in labels
        ):
            raise TargetPolicyError("target hostname is malformed")
        normalized_host = ascii_host
    else:
        normalized_host = f"[{address.compressed}]" if address.version == 6 else address.compressed

    normalized_port = "" if port in (None, 443) else f":{port}"
    return f"https://{normalized_host}{normalized_port}"


def authorize_target(target: str, allowlist_json: str) -> str:
    if not isinstance(allowlist_json, str) or len(allowlist_json) > 16 * 1024:
        raise TargetPolicyError("authorized-targets exceeds the configured size limit")
    try:
        entries = json.loads(allowlist_json)
    except (TypeError, json.JSONDecodeError) as exc:
        raise TargetPolicyError("authorized-targets must be a JSON array") from exc
    if not isinstance(entries, list) or not entries:
        raise TargetPolicyError("authorized-targets must be a non-empty JSON array")
    if len(entries) > 100:
        raise TargetPolicyError("authorized-targets exceeds the configured size limit")

    normalized_entries = {normalize_origin(entry) for entry in entries}
    normalized_target = normalize_origin(target)
    if normalized_target not in normalized_entries:
        raise TargetPolicyError("target does not exactly match an authorized HTTPS origin")
    return normalized_target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="HTTPS origin to check")
    parser.add_argument(
        "--authorized-targets",
        required=True,
        help="JSON array of operator-authorized HTTPS origins",
    )
    args = parser.parse_args()

    try:
        authorize_target(args.target, args.authorized_targets)
    except TargetPolicyError as exc:
        print(f"Target policy rejected the request: {exc}", file=sys.stderr)
        return 1

    print("Target matches the configured authorized-origin allowlist.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
