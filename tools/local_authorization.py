#!/usr/bin/env python3
"""Operator helper for managing local-only authorization records."""

import argparse
import getpass
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mcp"))

from src.authorization import (  # noqa: E402
    ALLOWED_METHODS,
    AuthorizationError,
    AuthorizationStore,
)


DEFAULT_FILE = ROOT / "gregorforge-authorizations" / "authorizations.json"
DEFAULT_AUDIT_FILE = (
    ROOT / "gregorforge-settings" / ".gregorforge-authorization-audit.json"
)


def _confirm(prompt: str) -> bool:
    if not sys.stdin.isatty():
        raise AuthorizationError("authorization changes require an interactive terminal")
    return input(prompt).strip() == "I AM AUTHORIZED"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", type=Path, default=DEFAULT_FILE)
    parser.add_argument("--audit-file", type=Path, default=DEFAULT_AUDIT_FILE)
    subparsers = parser.add_subparsers(dest="action", required=True)

    grant = subparsers.add_parser("grant", help="authorize one loopback HTTP target")
    grant.add_argument("--target", required=True, help="exact localhost URL, e.g. http://127.0.0.1:3000")
    grant.add_argument("--ports", required=True, help="comma-separated explicit ports")
    grant.add_argument("--methods", required=True, help="comma-separated permitted methods")
    grant.add_argument("--ttl-seconds", type=int, default=3600)

    revoke = subparsers.add_parser("revoke", help="revoke an authorization ID")
    revoke.add_argument("authorization_id")

    subparsers.add_parser("list", help="list local authorization metadata")
    args = parser.parse_args()
    store = AuthorizationStore(args.file, audit_path=args.audit_file)
    operator = getpass.getuser()

    try:
        if args.action == "grant":
            ports = [int(value) for value in args.ports.split(",") if value]
            methods = [value.strip() for value in args.methods.split(",") if value.strip()]
            if not set(methods).issubset(ALLOWED_METHODS):
                raise AuthorizationError("unsupported testing method")
            confirmed = _confirm(
                f"Authorize only {args.target} for {methods} from local account "
                f"{operator!r}? Type 'I AM AUTHORIZED': "
            )
            record = store.create_local_authorization(
                args.target,
                ports=ports,
                methods=methods,
                operator=operator,
                confirm_authority=confirmed,
                ttl_seconds=args.ttl_seconds,
            )
            print(f"Authorization created: {record['id']}")
            print(f"Target: {record['target_origin']} (loopback only)")
            print(f"Expires: {record['expires_at']}")
            print("Note: this record does not enable active execution.")
        elif args.action == "revoke":
            confirmed = _confirm(
                f"Revoke {args.authorization_id} as local account {operator!r}? "
                "Type 'I AM AUTHORIZED': "
            )
            store.revoke(args.authorization_id, operator=operator, confirm=confirmed)
            print(f"Authorization revoked: {args.authorization_id}")
        else:
            for record in store.list_authorizations():
                print(
                    f"{record['id']} {record['status']} {record['target_origin']} "
                    f"expires={record['expires_at']} methods={','.join(record['methods'])}"
                )
    except (AuthorizationError, ValueError, OSError) as exc:
        print(f"Authorization operation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
