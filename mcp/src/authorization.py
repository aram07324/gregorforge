"""Local-only target authorization and auditable scope checks.

Authorization records are operator-managed, never model-created. They describe
local test scope only; they do not enable execution. Active network execution
remains disabled until redirects and worker egress can be enforced in-process.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import tempfile
import threading
import uuid
from contextlib import ExitStack, contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator
from urllib.parse import urlsplit


ALLOWED_METHODS = frozenset({
    "http_get",
    "http_head",
    "port_discovery",
    "passive_crawl",
    "vulnerability_scan",
})
MAX_AUTHORIZATION_SECONDS = 24 * 60 * 60
DEFAULT_AUTHORIZATION_FILE = (
    Path.home()
    / ".config"
    / "gregorforge-authorizations"
    / "authorizations.json"
)
DEFAULT_AUDIT_FILE = (
    Path.home() / ".config" / "opencode" / ".gregorforge-authorization-audit.json"
)

_authorization_id: ContextVar[str | None] = ContextVar(
    "gregorforge_authorization_id", default=None
)
_store_lock = threading.RLock()
_AUTHORIZATION_ID_RE = re.compile(r"auth_[0-9a-f]{32}\Z")
_REQUEST_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")


@contextmanager
def _file_lock(path: Path) -> Iterator[None]:
    lock_path = path.with_name(f".{path.name}.lock")
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_file = lock_path.open("a+b")
    except OSError as exc:
        raise AuthorizationError("authorization store lock cannot be opened") from exc

    try:
        if os.name == "nt":
            import msvcrt

            lock_file.seek(0, os.SEEK_END)
            if lock_file.tell() == 0:
                lock_file.write(b"\0")
                lock_file.flush()
            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
    except OSError as exc:
        lock_file.close()
        raise AuthorizationError("authorization store lock cannot be acquired") from exc

    try:
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt

                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        except OSError as exc:
            raise AuthorizationError("authorization store lock cannot be released") from exc
        finally:
            lock_file.close()


@contextmanager
def _file_locks(*paths: Path) -> Iterator[None]:
    lock_paths = sorted({path.resolve() for path in paths}, key=str)
    with ExitStack() as stack:
        for path in lock_paths:
            stack.enter_context(_file_lock(path))
        yield


class AuthorizationError(ValueError):
    """Raised when an authorization record is invalid or cannot be stored."""


@dataclass(frozen=True)
class ParsedTarget:
    origin: str
    host: str
    port: int
    addresses: tuple[str, ...]


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    authorization_id: str | None
    target: str | None
    reason: str


def current_authorization_id() -> str | None:
    return _authorization_id.get()


@contextmanager
def authorization_context(authorization_id: str | None) -> Iterator[None]:
    token = _authorization_id.set(authorization_id)
    try:
        yield
    finally:
        _authorization_id.reset(token)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def _validated_loopback_addresses(addresses: object) -> tuple[str, ...]:
    if not isinstance(addresses, (tuple, list, set, frozenset)) or not addresses:
        raise AuthorizationError("target did not resolve to valid addresses")
    normalized: set[str] = set()
    for address in addresses:
        if not isinstance(address, str):
            raise AuthorizationError("resolver returned an invalid address")
        try:
            parsed = ipaddress.ip_address(address.split("%", 1)[0])
        except ValueError as exc:
            raise AuthorizationError("resolver returned an invalid address") from exc
        if not parsed.is_loopback:
            raise AuthorizationError("target resolves outside the loopback interface")
        normalized.add(parsed.compressed)
    if not normalized:
        raise AuthorizationError("target did not resolve to valid addresses")
    return tuple(sorted(normalized))


def _resolve_loopback(host: str) -> tuple[str, ...]:
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        if host != "localhost":
            raise AuthorizationError("only localhost and loopback IPs can be authorized")
        try:
            results = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise AuthorizationError("localhost did not resolve") from exc
        try:
            addresses = [result[4][0] for result in results]
        except (IndexError, TypeError) as exc:
            raise AuthorizationError("localhost returned an invalid DNS answer") from exc
    else:
        addresses = [literal.compressed]
    return _validated_loopback_addresses(addresses)


def parse_local_target(
    value: str,
    resolver: Callable[[str], tuple[str, ...]] = _resolve_loopback,
) -> ParsedTarget:
    if not isinstance(value, str) or not value or value != value.strip():
        raise AuthorizationError("target URL is empty or malformed")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise AuthorizationError("target URL has an invalid port or authority") from exc
    if parsed.scheme.lower() not in {"http", "https"}:
        raise AuthorizationError("only HTTP and HTTPS target URLs are supported")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise AuthorizationError("target URL must have a host and no embedded credentials")
    if parsed.netloc.endswith(":"):
        raise AuthorizationError("target URL has an empty port")
    if parsed.fragment:
        raise AuthorizationError("target URL fragments are not allowed")

    host = parsed.hostname.lower().rstrip(".")
    if not host or any(char.isspace() for char in host):
        raise AuthorizationError("target hostname is malformed")
    try:
        host_ip = ipaddress.ip_address(host)
    except ValueError:
        if host != "localhost":
            raise AuthorizationError("only localhost and loopback IPs can be authorized")
        canonical_host = "localhost"
    else:
        if not host_ip.is_loopback:
            raise AuthorizationError("only loopback IPs can be authorized")
        canonical_host = host_ip.compressed

    target_port = port if port is not None else (
        443 if parsed.scheme.lower() == "https" else 80
    )
    if not 1 <= target_port <= 65535:
        raise AuthorizationError("target port is outside the valid range")
    if canonical_host == "localhost":
        try:
            addresses = _validated_loopback_addresses(resolver(canonical_host))
        except AuthorizationError:
            raise
        except (OSError, TypeError, ValueError) as exc:
            raise AuthorizationError("target could not be resolved safely") from exc
    else:
        addresses = (canonical_host,)

    authority = (
        f"[{canonical_host}]" if ":" in canonical_host else canonical_host
    )
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    origin = f"{parsed.scheme.lower()}://{authority}"
    if target_port != default_port:
        origin += f":{target_port}"
    return ParsedTarget(origin, canonical_host, target_port, addresses)


class AuthorizationStore:
    """Atomic JSON store for operator-issued local-target authorizations."""

    def __init__(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        audit_path: str | os.PathLike[str] | None = None,
        resolver: Callable[[str], tuple[str, ...]] = _resolve_loopback,
        clock: Callable[[], datetime] = _utc_now,
    ):
        self.path = Path(path) if path is not None else DEFAULT_AUTHORIZATION_FILE
        self.audit_path = Path(audit_path) if audit_path is not None else DEFAULT_AUDIT_FILE
        if self.path.resolve() == self.audit_path.resolve():
            raise AuthorizationError("authorization registry and audit log must be separate files")
        self.resolver = resolver
        self.clock = clock

    def _load(self) -> dict[str, Any]:
        try:
            with self.path.open("r", encoding="utf-8") as file:
                data = json.load(file)
        except FileNotFoundError:
            data = {"schema_version": 1, "authorizations": []}
        except (OSError, json.JSONDecodeError) as exc:
            raise AuthorizationError("authorization store cannot be read") from exc
        if (
            not isinstance(data, dict)
            or type(data.get("schema_version")) is not int
            or data.get("schema_version") != 1
            or not isinstance(data.get("authorizations"), list)
            or any(
                not isinstance(record, dict)
                or not isinstance(record.get("id"), str)
                or not isinstance(record.get("status"), str)
                for record in data["authorizations"]
            )
        ):
            raise AuthorizationError("authorization store has an invalid schema")
        data["audit"] = self._load_audit()
        return data

    def _write_json(self, path: Path, data: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=path.parent,
                prefix=f".{path.name}.",
                suffix=".tmp",
                delete=False,
            ) as file:
                temp_name = file.name
                json.dump(data, file, ensure_ascii=True, separators=(",", ":"))
                file.write("\n")
                file.flush()
                os.fsync(file.fileno())
            if os.name == "posix":
                os.chmod(temp_name, 0o600)
            os.replace(temp_name, path)
        except OSError as exc:
            if temp_name is not None:
                try:
                    os.unlink(temp_name)
                except OSError:
                    pass
            raise AuthorizationError("authorization store cannot be written") from exc

    def _load_audit(self) -> list[dict[str, Any]]:
        try:
            with self.audit_path.open("r", encoding="utf-8") as file:
                data = json.load(file)
        except FileNotFoundError:
            return []
        except (OSError, json.JSONDecodeError) as exc:
            raise AuthorizationError("authorization audit log cannot be read") from exc
        if (
            not isinstance(data, dict)
            or type(data.get("schema_version")) is not int
            or data.get("schema_version") != 1
            or not isinstance(data.get("events"), list)
            or any(not isinstance(event, dict) for event in data["events"])
        ):
            raise AuthorizationError("authorization audit log has an invalid schema")
        return data["events"]

    def _save(self, data: dict[str, Any]) -> None:
        self._write_json(
            self.path,
            {
                "schema_version": 1,
                "authorizations": data["authorizations"],
            },
        )

    def _save_audit(self, data: dict[str, Any]) -> None:
        self._write_json(
            self.audit_path,
            {"schema_version": 1, "events": data["audit"][-10000:]},
        )

    def _audit(
        self,
        data: dict[str, Any],
        action: str,
        *,
        authorization_id: str | None = None,
        target: str | None = None,
        actor: str | None = None,
        reason: str | None = None,
        request_id: str | None = None,
    ) -> None:
        event = {
            "at": _iso(self._now()),
            "action": action,
            "authorization_id": authorization_id,
            "target": target,
            "actor": actor,
            "reason": reason,
        }
        if request_id is not None:
            event["request_id"] = request_id
        data["audit"].append(event)
        data["audit"] = data["audit"][-10000:]

    def _now(self) -> datetime:
        now = self.clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise AuthorizationError("authorization clock must return a timezone-aware timestamp")
        return now.astimezone(timezone.utc)

    @staticmethod
    def _operator_name(operator: str) -> str:
        if not isinstance(operator, str):
            raise AuthorizationError("operator name must be a non-empty string")
        normalized = operator.strip()
        if (
            not normalized
            or len(normalized) > 128
            or any(ord(character) < 32 for character in normalized)
        ):
            raise AuthorizationError("operator name must be 1 to 128 printable characters")
        return normalized

    def create_local_authorization(
        self,
        target_url: str,
        *,
        ports: list[int],
        methods: list[str],
        operator: str,
        confirm_authority: bool,
        ttl_seconds: int = 3600,
    ) -> dict[str, Any]:
        authorizer = self._operator_name(operator)
        if confirm_authority is not True:
            raise AuthorizationError("an identified operator must confirm local authority")
        if (
            type(ttl_seconds) is not int
            or not 60 <= ttl_seconds <= MAX_AUTHORIZATION_SECONDS
        ):
            raise AuthorizationError("authorization lifetime must be 60 seconds to 24 hours")
        target = parse_local_target(target_url, self.resolver)
        if (
            not isinstance(ports, (list, tuple))
            or not ports
            or any(type(port) is not int or not 1 <= port <= 65535 for port in ports)
        ):
            raise AuthorizationError("explicit valid ports must include the target URL port")
        normalized_ports = sorted(set(ports))
        if target.port not in normalized_ports:
            raise AuthorizationError("explicit valid ports must include the target URL port")
        if (
            not isinstance(methods, (list, tuple))
            or not methods
            or any(not isinstance(method, str) for method in methods)
        ):
            raise AuthorizationError("testing methods are missing or unsupported")
        normalized_methods = sorted(set(methods))
        if not set(normalized_methods).issubset(ALLOWED_METHODS):
            raise AuthorizationError("testing methods are missing or unsupported")

        now = self._now()
        record = {
            "id": f"auth_{uuid.uuid4().hex}",
            "authorizer": authorizer,
            "authorization_basis": "local_operator_attestation",
            "target_origin": target.origin,
            "target_host": target.host,
            "resolved_addresses": list(target.addresses),
            "ports": normalized_ports,
            "methods": normalized_methods,
            "created_at": _iso(now),
            "expires_at": _iso(now + timedelta(seconds=ttl_seconds)),
            "status": "active",
            "revoked_at": None,
        }
        with _store_lock, _file_locks(self.audit_path):
            data = self._load()
            previous_authorizations = list(data["authorizations"])
            data["authorizations"].append(record)
            self._audit(
                data, "created", authorization_id=record["id"],
                target=target.origin, actor=record["authorizer"],
            )
            self._save(data)
            try:
                self._save_audit(data)
            except AuthorizationError as exc:
                data["authorizations"] = previous_authorizations
                try:
                    self._save(data)
                except AuthorizationError as rollback_error:
                    raise AuthorizationError(
                        "authorization audit could not be saved and grant rollback "
                        "failed; registry state may be partial"
                    ) from rollback_error
                raise AuthorizationError(
                    "authorization grant was rolled back because its audit event "
                    "could not be saved"
                ) from exc
        return record.copy()

    def revoke(
        self, authorization_id: str, *, operator: str, confirm: bool
    ) -> None:
        actor = self._operator_name(operator)
        if confirm is not True:
            raise AuthorizationError("an identified operator must confirm revocation")
        if not isinstance(authorization_id, str) or not authorization_id:
            raise AuthorizationError("authorization ID must be a non-empty string")
        with _store_lock, _file_locks(self.audit_path):
            data = self._load()
            record = next(
                (r for r in data["authorizations"] if r.get("id") == authorization_id),
                None,
            )
            if record is None:
                self._audit(
                    data, "denied", authorization_id=authorization_id,
                    actor=actor, reason="authorization not found",
                )
                self._save_audit(data)
                raise AuthorizationError("authorization not found")
            if record.get("status") != "revoked":
                record["status"] = "revoked"
                record["revoked_at"] = _iso(self.clock())
            self._audit(
                data, "revoked", authorization_id=authorization_id,
                target=record.get("target_origin"), actor=actor,
            )
            self._save(data)
            try:
                self._save_audit(data)
            except AuthorizationError as exc:
                raise AuthorizationError(
                    "authorization was revoked, but its audit event could not be saved"
                ) from exc

    def authorize_url(
        self,
        authorization_id: str | None,
        target_url: str,
        *,
        method: str,
        redirect: bool = False,
        request_id: str | None = None,
    ) -> AuthorizationDecision:
        if not isinstance(method, str) or method not in ALLOWED_METHODS:
            raise AuthorizationError("testing method is missing or unsupported")
        if type(redirect) is not bool:
            raise AuthorizationError("redirect flag must be a boolean")
        if request_id is not None and (
            not isinstance(request_id, str)
            or not _REQUEST_ID_RE.fullmatch(request_id)
        ):
            raise AuthorizationError("request ID is malformed")
        if authorization_id is not None and (
            not isinstance(authorization_id, str)
            or not _AUTHORIZATION_ID_RE.fullmatch(authorization_id)
        ):
            raise AuthorizationError("authorization ID is malformed")
        target_origin: str | None = None
        record: dict[str, Any] | None = None
        try:
            target = parse_local_target(target_url, self.resolver)
            target_origin = target.origin
        except AuthorizationError as exc:
            target = None
            parse_error = str(exc)
        else:
            parse_error = ""

        with _store_lock, _file_locks(self.audit_path):
            data = self._load()
            if authorization_id:
                record = next(
                    (r for r in data["authorizations"] if r.get("id") == authorization_id),
                    None,
                )

            reason = ""
            if target is None:
                reason = parse_error
            elif not authorization_id:
                reason = "authorization ID is required"
            elif record is None:
                reason = "authorization not found"
            elif record.get("status") != "active":
                reason = "authorization is revoked or inactive"
            else:
                stored_target: ParsedTarget | None = None
                canonical_addresses: tuple[str, ...] = ()
                try:
                    now = self._now()
                    created_at = _parse_utc(record["created_at"])
                    expires_at = _parse_utc(record["expires_at"])
                    recorded_addresses = record["resolved_addresses"]
                    canonical_addresses = _validated_loopback_addresses(
                        recorded_addresses
                    )
                    stored_target = parse_local_target(
                        record["target_origin"],
                        resolver=lambda _host: canonical_addresses,
                    )
                except AuthorizationError:
                    created_at = None
                    expires_at = None
                    reason = "authorization scope data is malformed"
                except (KeyError, TypeError, ValueError):
                    created_at = None
                    expires_at = None
                    reason = "authorization timestamps are invalid"
                if not reason and (
                    not isinstance(record.get("authorizer"), str)
                    or not record["authorizer"].strip()
                    or len(record["authorizer"]) > 128
                    or any(ord(char) < 32 for char in record["authorizer"])
                    or record.get("authorization_basis") != "local_operator_attestation"
                    or not _AUTHORIZATION_ID_RE.fullmatch(record["id"])
                    or not isinstance(record.get("target_origin"), str)
                    or stored_target is None
                    or stored_target.origin != record.get("target_origin")
                    or record.get("target_host") != stored_target.host
                    or not isinstance(record.get("ports"), list)
                    or not record["ports"]
                    or any(
                        type(port) is not int or not 1 <= port <= 65535
                        for port in record["ports"]
                    )
                    or len(record["ports"]) != len(set(record["ports"]))
                    or stored_target.port not in record["ports"]
                    or not isinstance(record.get("methods"), list)
                    or not record["methods"]
                    or any(
                        not isinstance(item, str) or item not in ALLOWED_METHODS
                        for item in record["methods"]
                    )
                    or len(record["methods"]) != len(set(record["methods"]))
                    or not isinstance(record.get("resolved_addresses"), list)
                    or list(canonical_addresses) != record["resolved_addresses"]
                    or stored_target.addresses != canonical_addresses
                    or record.get("revoked_at") is not None
                    or created_at is None
                    or expires_at is None
                    or created_at > now
                    or expires_at <= created_at
                    or expires_at - created_at > timedelta(
                        seconds=MAX_AUTHORIZATION_SECONDS
                    )
                ):
                    reason = "authorization scope data is malformed"
                if not reason and expires_at <= now:
                    self._audit(
                        data, "expired", authorization_id=authorization_id,
                        target=record.get("target_origin"),
                        reason="authorization expired or has invalid expiry",
                        request_id=request_id,
                    )
                    reason = reason or "authorization has expired"
                elif not reason and target.port not in record["ports"]:
                    reason = "target port is outside the authorized ports"
                elif not reason and method not in record["methods"]:
                    reason = "testing method is outside the authorized methods"
                elif not reason and record.get("target_origin") != target.origin:
                    reason = "target is outside the authorized origin"
                elif not reason and not any(
                    event.get("action") == "created"
                    and event.get("authorization_id") == authorization_id
                    and event.get("target") == record.get("target_origin")
                    for event in data["audit"]
                ):
                    reason = "authorization creation audit event is missing"
                elif not reason and list(target.addresses) != record.get("resolved_addresses"):
                    reason = "target DNS resolution changed"

            allowed = not reason and target is not None
            action = (
                "redirect_allowed" if redirect else "use"
            ) if allowed else (
                "redirect_denied" if redirect else "denied"
            )
            self._audit(
                data, action, authorization_id=authorization_id,
                target=target_origin, reason=reason or None, request_id=request_id,
            )
            self._save_audit(data)

        return AuthorizationDecision(
            allowed=allowed,
            authorization_id=authorization_id,
            target=target_origin,
            reason=reason or "authorized local target",
        )

    def audit_denial(
        self,
        *,
        authorization_id: str | None,
        tool: str,
        reason: str,
        request_id: str | None = None,
    ) -> None:
        if not isinstance(tool, str) or not tool:
            tool = "unknown"
        if request_id is not None and (
            not isinstance(request_id, str)
            or not _REQUEST_ID_RE.fullmatch(request_id)
        ):
            request_id = None
        safe_authorization_id = (
            authorization_id
            if isinstance(authorization_id, str)
            and _AUTHORIZATION_ID_RE.fullmatch(authorization_id)
            else None
        )
        with _store_lock, _file_locks(self.audit_path):
            data = self._load()
            self._audit(
                data,
                "denied",
                authorization_id=safe_authorization_id,
                actor=f"tool:{tool[:64]}",
                reason=reason[:256] if isinstance(reason, str) else "execution denied",
                request_id=request_id,
            )
            self._save_audit(data)

    def list_authorizations(self) -> list[dict[str, Any]]:
        with _store_lock, _file_locks(self.audit_path):
            return [record.copy() for record in self._load()["authorizations"]]
