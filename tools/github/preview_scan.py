"""Perform one pinned, read-only HTTPS header check on an attested preview."""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence
from urllib.parse import urlsplit

from authorize_target import TargetPolicyError, normalize_origin


class PreviewScanError(ValueError):
    """Raised when a preview cannot be checked safely."""


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    title: str


@dataclass(frozen=True)
class CheckResult:
    status_code: int
    findings: tuple[Finding, ...]


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that dials one prevalidated IP but verifies the host."""

    def __init__(self, host: str, port: int, connect_ip: str, timeout: float) -> None:
        super().__init__(
            host=host,
            port=port,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
        self._connect_ip = connect_ip

    def connect(self) -> None:
        raw_socket = socket.create_connection(
            (self._connect_ip, self.port),
            timeout=self.timeout,
        )
        try:
            self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)
        except (OSError, ssl.SSLError, ValueError):
            raw_socket.close()
            raise


Resolver = Callable[[str, int], Iterable[str]]
ConnectionFactory = Callable[[str, int, str, float], http.client.HTTPSConnection]
PreConnectCheck = Callable[[], None]


def _resolve_public_addresses(host: str, port: int) -> tuple[str, ...]:
    try:
        results = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise PreviewScanError("preview hostname did not resolve") from exc

    addresses: set[str] = set()
    try:
        for result in results:
            raw_address = result[4][0]
            if "%" in raw_address:
                raise PreviewScanError("preview returned a scoped IP address")
            address = ipaddress.ip_address(raw_address)
            if not address.is_global:
                raise PreviewScanError("preview resolved to a non-public IP address")
            addresses.add(address.compressed)
    except (IndexError, TypeError, ValueError) as exc:
        if isinstance(exc, PreviewScanError):
            raise
        raise PreviewScanError("preview hostname returned an invalid DNS answer") from exc

    if not addresses:
        raise PreviewScanError("preview hostname returned no IP addresses")
    return tuple(sorted(addresses))


def _header_findings(headers: Sequence[tuple[str, str]]) -> tuple[Finding, ...]:
    lowered: dict[str, list[str]] = {}
    for name, value in headers:
        lowered.setdefault(name.lower(), []).append(value.strip())
    findings: list[Finding] = []

    hsts_values = lowered.get("strict-transport-security", [])
    max_age = None
    if len(hsts_values) == 1:
        for directive in hsts_values[0].split(";"):
            name, separator, value = directive.strip().partition("=")
            age_value = value.strip()
            if (
                separator
                and name.strip().lower() == "max-age"
                and age_value.isdigit()
                and len(age_value) <= 12
            ):
                max_age = int(age_value)
                break
    if max_age is None or max_age <= 0:
        findings.append(Finding(
            "invalid-hsts",
            "medium",
            "Strict-Transport-Security is missing, duplicated, or lacks a positive max-age directive",
        ))
    csp_values = lowered.get("content-security-policy", [])
    csp = csp_values[0] if len(csp_values) == 1 else ""
    if not csp:
        findings.append(Finding(
            "missing-csp",
            "medium",
            "Content-Security-Policy header is missing, duplicated, or empty",
        ))
    if [value.lower() for value in lowered.get("x-content-type-options", [])] != ["nosniff"]:
        findings.append(Finding(
            "missing-nosniff",
            "low",
            "X-Content-Type-Options is missing, duplicated, or is not nosniff",
        ))
    referrer_values = lowered.get("referrer-policy", [])
    if len(referrer_values) != 1 or not referrer_values[0]:
        findings.append(Finding(
            "missing-referrer-policy",
            "low",
            "Referrer-Policy header is missing, duplicated, or empty",
        ))

    x_frame_values = [value.lower() for value in lowered.get("x-frame-options", [])]
    has_frame_ancestors = False
    if len(csp_values) == 1:
        for directive in csp.split(";"):
            parts = directive.strip().lower().split()
            if parts and parts[0] == "frame-ancestors":
                has_frame_ancestors = bool(parts[1:]) and all(
                    source in {"'none'", "'self'"} for source in parts[1:]
                )
                break
    restrictive_x_frame = (
        len(x_frame_values) == 1
        and x_frame_values[0] in {"deny", "sameorigin"}
    )
    if not restrictive_x_frame and not has_frame_ancestors:
        findings.append(Finding(
            "missing-frame-protection",
            "medium",
            "Neither a restrictive X-Frame-Options nor CSP frame-ancestors directive is present",
        ))

    for set_cookie in lowered.get("set-cookie", []):
        parts = [part.strip().lower() for part in set_cookie.split(";")]
        if not parts or "=" not in parts[0]:
            continue
        cookie_attributes: dict[str, list[str | None]] = {}
        for attribute in parts[1:]:
            name, separator, value = attribute.partition("=")
            cookie_attributes.setdefault(name.strip(), []).append(
                value.strip() if separator else None
            )
        secure_values = cookie_attributes.get("secure", [])
        if secure_values != [None]:
            findings.append(Finding(
                "cookie-missing-secure",
                "medium",
                "A cookie observed in the response is missing or has an invalid Secure attribute",
            ))
        http_only_values = cookie_attributes.get("httponly", [])
        if http_only_values != [None]:
            findings.append(Finding(
                "cookie-missing-httponly",
                "low",
                "A cookie observed in the response is missing or has an invalid HttpOnly attribute",
            ))
        same_site_values = cookie_attributes.get("samesite", [])
        same_site = same_site_values[0] if len(same_site_values) == 1 else None
        if same_site not in {"strict", "lax", "none"}:
            findings.append(Finding(
                "cookie-missing-samesite",
                "low",
                "A cookie observed in the response is missing, duplicated, or has an invalid SameSite attribute",
            ))
        elif same_site == "none" and secure_values != [None]:
            findings.append(Finding(
                "cookie-samesite-none-without-secure",
                "medium",
                "A SameSite=None cookie must also include Secure",
            ))

    return tuple(findings)


def check_preview_origin(
    origin: str,
    *,
    resolver: Resolver = _resolve_public_addresses,
    connection_factory: ConnectionFactory = PinnedHTTPSConnection,
    before_connect: PreConnectCheck | None = None,
    timeout: float = 5.0,
) -> CheckResult:
    """Make one HTTPS HEAD request to the exact origin; never follow redirects."""
    try:
        normalized = normalize_origin(origin)
    except TargetPolicyError as exc:
        raise PreviewScanError("preview origin is not a valid HTTPS origin") from exc

    parsed = urlsplit(normalized)
    host = parsed.hostname
    if host is None:
        raise PreviewScanError("preview origin has no hostname")
    port = parsed.port or 443

    try:
        literal_address = ipaddress.ip_address(host)
    except ValueError:
        literal_address = None
    if literal_address is not None and not literal_address.is_global:
        raise PreviewScanError("preview origin is not a public IP address")

    try:
        addresses = tuple(resolver(host, port))
    except PreviewScanError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        if isinstance(exc, PreviewScanError):
            raise
        raise PreviewScanError("preview DNS validation failed") from exc

    if not addresses:
        raise PreviewScanError("preview hostname returned no IP addresses")
    try:
        validated_addresses = []
        for value in addresses:
            if not isinstance(value, str) or "%" in value:
                raise PreviewScanError("preview hostname returned an invalid IP address")
            address = ipaddress.ip_address(value)
            if not address.is_global:
                raise PreviewScanError("preview resolved to a non-public IP address")
            validated_addresses.append(address.compressed)
    except (TypeError, ValueError) as exc:
        if isinstance(exc, PreviewScanError):
            raise
        raise PreviewScanError("preview hostname returned an invalid DNS answer") from exc
    if literal_address is not None and set(validated_addresses) != {literal_address.compressed}:
        raise PreviewScanError("preview IP address resolution did not match the literal origin")

    if before_connect is not None:
        before_connect()
    connect_ip = sorted(set(validated_addresses))[0]
    connection = connection_factory(host, port, connect_ip, timeout)
    try:
        connection.request(
            "HEAD",
            "/",
            headers={
                "Connection": "close",
                "User-Agent": "GregorForge-Preview-Check/1.0",
            },
        )
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise PreviewScanError("preview returned a redirect; redirects are never followed")
        if not 200 <= response.status < 300:
            raise PreviewScanError("preview did not return a successful HTTP status")
        response_headers = response.getheaders()
        if len(response_headers) > 64:
            raise PreviewScanError("preview returned too many response headers")
        if sum(len(name) + len(value) for name, value in response_headers) > 16 * 1024:
            raise PreviewScanError("preview response headers exceeded the size limit")
        return CheckResult(response.status, _header_findings(response_headers))
    except PreviewScanError:
        raise
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise PreviewScanError("HTTPS request to the attested preview failed") from exc
    finally:
        connection.close()
