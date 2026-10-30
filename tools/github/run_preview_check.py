#!/usr/bin/env python3
"""Verify a trusted preview attestation and perform one read-only HTTPS check."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import http.client
import json
import os
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from authorize_target import TargetPolicyError, authorize_target, normalize_origin
from preview_scan import (
    CheckResult,
    PinnedHTTPSConnection,
    PreviewScanError,
    _resolve_public_addresses,
    check_preview_origin,
)


MAX_RESPONSE_BYTES = 16 * 1024
MAX_ATTESTATION_TTL = dt.timedelta(minutes=15)
SIGNED_FIELDS = (
    "expires_at",
    "head_sha",
    "origin",
    "preview_id",
    "pull_request",
    "repository",
    "status",
)


class PreviewCheckError(ValueError):
    """Raised when the trusted PR-preview scan preconditions are not met."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, _request, _response, _code, _message, _headers, _new_url):
        return None


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, request: urllib.request.Request):
        return self.do_open(self._make_connection, request)

    @staticmethod
    def _make_connection(host: str, timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
        try:
            parsed = urllib.parse.urlsplit(f"//{host}")
            hostname = parsed.hostname
            port = parsed.port or 443
        except ValueError as exc:
            raise PreviewCheckError("trusted HTTPS endpoint authority is malformed") from exc
        if not hostname:
            raise PreviewCheckError("trusted HTTPS endpoint has no hostname")
        addresses = _resolve_public_addresses(hostname, port)
        actual_timeout = 8.0 if timeout is socket._GLOBAL_DEFAULT_TIMEOUT else timeout
        return PinnedHTTPSConnection(hostname, port, addresses[0], actual_timeout)


def _https_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _PinnedHTTPSHandler(context=ssl.create_default_context()),
        _NoRedirect(),
    )


def _read_json_response(
    opener: urllib.request.OpenerDirector,
    request: urllib.request.Request,
    *,
    expected_status: tuple[int, ...] = (200,),
) -> dict[str, Any]:
    try:
        with opener.open(request, timeout=8) as response:
            if response.status not in expected_status:
                raise PreviewCheckError("trusted API returned an unsuccessful status")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except PreviewCheckError:
        raise
    except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException) as exc:
        raise PreviewCheckError("trusted API request failed") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise PreviewCheckError("trusted API response exceeded the size limit")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PreviewCheckError("trusted API returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise PreviewCheckError("trusted API response must be a JSON object")
    return value


def _validated_repository(value: str) -> tuple[str, str]:
    match = re.fullmatch(r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", value or "")
    if (
        match is None
        or match.group(1) in {".", ".."}
        or match.group(2) in {".", ".."}
        or len(match.group(1)) > 100
        or len(match.group(2)) > 100
    ):
        raise PreviewCheckError("repository identity is malformed")
    return match.group(1), match.group(2)


def _github_pr(opener: urllib.request.OpenerDirector, repository: str, number: int) -> dict[str, Any]:
    owner, repo = _validated_repository(repository)
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise PreviewCheckError("GitHub read token is not configured")
    request = urllib.request.Request(
        f"https://api.github.com/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}/pulls/{number}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "GregorForge-Preview-Check/1.0",
        },
    )
    return _read_json_response(opener, request)


def _provider_endpoint(value: str, repository: str, number: int, head_sha: str) -> str:
    try:
        base = normalize_origin(value)
    except TargetPolicyError as exc:
        raise PreviewCheckError("preview provider must be a configured HTTPS origin") from exc
    owner, repo = _validated_repository(repository)
    endpoint = (
        f"{base}/v1/previews/github/{urllib.parse.quote(owner)}/"
        f"{urllib.parse.quote(repo)}/{number}"
    )
    return f"{endpoint}?head_sha={urllib.parse.quote(head_sha)}"


def _fetch_attestation(
    opener: urllib.request.OpenerDirector,
    endpoint: str,
    token: str,
) -> dict[str, Any]:
    request = urllib.request.Request(
        endpoint,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "GregorForge-Preview-Check/1.0",
        },
    )
    return _read_json_response(opener, request)


def _create_check_run(
    opener: urllib.request.OpenerDirector,
    repository: str,
    pull_request: int,
    head_sha: str,
) -> int:
    owner, repo = _validated_repository(repository)
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise PreviewCheckError("GitHub check-write token is not configured")
    endpoint = (
        f"https://api.github.com/repos/{urllib.parse.quote(owner)}/"
        f"{urllib.parse.quote(repo)}/check-runs"
    )
    payload = {
        "name": "GregorForge authorized preview",
        "head_sha": head_sha,
        "status": "in_progress",
        "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "external_id": f"pull-request-{pull_request}",
        "output": {
            "title": "Checking an authorized preview",
            "summary": (
                "A protected, read-only preview check is running. It sends one "
                "HTTPS HEAD request and does not follow redirects."
            ),
        },
    }
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "GregorForge-Preview-Check/1.0",
        },
        method="POST",
    )
    response = _read_json_response(opener, request, expected_status=(201,))
    check_run_id = response.get("id")
    if type(check_run_id) is not int or check_run_id <= 0:
        raise PreviewCheckError("GitHub did not return a valid check-run ID")
    return check_run_id


def _complete_check_run(
    opener: urllib.request.OpenerDirector,
    repository: str,
    check_run_id: int,
    *,
    result: CheckResult | None = None,
    error: str | None = None,
) -> None:
    owner, repo = _validated_repository(repository)
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise PreviewCheckError("GitHub check-write token is not configured")
    if error is not None:
        conclusion = "failure"
        title = "Preview check stopped safely"
        summary = f"The check did not reach a scan result: {error}"
    elif result is not None and result.findings:
        conclusion = "failure"
        title = f"{len(result.findings)} security-header finding(s)"
        summary = "\n".join(
            f"- **{finding.severity.upper()}** `{finding.code}` — {finding.title}"
            for finding in result.findings
        )
    else:
        conclusion = "success"
        title = "No configured security-header gaps"
        summary = "The authorized preview returned the required configured security headers."
    payload = {
        "status": "completed",
        "conclusion": conclusion,
        "completed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "output": {
            "title": title,
            "summary": (
                f"{summary}\n\nOne HTTPS `HEAD /` request; no redirects, response "
                "bodies, or target URL are included in this check."
            ),
        },
    }
    request = urllib.request.Request(
        f"https://api.github.com/repos/{urllib.parse.quote(owner)}/"
        f"{urllib.parse.quote(repo)}/check-runs/{check_run_id}",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "GregorForge-Preview-Check/1.0",
        },
        method="PATCH",
    )
    _read_json_response(opener, request)


def _canonical_signed_payload(attestation: dict[str, Any]) -> bytes:
    payload = {field: attestation[field] for field in SIGNED_FIELDS}
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def verify_attestation(
    attestation: dict[str, Any],
    *,
    repository: str,
    pull_request: int,
    head_sha: str,
    signing_key: str,
    authorized_targets: str,
    now: dt.datetime | None = None,
) -> str:
    expected_keys = set(SIGNED_FIELDS) | {"signature"}
    if set(attestation) != expected_keys:
        raise PreviewCheckError("preview attestation has an unexpected shape")
    if len(signing_key.encode("utf-8")) < 32:
        raise PreviewCheckError("preview attestation signing key must be at least 32 bytes")
    if attestation["repository"] != repository:
        raise PreviewCheckError("preview attestation repository does not match")
    if type(attestation["pull_request"]) is not int or attestation["pull_request"] != pull_request:
        raise PreviewCheckError("preview attestation pull request does not match")
    if attestation["head_sha"] != head_sha:
        raise PreviewCheckError("preview attestation commit does not match the current PR head")
    if attestation["status"] != "ready":
        raise PreviewCheckError("preview provider has not marked the preview ready")
    if not isinstance(attestation["preview_id"], str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", attestation["preview_id"]
    ):
        raise PreviewCheckError("preview identifier is malformed")
    if not isinstance(attestation["expires_at"], str):
        raise PreviewCheckError("preview attestation expiry is malformed")

    try:
        expires_at = dt.datetime.fromisoformat(attestation["expires_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise PreviewCheckError("preview attestation expiry is malformed") from exc
    if expires_at.tzinfo is None:
        raise PreviewCheckError("preview attestation expiry must include a timezone")
    current_time = now or dt.datetime.now(dt.timezone.utc)
    if current_time.tzinfo is None:
        raise PreviewCheckError("verification time must include a timezone")
    expiry_utc = expires_at.astimezone(dt.timezone.utc)
    current_utc = current_time.astimezone(dt.timezone.utc)
    if expiry_utc <= current_utc or expiry_utc > current_utc + MAX_ATTESTATION_TTL:
        raise PreviewCheckError("preview attestation is expired or has an excessive lifetime")

    signature = attestation["signature"]
    if not isinstance(signature, str) or re.fullmatch(r"[0-9a-f]{64}", signature) is None:
        raise PreviewCheckError("preview attestation signature is malformed")
    expected_signature = hmac.new(
        signing_key.encode("utf-8"),
        _canonical_signed_payload(attestation),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        raise PreviewCheckError("preview attestation signature is invalid")

    try:
        return authorize_target(attestation["origin"], authorized_targets)
    except TargetPolicyError as exc:
        raise PreviewCheckError("attested preview origin is not exactly allowlisted") from exc


def _write_summary(
    *,
    pull_request: int,
    result: CheckResult | None = None,
    error: str | None = None,
) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    lines = [
        "## GregorForge authorized preview check",
        "",
        f"- Pull request: `#{pull_request}`",
        "- Check performed: one HTTPS `HEAD /` request",
        "- Redirects followed: no",
        "- Request/response bodies retained: no",
    ]
    if error:
        lines.extend(["", f"**Check stopped safely:** {error}"])
    elif result is not None:
        lines.extend(["", f"- HTTP status: `{result.status_code}`"])
        if result.findings:
            lines.extend(["", "### Findings"])
            lines.extend(
                f"- **{finding.severity.upper()}** `{finding.code}` — {finding.title}"
                for finding in result.findings
            )
        else:
            lines.extend(["", "No configured security-header gaps were detected."])
    with Path(summary_path).open("a", encoding="utf-8") as summary:
        summary.write("\n".join(lines) + "\n")


def run_check(pull_request: int) -> CheckResult:
    if pull_request <= 0:
        raise PreviewCheckError("pull request number must be positive")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    _validated_repository(repository)
    authorized_targets = os.environ.get("GREGORFORGE_AUTHORIZED_TARGETS", "")
    provider_url = os.environ.get("GREGORFORGE_PREVIEW_PROVIDER_URL", "")
    provider_token = os.environ.get("GREGORFORGE_PREVIEW_PROVIDER_TOKEN", "")
    signing_key = os.environ.get("GREGORFORGE_PREVIEW_ATTESTATION_KEY", "")
    if not all((authorized_targets, provider_url, provider_token, signing_key)):
        raise PreviewCheckError("preview provider and authorization configuration is incomplete")

    opener = _https_opener()
    pr_data = _github_pr(opener, repository, pull_request)
    if (
        pr_data.get("number") != pull_request
        or pr_data.get("state") != "open"
        or pr_data.get("draft") is not False
    ):
        raise PreviewCheckError("pull request must be open and ready for review")
    base_data = pr_data.get("base")
    head_data = pr_data.get("head")
    base_repo_data = base_data.get("repo") if isinstance(base_data, dict) else None
    base_ref = base_data.get("ref") if isinstance(base_data, dict) else None
    base_repository = (
        base_repo_data.get("full_name") if isinstance(base_repo_data, dict) else None
    )
    head_sha = head_data.get("sha") if isinstance(head_data, dict) else None
    if base_ref != "main":
        raise PreviewCheckError("pull request must target the protected main branch")
    if not isinstance(base_repository, str) or base_repository.lower() != repository.lower():
        raise PreviewCheckError("pull request base repository does not match")
    if not isinstance(head_sha, str) or re.fullmatch(r"[0-9a-fA-F]{40,64}", head_sha) is None:
        raise PreviewCheckError("pull request head commit is malformed")

    check_run_id = _create_check_run(opener, repository, pull_request, head_sha)
    try:
        result = _run_attested_preview_check(
            opener=opener,
            repository=repository,
            pull_request=pull_request,
            head_sha=head_sha,
            authorized_targets=authorized_targets,
            provider_url=provider_url,
            provider_token=provider_token,
            signing_key=signing_key,
        )
    except (PreviewCheckError, PreviewScanError, OSError, ssl.SSLError) as exc:
        safe_error = (
            str(exc)
            if isinstance(exc, (PreviewCheckError, PreviewScanError))
            else "a required trusted network operation failed"
        )
        _complete_check_run(
            opener,
            repository,
            check_run_id,
            error=safe_error,
        )
        raise
    _complete_check_run(opener, repository, check_run_id, result=result)
    return result


def _run_attested_preview_check(
    *,
    opener: urllib.request.OpenerDirector,
    repository: str,
    pull_request: int,
    head_sha: str,
    authorized_targets: str,
    provider_url: str,
    provider_token: str,
    signing_key: str,
) -> CheckResult:
    endpoint = _provider_endpoint(provider_url, repository, pull_request, head_sha)
    attestation = _fetch_attestation(opener, endpoint, provider_token)
    origin = verify_attestation(
        attestation,
        repository=repository,
        pull_request=pull_request,
        head_sha=head_sha,
        signing_key=signing_key,
        authorized_targets=authorized_targets,
    )
    refreshed_pr = _github_pr(opener, repository, pull_request)
    refreshed_head = refreshed_pr.get("head")
    refreshed_base = refreshed_pr.get("base")
    refreshed_base_repo = (
        refreshed_base.get("repo") if isinstance(refreshed_base, dict) else None
    )
    refreshed_base_repository = (
        refreshed_base_repo.get("full_name")
        if isinstance(refreshed_base_repo, dict)
        else None
    )
    if (
        refreshed_pr.get("number") != pull_request
        or refreshed_pr.get("state") != "open"
        or refreshed_pr.get("draft") is not False
        or not isinstance(refreshed_base, dict)
        or refreshed_base.get("ref") != "main"
        or not isinstance(refreshed_base_repository, str)
        or refreshed_base_repository.lower() != repository.lower()
        or not isinstance(refreshed_head, dict)
        or refreshed_head.get("sha") != head_sha
    ):
        raise PreviewCheckError("pull request changed during preview authorization")
    origin = verify_attestation(
        attestation,
        repository=repository,
        pull_request=pull_request,
        head_sha=head_sha,
        signing_key=signing_key,
        authorized_targets=authorized_targets,
    )
    def revalidate_before_connect() -> None:
        verify_attestation(
            attestation,
            repository=repository,
            pull_request=pull_request,
            head_sha=head_sha,
            signing_key=signing_key,
            authorized_targets=authorized_targets,
        )

    return check_preview_origin(origin, before_connect=revalidate_before_connect)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pull-request", required=True, type=int)
    args = parser.parse_args()
    try:
        result = run_check(args.pull_request)
    except (PreviewCheckError, PreviewScanError, OSError, ssl.SSLError) as exc:
        safe_error = str(exc) if isinstance(exc, (PreviewCheckError, PreviewScanError)) else "required trusted network operation failed"
        print(f"Preview check stopped safely: {safe_error}", file=sys.stderr)
        try:
            _write_summary(pull_request=args.pull_request, error=safe_error)
        except OSError:
            print("Unable to write the GitHub Actions summary.", file=sys.stderr)
        return 2

    try:
        _write_summary(pull_request=args.pull_request, result=result)
    except OSError:
        print("Unable to write the GitHub Actions summary.", file=sys.stderr)
        return 2

    if result.findings:
        print(f"Preview check completed with {len(result.findings)} security-header finding(s).")
        return 1
    print("Preview check completed with no configured security-header gaps.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
