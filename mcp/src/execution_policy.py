"""Fail-closed command policy for diagnostic-only deployments."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Sequence

from src.tools.core.allowlist import EXECUTOR_ALLOWED_TOOLS


_SHELL_SYNTAX = re.compile(r"[;&|<>`$()\r\n\0]")
_VERSION_FLAGS = frozenset({"--version", "-version", "version"})
VERSION_DIAGNOSTIC_TOOLS = frozenset({"naabu", "nuclei", "httpx", "subfinder"})
_DISABLED_MESSAGE = (
    "Active tool execution is disabled. This deployment permits only read-only "
    "diagnostics until target authorization, redirect checks, and worker network "
    "isolation are enforced."
)


@dataclass(frozen=True)
class CommandDecision:
    allowed: bool
    argv: tuple[str, ...]
    reason: str


def parse_command(command: str | Sequence[str]) -> tuple[str, ...]:
    if isinstance(command, str):
        if _SHELL_SYNTAX.search(command):
            raise ValueError("shell operators and shell expansion are not accepted")
        try:
            argv = tuple(shlex.split(command, posix=True))
        except ValueError as exc:
            raise ValueError("command arguments are malformed") from exc
    elif isinstance(command, (list, tuple)):
        if any(not isinstance(arg, str) or not arg for arg in command):
            raise ValueError("command arguments must be non-empty strings")
        argv = tuple(command)
    else:
        raise ValueError("command must be a string or an argument sequence")
    if not argv:
        raise ValueError("command is empty")
    if any("\0" in arg for arg in argv):
        raise ValueError("NUL bytes are not permitted in command arguments")
    return argv


def evaluate_command(
    command: str | Sequence[str],
    *,
    workdir: str | None = None,
    environment: object | None = None,
) -> CommandDecision:
    try:
        argv = parse_command(command)
    except ValueError as exc:
        return CommandDecision(False, (), str(exc))

    if workdir is not None or environment is not None:
        return CommandDecision(
            False,
            argv,
            "diagnostic execution does not accept workdir or environment overrides",
        )

    if "/" in argv[0] or "\\" in argv[0]:
        return CommandDecision(False, argv, "executable paths are not permitted")

    executable = argv[0]
    args = argv[1:]
    if executable in {"bash", "sh", "dash", "zsh", "env", "python", "python3"}:
        return CommandDecision(False, argv, "shell and interpreter execution is disabled")
    if executable == "which":
        if len(args) == 1 and args[0] in EXECUTOR_ALLOWED_TOOLS:
            return CommandDecision(True, argv, "read-only executable lookup")
        return CommandDecision(False, argv, "only one allowlisted executable may be queried")
    if executable == "df" and args in (("-h",), ("-h", "/opt/gregorforge/out")):
        return CommandDecision(True, argv, "read-only disk diagnostic")
    if executable == "free" and args == ("-h",):
        return CommandDecision(True, argv, "read-only memory diagnostic")
    if (
        executable in VERSION_DIAGNOSTIC_TOOLS
        and executable in EXECUTOR_ALLOWED_TOOLS
        and len(args) == 1
        and args[0] in _VERSION_FLAGS
    ):
        return CommandDecision(True, argv, "read-only version diagnostic")
    return CommandDecision(False, argv, _DISABLED_MESSAGE)
