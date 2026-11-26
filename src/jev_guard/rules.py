"""Cheap local prefilter: obvious cases never need a model call."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

# (pattern, reason) -> always blocked, no API call
DENY_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\brm\s+(-\w*\s+)*-\w*[rR]\w*[fF]?\w*\s+(/|~|\$HOME)(\s|$|\*)"), "recursive delete of / or home"),
    (re.compile(r":\(\)\s*\{.*\};\s*:"), "fork bomb"),
    (re.compile(r"\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z)?sh\b"), "pipes a download into a shell"),
    (re.compile(r"\bmkfs(\.\w+)?\b"), "formats a filesystem"),
    (re.compile(r"\bdd\b.*\bof=/dev/(sd|nvme|disk|hd)"), "writes directly to a disk device"),
    (re.compile(r"git\s+push\b(?=.*(--force\b|\s-f\b))(?=.*\b(main|master)\b)"), "force-push to main/master"),
    (re.compile(r"\bchmod\s+-R\s+0?777\s+/(\s|$)"), "world-writable chmod on /"),
]

SAFE_COMMANDS = {
    "ls", "pwd", "cat", "head", "tail", "wc", "grep", "rg", "which", "whoami",
    "date", "uname", "tree", "stat", "file", "du", "df",
}
SAFE_GIT = {"status", "log", "diff", "show", "branch", "remote", "rev-parse"}
SHELL_META = re.compile(r"[;&|<>`]|\$\(")


@dataclass(frozen=True)
class Verdict:
    action: str  # "deny" or "pass"
    reason: str


def prefilter(command: str) -> Verdict | None:
    """Return a Verdict for obvious cases, or None to defer to Jev."""
    for pattern, reason in DENY_PATTERNS:
        if pattern.search(command):
            return Verdict("deny", f"blocked locally: {reason}")
    if SHELL_META.search(command):
        return None
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    if not tokens:
        return Verdict("pass", "empty command")
    head = tokens[0]
    if head in SAFE_COMMANDS:
        return Verdict("pass", f"read-only command: {head}")
    if head == "git" and len(tokens) > 1 and tokens[1] in SAFE_GIT:
        return Verdict("pass", f"read-only git: {tokens[1]}")
    return None
