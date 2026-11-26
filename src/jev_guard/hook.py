"""Claude Code PreToolUse hook entry point (reads event JSON on stdin)."""

from __future__ import annotations

import json
import os
import sys
import time
from typing import TextIO

from .client import JevClient
from .policy import Decision, evaluate


def config_from_env() -> dict:
    return {
        "threshold": float(os.environ.get("JEV_GUARD_THRESHOLD", "0.8")),
        "deny_destructive": os.environ.get("JEV_GUARD_DENY_DESTRUCTIVE") == "1",
        "fail": os.environ.get("JEV_GUARD_FAIL", "pass"),  # "pass" or "ask"
    }


def _log(command: str, decision: Decision, model: str | None) -> None:
    path = os.environ.get("JEV_GUARD_LOG")
    if not path:
        return
    entry = {
        "ts": time.time(),
        "action": decision.action,
        "source": decision.source,
        "reason": decision.reason,
        "model": model,
        "command": command[:200],
    }
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


def run(stdin: TextIO, stdout: TextIO, client: JevClient | None = None, offline: bool = False) -> int:
    try:
        event = json.load(stdin)
    except json.JSONDecodeError:
        return 0  # never break the session on bad input
    if event.get("tool_name") != "Bash":
        return 0
    command = (event.get("tool_input") or {}).get("command", "")
    if client is None and not offline:
        client = JevClient(model=os.environ.get("JEV_GUARD_MODEL", "jev-latest"))
    decision = evaluate(command, None if offline else client, **config_from_env())
    _log(command, decision, getattr(client, "last_model", None))
    if decision.action in ("ask", "deny"):
        stdout.write(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": decision.action,
                        "permissionDecisionReason": decision.reason,
                    }
                }
            )
        )
    return 0


def main() -> int:
    return run(sys.stdin, sys.stdout)
