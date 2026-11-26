from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .client import JevClient
from .hook import config_from_env, run
from .policy import evaluate

SETTINGS_SNIPPET = {
    "hooks": {
        "PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "jev-guard hook"}]}
        ]
    }
}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="jev-guard", description=__doc__)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    h = sub.add_parser("hook", help="run as a Claude Code PreToolUse hook (JSON on stdin)")
    h.add_argument("--offline", action="store_true", help="local rules only, no API calls")

    c = sub.add_parser("check", help="evaluate one command and print the decision")
    c.add_argument("command")
    c.add_argument("--offline", action="store_true")

    sub.add_parser("install", help="print the settings.json snippet to register the hook")

    args = p.parse_args(argv)
    if args.cmd == "hook":
        return run(sys.stdin, sys.stdout, offline=args.offline)
    if args.cmd == "check":
        client = None if args.offline else JevClient()
        d = evaluate(args.command, client, **config_from_env())
        print(json.dumps({"action": d.action, "reason": d.reason, "source": d.source}))
        return 0 if d.action == "pass" else 1
    print(json.dumps(SETTINGS_SNIPPET, indent=2))
    return 0
