# jev-guard

A [Claude Code](https://claude.com/claude-code) `PreToolUse` hook that uses
[TypeSafe's Jev](https://typesafe.ai) (a fast, cheap "System One" decision model) to
decide whether a Bash command Claude wants to run needs your confirmation.

**Claude writes and reasons. Jev decides. Code enforces.**

Zero runtime dependencies (stdlib only). Python 3.9+.

## How it works

```
Claude wants to run a Bash command
        │
        ▼
  local rules ──► obvious disaster (rm -rf /, curl | sh, force-push to main) → DENY
        │         obviously read-only (ls, git status, cat)                  → no opinion, no API call
        ▼
  Jev (≈ one call, two questions run in parallel)
     • risk: read_only | reversible | destructive   (+ confidence)
     • secrets: P(command touches credentials)
        │
        ▼
  destructive, low confidence, or likely secrets → ASK you
  otherwise → no opinion (normal Claude Code permissions apply)
```

The hook **never auto-approves** anything. It can only add a confirmation prompt (or
deny), so it is a safety net, not a security boundary.

If Jev is unreachable, the hook falls back to normal permissions (or to `ask` with
`JEV_GUARD_FAIL=ask`). It never breaks your session.

## Install

```bash
pip install git+https://github.com/ashishdhillon/jev-guard
export TYPESAFE_API_KEY="..."        # from console.typesafe.ai; keep it out of repos
jev-guard install                    # prints the settings.json snippet
```

Add the snippet to `~/.claude/settings.json` (see `examples/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "jev-guard hook" }] }
    ]
  }
}
```

## Try it without Claude Code

```bash
jev-guard check "ls -la" --offline               # pass (read-only, no API call)
jev-guard check "rm -rf /" --offline             # deny (local rule)
jev-guard check "git reset --hard HEAD~5"        # asks Jev (needs TYPESAFE_API_KEY)
```

## Configuration (env vars)

| Variable | Default | Meaning |
|---|---|---|
| `TYPESAFE_API_KEY` | none | API key (required for model calls) |
| `JEV_GUARD_MODEL` | `jev-latest` | Pin a version (e.g. `jev-1.13.0`) so thresholds don't drift |
| `JEV_GUARD_THRESHOLD` | `0.8` | Ask when risk confidence is below this |
| `JEV_GUARD_DENY_DESTRUCTIVE` | off | `1` = deny destructive commands instead of asking |
| `JEV_GUARD_FAIL` | `pass` | Behavior if Jev is down: `pass` or `ask` |
| `JEV_GUARD_LOG` | off | Path to a JSONL audit log (command truncated to 200 chars) |

## Privacy

Commands that reach Jev are sent to TypeSafe's API. Commands handled by local rules
are not. Use `--offline` on the hook (`jev-guard hook --offline`) for rules only.

## Develop

```bash
pip install -e ".[dev]" && pytest -q
```

Tests use a fake transport, so no network or key is needed.

## Status / caveats

- Request and response shapes follow TypeSafe's public REST docs (`POST /v1/systemone`,
  question types `choice` and `noul`). Verify against the current docs before relying on it,
  and run a few real commands to calibrate the thresholds.
- Jev's accuracy figures are vendor-reported; treat this as a convenience layer, not a guarantee.

## License

MIT
