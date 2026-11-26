"""Decision policy: local rules first, then Jev. This hook never auto-approves."""

from __future__ import annotations

from dataclasses import dataclass

from .client import JevClient, JevError
from .rules import prefilter

QUESTIONS: dict[str, dict] = {
    "risk": {
        "type": "choice",
        "instructions": "What happens if this shell command is run?",
        "criteria": {
            "read_only": {"what": "Only reads, lists or inspects; changes nothing."},
            "reversible": {"what": "Changes local files or state in a way that is easy to undo."},
            "destructive": {
                "what": "Deletes data, rewrites git history, or changes remote systems.",
                "not_for": "Ordinary file edits inside a project directory.",
            },
        },
    },
    "secrets": {
        "type": "noul",
        "instructions": "Does this command read, print, or send credentials, tokens, or private keys?",
        "criteria": {
            "true": {"what": "Touches .env files, ssh keys, API tokens, or cloud credentials."},
            "false": {"what": "Does not touch credentials."},
        },
    },
}


@dataclass(frozen=True)
class Decision:
    action: str  # "pass" (no opinion, normal permissions apply), "ask", or "deny"
    reason: str
    source: str  # "rules", "jev", or "fallback"


def _parse(answers: dict) -> tuple[str, float, float]:
    try:
        risk = answers["risk"]
        choice, confidence = risk["choice"], float(risk["confidence"])
        secrets = float(answers["secrets"]["noul"])
    except (KeyError, TypeError, ValueError) as exc:
        raise JevError(f"unexpected answer shape: {exc!r}") from exc
    if not isinstance(choice, str):
        raise JevError("risk.choice is not a string")
    return choice, confidence, secrets


def evaluate(
    command: str,
    client: JevClient | None,
    threshold: float = 0.8,
    secrets_threshold: float = 0.5,
    deny_destructive: bool = False,
    fail: str = "pass",
) -> Decision:
    """Decide what to do with a Bash command. `client=None` means offline (rules only)."""
    verdict = prefilter(command)
    if verdict:
        return Decision(verdict.action, verdict.reason, "rules")
    if client is None:
        return Decision("pass", "offline mode: no model consulted", "rules")

    try:
        choice, confidence, secrets = _parse(client.decide({"shell_command": command}, QUESTIONS))
    except JevError as exc:
        return Decision(fail, f"Jev unavailable ({exc}); using fallback '{fail}'", "fallback")

    if choice == "destructive":
        action = "deny" if deny_destructive else "ask"
        return Decision(action, f"Jev: destructive ({confidence:.0%} confident)", "jev")
    if confidence < threshold:
        return Decision("ask", f"Jev unsure: {choice} at {confidence:.0%} (< {threshold:.0%})", "jev")
    if secrets >= secrets_threshold:
        return Decision("ask", f"Jev: may touch credentials (p={secrets:.2f})", "jev")
    return Decision("pass", f"Jev: {choice} ({confidence:.0%} confident)", "jev")
