"""Minimal stdlib client for the Jev (TypeSafe "System One") REST endpoint."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Callable

ENDPOINT = "https://api.typesafe.ai/v1/systemone"

# transport(url, headers, body, timeout) -> parsed JSON response
Transport = Callable[[str, dict, dict, float], dict]


class JevError(RuntimeError):
    """Raised when Jev cannot be reached or returns something unusable."""


def _http_post(url: str, headers: dict, body: dict, timeout: float) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise JevError(f"HTTP {exc.code} from Jev") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise JevError(f"Jev request failed: {exc}") from exc


class JevClient:
    def __init__(
        self,
        api_key: str | None = None,
        model: str = "jev-latest",
        endpoint: str = ENDPOINT,
        timeout: float = 5.0,
        transport: Transport | None = None,
    ) -> None:
        self.api_key = api_key or os.environ.get("TYPESAFE_API_KEY")
        self.model = model
        self.endpoint = endpoint
        self.timeout = timeout
        self._transport = transport or _http_post
        self.last_model: str | None = None  # versioned id reported by the API

    def decide(self, state: Any, questions: dict[str, dict]) -> dict[str, dict]:
        """Ask Jev named questions about `state`; returns the `answers` mapping."""
        if not self.api_key:
            raise JevError("TYPESAFE_API_KEY is not set")
        headers = {
            "content-type": "application/json",
            "authorization": f"Bearer {self.api_key}",
            "user-agent": "jev-guard/0.1",
        }
        body = {"model": self.model, "state": state, "questions": questions}
        data = self._transport(self.endpoint, headers, body, self.timeout)
        answers = data.get("answers") if isinstance(data, dict) else None
        if not isinstance(answers, dict):
            raise JevError("response has no 'answers' object")
        self.last_model = data.get("model")
        return answers
