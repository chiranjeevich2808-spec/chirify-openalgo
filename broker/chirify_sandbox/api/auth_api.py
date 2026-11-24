"""Authentication hook for Chirify Analyzer Sandbox (no external broker login required)."""

from __future__ import annotations

import secrets
from typing import Any


def authenticate_broker(*args: Any, **kwargs: Any) -> tuple[str | None, str | None]:
    """Return a synthetic sandbox session token tuple ``(auth_token, error_message)``."""
    return f"chirify_sandbox_{secrets.token_hex(16)}", None
