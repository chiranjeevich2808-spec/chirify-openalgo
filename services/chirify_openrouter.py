"""Regional OpenRouter configuration builder for Chirify / OpenAlgo `/agent`.

Implements OpenRouter's November 2026 regional data-residency routing and
workspace API-key isolation rules on top of :mod:`services.agent.providers`:

- ``EU`` residency -> ``api_base="https://eu.openrouter.ai/api/v1"``
  (rejects keys prefixed or tagged for ``US`` workspace).
- ``US`` residency -> ``api_base="https://us.openrouter.ai/api/v1"``
  (rejects keys prefixed or tagged for ``EU`` workspace).
- ``IN`` / ``GLOBAL`` residency -> ``api_base="https://openrouter.ai/api/v1"``
  (rejects workspace-locked ``EU`` or ``US`` keys).

Builds kwargs directly via :func:`services.agent.providers.litellm_kwargs` with
``provider_kind="openai_compatible"``, ensuring ``api_base`` (never ``base_url``)
and ``extra_headers={"HTTP-Referer": "https://chirify.io", "X-Title": "Chirify"}``
are emitted consistently.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from services.agent.providers import litellm_kwargs

OPENROUTER_ENDPOINTS: Mapping[str, str] = MappingProxyType(
    {
        "EU": "https://eu.openrouter.ai/api/v1",
        "US": "https://us.openrouter.ai/api/v1",
        "IN": "https://openrouter.ai/api/v1",
        "GLOBAL": "https://openrouter.ai/api/v1",
    }
)

DEFAULT_CHIRIFY_HEADERS: Mapping[str, str] = MappingProxyType(
    {
        "HTTP-Referer": "https://chirify.io",
        "X-Title": "Chirify",
    }
)

# Recognises OpenRouter regional key prefixes / tags such as:
#   sk-or-eu-..., sk-or-v1-eu-..., or-eu-..., eu_sk-or-...
#   sk-or-us-..., sk-or-v1-us-..., or-us-..., us_sk-or-...
_EU_KEY_RE = re.compile(r"^(?:sk-or-(?:v\d+-)?eu-|or-eu-|eu[_:-])", re.IGNORECASE)
_US_KEY_RE = re.compile(r"^(?:sk-or-(?:v\d+-)?us-|or-us-|us[_:-])", re.IGNORECASE)


class OpenRouterConfigError(ValueError):
    """Raised when residency or model configuration is invalid."""


class OpenRouterKeyRegionMismatchError(OpenRouterConfigError):
    """Raised when an OpenRouter API key's workspace region conflicts with tenant residency."""


def detect_key_workspace(api_key: str, explicit_workspace: str | None = None) -> str | None:
    """Detect whether an OpenRouter API key is scoped to the ``EU`` or ``US`` workspace.

    Args:
        api_key: Raw OpenRouter API key string.
        explicit_workspace: Optional explicit workspace tag stored alongside secret metadata.

    Returns:
        ``"EU"``, ``"US"``, ``"GLOBAL"``, or ``None`` when the key carries no
        region-pinning prefix/tag.
    """
    if explicit_workspace and explicit_workspace.strip():
        tag = explicit_workspace.strip().upper()
        if tag in {"EU", "US", "GLOBAL", "IN"}:
            return "GLOBAL" if tag == "IN" else tag
        raise OpenRouterConfigError(f"Unsupported OpenRouter key workspace tag: {explicit_workspace!r}")

    cleaned = (api_key or "").strip()
    if _EU_KEY_RE.match(cleaned):
        return "EU"
    if _US_KEY_RE.match(cleaned):
        return "US"
    return None


def resolve_openrouter_endpoint(residency: str) -> str:
    """Return the canonical ``api_base`` URL for a tenant data-residency region."""
    region = (residency or "").strip().upper()
    endpoint = OPENROUTER_ENDPOINTS.get(region)
    if endpoint is None:
        accepted = ", ".join(OPENROUTER_ENDPOINTS)
        raise OpenRouterConfigError(
            f"Unsupported data residency {residency!r}. Expected one of: {accepted}"
        )
    return endpoint


def validate_openrouter_key_isolation(
    api_key: str,
    residency: str,
    *,
    key_workspace: str | None = None,
) -> None:
    """Enforce OpenRouter Nov 2026 regional workspace key isolation.

    - ``EU`` residency rejects ``US``-scoped keys.
    - ``US`` residency rejects ``EU``-scoped keys.
    - ``IN`` / ``GLOBAL`` residency rejects region-locked ``EU`` or ``US`` keys.
    """
    cleaned_key = (api_key or "").strip()
    if not cleaned_key:
        raise OpenRouterConfigError("OpenRouter API key is required.")

    normalized_residency = (residency or "").strip().upper()
    resolve_openrouter_endpoint(normalized_residency)

    detected_ws = detect_key_workspace(cleaned_key, explicit_workspace=key_workspace)
    if detected_ws == "US" and normalized_residency != "US":
        raise OpenRouterKeyRegionMismatchError(
            f"OpenRouter key belongs to the US workspace and cannot be used for "
            f"{normalized_residency} residency endpoint ({OPENROUTER_ENDPOINTS[normalized_residency]})."
        )
    if detected_ws == "EU" and normalized_residency != "EU":
        raise OpenRouterKeyRegionMismatchError(
            f"OpenRouter key belongs to the EU workspace and cannot be used for "
            f"{normalized_residency} residency endpoint ({OPENROUTER_ENDPOINTS[normalized_residency]})."
        )


def build_openrouter_config(
    model_name: str,
    api_key: str,
    *,
    residency: str = "GLOBAL",
    key_workspace: str | None = None,
    extra_headers: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build LiteLLM-ready OpenRouter kwargs compatible with :mod:`services.agent.providers`.

    Args:
        model_name: OpenRouter model identifier (e.g. ``"anthropic/claude-sonnet-4"``).
        api_key: Decrypted OpenRouter API key.
        residency: Tenant data residency (``"EU"``, ``"US"``, ``"IN"``, or ``"GLOBAL"``).
        key_workspace: Optional explicit workspace tag for the key (``"EU"`` / ``"US"``).
        extra_headers: Optional additional headers merged over Chirify attribution headers.

    Returns:
        Dictionary carrying ``provider_kind="openai_compatible"``, ``id``, ``api_key``,
        ``api_base`` (never ``base_url``), ``extra_headers``, and sampling defaults
        from :func:`services.agent.providers.litellm_kwargs`.
    """
    normalized_residency = (residency or "GLOBAL").strip().upper()
    api_base = resolve_openrouter_endpoint(normalized_residency)
    validate_openrouter_key_isolation(api_key, normalized_residency, key_workspace=key_workspace)

    provider_row = {
        "provider_kind": "openai_compatible",
        "model_name": (model_name or "").strip(),
        "base_url": api_base,
    }
    kwargs = litellm_kwargs(provider_row, api_key=api_key)
    # Guarantee base_url is never present (LiteLLM ignores base_url on non-proxy class)
    kwargs.pop("base_url", None)

    headers = dict(DEFAULT_CHIRIFY_HEADERS)
    if extra_headers:
        headers.update({str(k): str(v) for k, v in extra_headers.items()})

    kwargs["provider_kind"] = "openai_compatible"
    kwargs["extra_headers"] = headers
    return kwargs
