"""Master contract seeder hook for Chirify Analyzer Sandbox."""

from __future__ import annotations

from utils.logging import get_logger

logger = get_logger(__name__)


def master_contract_download() -> dict:
    """Idempotently refresh Sandbox SymToken master contracts and symbol cache."""
    from services.chirify_sandbox_bootstrap import seed_sandbox_symtokens

    result = seed_sandbox_symtokens()
    logger.info(f"[ChirifySandbox] Master contract refresh complete: {result}")
    return {"status": "success", "details": result}
