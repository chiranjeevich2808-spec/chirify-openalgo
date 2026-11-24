"""Master contract seeder hook for Chirify Analyzer Sandbox."""

from __future__ import annotations

import os

from sqlalchemy.orm import scoped_session, sessionmaker

from database.engine_factory import create_db_engine
from utils.logging import get_logger

logger = get_logger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_db_engine(DATABASE_URL)
db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))


def master_contract_download() -> dict:
    """Idempotently refresh Sandbox SymToken master contracts and symbol cache."""
    from services.chirify_sandbox_bootstrap import seed_sandbox_symtokens

    result = seed_sandbox_symtokens()
    logger.info(f"[ChirifySandbox] Master contract refresh complete: {result}")
    return {"status": "success", "details": result}
