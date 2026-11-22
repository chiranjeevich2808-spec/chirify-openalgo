"""Single-Use Short-Lived HS256 SSO Launch Ticket Blueprint (`/auth/chirify/*`).

Allows ``chirify-control`` to hand off an authenticated customer from the
Chirify Cloud Console ("Open My Trading Pod") directly into their isolated
OpenAlgo pod without exposing or transmitting any password:

1. **Cryptographic Isolation & Anti-Confusion**:
   - Constant-time HMAC-SHA256 verification using ``CHIRIFY_SSO_SECRET``
     (falling back to ``CHIRIFY_ENTITLEMENT_SECRET``).
   - Strictly binds ``iss == "chirify-control-plane"``, ``aud == tenant_id``,
     and ``tenant_id == expected_tenant_id``.
   - Requires payload ``typ == "CHIRIFY-SSO"`` OR ``purpose == "pod_sso"``
     (and rejects non-SSO header ``typ`` values such as
     ``"CHIRIFY-ENTITLEMENT"``) so an entitlement token can never be abused as
     an interactive login ticket.
2. **Hard 120s TTL Ceiling & Clock-Skew Bounds**:
   - Rejects any ticket whose lifetime ``exp - iat`` exceeds ``120`` seconds
     (default minted TTL is ``60`` seconds) or whose ``iat`` is more than ``5``
     seconds in the future.
3. **Thread-Safe Single-Use ``jti`` Replay Cache**:
   - Atomically records consumed ``jti`` values under a lock and prunes expired
     entries; any second attempt with the same ``jti`` fails with
     :class:`SSOTicketReplayError` (``HTTP 401``).
"""

from __future__ import annotations

import base64
import hashlib
import heapq
import hmac
import json
import os
import secrets
import time
from collections.abc import Iterator, Mapping
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from flask import Blueprint, Response, jsonify, make_response, redirect, request, session

from blueprints.auth import _try_resume_broker_session
from database.auth_db import log_login_attempt
from database.user_db import find_user_by_email, find_user_by_exact_username
from services.chirify_bootstrap_service import (
    _clean_env_val,
    is_managed_pod,
    is_worm_audit_enabled,
)
from utils import real_threading
from utils.ip_helper import get_real_ip
from utils.logging import get_logger
from utils.session import mark_signed_in

logger = get_logger(__name__)

chirify_sso_bp = Blueprint("chirify_sso", __name__, url_prefix="/auth/chirify")

EXPECTED_SSO_ISSUER = "chirify-control-plane"
HARD_MAX_SSO_TTL_SECONDS = 120
IAT_CLOCK_SKEW_GRACE_SECONDS = 5.0
MAX_CONSUMED_JTIS = 10_000
ALLOWED_TYP_VALUES: frozenset[str] = frozenset({"JWT", "CHIRIFY-SSO"})

_JTI_LOCK = real_threading.Lock()
_CONSUMED_JTIS: dict[str, float] = {}


class SSOTicketError(PermissionError):
    """Raised when a Chirify SSO launch ticket is missing, malformed, forged, or unauthorized."""

    status_code: int = 401
    code: str = "sso_ticket_invalid"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        if code is not None:
            self.code = code
        super().__init__(message)


class SSOTicketExpiredError(SSOTicketError):
    """Raised when a Chirify SSO launch ticket is past its ``exp`` timestamp."""

    code: str = "sso_ticket_expired"


class SSOTicketReplayError(SSOTicketError):
    """Raised when a single-use Chirify SSO ``jti`` has already been consumed."""

    code: str = "sso_ticket_replayed"


@dataclass(frozen=True, slots=True)
class SSOTicketClaims(Mapping[str, Any]):
    """Verified claims extracted from a single-use Chirify SSO launch ticket."""

    iss: str
    aud: str
    sub: str
    tenant_id: str
    username: str | None
    iat: int
    exp: int
    jti: str
    typ: str | None = "CHIRIFY-SSO"
    purpose: str | None = "pod_sso"

    @property
    def email(self) -> str:
        return self.sub

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.to_dict())

    def __len__(self) -> int:
        return len(self.to_dict())


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def resolve_sso_secret(env: Mapping[str, str] | None = None) -> str:
    """Return ``CHIRIFY_SSO_SECRET``, falling back to ``CHIRIFY_ENTITLEMENT_SECRET``."""
    source = env if env is not None else os.environ
    sso_secret = _clean_env_val(source.get("CHIRIFY_SSO_SECRET"))
    if sso_secret:
        return sso_secret
    return _clean_env_val(source.get("CHIRIFY_ENTITLEMENT_SECRET"))


def reset_consumed_jtis() -> None:
    """Clear in-memory consumed JTI replay cache (intended for deterministic unit tests)."""
    with _JTI_LOCK:
        _CONSUMED_JTIS.clear()


def _prune_expired_jtis_locked(now: float) -> None:
    cutoff = now - IAT_CLOCK_SKEW_GRACE_SECONDS
    expired_keys = [jti for jti, exp_epoch in _CONSUMED_JTIS.items() if exp_epoch < cutoff]
    for key in expired_keys:
        _CONSUMED_JTIS.pop(key, None)


def mint_sso_ticket(
    *,
    secret: str,
    tenant_id: str,
    email: str,
    username: str | None = None,
    ttl_seconds: int = 60,
    now_epoch: int | float | None = None,
    jti: str | None = None,
    iss: str = EXPECTED_SSO_ISSUER,
    aud: str | None = None,
    typ: str | None = "CHIRIFY-SSO",
    purpose: str | None = "pod_sso",
    header_typ: str = "JWT",
    extra_claims: Mapping[str, Any] | None = None,
) -> str:
    """Mint a compact HS256 single-use Chirify SSO launch ticket."""
    if not secret or not secret.strip():
        raise ValueError("SSO signing secret must be non-empty.")
    if not tenant_id or not tenant_id.strip():
        raise ValueError("tenant_id must be non-empty.")
    if not email or not email.strip():
        raise ValueError("email (sub) must be non-empty.")

    issued_at = int(now_epoch if now_epoch is not None else time.time())
    expires_at = issued_at + int(ttl_seconds)
    ticket_jti = jti if jti is not None else secrets.token_hex(16)

    payload: dict[str, Any] = {
        "iss": iss,
        "aud": tenant_id if aud is None else aud,
        "sub": email.strip(),
        "tenant_id": tenant_id.strip(),
        "iat": issued_at,
        "exp": expires_at,
        "jti": ticket_jti,
    }
    if username is not None and str(username).strip():
        payload["username"] = str(username).strip()
    if typ is not None:
        payload["typ"] = typ
    if purpose is not None:
        payload["purpose"] = purpose
    if extra_claims:
        payload.update(extra_claims)

    header = {"alg": "HS256", "typ": header_typ}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url_encode(signature)}"


def verify_and_consume_sso_ticket(
    ticket: str,
    *,
    secret: str,
    expected_tenant_id: str,
    now_epoch: float | None = None,
    max_ttl_seconds: int = HARD_MAX_SSO_TTL_SECONDS,
) -> SSOTicketClaims:
    """Verify HS256 signature, tenant binding, TTL bounds, and atomically consume ``jti``.

    Raises:
        SSOTicketReplayError: If ``jti`` was already consumed.
        SSOTicketExpiredError: If ``now_epoch > exp``.
        SSOTicketError: On any signature, claim, audience, issuer, or TTL violation.
    """
    if not secret or not secret.strip():
        raise SSOTicketError("SSO verification secret is not configured.", code="sso_unconfigured")
    clean_expected_tenant = _clean_env_val(expected_tenant_id)
    if not clean_expected_tenant:
        raise SSOTicketError("Expected tenant_id is not configured.", code="sso_unconfigured")
    if not ticket or not isinstance(ticket, str) or not ticket.strip():
        raise SSOTicketError("Missing SSO ticket.", code="sso_ticket_missing")

    parts = ticket.strip().split(".")
    if len(parts) != 3:
        raise SSOTicketError("Malformed SSO JWT format.", code="sso_ticket_malformed")

    header_b64, payload_b64, sig_b64 = parts
    try:
        header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
        provided_sig = _b64url_decode(sig_b64)
    except Exception as exc:
        raise SSOTicketError(
            f"Malformed SSO JWT header or signature encoding: {exc}",
            code="sso_ticket_malformed",
        ) from exc

    if not isinstance(header, Mapping) or header.get("alg") != "HS256":
        raise SSOTicketError("Unsupported SSO JWT algorithm.", code="sso_alg_invalid")

    header_typ = header.get("typ")
    if header_typ is not None and str(header_typ) not in ALLOWED_TYP_VALUES:
        raise SSOTicketError(
            "Invalid JWT header type for SSO login ticket.",
            code="sso_wrong_token_type",
        )

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected_sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(provided_sig, expected_sig):
        raise SSOTicketError("Invalid SSO ticket HMAC signature.", code="sso_bad_signature")

    try:
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except Exception as exc:
        raise SSOTicketError(
            f"Malformed SSO JWT payload JSON: {exc}",
            code="sso_ticket_malformed",
        ) from exc

    if not isinstance(payload, Mapping):
        raise SSOTicketError("SSO JWT payload must be a JSON object.", code="sso_ticket_malformed")

    # Prevent cross-protocol token confusion: an entitlement token cannot be used for SSO!
    payload_typ = payload.get("typ")
    payload_purpose = payload.get("purpose")
    if payload_typ is not None and str(payload_typ) not in ALLOWED_TYP_VALUES:
        raise SSOTicketError(
            "Token payload typ is not valid for pod SSO.",
            code="sso_wrong_token_type",
        )
    if payload_typ != "CHIRIFY-SSO" and payload_purpose != "pod_sso":
        raise SSOTicketError(
            "Token is missing required SSO purpose ('typ': 'CHIRIFY-SSO' or 'purpose': 'pod_sso').",
            code="sso_wrong_token_type",
        )

    iss = payload.get("iss")
    if not isinstance(iss, str) or not hmac.compare_digest(iss, EXPECTED_SSO_ISSUER):
        raise SSOTicketError("Invalid SSO ticket issuer.", code="sso_invalid_issuer")

    aud = payload.get("aud")
    claim_tenant_id = payload.get("tenant_id")
    if not isinstance(aud, str) or not hmac.compare_digest(
        aud.encode("utf-8"), clean_expected_tenant.encode("utf-8")
    ):
        raise SSOTicketError("SSO ticket audience does not match this pod.", code="sso_wrong_aud")
    if not isinstance(claim_tenant_id, str) or not hmac.compare_digest(
        claim_tenant_id.encode("utf-8"), clean_expected_tenant.encode("utf-8")
    ):
        raise SSOTicketError(
            "SSO ticket tenant_id does not match this pod.", code="sso_wrong_tenant"
        )

    sub = payload.get("sub")
    if not isinstance(sub, str) or not sub.strip():
        raise SSOTicketError("SSO ticket is missing subject email (sub).", code="sso_missing_sub")

    iat = payload.get("iat")
    exp = payload.get("exp")
    if (
        not isinstance(iat, int)
        or isinstance(iat, bool)
        or not isinstance(exp, int)
        or isinstance(exp, bool)
    ):
        raise SSOTicketError("SSO ticket iat and exp must be integers.", code="sso_invalid_time")

    effective_max_ttl = min(int(max_ttl_seconds), HARD_MAX_SSO_TTL_SECONDS)
    ttl = exp - iat
    if ttl <= 0 or ttl > effective_max_ttl:
        raise SSOTicketError(
            f"SSO ticket TTL ({ttl}s) must be in 1..{effective_max_ttl}s.",
            code="sso_ttl_exceeded",
        )

    now = float(now_epoch if now_epoch is not None else time.time())
    if float(iat) > now + IAT_CLOCK_SKEW_GRACE_SECONDS:
        raise SSOTicketError(
            "SSO ticket iat is in the future beyond allowed clock-skew grace.",
            code="sso_iat_in_future",
        )
    if now > float(exp):
        raise SSOTicketExpiredError("SSO ticket has expired.")

    raw_jti = payload.get("jti")
    if not isinstance(raw_jti, str) or not raw_jti.strip():
        raise SSOTicketError("SSO ticket jti is required.", code="sso_missing_jti")
    jti = raw_jti.strip()

    with _JTI_LOCK:
        _prune_expired_jtis_locked(now)
        if jti in _CONSUMED_JTIS:
            raise SSOTicketReplayError("SSO ticket jti has already been used.")
        max_entries = max(1, int(MAX_CONSUMED_JTIS))
        if len(_CONSUMED_JTIS) >= max_entries:
            evict_count = len(_CONSUMED_JTIS) - max_entries + 1
            if evict_count == 1:
                oldest_keys = [min(_CONSUMED_JTIS, key=_CONSUMED_JTIS.__getitem__)]
            else:
                oldest_keys = [
                    key
                    for key, _ in heapq.nsmallest(
                        evict_count, _CONSUMED_JTIS.items(), key=lambda item: item[1]
                    )
                ]
            for key in oldest_keys:
                _CONSUMED_JTIS.pop(key, None)
            logger.warning(
                "[ChirifySSO] Consumed JTI replay cache reached capacity "
                f"({max_entries}); evicted {len(oldest_keys)} oldest-expiring "
                "entry(s) to prevent unbounded memory growth."
            )
        _CONSUMED_JTIS[jti] = float(exp)

    raw_username = payload.get("username")
    username = str(raw_username).strip() if isinstance(raw_username, str) and raw_username.strip() else None

    return SSOTicketClaims(
        iss=iss,
        aud=aud,
        sub=sub.strip(),
        tenant_id=claim_tenant_id,
        username=username,
        iat=iat,
        exp=exp,
        jti=jti,
        typ=str(payload_typ) if payload_typ is not None else None,
        purpose=str(payload_purpose) if payload_purpose is not None else None,
    )


def _wants_json_response() -> bool:
    if request.method == "POST":
        return True
    if (request.args.get("format") or "").strip().lower() == "json":
        return True
    if request.is_json:
        return True
    accept = (request.headers.get("Accept") or "").lower()
    return "application/json" in accept


def _extract_request_ticket() -> str:
    if request.method == "POST":
        body = request.get_json(silent=True)
        if isinstance(body, Mapping) and body.get("ticket"):
            return str(body["ticket"]).strip()
        if request.form.get("ticket"):
            return str(request.form["ticket"]).strip()
    return str(request.args.get("ticket") or "").strip()


def _emit_sso_worm_event(payload: Mapping[str, Any]) -> None:
    if not is_worm_audit_enabled():
        return
    from subscribers.worm_audit_subscriber import WormAuditWriter, emit_worm_audit_event

    try:
        emit_worm_audit_event("chirify_sso_login", payload)
    except OSError:
        fallback_dir = Path(_clean_env_val(os.getenv("LOG_DIR")) or "log")
        WormAuditWriter(fallback_dir / "worm_audit.jsonl").append("chirify_sso_login", payload)


@chirify_sso_bp.after_request
def _apply_sso_no_store_headers(response: Response) -> Response:
    """Prevent browser/proxy caching, MIME sniffing, and Referer leakage of one-time SSO tickets."""
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@chirify_sso_bp.route("/sso", methods=["GET", "POST"])
def sso_handoff():
    """Verify single-use Chirify SSO launch ticket and establish OpenAlgo Flask session."""
    expected_tenant_id = _clean_env_val(os.getenv("CHIRIFY_TENANT_ID"))
    if not is_managed_pod() or not expected_tenant_id:
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "chirify_sso_disabled",
                    "message": "Chirify SSO handoff is only enabled on managed tenant pods.",
                }
            ),
            403,
        )

    if request.method == "HEAD":
        return _apply_sso_no_store_headers(make_response("", 200))

    ticket = _extract_request_ticket()
    secret = resolve_sso_secret()
    ip = get_real_ip()
    ua = request.headers.get("User-Agent", "")

    try:
        claims = verify_and_consume_sso_ticket(
            ticket,
            secret=secret,
            expected_tenant_id=expected_tenant_id,
        )
    except SSOTicketError as exc:
        logger.warning(f"[ChirifySSO] Rejected SSO ticket ({exc.code}) from IP={ip}: {exc}")
        log_login_attempt(
            expected_tenant_id,
            ip,
            ua,
            status="failed",
            login_type="chirify_sso",
            failure_reason=exc.code,
        )
        return (
            jsonify(
                {
                    "status": "error",
                    "code": exc.code,
                    "message": str(exc),
                }
            ),
            exc.status_code,
        )

    user = (
        find_user_by_email(claims.sub)
        or find_user_by_email(claims.sub.lower())
        or (find_user_by_exact_username(claims.username) if claims.username else None)
    )
    if user is None:
        logger.warning(
            f"[ChirifySSO] Verified SSO ticket for tenant={claims.tenant_id}, "
            f"but local user not found for sub={claims.sub!r} username={claims.username!r}"
        )
        log_login_attempt(
            claims.username or claims.sub,
            ip,
            ua,
            status="failed",
            login_type="chirify_sso",
            failure_reason="user_not_provisioned",
        )
        return (
            jsonify(
                {
                    "status": "error",
                    "code": "sso_user_not_provisioned",
                    "message": "Provisioned pod owner matching SSO ticket was not found.",
                }
            ),
            403,
        )

    # Exact OpenAlgo session establishment
    session.clear()

    if user.is_totp_required_for("login"):
        session["pending_totp_user"] = user.username
        session["pending_totp_started_at"] = datetime.utcnow().isoformat()
        logger.info(f"[ChirifySSO] TOTP second factor required for user={user.username}")
        if _wants_json_response():
            return (
                jsonify(
                    {
                        "status": "totp_required",
                        "redirect": "/login",
                        "user": user.username,
                    }
                ),
                200,
            )
        return redirect("/login?totp=1")

    session["user"] = user.username
    mark_signed_in()

    resumed = _try_resume_broker_session(user.username)
    resumed_broker = session.get("broker") if resumed is not None else None
    target_redirect = "/dashboard" if resumed is not None else "/broker"

    log_login_attempt(
        user.username,
        ip,
        ua,
        status="success",
        login_type="chirify_sso",
        broker=resumed_broker,
    )
    _emit_sso_worm_event(
        {
            "tenant_id": claims.tenant_id,
            "username": user.username,
            "email": user.email,
            "jti": claims.jti,
            "ip": ip,
            "resumed_broker": resumed_broker,
            "redirect": target_redirect,
        }
    )

    if _wants_json_response():
        payload: dict[str, Any] = {
            "status": "success",
            "redirect": target_redirect,
            "user": user.username,
        }
        if resumed_broker:
            payload["broker"] = resumed_broker
        return jsonify(payload), 200

    return redirect(target_redirect)
