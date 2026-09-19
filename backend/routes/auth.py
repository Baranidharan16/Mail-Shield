"""
MailShield Authentication API Routes.

Session model
-------------
* POST /api/auth/register | /login  -> returns a short-lived JWT access token in
  the JSON body AND sets an httpOnly refresh cookie (`ms_refresh`, path /api/auth).
* The SPA keeps the access token in memory and sends it as `Authorization: Bearer`.
* POST /api/auth/refresh            -> rotates the refresh cookie, returns a new access token.
  Called on page load (restores the session after refresh / new tab) and whenever
  an API call returns 401.
* POST /api/auth/logout             -> revokes the server-side session and clears the cookie.

Every route is also mounted under /api/v1/auth/* and /auth/* for backwards compatibility.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.database.session import get_db
from app.models.auth_session import PasswordResetToken, UserSession
from app.models.investigation import Investigation
from app.models.user import User
from schemas.auth import (
    AuthResponse,
    AuthStatusResponse,
    ChangePasswordRequest,
    ForgotPasswordRequest,
    MessageResponse,
    ProfileUpdateRequest,
    ResetPasswordRequest,
    UserLoginRequest,
    UserPublicProfile,
    UserRegisterRequest,
)
from services.auth_service import (
    create_access_token,
    hash_password_async,
    hash_token,
    new_opaque_token,
    password_problems,
    verify_password_async,
    verify_password_constant_time,
)
from utils.auth_deps import get_current_user, get_optional_current_user

logger = logging.getLogger("mailshield.routes.auth")
settings = get_settings()

router = APIRouter(tags=["Authentication"])

_PREFIXES = ("/api/auth", "/api/v1/auth", "/auth")


def _route(method: str, path: str, **kwargs):
    """Registers one handler under all supported auth prefixes."""
    def decorator(fn):
        for prefix in _PREFIXES:
            getattr(router, method)(f"{prefix}{path}", **kwargs)(fn)
        return fn
    return decorator


# ── Helpers ──────────────────────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _iso(dt: Optional[datetime]) -> Optional[str]:
    dt = _aware(dt)
    return dt.isoformat() if dt else None


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _build_user_profile(user: User, db: Session) -> UserPublicProfile:
    """Public profile with investigation counts scoped to this user only."""
    base = db.query(Investigation).filter(Investigation.user_id == user.id)
    return UserPublicProfile(
        id=user.id,
        name=user.name,
        email=user.email,
        is_active=user.is_active,
        created_at=_iso(user.created_at),
        updated_at=_iso(user.updated_at),
        last_login=_iso(user.last_login),
        total_investigations=base.count(),
        threats_detected=base.filter(Investigation.classification.in_(["HIGH", "CRITICAL"])).count(),
    )


def _weak_password_error(problems: list[str]) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail="Password is too weak. It must have " + ", ".join(problems) + ".",
    )


def _set_refresh_cookie(response: Response, token: str, remember: bool, expires_at: datetime) -> None:
    kwargs = dict(
        key=settings.REFRESH_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=bool(settings.COOKIE_SECURE),
        samesite=settings.COOKIE_SAMESITE,
        path="/",
        domain=settings.COOKIE_DOMAIN or None,
    )
    if remember:
        # Persistent cookie survives browser restarts
        kwargs["max_age"] = int((expires_at - _now()).total_seconds())
    # else: session cookie — cleared when the browser is closed
    response.set_cookie(**kwargs)


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        path="/",
        domain=settings.COOKIE_DOMAIN or None,
        secure=bool(settings.COOKIE_SECURE),
        httponly=True,
        samesite=settings.COOKIE_SAMESITE,
    )


def _unauthorized_clearing_cookie(detail: str) -> JSONResponse:
    resp = JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"detail": detail},
        headers={"X-Auth-Error": "session_expired", "Cache-Control": "no-store"},
    )
    _clear_refresh_cookie(resp)
    return resp


def _issue_session(
    request: Request, response: Response, db: Session, user: User, remember: bool
) -> AuthResponse:
    """Creates a server-side session, sets the refresh cookie, returns an access token."""
    refresh_token = new_opaque_token()
    lifetime = (
        timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        if remember
        else timedelta(hours=settings.SESSION_TOKEN_EXPIRE_HOURS)
    )
    sess = UserSession(
        user_id=user.id,
        refresh_token_hash=hash_token(refresh_token),
        remember_me=remember,
        expires_at=_now() + lifetime,
        user_agent=(request.headers.get("user-agent") or "")[:255],
        ip_address=_client_ip(request)[:64],
    )
    db.add(sess)
    db.commit()
    db.refresh(sess)

    _set_refresh_cookie(response, refresh_token, remember, _aware(sess.expires_at))
    response.headers["Cache-Control"] = "no-store"

    access = create_access_token(user_id=user.id, email=user.email, name=user.name, session_id=sess.id)
    return AuthResponse(
        access_token=access,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=_build_user_profile(user, db),
    )


# ── Brute-force protection (in-memory, per process) ──────────────────────────

class _LoginThrottle:
    def __init__(self) -> None:
        self._fails: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _window(self) -> float:
        return settings.LOGIN_LOCKOUT_MINUTES * 60

    def _prune(self, key: str, now: float) -> Deque[float]:
        q = self._fails[key]
        while q and now - q[0] > self._window():
            q.popleft()
        return q

    def retry_after(self, *keys: str) -> int:
        now = time.time()
        with self._lock:
            for key in keys:
                q = self._prune(key, now)
                if len(q) >= settings.LOGIN_MAX_FAILURES:
                    return max(1, int(self._window() - (now - q[0])))
        return 0

    def fail(self, *keys: str) -> None:
        now = time.time()
        with self._lock:
            for key in keys:
                self._prune(key, now).append(now)

    def reset(self, *keys: str) -> None:
        with self._lock:
            for key in keys:
                self._fails.pop(key, None)


_throttle = _LoginThrottle()


# ── Registration / login ─────────────────────────────────────────────────────

@_route("post", "/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    payload: UserRegisterRequest, request: Request, response: Response, db: Session = Depends(get_db)
):
    """Registers a new user account (Argon2id password hash) and signs them in."""
    problems = password_problems(payload.password, payload.email, payload.name)
    if problems:
        raise _weak_password_error(problems)

    if db.query(User.id).filter(User.email == payload.email).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists. Please sign in instead.",
        )

    hashed = await hash_password_async(payload.password)
    user = User(name=payload.name, email=payload.email, password_hash=hashed, last_login=_now())
    db.add(user)
    try:
        db.commit()
    except IntegrityError:  # concurrent registration with the same e-mail
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists. Please sign in instead.",
        )
    db.refresh(user)
    logger.info("New user registered: id=%s", user.id)
    return _issue_session(request, response, db, user, remember=False)


@_route("post", "/login", response_model=AuthResponse)
async def login_user(
    payload: UserLoginRequest, request: Request, response: Response, db: Session = Depends(get_db)
):
    """Authenticates with email + password. Error messages never reveal whether the email exists."""
    ip_key, email_key = f"ip:{_client_ip(request)}", f"email:{payload.email}"
    wait = _throttle.retry_after(email_key, ip_key)
    if wait:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed sign-in attempts. Please try again in {max(1, wait // 60)} minute(s).",
            headers={"Retry-After": str(wait)},
        )

    user = db.query(User).filter(User.email == payload.email).first()
    ok = await verify_password_constant_time(payload.password, user.password_hash if user else None)
    if not ok or not user or not user.is_active:
        _throttle.fail(email_key, ip_key)
        logger.warning("Failed login attempt from %s", _client_ip(request))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
        )

    _throttle.reset(email_key)
    user.last_login = _now()
    db.commit()
    logger.info("User logged in: id=%s", user.id)
    return _issue_session(request, response, db, user, remember=payload.remember_me)


# ── Session refresh / logout ─────────────────────────────────────────────────

def _session_from_cookie(request: Request, db: Session) -> Optional[UserSession]:
    raw = request.cookies.get(settings.REFRESH_COOKIE_NAME)
    if not raw:
        return None
    return db.query(UserSession).filter(UserSession.refresh_token_hash == hash_token(raw)).first()


@_route("post", "/refresh", response_model=AuthResponse)
async def refresh_session(request: Request, response: Response, db: Session = Depends(get_db)):
    """Exchanges the httpOnly refresh cookie for a new access token (and rotates the cookie)."""
    sess = _session_from_cookie(request, db)
    now = _now()
    if sess is None or sess.revoked_at is not None or _aware(sess.expires_at) <= now:
        return _unauthorized_clearing_cookie("Your session has expired. Please sign in again.")

    user = db.get(User, sess.user_id)
    if not user or not user.is_active:
        sess.revoked_at = now
        db.commit()
        return _unauthorized_clearing_cookie("Account is not active.")

    # Rotate: a stolen, already-used refresh token becomes worthless.
    new_refresh = new_opaque_token()
    sess.refresh_token_hash = hash_token(new_refresh)
    sess.last_used_at = now
    if not sess.remember_me:
        # sliding window for browser-session logins
        sess.expires_at = now + timedelta(hours=settings.SESSION_TOKEN_EXPIRE_HOURS)
    db.commit()

    _set_refresh_cookie(response, new_refresh, bool(sess.remember_me), _aware(sess.expires_at))
    response.headers["Cache-Control"] = "no-store"
    access = create_access_token(user_id=user.id, email=user.email, name=user.name, session_id=sess.id)
    return AuthResponse(
        access_token=access,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=_build_user_profile(user, db),
    )


@_route("post", "/logout", response_model=MessageResponse)
async def logout_user(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(get_optional_current_user),
):
    """Revokes this device's session. Works even when the access token has already expired."""
    now = _now()
    sess = _session_from_cookie(request, db)
    sid = getattr(request.state, "session_id", None)
    if sess is None and sid:
        sess = db.get(UserSession, sid)
    if sess is not None and sess.revoked_at is None:
        sess.revoked_at = now
        db.commit()
    _clear_refresh_cookie(response)
    return MessageResponse(message="Successfully logged out.")


@_route("post", "/logout-all", response_model=MessageResponse)
async def logout_all_devices(
    response: Response,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Signs the user out on every device/browser."""
    db.query(UserSession).filter(
        UserSession.user_id == current_user.id, UserSession.revoked_at.is_(None)
    ).update({UserSession.revoked_at: _now()}, synchronize_session=False)
    db.commit()
    _clear_refresh_cookie(response)
    return MessageResponse(message="Signed out from all devices.")


# ── Profile ──────────────────────────────────────────────────────────────────

@_route("get", "/me", response_model=UserPublicProfile)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    return _build_user_profile(current_user, db)


@_route("patch", "/me", response_model=UserPublicProfile)
async def update_profile(
    payload: ProfileUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    current_user.name = payload.name
    db.commit()
    db.refresh(current_user)
    return _build_user_profile(current_user, db)


@_route("post", "/change-password", response_model=MessageResponse)
async def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not await verify_password_async(payload.current_password, current_user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect.")
    problems = password_problems(payload.new_password, current_user.email, current_user.name)
    if problems:
        raise _weak_password_error(problems)
    current_user.password_hash = await hash_password_async(payload.new_password)
    # Sign out every OTHER device
    keep = getattr(request.state, "session_id", None)
    db.query(UserSession).filter(
        UserSession.user_id == current_user.id,
        UserSession.revoked_at.is_(None),
        UserSession.id != keep,
    ).update({UserSession.revoked_at: _now()}, synchronize_session=False)
    db.commit()
    return MessageResponse(message="Password updated. Other devices have been signed out.")


@_route("get", "/status", response_model=AuthStatusResponse)
async def get_auth_status(
    user: Optional[User] = Depends(get_optional_current_user), db: Session = Depends(get_db)
):
    if user:
        return AuthStatusResponse(authenticated=True, user=_build_user_profile(user, db))
    return AuthStatusResponse(authenticated=False, user=None)


# ── Password reset ───────────────────────────────────────────────────────────

_GENERIC_RESET_MSG = "If an account exists for that email, a password reset link has been sent."


@_route("post", "/forgot-password", response_model=MessageResponse)
async def forgot_password(payload: ForgotPasswordRequest, request: Request, db: Session = Depends(get_db)):
    """Always returns the same message so it cannot be used to discover registered emails."""
    wait = _throttle.retry_after(f"reset:{_client_ip(request)}")
    if wait:
        return MessageResponse(message=_GENERIC_RESET_MSG)
    _throttle.fail(f"reset:{_client_ip(request)}")  # counts towards a per-IP budget

    user = db.query(User).filter(User.email == payload.email).first()
    if user and user.is_active:
        raw = new_opaque_token()
        db.add(PasswordResetToken(
            user_id=user.id,
            token_hash=hash_token(raw),
            expires_at=_now() + timedelta(minutes=settings.PASSWORD_RESET_EXPIRE_MINUTES),
        ))
        db.commit()
        base = (settings.FRONTEND_URL or "http://localhost:5173").rstrip("/")
        link = f"{base}/reset-password?token={raw}"
        # TODO(email): send `link` via your SMTP / e-mail provider.
        if settings.is_production:
            logger.warning("Password reset requested but no e-mail provider is configured.")
        else:
            logger.info("DEV ONLY — password reset link for user %s: %s", user.id, link)
    return MessageResponse(message=_GENERIC_RESET_MSG)


@_route("post", "/reset-password", response_model=MessageResponse)
async def reset_password(payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    now = _now()
    rec = db.query(PasswordResetToken).filter(PasswordResetToken.token_hash == hash_token(payload.token)).first()
    if rec is None or rec.used_at is not None or _aware(rec.expires_at) <= now:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="This reset link is invalid or has expired.")
    user = db.get(User, rec.user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="This reset link is invalid or has expired.")
    problems = password_problems(payload.new_password, user.email, user.name)
    if problems:
        raise _weak_password_error(problems)
    user.password_hash = await hash_password_async(payload.new_password)
    rec.used_at = now
    db.query(UserSession).filter(
        UserSession.user_id == user.id, UserSession.revoked_at.is_(None)
    ).update({UserSession.revoked_at: now}, synchronize_session=False)
    db.commit()
    return MessageResponse(message="Your password has been reset. Please sign in.")
