"""
MailShield Authentication API Routes.
Provides /api/auth/register, /api/auth/login, /api/auth/logout, /api/auth/me, /api/auth/status.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.investigation import Investigation
from app.models.user import User
from schemas.auth import (
    AuthResponse,
    AuthStatusResponse,
    MessageResponse,
    UserLoginRequest,
    UserPublicProfile,
    UserRegisterRequest,
)
from services.auth_service import create_access_token, hash_password, verify_password
from utils.auth_deps import get_current_user, get_optional_current_user

logger = logging.getLogger("mailshield.routes.auth")

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


def _build_user_profile(user: User, db: Session) -> UserPublicProfile:
    """Helper to build public profile with user-specific investigation counts."""
    total_inv = db.query(Investigation).filter(Investigation.user_id == user.id).count()
    threats = (
        db.query(Investigation)
        .filter(
            Investigation.user_id == user.id,
            Investigation.classification.in_(["HIGH", "CRITICAL"]),
        )
        .count()
    )

    return UserPublicProfile(
        id=user.id,
        name=user.name,
        email=user.email,
        is_active=user.is_active,
        created_at=user.created_at.isoformat() if user.created_at else None,
        last_login=user.last_login.isoformat() if user.last_login else None,
        total_investigations=total_inv,
        threats_detected=threats,
    )


@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
async def register_user(payload: UserRegisterRequest, db: Session = Depends(get_db)):
    """Registers a new user account with Argon2 password hashing."""
    # Check if user with this email already exists
    existing_user = db.query(User).filter(User.email == payload.email.lower().strip()).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists.",
        )

    # Hash password with Argon2
    hashed = hash_password(payload.password)

    user = User(
        name=payload.name.strip(),
        email=payload.email.lower().strip(),
        password_hash=hashed,
        last_login=datetime.now(timezone.utc),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    logger.info("New user registered: %s (%s)", user.name, user.email)

    token = create_access_token(user_id=user.id, email=user.email, name=user.name)
    profile = _build_user_profile(user, db)

    return AuthResponse(
        access_token=token,
        token_type="bearer",
        user=profile,
    )


@router.post("/login", response_model=AuthResponse)
async def login_user(payload: UserLoginRequest, db: Session = Depends(get_db)):
    """Authenticates a user with email and password and returns a JWT access token."""
    email_clean = payload.email.lower().strip()
    user = db.query(User).filter(User.email == email_clean).first()

    if not user or not verify_password(payload.password, user.password_hash):
        logger.warning("Failed login attempt for email: %s", email_clean)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been deactivated.",
        )

    # Update last login timestamp
    user.last_login = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)

    logger.info("User logged in: %s (%s)", user.name, user.email)

    token = create_access_token(user_id=user.id, email=user.email, name=user.name)
    profile = _build_user_profile(user, db)

    return AuthResponse(
        access_token=token,
        token_type="bearer",
        user=profile,
    )


@router.post("/logout", response_model=MessageResponse)
async def logout_user(current_user: User = Depends(get_current_user)):
    """Logs out the current user session."""
    logger.info("User logged out: %s", current_user.email)
    return MessageResponse(message="Successfully logged out.")


@router.get("/me", response_model=UserPublicProfile)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Returns profile and investigation statistics for the currently authenticated user."""
    return _build_user_profile(current_user, db)


@router.get("/status", response_model=AuthStatusResponse)
async def get_auth_status(
    user: User | None = Depends(get_optional_current_user),
    db: Session = Depends(get_db),
):
    """Checks whether the client has an active authenticated session."""
    if user:
        return AuthStatusResponse(
            authenticated=True,
            user=_build_user_profile(user, db),
        )
    return AuthStatusResponse(authenticated=False, user=None)
