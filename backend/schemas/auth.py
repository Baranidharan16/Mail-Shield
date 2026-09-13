"""
Pydantic schemas for MailShield Authentication.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, field_validator


class UserRegisterRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100, description="Full Name of the user")
    email: EmailStr = Field(..., description="Unique email address")
    password: str = Field(..., min_length=8, max_length=128, description="Password (min 8 chars)")
    confirm_password: str = Field(..., description="Must match password")

    @field_validator("confirm_password")
    @classmethod
    def passwords_match(cls, v: str, values):
        if "password" in values.data and v != values.data["password"]:
            raise ValueError("Passwords do not match.")
        return v


class UserLoginRequest(BaseModel):
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., description="User password")


class UserPublicProfile(BaseModel):
    id: str
    name: str
    email: str
    is_active: bool = True
    created_at: Optional[str] = None
    last_login: Optional[str] = None
    total_investigations: int = 0
    threats_detected: int = 0


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserPublicProfile


class AuthStatusResponse(BaseModel):
    authenticated: bool
    user: Optional[UserPublicProfile] = None


class MessageResponse(BaseModel):
    message: str
