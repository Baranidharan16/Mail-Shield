"""
Pydantic schemas for MailShield Authentication.
"""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator


def _clean_name(v: str) -> str:
    v = " ".join((v or "").split())
    if len(v) < 2:
        raise ValueError("Name must be at least 2 characters.")
    if any(ch in v for ch in "<>{}"):
        raise ValueError("Name contains invalid characters.")
    return v


class UserRegisterRequest(BaseModel):
    name: str = Field(..., max_length=100, description="Full name of the user")
    email: EmailStr = Field(..., description="Unique email address")
    password: str = Field(..., max_length=128, description="Password (min 8 chars, letters + numbers)")
    confirm_password: str = Field(..., max_length=128, description="Must match password")

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        return _clean_name(v)

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        return v.strip().lower()

    @model_validator(mode="after")
    def _passwords_match(self):
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match.")
        return self


class UserLoginRequest(BaseModel):
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=1, max_length=128, description="User password")
    remember_me: bool = Field(False, description="Keep me signed in on this device")

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        return v.strip().lower()


class ProfileUpdateRequest(BaseModel):
    name: str = Field(..., max_length=100)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        return _clean_name(v)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(..., max_length=128)
    confirm_password: str = Field(..., max_length=128)

    @model_validator(mode="after")
    def _match(self):
        if self.new_password != self.confirm_password:
            raise ValueError("Passwords do not match.")
        return self


class ForgotPasswordRequest(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        return v.strip().lower()


class ResetPasswordRequest(BaseModel):
    token: str = Field(..., min_length=20, max_length=200)
    new_password: str = Field(..., max_length=128)
    confirm_password: str = Field(..., max_length=128)

    @model_validator(mode="after")
    def _match(self):
        if self.new_password != self.confirm_password:
            raise ValueError("Passwords do not match.")
        return self


class UserPublicProfile(BaseModel):
    id: str
    name: str
    email: str
    is_active: bool = True
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    last_login: Optional[str] = None
    total_investigations: int = 0
    threats_detected: int = 0


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 0  # seconds until the access token expires
    user: UserPublicProfile


class AuthStatusResponse(BaseModel):
    authenticated: bool
    user: Optional[UserPublicProfile] = None


class MessageResponse(BaseModel):
    message: str
