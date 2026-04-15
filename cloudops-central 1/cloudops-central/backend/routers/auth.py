"""Auth router — login, profile, password reset."""
import asyncio
import logging
import os
from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from slowapi import Limiter
from slowapi.util import get_remote_address

from core.config import get_settings
from core.database import USERS_DB
from core.security import (
    create_access_token, get_current_user, hash_password,
    verify_password, validate_password_strength,
)
from audit import audit

log = logging.getLogger("cloudops.auth")
router = APIRouter(prefix="/auth", tags=["auth"])
limiter = Limiter(key_func=get_remote_address)

_APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8001")


class Token(BaseModel):
    access_token: str
    token_type: str
    role: str
    username: str
    name: str


class UpdateProfileRequest(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    current_password: Optional[str] = None
    new_password: Optional[str] = None


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str


@router.post("/token", response_model=Token)
@limiter.limit("10/minute")
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    settings = get_settings()
    ip = get_remote_address(request)
    # Sanitize username before logging to prevent log injection
    safe_username = "".join(c for c in form_data.username if c.isprintable())[:64]

    user = USERS_DB.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        audit(safe_username, "LOGIN_FAILED", ip=ip, status="failure")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    token = create_access_token(
        {"sub": user["username"]},
        timedelta(minutes=settings.access_token_expire_minutes),
    )
    audit(user["username"], "LOGIN", ip=ip)
    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user["role"],
        "username": user["username"],
        "name": user["name"],
    }


@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return {k: v for k, v in current_user.items() if k != "hashed_password"}


@router.put("/profile")
async def update_profile(
    payload: UpdateProfileRequest,
    current_user: dict = Depends(get_current_user),
):
    user = dict(current_user)
    if payload.new_password:
        if not payload.current_password or not verify_password(
            payload.current_password, user["hashed_password"]
        ):
            raise HTTPException(400, "Current password is incorrect")
        try:
            validate_password_strength(payload.new_password)
        except ValueError as e:
            raise HTTPException(400, str(e))
        user["hashed_password"] = hash_password(payload.new_password)
    if payload.name:
        user["name"] = payload.name
    if payload.email:
        user["email"] = str(payload.email)
    USERS_DB[user["username"]] = user
    audit(user["username"], "PROFILE_UPDATE")
    return {"message": "Profile updated successfully"}


@router.post("/password-reset/request")
@limiter.limit("5/minute")
async def request_password_reset(request: Request, payload: PasswordResetRequest):
    from email_service import create_otp, send_password_reset_email
    # Always return 200 to prevent email enumeration
    target = next(
        (u for u in USERS_DB.values() if u.get("email") == str(payload.email)), None
    )
    if target:
        try:
            token = create_otp(target["username"], "password_reset", ttl_minutes=30)
            reset_link = f"{_APP_BASE_URL}/reset-password?token={token}"
            asyncio.create_task(
                send_password_reset_email(target["email"], target["name"], reset_link)
            )
            audit(target["username"], "PASSWORD_RESET_REQUEST")
        except Exception:
            log.exception("Failed to create password reset OTP for %s", target["username"])
    return {"message": "If that email exists, a reset link has been sent."}


@router.post("/password-reset/confirm")
async def confirm_password_reset(payload: PasswordResetConfirm):
    from email_service import verify_otp
    username = verify_otp(payload.token, "password_reset")
    if not username:
        raise HTTPException(400, "Invalid or expired reset token")
    try:
        validate_password_strength(payload.new_password)
    except ValueError as e:
        raise HTTPException(400, str(e))
    user = USERS_DB.get(username)
    if not user:
        raise HTTPException(404, "User not found")
    user["hashed_password"] = hash_password(payload.new_password)
    USERS_DB[username] = user
    audit(username, "PASSWORD_RESET_COMPLETE")
    return {"message": "Password reset successfully"}
