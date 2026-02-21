"""JWT authentication and password hashing for the SOC dashboard."""

from __future__ import annotations

import time
from typing import Any

import bcrypt
import jwt
from fastapi import HTTPException, Request


def hash_password(plain: str) -> str:
    """Hash a plaintext password with bcrypt."""
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    """Check a plaintext password against a bcrypt hash."""
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def create_token(username: str, role: str, secret: str, ttl_hours: int = 8) -> str:
    """Create a JWT with username, role, and expiry."""
    payload = {
        "sub": username,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + ttl_hours * 3600,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_token(token: str, secret: str) -> dict[str, Any]:
    """Decode and validate a JWT. Raises HTTPException on failure."""
    try:
        return jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired") from None
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token") from None


# --- FastAPI dependency ---

# Set by app.py at startup
_jwt_secret: str = ""


def set_jwt_secret(secret: str) -> None:
    global _jwt_secret
    _jwt_secret = secret


async def get_current_user(request: Request) -> dict[str, Any]:
    """FastAPI dependency: extract and validate JWT from Authorization header."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = auth[7:]
    return decode_token(token, _jwt_secret)
