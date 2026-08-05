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

# HS256 derives its security directly from the secret's entropy. RFC 7518
# section 3.2 requires a key at least as long as the hash output (32 bytes for
# SHA-256); anything shorter is brute-forceable, and a forged token here is a
# full authentication bypass for the SOC dashboard. PyJWT >= 2.13 emits
# InsecureKeyLengthWarning below this threshold.
MIN_JWT_SECRET_BYTES = 32


def set_jwt_secret(secret: str) -> None:
    """Install the process-wide JWT signing secret.

    Raises:
        ValueError: if the secret is missing or shorter than
            ``MIN_JWT_SECRET_BYTES``. This fails closed on purpose -- starting
            with a weak signing key would let an attacker forge admin tokens,
            which is worse than refusing to start.
    """
    global _jwt_secret
    if not secret:
        raise ValueError(
            "JWT signing secret is empty. Set the JWT_SECRET environment "
            "variable, or leave it unset to have one generated at startup."
        )
    if len(secret.encode()) < MIN_JWT_SECRET_BYTES:
        raise ValueError(
            f"JWT_SECRET is too short ({len(secret.encode())} bytes); "
            f"HS256 requires at least {MIN_JWT_SECRET_BYTES} bytes. "
            f"Generate a strong one with: python -c "
            f'"import secrets; print(secrets.token_hex(32))"'
        )
    _jwt_secret = secret


async def get_current_user(request: Request) -> dict[str, Any]:
    """FastAPI dependency: extract and validate JWT from Authorization header."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = auth[7:]
    return decode_token(token, _jwt_secret)
