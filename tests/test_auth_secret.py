"""Tests for JWT signing-secret strength enforcement.

A short HS256 secret is brute-forceable, and a forged token grants dashboard
access, so ``set_jwt_secret`` must fail closed rather than warn.
"""

from __future__ import annotations

import secrets

import pytest

from server.auth import MIN_JWT_SECRET_BYTES, create_token, decode_token, set_jwt_secret

STRONG_SECRET = secrets.token_hex(32)  # 64 chars / 64 bytes


class TestJwtSecretStrength:
    def test_minimum_is_at_least_sha256_output(self):
        """RFC 7518 s3.2 requires an HS256 key no shorter than the hash output."""
        assert MIN_JWT_SECRET_BYTES >= 32

    def test_strong_secret_accepted(self):
        set_jwt_secret(STRONG_SECRET)

    def test_empty_secret_rejected(self):
        with pytest.raises(ValueError, match="empty"):
            set_jwt_secret("")

    def test_short_secret_rejected(self):
        short = "x" * (MIN_JWT_SECRET_BYTES - 1)
        with pytest.raises(ValueError, match="too short"):
            set_jwt_secret(short)

    def test_boundary_secret_accepted(self):
        set_jwt_secret("x" * MIN_JWT_SECRET_BYTES)

    def test_multibyte_secret_measured_in_bytes_not_chars(self):
        """A 31-character string can still be >= 32 bytes once encoded."""
        multibyte = "é" * (MIN_JWT_SECRET_BYTES - 1)  # 2 bytes each
        assert len(multibyte) < MIN_JWT_SECRET_BYTES
        set_jwt_secret(multibyte)

    def test_short_multibyte_secret_rejected(self):
        with pytest.raises(ValueError, match="too short"):
            set_jwt_secret("é" * 8)  # 8 chars, 16 bytes


class TestTokenRoundTrip:
    def test_token_signed_with_strong_secret_verifies(self):
        token = create_token("analyst", "viewer", STRONG_SECRET, ttl_hours=1)
        claims = decode_token(token, STRONG_SECRET)
        assert claims["sub"] == "analyst"
        assert claims["role"] == "viewer"

    def test_token_does_not_verify_under_a_different_secret(self):
        from fastapi import HTTPException

        token = create_token("analyst", "viewer", STRONG_SECRET, ttl_hours=1)
        with pytest.raises(HTTPException) as exc:
            decode_token(token, secrets.token_hex(32))
        assert exc.value.status_code == 401
