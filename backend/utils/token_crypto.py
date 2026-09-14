"""
MailShield Token Encryption Utility.
Uses Fernet symmetric encryption to protect OAuth tokens at rest.
Tokens are stored in the database as base64-encoded ciphertext.
"""
from __future__ import annotations

import base64
import logging
import os

logger = logging.getLogger("mailshield.utils.token_crypto")

_fernet = None


def _get_fernet():
    global _fernet
    if _fernet is not None:
        return _fernet

    key_str = os.getenv("FERNET_KEY", "")
    if not key_str:
        try:
            import dotenv
            dotenv.load_dotenv()
            key_str = os.getenv("FERNET_KEY", "")
        except Exception:
            pass
    if key_str:
        try:
            from cryptography.fernet import Fernet
            _fernet = Fernet(key_str.encode())
            return _fernet
        except Exception as e:
            logger.error("Invalid FERNET_KEY: %s — falling back to base64 obfuscation", e)

    # Dev-only fallback: simple base64 (NOT secure — only for local dev)
    logger.warning(
        "FERNET_KEY not set. Using base64 obfuscation ONLY. "
        "Set FERNET_KEY in production!"
    )
    return None


def encrypt_token(plaintext: str) -> str:
    """Encrypts a token string. Returns a base64-encoded ciphertext string."""
    if not plaintext:
        return ""
    f = _get_fernet()
    if f:
        return f.encrypt(plaintext.encode()).decode()
    # Dev fallback
    return base64.b64encode(plaintext.encode()).decode()


def decrypt_token(ciphertext: str) -> str:
    """Decrypts a token string. Returns the plaintext token."""
    if not ciphertext:
        return ""
    f = _get_fernet()
    if f:
        try:
            return f.decrypt(ciphertext.encode()).decode()
        except Exception as e:
            logger.error("Token decryption failed: %s", e)
            return ""
    # Dev fallback
    try:
        return base64.b64decode(ciphertext.encode()).decode()
    except Exception:
        return ""
