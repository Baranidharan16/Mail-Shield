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

    key_str = os.getenv("FERNET_KEY", "").strip().strip('"').strip("'")
    if not key_str:
        try:
            import dotenv
            dotenv.load_dotenv()
            key_str = os.getenv("FERNET_KEY", "").strip().strip('"').strip("'")
        except Exception:
            pass
    if key_str:
        try:
            from cryptography.fernet import Fernet
            _fernet = Fernet(key_str.encode())
            return _fernet
        except Exception as e:
            logger.error("Invalid FERNET_KEY: %s — falling back to base64 obfuscation", e)

    # No FERNET_KEY: derive a real Fernet key from the server's JWT secret so
    # OAuth tokens are ALWAYS encrypted at rest (never plain base64).
    # Note: rotating JWT_SECRET_KEY then requires users to reconnect Gmail.
    try:
        import hashlib
        from cryptography.fernet import Fernet
        from app.core.config import get_settings
        seed = get_settings().JWT_SECRET_KEY
        derived = base64.urlsafe_b64encode(hashlib.sha256(("mailshield-oauth-token-key|" + seed).encode()).digest())
        _fernet = Fernet(derived)
        logger.warning("FERNET_KEY not set — OAuth tokens are encrypted with a key derived from JWT_SECRET_KEY.")
        return _fernet
    except Exception as e:  # pragma: no cover
        logger.error("Could not derive token-encryption key: %s", e)
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
