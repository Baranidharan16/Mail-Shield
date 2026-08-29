from __future__ import annotations

import os
import re
import uuid
from pathlib import Path
from typing import Tuple

from app.core.config import get_settings

settings = get_settings()

_SAFE_ORIGINAL_NAME_RE = re.compile(r"[^A-Za-z0-9._-]")


class UnsupportedFileTypeError(Exception):
    pass


class FileTooLargeError(Exception):
    pass


def sanitize_original_filename(filename: str) -> str:
    """Strips path components and unsafe characters. Used only for display, never for the on-disk path."""
    base = os.path.basename(filename or "upload.eml")
    base = _SAFE_ORIGINAL_NAME_RE.sub("_", base)
    return base[:255] or "upload.eml"


def validate_extension(filename: str) -> None:
    ext = Path(filename or "").suffix.lower()
    if ext not in settings.ALLOWED_UPLOAD_EXTENSIONS:
        raise UnsupportedFileTypeError(
            f"File extension '{ext}' is not permitted. Allowed: {settings.ALLOWED_UPLOAD_EXTENSIONS}"
        )


def validate_size(size_bytes: int) -> None:
    if size_bytes > settings.MAX_UPLOAD_SIZE_BYTES:
        raise FileTooLargeError(
            f"File size {size_bytes} bytes exceeds maximum allowed {settings.MAX_UPLOAD_SIZE_BYTES} bytes"
        )
    if size_bytes == 0:
        raise FileTooLargeError("Uploaded file is empty")


def build_storage_path(original_filename: str) -> Tuple[str, str]:
    """Returns (stored_filename, absolute_path). Storage filename is always a
    fresh UUID + validated extension - the original filename is NEVER used to
    build the on-disk path, which eliminates path-traversal risk entirely."""
    ext = Path(original_filename or "").suffix.lower()
    stored_filename = f"{uuid.uuid4()}{ext}"

    storage_dir = Path(settings.UPLOAD_STORAGE_DIR).resolve()
    storage_dir.mkdir(parents=True, exist_ok=True)

    absolute_path = (storage_dir / stored_filename).resolve()
    # Defensive check: resolved path must still live inside storage_dir
    if storage_dir not in absolute_path.parents and absolute_path.parent != storage_dir:
        raise ValueError("Resolved storage path escapes the configured storage directory")

    return stored_filename, str(absolute_path)


def save_evidence_file(raw_bytes: bytes, original_filename: str) -> Tuple[str, str]:
    validate_extension(original_filename)
    validate_size(len(raw_bytes))
    stored_filename, absolute_path = build_storage_path(original_filename)
    with open(absolute_path, "wb") as f:
        f.write(raw_bytes)
    # Evidence should be read-only once written
    os.chmod(absolute_path, 0o440)
    return stored_filename, absolute_path


def generate_case_id() -> str:
    """Human-friendly case identifier, e.g. CASE-2026-A1B2C3D4."""
    from datetime import datetime, timezone
    year = datetime.now(timezone.utc).year
    suffix = uuid.uuid4().hex[:8].upper()
    return f"CASE-{year}-{suffix}"
