# Security — Phase 1

This is a cybersecurity platform that processes **untrusted, potentially malicious** input (arbitrary uploaded emails). Every design decision below follows from treating the uploaded `.eml` as hostile by default.

## Implemented controls

| Control | Implementation |
|---|---|
| File type validation | Only `.eml` extension accepted (`app/utils/storage.py::validate_extension`); rejected with `415` otherwise |
| File size limits | `MAX_UPLOAD_SIZE_BYTES` (default 10 MB) enforced before processing; empty files rejected |
| Safe filename handling | Original filename is sanitized for *display only* (`sanitize_original_filename`) and is **never** used to build an on-disk path |
| UUID-based storage | Every stored evidence file is named `{uuid4}{ext}` — the original filename never touches the filesystem path |
| Path traversal protection | `build_storage_path()` resolves the final path and asserts it is still inside the configured storage directory before writing |
| Evidence immutability | Stored evidence files are `chmod 0o440` (read-only) after write |
| Input validation | Pydantic schemas validate every request/response shape; FastAPI rejects malformed multipart/JSON automatically |
| No arbitrary command execution | The forensic engine never calls `subprocess`, `os.system`, `eval`, or shells out on any part of an uploaded email |
| No shell execution on uploaded data | Confirmed — `email_parser.py` uses only the Python stdlib `email` package |
| No automatic execution of attachments | Attachments are hashed (SHA-256) and metadata-only extracted; contents are never opened, rendered, or executed |
| No active URL crawling | `url_analyzer.py` performs purely string-based analysis; **no `requests`/`httpx` call is ever made** to a URL found in a message |
| Secrets via environment only | `app/core/config.py` reads all configuration from environment variables via `pydantic-settings`; nothing is hard-coded |
| CORS configuration | `CORS_ORIGINS` is an explicit allow-list, not `*` |
| Rate limiting | Per-IP sliding-window limiter (`app/core/rate_limit.py`), default 30 req/min |
| Secure error handling | Global exception handler (`app/core/error_handlers.py`) returns a generic message; full details are logged server-side only |
| Logging without sensitive content | `investigation_service.py` logs only case IDs, sizes, and scores — never email body/subject content |
| SQL injection protection | All queries go through the SQLAlchemy ORM with parameter binding — no raw string-interpolated SQL anywhere |

## Threat model for the platform itself

See [`THREAT_MODEL.md`](THREAT_MODEL.md) for what the *analyzed emails* are checked against. This section is about attacks against the **platform**:

- **Malicious `.eml` designed to exploit the parser**: mitigated by using only Python's well-maintained standard-library `email` package (`policy.default`), with a `try/except` fallback to `compat32` for malformed input, and defensive decoding (`errors="replace"`) rather than raising.
- **Zip-bomb / oversized attachment DoS**: mitigated by the overall file-size cap; attachment payloads are only hashed, never decompressed or processed further in Phase 1.
- **Path traversal via crafted filename** (e.g. `../../etc/passwd.eml`): mitigated by UUID-based storage naming — the original filename never appears in any filesystem path.
- **Stored XSS via email subject/body rendered in the frontend**: React escapes all interpolated text content by default; no `dangerouslySetInnerHTML` is used anywhere in the frontend for uploaded content.
- **Resource exhaustion via many rapid uploads**: mitigated by per-IP rate limiting.

## Known Phase-1 limitations (tracked for Phase 2/3)

- DKIM signatures are parsed from headers but not cryptographically verified against DNS-published public keys.
- Rate limiting is in-memory and per-process; a horizontally scaled deployment needs a shared store (e.g. Redis).
- Authentication/authorization for the API is not yet implemented (`created_by` column exists on `investigations` for this purpose) — Phase 1 is single-tenant/trusted-network by design, per the project brief ("keep simple in Phase 1 but design the architecture so role-based auth can be added later").
- No malware/attachment sandboxing — attachments are hashed and cataloged only, never opened.
