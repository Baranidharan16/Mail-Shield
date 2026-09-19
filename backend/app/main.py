"""
Legacy entry point kept for backwards compatibility.

Historically the Dockerfile ran `uvicorn app.main:app`, which built a SECOND,
older FastAPI app WITHOUT the /api/auth routes, the Gmail routes or the
ownership checks — so login/registration returned 404 in any deployment that
used it. There is now exactly one application object, defined in backend/main.py.
"""
from main import app  # noqa: F401
