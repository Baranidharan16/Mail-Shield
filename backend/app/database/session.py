from __future__ import annotations

import sqlalchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from app.core.config import get_settings

from pathlib import Path

settings = get_settings()

db_url = settings.DATABASE_URL.strip()
# Render / Neon / Supabase hand out "postgres://" or "postgresql://" URLs;
# SQLAlchemy needs an explicit driver.
if db_url.startswith("postgres://"):
    db_url = "postgresql+psycopg2://" + db_url[len("postgres://"):]
elif db_url.startswith("postgresql://"):
    db_url = "postgresql+psycopg2://" + db_url[len("postgresql://"):]
if db_url.startswith("sqlite:///./") or db_url == "sqlite:///forensics.db":
    backend_dir = Path(__file__).resolve().parent.parent.parent
    db_path = (backend_dir / "forensics.db").resolve()
    db_url = f"sqlite:///{db_path.as_posix()}"

_connect_args = {}
if db_url.startswith("sqlite"):
    _connect_args = {"check_same_thread": False}

engine = create_engine(
    db_url,
    connect_args=_connect_args,
    future=True,
    pool_pre_ping=not db_url.startswith("sqlite"),  # drop dead Postgres connections transparently
    **({} if db_url.startswith("sqlite") else {"pool_recycle": 280, "pool_size": 5, "max_overflow": 5}),
)

if db_url.startswith("sqlite"):
    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _record):  # pragma: no cover - trivial
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")   # concurrent reads while writing
        cur.execute("PRAGMA busy_timeout=5000")  # wait instead of 'database is locked'
        cur.close()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, future=True)

Base = declarative_base()


def get_db():
    """FastAPI dependency that yields a DB session and always closes it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables if they do not already exist. Called on app startup."""
    # Import models so they are registered on Base.metadata before create_all
    from app.models import investigation  # noqa: F401
    from app.models import user  # noqa: F401
    from app.models import gmail_account  # noqa: F401  ← per-user Gmail token storage
    from app.models import auth_session  # noqa: F401  ← login sessions + password resets

    inspector = sqlalchemy.inspect(engine)
    existing_tables = set(inspector.get_table_names())
    tables_to_create = [table for table in Base.metadata.sorted_tables if table.name not in existing_tables]

    if tables_to_create:
        Base.metadata.create_all(bind=engine, tables=tables_to_create)

    # Migrate existing investigations table if user_id column is missing
    if "investigations" in existing_tables:
        columns = {col["name"] for col in inspector.get_columns("investigations")}
        if "user_id" not in columns:
            with engine.begin() as conn:
                conn.execute(sqlalchemy.text("ALTER TABLE investigations ADD COLUMN user_id VARCHAR(36)"))

    # Normalise stored e-mails so the unique index is effectively case-insensitive.
    if "users" in existing_tables:
        try:
            with engine.begin() as conn:
                conn.execute(sqlalchemy.text(
                    "UPDATE users SET email = LOWER(TRIM(email)) WHERE email <> LOWER(TRIM(email))"
                ))
        except Exception:  # duplicate after normalisation — leave data untouched
            import logging
            logging.getLogger("mailshield.db").warning(
                "Could not normalise user e-mails (case-duplicates exist); please resolve manually."
            )

