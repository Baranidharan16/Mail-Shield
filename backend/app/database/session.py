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


# Email content is attacker-controlled: a single header or URL longer than its
# VARCHAR column would make Postgres reject the whole analysis
# ("value too long for type character varying"). SQLite does not enforce
# lengths, so this only showed up in production. Trim over-long strings to the
# column size right before every flush (the full raw email is preserved as
# evidence on disk, so no forensic information is lost).
import logging as _logging
from sqlalchemy import String as _String, event as _event, inspect as _inspect
from sqlalchemy.orm import Session as _Session

_len_log = _logging.getLogger("mailshield.db")


@_event.listens_for(_Session, "before_flush")
def _fit_strings_to_columns(session, _flush_context, _instances):
    for obj in list(session.new) + list(session.dirty):
        try:
            mapper = _inspect(obj).mapper
        except Exception:  # noqa: BLE001
            continue
        for prop in mapper.column_attrs:
            col = prop.columns[0]
            limit = getattr(col.type, "length", None)
            if not limit or not isinstance(col.type, _String):
                continue
            value = getattr(obj, prop.key, None)
            if isinstance(value, str) and len(value) > limit:
                setattr(obj, prop.key, value[: limit - 1] + "\u2026")
                _len_log.warning("Trimmed %s.%s from %d to %d characters to fit the column.",
                                 mapper.class_.__name__, prop.key, len(value), limit)

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
    from app.models import processed_email  # noqa: F401  ← real-time monitor dedup/state
    from app.models import advanced  # noqa: F401  ← sandbox / GRC / VAPT / SOC alarm tables

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

