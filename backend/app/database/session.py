from __future__ import annotations

import sqlalchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from app.core.config import get_settings

settings = get_settings()

_connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    _connect_args = {"check_same_thread": False}

engine = create_engine(settings.DATABASE_URL, connect_args=_connect_args, future=True)
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

