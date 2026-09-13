import os


def test_init_db_is_idempotent(tmp_path):
    db_path = tmp_path / "forensics.db"
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"

    from app.database.session import Base, engine, init_db
    from app.models import investigation  # noqa: F401

    init_db()
    init_db()

    assert "investigations" in [table.name for table in Base.metadata.sorted_tables]
    assert engine is not None
