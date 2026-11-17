from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker, declarative_base

from config import DATABASE_URL

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def check_schema():
    """Stop with a clear message if an old-format database is found."""
    insp = inspect(engine)
    tables = insp.get_table_names()
    needed = {"merkle_roots": {"seal"}, "logs": {"mac", "agent_id", "event_time"}}
    for table, columns in needed.items():
        if table not in tables:
            continue
        cols = {c["name"] for c in insp.get_columns(table)}
        if not columns <= cols:
            raise RuntimeError(
                "secure_logs.db was created by an older version of this project. "
                "Stop the server, delete secure_logs.db and the keys/ folder, "
                "then start again."
            )