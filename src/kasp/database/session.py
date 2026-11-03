"""Подключение к базе данных и управление сессиями."""

import os
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from kasp.database.models import Base

DEFAULT_DB_URL = "sqlite:///kasp.db"

engine = create_engine(os.environ.get("KASP_DB_URL", DEFAULT_DB_URL))

SessionLocal = sessionmaker(engine)


@contextmanager
def get_session() -> Iterator[Session]:
    with SessionLocal() as session:
        yield session


def init_db() -> None:
    """Создание таблиц."""
    Base.metadata.create_all(engine)
