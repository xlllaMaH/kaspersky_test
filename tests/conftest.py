from datetime import date

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from kasp.database.models import Base, Product, Version, Vulnerability


@pytest.fixture
def session():
    """Пустая база SQLite в памяти для каждого теста."""
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture
def make_product(session):
    """Фабрика: создаёт продукт с версиями и уязвимостями."""

    def _make(name, versions=(), vulnerabilities=(), vendor="Vendor"):
        product = Product(vendor=vendor, name=name)
        session.add(product)
        session.flush()
        for version in versions:
            session.add(Version(product_id=product.id, version=version))
        for kla_id, published, start, fixed in vulnerabilities:
            session.add(
                Vulnerability(
                    product_id=product.id,
                    kla_id=kla_id,
                    description=f"Vulnerability {kla_id}",
                    pub_date=date.fromisoformat(published),
                    start_version=start,
                    fixed_version=fixed,
                )
            )
        session.commit()
        return product

    return _make
