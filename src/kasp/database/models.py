"""ORM-модели: продукты, версии и уязвимости."""

from datetime import date

from sqlalchemy import ForeignKey, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Базовый класс для всех моделей"""


class Product(Base):
    """Продукт производителя."""

    __tablename__ = "products"
    __table_args__ = (UniqueConstraint("name", "vendor"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    vendor: Mapped[str]
    name: Mapped[str]


class Version(Base):
    """Известная версия продукта."""

    __tablename__ = "versions"
    __table_args__ = (UniqueConstraint("product_id", "version"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    product_id: Mapped[int] = mapped_column(ForeignKey("products.id"))
    version: Mapped[str]


class Vulnerability(Base):
    """
    Уязвимость продукта в диапазоне версий.

    Один KLA_id может описывать несколько диапазонов,
    поэтому kla_id не может быть уникален сам по себе
    """

    __tablename__ = "vulnerabilities"
    __table_args__ = (
        UniqueConstraint("product_id", "kla_id", "start_version", "fixed_version"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    product_id: Mapped[int] = mapped_column(ForeignKey("products.id"))
    kla_id: Mapped[str]
    description: Mapped[str]
    pub_date: Mapped[date]
    start_version: Mapped[str]
    fixed_version: Mapped[str]
