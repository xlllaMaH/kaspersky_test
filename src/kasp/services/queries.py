"""Поиск продуктов, безопасные версии и проверка версии."""

from dataclasses import dataclass, field

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from kasp.database.models import Product, Version, Vulnerability
from kasp.utils.versions import is_vulnerable, parse


@dataclass
class CheckResult:
    """Результат проверки версии продукта."""

    product: Product
    version: str
    known_version: bool
    vulnerabilities: list[Vulnerability] = field(default_factory=list)


def has_data(session: Session) -> bool:
    """Проверить, что в базе есть хотя бы один продукт."""

    return session.scalar(select(Product.id).limit(1)) is not None


def find_products(session: Session, text: str) -> list[Product]:
    """Найти продукты по названию (без учёта регистра).

    Сначала ищется точное совпадение, если его нет, то вхождение подстроки.

    Аргументы:
        session: Открытая сессия
        text: Название продукта

    Вывод:
        Найденные продукты. Если не найдено - пустой список
    """

    text = text.strip()
    exact = select(Product).where(func.lower(Product.name) == text.lower())
    products = list(session.scalars(exact))

    if products:
        return products
    partials = (
        select(Product)
        .where(Product.name.icontains(text, autoescape=True))
        .order_by(Product.name)
    )

    return list(session.scalars(partials))


def _get_vulnerabilities(session: Session, product: Product) -> list[Vulnerability]:
    """Получить все уязвимости продукта."""

    query = select(Vulnerability).where(Vulnerability.product_id == product.id)
    return list(session.scalars(query))


def safe_versions(session: Session, product: Product) -> list[str]:
    """Получить версии продукта, не попадающие в уязвимые диапазоны

    Аргументы:
        session: Открытая сессия
        product: Продукт, для которого ищутся версии

    Вывод:
        Безопасные версии по возрастанию, самая новая последняя
    """

    ranges = _get_vulnerabilities(session, product)
    versions = session.scalars(
        select(Version.version).where(Version.product_id == product.id)
    )
    safe = [
        v
        for v in versions
        if not any(is_vulnerable(v, r.start_version, r.fixed_version) for r in ranges)
    ]

    return sorted(safe, key=parse)


def check_version(session: Session, product: Product, version: str) -> CheckResult:
    """Найти уязвимости, в диапазон которых попадает версия.

    Аргументы:
        session: Открытая сессия
        product: Проверяемый продукт
        version: Проверяемая версия

    Вывод:
        Есть ли версия в списке известных и её уязвимости,
        от новых к старым

    Исключения:
        ValueError: Версия записана некорректно
    """

    target = parse(version)
    known_versions = session.scalars(
        select(Version.version).where(Version.product_id == product.id)
    )
    known = any(parse(v) == target for v in known_versions)
    found = [
        v
        for v in _get_vulnerabilities(session, product)
        if is_vulnerable(version, v.start_version, v.fixed_version)
    ]
    found.sort(key=lambda v: (-v.pub_date.toordinal(), v.kla_id))
    return CheckResult(product, version, known, found)
