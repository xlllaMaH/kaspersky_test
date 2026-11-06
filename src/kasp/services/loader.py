"""Загрузка записей json фидов в базу данных."""

import json
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from kasp.database.models import Product, Version, Vulnerability
from kasp.database.schemas import VersionRecord, VulnerabilityRecord


@dataclass
class FeedReport:
    """Результат загрузки одного фида."""

    source: str
    added: int = 0
    existing: int = 0
    errors: list[str] = field(default_factory=list)


def _read_json(path: Path) -> list[dict]:
    """Прочитать json-файл, в котором ожидается список записей.

    Аргументы:
        path: Путь к json-файлу

    Вывод:
        Список записей, как они записаны в файле

    Исключения:
        FileNotFoundError: Файл не найден
        json.JSONDecodeError: Некорректный json
        TypeError: Верхний уровень файла не список

    """

    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise TypeError(f"{path.name}: expected a list of records")
    return data


def _validate(
    raw_records: list[dict], schema: type[BaseModel], report: FeedReport
) -> list:
    """Проверить записи схемой; невалидные пропустить и описать в отчёте.

    Аргументы:
        raw_records: сырые записи из json
        schema: Pydantic-схема, по которой проверяются записи
        report: Отчёт с описанием ошибок

    Вывод:
        Записи, которые прошли проверку, в виде объектов схемы

    """
    valid = []
    for number, raw in enumerate(raw_records, start=1):
        try:
            valid.append(schema.model_validate(raw))
        except ValidationError as e:
            for err in e.errors():
                field_name = ".".join(str(p) for p in err["loc"]) or "record"
                report.errors.append(
                    f"{report.source}, record {number}: {field_name}: {err['msg']}"
                )
    return valid


class _Products:
    """Кэш продуктов: поиск по (vendor, name) или создание нового"""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._ids = {(p.vendor, p.name): p.id for p in session.scalars(select(Product))}

    def get_id(self, vendor: str, name: str) -> int:
        """Вернуть id продукта, создав его в базе, если ещё нет

        Аргументы:
            vendor: Производитель
            name: Название продукта

        Вывод:
            Идентификатор продукта в базе

        """

        key = (vendor, name)
        if key not in self._ids:
            product = Product(vendor=vendor, name=name)
            self._session.add(product)
            self._session.flush()
            self._ids[key] = product.id
        return self._ids[key]


def _load_version(
    session: Session,
    products: _Products,
    records: list[VersionRecord],
    report: FeedReport,
) -> None:
    """Добавить в базу версии, которых там ещё нет.

    Аргументы:
        session: Открытая сессия
        products: Кэш продуктов
        records: Проверенные записи фида версий
        report: Отчёт с подсчетом добавленных и существующих записей
    """

    know = set(session.execute(select(Version.product_id, Version.version)).all())
    for rec in records:
        key = (products.get_id(rec.vendor, rec.product), rec.version)
        if key in know:
            report.existing += 1
            continue
        session.add(Version(product_id=key[0], version=key[1]))
        know.add(key)
        report.added += 1


def _load_vulnerabilities(
    session: Session,
    products: _Products,
    records: list[VulnerabilityRecord],
    report: FeedReport,
) -> None:
    """Добавить в базу уязвимости, которых там ещё нет.

    Аргументы:
        session: Открытая сессия
        products: Кэш продуктов
        records: Проверенные записи фида уязвимостей
        report: Отчёт с подсчетом добавленных и существующих записей
    """

    know = set(
        session.execute(
            select(
                Vulnerability.product_id,
                Vulnerability.kla_id,
                Vulnerability.start_version,
                Vulnerability.fixed_version,
            )
        ).all()
    )
    for rec in records:
        product_id = products.get_id(rec.vendor, rec.product)
        key = (product_id, rec.kla_id, rec.start_version, rec.fixed_version)
        if key in know:
            report.existing += 1
            continue
        session.add(
            Vulnerability(
                product_id=product_id, **rec.model_dump(exclude={"vendor", "product"})
            )
        )
        know.add(key)
        report.added += 1


def load_feeds(
    session: Session, versions_path: Path, vulnerabilities_path: Path
) -> tuple[FeedReport, FeedReport]:
    """Загрузить фиды отдельными транзакциями.

    Существующие записи пропускаются, невалидные не
    загружаются и попадают в отчёт

    Аргументы:
        session: Открытая сессия
        versions_path: Путь к файлу с версиями
        vulnerabilities_path: Путь к файлу с уязвимостями

    Вывод:
        Отдельные отчёты по версиям и уязвимостям

    Исключения:
        FileNotFoundError: Файл не найден
        json.JSONDecodeError: Некорректный json
        TypeError: Верхний уровень файла не список
    """

    products = _Products(session)

    versions_report = FeedReport(versions_path.name)
    versions = _validate(_read_json(versions_path), VersionRecord, versions_report)

    _load_version(session, products, versions, versions_report)
    session.commit()

    vulns_report = FeedReport(vulnerabilities_path.name)
    vulns = _validate(
        _read_json(vulnerabilities_path), VulnerabilityRecord, vulns_report
    )

    _load_vulnerabilities(session, products, vulns, vulns_report)
    session.commit()

    return versions_report, vulns_report
