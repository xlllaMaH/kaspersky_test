"""Консольный интерфейс: команды load, safe и check."""

import argparse
import json
import sys
from pathlib import Path

from sqlalchemy.orm import Session

from kasp.database.models import Product
from kasp.database.session import get_session, init_db
from kasp.services.loader import FeedReport, load_feeds
from kasp.services.queries import check_version, find_products, has_data, safe_versions
from kasp.utils.versions import parse

PROG = "vulncheck"
DEFAULT_VERSIONS = "data/versions.json"
DEFAULT_VULNERABILITIES = "data/vulnerabilities.json"


def _non_empty(value: str) -> str:
    """Проверить, что аргумент командной строки не пустой."""

    if not value.strip():
        raise argparse.ArgumentTypeError("не может быть пустым")
    return value


def _print_report(report: FeedReport) -> None:
    """Вывести итог загрузки одного фида."""

    print(
        f"{report.source}: добавлено {report.added}, "
        f"уже было {report.existing}, ошибок {len(report.errors)}"
    )


def _cmd_load(session: Session, args: argparse.Namespace) -> None:
    """Выполнить команду load: загрузить фиды в базу."""

    try:
        reports = load_feeds(session, Path(args.versions), Path(args.vulns))
    except FileNotFoundError as e:
        sys.exit(
            f"Файл не найден: {e.filename}. Укажите путь через --versions и --vulns."
        )
    except json.JSONDecodeError as e:
        sys.exit(f"Файл не является корректным JSON: {e}")
    except TypeError as e:
        sys.exit(f"Неверный формат файла: {e}")

    for report in reports:
        _print_report(report)

    errors = [error for report in reports for error in report.errors]
    if errors:
        sys.exit("\n".join(errors))


def _find_or_exit(session: Session, text: str) -> list[Product]:
    """Найти продукты по названию; завершить программу, если база пуста или их нет."""

    if not has_data(session):
        sys.exit(f"База пуста. Сначала выполните: {PROG} load")
    products = find_products(session, text)
    if not products:
        sys.exit(f"Продукт не найден: {text}")
    return products


def _cmd_safe(session: Session, args: argparse.Namespace) -> None:
    """Выполнить команду safe: показать версии без уязвимостей."""
    for product in _find_or_exit(session, args.product):
        print(f"Продукт: {product.name} ({product.vendor})")
        versions = safe_versions(session, product)
        if not versions:
            print("  Безопасных версий не найдено")
        elif args.all:
            print("  Безопасные версии:")
            for version in versions:
                print(f"  {version}")
        else:
            print(f"  Последняя безопасная версия: {versions[-1]}")


def _cmd_check(session: Session, args: argparse.Namespace) -> None:
    """Выполнить команду check: показать уязвимости версии."""

    try:
        parse(args.version)
    except ValueError:
        sys.exit(f"Некорректная версия '{args.version}', укажите вид 1.2.3")
    for product in _find_or_exit(session, args.product):
        result = check_version(session, product, args.version)
        print(f"Продукт: {product.name} ({product.vendor}), версия {args.version}")
        if not result.vulnerabilities:
            if result.known_version:
                print("  Уязвимостей не найдено")
            else:
                print("  Версия не найдена в данных")
            continue
        if not result.known_version:
            print("  Версии нет в списке известных версий")
        print(f"  Найдено уязвимостей: {len(result.vulnerabilities)}")
        for vuln in result.vulnerabilities:
            print(f"\n  {vuln.kla_id}  {vuln.pub_date}")
            print(f"    Описание: {vuln.description}")
            print(f"    Уязвима с: {vuln.start_version}")
            print(f"    Исправлено в: {vuln.fixed_version}")


def _build_parser() -> argparse.ArgumentParser:
    """Собрать разбор аргументов командной строки."""

    parser = argparse.ArgumentParser(
        prog=PROG, description="Проверка версий продуктов на уязвимости"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    load = commands.add_parser("load", help="Загрузить данные из json-файлов в базу")
    load.add_argument("--versions", default=DEFAULT_VERSIONS, help="файл с версиями")
    load.add_argument(
        "--vulns", default=DEFAULT_VULNERABILITIES, help="Файл с уязвимостями"
    )
    load.set_defaults(handler=_cmd_load)

    safe = commands.add_parser("safe", help="Показать версию без уязвимостей")
    safe.add_argument("product", type=_non_empty, help="Название продукта")
    safe.add_argument("--all", action="store_true", help="Показать все безопасные")
    safe.set_defaults(handler=_cmd_safe)

    check = commands.add_parser("check", help="Показать уязвимости версии")
    check.add_argument("product", type=_non_empty, help="Название продукта")
    check.add_argument("version", help="Проверяемая версия, например 10.0.2")
    check.set_defaults(handler=_cmd_check)

    return parser


def main(argv: list[str] | None = None) -> None:
    """Точка входа: разобрать аргументы и выполнить команду.

    Ошибки пользователя завершают программу через sys.exit.

    Аргументы:
        argv: Аргументы командной строки, по умолчанию
        берутся из sys.argv
    """

    args = _build_parser().parse_args(argv)
    init_db()
    with get_session() as session:
        args.handler(session, args)


if __name__ == "__main__":
    main()
