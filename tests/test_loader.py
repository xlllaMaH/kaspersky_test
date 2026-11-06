import json

from sqlalchemy import func, select

from kasp.database.models import Product, Version, Vulnerability
from kasp.services.loader import load_feeds

VERSIONS = [
    {"vendor": "Apache", "product": "Tomcat", "version": "9.0.50"},
    {"vendor": "Apache", "product": "Tomcat", "version": "9.0.80"},
]
VULNERABILITY = {
    "vendor": "Apache",
    "product": "Tomcat",
    "KLA_id": "KLA1",
    "description": "XSS vulnerability",
    "publish_date": "2023-05-10",
    "start_vuln_version": "9",
    "fixed_version": "9.0.75",
}


def write_feeds(tmp_path, versions, vulnerabilities):
    versions_path = tmp_path / "versions.json"
    vulns_path = tmp_path / "vulnerabilities.json"
    versions_path.write_text(json.dumps(versions), encoding="utf-8")
    vulns_path.write_text(json.dumps(vulnerabilities), encoding="utf-8")
    return versions_path, vulns_path


def counts(session):
    return [
        session.scalar(select(func.count()).select_from(model))
        for model in (Product, Version, Vulnerability)
    ]


def test_load_feeds_adds_records(session, tmp_path):
    paths = write_feeds(tmp_path, VERSIONS, [VULNERABILITY])
    versions_report, vulns_report = load_feeds(session, *paths)
    assert counts(session) == [1, 2, 1]
    assert (versions_report.added, vulns_report.added) == (2, 1)


def test_load_feeds_twice_adds_no_duplicates(session, tmp_path):
    paths = write_feeds(tmp_path, VERSIONS, [VULNERABILITY])
    load_feeds(session, *paths)
    versions_report, vulns_report = load_feeds(session, *paths)
    assert counts(session) == [1, 2, 1]
    assert (versions_report.existing, vulns_report.existing) == (2, 1)
    assert (versions_report.added, vulns_report.added) == (0, 0)


def test_load_feeds_skips_invalid_records(session, tmp_path):
    bad_version = {"vendor": "Apache", "product": "Tomcat", "version": "1.x"}
    paths = write_feeds(tmp_path, [*VERSIONS, bad_version], [VULNERABILITY])
    versions_report, _ = load_feeds(session, *paths)
    assert versions_report.added == 2
    assert versions_report.errors == [
        (
            "versions.json, record 3: version: "
            "Value error, Invalid version '1.x', use a form like 1.2.3"
        )
    ]


def test_load_feeds_creates_product_known_only_from_vulnerabilities(session, tmp_path):
    paths = write_feeds(tmp_path, [], [VULNERABILITY])
    load_feeds(session, *paths)
    assert counts(session) == [1, 0, 1]
