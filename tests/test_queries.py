import pytest

from kasp.services.queries import check_version, find_products, safe_versions

TOMCAT_VULNS = [
    ("KLA-OLD", "2022-07-26", "9", "9.0.68"),
    ("KLA-NEW", "2023-05-10", "9", "9.0.75"),
]


@pytest.fixture
def tomcat(make_product):
    return make_product(
        "Apache Tomcat",
        versions=["9.0.50", "9.0.80", "10.0.27"],
        vulnerabilities=TOMCAT_VULNS,
    )


def test_find_products_exact_match_ignores_case(make_product, session):
    make_product("VLC media player")
    make_product("VLC media player (MSI installer)")
    found = find_products(session, "vlc MEDIA player")
    assert [p.name for p in found] == ["VLC media player"]


def test_find_products_by_substring(make_product, session):
    make_product("VLC media player")
    make_product("VLC media player (MSI installer)")
    assert len(find_products(session, "vlc")) == 2


def test_find_products_not_found(make_product, session):
    make_product("PuTTY")
    assert find_products(session, "Nonexistent") == []
    assert find_products(session, "%") == []


def test_safe_versions_are_sorted_numerically(session, tomcat):
    assert safe_versions(session, tomcat) == ["9.0.80", "10.0.27"]


def test_check_known_version_lists_newest_first(session, tomcat):
    result = check_version(session, tomcat, "9.0.50")
    assert result.known_version is True
    assert [v.kla_id for v in result.vulnerabilities] == ["KLA-NEW", "KLA-OLD"]


@pytest.mark.parametrize(
    ("version", "kla_ids"),
    [("9.0.3", ["KLA-NEW", "KLA-OLD"]), ("9.0.99", [])],
)
def test_check_unknown_version(session, tomcat, version, kla_ids):
    result = check_version(session, tomcat, version)
    assert result.known_version is False
    assert [v.kla_id for v in result.vulnerabilities] == kla_ids
