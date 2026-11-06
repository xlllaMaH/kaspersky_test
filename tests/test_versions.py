import pytest

from kasp.utils.versions import is_vulnerable, parse


@pytest.mark.parametrize(
    ("version", "expected"),
    [("3.0.12", (3, 0, 12)), ("8.0.3610.9", (8, 0, 3610, 9))],
)
def test_parse(version, expected):
    assert parse(version) == expected


def test_parse_ignores_trailing_zeros():
    assert parse("15") == parse("15.0") == parse("15.0.0")
    assert parse("0") == ()


def test_parse_compares_numbers_not_strings():
    assert parse("10.0.9") < parse("10.0.23")
    assert parse("9.0.9") < parse("9.0.10")


@pytest.mark.parametrize("bad", ["1.x", "", "1_0", "+1", " 1", "-1", "1."])
def test_parse_rejects_invalid_version(bad):
    with pytest.raises(ValueError):
        parse(bad)


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("9.0.50", True),  # внутри диапазона
        ("9", True),  # start входит в диапазон
        ("9.0.75", False),  # fixed в диапазон не входит
    ],
)
def test_is_vulnerable_range(version, expected):
    assert is_vulnerable(version, start="9", fixed="9.0.75") is expected
