import pytest

from app.target_validator import validate_target


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("http://localhost:8000", "http://127.0.0.1:8000/"),
        ("http://LOCALHOST/path", "http://127.0.0.1/path"),
        ("https://127.0.0.1/path?q=1", "https://127.0.0.1/path?q=1"),
        ("http://[::1]:8080", "http://[::1]:8080/"),
        ("http://127.255.255.254/", "http://127.255.255.254/"),
    ],
)
def test_accepts_local_targets(target, expected):
    assert validate_target(target) == expected


@pytest.mark.parametrize(
    "target",
    [
        "",
        "https://example.com",
        "http://localhost.example.com",
        "ftp://localhost",
        "http://user:password@localhost",
        "http://192.168.1.10",
        "http://[fe80::1%25en0]",
        "http://localhost:99999",
        "http://[::1",
        "http:///path",
        "http://localhost:bad-port",
        "http://127.1",
        "http://2130706433",
        "http://0x7f000001",
        "http://0177.0.0.1",
        "http://[::ffff:127.0.0.1]",
        "http://127.0.0.1.example",
        "http://localhost./",
        "http://user@localhost/",
        "http://localhost\\@example.com/",
        "http://localhost/with whitespace",
    ],
)
def test_rejects_invalid_or_nonlocal_targets(target):
    with pytest.raises(ValueError):
        validate_target(target)
