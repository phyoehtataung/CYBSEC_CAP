import pytest

from app.scanner.allowlist import TargetNotAllowed, validate_local_target


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com",
        "http://192.168.1.50",
        "http://localhost:9999",
        "http://user:pass@localhost:3000",
        "ftp://localhost:3000",
        "http://google.com",
    ],
)
def test_rejects_unauthorised_targets(url):
    with pytest.raises(TargetNotAllowed):
        validate_local_target(url)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://localhost:3000/", "http://localhost:3000"),
        ("http://127.0.0.1:8081", "http://127.0.0.1:8081"),
        ("http://juice-shop:3000", "http://juice-shop:3000"),
        ("http://dvwa:80", "http://dvwa:80"),
    ],
)
def test_accepts_lab_urls(url, expected):
    assert validate_local_target(url) == expected
