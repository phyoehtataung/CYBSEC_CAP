from app.scanner.dynamic.checks import analyse_pages, cors_finding


def _page(**overrides):
    page = {
        "url": "http://localhost:3000/",
        "requested_url": "http://localhost:3000/",
        "status_code": 200,
        "headers": {},
        "set_cookie": [],
        "body": "<html><body>ok</body></html>",
        "content_type": "text/html",
        "forms": [],
    }
    page.update(overrides)
    return page


def test_missing_headers_banner_and_cookie_flags():
    findings = analyse_pages(
        [
            _page(
                headers={"server": "Express", "x-powered-by": "Express"},
                set_cookie=["token=abc"],
            )
        ],
        start_url="http://localhost:3000/",
    )
    titles = " ".join(item["title"] for item in findings)
    assert "Security headers missing" in titles
    assert "No framing control" in titles
    assert "Server or framework version disclosed" in titles
    assert "token" in titles
    assert all(item["detection_type"] == "dynamic" for item in findings)


def test_hardened_cookie_is_not_flagged():
    findings = analyse_pages(
        [
            _page(
                headers={
                    "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
                    "x-content-type-options": "nosniff",
                    "x-frame-options": "DENY",
                    "referrer-policy": "no-referrer",
                    "permissions-policy": "geolocation=()",
                },
                set_cookie=["token=abc; HttpOnly; SameSite=Lax"],
            )
        ],
        start_url="http://localhost:3000/",
    )
    assert not any("Cookie" in item["title"] for item in findings)
    assert not any("Security headers missing" in item["title"] for item in findings)


def test_cors_reflects_foreign_origin():
    finding = cors_finding(
        "http://localhost:3000/",
        {"access-control-allow-origin": "http://webset-cors-test.localhost"},
    )
    assert finding is not None
    assert finding["cwe"] == "CWE-942"


def test_sensitive_env_path():
    findings = analyse_pages(
        [
            _page(
                url="http://localhost:3000/.env",
                requested_url="http://localhost:3000/.env",
                body="DB_PASSWORD=lab",
            )
        ],
        start_url="http://localhost:3000/",
    )
    assert any(item["cwe"] == "CWE-538" for item in findings)
