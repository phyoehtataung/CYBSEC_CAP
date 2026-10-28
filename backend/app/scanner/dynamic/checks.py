from __future__ import annotations

from urllib.parse import urlparse

from ..findings import make_finding, stable_id
from ..headers import SECURITY_HEADERS

SENSITIVE_PATHS = [
    "/robots.txt",
    "/.git/HEAD",
    "/.env",
    "/admin",
    "/admin/",
    "/phpinfo.php",
    "/server-status",
    "/backup",
    "/config.json",
    "/ftp",
]

TARGET_PATHS = {
    "juice-shop": [
        "/rest/products/search?q=webset",
        "/api/Users",
        "/encryptionkeys",
        "/ftp",
        "/rest/admin/application-configuration",
    ],
    "dvwa": [
        "/login.php",
        "/phpinfo.php",
        "/robots.txt",
        "/vulnerabilities/xss_r/",
        "/vulnerabilities/sqli/",
    ],
}

VERBOSE_MARKERS = (
    "traceback (most recent call last)",
    "fatal error",
    "warning:",
    "stack trace",
    "sql syntax",
    "unhandledpromiserejection",
    "exception in",
)


def extra_paths_for(target_id: str) -> list[str]:
    return list(SENSITIVE_PATHS) + list(TARGET_PATHS.get(target_id, []))


def parse_set_cookies(headers: list[str]) -> list[dict]:
    cookies = []
    for raw in headers or []:
        parts = [part.strip() for part in raw.split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name, _value = parts[0].split("=", 1)
        flags = {}
        for part in parts[1:]:
            key, _, val = part.partition("=")
            flags[key.strip().lower()] = val.strip()
        cookies.append(
            {
                "name": name.strip(),
                "secure": "secure" in flags,
                "httponly": "httponly" in flags,
                "samesite": flags.get("samesite") or "",
                "raw": raw,
            }
        )
    return cookies


def _id(rule: str, location: str) -> str:
    return stable_id("DYN", rule, location)


def analyse_pages(pages: list[dict], *, start_url: str | None = None) -> list[dict]:
    findings: list[dict] = []
    seen: set[str] = set()

    def add(item: dict) -> None:
        if item["finding_id"] in seen:
            return
        seen.add(item["finding_id"])
        findings.append(item)

    homepage = pages[0] if pages else None
    if homepage:
        add_header_findings(add, homepage)
        add_clickjacking(add, homepage)
        add_server_disclosure(add, homepage)

    for page in pages:
        add_cookie_findings(add, page)
        add_directory_listing(add, page)
        add_verbose_errors(add, page)
        add_mixed_content(add, page)
        add_form_findings(add, page)
        add_sensitive_path(add, page)

    return findings


def add_header_findings(add, page: dict) -> None:
    headers = page.get("headers") or {}
    missing = []
    for name in SECURITY_HEADERS:
        if name.lower() not in headers:
            if name == "Strict-Transport-Security" and urlparse(page["url"]).scheme != "https":
                continue
            missing.append(name)
    if not missing:
        return
    add(
        make_finding(
            finding_id=_id("HDR", page["url"]),
            title="Security headers missing on the local target",
            severity="medium",
            confidence="high",
            detection_type="dynamic",
            owasp_id="A05:2021",
            cwe="CWE-693",
            nist="CM-6",
            sans="CWE-16",
            location=page["url"],
            description=(
                "An unauthenticated GET against the authorised lab URL found missing browser "
                "security headers. This is a configuration review, not an exploit."
            ),
            evidence="Missing headers: " + ", ".join(missing),
            recommendation=(
                "Set CSP, X-Content-Type-Options, a framing policy, Referrer-Policy, "
                "and Permissions-Policy on all responses."
            ),
        )
    )


def add_clickjacking(add, page: dict) -> None:
    headers = page.get("headers") or {}
    csp = headers.get("content-security-policy", "")
    xfo = headers.get("x-frame-options", "")
    if xfo or "frame-ancestors" in csp.lower():
        return
    add(
        make_finding(
            finding_id=_id("CLICKJACK", page["url"]),
            title="No framing control (clickjacking)",
            severity="medium",
            confidence="high",
            detection_type="dynamic",
            owasp_id="A05:2021",
            cwe="CWE-1021",
            nist="CM-6",
            sans="CWE-1021",
            location=page["url"],
            description="Neither X-Frame-Options nor CSP frame-ancestors is set, so the page can be framed.",
            evidence="X-Frame-Options absent; CSP has no frame-ancestors directive.",
            recommendation="Set Content-Security-Policy: frame-ancestors 'self' (or X-Frame-Options: DENY).",
        )
    )


def add_server_disclosure(add, page: dict) -> None:
    headers = page.get("headers") or {}
    server = headers.get("server")
    powered = headers.get("x-powered-by")
    if not server and not powered:
        return
    detail = ", ".join(item for item in (server, powered) if item)
    add(
        make_finding(
            finding_id=_id("BANNER", "server"),
            title="Server or framework version disclosed",
            severity="low",
            confidence="high",
            detection_type="dynamic",
            owasp_id="A05:2021",
            cwe="CWE-200",
            nist="CM-6",
            sans="CWE-200",
            location="HTTP response headers",
            description="The response advertises server or framework versions, which helps an attacker pick exploits.",
            evidence=detail,
            recommendation="Remove or genericise Server and X-Powered-By headers in the reverse proxy or app config.",
        )
    )


def add_cookie_findings(add, page: dict) -> None:
    cookies = parse_set_cookies(page.get("set_cookie") or [])
    scheme = urlparse(page["url"]).scheme
    for cookie in cookies:
        issues = []
        if not cookie["httponly"]:
            issues.append("HttpOnly")
        if scheme == "https" and not cookie["secure"]:
            issues.append("Secure")
        if not cookie["samesite"]:
            issues.append("SameSite")
        if not issues:
            continue
        add(
            make_finding(
                finding_id=_id("COOKIE", f"{page['url']}|{cookie['name']}"),
                title=f"Cookie '{cookie['name']}' missing flags: {', '.join(issues)}",
                severity="medium",
                confidence="high",
                detection_type="dynamic",
                owasp_id="A05:2021",
                cwe="CWE-614",
                nist="SC-23",
                sans="CWE-614",
                location=page["url"],
                description=(
                    "Session or application cookies should set HttpOnly, SameSite, and Secure "
                    "(on HTTPS) so scripts and cross-site requests cannot misuse them."
                ),
                evidence=cookie["raw"][:220],
                recommendation="Set Secure (HTTPS), HttpOnly, and SameSite=Lax or Strict on session cookies.",
            )
        )


def add_directory_listing(add, page: dict) -> None:
    body = (page.get("body") or "")[:4000]
    if page.get("status_code") != 200:
        return
    if "index of /" not in body.lower() and "<title>directory listing" not in body.lower():
        return
    add(
        make_finding(
            finding_id=_id("DIRLIST", page["url"]),
            title="Directory listing enabled",
            severity="medium",
            confidence="high",
            detection_type="dynamic",
            owasp_id="A01:2021",
            cwe="CWE-548",
            nist="AC-3",
            sans="CWE-548",
            location=page["url"],
            description="The server returned a directory index, exposing file names that should stay hidden.",
            evidence="Response body contains a directory listing signature.",
            recommendation="Disable autoindex/directory listing in the web server and return 403 for folder URLs.",
        )
    )


def add_verbose_errors(add, page: dict) -> None:
    body = (page.get("body") or "").lower()
    hit = next((marker for marker in VERBOSE_MARKERS if marker in body), None)
    if not hit:
        return
    add(
        make_finding(
            finding_id=_id("VERBOSE", page["url"]),
            title="Verbose error or stack trace in the response",
            severity="low",
            confidence="medium",
            detection_type="dynamic",
            owasp_id="A05:2021",
            cwe="CWE-209",
            nist="SI-11",
            sans="CWE-209",
            location=page["url"],
            description="A detailed error page leaked implementation details that help an attacker.",
            evidence=f"Matched marker: {hit}",
            recommendation="Return generic errors to clients and log stack traces only on the server.",
        )
    )


def add_mixed_content(add, page: dict) -> None:
    if not page["url"].startswith("https://"):
        return
    body = page.get("body") or ""
    if "http://" not in body:
        return
    add(
        make_finding(
            finding_id=_id("MIXED", page["url"]),
            title="Page references insecure HTTP resources",
            severity="low",
            confidence="low",
            detection_type="dynamic",
            owasp_id="A02:2021",
            cwe="CWE-311",
            nist="SC-8",
            sans="CWE-311",
            location=page["url"],
            description="An HTTPS page includes http:// URLs, which browsers treat as mixed content.",
            evidence="Body contains http:// resource references.",
            recommendation="Serve all assets over HTTPS and use protocol-relative or https URLs.",
        )
    )


def add_form_findings(add, page: dict) -> None:
    for form in page.get("forms") or []:
        location = f"{form.get('action') or page['url']} ({form.get('method', 'get')})"
        names = {item["name"].lower() for item in form.get("inputs") or []}
        types = {item["type"] for item in form.get("inputs") or []}
        csrf_keys = {"csrf", "csrf_token", "csrftoken", "user_token", "_token", "authenticity_token"}
        if form.get("method") == "post" and names.isdisjoint(csrf_keys):
            add(
                make_finding(
                    finding_id=_id("CSRF", location),
                    title="POST form has no CSRF token field",
                    severity="medium",
                    confidence="medium",
                    detection_type="dynamic",
                    owasp_id="A01:2021",
                    cwe="CWE-352",
                    nist="SC-23",
                    sans="CWE-352",
                    location=location,
                    description=(
                        "A state-changing form does not include a hidden anti-CSRF token. "
                        "Browsers may submit it from another origin if cookies are sent."
                    ),
                    evidence=f"Input names: {', '.join(sorted(names)) or '(none)'}",
                    recommendation="Add a unique, unpredictable CSRF token and verify it on the server.",
                )
            )
        for item in form.get("inputs") or []:
            if item["type"] == "password" and item.get("autocomplete") not in {"off", "new-password"}:
                add(
                    make_finding(
                        finding_id=_id("AUTOCOMPLETE", location),
                        title="Password field allows autocomplete",
                        severity="low",
                        confidence="medium",
                        detection_type="dynamic",
                        owasp_id="A07:2021",
                        cwe="CWE-522",
                        nist="IA-5",
                        sans="CWE-522",
                        location=location,
                        description="A password input does not disable autocomplete, so browsers may cache credentials.",
                        evidence=f"input name={item['name']} type=password",
                        recommendation="Set autocomplete=\"off\" or \"new-password\" on password fields where appropriate.",
                    )
                )


def add_sensitive_path(add, page: dict) -> None:
    requested = page.get("requested_url") or page.get("url") or ""
    path = urlparse(requested).path
    if page.get("status_code") not in {200, 401, 403}:
        return
    interesting = {
        "/.git/HEAD",
        "/.env",
        "/phpinfo.php",
        "/server-status",
        "/ftp",
        "/backup",
        "/config.json",
        "/admin",
        "/admin/",
        "/robots.txt",
        "/encryptionkeys",
    }
    if path.rstrip("/") not in {item.rstrip("/") for item in interesting} and path not in interesting:
        return
    body = page.get("body") or ""
    if path.endswith("/.git/HEAD") and not body.startswith("ref:"):
        return
    if path.endswith("/.env") and "=" not in body:
        return
    if path.endswith("phpinfo.php") and "phpinfo" not in body.lower() and page.get("status_code") == 200:
        # SPA fallback
        if "<html" in body.lower() and "php version" not in body.lower():
            return
    severity = "high" if path in {"/.git/HEAD", "/.env", "/phpinfo.php"} else "low"
    if page.get("status_code") in {401, 403}:
        severity = "info"
    add(
        make_finding(
            finding_id=_id("PATH", requested),
            title=f"Sensitive path responded: {path}",
            severity=severity,
            confidence="medium" if page.get("status_code") == 200 else "low",
            detection_type="dynamic",
            owasp_id="A01:2021" if "admin" in path or "ftp" in path else "A05:2021",
            cwe="CWE-538",
            nist="CM-6",
            sans="CWE-538",
            location=requested,
            description=(
                "A GET to a well-known sensitive path on the authorised lab returned a useful status. "
                "No exploit payload was sent."
            ),
            evidence=f"HTTP {page.get('status_code')} on {requested}",
            recommendation="Block or authenticate these paths and keep VCS metadata and env files off the web root.",
        )
    )


def cors_finding(start_url: str, response_headers: dict) -> dict | None:
    acao = response_headers.get("access-control-allow-origin")
    if not acao:
        return None
    if acao.strip() in {"*", "http://webset-cors-test.localhost"}:
        return make_finding(
            finding_id=_id("CORS", start_url),
            title="CORS reflects a foreign origin or allows any origin",
            severity="medium",
            confidence="high",
            detection_type="dynamic",
            owasp_id="A05:2021",
            cwe="CWE-942",
            nist="AC-3",
            sans="CWE-942",
            location=start_url,
            description=(
                "The lab responded to a test Origin with '*' or by echoing the foreign origin. "
                "Authenticated APIs must not do this."
            ),
            evidence=f"Access-Control-Allow-Origin: {acao}",
            recommendation="Allow only trusted origins. Never reflect arbitrary Origin values.",
        )
    return None
