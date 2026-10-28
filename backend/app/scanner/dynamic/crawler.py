from __future__ import annotations

from collections import deque
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from ...config import DYNAMIC_MAX_BODY_BYTES, DYNAMIC_MAX_DEPTH, DYNAMIC_MAX_PAGES, DYNAMIC_TIMEOUT_SECONDS
from ..allowlist import TargetNotAllowed, validate_local_target
from ..findings import ScanCancelled

USER_AGENT = "WebSET/1.0 (local-lab scanner; no exploit payloads)"


def _cancelled(flag) -> bool:
    return bool(flag and flag())


def same_origin(left: str, right: str) -> bool:
    a, b = urlparse(left), urlparse(right)
    return (a.scheme, a.hostname, a.port or _default_port(a.scheme)) == (
        b.scheme,
        b.hostname,
        b.port or _default_port(b.scheme),
    )


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def normalise(base: str, href: str | None) -> str | None:
    if not href:
        return None
    href = href.strip()
    if href.startswith(("mailto:", "javascript:", "data:", "tel:")):
        return None
    joined = urljoin(base, href.split("#", 1)[0])
    parsed = urlparse(joined)
    if parsed.scheme not in {"http", "https"}:
        return None
    try:
        return validate_local_target(joined)
    except TargetNotAllowed:
        return None


def extract_links(url: str, html: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    found: list[str] = []
    for tag, attr in (("a", "href"), ("area", "href"), ("link", "href"), ("script", "src"), ("img", "src")):
        for node in soup.find_all(tag):
            target = normalise(url, node.get(attr))
            if target:
                found.append(target)
    for form in soup.find_all("form"):
        target = normalise(url, form.get("action") or url)
        if target:
            found.append(target)
    return found


def extract_forms(url: str, html: str) -> list[dict]:
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = normalise(url, form.get("action") or url) or url
        method = (form.get("method") or "get").lower()
        inputs = []
        for node in form.find_all(["input", "textarea", "select"]):
            name = node.get("name")
            if not name:
                continue
            inputs.append(
                {
                    "name": name,
                    "type": (node.get("type") or node.name or "text").lower(),
                    "value": node.get("value") or "",
                    "autocomplete": (node.get("autocomplete") or "").lower(),
                }
            )
        forms.append({"action": action, "method": method, "inputs": inputs})
    return forms


def fetch(client: httpx.Client, url: str, extra_headers: dict | None = None) -> httpx.Response | None:
    try:
        validate_local_target(url)
    except TargetNotAllowed:
        return None
    headers = {"User-Agent": USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)
    try:
        response = client.get(url, headers=headers, follow_redirects=True)
    except httpx.RequestError:
        return None
    try:
        validate_local_target(str(response.url))
    except TargetNotAllowed:
        return None
    return response


def read_body(response: httpx.Response) -> str:
    content = response.content[:DYNAMIC_MAX_BODY_BYTES]
    return content.decode(response.encoding or "utf-8", errors="replace")


def crawl(start_url: str, *, extra_paths: list[str] | None = None, cancelled=None, progress=None) -> dict:
    start = validate_local_target(start_url)
    pages: list[dict] = []
    seen: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(start, 0)])

    reachable = False
    error = None
    homepage = None

    with httpx.Client(timeout=DYNAMIC_TIMEOUT_SECONDS, follow_redirects=True) as client:
        while queue and len(pages) < DYNAMIC_MAX_PAGES:
            if _cancelled(cancelled):
                raise ScanCancelled()
            url, depth = queue.popleft()
            if url in seen or depth > DYNAMIC_MAX_DEPTH:
                continue
            seen.add(url)
            response = fetch(client, url)
            if response is None:
                if url == start:
                    error = "target was not reachable"
                    break
                continue
            reachable = True
            body = read_body(response)
            content_type = response.headers.get("content-type", "")
            if hasattr(response.headers, "get_list"):
                set_cookie = response.headers.get_list("set-cookie")
            elif "set-cookie" in response.headers:
                set_cookie = [response.headers["set-cookie"]]
            else:
                set_cookie = []
            page = {
                "url": str(response.url),
                "requested_url": url,
                "status_code": response.status_code,
                "headers": {k.lower(): v for k, v in response.headers.items()},
                "set_cookie": set_cookie,
                "body": body,
                "content_type": content_type,
                "forms": extract_forms(str(response.url), body) if "html" in content_type.lower() else [],
            }
            pages.append(page)
            if homepage is None:
                homepage = page
                for path in extra_paths or []:
                    candidate = normalise(start, path)
                    if candidate and candidate not in seen:
                        queue.append((candidate, 1))
            if progress:
                progress(
                    int(100 * len(pages) / DYNAMIC_MAX_PAGES),
                    f"Crawled {len(pages)} page(s)",
                )
            if "html" in content_type.lower() and depth < DYNAMIC_MAX_DEPTH:
                for link in extract_links(str(response.url), body):
                    if link not in seen and same_origin(start, link):
                        queue.append((link, depth + 1))

    return {
        "reachable": reachable,
        "error": error,
        "pages": pages,
        "homepage": homepage,
        "start_url": start,
    }
