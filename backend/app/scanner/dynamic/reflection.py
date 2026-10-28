from __future__ import annotations

from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

import httpx

from ...config import DYNAMIC_TIMEOUT_SECONDS
from ..allowlist import TargetNotAllowed, validate_local_target
from ..findings import ScanCancelled, make_finding, stable_id
from .crawler import USER_AGENT, read_body

CANARY = "webset_canary_x7k9q2"
MAX_TESTS = 6
SKIP_TYPES = {"password", "file", "hidden", "submit", "button", "checkbox", "radio", "image"}


def _cancelled(flag) -> bool:
    return bool(flag and flag())


def _text_fields(form: dict) -> list[str]:
    names = []
    for item in form.get("inputs") or []:
        if item.get("type") in SKIP_TYPES:
            continue
        names.append(item["name"])
    return names


def probe_reflections(pages: list[dict], *, cancelled=None) -> list[dict]:
    findings: list[dict] = []
    tested = 0
    with httpx.Client(timeout=DYNAMIC_TIMEOUT_SECONDS, follow_redirects=True) as client:
        for page in pages:
            if tested >= MAX_TESTS:
                break
            if _cancelled(cancelled):
                raise ScanCancelled()
            for form in page.get("forms") or []:
                if tested >= MAX_TESTS:
                    break
                fields = _text_fields(form)
                if not fields:
                    continue
                action = form.get("action") or page["url"]
                try:
                    validate_local_target(action)
                except TargetNotAllowed:
                    continue
                data = {name: CANARY for name in fields[:4]}
                method = (form.get("method") or "get").lower()
                try:
                    headers = {"User-Agent": USER_AGENT}
                    if method == "post":
                        response = client.post(action, data=data, headers=headers)
                    else:
                        response = client.get(action, params=data, headers=headers)
                except httpx.RequestError:
                    continue
                tested += 1
                body = read_body(response)
                if CANARY in body:
                    location = f"{action} ({method})"
                    findings.append(
                        make_finding(
                            finding_id=stable_id("DYN", "REFLECT", location),
                            title="User input reflected without HTML encoding",
                            severity="medium",
                            confidence="medium",
                            detection_type="dynamic",
                            owasp_id="A03:2021",
                            cwe="CWE-79",
                            nist="SI-10",
                            sans="CWE-79",
                            location=location,
                            description=(
                                "A benign canary marker submitted through a form was echoed in the response. "
                                "Unencoded reflection is the prerequisite for reflected XSS. "
                                "No script or exploit payload was sent."
                            ),
                            evidence=f"Canary {CANARY} present in the response body.",
                            recommendation=(
                                "HTML-encode untrusted output for the context it is inserted into "
                                "and add a strict Content-Security-Policy."
                            ),
                        )
                    )

            if tested >= MAX_TESTS:
                break
            parsed = urlparse(page.get("url") or "")
            if parsed.query:
                query = dict(parse_qsl(parsed.query, keep_blank_values=True))
                if not query:
                    continue
                for key in list(query):
                    query[key] = CANARY
                probed = urlunparse(parsed._replace(query=urlencode(query)))
                try:
                    validate_local_target(probed)
                    response = client.get(probed, headers={"User-Agent": USER_AGENT})
                except (TargetNotAllowed, httpx.RequestError):
                    continue
                tested += 1
                if CANARY in read_body(response):
                    findings.append(
                        make_finding(
                            finding_id=stable_id("DYN", "REFLECT", probed),
                            title="Query parameter reflected without encoding",
                            severity="medium",
                            confidence="medium",
                            detection_type="dynamic",
                            owasp_id="A03:2021",
                            cwe="CWE-79",
                            nist="SI-10",
                            sans="CWE-79",
                            location=probed,
                            description=(
                                "A benign canary in the query string was echoed in the response. "
                                "No exploit payload was sent."
                            ),
                            evidence=f"Canary {CANARY} present in the response body.",
                            recommendation="Encode query values before inserting them into HTML.",
                        )
                    )
    return findings
